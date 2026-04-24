from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import requests
import socketio


TEST_BSSID = "AA:BB:CC:DD:EE:FF"


class EventStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, list[Any]] = {}

    def push(self, name: str, payload: Any) -> None:
        with self._lock:
            self._events.setdefault(name, []).append(payload)

    def wait_for(self, name: str, predicate: Callable[[Any], bool], timeout: float) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                events = list(self._events.get(name, []))
            for event in events:
                if predicate(event):
                    return event
            time.sleep(0.1)
        raise AssertionError(f"Timed out waiting for {name}")


def wait_for_backend(backend_url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(f"{backend_url}/health", timeout=2)
            if response.ok:
                return
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(0.5)
    raise AssertionError(f"Backend failed health check at {backend_url}: {last_error}")


def start_backend(root_dir: Path, port: int) -> subprocess.Popen[str]:
    backend_dir = root_dir / "backend"
    validation_db = (root_dir / "instance" / "validation-realtime.db").resolve()
    validation_db.parent.mkdir(parents=True, exist_ok=True)
    database_url = f"sqlite:///{validation_db.as_posix()}"
    env = dict(os.environ)
    env["DATABASE_URL"] = database_url
    env["FLASK_PORT"] = str(port)
    env["SOCKETIO_ASYNC_MODE"] = "threading"
    env["PYTHONUNBUFFERED"] = "1"

    return subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=str(backend_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the ZeinaGuard realtime pipeline.")
    parser.add_argument("--backend-port", type=int, default=8010)
    parser.add_argument("--backend-url", default="")
    parser.add_argument("--reuse-backend", action="store_true")
    parser.add_argument("--timeout", type=float, default=25.0)
    args = parser.parse_args()

    script_path = Path(__file__).resolve()
    root_dir = script_path.parent.parent
    backend_url = args.backend_url or f"http://127.0.0.1:{args.backend_port}"
    backend_process: subprocess.Popen[str] | None = None

    try:
        if not args.reuse_backend:
            print(f"[START] backend on {backend_url}")
            backend_process = start_backend(root_dir, args.backend_port)

        wait_for_backend(backend_url, timeout=args.timeout)
        print("[PASS] backend healthy")

        dashboard_events = EventStore()
        dashboard = socketio.Client(logger=False, engineio_logger=False)

        @dashboard.event
        def connect():
            print("[CONNECT] dashboard connected")

        @dashboard.on("network_snapshot")
        def on_network_snapshot(payload):
            dashboard_events.push("network_snapshot", payload)

        @dashboard.on("sensor_snapshot")
        def on_sensor_snapshot(payload):
            dashboard_events.push("sensor_snapshot", payload)

        @dashboard.on("attack_command_ack")
        def on_attack_command_ack(payload):
            dashboard_events.push("attack_command_ack", payload)

        @dashboard.on("attack_ack")
        def on_attack_ack(payload):
            dashboard_events.push("attack_ack", payload)

        dashboard.connect(backend_url, transports=["websocket"])

        sensor_events = EventStore()
        sensor = socketio.Client(logger=False, engineio_logger=False)
        sensor_state = {"sensor_id": None}
        stop_heartbeat = threading.Event()

        @sensor.event
        def connect():
            print("[CONNECT] sensor connected")
            sensor.emit(
                "sensor_register",
                {
                    "registration_key": "validation-sensor",
                    "hostname": "validation-sensor",
                    "interface": "mon0",
                },
            )

        @sensor.on("registration_success")
        def on_registration_success(payload):
            sensor_id = payload.get("sensor_id")
            if not isinstance(sensor_id, int):
                raise AssertionError(f"registration_success returned non-int sensor_id: {payload}")
            sensor_state["sensor_id"] = sensor_id
            sensor_events.push("registration_success", payload)

        @sensor.on("execute_attack")
        def on_execute_attack(payload):
            sensor_id = sensor_state["sensor_id"]
            assert isinstance(sensor_id, int)
            sensor.emit(
                "attack_ack",
                {
                    "event": "attack_ack",
                    "sensor_id": sensor_id,
                    "bssid": payload.get("bssid"),
                    "status": "executed",
                    "message": "Validation sensor executed the attack",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                },
            )

        sensor.connect(backend_url, transports=["websocket"])
        registration = sensor_events.wait_for("registration_success", lambda payload: isinstance(payload.get("sensor_id"), int), timeout=5)
        sensor_id = registration["sensor_id"]
        print(f"[PASS] sensor registered as #{sensor_id}")

        def heartbeat_loop() -> None:
            while not stop_heartbeat.is_set():
                sensor.emit(
                    "sensor_status",
                    {
                        "event": "sensor_status",
                        "sensor_id": sensor_id,
                        "hostname": "validation-sensor",
                        "status": "online",
                        "cpu": 11.5,
                        "memory": 22.5,
                        "uptime": int(time.time()),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "last_heartbeat": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "interface": "mon0",
                        "message": "validation heartbeat",
                    },
                )
                stop_heartbeat.wait(4.0)

        heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True, name="validation-heartbeat")
        heartbeat_thread.start()

        dashboard_events.wait_for(
            "sensor_snapshot",
            lambda payload: any(
                sensor_snapshot.get("sensor_id") == sensor_id and sensor_snapshot.get("status") != "offline"
                for sensor_snapshot in payload.get("data", [])
            ),
            timeout=3,
        )
        print("[PASS] sensor appears online within 3 seconds")

        sensor.emit(
            "network_scan",
            {
                "sensor_id": sensor_id,
                "hostname": "validation-sensor",
                "networks": [
                    {
                        "sensor_id": sensor_id,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "ssid": "Validation Rogue AP",
                        "bssid": TEST_BSSID,
                        "channel": 6,
                        "signal": -42,
                        "classification": "ROGUE",
                        "manufacturer": "Validation Labs",
                        "score": 95,
                    }
                ],
            },
        )

        dashboard_events.wait_for(
            "network_snapshot",
            lambda payload: any(
                network.get("bssid") == TEST_BSSID
                for network in payload.get("data", [])
            ),
            timeout=5,
        )
        print("[PASS] network appears in realtime snapshot")

        dashboard.emit("attack_command", {"sensor_id": sensor_id, "bssid": TEST_BSSID})

        dashboard_events.wait_for(
            "attack_command_ack",
            lambda payload: payload.get("status") == "ok" and payload.get("sensor_id") == sensor_id,
            timeout=5,
        )
        dashboard_events.wait_for(
            "attack_ack",
            lambda payload: payload.get("status") == "executed" and payload.get("bssid") == TEST_BSSID,
            timeout=5,
        )
        print("[PASS] attack acknowledgment received")

        dashboard_events.wait_for(
            "network_snapshot",
            lambda payload: all(
                network.get("bssid") != TEST_BSSID
                for network in payload.get("data", [])
            ),
            timeout=10,
        )
        print("[PASS] stale network disappears within 10 seconds")

        stop_heartbeat.set()
        sensor.disconnect()
        dashboard.disconnect()
        print("[RESULT] realtime pipeline validation passed")
        return 0
    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1
    finally:
        if backend_process is not None:
            backend_process.terminate()
            try:
                backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend_process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
