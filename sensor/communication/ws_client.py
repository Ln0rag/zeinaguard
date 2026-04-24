import logging
import os
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from queue import Empty, Full, Queue

import psutil
import socketio

import config
from core.event_bus import dashboard_queue, scan_queue
from local_data_logger import LocalDataLogger
from runtime_state import get_status_snapshot, log_attack, mark_sent, update_status


LOGGER = logging.getLogger("zeinaguard.sensor.ws")

DEFAULT_BACKEND_URL = os.getenv("BACKEND_URL", os.getenv("ZEINAGUARD_BACKEND_URL", "http://localhost:5000"))

SCAN_EMIT_BATCH_SIZE = int(os.getenv("SCAN_EMIT_BATCH_SIZE", "25"))
SCAN_EMIT_INTERVAL_SECONDS = float(os.getenv("SCAN_EMIT_INTERVAL_SECONDS", "3.0"))
SCAN_DEDUP_SIGNAL_DELTA = int(os.getenv("SCAN_DEDUP_SIGNAL_DELTA", "5"))
SCAN_DEDUP_MAX_AGE_SECONDS = float(os.getenv("SCAN_DEDUP_MAX_AGE_SECONDS", "30"))
SENSOR_STATUS_INTERVAL_SECONDS = float(os.getenv("SENSOR_STATUS_INTERVAL_SECONDS", "5"))
OUTBOUND_QUEUE_MAXSIZE = int(os.getenv("SENSOR_OUTBOUND_QUEUE_MAXSIZE", "4000"))
BACKEND_CONNECT_MAX_RETRIES = int(os.getenv("SENSOR_BACKEND_MAX_RETRIES", "5"))
DISCONNECTED_LOG_INTERVAL_SECONDS = float(os.getenv("SENSOR_DISCONNECTED_LOG_INTERVAL_SECONDS", "15"))
RETRY_BACKOFF_SEQUENCE = [1, 2, 5, 10]


def retry_delay_seconds(attempt_number: int) -> int:
    index = max(0, min(attempt_number - 1, len(RETRY_BACKOFF_SEQUENCE) - 1))
    return RETRY_BACKOFF_SEQUENCE[index]


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class WSClient:
    def __init__(self, backend_url=None, token=None, sensor_id=None):
        self.backend_url = backend_url or DEFAULT_BACKEND_URL
        self.token = token
        self.hostname = socket.gethostname()
        self.sensor_registration_key = sensor_id or os.getenv("ZEINAGUARD_SENSOR_ID", self.hostname)
        self.sensor_id = None
        self.started_at = time.time()
        self.is_running = False
        self.remote_enabled = bool(token)
        self._remote_disabled_reason = None
        self._connect_attempts = 0
        self._last_disconnect_log_at = 0.0
        self._startup_error = None
        self._startup_error_lock = threading.Lock()
        self._registered_event = threading.Event()
        self._worker_threads_started = False
        self.local_logger = LocalDataLogger()
        self.outbound_queue = Queue(maxsize=OUTBOUND_QUEUE_MAXSIZE)
        self._sender_lock = threading.Lock()
        self._scan_cache_lock = threading.Lock()
        self._scan_batch_lock = threading.Lock()
        self.last_sent_cache = {}
        self.sio = socketio.Client(
            reconnection=True,
            reconnection_attempts=0,
            reconnection_delay=3,
            reconnection_delay_max=10,
            logger=False,
            engineio_logger=False,
        )
        psutil.cpu_percent(interval=None)

        self._register_handlers()

    def _register_handlers(self):
        @self.sio.event
        def connect():
            self._connect_attempts = 0
            self._last_disconnect_log_at = 0.0
            LOGGER.info("[Sensor] Backend connected")
            update_status(backend_status="connected", message=f"Connected to {self.backend_url}")
            self._enqueue_event(
                "sensor_register",
                {
                    "registration_key": self.sensor_registration_key,
                    "hostname": self.hostname,
                    "interface": config.get_interface(),
                },
            )

        @self.sio.event
        def disconnect():
            update_status(backend_status="disconnected", message="Backend connection lost")

        @self.sio.event
        def connect_error(_data):
            details = _data if _data else "unknown connect_error"
            self._set_startup_error(f"Backend connect failed: {details}")
            update_status(backend_status="offline", message=f"Backend connect failed: {details}")

        @self.sio.on("registration_success")
        def registration_success(data):
            sensor_id = data.get("sensor_id")
            if isinstance(sensor_id, bool) or not isinstance(sensor_id, int) or sensor_id <= 0:
                update_status(backend_status="degraded", message="Backend returned invalid sensor_id")
                LOGGER.warning("[DROP] registration_success returned invalid sensor_id=%s", sensor_id)
                return
            self.sensor_id = sensor_id
            update_status(
                backend_status="registered",
                message=f"Sensor registered as #{self.sensor_id}",
            )
            if self.sensor_id:
                self._enqueue_event("sensor_heartbeat", self._build_sensor_status_payload())

        @self.sio.on("registration_error")
        def registration_error(data):
            message = f"Sensor registration failed: {data}"
            self._set_startup_error(message)
            LOGGER.error("[Sensor] %s", message)
            update_status(backend_status="offline", message=message)
            try:
                self.sio.disconnect()
            except Exception:
                pass

        @self.sio.on("execute_attack")
        def execute_attack(payload):
            LOGGER.info("[COMMAND RECEIVED] execute_attack=%s", payload)
            self._handle_attack_command(payload)

        @self.sio.on("attack_command")
        def attack_command(payload):
            LOGGER.info("[COMMAND RECEIVED] attack_command=%s", payload)
            self._handle_attack_command(payload)

    def start(self):
        self.is_running = True
        self._start_worker_threads()

        if not self.token:
            self._set_startup_error("Backend authentication token is missing")
            self._disable_remote("missing_token", "Backend authentication unavailable; local logging only")
            while self.is_running:
                time.sleep(1)
            return

        while self.is_running and self.remote_enabled:
            if self.sio.connected:
                time.sleep(1)
                continue

            try:
                update_status(backend_status="connecting", message=f"Connecting to {self.backend_url}")
                self.sio.connect(
                    self.backend_url,
                    headers={"Authorization": f"Bearer {self.token}"},
                    transports=["websocket", "polling"],
                    wait=True,
                    wait_timeout=10,
                )
                self.sio.wait()
                if self.is_running and self.remote_enabled and not self.sio.connected:
                    raise RuntimeError("Backend socket disconnected before registration completed")
            except Exception as exc:
                self._set_startup_error(str(exc))
                self._connect_attempts += 1
                if self._connect_attempts >= BACKEND_CONNECT_MAX_RETRIES:
                    self._disable_remote(
                        "retry_limit",
                        f"Backend unavailable after {self._connect_attempts} attempts; last error: {exc}",
                    )
                    break

                retry_delay = retry_delay_seconds(self._connect_attempts)
                update_status(
                    backend_status="offline",
                    message=f"Backend retry {self._connect_attempts}/{BACKEND_CONNECT_MAX_RETRIES} in {retry_delay}s: {exc}",
                )
                time.sleep(retry_delay)

        while self.is_running:
            time.sleep(1)

    def wait_until_ready(self, timeout_seconds):
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            if self._registered_event.wait(timeout=0.25):
                return

            startup_error = self._get_startup_error()
            if not self.remote_enabled and startup_error:
                raise RuntimeError(startup_error)

        startup_error = self._get_startup_error()
        if startup_error:
            raise RuntimeError(startup_error)
        raise TimeoutError(
            f"Backend socket was not fully ready within {timeout_seconds}s for {self.backend_url}"
        )

    def _start_worker_threads(self):
        if self._worker_threads_started:
            return

        threading.Thread(target=self._scan_listener, daemon=True, name="WSScanListener").start()
        threading.Thread(target=self._threat_listener, daemon=True, name="WSThreatListener").start()
        threading.Thread(target=self._status_publisher, daemon=True, name="WSSensorStatus").start()
        threading.Thread(target=self._sender_worker, daemon=True, name="WSSenderWorker").start()
        self._worker_threads_started = True

    def _set_startup_error(self, message):
        with self._startup_error_lock:
            self._startup_error = str(message)

    def _clear_startup_error(self):
        with self._startup_error_lock:
            self._startup_error = None

    def _get_startup_error(self):
        with self._startup_error_lock:
            return self._startup_error

    def _disable_remote(self, reason, message):
        if self._remote_disabled_reason == reason:
            return

        self.remote_enabled = False
        self._remote_disabled_reason = reason
        if self.sio.connected:
            try:
                self.sio.disconnect()
            except Exception:
                pass
        LOGGER.warning("[Sensor] %s", message)
        update_status(backend_status="offline", message=message)

    def _enqueue_event(self, event_name, payload):
        if event_name != "sensor_register" and not self._payload_has_int_sensor_id(payload):
            LOGGER.warning("[DROP] event=%s invalid sensor_id payload=%s", event_name, self._payload_preview(payload))
            return False

        envelope = {
            "event_name": event_name,
            "payload": payload,
            "queued_at": utc_iso(),
        }

        try:
            self.outbound_queue.put(envelope, timeout=1)
            if event_name not in {"network_scan", "sensor_heartbeat"}:
                LOGGER.info("[QUEUE] queued %s", event_name)
            return True
        except Full:
            LOGGER.warning("[QUEUE] outbound queue full, dropped %s", event_name)
            update_status(backend_status="degraded", message=f"Outbound queue full for {event_name}")
            return False

    def _sender_worker(self):
        deferred_events = deque()
        scan_batch = []
        next_flush_deadline = time.monotonic() + SCAN_EMIT_INTERVAL_SECONDS

        while self.is_running:
            if not self.remote_enabled:
                deferred_events.clear()
                with self._scan_batch_lock:
                    scan_batch.clear()
                self._drain_outbound_queue()
                time.sleep(1)
                continue

            if deferred_events and self.sio.connected:
                envelope = deferred_events.popleft()
                if envelope["event_name"] == "network_scan":
                    self._append_scan_batch(scan_batch, envelope["payload"])
                elif not self._send_event(envelope["event_name"], envelope["payload"]):
                    deferred_events.appendleft(envelope)
                    time.sleep(1)
                    continue

            timeout = max(0.1, next_flush_deadline - time.monotonic())
            try:
                envelope = self.outbound_queue.get(timeout=timeout)
            except Empty:
                envelope = None

            if envelope is not None:
                event_name = envelope["event_name"]
                payload = envelope["payload"]

                if event_name == "network_scan":
                    self._append_scan_batch(scan_batch, payload)
                else:
                    self._flush_scan_batch(scan_batch, deferred_events)
                    if not self._send_event(event_name, payload):
                        deferred_events.append(envelope)

            should_flush = (
                len(scan_batch) >= SCAN_EMIT_BATCH_SIZE
                or (scan_batch and time.monotonic() >= next_flush_deadline)
            )
            if should_flush:
                self._flush_scan_batch(scan_batch, deferred_events)
                next_flush_deadline = time.monotonic() + SCAN_EMIT_INTERVAL_SECONDS

    def _append_scan_batch(self, scan_batch, payload):
        with self._scan_batch_lock:
            scan_batch.append(payload)

    def _flush_scan_batch(self, scan_batch, deferred_events):
        with self._scan_batch_lock:
            if not scan_batch:
                return
            batch = list(scan_batch)
            scan_batch.clear()

        sensor_id = self._sensor_id_value()
        if sensor_id is None:
            LOGGER.warning("[DROP] event=network_scan invalid sensor_id payload=%s", {"batch_size": len(batch)})
            return

        payload = {
            "sensor_id": sensor_id,
            "hostname": self.hostname,
            "sent_at": utc_iso(),
            "networks": batch,
        }
        if not self.remote_enabled:
            return
        if payload["sensor_id"] is None:
            for item in batch:
                deferred_events.appendleft({"event_name": "network_scan", "payload": item})
            return
        if self._send_event("network_scan", payload):
            self._mark_scan_batch_sent(batch)
            return

        for item in batch:
            deferred_events.appendleft({"event_name": "network_scan", "payload": item})

    def _send_event(self, event_name, payload):
        if not self.remote_enabled:
            return False

        if not self.sio.connected:
            if event_name not in {"network_scan", "sensor_heartbeat"}:
                self._log_disconnected_once(f"Backend socket unavailable; deferring {event_name}")
            return False

        try:
            with self._sender_lock:
                if event_name not in {"network_scan", "sensor_heartbeat"}:
                    LOGGER.info("[SEND] event=%s payload=%s", event_name, self._payload_preview(payload))
                self.sio.emit(event_name, payload)
            return True
        except Exception as exc:
            LOGGER.warning("[SEND] failed event=%s error=%s", event_name, exc)
            update_status(backend_status="degraded", message=f"Send failed for {event_name}")
            return False

    def _log_disconnected_once(self, message):
        now = time.monotonic()
        if (now - self._last_disconnect_log_at) < DISCONNECTED_LOG_INTERVAL_SECONDS:
            return
        self._last_disconnect_log_at = now
        LOGGER.warning("[Sensor] %s", message)

    def _drain_outbound_queue(self):
        while True:
            try:
                self.outbound_queue.get_nowait()
            except Empty:
                return

    def _payload_preview(self, payload):
        if not isinstance(payload, dict):
            return payload
        return {
            key: payload.get(key)
            for key in (
                "event",
                "sensor_id",
                "status",
                "bssid",
                "target_bssid",
                "action",
                "channel",
                "ssid",
                "bssid",
            )
            if key in payload
        }

    def _threat_listener(self):
        while self.is_running:
            try:
                threat = dashboard_queue.get(timeout=0.5)
            except Empty:
                continue

            if not threat or threat.get("type") == "REMOVED":
                continue

            event = threat.get("event", {})
            payload = {
                "sensor_id": self._sensor_id_value(),
                "ssid": event.get("ssid"),
                "bssid": event.get("bssid"),
                "signal": event.get("signal"),
                "channel": event.get("channel"),
                "classification": event.get("classification"),
                "timestamp": event.get("timestamp") or utc_iso(),
                "manufacturer": event.get("manufacturer"),
                "threat_type": threat.get("status"),
                "severity": "high" if event.get("classification") == "ROGUE" else "medium",
            }
            self._enqueue_event("new_threat", payload)

    def _scan_listener(self):
        while self.is_running:
            try:
                scan = scan_queue.get(timeout=0.5)
            except Empty:
                continue

            if not self._should_process_scan(scan):
                continue

            payload = self._build_scan_payload(scan)
            if payload is None:
                continue
            self.local_logger.log_scan(payload)
            self._update_last_sent_cache(payload)
            self._enqueue_event("network_scan", payload)

    def _status_publisher(self):
        while self.is_running:
            payload = self._build_sensor_status_payload()
            if payload is not None:
                self._enqueue_event("sensor_status", payload)
            time.sleep(SENSOR_STATUS_INTERVAL_SECONDS)

    def _should_process_scan(self, scan):
        bssid = str(scan.get("bssid") or "").strip().upper()
        if not bssid:
            return False

        now = time.time()
        current_signal = scan.get("signal")
        current_classification = scan.get("classification", "LEGIT")
        with self._scan_cache_lock:
            cached = self.last_sent_cache.get(bssid)

        if cached is None:
            return True

        if self._signal_changed(cached.get("signal"), current_signal):
            return True

        if cached.get("classification") != current_classification:
            return True

        return (now - cached.get("last_sent", 0)) > SCAN_DEDUP_MAX_AGE_SECONDS

    def _signal_changed(self, previous_signal, current_signal):
        if previous_signal is None or current_signal is None:
            return previous_signal != current_signal

        try:
            return abs(int(current_signal) - int(previous_signal)) >= SCAN_DEDUP_SIGNAL_DELTA
        except (TypeError, ValueError):
            return previous_signal != current_signal

    def _update_last_sent_cache(self, payload):
        bssid = str(payload.get("bssid") or "").strip().upper()
        if not bssid:
            return

        with self._scan_cache_lock:
            self.last_sent_cache[bssid] = {
                "signal": payload.get("signal"),
                "classification": payload.get("classification", "LEGIT"),
                "last_sent": time.time(),
            }

    def _mark_scan_batch_sent(self, batch):
        sample = batch[-1]
        mark_sent(
            {
                "ssid": sample.get("ssid"),
                "bssid": sample.get("bssid"),
                "batch_size": len(batch),
            }
        )

    def _build_scan_payload(self, scan):
        sensor_id = self._sensor_id_value()
        if sensor_id is None:
            LOGGER.warning("[DROP] event=network_scan invalid sensor_id payload=%s", {"bssid": scan.get("bssid")})
            return None

        clients = self._build_clients_payload(scan.get("bssid"))

        return {
            "sensor_id": sensor_id,
            "timestamp": scan.get("timestamp") or datetime.utcnow().isoformat(),
            "ssid": scan.get("ssid") or "Hidden",
            "bssid": scan.get("bssid"),
            "channel": scan.get("channel"),
            "signal": scan.get("signal"),
            "classification": scan.get("classification", "LEGIT"),
            "manufacturer": scan.get("manufacturer"),
            "score": scan.get("score", 0),
            "auth": scan.get("auth"),
            "wps": scan.get("wps"),
            "distance": scan.get("distance"),
            "raw_beacon": scan.get("raw_beacon"),
            "clients": clients,
            "clients_count": len(clients),
        }

    def _build_clients_payload(self, bssid):
        if not bssid:
            return []

        try:
            from monitoring.sniffer import clients_map

            client_set = (
                clients_map.get(bssid)
                or clients_map.get(str(bssid).upper())
                or clients_map.get(str(bssid).lower())
                or set()
            )
            client_macs = sorted(str(mac).strip().upper() for mac in client_set if mac)
            return [{"mac": mac, "type": "device"} for mac in client_macs]
        except Exception as exc:
            LOGGER.debug("[SCAN PAYLOAD] failed to build clients for %s: %s", bssid, exc)
            return []

    def _build_sensor_status_payload(self):
        sensor_id = self._sensor_id_value()
        if sensor_id is None:
            return None

        status_snapshot = get_status_snapshot()
        cpu_percent = psutil.cpu_percent(interval=None)
        memory_percent = psutil.virtual_memory().percent
        uptime_seconds = int(time.time() - self.started_at)
        return {
            "event": "sensor_status",
            "sensor_id": sensor_id,
            "registration_key": self.sensor_registration_key,
            "hostname": self.hostname,
            "status": "online",
            "signal_strength": 0,
            "cpu": cpu_percent,
            "memory": memory_percent,
            "cpu_usage": cpu_percent,
            "memory_usage": memory_percent,
            "uptime": uptime_seconds,
            "last_heartbeat": datetime.utcnow().isoformat(),
            "timestamp": datetime.utcnow().isoformat(),
            "message": status_snapshot.get("message"),
            "interface": config.get_interface(),
        }

    def _handle_attack_command(self, payload):
        payload = payload or {}
        requested_sensor_id = self._safe_int(payload.get("sensor_id"), default=0)
        actual_sensor_id = self._safe_int(self.sensor_id, default=0)
        target_bssid = str(payload.get("bssid") or payload.get("target_bssid") or "").strip().upper()
        channel = payload.get("channel")

        if not actual_sensor_id:
            self._queue_attack_ack("failed", target_bssid, "Sensor is not registered yet")
            return

        if requested_sensor_id != actual_sensor_id:
            self._queue_attack_ack(
                "failed",
                target_bssid,
                f"Command targeted sensor {requested_sensor_id}, local sensor is {actual_sensor_id}",
            )
            return

        if str(payload.get("action") or "").lower() != "deauth":
            self._queue_attack_ack("failed", target_bssid, f"Unsupported command: {payload.get('action')}")
            return

        if not target_bssid:
            self._queue_attack_ack("failed", target_bssid, "Missing target_bssid")
            return

        threading.Thread(
            target=self._execute_attack_command,
            args=(target_bssid, channel),
            daemon=True,
            name=f"AttackCommand-{target_bssid}",
        ).start()

    def _execute_attack_command(self, target_bssid, channel):
        try:
            from monitoring.sniffer import clients_map
            from prevention.containment_engine import ContainmentEngine

            log_attack(f"Commanded containment requested -> {target_bssid}", target_bssid)
            LOGGER.info("Starting Deauth Attack on BSSID %s channel=%s", target_bssid, channel)
            clients = list(clients_map.get(target_bssid, set()))
            containment = ContainmentEngine(config.get_interface())
            containment.contain(target_bssid, clients, channel)
            LOGGER.info("[ATTACK EXECUTED] target=%s channel=%s", target_bssid, channel)
            self._queue_attack_ack("executed", target_bssid, "Containment finished successfully")
        except Exception as exc:
            LOGGER.warning("[ATTACK EXECUTED] failed target=%s error=%s", target_bssid, exc)
            self._queue_attack_ack("failed", target_bssid, str(exc))

    def _queue_attack_ack(self, status, target_bssid, message=None):
        sensor_id = self._sensor_id_value()
        if sensor_id is None:
            LOGGER.warning("[DROP] event=attack_ack invalid sensor_id payload=%s", {"bssid": target_bssid})
            return

        payload = {
            "event": "attack_ack",
            "status": status,
            "bssid": target_bssid,
            "sensor_id": sensor_id,
            "message": message,
            "timestamp": utc_iso(),
        }
        self._enqueue_event("attack_ack", payload)

    def _sensor_id_value(self):
        if isinstance(self.sensor_id, bool) or not isinstance(self.sensor_id, int) or self.sensor_id <= 0:
            return None
        return self.sensor_id

    def _payload_has_int_sensor_id(self, payload):
        if not isinstance(payload, dict):
            return False
        sensor_id = payload.get("sensor_id")
        return isinstance(sensor_id, int) and not isinstance(sensor_id, bool) and sensor_id > 0

    def _safe_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
