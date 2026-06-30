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
        self._sanity_check_client_env()
        self.hostname = socket.gethostname()
        self.sensor_registration_key = sensor_id or os.getenv("ZEINAGUARD_SENSOR_ID", self.hostname)
        self.sensor_id = None
        self.started_at = time.time()
        self.is_running = False
        self.remote_enabled = bool(self.token)
        self._remote_disabled_reason = None
        self._connect_attempts = 0
        self._last_disconnect_log_at = 0.0
        self._startup_error = None
        self._startup_error_lock = threading.Lock()
        self._registered_event = threading.Event()
        self._worker_threads_started = False


    def _sanity_check_client_env(self):
        if not self.token:
            import sys
            LOGGER.critical("[FATAL] API_TOKEN is missing or None. The sensor cannot authenticate with the backend.")
            sys.exit(1)
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
                self._enqueue_event("sensor_status_update", self._build_sensor_status_payload())

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

        @self.sio.on("execute_kill")
        def handle_execute_kill(payload):
            LOGGER.info("[COMMAND RECEIVED] execute_kill=%s", payload)
            from core.event_bus import event_queue
            event_queue.put(payload)


        @self.sio.on("shell_command")
        def shell_command(payload):
            """Listen for arbitrary terminal commands from the UI"""
            threading.Thread(
                target=self._execute_shell_command,
                args=(payload,),
                daemon=True,
                name="ShellCommand"
            ).start()

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
                    auth={"token": self.token},
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
            if event_name not in {"network_scan", "sensor_status_update"}:
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
            if event_name not in {"network_scan", "sensor_status_update"}:
                self._log_disconnected_once(f"Backend socket unavailable; deferring {event_name}")
            return False

        try:
            with self._sender_lock:
                if event_name not in {"network_scan", "sensor_status_update"}:
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

            if not threat:
                continue

            event_type = threat.get("type")
            if event_type:
                if event_type == "DEAUTH_ATTACK":
                    target_bssid_log = threat.get("target_bssid", "N/A")
                    network_name_log = threat.get("network_name", "Unknown")
                    LOGGER.warning(
                        "[WS] DEAUTH_ATTACK received from dashboard_queue | "
                        "target=%s network=%s rssi=%s distance=%s",
                        target_bssid_log, network_name_log,
                        threat.get("attacker_rssi"),
                        threat.get("estimated_distance_m"),
                    )

                    sensor_id_val = self._sensor_id_value()
                    if sensor_id_val is None:
                        LOGGER.error(
                            "[WS] DEAUTH_ATTACK DROPPED — sensor not registered yet "
                            "(sensor_id is None) | target=%s network=%s | "
                            "Ensure sensor registers before deauth alerts arrive.",
                            target_bssid_log, network_name_log,
                        )
                        continue

                    dist = threat.get("estimated_distance_m")
                    dist_str = f"{dist:.1f}m" if isinstance(dist, (int, float)) and dist > 0 else "unknown"
                    deauth_payload = {
                        "sensor_id": sensor_id_val,
                        "target_bssid": threat.get("target_bssid"),
                        "ssid": threat.get("network_name", "Unknown Network"),
                        "attacker_rssi": threat.get("attacker_rssi"),
                        "estimated_distance_m": dist,
                        "frame_count": threat.get("frame_count"),
                        "reason_code": threat.get("reason_code"),
                        "spoofed_src_mac": threat.get("spoofed_src_mac"),
                        "description": (
                            f"External deauthentication attack on trusted network "
                            f"{threat.get('network_name', 'Unknown')} "
                            f"({threat.get('target_bssid', 'N/A')}) | "
                            f"RSSI={threat.get('attacker_rssi')} dBm | "
                            f"Distance≈{dist_str} | "
                            f"Reason code={threat.get('reason_code', 0)}"
                        ),
                        "timestamp": utc_iso(),
                    }
                    queued = self._enqueue_event("deauth_attack", deauth_payload)
                    if queued:
                        LOGGER.warning(
                            "[WS] DEAUTH_ATTACK enqueued for transmission | "
                            "target=%s sensor_id=%d",
                            target_bssid_log, sensor_id_val,
                        )
                    else:
                        LOGGER.error(
                            "[WS] DEAUTH_ATTACK failed to enqueue | "
                            "target=%s sensor_id=%d — check outbound queue capacity",
                            target_bssid_log, sensor_id_val,
                        )
                    continue

                if event_type == "THREAT_RESOLVED":
                    resolved_payload = {
                        "sensor_id": self._sensor_id_value(),
                        "bssid": threat.get("bssid"),
                        "status": threat.get("status"),
                        "is_resolved": threat.get("is_resolved", True),
                        "reason": threat.get("resolution_reason", "Network no longer visible"),
                        "timestamp": threat.get("timestamp") or utc_iso(),
                    }
                    self._enqueue_event("sensor_attack_status", resolved_payload)
                    self._enqueue_event("threat_resolved", resolved_payload)
                    continue

                if event_type == "ATTACK_STATE_CHANGE":
                    engine_status = threat.get("status")
                    state_payload = {
                        "sensor_id": self._sensor_id_value(),
                        "bssid": threat.get("bssid"),
                        "status": engine_status,
                        "reason": threat.get("reason"),
                        "timestamp": threat.get("timestamp") or utc_iso(),
                    }
                    self._enqueue_event("sensor_attack_status", state_payload)
                    
                    if engine_status == "MONITORING":
                        self._queue_attack_ack("executed", threat.get("bssid"), message=f"Attack finished: {threat.get('reason')}")
                    
                    elif engine_status == "KILLED":
                        reason_str = (threat.get("reason") or "").lower()
                        if "hardware failure" in reason_str or "error" in reason_str:
                            self._queue_attack_ack("failed", threat.get("bssid"), message=threat.get("reason"))
                        else:
                            self._queue_attack_ack("aborted", threat.get("bssid"), message=threat.get("reason"))
                
                elif event_type == "ATTACK_LOG":
                    bssid_raw = threat.get("bssid")
                    log_payload = {
                        "sensor_id": self._sensor_id_value(),
                        "bssid": bssid_raw.upper() if bssid_raw else None,
                        "message": threat.get("message"),
                        "timestamp": threat.get("timestamp") or utc_iso(),
                    }
                    self._enqueue_event("deauth_log", log_payload)
                continue

            event = threat.get("event")
            if not event or not isinstance(event, dict) or not event.get("bssid"):
                continue

            is_open = (event.get("auth") == "OPEN")
            signal_val = int(event.get("signal") or -100)
            classification = event.get("classification", "LEGIT")

            if classification == "ROGUE" or (is_open and signal_val >= -30):
                current_severity = "high"
            elif is_open or classification == "SUSPICIOUS":
                current_severity = "medium"
            else:
                current_severity = "low"

            payload = {
                "sensor_id": self._sensor_id_value(),
                "ssid": event.get("ssid"),
                "bssid": event.get("bssid"),
                "signal": event.get("signal"),
                "channel": event.get("channel"),
                "classification": classification,
                "score": threat.get("score", 0),
                "reasons": threat.get("reasons", []),
                "timestamp": event.get("timestamp") or utc_iso(),
                "manufacturer": event.get("manufacturer"),
                "threat_type": threat.get("status"),
                "severity": current_severity,
                "description": " | ".join(threat.get("reasons", [])) if threat.get("reasons") else "Detected via Sensor WebSocket"
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
                self._enqueue_event("sensor_status_update", payload)
            time.sleep(SENSOR_STATUS_INTERVAL_SECONDS)

    def _should_process_scan(self, scan):
        bssid = str(scan.get("bssid") or "").strip().upper()
        if not bssid:
            return False

        now = time.time()
        current_signal = scan.get("signal")
        current_classification = scan.get("classification", "LEGIT")
        current_ssid = scan.get("ssid")
        was_hidden = scan.get("was_hidden", False)

        with self._scan_cache_lock:
            cached = self.last_sent_cache.get(bssid)

        if cached is None:
            return True

        if was_hidden and not cached.get("was_hidden"):
            return True
        if current_ssid and current_ssid != "Hidden" and cached.get("ssid") in ["Hidden", "", None]:
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
                "ssid": payload.get("ssid"),
                "was_hidden": payload.get("was_hidden", False),
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
            return None

        clients = self._build_clients_payload(scan.get("bssid"))
        
        auth_val = scan.get("auth", "Unknown")
        enc_val = "OPEN" if auth_val == "OPEN" else "UNKNOWN"

        return {
            "sensor_id": sensor_id,
            "timestamp": scan.get("timestamp") or (datetime.utcnow().isoformat() + "Z"),
            "ssid": scan.get("ssid") or "Hidden",
            "bssid": scan.get("bssid"),
            "channel": scan.get("channel"),
            "signal": scan.get("signal"),
            "classification": scan.get("classification", "LEGIT"),
            "manufacturer": scan.get("manufacturer", "Unknown"),
            "score": scan.get("score", 0),
            "reasons": scan.get("reasons", []),
            "is_trusted": scan.get("is_trusted", False),
            "encryption": enc_val,
            "auth": auth_val,
            "wps": scan.get("wps", "Unknown"),
            "uptime": scan.get("uptime", "0"),
            "distance": scan.get("distance", "Unknown"),
            "frequency": scan.get("frequency"),
            "clients": clients,
            "clients_count": len(clients),
            "was_hidden": scan.get("was_hidden", False),
        } 

    def _build_clients_payload(self, bssid):
        if not bssid:
            return []

        try:
            from monitoring.sniffer import clients_map

            norm_bssid = str(bssid).strip().upper().replace("-", ":")
            
            client_set = clients_map.get(norm_bssid, {})
            
            if isinstance(client_set, dict):
                client_iterable = client_set.keys()
            else:
                client_iterable = client_set
                
            client_macs = sorted(str(mac).strip().upper() for mac in client_iterable if mac)
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
        
        # Real OS uptime
        uptime_seconds = int(time.time() - psutil.boot_time())

        return {
            "event": "sensor_status_update",
            "sensor_id": sensor_id,
            "registration_key": self.sensor_registration_key,
            "hostname": self.hostname,
            "status": status_snapshot.get("sensor_status", "online"),
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
            from core.event_bus import event_queue
            from monitoring.sniffer import aps_state

            net_info = aps_state.get(target_bssid, {}).get("event", {})
            resolved_channel = channel or net_info.get("channel")
            resolved_ssid = net_info.get("ssid") or "Unknown"

            if not resolved_channel:
                self._queue_attack_ack(
                    "failed",
                    target_bssid,
                    "Cannot attack: channel is unknown. "
                    "Wait for at least one beacon scan before retrying.",
                )
                return

            manual_attack_event = {
                "type": "MANUAL_ATTACK",
                "bssid": target_bssid,
                "channel": resolved_channel,
                "ssid": resolved_ssid,
                "sensor_id": self._sensor_id_value(),
                "timestamp": utc_iso(),
            }

            event_queue.put(manual_attack_event, timeout=2)
            log_attack(
                f"Manual attack dispatched for {resolved_ssid} ({target_bssid}) "
                f"on channel {resolved_channel}",
                target_bssid,
            )
            self._queue_attack_ack(
                "started",
                target_bssid,
                f"Manual deauth attack initiated on channel {resolved_channel}.",
                ssid=resolved_ssid,
                channel=resolved_channel,
                signal=net_info.get("signal"),
            )

        except Exception as exc:
            LOGGER.exception(
                "[ATTACK] Failed to dispatch manual attack for %s", target_bssid,
            )
            self._queue_attack_ack(
                "failed",
                target_bssid,
                f"Attack dispatch failed: {exc}",
            )

    def _queue_attack_ack(self, status, target_bssid, message=None, ssid=None, channel=None, signal=None):
        sensor_id = self._sensor_id_value()
        if sensor_id is None: return

        from monitoring.sniffer import aps_state
        
        net_info = {}
        for k, v in aps_state.items():
            if k.lower() == target_bssid.lower():
                net_info = v.get("event", {})
                break
        
        payload = {
            "event": "attack_ack",
            "status": status,
            "bssid": target_bssid.upper(),
            "sensor_id": sensor_id,
            "ssid": ssid or net_info.get("ssid", "Unknown"), 
            "channel": channel or net_info.get("channel"),
            "signal": signal or net_info.get("signal"),
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

