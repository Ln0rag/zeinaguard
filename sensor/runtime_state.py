import logging
import threading
import time
from collections import deque
from copy import deepcopy
# استيراد الـ Bus عشان نبعت الداتا لايف للـ ws_client
from core.event_bus import dashboard_queue 

LOGGER = logging.getLogger("zeinaguard.sensor")

_lock = threading.Lock()
_aps_view = {}
_signal_history = {}
_recent_sent = deque(maxlen=20)
_attack_log = deque(maxlen=20)

_status_state = {
    "sensor_status": "starting",
    "backend_status": "offline",
    "message": "Booting sensor",
    "sent_count": 0,
}

_attack_stats = {
    "deauth_count": 0,
    "clients_kicked": 0,
    "target_bssid": None,
    "start_time": None,
}

def update_ap(event_summary):
    with _lock:
        bssid = event_summary["bssid"]
        signal = event_summary.get("signal")
        if signal is not None:
            history = _signal_history.setdefault(bssid, deque(maxlen=8))
            history.append(signal)
        event_summary["last_seen"] = time.time()
        _aps_view[bssid] = deepcopy(event_summary)

def remove_ap(bssid):
    with _lock:
        _aps_view.pop(bssid, None)
        _signal_history.pop(bssid, None)

def update_status(sensor_status=None, backend_status=None, message=None):
    with _lock:
        if sensor_status is not None:
            _status_state["sensor_status"] = sensor_status
        if backend_status is not None:
            _status_state["backend_status"] = backend_status
        if message is not None:
            _status_state["message"] = message
            LOGGER.info("[Sensor] %s", message)

def mark_sent(event_summary):
    batch_size = int(event_summary.get("batch_size") or 1)
    with _lock:
        _status_state["sent_count"] += batch_size
        message = f"Sent update for {event_summary.get('bssid') or 'batch'}"
        _status_state["message"] = message
    LOGGER.info("[Sensor] %s", message)

def log_attack(message, bssid=None):
    """تسجيل الهجوم محلياً وإرساله فوراً للداشبورد عبر الـ Queue"""
    with _lock:
        _attack_log.appendleft({
            "timestamp": time.time(),
            "message": message,
            "bssid": bssid,
        })
        _status_state["message"] = message
        if bssid:
            _attack_stats["target_bssid"] = bssid
        if "Deauth" in message or "Burst" in message:
            _attack_stats["deauth_count"] += 1
            
    # إرسال اللوج للـ Dashboard Queue عشان الـ ws_client يلقطه
    dashboard_queue.put({
        "type": "ATTACK_LOG",
        "bssid": bssid,
        "message": message,
        "timestamp": time.time()
    })
    LOGGER.info("[Sensor] %s", message)

def client_kicked():
    with _lock:
        _attack_stats["clients_kicked"] += 1
    dashboard_queue.put({"type": "STATS_REFRESH", "timestamp": time.time()})

# الدوال اللي كانت ناقصة وعملت الـ Error:
def get_status_snapshot():
    """هذه الدالة هي التي يستدعيها ws_client.py في سطر 16"""
    with _lock:
        return {
            **deepcopy(_status_state),
            "attack": deepcopy(_attack_stats),
        }

def get_network_snapshot(bssid):
    with _lock:
        entry = _aps_view.get(bssid)
        return deepcopy(entry) if entry else None

def get_signal_history(bssid):
    with _lock:
        return list(_signal_history.get(bssid, []))