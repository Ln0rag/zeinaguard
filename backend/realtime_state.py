from __future__ import annotations

import os
import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

# Add sensor dir to path so backend can use the unified config API
sys.path.append(str(Path(__file__).resolve().parent.parent / "sensor"))
from config import get_trusted_macs

NETWORK_TTL_SECONDS = float(os.getenv("LIVE_NETWORK_TTL_SECONDS", "5"))
SENSOR_TTL_SECONDS = float(os.getenv("LIVE_SENSOR_TTL_SECONDS", "5"))

_state_lock = threading.Lock()
_active_networks: dict[str, dict[str, Any]] = {}
_active_sensors: dict[int, dict[str, Any]] = {}

def _utcnow() -> datetime:
    return datetime.utcnow()

def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(normalized).replace(tzinfo=None)
        except ValueError:
            return _utcnow()
    return _utcnow()

def _safe_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

def _normalize_bssid(value: Any) -> str:
    if value is None:
        return ""
    hex_value = re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()
    if len(hex_value) == 12:
        return ":".join(hex_value[index:index + 2] for index in range(0, 12, 2))
    return str(value).strip().upper().replace("-", ":")

def _normalize_ssid(value: Any) -> str:
    return str(value or "Hidden").strip() or "Hidden"

def _normalize_classification(value: Any) -> str:
    classification = str(value or "LEGIT").strip().upper()
    if classification not in {"ROGUE", "SUSPICIOUS", "LEGIT"}:
        return "LEGIT"
    return classification

def _normalize_clients(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized_clients: list[dict[str, Any]] = []
    seen_macs: set[str] = set()
    for item in value:
        if isinstance(item, dict):
            mac = _normalize_bssid(item.get("mac"))
            client_type = str(item.get("type") or "device").strip().lower() or "device"
        else:
            mac = _normalize_bssid(item)
            client_type = "device"
        if not mac or mac in seen_macs:
            continue
        seen_macs.add(mac)
        normalized_clients.append({"mac": mac, "type": client_type})
    return normalized_clients

def force_trust_bssid(bssid: str) -> None:
    # Deprecated: Persistence is now handled synchronously by config.add_trusted_mac
    pass

def load_trusted_bssids(bssids: list[str]) -> None:
    # Deprecated: config.py automatically handles file loading and caching
    pass

def is_bssid_trusted(bssid: str) -> bool:
    if not bssid:
        return False
    normalized = _normalize_bssid(bssid)
    # Check the actual JSON cache dictionary
    return normalized in get_trusted_macs()

def upsert_network(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    bssid = _normalize_bssid(payload.get("bssid"))
    if not bssid:
        raise ValueError("network missing bssid")

    seen_at = _utcnow()

    with _state_lock:
        existing = _active_networks.get(bssid, {})

        def merge_str(key: str, default: str = "Unknown") -> str:
            new_val = str(payload.get(key) or "").strip()
            if new_val and new_val.lower() not in ["none", "unknown", "n/a", ""]:
                return new_val
            old_val = str(existing.get(key) or "").strip()
            if old_val and old_val.lower() not in ["none", "unknown", "n/a", ""]:
                return old_val
            return default

        def merge_int(key: str, default: int = 0) -> int:
            new_val = _safe_int(payload.get(key))
            if new_val and new_val > 0:
                return new_val
            return _safe_int(existing.get(key), default)

        raw_clients = payload.get("clients")
        # Support both 'clients' list and 'clients_count' direct value
        incoming_clients_count = _safe_int(payload.get("clients_count"))
        
        clients_list = existing.get("clients", [])
        clients_count = existing.get("clients_count", 0)
        
        # Explicit update: if clients list is provided, use it
        if isinstance(raw_clients, list):
            clients_list = _normalize_clients(raw_clients)
            clients_count = len(clients_list)
        # If no list but count is provided, update count (and clear list if count is 0)
        elif incoming_clients_count is not None:
            clients_count = max(incoming_clients_count, 0)
            if clients_count == 0:
                clients_list = []
        # Fallback for some payloads that might just have 'clients' as a number
        elif isinstance(raw_clients, (int, float)):
            clients_count = max(int(raw_clients), 0)
            if clients_count == 0:
                clients_list = []

        # --- RE-EVALUATION LOGIC START ---
        # 1. First, check the live status from the physical file
        is_currently_trusted = is_bssid_trusted(bssid)
        
        if is_currently_trusted:
            final_classification = "LEGIT"
            final_score = 0
            final_reasons = []
        else:
            # 2. If NOT in the file, we look at the incoming scan data
            # We explicitly ignore the stale memory if it was previously marked LEGIT
            incoming_data_class = payload.get("classification")
            
            if incoming_data_class:
                final_classification = _normalize_classification(incoming_data_class)
            else:
                # 3. If no new data, and old data was "LEGIT", force it to SUSPICIOUS
                # because we already know it is NOT in the trusted file anymore
                old_class = existing.get("classification", "SUSPICIOUS")
                if old_class == "LEGIT":
                    final_classification = "SUSPICIOUS"
                else:
                    final_classification = old_class

            final_score = _safe_int(payload.get("score"), existing.get("score", 0))
            final_reasons = payload.get("reasons") or existing.get("reasons", [])
        # --- RE-EVALUATION LOGIC END ---

        snapshot = {
            "ssid": merge_str("ssid", "Hidden"),
            "classification": final_classification,
            "channel": merge_int("channel", 0),
            "sensor_id": _safe_int(payload.get("sensor_id"), existing.get("sensor_id", 0)),
            "last_seen": seen_at.isoformat() + "Z",
            "last_heartbeat": seen_at.isoformat() + "Z",
            "bssid": bssid,
            "signal": _safe_int(payload.get("signal"), existing.get("signal", 0)),
            "manufacturer": merge_str("manufacturer", "Unknown Mfr"),
            "clients": clients_list,
            "clients_count": clients_count,
            "distance": merge_str("distance", "Unknown"),
            "auth": merge_str("auth", "Unknown"),
            "wps": merge_str("wps", "Unknown"),
            "encryption": merge_str("encryption", "Unknown"),
            "uptime": str(payload.get("uptime") or existing.get("uptime") or "0"),
            "frequency": merge_int("frequency", 0),
            "reasons": final_reasons,
            "score": final_score,
        }

        action = "ADD" if bssid not in _active_networks else "UPDATE"
        _active_networks[bssid] = snapshot
        return action, snapshot.copy()

def get_network(bssid: str) -> dict[str, Any] | None:
    normalized = _normalize_bssid(bssid)
    with _state_lock:
        snapshot = _active_networks.get(normalized)
        return snapshot.copy() if snapshot else None

def get_network_snapshot() -> list[dict[str, Any]]:
    with _state_lock:
        snapshot = [network.copy() for network in _active_networks.values()]
    snapshot.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
    return snapshot

def get_active_network_snapshot(*, max_age_seconds: float | None = None) -> list[dict[str, Any]]:
    threshold_seconds = NETWORK_TTL_SECONDS if max_age_seconds is None else max_age_seconds
    now = _utcnow()
    with _state_lock:
        snapshot = [
            network.copy()
            for network in _active_networks.values()
            if (now - _parse_timestamp(network.get("last_seen"))).total_seconds() <= threshold_seconds
        ]
    snapshot.sort(key=lambda item: item.get("last_seen") or "", reverse=True)
    return snapshot

def upsert_sensor(sensor_id: int, payload: dict[str, Any], *, connected: bool = True) -> tuple[str, dict[str, Any]]:
    seen_at = _utcnow()
    requested_status = str(payload.get("status") or ("online" if connected else "offline")).strip().lower()
    status = "offline" if (not connected or requested_status == "offline") else requested_status
    snapshot = {
        "sensor_id": sensor_id,
        "last_seen": seen_at.isoformat() + "Z",
        "timestamp": seen_at.isoformat() + "Z",
        "last_heartbeat": seen_at.isoformat(),
        "cpu": _safe_float(payload.get("cpu", payload.get("cpu_usage")), default=0.0),
        "memory": _safe_float(payload.get("memory", payload.get("memory_usage")), default=0.0),
        "uptime": _safe_int(payload.get("uptime"), default=0) or 0,
        "status": status,
        "connected": status != "offline",
        "interface": (str(payload.get("interface") or "").strip() or None),
        "message": (str(payload.get("message") or "").strip() or None),
        "hostname": (str(payload.get("hostname") or "").strip() or None),
        "sid": payload.get("sid"),
    }
    with _state_lock:
        action = "ADD" if sensor_id not in _active_sensors else "UPDATE"
        existing = _active_sensors.get(sensor_id, {}).copy()
        existing.update({key: value for key, value in snapshot.items() if value is not None})
        existing["sensor_id"] = sensor_id
        existing["status"] = status
        existing["connected"] = status != "offline"
        existing["last_seen"] = snapshot["last_seen"]
        existing["last_heartbeat"] = snapshot["last_heartbeat"]
        _active_sensors[sensor_id] = existing
        return action, existing.copy()

def mark_sensor_offline(sensor_id: int, *, message: str | None = None, sid: str | None = None) -> tuple[bool, dict[str, Any] | None]:
    with _state_lock:
        existing = _active_sensors.get(sensor_id)
        if existing is None:
            return False, None
        was_online = existing.get("status") != "offline" or bool(existing.get("connected"))
        updated = existing.copy()
        updated["status"] = "offline"
        updated["connected"] = False
        if message:
            updated["message"] = message
        if sid is not None:
            updated["sid"] = sid
        _active_sensors[sensor_id] = updated
        return was_online, updated.copy()

def get_sensor_snapshot() -> list[dict[str, Any]]:
    with _state_lock:
        snapshot = [sensor.copy() for sensor in _active_sensors.values()]
    snapshot.sort(key=lambda item: item["sensor_id"])
    return snapshot

def get_connected_sensors_snapshot() -> dict[int, dict[str, Any]]:
    with _state_lock:
        return {sensor_id: snapshot.copy() for sensor_id, snapshot in _active_sensors.items()}

def get_sensor(sensor_id: int) -> dict[str, Any] | None:
    with _state_lock:
        snapshot = _active_sensors.get(sensor_id)
        return snapshot.copy() if snapshot else None

def is_sensor_online(sensor_id: int) -> bool:
    snapshot = get_sensor(sensor_id)
    if snapshot is None:
        return False
    last_seen = _parse_timestamp(snapshot.get("last_seen"))
    if (_utcnow() - last_seen).total_seconds() > SENSOR_TTL_SECONDS:
        return False
    return snapshot.get("status") != "offline" and bool(snapshot.get("connected", True))

def prune_expired_state() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    now = _utcnow()
    removed_networks: list[dict[str, Any]] = []
    updated_sensors: list[dict[str, Any]] = []
    with _state_lock:
        stale_networks = [
            bssid for bssid, snapshot in _active_networks.items()
            if (now - _parse_timestamp(snapshot.get("last_seen"))).total_seconds() > NETWORK_TTL_SECONDS
        ]
        for bssid in stale_networks:
            removed_networks.append(_active_networks.pop(bssid).copy())
        for sensor_id, snapshot in list(_active_sensors.items()):
            if snapshot.get("status") == "offline":
                continue
            last_seen = _parse_timestamp(snapshot.get("last_seen"))
            if (now - last_seen).total_seconds() <= SENSOR_TTL_SECONDS:
                continue
            updated = snapshot.copy()
            updated["status"] = "offline"
            updated["connected"] = False
            updated["message"] = updated.get("message") or "Heartbeat timed out"
            _active_sensors[sensor_id] = updated
            updated_sensors.append(updated.copy())
    return removed_networks, updated_sensors
