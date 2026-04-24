"""
In-memory source of truth for ZeinaGuard live state.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from typing import Any


NETWORK_TTL_SECONDS = float(os.getenv("LIVE_NETWORK_TTL_SECONDS", "60"))
SENSOR_TTL_SECONDS = float(os.getenv("LIVE_SENSOR_TTL_SECONDS", "30"))

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
        normalized_clients.append(
            {
                "mac": mac,
                "type": client_type,
            }
        )

    return normalized_clients


def upsert_network(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    bssid = _normalize_bssid(payload.get("bssid"))
    if not bssid:
        raise ValueError("network missing bssid")

    seen_at = _utcnow()
    clients = _normalize_clients(payload.get("clients"))
    snapshot = {
        "ssid": _normalize_ssid(payload.get("ssid")),
        "classification": _normalize_classification(payload.get("classification")),
        "channel": _safe_int(payload.get("channel")),
        "sensor_id": int(payload["sensor_id"]),
        "last_seen": seen_at.isoformat(),
        "timestamp": seen_at.isoformat(),
        "bssid": bssid,
        "signal": _safe_int(payload.get("signal")),
        "manufacturer": (str(payload.get("manufacturer") or "").strip() or None),
        "clients": clients,
        "clients_count": len(clients),
    }

    with _state_lock:
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
        "last_seen": seen_at.isoformat(),
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
            bssid
            for bssid, snapshot in _active_networks.items()
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
