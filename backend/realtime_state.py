from __future__ import annotations

import os
import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.append(str(Path(__file__).resolve().parent.parent / "sensor"))
from config import get_trusted_macs

NETWORK_TTL_SECONDS = float(os.getenv("LIVE_NETWORK_TTL_SECONDS", "30"))
SENSOR_TTL_SECONDS = float(os.getenv("LIVE_SENSOR_TTL_SECONDS", "30"))
_BASELINE_MAX_ENTRIES: int = int(os.getenv("BASELINE_MAX_ENTRIES", "5000"))

_state_lock = threading.Lock()
_active_networks: dict[str, dict[str, Any]] = {}
_active_sensors: dict[int, dict[str, Any]] = {}
_ssid_index: dict[str, set[str]] = {}
_bssid_channel_baseline: dict[str, int] = {}
_bssid_security_baseline: dict[str, str] = {}
_bssid_sensor_observations: dict[str, dict[int, dict[str, Any]]] = {}

_CLASSIFICATION_RANK: dict[str, int] = {
    "ROGUE": 3,
    "SUSPICIOUS": 2,
    "LEGIT": 1,
    "UNKNOWN": 0,
}


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

_OPEN_ENCRYPTION_VALS: frozenset[str] = frozenset({"OPEN", "OPN", "NONE", "NOAUTH", ""})
_ENCRYPTED_MARKERS: tuple[str, ...] = ("WPA", "WEP", "802.1X", "PSK", "CCMP", "TKIP", "EAP")


def _enc_is_open(enc: str) -> bool:
    return enc.strip().upper() in _OPEN_ENCRYPTION_VALS


def _enc_is_encrypted(enc: str) -> bool:
    upper = enc.strip().upper()
    return any(marker in upper for marker in _ENCRYPTED_MARKERS)


def _is_security_degraded(old_enc: str, new_enc: str) -> bool:
    return _enc_is_encrypted(old_enc) and _enc_is_open(new_enc)


def _evict_baseline(baseline: dict, max_entries: int) -> None:
    overflow = len(baseline) - max_entries
    if overflow <= 0:
        return
    for key in list(baseline.keys())[:overflow]:
        del baseline[key]


def _resolve_consensus(
    observations: dict[int, dict[str, Any]],
    *,
    trusted: bool,
) -> dict[str, Any]:
    if not observations:
        return {
            "classification": "LEGIT" if trusted else "UNKNOWN",
            "sensor_id": 0,
            "signal": 0,
        }

    best_sensor_id: int = 0
    best_rssi: int = -9999
    top_rank: int = -1
    top_classification: str = "UNKNOWN"

    for sid, obs in observations.items():
        rssi: int = _safe_int(obs.get("rssi"), default=0) or 0
        raw_cls: str = str(obs.get("classification") or "UNKNOWN").strip().upper()
        rank: int = _CLASSIFICATION_RANK.get(raw_cls, 0)

        if rank > top_rank:
            top_rank = rank
            top_classification = raw_cls

        if rssi > best_rssi:
            best_rssi = rssi
            best_sensor_id = sid

    if trusted:
        final_cls = "LEGIT"
    elif top_classification and top_classification != "UNKNOWN":
        final_cls = top_classification
    else:
        final_cls = "LEGIT"

    return {
        "classification": final_cls,
        "sensor_id": best_sensor_id,
        "signal": best_rssi if best_rssi > -9999 else 0,
    }


def get_best_sensor_for_bssid(bssid: str) -> int | None:
    normalized = _normalize_bssid(bssid)
    if not normalized:
        return None
    with _state_lock:
        observations = dict(_bssid_sensor_observations.get(normalized) or {})
    if not observations:
        return None
    best = max(
        observations.items(),
        key=lambda kv: (_safe_int(kv[1].get("rssi"), default=-9999) or -9999),
    )
    return int(best[0])


def force_trust_bssid(bssid: str) -> None:
    pass

def is_bssid_trusted(bssid: str) -> bool:
    if not bssid:
        return False
    normalized = _normalize_bssid(bssid)
    return normalized in get_trusted_macs()

def upsert_network(
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    
    # CRITICAL EXCLUSION: Actively ignore timestamps from stateless sensor
    payload.pop("first_seen", None)
    payload.pop("created_at", None)
    payload.pop("last_seen", None)
    payload.pop("updated_at", None)
    payload.pop("timestamp", None)

    bssid = _normalize_bssid(payload.get("bssid"))
    if not bssid:
        raise ValueError("network missing bssid")

    seen_at = _utcnow()

    with _state_lock:
        existing = _active_networks.get(bssid, {})
        # Determine ADD vs UPDATE before any mutation so anomaly checks know context.
        action = "ADD" if bssid not in _active_networks else "UPDATE"

        def merge_str(key: str, default: str = "Unknown") -> str:
            new_val = str(payload.get(key) or "").strip()
            old_val = str(existing.get(key) or "").strip()

            # --- SSID AMNESIA PROTECTION ---
            if key == "ssid":
                if old_val and old_val.lower() not in ["none", "unknown", "n/a", "", "hidden"]:
                    if not new_val or new_val.lower() in ["none", "unknown", "n/a", "", "hidden"]:
                        return old_val

            if new_val and new_val.lower() not in ["none", "unknown", "n/a", ""]:
                return new_val
            if old_val and old_val.lower() not in ["none", "unknown", "n/a", ""]:
                return old_val
            return default

        def merge_int(key: str, default: int = 0) -> int:
            new_val = _safe_int(payload.get(key))
            if new_val and new_val > 0:
                return new_val
            return _safe_int(existing.get(key), default)

        raw_clients = payload.get("clients")
        incoming_clients_count = _safe_int(payload.get("clients_count"))

        clients_list = existing.get("clients", [])
        clients_count = existing.get("clients_count", 0)

        if isinstance(raw_clients, list):
            clients_list = _normalize_clients(raw_clients)
            clients_count = len(clients_list)
        elif incoming_clients_count is not None:
            clients_count = max(incoming_clients_count, 0)
            if clients_count == 0:
                clients_list = []
        elif isinstance(raw_clients, (int, float)):
            clients_count = max(int(raw_clients), 0)
            if clients_count == 0:
                clients_list = []


        is_currently_trusted = is_bssid_trusted(bssid)
        if is_currently_trusted:
            final_classification = "LEGIT"
            final_score = 0
            final_reasons: list[str] = []
        else:
            incoming_data_class = payload.get("classification")

            if incoming_data_class:
                final_classification = _normalize_classification(incoming_data_class)
            else:
                old_class = existing.get("classification", "SUSPICIOUS")
                final_classification = "SUSPICIOUS" if old_class == "LEGIT" else old_class

            final_score = _safe_int(payload.get("score"), existing.get("score", 0))
            final_reasons = payload.get("reasons") or existing.get("reasons", [])

        incoming_sensor_id: int = _safe_int(payload.get("sensor_id"), existing.get("sensor_id", 0)) or 0
        incoming_rssi: int = _safe_int(payload.get("signal"), existing.get("signal", 0)) or 0
        raw_incoming_class: str = _normalize_classification(payload.get("classification")) if payload.get("classification") else final_classification

        if incoming_sensor_id:
            _bssid_sensor_observations.setdefault(bssid, {})[incoming_sensor_id] = {
                "rssi": incoming_rssi,
                "classification": raw_incoming_class,
                "last_seen": seen_at,
            }

        consensus = _resolve_consensus(
            _bssid_sensor_observations.get(bssid, {}),
            trusted=is_currently_trusted,
        )
        final_classification = consensus["classification"]
        consensus_sensor_id: int = consensus["sensor_id"] or incoming_sensor_id
        consensus_signal: int = consensus["signal"] if consensus["signal"] != 0 else incoming_rssi

        snapshot = {
            "ssid": merge_str("ssid", "Hidden"),
            "classification": final_classification,
            "channel": merge_int("channel", 0),
            "sensor_id": consensus_sensor_id,
            "last_seen": seen_at.isoformat() + "Z",
            "last_heartbeat": seen_at.isoformat() + "Z",
            "bssid": bssid,
            "signal": consensus_signal,
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

        _active_networks[bssid] = snapshot

        # ------------------------------------------------------------------
        # Anomaly detection:
        # ------------------------------------------------------------------
        anomalies: list[dict[str, Any]] = []
        ssid = snapshot["ssid"]
        channel = snapshot["channel"]
        encryption = snapshot["encryption"]

        enc_upper = encryption.strip().upper() if encryption else ""
        enc_is_known = enc_upper and enc_upper not in ("UNKNOWN", "N/A")

        # SSIDs that are too generic to serve as evil-twin fingerprints.
        ssid_is_trivial = not ssid or ssid.lower() in ("hidden", "unknown", "")

        if action == "ADD":
            # SSID collision / Evil Twin check
            if not ssid_is_trivial:
                # Check BOTH: active networks AND trusted file for this SSID
                existing_bssids_for_ssid: set[str] = _ssid_index.get(ssid, set()).copy()

                # Also check trusted file for networks with same SSID
                from config import get_trusted_networks_dict
                trusted_dict = get_trusted_networks_dict()
                for trusted_bssid, trusted_ssid in trusted_dict.items():
                    if trusted_ssid == ssid:
                        existing_bssids_for_ssid.add(trusted_bssid)

                if existing_bssids_for_ssid and bssid not in existing_bssids_for_ssid:
                    if not is_currently_trusted:
                        trusted_originals = [
                            b for b in existing_bssids_for_ssid if is_bssid_trusted(b)
                        ]
                        # Only alert if there's a trusted original with this SSID
                        if trusted_originals:
                            anomalies.append({
                                "type": "evil_twin_suspected",
                                "data": {
                                    "bssid": bssid,
                                    "ssid": ssid,
                                    "channel": channel,
                                    "signal": snapshot.get("signal"),
                                    "known_bssids": sorted(existing_bssids_for_ssid),
                                    "trusted_originals": trusted_originals,
                                    "is_high_confidence": True,
                                    "classification": final_classification,
                                    "score": final_score,
                                    "timestamp": seen_at.isoformat() + "Z",
                                },
                            })

                # Register this BSSID under its SSID regardless of alert outcome.
                _ssid_index.setdefault(ssid, set()).add(bssid)

            # record baselines on first observation
            if channel and channel > 0:
                _bssid_channel_baseline[bssid] = channel
            if enc_is_known:
                _bssid_security_baseline[bssid] = enc_upper

        elif action == "UPDATE":
            # channel consistency check
            baseline_channel = _bssid_channel_baseline.get(bssid)
            if baseline_channel and channel and channel > 0:
                channel_delta = abs(channel - baseline_channel)
                if channel_delta > 2:
                    # Channel moved by more than ±2 — too large to be routine ACS.
                    anomalies.append({
                        "type": "trusted_ap_anomaly",
                        "data": {
                            "bssid": bssid,
                            "ssid": ssid,
                            "is_trusted": is_currently_trusted,
                            "anomaly_kind": "channel_change",
                            "baseline_value": baseline_channel,
                            "current_value": channel,
                            "delta": channel_delta,
                            "timestamp": seen_at.isoformat() + "Z",
                        },
                    })
                    # Advance the baseline so we don't re-fire on every subsequent scan.
                    _bssid_channel_baseline[bssid] = channel

            # security degradation check
            baseline_encryption = _bssid_security_baseline.get(bssid)
            if baseline_encryption and enc_is_known:
                if _is_security_degraded(baseline_encryption, enc_upper):
                    anomalies.append({
                        "type": "trusted_ap_anomaly",
                        "data": {
                            "bssid": bssid,
                            "ssid": ssid,
                            "is_trusted": is_currently_trusted,
                            "anomaly_kind": "security_degradation",
                            "baseline_value": baseline_encryption,
                            "current_value": enc_upper,
                            "timestamp": seen_at.isoformat() + "Z",
                        },
                    })
                    # Advance the baseline to the new (degraded) state.
                    _bssid_security_baseline[bssid] = enc_upper

        return action, snapshot.copy(), anomalies

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
        "last_heartbeat": seen_at.isoformat() + "Z",
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

def periodic_evil_twin_scan() -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    seen_at = _utcnow()

    with _state_lock:
        from config import get_trusted_networks_dict
        trusted_dict = get_trusted_networks_dict()

        if not trusted_dict:
            return anomalies

        trusted_bssids_normalized: set[str] = {
            _normalize_bssid(b) for b in trusted_dict.keys()
        }

        # SSID comparison is intentionally case-sensitive: "AHMED" ≠ "ahmed".
        trusted_ssid_to_bssids: dict[str, list[str]] = {}
        for t_bssid, t_ssid in trusted_dict.items():
            if not t_ssid:
                continue
            normalized_t_bssid = _normalize_bssid(t_bssid)
            trusted_ssid_to_bssids.setdefault(t_ssid, []).append(normalized_t_bssid)

        # Check every active non-trusted network
        for bssid, network in _active_networks.items():
            # Skip if this AP is itself a trusted device
            if bssid in trusted_bssids_normalized:
                continue

            ssid = network.get("ssid", "")
            if not ssid or ssid.lower() in ("hidden", "unknown", "", "none"):
                continue

            # Evil twin: exact case-sensitive SSID match against a trusted network name.
            # "AHMED" and "ahmed" are different SSIDs and must NOT trigger a false positive.
            if ssid in trusted_ssid_to_bssids:
                trusted_originals = trusted_ssid_to_bssids[ssid]
                anomalies.append({
                    "type": "evil_twin_suspected",
                    "data": {
                        "bssid": bssid,
                        "ssid": ssid,
                        "channel": network.get("channel"),
                        "signal": network.get("signal"),
                        "known_bssids": sorted(trusted_originals),
                        "trusted_originals": trusted_originals,
                        "is_high_confidence": True,
                        "classification": network.get("classification", "UNKNOWN"),
                        "score": network.get("score", 0),
                        "timestamp": seen_at.isoformat() + "Z",
                    },
                })

    return anomalies


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
            stale_snapshot = _active_networks.pop(bssid)
            removed_networks.append(stale_snapshot.copy())
            stale_ssid = stale_snapshot.get("ssid", "")
            if stale_ssid and stale_ssid in _ssid_index:
                _ssid_index[stale_ssid].discard(bssid)
                if not _ssid_index[stale_ssid]:
                    del _ssid_index[stale_ssid]

        _evict_baseline(_bssid_channel_baseline, _BASELINE_MAX_ENTRIES)
        _evict_baseline(_bssid_security_baseline, _BASELINE_MAX_ENTRIES)


        for _expired_bssid in stale_networks:
            _bssid_sensor_observations.pop(_expired_bssid, None)
        for _obs_bssid, _sensor_obs in list(_bssid_sensor_observations.items()):
            _stale_sids = [
                _sid for _sid, _obs in _sensor_obs.items()
                if (now - _parse_timestamp(_obs.get("last_seen"))).total_seconds() > NETWORK_TTL_SECONDS
            ]
            for _sid in _stale_sids:
                del _sensor_obs[_sid]
            if not _sensor_obs:
                _bssid_sensor_observations.pop(_obs_bssid, None)

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
