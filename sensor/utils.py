import binascii
import json
import math
from pathlib import Path

from scapy.layers.dot11 import Dot11Beacon, Dot11Elt


_OUI_DB_PATH = Path(__file__).resolve().parent / "oui_db.json"
_OUI_CACHE: dict[str, str] = {}
_OUI_DB: dict[str, str] = {}


def _sanitize_text_bytes(value: bytes | str | None) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="ignore")
    else:
        text = str(value)

    text = text.replace("\x00", "")
    text = "".join(ch for ch in text if ch.isprintable())
    return text.strip()


def _load_oui_db() -> dict[str, str]:
    global _OUI_DB

    if _OUI_DB:
        return _OUI_DB

    try:
        with _OUI_DB_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            _OUI_DB = {str(key).upper(): str(value) for key, value in data.items()}
    except Exception:
        _OUI_DB = {}

    return _OUI_DB


def _normalize_oui(mac: str | None) -> str:
    if not mac:
        return ""
    sanitized = str(mac).strip().upper().replace("-", ":")
    parts = sanitized.split(":")
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])


def get_ssid(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            try:
                ssid = _sanitize_text_bytes(elt.info)
                return ssid if ssid else "Hidden"
            except Exception:
                return "Hidden"
        elt = elt.payload.getlayer(Dot11Elt)
    return "Hidden"


def extract_channel(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:
            try:
                if elt.info:
                    return int(elt.info[0])
            except Exception:
                pass
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def estimate_distance(pwr):
    if pwr is None:
        return -1
    try:
        dist = 10 ** ((abs(pwr) - 40) / 20)
        return round(dist, 2)
    except Exception:
        return -1


def get_auth_type(packet):
    cap = packet.getlayer(Dot11Beacon).cap
    elt = packet.getlayer(Dot11Elt)

    auth = "OPEN"
    if cap.privacy:
        auth = "WEP"

    while elt:
        if elt.ID == 48:
            auth = "WPA2"
            if "WPA3" in str(elt.info):
                auth = "WPA3"
        elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            auth = "WPA"
        elt = elt.payload.getlayer(Dot11Elt)
    return auth


def get_wps_info(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x04"):
            return "V1.0 (PBC/PIN)"
        elt = elt.payload.getlayer(Dot11Elt)
    return "N/A"


def get_manufacturer(mac):
    oui = _normalize_oui(mac)
    if not oui:
        return "Unknown"

    if oui in _OUI_CACHE:
        return _OUI_CACHE[oui]

    manufacturer = _load_oui_db().get(oui, "Unknown")
    _OUI_CACHE[oui] = manufacturer
    return manufacturer


def get_uptime(packet):
    try:
        timestamp = packet.getlayer(Dot11Beacon).timestamp
        seconds = timestamp / 1000000
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{days}d {hours}h {minutes}m"
    except Exception:
        return "Unknown"


def get_raw_beacon(packet):
    try:
        return binascii.hexlify(bytes(packet)).decode()[:100] + "..."
    except Exception:
        return ""


_load_oui_db()
