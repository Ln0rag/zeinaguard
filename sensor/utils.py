import binascii
import json
import math
import re
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
        if _OUI_DB_PATH.exists():
            with _OUI_DB_PATH.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
                _OUI_DB = {}
                for key, value in data.items():
                    normalized_key = _normalize_oui(str(key))
                    if normalized_key:
                        _OUI_DB[normalized_key] = str(value).strip()
    except Exception:
        _OUI_DB = {}
    return _OUI_DB


def _normalize_oui(mac: str | None) -> str:
    if not mac:
        return ""
    hex_value = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    if len(hex_value) < 6:
        return ""
    return ":".join(hex_value[index:index + 2] for index in range(0, 6, 2))


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
    # Try DS Parameter Set first (ID 3)
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:
            try:
                if elt.info:
                    return int(elt.info[0])
            except Exception:
                pass
        elt = elt.payload.getlayer(Dot11Elt)
        
    # Fallback to radio tap header or Frequency if needed, but usually ID 3 is enough
    if hasattr(packet, "Channel"):
        return int(packet.Channel)
    return None


def estimate_distance(pwr):
    if pwr is None or pwr == 0:
        return "Unknown"
    # FSPL Formula for better accuracy
    try:
        freq = 2412 # Default to 2.4Ghz if not known
        exp = (27.55 - (20 * math.log10(freq)) + abs(pwr)) / 20.0
        dist = math.pow(10.0, exp)
        return f"~{round(dist, 1)}m"
    except Exception:
        return "Unknown"


def get_auth_type(packet):
    cap = packet.getlayer(Dot11Beacon).cap
    elt = packet.getlayer(Dot11Elt)

    auth = "OPEN"
    if cap.privacy:
        auth = "WEP"

    while elt:
        if elt.ID == 48:
            auth = "WPA2"
            if b"WPA3" in elt.info or b"\x00\x0f\xac\x08" in elt.info: # Check RSN for SAE (WPA3)
                auth = "WPA3"
        elif elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            if auth == "OPEN" or auth == "WEP": # Don't override WPA2/3
                auth = "WPA"
        elt = elt.payload.getlayer(Dot11Elt)
    return auth


def get_wps_info(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 221 and elt.info.startswith(b"\x00P\xf2\x04"):
            return "Active"
        elt = elt.payload.getlayer(Dot11Elt)
    return "Disabled"

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
        # Return Raw seconds for the Backend to process properly
        timestamp = packet.getlayer(Dot11Beacon).timestamp
        seconds = int(timestamp / 1000000)
        return str(seconds)
    except Exception:
        return "0"


def get_raw_beacon(packet):
    try:
        return binascii.hexlify(bytes(packet)).decode()[:100] + "..."
    except Exception:
        return ""

_load_oui_db()
