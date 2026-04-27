import os
import sys
from pathlib import Path
from urllib.parse import urlparse

BACKEND_URL = os.getenv("BACKEND_URL", os.getenv("ZEINAGUARD_BACKEND_URL", "http://localhost:5000"))
_parsed_backend_url = urlparse(BACKEND_URL)
BACKEND_HOST = _parsed_backend_url.hostname or "localhost"
BACKEND_PORT = _parsed_backend_url.port or 5000

ENV_INTERFACE = (os.getenv("SENSOR_INTERFACE") or "").strip()
LOCKED_CHANNEL = None
INTERFACE = None

# TRUSTED_APS - Whitelist of known trusted wireless networks
TRUSTED_BSSIDS = [
    "38:54:9B:36:F7:BC", # name:2.4ghz
    "60:E3:27:67:90:E8", # name:0
    "B0:95:75:0B:A6:DA", # name:AHMED
]


DEAUTH_COUNT = int(os.getenv("DEAUTH_COUNT", "40"))
DEAUTH_INTERVAL = float(os.getenv("DEAUTH_INTERVAL", "0.1"))


def _linux_wireless_interfaces():
    base = Path("/sys/class/net")
    if not base.exists():
        return []

    return [entry.name for entry in base.iterdir() if (entry / "wireless").exists()]


def list_wireless_interfaces():
    interfaces = _linux_wireless_interfaces()
    if not interfaces and os.name == "nt" and INTERFACE:
        return [INTERFACE]
    return interfaces


def set_interface(interface_name):
    global INTERFACE
    if interface_name and interface_name.strip():
        INTERFACE = interface_name.strip()
        os.environ["SENSOR_INTERFACE"] = INTERFACE


def get_interface():
    return INTERFACE


def _default_interface(interfaces):
    configured = (INTERFACE or "").strip()
    if configured and configured in interfaces:
        return configured

    for interface in interfaces:
        try:
            import subprocess
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                return interface
        except:
            continue

    return interfaces[0] if interfaces else None


def select_wireless_interface():
    interfaces = list_wireless_interfaces()
    requested_interface = (os.getenv("SENSOR_INTERFACE") or "").strip()

    if not interfaces:
        raise RuntimeError("No wireless interfaces detected.")

    if requested_interface:
        set_interface(requested_interface)
        return INTERFACE

    selected = _default_interface(interfaces)
    set_interface(selected)
    return INTERFACE
