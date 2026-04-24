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
# Interface will be set dynamically at runtime
INTERFACE = None

# TRUSTED_APS - Whitelist of known trusted wireless networks
# Structure:
# {
#     "SSID": {
#         "bssid": "MAC_ADDRESS",           # Hardware MAC address of the AP
#         "channel": INTEGER,              # WiFi channel number (1-14)
#         "encryption": "TYPE",            # "SECURED", "OPEN", "WPA2", "WPA3", etc.
#     }
# }
# To add new routers, copy the structure and update with your network details
TRUSTED_APS = {
    "AHMED": {
        "bssid": "B0:95:75:0B:A6:DA",
        "channel": 1,
        "encryption": "WPA2",
    }
}

DEAUTH_COUNT = int(os.getenv("DEAUTH_COUNT", "40"))
DEAUTH_INTERVAL = float(os.getenv("DEAUTH_INTERVAL", "0.1"))


def _linux_wireless_interfaces():
    base = Path("/sys/class/net")
    if not base.exists():
        return []

    interfaces = []
    for entry in sorted(base.iterdir()):
        if (entry / "wireless").exists():
            interfaces.append(entry.name)
    return interfaces


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
    # If no interface provided, keep INTERFACE as None for dynamic selection


def get_interface():
    return INTERFACE


def _default_interface(interfaces):
    configured = (INTERFACE or "").strip()
    if configured and configured in interfaces:
        return configured
    
    # Dynamic selection: prefer monitor mode interfaces, then first available
    for interface in interfaces:
        try:
            import subprocess
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and 'Mode:Monitor' in result.stdout:
                return interface
        except:
            continue
    
    # If no monitor mode found, return first available
    return interfaces[0] if interfaces else None


def _can_prompt_for_interface():
    if os.getenv("ZEINAGUARD_NONINTERACTIVE", "").strip() == "1":
        return False
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def select_wireless_interface():
    interfaces = list_wireless_interfaces()
    requested_interface = (os.getenv("SENSOR_INTERFACE") or "").strip()

    if not interfaces:
        if os.name == "nt":
            print("No wireless interfaces detected on Windows. Please set SENSOR_INTERFACE environment variable.")
            return None
        raise RuntimeError("No wireless interfaces detected. Set SENSOR_INTERFACE to a valid adapter before starting the sensor.")

    if requested_interface:
        requested_path = Path("/sys/class/net") / requested_interface
        if requested_interface not in interfaces and not requested_path.exists():
            raise RuntimeError(
                f"Configured SENSOR_INTERFACE '{requested_interface}' is unavailable. "
                f"Detected interfaces: {', '.join(interfaces)}"
            )
        print(f"Using configured wireless interface: {requested_interface}")
        set_interface(requested_interface)
        return INTERFACE

    selected = _default_interface(interfaces)

    if not _can_prompt_for_interface():
        print(f"Using wireless interface without prompt: {selected}")
        set_interface(selected)
        return INTERFACE

    print("Available wireless interfaces:")
    for index, interface_name in enumerate(interfaces, start=1):
        default_label = " (default)" if interface_name == selected else ""
        # Try to get interface status
        try:
            import subprocess
            result = subprocess.run(['iwconfig', interface_name], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Extract mode from iwconfig output
                for line in result.stdout.split('\n'):
                    if 'Mode:' in line:
                        mode = line.split('Mode:')[1].split()[0]
                        default_label += f" - Mode: {mode}"
                        break
            else:
                default_label += " - Status: Unknown"
        except:
            default_label += " - Status: Unknown"
        
        print(f"  {index}. {interface_name}{default_label}")

    choice = input(
        f"Choose interface [1-{len(interfaces)}] or press Enter for {selected}: "
    ).strip()
    if not choice:
        print(f"Using interface: {selected}")
        set_interface(selected)
        return INTERFACE

    try:
        selected = interfaces[int(choice) - 1]
    except (ValueError, IndexError):
        selected = choice if choice in interfaces else _default_interface(interfaces)

    print(f"Using interface: {selected}")
    set_interface(selected)
    return INTERFACE
