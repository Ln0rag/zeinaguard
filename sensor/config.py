import os
import json
import threading
from pathlib import Path
from urllib.parse import urlparse

BACKEND_URL = os.getenv("BACKEND_URL", os.getenv("ZEINAGUARD_BACKEND_URL", "http://localhost:5000"))
_parsed_backend_url = urlparse(BACKEND_URL)
BACKEND_HOST = _parsed_backend_url.hostname or "localhost"
BACKEND_PORT = _parsed_backend_url.port or 5000

ENV_INTERFACE = (os.getenv("SENSOR_INTERFACE") or "").strip()
LOCKED_CHANNEL = None
INTERFACE = None

DEAUTH_COUNT = int(os.getenv("DEAUTH_COUNT", "40"))
DEAUTH_INTERVAL = float(os.getenv("DEAUTH_INTERVAL", "0.1"))

# --- Single Source of Truth API ---
ROOT_DIR = Path(__file__).resolve().parent.parent
TRUSTED_FILE = ROOT_DIR / "backend" / "trusted.json"

BUILTIN_TRUSTED_MACS = {
    # "MAC_ADDRESS": "NETWORK_NAME",
}

_config_lock = threading.Lock()
_trusted_macs_cache = {}
_last_mtime = 0.0

def normalize_mac(mac: str) -> str:
    return str(mac or "").strip().upper().replace("-", ":")

def _read_trusted_json() -> dict:
    trusted = {normalize_mac(k): str(v) for k, v in BUILTIN_TRUSTED_MACS.items()}
    if not TRUSTED_FILE.exists():
        return trusted
    try:
        data = json.loads(TRUSTED_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for m in data:
                if m: trusted[normalize_mac(m)] = "Unknown Network"
        elif isinstance(data, dict):
            for m, name in data.items():
                if m: trusted[normalize_mac(m)] = str(name or "Unknown Network")
        return trusted
    except (OSError, json.JSONDecodeError):
        return trusted

def get_trusted_macs() -> dict:
    global _trusted_macs_cache, _last_mtime
    with _config_lock:
        try:
            current_mtime = os.path.getmtime(TRUSTED_FILE) if TRUSTED_FILE.exists() else 0.0
        except OSError:
            current_mtime = 0.0

        if current_mtime > _last_mtime or not _trusted_macs_cache:
            _trusted_macs_cache = _read_trusted_json()
            _last_mtime = current_mtime
            
        return _trusted_macs_cache.copy()

def save_trusted_macs(macs_dict: dict):
    global _trusted_macs_cache, _last_mtime
    with _config_lock:
        TRUSTED_FILE.parent.mkdir(parents=True, exist_ok=True)
        temp_file = TRUSTED_FILE.with_suffix(".tmp")
        temp_file.write_text(json.dumps(macs_dict, indent=2) + "\n", encoding="utf-8")
        os.replace(temp_file, TRUSTED_FILE)
        
        _trusted_macs_cache = macs_dict.copy()
        try:
            _last_mtime = os.path.getmtime(TRUSTED_FILE)
        except OSError:
            pass

def add_trusted_mac(mac: str, ssid: str = "") -> bool:
    macs = get_trusted_macs()
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    
    network_name = ssid.strip() if ssid else "Unknown Network"
    if normalized in macs and macs[normalized] == network_name:
        return False
        
    macs[normalized] = network_name
    save_trusted_macs(macs)
    return True

def remove_trusted_mac(mac: str) -> bool:
    macs = get_trusted_macs()
    normalized = normalize_mac(mac)
    
    if normalized in {normalize_mac(k) for k in BUILTIN_TRUSTED_MACS}:
        return False
        
    if normalized not in macs:
        return False
        
    del macs[normalized]
    save_trusted_macs(macs)
    return True

# --- Interface Management (Preserved) ---
def _linux_wireless_interfaces():
    base = Path("/sys/class/net")
    return [entry.name for entry in base.iterdir() if (entry / "wireless").exists()] if base.exists() else []

def list_wireless_interfaces():
    interfaces = _linux_wireless_interfaces()
    return [INTERFACE] if not interfaces and os.name == "nt" and INTERFACE else interfaces

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