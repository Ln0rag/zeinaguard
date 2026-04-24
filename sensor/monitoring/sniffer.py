from datetime import datetime
import logging
import os
import threading
import time

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon

import config
from core.event_bus import event_queue
from runtime_state import update_status
from utils import (
    estimate_distance,
    extract_channel,
    get_auth_type,
    get_manufacturer,
    get_raw_beacon,
    get_ssid,
    get_uptime,
    get_wps_info,
)


clients_map = {}
aps_state = {}
LOGGER = logging.getLogger("zeinaguard.sensor.sniffer")

AP_TIMEOUT = 60
START_TIME = time.time()
FIRST_PACKET = True


def is_open_network(packet):
    if packet.haslayer(Dot11Beacon):
        cap = packet[Dot11Beacon].cap
        return not cap.privacy
    return False


def build_event(packet):
    global FIRST_PACKET

    if FIRST_PACKET:
        update_status(sensor_status="capturing", message="First WiFi packet captured")
        FIRST_PACKET = False

    dot11 = packet[Dot11]
    bssid = dot11.addr2
    ssid = get_ssid(packet)
    channel = extract_channel(packet)
    signal = getattr(packet, "dBm_AntSignal", None)
    clients_count = len(clients_map.get(bssid, set()))

    return {
        "timestamp": datetime.now().isoformat(),
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "signal": signal,
        "distance": estimate_distance(signal),
        "auth": get_auth_type(packet),
        "wps": get_wps_info(packet),
        "manufacturer": get_manufacturer(bssid),
        "uptime": get_uptime(packet),
        "raw_beacon": get_raw_beacon(packet),
        "elapsed_time": round(time.time() - START_TIME, 2),
        "encryption": "OPEN" if is_open_network(packet) else "SECURED",
        "clients": clients_count,
    }


def handle_packet(packet):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if packet.haslayer(Dot11Beacon) and dot11.addr2:
        event = build_event(packet)
        bssid = event["bssid"]
        aps_state[bssid] = {
            "last_seen": time.time(),
            "event": event,
        }
        event_queue.put(event)

    if dot11.type == 2:
        bssid = dot11.addr3
        src = dot11.addr2
        if bssid and src and bssid != src:
            clients_map.setdefault(bssid, set()).add(src)


def ap_cleaner():
    while True:
        now = time.time()

        for bssid in list(aps_state.keys()):
            if now - aps_state[bssid]["last_seen"] > AP_TIMEOUT:
                del aps_state[bssid]
                event_queue.put(
                    {
                        "type": "AP_REMOVED",
                        "bssid": bssid,
                    }
                )

        time.sleep(5)


def channel_hopper():
    import config

    while True:
        if config.LOCKED_CHANNEL is not None:
            os.system(f"iwconfig {config.get_interface()} channel {config.LOCKED_CHANNEL} 2>/dev/null")
            time.sleep(1)
            continue

        for ch in range(1, 14):
            if config.LOCKED_CHANNEL is not None:
                break

            os.system(f"iwconfig {config.get_interface()} channel {ch} 2>/dev/null")
            time.sleep(0.4)


def start_monitoring():
    interface_name = config.get_interface()

    if os.name != "nt" and not os.path.exists(f"/sys/class/net/{interface_name}"):
        detected_interfaces = config.list_wireless_interfaces()
        detected_summary = ", ".join(detected_interfaces) if detected_interfaces else "none"
        message = f"Interface not found: {interface_name}. Detected interfaces: {detected_summary}"
        update_status(sensor_status="error", message=message)
        raise RuntimeError(message)

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        message = "Root privileges required for sniffing"
        update_status(sensor_status="error", message=message)
        raise PermissionError(message)

    threading.Thread(target=channel_hopper, daemon=True).start()
    threading.Thread(target=ap_cleaner, daemon=True).start()
    update_status(sensor_status="monitoring", message=f"Sniffing on {interface_name}")
    LOGGER.info("[Sensor] Starting packet capture on interface=%s", interface_name)

    try:
        sniff(iface=interface_name, prn=handle_packet, store=False)
    except Exception as exc:
        message = f"Sniffing failed on {interface_name}: {exc}"
        update_status(sensor_status="error", message=message)
        raise RuntimeError(message) from exc

    message = f"Packet capture stopped unexpectedly on {interface_name}"
    update_status(sensor_status="error", message=message)
    raise RuntimeError(message)
