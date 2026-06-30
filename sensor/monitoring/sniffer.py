from datetime import datetime
import logging
import os
import subprocess
import threading
import time

from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeResp
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
CLIENT_TIMEOUT = float(os.getenv("CLIENT_ACTIVITY_TIMEOUT_SECONDS", "10"))
START_TIME = time.time()
FIRST_PACKET = True


def is_open_network(packet):
    if packet.haslayer(Dot11Beacon):
        cap = packet[Dot11Beacon].cap
        return not cap.privacy
    return False


def _normalize_mac(value):
    if not value:
        return ""
    # Ensure consistent uppercase with colons
    return str(value).strip().upper().replace("-", ":")


def _is_group_mac(value):
    normalized = _normalize_mac(value)
    if not normalized or normalized == "FF:FF:FF:FF:FF:FF":
        return True
    try:
        # Check first octet for multicast bit
        first_octet = int(normalized.split(":")[0], 16)
        return bool(first_octet & 1)
    except Exception:
        return True


def _prune_clients(bssid, now=None):
    normalized_bssid = _normalize_mac(bssid)
    if not normalized_bssid:
        return
    now = time.time() if now is None else now
    clients = clients_map.get(normalized_bssid)
    if not clients:
        return
    
    stale_clients = [
        mac for mac, last_seen in clients.items()
        if now - last_seen > CLIENT_TIMEOUT
    ]
    
    for mac in stale_clients:
        LOGGER.info("[CLIENT REMOVE] BSSID=%s MAC=%s (timeout)", normalized_bssid, mac)
        clients.pop(mac, None)
        
    if not clients:
        clients_map.pop(normalized_bssid, None)


def _active_clients(bssid):
    normalized_bssid = _normalize_mac(bssid)
    _prune_clients(normalized_bssid)
    return clients_map.get(normalized_bssid, {})


def _extract_client_observation(dot11):
    # FCfield bit 0: ToDS, bit 1: FromDS
    to_ds = bool(int(dot11.FCfield) & 0x1)
    from_ds = bool(int(dot11.FCfield) & 0x2)

    # Simplified logic for identifying Client -> AP or AP -> Client
    if to_ds and not from_ds:
        # Client to AP: addr1=BSSID, addr2=SA(Client), addr3=DA
        bssid = dot11.addr1
        client = dot11.addr2
    elif from_ds and not to_ds:
        # AP to Client: addr1=DA(Client), addr2=BSSID, addr3=SA
        bssid = dot11.addr2
        client = dot11.addr1
    elif not to_ds and not from_ds:
        # Ad-hoc or Management? addr1=DA, addr2=SA, addr3=BSSID
        bssid = dot11.addr3
        client = dot11.addr2
    else:
        # Mesh / WDS
        bssid = dot11.addr3
        client = dot11.addr2

    bssid = _normalize_mac(bssid)
    client = _normalize_mac(client)
    
    if not bssid or not client or bssid == client or _is_group_mac(client) or _is_group_mac(bssid):
        return None, None
        
    return bssid, client


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
    clients_count = len(_active_clients(bssid))

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
        "encryption": "OPEN" if is_open_network(packet) else "UNKNOWN",
        "clients": clients_count,
    }


def handle_packet(packet):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if packet.haslayer(Dot11Beacon) and dot11.addr2:
        event = build_event(packet)
        bssid = event["bssid"]
        
        now = time.time()
        if bssid in aps_state:
            old_state = aps_state[bssid]
            old_event = old_state.get("event", {})
            
            # --- SSID AMNESIA PROTECTION ---
            old_ssid = old_event.get("ssid", "")
            new_ssid = event.get("ssid", "")
            
            if old_ssid and old_ssid not in ["Hidden", ""]:
                if not new_ssid or new_ssid in ["Hidden", ""]:
                    event["ssid"] = old_ssid
            
            # Always update physical reality
            aps_state[bssid]["last_seen"] = now
            aps_state[bssid]["event"] = event
            
            # Rate limit pushing to event queue to max 1 per second per AP
            if now - old_state.get("last_sent", 0) < 1.0:
                return
        else:
            aps_state[bssid] = {
                "last_seen": now,
                "last_sent": 0,
                "event": event,
            }
        
        aps_state[bssid]["last_sent"] = now
        event_queue.put(event)

    if packet.haslayer(Dot11ProbeResp) and dot11.addr2:
        bssid = dot11.addr2 
        if bssid in aps_state:
            old_ssid = aps_state[bssid]["event"].get("ssid", "Hidden")
            
            if old_ssid == "Hidden" or not old_ssid.strip():
                real_ssid = get_ssid(packet)
                if real_ssid and real_ssid != "Hidden":
                    LOGGER.info("[UNMASKED] Hidden network %s is actually '%s'", bssid, real_ssid)
                    aps_state[bssid]["event"]["ssid"] = real_ssid
                    event_queue.put(aps_state[bssid]["event"])

    if dot11.type == 2:
        bssid, client = _extract_client_observation(dot11)
        if bssid and client:
            clients_map.setdefault(bssid, {})[client] = time.time()

    # Deauthentication frames (management type=0, subtype=12).
    # Routed to the DeauthDetector via the event queue using the existing typed-event
    # pattern (same as AP_REMOVED).  addr3 is the authoritative BSSID field.

    if packet.haslayer(Dot11Deauth):
        addr3_val = dot11.addr3 or ""
        addr2_val = dot11.addr2 or ""
        addr1_val = dot11.addr1 or ""
        rssi_val  = getattr(packet, "dBm_AntSignal", None)
        sc_val    = int(dot11.SC) if dot11.SC is not None else 0
        reason_val = int(packet[Dot11Deauth].reason)

        LOGGER.info(
            "[SNIFFER] Dot11Deauth captured | addr1=%s addr2=%s addr3=%s "
            "sc=%s rssi=%s reason=%d addr3_present=%s",
            addr1_val, addr2_val, addr3_val, sc_val, rssi_val, reason_val,
            bool(addr3_val),
        )

        if not addr3_val:
            LOGGER.warning(
                "[SNIFFER] Deauth frame dropped — addr3 (BSSID) is empty | "
                "addr1=%s addr2=%s reason=%d",
                addr1_val, addr2_val, reason_val,
            )
        else:
            deauth_event = {
                "type": "DEAUTH_FRAME",
                "addr1": addr1_val,
                "addr2": addr2_val,
                "addr3": addr3_val,
                "sc": sc_val,
                "rssi": rssi_val,
                "reason": reason_val,
            }
            try:
                event_queue.put_nowait(deauth_event)
                LOGGER.info(
                    "[SNIFFER] DEAUTH_FRAME queued | addr3=%s reason=%d rssi=%s qsize~=%d",
                    addr3_val, reason_val, rssi_val, event_queue.qsize(),
                )
            except Exception:
                try:
                    event_queue.put(deauth_event, timeout=0.1)
                    LOGGER.info(
                        "[SNIFFER] DEAUTH_FRAME queued (after wait) | addr3=%s", addr3_val,
                    )
                except Exception:
                    LOGGER.error(
                        "[SNIFFER] DEAUTH_FRAME DROPPED — event_queue full (size=%d) | "
                        "addr3=%s reason=%d",
                        event_queue.qsize(), addr3_val, reason_val,
                    )


def ap_cleaner():
    while True:
        now = time.time()

        for bssid in list(aps_state.keys()):
            _prune_clients(bssid, now)
            if now - aps_state[bssid]["last_seen"] > AP_TIMEOUT:
                del aps_state[bssid]
                clients_map.pop(_normalize_mac(bssid), None)
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


def hardware_watchdog():
    import config
    while True:
        time.sleep(3)
        iface = config.get_interface()
        if not iface:
            continue

        try:
            result = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
            
            if 'No such device' in result.stderr:
                update_status(
                    sensor_status="error", 
                    message=f"Adapter {iface} physically disconnected. Waiting..."
                )
                continue

            if 'Mode:Monitor' not in result.stdout:
                update_status(
                    sensor_status="warning", 
                    message=f"Auto-healing: Forcing {iface} into Monitor mode..."
                )
                
                # Tell NetworkManager to stop fighting us
                subprocess.run(['nmcli', 'device', 'set', iface, 'managed', 'no'], check=False)
                
                subprocess.run(['ip', 'link', 'set', iface, 'down'], check=False)
                time.sleep(0.5)
                subprocess.run(['iwconfig', iface, 'mode', 'monitor'], check=False)
                time.sleep(0.5)
                subprocess.run(['ip', 'link', 'set', iface, 'up'], check=False)
                
                verify = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
                if 'Mode:Monitor' in verify.stdout:
                    update_status(
                        sensor_status="monitoring", 
                        message=f"Auto-heal successful: {iface} is now in Monitor mode"
                    )
                else:
                    update_status(
                        sensor_status="error", 
                        message=f"Auto-heal failed: Could not set {iface} to Monitor mode"
                    )
            else:
                ip_res = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
                if 'state DOWN' in ip_res.stdout or ',UP' not in ip_res.stdout and '<UP' not in ip_res.stdout:
                    update_status(
                        sensor_status="warning", 
                        message=f"Auto-healing: Interface {iface} is DOWN. Bringing UP..."
                    )
                    subprocess.run(['ip', 'link', 'set', iface, 'up'], check=False)
                    update_status(
                        sensor_status="monitoring", 
                        message=f"Auto-heal successful: {iface} brought UP"
                    )

        except Exception as e:
            LOGGER.debug(f"Watchdog encountered an error: {e}")


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
    threading.Thread(target=hardware_watchdog, daemon=True).start()
    
    LOGGER.info("[Sensor] Starting resilient packet capture on interface=%s", interface_name)

    while True:
        try:
            # timeout=3 forces Scapy to refresh the raw socket so it doesn't hang silently
            sniff(iface=interface_name, prn=handle_packet, store=False, timeout=3)
            
            # Keep status accurate between socket refreshes
            verify = subprocess.run(['iwconfig', interface_name], capture_output=True, text=True)
            if 'Mode:Monitor' in verify.stdout:
                update_status(sensor_status="monitoring", message=f"Sniffing on {interface_name}")
                
        except OSError as exc:
            message = f"Adapter lost or down: {exc}. Waiting for watchdog..."
            update_status(sensor_status="warning", message=message)
            time.sleep(3)
        except Exception as exc:
            message = f"Sniffer crashed: {exc}. Restarting in 3s..."
            update_status(sensor_status="error", message=message)
            time.sleep(3)
