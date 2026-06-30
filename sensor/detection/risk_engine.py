import os
import sys
import math
import statistics

current_dir = os.path.dirname(os.path.abspath(__file__))
sensor_dir = os.path.dirname(current_dir)
if sensor_dir not in sys.path:
    sys.path.append(sensor_dir)

import config

class RiskEngine:
    def __init__(self, trusted_bssids=None):
        self.manual_trusted_bssids = None
        if trusted_bssids:
            self.manual_trusted_bssids = set(mac.lower() for mac in trusted_bssids)
        
        self.rssi_history = {}
        self.max_history_size = 5

    def _get_stable_rssi(self, bssid, raw_rssi):
        if raw_rssi is None or raw_rssi >= 0 or not bssid:
            return raw_rssi
            
        if bssid not in self.rssi_history:
            self.rssi_history[bssid] = []
            
        self.rssi_history[bssid].append(raw_rssi)
        
        if len(self.rssi_history[bssid]) > self.max_history_size:
            self.rssi_history[bssid].pop(0)
            
        return statistics.median(self.rssi_history[bssid])

    def _calculate_indoor_distance(self, rssi):
        if rssi is None or rssi == 0 or rssi > 0:
            return -1.0
            
        tx_power = -35.0 
        n = 3.3             # {2 to 4} n=2 for free space n=4 for concrete buildings.
        
        distance = 10 ** ((tx_power - rssi) / (10.0 * n))
        return round(distance, 2)

    def analyze(self, event):
        score = 0
        reasons = []

        bssid = (event.get("bssid") or "").lower()
        encryption = str(event.get("encryption", "OPEN")).upper()
        auth_type = (event.get("auth") or "").upper()
        wps_info = (event.get("wps") or "").upper()
        clients = event.get("clients", 0)
        
        is_open_network = encryption in ["", "OPEN", "OPN", "NONE"]
        raw_signal = event.get("signal")
        smoothed_signal = self._get_stable_rssi(bssid, raw_signal)
        distance_meters = self._calculate_indoor_distance(smoothed_signal)

        client_count = 0
        if isinstance(clients, int):
            client_count = clients
        elif isinstance(clients, list):
            client_count = len(clients)

        is_trusted = False
        if self.manual_trusted_bssids and bssid in self.manual_trusted_bssids:
            is_trusted = True
        else:
            is_trusted = bssid.upper() in config.get_trusted_macs()

        is_hidden_network = event.get("was_hidden", False) or not event.get("ssid") or event.get("ssid") == "Hidden"

        if encryption == "OPEN" and not is_hidden_network:
            if client_count > 0:
                score += 30
                reasons.append("High: Unencrypted Network WITH ACTIVE CLIENTS")
            elif smoothed_signal is not None and smoothed_signal > -75:
                score += 15
                reasons.append(f"Suspicious: Strong Unencrypted Network Nearby ({smoothed_signal}dBm)")
            else:
                score += 10 
                reasons.append(f"Medium: Distant Unencrypted Network ({smoothed_signal}dBm)")

        if "V1.0" in wps_info or "PBC" in wps_info or "PIN" in wps_info or "ACTIVE" in wps_info:
            score += 25
            reasons.append("VULNERABLE: WPS Enabled")

        if "WEP" in auth_type:
            score += 40
            reasons.append("HIGH: WEP detected")
        elif "WPA" in auth_type and "WPA2" not in auth_type and "WPA3" not in auth_type:
            score += 15
            reasons.append("MEDIUM: Legacy WPA1 detected")

        if client_count > 0:
            score += 10
            
        if smoothed_signal is not None and smoothed_signal > -45:
            score += 5

        if is_open_network and smoothed_signal is not None and smoothed_signal > -60:
            if client_count > 0:
                score += 50
                reasons.append(f"CRITICAL ALERT: Unauthorized Open Network with {client_count} Active Clients! (Auto-Kill Triggered)")
            else:
                score += 15
                reasons.append("Alert: Strong Open Network nearby (No Active Clients, Monitoring Only)")

        if not is_trusted:
            score += 10
            reasons.append("Identity: External Device")

        if is_open_network and client_count > 0:
            classification = "ROGUE"
            score = max(score, 80)
            if not any("active client" in r.lower() for r in reasons):
                reasons.append(f"CRITICAL: Open Network with {client_count} Active Client(s) — Trust Override Ignored")
        elif is_trusted:
            classification = "LEGIT"
            score = 0 
            reasons = []
        else:
            if score >= 50:
                classification = "ROGUE"
            else:
                classification = "SUSPICIOUS"

        return self._build_result(event, score, reasons, is_trusted, classification, distance_meters, smoothed_signal)

    def _build_result(self, event, score, reasons, is_trusted, classification, distance_meters, smoothed_signal):
        return {
            "classification": classification,
            "score": min(score, 100),
            "reasons": reasons,
            "ssid": event.get("ssid") or "Hidden",
            "bssid": event.get("bssid"),
            "channel": event.get("channel"),
            "signal": int(round(smoothed_signal)) if smoothed_signal else event.get("signal"),
            "estimated_distance_m": distance_meters,  
            "encryption": event.get("encryption"),
            "clients": event.get("clients", 0),
            "manufacturer": event.get("manufacturer", "Unknown"),
            "is_trusted": is_trusted,
            "was_hidden": event.get("was_hidden", False)
        }