import os
import sys

# Ensure config.py is strictly importable
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

    def analyze(self, event):
        score = 0
        reasons = []

        bssid = (event.get("bssid") or "").lower()
        encryption = (event.get("encryption") or "").upper()
        auth_type = (event.get("auth") or "").upper()
        wps_info = (event.get("wps") or "").upper()
        clients = event.get("clients", 0)
        signal = event.get("signal")
        
        # DYNAMIC RELOAD: Efficiently check config using the atomic cache API
        is_trusted = False
        if self.manual_trusted_bssids and bssid in self.manual_trusted_bssids:
            is_trusted = True
        else:
            # Check against the centralized JSON source of truth
            is_trusted = bssid.upper() in config.get_trusted_macs()

        if encryption == "OPEN":
            score += 60
            reasons.append("CRITICAL: Unencrypted Communication")
        
        if "V1.0" in wps_info or "PBC" in wps_info or "PIN" in wps_info or "ACTIVE" in wps_info:
            score += 25
            reasons.append("VULNERABLE: WPS Enabled")

        if "WEP" in auth_type:
            score += 40
            reasons.append("HIGH: WEP detected")
        elif "WPA" in auth_type and "WPA2" not in auth_type and "WPA3" not in auth_type:
            score += 15
            reasons.append("MEDIUM: Legacy WPA1 detected")

        if isinstance(clients, int) and clients > 0:
            score += 10
        elif isinstance(clients, list) and len(clients) > 0:
            score += 10
            
        if signal is not None and signal > -45:
            score += 5

        if not is_trusted:
            score += 10
            reasons.append("Identity: External Device")

        # The Ultimate Override
        if is_trusted:
            classification = "LEGIT"
            score = 0 
            reasons = []
        else:
            if score >= 50:
                classification = "ROGUE"
            else:
                classification = "SUSPICIOUS"

        return self._build_result(event, score, reasons, is_trusted, classification)

    def _build_result(self, event, score, reasons, is_trusted, classification):
        return {
            "classification": classification,
            "score": min(score, 100),
            "reasons": reasons,
            "ssid": event.get("ssid") or "Hidden",
            "bssid": event.get("bssid"),
            "channel": event.get("channel"),
            "signal": event.get("signal"),
            "encryption": event.get("encryption"),
            "clients": event.get("clients", 0),
            "manufacturer": event.get("manufacturer", "Unknown"),
            "is_trusted": is_trusted,
            "was_hidden": event.get("was_hidden", False) # السطر الجديد
        }