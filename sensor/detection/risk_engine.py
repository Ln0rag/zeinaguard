# detection/risk_engine.py

class RiskEngine:
    def __init__(self, trusted_aps=None):
        # If no array comes from API, get from config as backup
        if trusted_aps is None:
            from config import TRUSTED_APS
            self.trusted_aps = TRUSTED_APS
        else:
            self.trusted_aps = trusted_aps

    def analyze(self, event):
        """
        Analyzes event and calculates risk score.
        """
        score = 0
        reasons = []

        ssid = event.get("ssid")
        bssid = event.get("bssid")
        channel = event.get("channel")
        signal = event.get("signal")
        encryption = event.get("encryption")
        clients = event.get("clients", 0)

        # Open network with connected clients
        if encryption == "OPEN" and clients > 0:
            score += 5
            reasons.append("Open network with connected clients")

        # Known/trusted network
        trusted_key = next((key for key in self.trusted_aps.keys() if key.upper() == ssid.upper()), None)
        if trusted_key:
            trusted = self.trusted_aps[trusted_key]

            # Evil Twin (SSID matches but BSSID different)
            if bssid.lower() != trusted["bssid"].lower():
                score += 6
                reasons.append("Evil Twin suspected (BSSID Spoofing)")
            else:
                # Security modification: if attacker copied MAC but changed encryption to OPEN
                trusted_enc = trusted.get("encryption", "SECURED")
                if encryption.upper() != trusted_enc.upper():
                    score += 6
                    reasons.append(f"Encryption downgrade (Expected {trusted_enc}, got {encryption})")

            # Channel mismatch
            if channel != trusted["channel"]:
                score += 2
                reasons.append("Channel mismatch")

        # Unknown SSID
        else:
            score += 3
            reasons.append("SSID not trusted")

        # Unusually strong signal
        if signal is not None and signal > -30:
            score += 2
            reasons.append("Unusually strong signal")

        classification = self.classify(score)

        event_summary = {
            "classification": classification,
            "score": score,
            "reasons": reasons,
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel,
            "signal": signal,
            "encryption": encryption,
            "clients": clients,
            "manufacturer": event.get("manufacturer", "Unknown"),
            "uptime": event.get("uptime", ""),
            "auth": event.get("auth", ""),
            "wps": event.get("wps", ""),
            "distance": event.get("distance", -1),
            "raw_beacon": event.get("raw_beacon", ""),
        }

        return event_summary

    def classify(self, score):
        if score >= 6:
            return "ROGUE"
        elif score >= 3:
            return "SUSPICIOUS"
        return "LEGIT"
