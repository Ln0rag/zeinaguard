class RiskEngine:
    def __init__(self, trusted_aps=None):
        if trusted_aps is None:
            from config import TRUSTED_APS
            self.trusted_aps = TRUSTED_APS
        else:
            self.trusted_aps = trusted_aps

    def normalize_ssid(self, ssid):
        if not ssid:
            return ""
        return ssid.strip().lower().replace("_5g", "").replace("-5g", "")

    def analyze(self, event):
        score = 0
        reasons = []

        ssid_raw = event.get("ssid") or ""
        ssid = self.normalize_ssid(ssid_raw)

        bssid = (event.get("bssid") or "").lower()
        channel = event.get("channel")
        signal = event.get("signal")
        encryption = (event.get("encryption") or "").upper()
        clients = event.get("clients", 0)

        # =========================
        # Trusted AP CHECK (HARD OVERRIDE)
        # =========================
        trusted_key = None

        for key in self.trusted_aps:
            if self.normalize_ssid(key) == ssid:
                trusted_key = key
                break

        if trusted_key:
            trusted = self.trusted_aps[trusted_key]

            return {
                "classification": "LEGIT",
                "score": 0,
                "reasons": ["Trusted network (whitelisted)"],
                "ssid": ssid_raw,
                "bssid": bssid,
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

        # =========================
        # Unknown networks scoring
        # =========================
        score += 3
        reasons.append("SSID not trusted")

        if encryption == "OPEN" and clients > 0:
            score += 3
            reasons.append("Open network with clients")

        if signal is not None and signal > -25:
            score += 1
            reasons.append("Very strong signal")

        return self._build_result(event, score, reasons)

    def _build_result(self, event, score, reasons):
        return {
            "classification": self.classify(score),
            "score": score,
            "reasons": reasons,
            "ssid": event.get("ssid"),
            "bssid": event.get("bssid"),
            "channel": event.get("channel"),
            "signal": event.get("signal"),
            "encryption": event.get("encryption"),
            "clients": event.get("clients", 0),
            "manufacturer": event.get("manufacturer", "Unknown"),
            "uptime": event.get("uptime", ""),
            "auth": event.get("auth", ""),
            "wps": event.get("wps", ""),
            "distance": event.get("distance", -1),
            "raw_beacon": event.get("raw_beacon", ""),
        }

    def classify(self, score):
        if score >= 6:
            return "ROGUE"
        elif score >= 3:
            return "SUSPICIOUS"
        return "LEGIT"
