class RiskEngine:
    def __init__(self, trusted_bssids=None):
        if trusted_bssids is None:
            try:
                from config import TRUSTED_BSSIDS
                self.trusted_bssids = [mac.lower() for mac in TRUSTED_BSSIDS]
            except ImportError:
                self.trusted_bssids = []
        else:
            self.trusted_bssids = [mac.lower() for mac in trusted_bssids]

    def analyze(self, event):
        score = 0
        reasons = []
        has_vulnerability = False # علامة تنبيه داخلية

        # استخراج البيانات الأساسية
        bssid = (event.get("bssid") or "").lower()
        encryption = (event.get("encryption") or "").upper()
        auth_type = (event.get("auth") or "").upper()
        wps_info = (event.get("wps") or "").upper()
        clients = event.get("clients", 0)
        signal = event.get("signal")
        is_trusted = bssid in self.trusted_bssids

        # ==========================================
        # 1. تقييم الثغرات (حساب السكور العادي)
        # ==========================================
        
        # فحص الشبكة المفتوحة
        if encryption == "OPEN":
            score += 60
            reasons.append("CRITICAL: Unencrypted Communication")
            has_vulnerability = True
        
        # فحص الـ WPS
        if "V1.0" in wps_info or "PBC" in wps_info or "PIN" in wps_info:
            score += 25
            reasons.append("VULNERABLE: WPS Enabled")
            has_vulnerability = True

        # فحص البروتوكولات القديمة
        if "WEP" in auth_type:
            score += 40
            reasons.append("HIGH: WEP detected")
            has_vulnerability = True
        elif "WPA" in auth_type and "WPA2" not in auth_type:
            score += 15
            reasons.append("MEDIUM: Legacy WPA1 detected")
            has_vulnerability = True

        # إضافة سكور النشاط والقرب
        if clients > 0:
            score += 10
        if signal is not None and signal > -45:
            score += 5

        # ضريبة "الغريب"
        if not is_trusted:
            score += 10
            reasons.append("Identity: External Device")

        # ==========================================
        # 2. منطق التصنيف الجديد (الحصانة لشبكتك)
        # ==========================================
        # هنا بنحدد اللون (Classification)
        if is_trusted:
            # شبكتك داااايماً LEGIT (أخضر) مهما حصل
            classification = "LEGIT"
            # لو فيها ثغرة، بنضيف تنبيه واضح في أول الأسباب
            if has_vulnerability:
                reasons.insert(0, "⚠️ CONFIG ALERT: Weak Security Settings")
        else:
            # جيرانك وأي حد غريب بيمشي بالنظام العادي (أصفر أو أحمر)
            if score >= 50:
                classification = "ROGUE"
            else:
                classification = "SUSPICIOUS"

        return self._build_result(event, score, reasons, is_trusted, classification)

    def _build_result(self, event, score, reasons, is_trusted, classification):
        return {
            "classification": classification, # اللون اللي هيظهر
            "score": min(score, 100),
            "reasons": reasons,
            "ssid": event.get("ssid") or "Hidden",
            "bssid": event.get("bssid"),
            "channel": event.get("channel"),
            "signal": event.get("signal"),
            "encryption": event.get("encryption"),
            "clients": event.get("clients", 0),
            "manufacturer": event.get("manufacturer", "Unknown"),
            "is_trusted": is_trusted
        }