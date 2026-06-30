import logging
import time
from typing import Optional

import config
from attack_identity import derive_attack_sc
from detection.risk_engine import RiskEngine

LOGGER = logging.getLogger("zeinaguard.sensor.deauth_detector")

DEAUTH_ALERT_THRESHOLD: int = 3
DEAUTH_TIME_WINDOW_SECONDS: int = 10
DEAUTH_COOLDOWN_SECONDS: int = 60 # 60 Seconds


class DeauthDetector:

    def __init__(self) -> None:
        self._frame_counts: dict[str, int] = {}
        self._window_start: dict[str, float] = {}
        self._last_alert_at: dict[str, float] = {}
        self._risk_engine = RiskEngine()

    def _is_own_frame(self, sc_field: int, bssid: str) -> bool:
        expected_seq = derive_attack_sc(bssid)
        captured_seq = (sc_field >> 4) & 0x0FFF
        return captured_seq == expected_seq

    def _in_cooldown(self, bssid: str) -> bool:
        last = self._last_alert_at.get(bssid)
        if last is None:
            return False
        return (time.time() - last) < DEAUTH_COOLDOWN_SECONDS

    def handle_frame(
        self,
        addr1: str,
        addr2: str,
        addr3: str,
        sc_field: int,
        rssi: Optional[int],
        reason_code: int,
    ) -> Optional[dict]:
        
        trusted_macs = config.get_trusted_macs()

        target_bssid: Optional[str] = None
        checked = []
        for candidate in (addr3, addr2):
            normalised = (candidate or "").upper().replace("-", ":")
            if normalised:
                checked.append(normalised)
                if normalised in trusted_macs:
                    target_bssid = normalised
                    break

        if target_bssid is None:
            LOGGER.info(
                "[DeauthDetector] Frame ignored — neither addr3 nor addr2 is a trusted MAC "
                "| checked=%s trusted_count=%d",
                checked, len(trusted_macs),
            )
            return None

        LOGGER.info(
            "[DeauthDetector] Trusted MAC matched: %s | addr1=%s addr2=%s addr3=%s reason=%d rssi=%s",
            target_bssid, addr1, addr2, addr3, reason_code, rssi,
        )

        if self._is_own_frame(sc_field, target_bssid):
            LOGGER.info(
                "[DeauthDetector] Own-frame suppressed for %s (SC tag match sc=%d)",
                target_bssid, sc_field,
            )
            return None

        # Cooldown: suppress further alerts for this BSSID for 3 minutes.
        if self._in_cooldown(target_bssid):
            remaining = DEAUTH_COOLDOWN_SECONDS - (time.time() - self._last_alert_at.get(target_bssid, 0))
            LOGGER.info(
                "[DeauthDetector] Cooldown active for %s — suppressing frame "
                "(reason=%d cooldown_remaining=%.0fs)",
                target_bssid, reason_code, max(0, remaining),
            )
            return None

        now = time.time()
        
        if now - self._window_start.get(target_bssid, 0) > DEAUTH_TIME_WINDOW_SECONDS:
            self._frame_counts[target_bssid] = 0
            self._window_start[target_bssid] = now

        self._frame_counts[target_bssid] = self._frame_counts.get(target_bssid, 0) + 1
        count = self._frame_counts[target_bssid]

        LOGGER.info(
            "[DeauthDetector] Deauth frame #%d/%d on trusted %s | rssi=%s | reason=%d",
            count, DEAUTH_ALERT_THRESHOLD, target_bssid, rssi, reason_code,
        )

        if reason_code == 15 and count < 15:
            return None

        if count < DEAUTH_ALERT_THRESHOLD:
            return None

        self._last_alert_at[target_bssid] = time.time()
        self._frame_counts[target_bssid] = 0

        distance_m = self._risk_engine._calculate_indoor_distance(rssi)

        network_name = trusted_macs.get(target_bssid, "Unknown Network")

        alert = {
            "type": "DEAUTH_ATTACK",
            "target_bssid": target_bssid,
            "network_name": network_name,
            "attacker_rssi": rssi,
            "estimated_distance_m": distance_m,
            "frame_count": count,
            "reason_code": reason_code,
            "spoofed_src_mac": (addr2 or "").upper().replace("-", ":"),
            "destination": (addr1 or "").upper().replace("-", ":"),
            "attacker_note": (
                "Source MAC is spoofed and does not identify the attacker's real hardware. "
                "RSSI reflects true RF signal proximity and cannot be spoofed at the physical layer."
            ),
        }

        dist_display = f"{distance_m:.1f}m" if distance_m and distance_m > 0 else "unknown"
        LOGGER.warning(
            "[DeauthDetector] ALERT: External deauth attack on trusted network %s (%s) "
            "| RSSI=%s dBm | Distance≈%s | Reason code=%d",
            target_bssid, network_name, rssi, dist_display, reason_code,
        )
        return alert