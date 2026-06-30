import logging
import time
import threading
from datetime import datetime, timedelta, timezone

import config
from config import AutoContainmentConfig
from core.event_bus import dashboard_queue, event_queue, scan_queue
from detection.risk_engine import RiskEngine
from detection.deauth_detector import DeauthDetector
from runtime_state import remove_ap, update_ap, update_status, get_status_snapshot
from prevention.containment_engine import ContainmentEngine
from monitoring.sniffer import clients_map

_LOGGER = logging.getLogger("zeinaguard.sensor.threat_manager")

class ThreatManager:
    def __init__(self):
        self.engine = RiskEngine()
        self.history = {}
        self.last_status = {}
        self._status_lock = threading.RLock()
        self.last_classification = {}
        self.confirmed_rogues = set()
        self.last_sent = {}
        self.cooldown = 300
        self.last_ui_update = {}
        self.ui_interval = 1.0
        
        self.containment_engine = ContainmentEngine(ack_callback=self._on_containment_state_change)
        self.whitelist = {}
        self.deauth_detector = DeauthDetector()

    def _on_containment_state_change(self, status, bssid, reason, ssid=None, channel=None, signal=None):
        with self._status_lock:
            self.last_status[bssid] = status

        event = {
            "type": "ATTACK_STATE_CHANGE",
            "bssid": bssid,
            "status": status,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }
        dashboard_queue.put(event)
        
        update_status(message=f"Attack state for {bssid} is now {status}: {reason}")

    def print_event(self, event_summary):
        bssid = event_summary["bssid"]
        now = time.time()

        if bssid not in self.last_ui_update or now - self.last_ui_update[bssid] > self.ui_interval:
            update_ap(event_summary)
            self.last_ui_update[bssid] = now

    def handle_removal(self, bssid):
        remove_ap(bssid)
        
        current_state = get_status_snapshot()
        if current_state.get("sensor_status") not in ["error", "warning"]:
            update_status(message=f"Cleared inactive network: {bssid}")

        with self._status_lock:
            current_attack_status = self.last_status.get(bssid)
            
            if current_attack_status == "ATTACKING":
                self.containment_engine.execute_kill(bssid, kill_token="ap_removed_auto")
                self.last_status[bssid] = "KILLED"
                
                dashboard_queue.put({
                    "type": "THREAT_RESOLVED",
                    "bssid": bssid,
                    "status": "KILLED",
                    "is_resolved": True,
                    "resolution_reason": "Network no longer visible - AP timeout"
                })
            elif current_attack_status in ["EVALUATING", "MONITORING"]:
                self.last_status[bssid] = "ARCHIVED"
                
                dashboard_queue.put({
                    "type": "THREAT_RESOLVED",
                    "bssid": bssid,
                    "status": "ARCHIVED",
                    "is_resolved": True,
                    "resolution_reason": "Network aged out of memory"
                })

        self.confirmed_rogues.discard(bssid)
        key = self._normalize_bssid(bssid)
        self.whitelist.pop(key, None)

        self.history.pop(bssid, None)
        with self._status_lock:
            self.last_status.pop(bssid, None)
        self.last_classification.pop(bssid, None)
        self.last_sent.pop(bssid, None)
        self.last_ui_update.pop(bssid, None)
        if self.engine:
            self.engine.rssi_history.pop(bssid, None)

        dashboard_queue.put({
            "type": "REMOVED",
            "bssid": bssid,
        })

    @staticmethod
    def _normalize_bssid(bssid):
        return (bssid or "").strip().lower()

    def _is_whitelisted(self, bssid):
        key = self._normalize_bssid(bssid)
        if key not in self.whitelist:
            return False
        if time.time() > self.whitelist[key]:
            del self.whitelist[key]
            return False
        return True

    def start(self):
        update_status(sensor_status="analyzing", message="Threat manager active")

        self.containment_engine.start_daemon()

        while True:
            event = event_queue.get()

            if isinstance(event, dict) and event.get("type") == "KILL_ATTACK":
                raw_bssid = event.get("bssid")
                if raw_bssid:
                    bssid = self._normalize_bssid(raw_bssid)
                    ttl_seconds = AutoContainmentConfig.WHITELIST_TTL_HOURS * 3600
                    self.whitelist[bssid] = time.time() + ttl_seconds
                    self.containment_engine.execute_kill(bssid, event.get("kill_token", "manual"))
                continue

            if isinstance(event, dict) and event.get("type") == "MANUAL_ATTACK":
                raw_bssid = event.get("bssid")
                channel = event.get("channel")
                ssid = event.get("ssid")
                if raw_bssid:
                    bssid = self._normalize_bssid(raw_bssid)
                    self.whitelist.pop(bssid, None)
                    clients = list(clients_map.get(bssid, set()))
                    self.containment_engine.evaluate_threat(
                        bssid=bssid,
                        score=100,
                        channel=channel,
                        ssid=ssid,
                        clients=clients,
                    )
                    with self._status_lock:
                        self.last_status[bssid] = "ATTACKING"
                    update_status(
                        message=f"Manual attack engaged: {ssid or 'Unknown'} ({bssid})",
                    )
                continue

            if isinstance(event, dict) and event.get("type") == "AP_REMOVED":
                self.handle_removal(self._normalize_bssid(event["bssid"]))
                continue

            if isinstance(event, dict) and event.get("type") == "DEAUTH_FRAME":
                _LOGGER.info(
                    "[ThreatManager] DEAUTH_FRAME received | addr1=%s addr2=%s addr3=%s "
                    "sc=%s rssi=%s reason=%s",
                    event.get("addr1"), event.get("addr2"), event.get("addr3"),
                    event.get("sc"), event.get("rssi"), event.get("reason"),
                )
                alert = self.deauth_detector.handle_frame(
                    addr1=event.get("addr1", ""),
                    addr2=event.get("addr2", ""),
                    addr3=event.get("addr3", ""),
                    sc_field=int(event.get("sc", 0)),
                    rssi=event.get("rssi"),
                    reason_code=int(event.get("reason", 0)),
                )
                if alert:
                    _LOGGER.warning(
                        "[ThreatManager] DEAUTH_ATTACK alert generated | target=%s network=%s "
                        "rssi=%s distance=%.1fm — pushing to dashboard_queue",
                        alert.get("target_bssid"), alert.get("network_name"),
                        alert.get("attacker_rssi"),
                        alert.get("estimated_distance_m") or 0,
                    )
                    dashboard_queue.put(alert)
                else:
                    _LOGGER.info(
                        "[ThreatManager] DEAUTH_FRAME produced no alert "
                        "(detector returned None — see DeauthDetector logs for reason)",
                    )
                continue

            if not event or not isinstance(event, dict):
                continue

            event_summary = self.engine.analyze(event)
            event_summary["timestamp"] = event.get("timestamp")
            event_summary["manufacturer"] = event.get("manufacturer", event_summary.get("manufacturer", "Unknown"))
            event_summary["uptime"] = event.get("uptime", event_summary.get("uptime", ""))
            event_summary["auth"] = event.get("auth", event_summary.get("auth", ""))
            event_summary["wps"] = event.get("wps", event_summary.get("wps", ""))
            event_summary["distance"] = event.get("distance", event_summary.get("distance", -1))
            event_summary["raw_beacon"] = event.get("raw_beacon", event_summary.get("raw_beacon", ""))

            bssid = event_summary["bssid"]
            status = event_summary["classification"]
            score = event_summary["score"]
            reasons = event_summary["reasons"]
            self.history[bssid] = self.history.get(bssid, 0) + 1


            self.print_event(event_summary)
            scan_queue.put(event_summary)

            if status == "ROGUE" and self.history[bssid] >= 3 and bssid not in self.confirmed_rogues:
                self.confirmed_rogues.add(bssid)
                update_status(
                    message=f"Confirmed rogue: {event_summary['ssid']} ({event_summary['bssid']})"
                )

            if not self._is_whitelisted(bssid):
                
                if status == "ROGUE":
                    with self._status_lock:
                        is_attacking = self.last_status.get(bssid) == "ATTACKING"
                    
                    if not is_attacking:
                        update_status(message=f"🚨 LETHAL FORCE ENGAGED: {event_summary.get('ssid')} ({bssid})")
                    
                    clients = list(clients_map.get(bssid.upper(), set()))
                    self.containment_engine.evaluate_threat(
                        bssid=bssid,
                        score=score,
                        channel=event_summary.get("channel"),
                        ssid=event_summary.get("ssid"),
                        clients=clients
                    )
                
                elif status == "SUSPICIOUS":
                    with self._status_lock:
                        if self.last_status.get(bssid) not in ["ATTACKING", "MONITORING", "EVALUATING"]:
                            self.last_status[bssid] = "EVALUATING"

            ssid = event_summary.get("ssid", "Hidden")
            is_hidden = (ssid == "Hidden" or not ssid)
            if is_hidden and status not in ["ROGUE", "SUSPICIOUS"]:
                pass
            elif status in ["SUSPICIOUS", "ROGUE", "LEGIT"] or score > 40:
                threat = {
                    "status": status,
                    "score": score,
                    "reasons": reasons,
                    "event": event_summary
                }

                now = time.time()
                previous_classification = self.last_classification.get(bssid)
                status_escalated = (status != previous_classification)
                self.last_classification[bssid] = status
                
                if bssid not in self.last_sent or (now - self.last_sent[bssid] > self.cooldown) or status_escalated:
                    dashboard_queue.put(threat)
                    self.last_sent[bssid] = now