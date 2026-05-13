import time
import threading
from datetime import datetime, timedelta

import config
from config import AutoContainmentConfig
from core.event_bus import dashboard_queue, event_queue, scan_queue
from detection.risk_engine import RiskEngine
from runtime_state import remove_ap, update_ap, update_status, get_status_snapshot
from prevention.containment_engine import ContainmentEngine
from monitoring.sniffer import clients_map

class ThreatManager:
    def __init__(self):
        self.engine = RiskEngine()
        self.history = {}
        self.last_status = {}               # Tracks Action Status (ATTACKING, MONITORING, EVALUATING)
        self.last_classification = {}       # Tracks Threat Level (ROGUE, SUSPICIOUS)
        self.confirmed_rogues = set()
        self.last_sent = {}
        self.cooldown = 300
        self.last_ui_update = {}
        self.ui_interval = 1.0
        
        # Initialize the global smart containment engine
        self.containment_engine = ContainmentEngine(ack_callback=self._on_containment_state_change)
        self.whitelist = {} # bssid -> expiration timestamp

    def _on_containment_state_change(self, status, bssid, reason, ssid=None, channel=None, signal=None):
        """Callback for emitting state changes from the Containment Engine to the dashboard."""
        event = {
            "type": "ATTACK_STATE_CHANGE",
            "bssid": bssid,
            "status": status,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        dashboard_queue.put(event)
        
        # Log to local sensor status for awareness
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

        self.history.pop(bssid, None)
        self.last_status.pop(bssid, None)
        self.last_classification.pop(bssid, None)
        self.last_sent.pop(bssid, None)
        self.last_ui_update.pop(bssid, None)
        self.engine.rssi_history.pop(bssid, None)

        dashboard_queue.put({
            "type": "REMOVED",
            "bssid": bssid,
        })

    def _is_whitelisted(self, bssid):
        if bssid not in self.whitelist:
            return False
        if time.time() > self.whitelist[bssid]:
            del self.whitelist[bssid] # expired TTL
            return False
        return True

    def start(self):
        update_status(sensor_status="analyzing", message="Threat manager active")

        # Start the containment engine state machine thread (background daemon)
        self.containment_engine.start_daemon()

        while True:
            event = event_queue.get()

            # Handle Kill Switch command from websocket (routed via event queue)
            if isinstance(event, dict) and event.get("type") == "KILL_ATTACK":
                bssid = event.get("bssid")
                if bssid:
                    # Add to TTL Whitelist
                    ttl_seconds = AutoContainmentConfig.WHITELIST_TTL_HOURS * 3600
                    self.whitelist[bssid] = time.time() + ttl_seconds
                    
                    # Stop the engine if it's currently attacking this BSSID
                    self.containment_engine.execute_kill(bssid, event.get("kill_token", "manual"))
                continue

            if isinstance(event, dict) and event.get("type") == "AP_REMOVED":
                self.handle_removal(event["bssid"])
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
            event_summary["history_count"] = self.history[bssid]

            self.print_event(event_summary)
            scan_queue.put(event_summary)

            if status == "ROGUE" and self.history[bssid] >= 3 and bssid not in self.confirmed_rogues:
                self.confirmed_rogues.add(bssid)
                update_status(
                    message=f"Confirmed rogue: {event_summary['ssid']} ({event_summary['bssid']})"
                )

            # =========================================================
            # 1. SMART AUTO-CONTAINMENT TRIGGER (تحديد الأكشن الأول)
            # =========================================================
            if not self._is_whitelisted(bssid):
                
                # أ. التهديد عالي الخطورة (ROGUE) -> هجوم مباشر
                if status == "ROGUE":
                    if self.last_status.get(bssid) != "ATTACKING":
                        alert_msg = f"TARGET ACQUIRED: Rogue threat detected. Auto-Containment Engaged!"
                        self._on_containment_state_change("ATTACKING", bssid, alert_msg)
                        self.last_status[bssid] = "ATTACKING"
                        update_status(message=f"🚨 LETHAL FORCE ENGAGED: {event_summary.get('ssid')} ({bssid})")
                    
                    clients = list(clients_map.get(bssid, set()))
                    self.containment_engine.evaluate_threat(
                        bssid=bssid,
                        score=score,
                        channel=event_summary.get("channel"),
                        ssid=event_summary.get("ssid"),
                        clients=clients
                    )
                
                # ب. التهديد SUSPICIOUS (متوسط)
                elif status == "SUSPICIOUS":
                    if self.last_status.get(bssid) not in ["ATTACKING", "MONITORING", "EVALUATING"]:
                        self._on_containment_state_change("EVALUATING", bssid, "Evaluating suspicious indicators over time.")
                        self.last_status[bssid] = "EVALUATING"

            # =========================================================
            # 2. إرسال الداتا للداشبورد والداتابيز (مدمجة بالحالة الجديدة لعدم ظهور IDLE)
            # =========================================================
            ssid = event_summary.get("ssid", "Hidden")
            is_hidden = (ssid == "Hidden" or not ssid)
            if is_hidden and status not in ["ROGUE", "SUSPICIOUS"]:
                pass
            elif status in ["SUSPICIOUS", "ROGUE", "LEGIT"] or score > 40:
                # تحديد الأكشن المناسب حسب التصنيف
                if status == "ROGUE":
                    default_action = "ATTACKING"
                elif status == "SUSPICIOUS":
                    default_action = "EVALUATING"
                else:
                    default_action = "IDLE"
                
                threat = {
                    "status": status,
                    "score": score,
                    "reasons": reasons,
                    "event": event_summary,
                    "action_status": self.last_status.get(bssid, default_action) 
                }

                now = time.time()
                previous_classification = self.last_classification.get(bssid)
                status_escalated = (status != previous_classification)
                self.last_classification[bssid] = status
                
                if bssid not in self.last_sent or (now - self.last_sent[bssid] > self.cooldown) or status_escalated:
                    dashboard_queue.put(threat)
                    self.last_sent[bssid] = now