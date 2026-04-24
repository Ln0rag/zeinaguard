import time

from core.event_bus import dashboard_queue, event_queue, scan_queue
from detection.risk_engine import RiskEngine
from runtime_state import remove_ap, update_ap, update_status


class ThreatManager:
    def __init__(self):
        self.engine = RiskEngine()
        self.history = {}
        self.last_status = {}
        self.confirmed_rogues = set()
        self.last_sent = {}
        self.cooldown = 15
        self.last_ui_update = {}
        self.ui_interval = 1.0

    def print_event(self, event_summary):
        bssid = event_summary["bssid"]
        now = time.time()

        if bssid not in self.last_ui_update or now - self.last_ui_update[bssid] > self.ui_interval:
            update_ap(event_summary)
            self.last_ui_update[bssid] = now

    def handle_removal(self, bssid):
        remove_ap(bssid)
        update_status(message=f"Removed network: {bssid}")

        self.history.pop(bssid, None)
        self.last_status.pop(bssid, None)
        self.last_sent.pop(bssid, None)
        self.last_ui_update.pop(bssid, None)

        dashboard_queue.put({
            "type": "REMOVED",
            "bssid": bssid,
        })

    def start(self):
        update_status(sensor_status="analyzing", message="Threat manager active")

        while True:
            event = event_queue.get()

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

            self.last_status[bssid] = status

            if status in ["SUSPICIOUS", "ROGUE"]:
                threat = {
                    "status": status,
                    "score": score,
                    "reasons": reasons,
                    "event": event_summary,
                }

                now = time.time()
                if bssid not in self.last_sent or now - self.last_sent[bssid] > self.cooldown:
                    dashboard_queue.put(threat)
                    self.last_sent[bssid] = now

            if status == "ROGUE" and self.history[bssid] >= 3 and bssid not in self.confirmed_rogues:
                self.confirmed_rogues.add(bssid)
                update_status(
                    message=f"Confirmed rogue: {event_summary['ssid']} ({event_summary['bssid']})"
                )
