from core.event_bus import dashboard_queue
from flask_socketio import SocketIO
import threading

socketio = SocketIO(cors_allowed_origins="*")


def dashboard_worker():

    while True:

        threat = dashboard_queue.get()

        data = {
            "type": threat["status"],
            "score": threat["score"],
            "ssid": threat["event"]["ssid"],
            "bssid": threat["event"]["bssid"],
            "channel": threat["event"]["channel"],
            "timestamp": threat["event"]["timestamp"]
        }

        print("📡 Sending threat to dashboard:", data)

        socketio.emit("new_threat", data)
