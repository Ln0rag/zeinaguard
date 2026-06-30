import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import app
from models import db, WiFiNetwork, NetworkScanEvent, Threat, ThreatEvent, MitigationAudit

def factory_reset():
    with app.app_context():
        print("Starting factory reset of telemetry and network data...")
        try:
            db.session.execute(db.text("TRUNCATE TABLE wifi_networks, network_scan_events, threats, threat_events, mitigation_audits, alerts CASCADE;"))
            print("Executed TRUNCATE CASCADE for PostgreSQL.")

            db.session.commit()
            print("\nDatabase is now in a TRUE ZERO state.")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during factory reset: {e}")

if __name__ == "__main__":
    factory_reset()
