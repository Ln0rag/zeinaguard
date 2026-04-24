from app import app
from models import db, Threat, Sensor, SensorHealth, Incident, Alert, User
from datetime import datetime, timedelta
import random

def seed_everything():
    with app.app_context():
        print("Cleaning old data...")
        db.drop_all()
        db.create_all()

        # 1. Add Sensors
        sensors = []
        for i in range(5):
            s = Sensor(
                name=f"Sensor-Zone-{i+1}",
                location=f"Floor {random.randint(1, 5)}",
                ip_address=f"192.168.1.{100+i}",
                is_active=True
            )
            db.session.add(s)
            sensors.append(s)
        db.session.commit()

        # 2. Add Threats and Sensor Health
        for s in sensors:
            # Sensor health
            health = SensorHealth(
                sensor_id=s.id,
                status="online",
                cpu_usage=random.uniform(10.5, 45.0),
                memory_usage=random.uniform(20.0, 60.0),
                signal_strength=random.randint(-70, -30),
                last_heartbeat=datetime.utcnow()
            )
            db.session.add(health)

            # Threats for this sensor
            for _ in range(3):
                t = Threat(
                    threat_type=random.choice(['rogue_ap', 'evil_twin', 'deauth_attack']),
                    severity=random.choice(['critical', 'high', 'medium', 'low']),
                    ssid=f"Fake_WiFi_{random.randint(10, 99)}",
                    source_mac=f"00:1A:2B:3C:4D:{random.randint(10, 99)}",
                    description="Automated simulation threat detected",
                    is_resolved=False,
                    detected_by=s.id
                )
                db.session.add(t)
        
        db.session.commit()
        print("Database Seeded Successfully!")

if __name__ == "__main__":
    seed_everything()