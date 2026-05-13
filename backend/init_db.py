import os
from app import app, db
from models import (
    Sensor, SensorHealth,
    Threat, ThreatEvent
)
from datetime import datetime

def init_database():
    """Initialize database with schema"""
    
    with app.app_context():
        print("[DB] Creating tables...")
        db.create_all()
        print("[DB] Tables created successfully!")

if __name__ == '__main__':
    init_database()
