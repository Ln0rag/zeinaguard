"""
Database Initialization Script
Creates tables, indexes, and seed data
Run this after first deployment
"""

import os
from app import app, db
from models import (
    User, Role, Permission, Sensor, SensorHealth,
    Threat, ThreatEvent, AlertRule, Alert, Incident,
    IncidentEvent, Report, AuditLog, NetworkTopology,
    BlockedDevice
)
from auth import hash_password
from datetime import datetime


def init_database():
    """Initialize database with schema and seed data"""
    
    with app.app_context():
        print("[DB] Creating tables...")
        db.create_all()
        print("[DB] Tables created successfully!")
        
        # Check if already seeded
        if User.query.first():
            print("[DB] Database already seeded, skipping...")
            return
        
        print("[DB] Seeding default roles...")
        admin_role = Role(
            name='Administrator',
            description='Full system access'
        )
        analyst_role = Role(
            name='Analyst',
            description='Threat analysis and incident management'
        )
        monitor_role = Role(
            name='Monitor',
            description='View-only access to dashboard and reports'
        )
        
        db.session.add_all([admin_role, analyst_role, monitor_role])
        db.session.commit()
        print("[DB] Roles created!")
        
        print("[DB] Seeding permissions...")
        permissions_data = [
            ('view_dashboard', 'View main dashboard'),
            ('view_threats', 'View threat events'),
            ('manage_alerts', 'Create and manage alert rules'),
            ('manage_incidents', 'Create and manage incidents'),
            ('manage_sensors', 'Manage sensors and deployment'),
            ('manage_users', 'Manage users and roles'),
            ('view_reports', 'View reports'),
            ('generate_reports', 'Generate new reports'),
            ('manage_system', 'System configuration and maintenance'),
            ('view_audit_logs', 'View audit logs'),
        ]
        
        permissions = []
        for name, description in permissions_data:
            perm = Permission(name=name, description=description)
            permissions.append(perm)
            db.session.add(perm)
        
        db.session.commit()
        print("[DB] Permissions created!")
        
        print("[DB] Assigning permissions to roles...")
        # Admin gets all permissions
        admin_role.permissions = permissions
        
        # Analyst gets most permissions except system management
        analyst_perms = [p for p in permissions if p.name not in ['manage_users', 'manage_system', 'view_audit_logs']]
        analyst_role.permissions = analyst_perms
        
        # Monitor gets read-only permissions
        monitor_perms = [p for p in permissions if 'view' in p.name or 'generate_reports' in p.name]
        monitor_role.permissions = monitor_perms
        
        db.session.commit()
        print("[DB] Permissions assigned!")
        
        print("[DB] Creating demo users...")
        admin_user = User(
            username='admin',
            email='admin@zeinaguard.local',
            password_hash=hash_password('admin123'),
            first_name='Admin',
            last_name='User',
            is_active=True,
            is_admin=True
        )
        admin_user.roles.append(admin_role)
        
        analyst_user = User(
            username='analyst',
            email='analyst@zeinaguard.local',
            password_hash=hash_password('analyst123'),
            first_name='Analyst',
            last_name='User',
            is_active=True,
            is_admin=False
        )
        analyst_user.roles.append(analyst_role)
        
        monitor_user = User(
            username='monitor',
            email='monitor@zeinaguard.local',
            password_hash=hash_password('monitor123'),
            first_name='Monitor',
            last_name='User',
            is_active=True,
            is_admin=False
        )
        monitor_user.roles.append(monitor_role)
        
        db.session.add_all([admin_user, analyst_user, monitor_user])
        db.session.commit()
        print("[DB] Demo users created!")
        
        print("[DB] Creating demo sensors...")
        sensor1 = Sensor(
            name='Office Main Sensor',
            hostname='sensor-office-1',
            ip_address='192.168.1.100',
            mac_address='00:1A:2B:3C:4D:5E',
            location='Main Office',
            is_active=True,
            firmware_version='2.1.0'
        )
        
        sensor2 = Sensor(
            name='Lobby Sensor',
            hostname='sensor-lobby-1',
            ip_address='192.168.1.101',
            mac_address='00:1A:2B:3C:4D:5F',
            location='Lobby Area',
            is_active=True,
            firmware_version='2.1.0'
        )
        
        sensor3 = Sensor(
            name='Parking Lot Sensor',
            hostname='sensor-parking-1',
            ip_address='192.168.1.102',
            mac_address='00:1A:2B:3C:4D:60',
            location='Parking Lot',
            is_active=True,
            firmware_version='2.1.0'
        )
        
        db.session.add_all([sensor1, sensor2, sensor3])
        db.session.commit()
        print("[DB] Demo sensors created!")
        
        print("[DB] Creating sensor health records...")
        for sensor in [sensor1, sensor2, sensor3]:
            health = SensorHealth(
                sensor_id=sensor.id,
                status='online',
                signal_strength=95,
                cpu_usage=25.5,
                memory_usage=45.2,
                uptime=86400,
                last_heartbeat=datetime.utcnow()
            )
            db.session.add(health)
        
        db.session.commit()
        print("[DB] Sensor health records created!")
        
        print("[DB] Creating demo threat...")
        threat = Threat(
            threat_type='rogue_ap',
            severity='critical',
            source_mac='00:11:22:33:44:55',
            ssid='FreeWiFi-Trap',
            detected_by=sensor1.id,
            created_by=admin_user.id,
            description='Critical rogue access point detected in office area',
            is_resolved=False
        )
        db.session.add(threat)
        db.session.commit()
        print("[DB] Demo threat created!")
        
        print("[DB] Creating demo alert rule...")
        alert_rule = AlertRule(
            name='Critical Threat Alert',
            description='Alert on critical threats',
            severity='critical',
            is_enabled=True,
            action_type='alert',
            created_by=admin_user.id
        )
        db.session.add(alert_rule)
        db.session.commit()
        print("[DB] Demo alert rule created!")
        
        print("[DB] ✓ Database initialization complete!")
        print("[DB] Demo credentials:")
        print("[DB]   Admin:    admin / admin123")
        print("[DB]   Analyst:  analyst / analyst123")
        print("[DB]   Monitor:  monitor / monitor123")


if __name__ == '__main__':
    init_database()
