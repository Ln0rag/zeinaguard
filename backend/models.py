"""
SQLAlchemy Database Models for ZeinaGuard Pro
Defines all database tables and relationships
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    String, Integer, Float, Boolean, Text, DateTime,
    ForeignKey, JSON, UniqueConstraint,
    Index
)
from sqlalchemy.orm import relationship

# Initialize SQLAlchemy
db = SQLAlchemy()


# ==================== User Management ====================

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(255), unique=True, nullable=False)
    email = db.Column(String(255), unique=True, nullable=False)
    password_hash = db.Column(String(255), nullable=False)
    first_name = db.Column(String(255))
    last_name = db.Column(String(255))
    is_active = db.Column(Boolean, default=True)
    is_admin = db.Column(Boolean, default=False)
    last_login = db.Column(DateTime)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    roles = relationship('Role', secondary='user_roles', backref='users')
    threats_created = relationship('Threat', backref='creator')
    incidents_assigned = relationship('Incident', foreign_keys='Incident.assigned_to', backref='assignee')
    audit_logs = relationship('AuditLog', backref='user')

    def __repr__(self):
        return f'<User {self.username}>'


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(100), unique=True, nullable=False)
    description = db.Column(Text)
    created_at = db.Column(DateTime, default=datetime.utcnow)

    # Relationships
    permissions = relationship('Permission', secondary='role_permissions', backref='roles')

    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(db.Model):
    __tablename__ = 'permissions'

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(100), unique=True, nullable=False)
    description = db.Column(Text)
    created_at = db.Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Permission {self.name}>'


class UserRole(db.Model):
    __tablename__ = 'user_roles'
    user_id = db.Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    role_id = db.Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)


class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    role_id = db.Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
    permission_id = db.Column(Integer, ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True)


# ==================== Sensors ====================

class Sensor(db.Model):
    __tablename__ = 'sensors'

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(255), nullable=False)
    hostname = db.Column(String(255), unique=True)
    ip_address = db.Column(String(45))  # IPv4 or IPv6
    mac_address = db.Column(String(17))
    location = db.Column(String(255))
    is_active = db.Column(Boolean, default=True)
    firmware_version = db.Column(String(50))
    last_heartbeat = db.Column(DateTime)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    health_records = relationship('SensorHealth', backref='sensor', cascade='all, delete-orphan')
    threats = relationship('Threat', backref='detecting_sensor')
    wifi_networks = relationship('WiFiNetwork', backref='sensor', cascade='all, delete-orphan')
    network_data = relationship('NetworkTopology', backref='sensor', uselist=False)

    def __repr__(self):
        return f'<Sensor {self.name}>'


class SensorHealth(db.Model):
    __tablename__ = 'sensor_health'

    id = db.Column(Integer, primary_key=True)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(String(50), default='online')  # online, offline, degraded
    signal_strength = db.Column(Integer)  # 0-100
    cpu_usage = db.Column(Float)
    memory_usage = db.Column(Float)
    uptime = db.Column(Integer)  # in seconds
    last_heartbeat = db.Column(DateTime)
    created_at = db.Column(DateTime, default=datetime.utcnow)

    # Index for time-series queries
    __table_args__ = (
        Index('idx_sensor_health_sensor_created', 'sensor_id', 'created_at'),
    )

    def __repr__(self):
        return f'<SensorHealth sensor={self.sensor_id}>'


# ==================== WiFi Networks (NEW - Optimized for high-frequency scans) ====================

class WiFiNetwork(db.Model):
    __tablename__ = 'wifi_networks'

    id = db.Column(Integer, primary_key=True)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id', ondelete='CASCADE'), nullable=False)

    # Network identification
    ssid = db.Column(String(255), nullable=False, index=True)
    bssid = db.Column(String(17), nullable=False, index=True)  # MAC address format: XX:XX:XX:XX:XX:XX

    # Network properties
    channel = db.Column(Integer)
    frequency = db.Column(Integer)  # 2412, 5180, etc.
    signal_strength = db.Column(Integer)  # dBm
    encryption = db.Column(String(50))  # OPEN, WEP, WPA, WPA2, WPA3
    clients_count = db.Column(Integer, default=0)
    classification = db.Column(String(50), default='UNKNOWN')
    risk_score = db.Column(Integer, default=0)
    auth_type = db.Column(String(50))
    wps_info = db.Column(JSON)  # WPS configuration if available

    # Additional metadata
    manufacturer = db.Column(String(255))  # OUI lookup result
    device_type = db.Column(String(50), default='AP')  # AP, Station, etc.
    uptime_seconds = db.Column(Integer, default=0)  # Device uptime if available

    # Deduplication counters
    seen_count = db.Column(Integer, default=1, nullable=False)  # How many times this network was seen
    first_seen = db.Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_active = db.Column(Boolean, default=True, nullable=False, index=True)

    # Raw data for debugging
    raw_beacon = db.Column(Text)
    raw_data = db.Column(JSON)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('sensor_id', 'bssid', name='uq_wifi_networks_sensor_bssid'),
        Index('idx_wifi_networks_sensor_bssid', 'sensor_id', 'bssid'),
        Index('idx_wifi_networks_sensor_last_seen', 'sensor_id', 'last_seen'),
        Index('idx_wifi_networks_last_seen', 'last_seen'),
        Index('idx_wifi_networks_active_last_seen', 'is_active', 'last_seen'),
        Index('idx_wifi_networks_signal', 'signal_strength'),
        Index('idx_wifi_networks_bssid', 'bssid'),
    )

    def __repr__(self):
        return f'<WiFiNetwork {self.ssid} ({self.bssid})>'


# ==================== Network Scan Events (Time-Series for history) ====================

class NetworkScanEvent(db.Model):
    __tablename__ = 'network_scan_events'

    id = db.Column(Integer, primary_key=True)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id', ondelete='CASCADE'), nullable=False)
    network_id = db.Column(Integer, ForeignKey('wifi_networks.id', ondelete='CASCADE'))

    # Event data
    event_type = db.Column(String(50), default='SCAN')  # SCAN, ROGUE, EVIL_TWIN, etc.
    severity = db.Column(String(50), default='INFO')  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score = db.Column(Float)  # 0-100 risk score

    # Snapshot of network state at scan time
    signal_strength = db.Column(Integer)
    channel = db.Column(Integer)

    # Additional context
    reasons = db.Column(JSON)  # Why this was flagged (if applicable)
    scan_metadata = db.Column('metadata', JSON)  # Additional scan metadata

    scanned_at = db.Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    is_purged = db.Column(Boolean, default=False)  # Marked for cleanup

    __table_args__ = (
        Index('idx_scan_events_sensor_time', 'sensor_id', 'scanned_at'),
        Index('idx_scan_events_scanned_at', 'scanned_at'),
        Index('idx_scan_events_network', 'network_id'),
        Index('idx_scan_events_severity', 'severity'),
        Index('idx_scan_events_purged', 'is_purged'),
    )

    def __repr__(self):
        return f'<NetworkScanEvent {self.event_type} at {self.scanned_at}>'


# ==================== Threats ====================

class Threat(db.Model):
    __tablename__ = 'threats'

    id = db.Column(Integer, primary_key=True)
    threat_type = db.Column(String(100), nullable=False)  # rogue_ap, evil_twin, etc.
    severity = db.Column(String(50), nullable=False)  # critical, high, medium, low, info
    source_mac = db.Column(String(17))
    target_mac = db.Column(String(17))
    ssid = db.Column(String(255))
    detected_by = db.Column(Integer, ForeignKey('sensors.id'))
    created_by = db.Column(Integer, ForeignKey('users.id'))
    description = db.Column(Text)
    is_resolved = db.Column(Boolean, default=False)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    events = relationship('ThreatEvent', backref='threat', cascade='all, delete-orphan')
    alerts = relationship('Alert', backref='threat')

    # Indexes for common queries
    __table_args__ = (
        Index('idx_threats_created_at', 'created_at'),
        Index('idx_threats_severity', 'severity'),
        Index('idx_threats_sensor', 'detected_by'),
        Index('idx_threats_source_type', 'source_mac', 'threat_type'),
        Index('idx_threats_source_type_created', 'source_mac', 'threat_type', 'created_at'),
    )

    def __repr__(self):
        return f'<Threat {self.threat_type}>'


class ThreatEvent(db.Model):
    __tablename__ = 'threat_events'

    id = db.Column(Integer, primary_key=True)
    threat_id = db.Column(Integer, ForeignKey('threats.id', ondelete='CASCADE'), nullable=False)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id'))
    time = db.Column(DateTime, default=datetime.utcnow, nullable=False)
    event_data = db.Column(JSON)  # Additional metadata
    packet_count = db.Column(Integer)
    signal_strength = db.Column(Integer)
    created_at = db.Column(DateTime, default=datetime.utcnow)

    # Indexes for time-series queries
    __table_args__ = (
        Index('idx_threat_events_threat_time', 'threat_id', 'time'),
        Index('idx_threat_events_sensor_time', 'sensor_id', 'time'),
    )

    def __repr__(self):
        return f'<ThreatEvent threat={self.threat_id}>'


# ==================== Alerts ====================

class AlertRule(db.Model):
    __tablename__ = 'alert_rules'

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(255), nullable=False)
    description = db.Column(Text)
    threat_type = db.Column(String(100))
    severity = db.Column(String(50))
    is_enabled = db.Column(Boolean, default=True)
    action_type = db.Column(String(50))  # block, alert, log
    created_by = db.Column(Integer, ForeignKey('users.id'))
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    alerts = relationship('Alert', backref='rule')

    # Index
    __table_args__ = (
        Index('idx_alert_rules_enabled', 'is_enabled'),
    )

    def __repr__(self):
        return f'<AlertRule {self.name}>'


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(Integer, primary_key=True)
    threat_id = db.Column(Integer, ForeignKey('threats.id'))
    rule_id = db.Column(Integer, ForeignKey('alert_rules.id'))
    message = db.Column(Text)
    is_read = db.Column(Boolean, default=False)
    is_acknowledged = db.Column(Boolean, default=False)
    acknowledged_by = db.Column(Integer, ForeignKey('users.id'))
    acknowledged_at = db.Column(DateTime)
    created_at = db.Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Alert {self.id}>'


# ==================== Incidents ====================

class Incident(db.Model):
    __tablename__ = 'incidents'

    id = db.Column(Integer, primary_key=True)
    title = db.Column(String(255), nullable=False)
    description = db.Column(Text)
    severity = db.Column(String(50))
    status = db.Column(String(50), default='open')  # open, investigating, resolved, closed
    threat_ids = db.Column(JSON)  # Array of related threat IDs
    assigned_to = db.Column(Integer, ForeignKey('users.id'))
    created_by = db.Column(Integer, ForeignKey('users.id'))
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(DateTime)

    # Relationships
    events = relationship('IncidentEvent', backref='incident', cascade='all, delete-orphan')

    # Index
    __table_args__ = (
        Index('idx_incidents_status', 'status'),
    )

    def __repr__(self):
        return f'<Incident {self.title}>'


class IncidentEvent(db.Model):
    __tablename__ = 'incident_events'

    id = db.Column(Integer, primary_key=True)
    incident_id = db.Column(Integer, ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False)
    event_type = db.Column(String(100))  # status_change, comment, action_taken
    event_data = db.Column(JSON)
    created_by = db.Column(Integer, ForeignKey('users.id'))
    created_at = db.Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<IncidentEvent {self.event_type}>'


# ==================== Reports & Audit ====================

class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(Integer, primary_key=True)
    title = db.Column(String(255), nullable=False)
    report_type = db.Column(String(100))  # daily, weekly, monthly, custom
    generated_by = db.Column(Integer, ForeignKey('users.id'))
    start_date = db.Column(String(10))
    end_date = db.Column(String(10))
    threat_summary = db.Column(JSON)
    sensor_summary = db.Column(JSON)
    file_path = db.Column(String(500))
    created_at = db.Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Report {self.title}>'


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey('users.id'))
    action = db.Column(String(255), nullable=False)
    entity_type = db.Column(String(100))
    entity_id = db.Column(Integer)
    changes = db.Column(JSON)
    ip_address = db.Column(String(45))
    created_at = db.Column(DateTime, default=datetime.utcnow)

    # Indexes
    __table_args__ = (
        Index('idx_audit_logs_user', 'user_id'),
        Index('idx_audit_logs_created', 'created_at'),
    )

    def __repr__(self):
        return f'<AuditLog {self.action}>'


# ==================== Network & Blocking ====================

class NetworkTopology(db.Model):
    __tablename__ = 'network_topology'

    id = db.Column(Integer, primary_key=True)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id'))
    discovered_networks = db.Column(JSON)  # Array of SSIDs
    discovered_devices = db.Column(JSON)  # Array of device info
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<NetworkTopology sensor={self.sensor_id}>'


class BlockedDevice(db.Model):
    __tablename__ = 'blocked_devices'

    id = db.Column(Integer, primary_key=True)
    mac_address = db.Column(String(17), unique=True, nullable=False)
    device_name = db.Column(String(255))
    reason = db.Column(Text)
    is_active = db.Column(Boolean, default=True)
    blocked_by = db.Column(Integer, ForeignKey('users.id'))
    created_at = db.Column(DateTime, default=datetime.utcnow)
    expires_at = db.Column(DateTime)

    def __repr__(self):
        return f'<BlockedDevice {self.mac_address}>'
