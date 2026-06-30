"""
SQLAlchemy >> Defines all database tables and relationships
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

# ==================== Sensors ====================

class Sensor(db.Model):
    __tablename__ = 'sensors'

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(255), nullable=False)
    hostname = db.Column(String(255), unique=True)
    ip_address = db.Column(String(45))
    mac_address = db.Column(String(17))
    location = db.Column(String(255))
    is_active = db.Column(Boolean, default=True)
    firmware_version = db.Column(String(50))
    last_heartbeat = db.Column(DateTime)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    health_records = relationship('SensorHealth', backref='sensor', cascade='all, delete-orphan')
    threats = relationship('Threat', backref='detecting_sensor')
    wifi_networks = relationship('WiFiNetwork', backref='sensor', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Sensor {self.name}>'


class SensorHealth(db.Model):
    __tablename__ = 'sensor_health'

    id = db.Column(Integer, primary_key=True)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(String(50), default='online')
    signal_strength = db.Column(Integer)
    cpu_usage = db.Column(Float)
    memory_usage = db.Column(Float)
    uptime = db.Column(Integer)
    last_heartbeat = db.Column(DateTime)
    created_at = db.Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('idx_sensor_health_sensor_created', 'sensor_id', 'created_at'),
    )

    def __repr__(self):
        return f'<SensorHealth sensor={self.sensor_id}>'


# ==================== WiFi Networks (Optimized for high-frequency scans) ====================

class WiFiNetwork(db.Model):
    __tablename__ = 'wifi_networks'

    id = db.Column(Integer, primary_key=True)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id', ondelete='CASCADE'), nullable=False)

    ssid = db.Column(String(255), nullable=False, index=True)
    bssid = db.Column(String(17), nullable=False, index=True)  #format: XX:XX:XX:XX:XX:XX

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
    ap_uptime = db.Column(Integer)  # True AP hardware uptime in seconds

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
        Index('idx_wifi_networks_bssid_sensor', 'bssid', 'sensor_id'),
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
    severity = db.Column(String(50), default='LOW')  # CRITICAL, HIGH, MEDIUM, LOW
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
    severity = db.Column(String(50), nullable=False)  # critical, high, medium.
    source_mac = db.Column(String(17))
    target_mac = db.Column(String(17))
    ssid = db.Column(String(255))
    detected_by = db.Column(Integer, ForeignKey('sensors.id'))
    description = db.Column(Text)
    is_resolved = db.Column(Boolean, default=False)
    ap_uptime = db.Column(Integer)  # True AP hardware uptime in seconds
    
    # Auto-Containment fields
    is_auto_mitigated = db.Column(Boolean, default=False)
    auto_mitigated_at = db.Column(DateTime)
    mitigated_by_sensor_id = db.Column(Integer)

    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    events = db.relationship('ThreatEvent', backref='threat_parent', cascade='all, delete-orphan')
    mitigations = db.relationship('MitigationAudit', backref='threat_parent', cascade='all, delete-orphan')

    # Indexes for common queries
    __table_args__ = (
        Index('idx_threats_created_at', 'created_at'),
        Index('idx_threats_severity', 'severity'),
        Index('idx_threats_sensor', 'detected_by'),
        Index('idx_threats_source_type', 'source_mac', 'threat_type'),
        Index('idx_threats_source_type_created', 'source_mac', 'threat_type', 'created_at'),
        Index('idx_threats_dedup_lookup', 'source_mac', 'threat_type', 'is_resolved'),
    )

    def __repr__(self):
        return f'<Threat {self.threat_type}>'


class ThreatEvent(db.Model):
    __tablename__ = 'threat_events'

    id = db.Column(Integer, primary_key=True)
    threat_id = db.Column(Integer, ForeignKey('threats.id', ondelete='CASCADE'), nullable=False)
    sensor_id = db.Column(Integer, ForeignKey('sensors.id'))
    time = db.Column(DateTime, default=datetime.utcnow, nullable=False)
    event_data = db.Column(JSON)
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


# ==================== Audit ====================

class MitigationAudit(db.Model):
    """Audit trail for all automated and manual containment actions"""
    __tablename__ = 'mitigation_audits'

    id = db.Column(Integer, primary_key=True)
    threat_id = db.Column(Integer, ForeignKey('threats.id', ondelete='CASCADE'), nullable=False)
    bssid = db.Column(String(17), nullable=False)
    sensor_id = db.Column(Integer, nullable=False)
    action_type = db.Column(String(50), nullable=False)  # auto_contain, kill_switch, trust_added
    operator_id = db.Column(String(255))  # Nullable, for human operator actions
    timestamp = db.Column(DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(JSON)  # Extra context

    # Relationships
    pass

    __table_args__ = (
        Index('idx_mitigation_audits_threat', 'threat_id'),
        Index('idx_mitigation_audits_sensor_time', 'sensor_id', 'timestamp'),
    )

    def __repr__(self):
        return f'<MitigationAudit {self.action_type} on {self.bssid}>'
