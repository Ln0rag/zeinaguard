-- ZeinaGuard Database Schema
-- Core tables for WIDPS system

SELECT 'Initializing ZeinaGuard Database Schema...' AS info;

-- Users and Authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- Sensors
CREATE TABLE IF NOT EXISTS sensors (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    hostname VARCHAR(255) UNIQUE,
    ip_address INET,
    mac_address MACADDR,
    location VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    firmware_version VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sensor Health (Time-Series Data)
CREATE TABLE IF NOT EXISTS sensor_health (
    id SERIAL,
    sensor_id INTEGER REFERENCES sensors(id) ON DELETE CASCADE,
    status VARCHAR(50), -- online, offline, degraded
    signal_strength INTEGER, -- 0-100
    cpu_usage FLOAT,
    memory_usage FLOAT,
    uptime INTEGER, -- in seconds
    last_heartbeat TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, created_at)
);

CREATE TABLE IF NOT EXISTS wifi_networks (
    id SERIAL PRIMARY KEY,
    sensor_id INTEGER NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    ssid VARCHAR(255) NOT NULL DEFAULT 'Hidden',
    bssid VARCHAR(17) NOT NULL,
    channel INTEGER,
    frequency INTEGER,
    signal_strength INTEGER,
    encryption VARCHAR(50),
    clients_count INTEGER DEFAULT 0,
    classification VARCHAR(50) DEFAULT 'UNKNOWN',
    risk_score INTEGER DEFAULT 0,
    auth_type VARCHAR(50),
    wps_info JSON,
    manufacturer VARCHAR(255),
    device_type VARCHAR(50) DEFAULT 'AP',
    uptime_seconds INTEGER NOT NULL DEFAULT 0,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_beacon TEXT,
    raw_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_wifi_networks_sensor_bssid UNIQUE (sensor_id, bssid)
);

CREATE TABLE IF NOT EXISTS network_scan_events (
    id SERIAL PRIMARY KEY,
    sensor_id INTEGER NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    network_id INTEGER REFERENCES wifi_networks(id) ON DELETE CASCADE,
    event_type VARCHAR(50) DEFAULT 'SCAN',
    severity VARCHAR(50) DEFAULT 'INFO',
    risk_score FLOAT,
    signal_strength INTEGER,
    channel INTEGER,
    reasons JSON,
    metadata JSON,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_purged BOOLEAN DEFAULT FALSE
);

-- Threats (Time-Series Data)
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    threat_type VARCHAR(100) NOT NULL, -- rogue_ap, evil_twin, deauth_attack, etc.
    severity VARCHAR(50) NOT NULL, -- critical, high, medium.
    source_mac MACADDR,
    target_mac MACADDR,
    ssid VARCHAR(255),
    detected_by INTEGER REFERENCES sensors(id),
    description TEXT,
    is_resolved BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat Events (Time-Series - Hypertable)
CREATE TABLE IF NOT EXISTS threat_events (
    time TIMESTAMP NOT NULL,
    threat_id INTEGER REFERENCES threats(id) ON DELETE CASCADE,
    sensor_id INTEGER REFERENCES sensors(id),
    event_data JSONB, -- Additional event metadata
    packet_count INTEGER,
    signal_strength INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Alerts and Rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    threat_type VARCHAR(100),
    severity VARCHAR(50),
    is_enabled BOOLEAN DEFAULT true,
    action_type VARCHAR(50), -- block, alert, log
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    threat_id INTEGER REFERENCES threats(id),
    rule_id INTEGER REFERENCES alert_rules(id),
    message TEXT,
    is_read BOOLEAN DEFAULT false,
    is_acknowledged BOOLEAN DEFAULT false,
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats(created_at);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_sensor ON threats(detected_by);
CREATE INDEX IF NOT EXISTS idx_sensor_health_sensor ON sensor_health(sensor_id);
CREATE INDEX IF NOT EXISTS idx_sensor_health_created ON sensor_health(created_at);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_sensor_last_seen ON wifi_networks(sensor_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_last_seen ON wifi_networks(last_seen);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_signal ON wifi_networks(signal_strength);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_bssid ON wifi_networks(bssid);
CREATE INDEX IF NOT EXISTS idx_scan_events_sensor_time ON network_scan_events(sensor_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_events_scanned_at ON network_scan_events(scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_events_network ON network_scan_events(network_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_purged ON network_scan_events(is_purged);
CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(is_enabled);
CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts(threat_id);