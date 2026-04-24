-- ZeinaGuard Pro Database Schema
-- Core tables for WIPS system

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

-- User Roles and Permissions
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
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

-- Network Topology
CREATE TABLE IF NOT EXISTS network_topology (
    id SERIAL PRIMARY KEY,
    sensor_id INTEGER REFERENCES sensors(id),
    discovered_networks TEXT, -- JSON array of SSIDs
    discovered_devices TEXT, -- JSON array of devices
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threats (Time-Series Data)
CREATE TABLE IF NOT EXISTS threats (
    id SERIAL PRIMARY KEY,
    threat_type VARCHAR(100) NOT NULL, -- rogue_ap, evil_twin, deauth_attack, etc.
    severity VARCHAR(50) NOT NULL, -- critical, high, medium, low, info
    source_mac MACADDR,
    target_mac MACADDR,
    ssid VARCHAR(255),
    detected_by INTEGER REFERENCES sensors(id),
    created_by INTEGER REFERENCES users(id),
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
    created_by INTEGER REFERENCES users(id),
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
    acknowledged_by INTEGER REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50),
    status VARCHAR(50) DEFAULT 'open', -- open, investigating, resolved, closed
    threat_ids TEXT, -- JSON array of related threat IDs
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incident_events (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
    event_type VARCHAR(100), -- status_change, comment, action_taken
    event_data JSONB,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Reports
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    report_type VARCHAR(100), -- daily, weekly, monthly, custom
    generated_by INTEGER REFERENCES users(id),
    start_date DATE,
    end_date DATE,
    threat_summary JSONB,
    sensor_summary JSONB,
    file_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    entity_type VARCHAR(100),
    entity_id INTEGER,
    changes JSONB,
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Blocked MAC Addresses and Devices
CREATE TABLE IF NOT EXISTS blocked_devices (
    id SERIAL PRIMARY KEY,
    mac_address MACADDR UNIQUE NOT NULL,
    device_name VARCHAR(255),
    reason TEXT,
    is_active BOOLEAN DEFAULT true,
    blocked_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
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
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);

-- Create some default roles
INSERT INTO roles (name, description) VALUES
    ('Administrator', 'Full system access'),
    ('Analyst', 'Threat analysis and incident management'),
    ('Monitor', 'View-only access to dashboard and reports'),
    ('Guest', 'Limited view-only access')
ON CONFLICT (name) DO NOTHING;

-- Create some default permissions
INSERT INTO permissions (name, description) VALUES
    ('view_dashboard', 'View main dashboard'),
    ('view_threats', 'View threat events'),
    ('manage_alerts', 'Create and manage alert rules'),
    ('manage_incidents', 'Create and manage incidents'),
    ('manage_sensors', 'Manage sensors and deployment'),
    ('manage_users', 'Manage users and roles'),
    ('view_reports', 'View reports'),
    ('generate_reports', 'Generate new reports'),
    ('manage_system', 'System configuration and maintenance'),
    ('view_audit_logs', 'View audit logs')
ON CONFLICT (name) DO NOTHING;

-- Network Topology Tables (added for topology visualization feature)
CREATE TABLE IF NOT EXISTS topology_sensors (
    id SERIAL PRIMARY KEY,
    sensor_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255),
    mac_address VARCHAR(17),
    is_active BOOLEAN DEFAULT true,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS topology_access_points (
    id SERIAL PRIMARY KEY,
    ap_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    ssid VARCHAR(255),
    mac_address VARCHAR(17),
    security VARCHAR(50),
    signal_strength INTEGER,
    is_shared BOOLEAN DEFAULT false,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS topology_stations (
    id SERIAL PRIMARY KEY,
    station_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(100),
    mac_address VARCHAR(17),
    vendor_info VARCHAR(255),
    status VARCHAR(50) DEFAULT 'offline',
    signal_strength INTEGER,
    is_shared BOOLEAN DEFAULT false,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS topology_connections (
    id SERIAL PRIMARY KEY,
    source_type VARCHAR(50) NOT NULL,
    source_id VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(100) NOT NULL,
    connection_type VARCHAR(50) DEFAULT 'association',
    signal_strength INTEGER,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_topology_sensors_active ON topology_sensors(is_active);
CREATE INDEX IF NOT EXISTS idx_topology_aps_shared ON topology_access_points(is_shared);
CREATE INDEX IF NOT EXISTS idx_topology_stations_shared ON topology_stations(is_shared);
CREATE INDEX IF NOT EXISTS idx_topology_connections_active ON topology_connections(is_active);

-- Add default Admin user (password: admin123)
-- This hash is compatible with werkzeug (pbkdf2:sha256)
INSERT INTO users (username, email, password_hash, first_name, last_name, is_admin)
VALUES (
    'admin', 
    'admin@zeinaguard.local', 
    'scrypt:32768:8:1$u7x8M8G9W2Z8S6E5$8049615024443977c030311096328373b537494553258872b2553198642232973167527653131', 
    'System', 
    'Admin', 
    true
) ON CONFLICT (username) DO NOTHING;

-- Connect Admin to Administrator Role
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id 
FROM users u, roles r 
WHERE u.username = 'admin' AND r.name = 'Administrator'
ON CONFLICT DO NOTHING;
