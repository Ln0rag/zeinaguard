-- TimescaleDB Extension and Hypertable Configuration
-- This script converts regular tables into hypertables for optimal time-series performance
-- Updated for ZeinaGuard Pro with WiFi Networks support

SELECT 'Enabling TimescaleDB Extension...' AS info;
-- Ensure TimescaleDB extension is created
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- =========================================================
-- 1. WiFi Networks Table (Optimized for high-frequency scans)
-- =========================================================

SELECT 'Creating wifi_networks table...' AS info;

CREATE TABLE IF NOT EXISTS wifi_networks (
    id SERIAL PRIMARY KEY,
    sensor_id INTEGER NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,

    -- Network identification
    ssid VARCHAR(255) NOT NULL,
    bssid VARCHAR(17) NOT NULL,

    -- Network properties
    channel INTEGER,
    frequency INTEGER,
    signal_strength INTEGER,
    encryption VARCHAR(50),
    auth_type VARCHAR(50),
    wps_info JSONB,

    -- Additional metadata
    manufacturer VARCHAR(255),
    device_type VARCHAR(50) DEFAULT 'AP',
    uptime_seconds INTEGER,

    -- Deduplication counters
    seen_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Raw data for debugging
    raw_beacon TEXT,

    -- Constraints and indexes
    CONSTRAINT uq_sensor_bssid UNIQUE (sensor_id, bssid)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_wifi_networks_ssid ON wifi_networks(ssid);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_bssid ON wifi_networks(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_sensor_id ON wifi_networks(sensor_id);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_sensor_lastseen ON wifi_networks(sensor_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_wifi_networks_signal ON wifi_networks(signal_strength);

-- =========================================================
-- 2. Network Scan Events (Time-Series - Hypertable)
-- =========================================================

SELECT 'Creating network_scan_events hypertable...' AS info;

CREATE TABLE IF NOT EXISTS network_scan_events (
    id SERIAL PRIMARY KEY,
    sensor_id INTEGER NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    network_id INTEGER REFERENCES wifi_networks(id) ON DELETE CASCADE,

    -- Event data
    event_type VARCHAR(50) DEFAULT 'SCAN',
    severity VARCHAR(50) DEFAULT 'INFO',
    risk_score FLOAT,

    -- Snapshot of network state
    signal_strength INTEGER,
    channel INTEGER,

    -- Additional context
    reasons JSONB,
    metadata JSONB,

    -- Timestamp
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Cleanup marker
    is_purged BOOLEAN DEFAULT FALSE
);

-- Convert to hypertable for time-series optimization
SELECT create_hypertable('network_scan_events', 'scanned_at', if_not_exists => TRUE);

-- Indexes for time-series queries
CREATE INDEX IF NOT EXISTS idx_scan_events_sensor_time ON network_scan_events(sensor_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_events_network ON network_scan_events(network_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_severity ON network_scan_events(severity);
CREATE INDEX IF NOT EXISTS idx_scan_events_purged ON network_scan_events(is_purged);

-- =========================================================
-- 3. Convert existing tables to hypertables
-- =========================================================

SELECT 'Converting existing tables to hypertables...' AS info;

-- Convert threat_events to hypertable
SELECT create_hypertable('threat_events', 'time', if_not_exists => TRUE);

-- Convert sensor_health to hypertable
SELECT create_hypertable('sensor_health', 'created_at', if_not_exists => TRUE);

-- =========================================================
-- 4. Compression Configuration
-- =========================================================

SELECT 'Configuring compression policies...' AS info;

-- WiFi Networks: No compression (frequently updated)
-- Network Scan Events: Compress after 7 days
ALTER TABLE network_scan_events SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'scanned_at DESC',
    timescaledb.compress_segmentby = 'sensor_id'
);
SELECT add_compression_policy('network_scan_events', INTERVAL '7 days', if_not_exists => TRUE);

-- Threat Events: Compress after 7 days
ALTER TABLE threat_events SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'time DESC',
    timescaledb.compress_segmentby = 'threat_id, sensor_id'
);
SELECT add_compression_policy('threat_events', INTERVAL '7 days', if_not_exists => TRUE);

-- Sensor Health: Compress after 7 days
ALTER TABLE sensor_health SET (
    timescaledb.compress,
    timescaledb.compress_orderby = 'created_at DESC',
    timescaledb.compress_segmentby = 'sensor_id'
);
SELECT add_compression_policy('sensor_health', INTERVAL '7 days', if_not_exists => TRUE);

-- =========================================================
-- 5. Retention Policies (Automatic Data Cleanup)
-- =========================================================

SELECT 'Configuring retention policies...' AS info;

-- Network scan events: Keep for 30 days (reduced from 90 for high-frequency scans)
SELECT add_retention_policy('network_scan_events', INTERVAL '30 days', if_not_exists => TRUE);

-- Threat events: Keep for 90 days
SELECT add_retention_policy('threat_events', INTERVAL '90 days', if_not_exists => TRUE);

-- Sensor health: Keep for 90 days
SELECT add_retention_policy('sensor_health', INTERVAL '90 days', if_not_exists => TRUE);

-- =========================================================
-- 6. Continuous Aggregates (Real-time Materialized Views)
-- =========================================================

SELECT 'Creating continuous aggregates...' AS info;

-- Hourly network scan statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS scan_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', scanned_at) as bucket,
    sensor_id,
    COUNT(*) as total_scans,
    COUNT(DISTINCT network_id) as unique_networks,
    AVG(signal_strength) as avg_signal,
    COUNT(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH')) as high_severity_count
FROM network_scan_events
GROUP BY bucket, sensor_id;

-- Daily network scan statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS scan_events_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', scanned_at) as bucket,
    sensor_id,
    COUNT(*) as total_scans,
    COUNT(DISTINCT network_id) as unique_networks,
    AVG(signal_strength) as avg_signal,
    MIN(signal_strength) as min_signal,
    MAX(signal_strength) as max_signal,
    COUNT(*) FILTER (WHERE severity IN ('CRITICAL', 'HIGH')) as high_severity_count
FROM network_scan_events
GROUP BY bucket, sensor_id;

-- Daily threat summary (existing)
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_events_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) as bucket,
    threat_id,
    sensor_id,
    COUNT(*) as event_count,
    AVG(packet_count) as avg_packets,
    MAX(signal_strength) as max_signal,
    MIN(signal_strength) as min_signal
FROM threat_events
GROUP BY bucket, threat_id, sensor_id;

-- Hourly threat summary (existing)
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) as bucket,
    threat_id,
    sensor_id,
    COUNT(*) as event_count,
    AVG(packet_count) as avg_packets
FROM threat_events
GROUP BY bucket, threat_id, sensor_id;

-- Sensor health daily summary (existing)
CREATE MATERIALIZED VIEW IF NOT EXISTS sensor_health_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', created_at) as bucket,
    sensor_id,
    AVG(CAST(signal_strength AS FLOAT)) as avg_signal,
    AVG(cpu_usage) as avg_cpu,
    AVG(memory_usage) as avg_memory,
    MAX(uptime) as max_uptime
FROM sensor_health
GROUP BY bucket, sensor_id;

-- =========================================================
-- 7. Continuous Aggregate Refresh Policies
-- =========================================================

SELECT 'Configuring refresh policies...' AS info;

SELECT add_continuous_aggregate_policy('scan_events_hourly',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE);

SELECT add_continuous_aggregate_policy('scan_events_daily',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

SELECT add_continuous_aggregate_policy('threat_events_daily',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

SELECT add_continuous_aggregate_policy('threat_events_hourly',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '15 minutes',
    if_not_exists => TRUE);

SELECT add_continuous_aggregate_policy('sensor_health_daily',
    start_offset => INTERVAL '1 month',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

-- =========================================================
-- 8. Additional Indexes
-- =========================================================

SELECT 'Creating additional indexes...' AS info;

CREATE INDEX IF NOT EXISTS threat_events_threat_time ON threat_events (threat_id, time DESC);
CREATE INDEX IF NOT EXISTS threat_events_sensor_time ON threat_events (sensor_id, time DESC);
CREATE INDEX IF NOT EXISTS sensor_health_sensor_time ON sensor_health (sensor_id, created_at DESC);

-- =========================================================
-- 9. Helper Functions
-- =========================================================

SELECT 'Creating helper functions...' AS info;

-- Function to cleanup old scan events manually (if needed)
CREATE OR REPLACE FUNCTION cleanup_old_scan_events(retention_hours INTEGER DEFAULT 720)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
    cutoff_time TIMESTAMP;
BEGIN
    cutoff_time := CURRENT_TIMESTAMP - (retention_hours || ' hours')::INTERVAL;

    -- Delete old events
    DELETE FROM network_scan_events
    WHERE scanned_at < cutoff_time;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get current network state
CREATE OR REPLACE FUNCTION get_current_network_state(p_sensor_id INTEGER DEFAULT NULL)
RETURNS TABLE (
    id INTEGER,
    sensor_id INTEGER,
    ssid VARCHAR,
    bssid VARCHAR,
    channel INTEGER,
    signal_strength INTEGER,
    encryption VARCHAR,
    manufacturer VARCHAR,
    seen_count INTEGER,
    last_seen TIMESTAMP,
    status VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        wn.id,
        wn.sensor_id,
        wn.ssid,
        wn.bssid,
        wn.channel,
        wn.signal_strength,
        wn.encryption,
        wn.manufacturer,
        wn.seen_count,
        wn.last_seen,
        CASE
            WHEN wn.last_seen < CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 'offline'
            ELSE 'active'
        END AS status
    FROM wifi_networks wn
    WHERE (p_sensor_id IS NULL OR wn.sensor_id = p_sensor_id)
    ORDER BY wn.last_seen DESC;
END;
$$ LANGUAGE plpgsql;

-- =========================================================
-- 10. Permissions
-- =========================================================

SELECT 'Setting permissions...' AS info;

GRANT ALL ON ALL TABLES IN SCHEMA public TO zeinaguard_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO zeinaguard_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO zeinaguard_user;

-- =========================================================
-- Summary
-- =========================================================

SELECT 'TimescaleDB configuration complete!' AS status;
SELECT 'Hypertables: threat_events, sensor_health, network_scan_events' AS info;
SELECT 'Compression: Enabled for all hypertables (7 days)' AS info;
SELECT 'Retention: network_scan_events (30 days), others (90 days)' AS info;
SELECT 'Continuous Aggregates: scan_events_hourly/daily, threat_events_hourly/daily, sensor_health_daily' AS info;
