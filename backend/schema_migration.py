"""
Runtime schema alignment for existing PostgreSQL databases.
"""

from __future__ import annotations

import logging

from models import db
from sqlalchemy import inspect


LOGGER = logging.getLogger("zeinaguard.schema")


SCHEMA_STATEMENTS = [
    "ALTER TABLE sensors ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMP",
    """
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
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT TRUE NOT NULL,
        raw_beacon TEXT,
        raw_data JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
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
    )
    """,
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS frequency INTEGER",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS clients_count INTEGER DEFAULT 0",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS classification VARCHAR(50) DEFAULT 'UNKNOWN'",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS auth_type VARCHAR(50)",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS wps_info JSON",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS manufacturer VARCHAR(255)",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS device_type VARCHAR(50) DEFAULT 'AP'",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS uptime_seconds INTEGER DEFAULT 0",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS raw_beacon TEXT",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS raw_data JSON",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE wifi_networks ALTER COLUMN seen_count SET DEFAULT 1",
    "ALTER TABLE wifi_networks ALTER COLUMN seen_count SET NOT NULL",
    "ALTER TABLE wifi_networks ALTER COLUMN uptime_seconds SET DEFAULT 0",
    "ALTER TABLE wifi_networks ALTER COLUMN uptime_seconds SET NOT NULL",
    "ALTER TABLE wifi_networks ALTER COLUMN first_seen SET DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE wifi_networks ALTER COLUMN last_seen SET DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE wifi_networks ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE",
    "UPDATE wifi_networks SET is_active = TRUE WHERE is_active IS NULL",
    "ALTER TABLE wifi_networks ALTER COLUMN is_active SET DEFAULT TRUE",
    "ALTER TABLE wifi_networks ALTER COLUMN is_active SET NOT NULL",
    "UPDATE wifi_networks SET seen_count = 1 WHERE seen_count IS NULL",
    "UPDATE wifi_networks SET uptime_seconds = 0 WHERE uptime_seconds IS NULL",
    "UPDATE wifi_networks SET first_seen = COALESCE(first_seen, CURRENT_TIMESTAMP)",
    "UPDATE wifi_networks SET last_seen = COALESCE(last_seen, CURRENT_TIMESTAMP)",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS event_type VARCHAR(50) DEFAULT 'SCAN'",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS severity VARCHAR(50) DEFAULT 'INFO'",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS risk_score FLOAT",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS signal_strength INTEGER",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS channel INTEGER",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS reasons JSON",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS metadata JSON",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE network_scan_events ADD COLUMN IF NOT EXISTS is_purged BOOLEAN DEFAULT FALSE",
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'uq_sensor_bssid'
              AND conrelid = 'wifi_networks'::regclass
        ) THEN
            ALTER TABLE wifi_networks
            RENAME CONSTRAINT uq_sensor_bssid TO uq_wifi_networks_sensor_bssid;
        END IF;
    EXCEPTION
        WHEN duplicate_object THEN NULL;
    END
    $$;
    """,
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'uq_wifi_networks_sensor_bssid'
              AND conrelid = 'wifi_networks'::regclass
        ) THEN
            ALTER TABLE wifi_networks
            ADD CONSTRAINT uq_wifi_networks_sensor_bssid UNIQUE (sensor_id, bssid);
        END IF;
    EXCEPTION
        WHEN duplicate_object THEN NULL;
    END
    $$;
    """,
    "CREATE INDEX IF NOT EXISTS idx_wifi_networks_sensor_last_seen ON wifi_networks(sensor_id, last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_wifi_networks_sensor_bssid ON wifi_networks(sensor_id, bssid)",
    "CREATE INDEX IF NOT EXISTS idx_wifi_networks_last_seen ON wifi_networks(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_wifi_networks_active_last_seen ON wifi_networks(is_active, last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_wifi_networks_signal ON wifi_networks(signal_strength)",
    "CREATE INDEX IF NOT EXISTS idx_wifi_networks_bssid ON wifi_networks(bssid)",
    "CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_threats_source_type ON threats(source_mac, threat_type)",
    "CREATE INDEX IF NOT EXISTS idx_threats_source_type_created ON threats(source_mac, threat_type, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_scan_events_sensor_time ON network_scan_events(sensor_id, scanned_at)",
    "CREATE INDEX IF NOT EXISTS idx_scan_events_scanned_at ON network_scan_events(scanned_at)",
    "CREATE INDEX IF NOT EXISTS idx_scan_events_network ON network_scan_events(network_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_events_purged ON network_scan_events(is_purged)",
]


SQLITE_MIGRATIONS = [
    ("sensors", "last_heartbeat", "ALTER TABLE sensors ADD COLUMN last_heartbeat DATETIME"),
]


def apply_sqlite_runtime_migrations() -> None:
    inspector = inspect(db.engine)
    with db.engine.begin() as connection:
        for table_name, column_name, statement in SQLITE_MIGRATIONS:
            existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            if column_name in existing_columns:
                continue
            LOGGER.info("[DB] Applying SQLite runtime migration: %s.%s", table_name, column_name)
            connection.exec_driver_sql(statement)
    LOGGER.info("[DB] SQLite runtime schema migrations complete")


def apply_runtime_migrations() -> None:
    if db.engine.dialect.name == "sqlite":
        apply_sqlite_runtime_migrations()
        return

    if db.engine.dialect.name != "postgresql":
        LOGGER.info("[DB] Skipping PostgreSQL runtime migrations for dialect=%s", db.engine.dialect.name)
        return

    LOGGER.info("[DB] Applying runtime schema migrations")
    with db.engine.begin() as connection:
        for statement in SCHEMA_STATEMENTS:
            connection.exec_driver_sql(statement)
    LOGGER.info("[DB] Runtime schema migrations complete")
