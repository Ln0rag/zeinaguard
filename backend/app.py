"""
ZeinaGuard Flask backend entrypoint.
"""

from __future__ import annotations

import os

if os.getenv("SOCKETIO_ASYNC_MODE", "eventlet") == "eventlet":
    import eventlet
    eventlet.monkey_patch()

import logging
import os
import socket
import sys
import time
from importlib.util import find_spec
from pathlib import Path
from datetime import timedelta

sys.path.append(str(Path(__file__).resolve().parent.parent / "sensor"))
from config import add_trusted_mac, get_trusted_macs, normalize_mac, remove_trusted_mac

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from models import db, Threat
from routes import register_blueprints
from schema_migration import apply_runtime_migrations
from websocket_server import dispatch_attack_command, get_realtime_status, init_socketio, mark_network_trusted

def configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    logging.getLogger("engineio").setLevel(logging.ERROR)
    logging.getLogger("socketio").setLevel(logging.ERROR)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.ERROR)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.ERROR)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    app_logger = logging.getLogger("zeinaguard")
    app_logger.setLevel(logging.INFO)
    return app_logger


logger = configure_logging()

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DB_CONNECT_RETRIES = int(os.getenv("DB_CONNECT_RETRIES", "15"))
DB_CONNECT_DELAY_SECONDS = float(os.getenv("DB_CONNECT_DELAY_SECONDS", "2"))


def is_tcp_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_database_url() -> str:
    explicit_url = os.getenv("DATABASE_URL")
    if explicit_url:
        return explicit_url

    user = os.getenv("POSTGRES_USER", "zeinaguard_user")
    password = os.getenv("POSTGRES_PASSWORD", "secure_password")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    database = os.getenv("POSTGRES_DB", "zeinaguard_db")
    postgres_url = f"postgresql://{user}:{password}@{host}:{port}/{database}"

    if find_spec("psycopg2") is None:
        logger.critical("[FATAL] 'psycopg2' library is missing! PostgreSQL is mandatory for ZeinaGuard performance.")
        sys.exit(1)

    if not is_tcp_port_open(host, int(port)):
        logger.critical(f"[FATAL] PostgreSQL is NOT reachable at {host}:{port}. Check if service is running.")
        sys.exit(1)

    return postgres_url


def initialize_database():
    logger.info("[DB] Initializing database at %s", db.engine.url.render_as_string(hide_password=True))

    last_error = None
    for attempt in range(1, DB_CONNECT_RETRIES + 1):
        try:
            db.session.execute(text("SELECT 1"))
            db.create_all()
            apply_runtime_migrations()

            db.session.commit()
            logger.info("[DB] Database connection verified")
            return
        except OperationalError as exc:
            last_error = exc
            db.session.rollback()
            logger.warning("[DB] Connection attempt %s/%s failed: %s", attempt, DB_CONNECT_RETRIES, exc)
            if attempt < DB_CONNECT_RETRIES:
                time.sleep(DB_CONNECT_DELAY_SECONDS)
            else:
                break
        except Exception:
            db.session.rollback()
            logger.exception("[DB] Database initialization failed")
            raise

    logger.critical("[FATAL] Could not establish a stable connection to PostgreSQL. Exiting.")
    sys.exit(1)


def register_routes(app):
    @app.route("/health", methods=["GET"])
    def health():
        """Endpoint for frontend to check system status and connectivity."""
        realtime_status = get_realtime_status()
        return jsonify(
            {
                "status": "healthy",
                "service": "zeinaguard-backend",
                "socketio": "initialized" if getattr(app, "socketio", None) else "not_initialized",
                "redis": realtime_status["redis"],
                "queue": realtime_status["queue"],
                "connected_sensors": realtime_status["connected_sensors"],
            }
        ), 200

    @app.route("/ready", methods=["GET"])
    def ready():
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"ready": True, "database": "connected"}), 200
        except Exception as exc:
            logger.warning("[DB] Readiness check failed: %s", exc)
            return jsonify({"ready": False, "error": str(exc)}), 503

    @app.route("/", methods=["GET"])
    def root():
        return jsonify(
            {
                "service": "ZeinaGuard Backend",
                "version": "1.0.0",
                "description": "Wireless Intrusion Detection & Prevention System API",
            }
        ), 200

    @app.route("/api/attack", methods=["POST"])
    def attack():
        payload = request.get_json(silent=True) or {}
        logger.info("[Attack API] request received payload=%s", payload)
        ack_payload, status_code = dispatch_attack_command(app.socketio, payload)
        return jsonify(ack_payload), status_code

    @app.route("/trust", methods=["POST"])
    def add_trusted():
        data = request.get_json(silent=True) or {}
        bssid = normalize_mac(data.get("bssid"))
        ssid = str(data.get("ssid") or "Unknown Network").strip()

        if not bssid:
            return jsonify({"error": "Missing BSSID"}), 400

        add_trusted_mac(bssid, ssid)
        
        mark_network_trusted(getattr(app, "socketio", None), bssid)

        return jsonify({
            "status": "added",
            "bssid": bssid,
            "trusted_list": list(get_trusted_macs().keys()),
        })

    @app.route("/untrust", methods=["POST"])
    def remove_trusted():
        data = request.get_json(silent=True) or {}
        bssid = normalize_mac(data.get("bssid"))

        if not bssid:
            return jsonify({"error": "Missing BSSID"}), 400

        success = remove_trusted_mac(bssid)
        if not success:
            return jsonify({"error": "BSSID not found or cannot be removed"}), 404

        return jsonify({
            "status": "removed",
            "bssid": bssid,
            "trusted_list": list(get_trusted_macs().keys()),
        })

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Not Found", "message": str(error)}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal Server Error", "message": str(error)}), 500

    @app.errorhandler(Exception)
    def handle_exception(error):
        if isinstance(error, HTTPException):
            return jsonify({"error": error.name, "message": error.description}), error.code
        logger.exception("[App] Unhandled exception")
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500


def create_app(config_object=None):
    app = Flask(__name__)

    app.config["JSON_SORT_KEYS"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", build_database_url())
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ECHO"] = False
    app.config["SOCKETIO_ASYNC_MODE"] = os.getenv("SOCKETIO_ASYNC_MODE", "eventlet")
    app.config["SOCKETIO_CORS_ALLOWED_ORIGINS"] = os.getenv("CORS_ORIGINS", "*")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_POOL_MAX_OVERFLOW", "20")),
        "pool_timeout": int(os.getenv("DB_POOL_TIMEOUT_SECONDS", "30")),
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE_SECONDS", "1800")),
    }

    if config_object:
        app.config.from_object(config_object)

    CORS(app, resources={r"/*": {"origins": os.getenv("CORS_ORIGINS", "*")}}, supports_credentials=True)

    db.init_app(app)

    with app.app_context():
        initialize_database()

    app.socketio = init_socketio(app)
    
    from sockets import register_soc_sockets
    register_soc_sockets(app.socketio)
    
    from routes_operation_center import operation_center_bp
    app.register_blueprint(operation_center_bp)
    
    register_blueprints(app)
    register_routes(app)
    logger.info("[App] Startup completed")

    return app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.socketio.run(
        app,
        host="127.0.0.1",
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True,
        use_reloader=debug,
    )