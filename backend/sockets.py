import logging
import time
import json
import os
import uuid

import redis
from datetime import datetime, timezone
from flask_socketio import emit
from models import db, Threat, ThreatEvent, MitigationAudit

LOGGER = logging.getLogger("zeinaguard.sockets")

_redis_client = None
_LOG_RING_SIZE = int(os.getenv("DEAUTH_LOG_RING_SIZE", "50"))
_LOG_TTL_SECONDS = int(os.getenv("DEAUTH_LOG_TTL_SECONDS", str(6 * 3600)))


def _build_redis():
    """Build a Redis client, returning ``None`` on failure."""
    try:
        host = os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_PORT", "6379"))
        password = os.getenv("REDIS_PASSWORD", "") or None
        client = redis.Redis(
            host=host, port=port, password=password,
            db=0, decode_responses=True, socket_connect_timeout=2,
        )
        client.ping()
        LOGGER.info("[SOC] Redis connected at %s:%s", host, port)
        return client
    except Exception as exc:
        LOGGER.warning("[SOC] Redis unavailable (%s); log history will fall back to PostgreSQL", exc)
        return None

_redis_client = _build_redis()
kill_switch_cooldowns = {}
DASHBOARD_ROOM = "dashboards"

def _sensor_room(sensor_id: int) -> str:
    return f"sensor:{sensor_id}"


def _push_log_to_redis(bssid: str, log_entry: dict) -> bool:

    global _redis_client
    if _redis_client is None:
        return False

    redis_key = f"zeinaguard:logs:{bssid}"
    try:
        pipe = _redis_client.pipeline(transaction=False)
        pipe.lpush(redis_key, json.dumps(log_entry, default=str))
        pipe.ltrim(redis_key, 0, _LOG_RING_SIZE - 1)
        pipe.expire(redis_key, _LOG_TTL_SECONDS)
        pipe.execute()
        return True
    except redis.RedisError as exc:
        LOGGER.warning("[SOC] Redis write failed for %s: %s", bssid, exc)
        return False


# ---------------------------------------------------------------------------
# Socket event handlers
# ---------------------------------------------------------------------------

def register_soc_sockets(socketio):

    @socketio.on('threat_resolved')
    def handle_threat_resolved(payload):
        bssid = payload.get('bssid')
        if not bssid:
            return
        try:
            threat = Threat.query.filter_by(
                source_mac=bssid.upper(), 
                is_resolved=False
            ).order_by(Threat.created_at.desc()).first()
            if threat:
                new_status = payload.get('status', 'KILLED')
                if new_status == 'KILLED':
                    threat.is_auto_mitigated = True
                    threat.auto_mitigated_at = datetime.now(timezone.utc)
                db.session.commit()
                
                emit('stats_update_required', room=DASHBOARD_ROOM)
        except Exception:
            db.session.rollback()
            LOGGER.exception("[SOC] Failed to resolve threat for %s", bssid)

    @socketio.on('deauth_log')
    def handle_deauth_log(payload):
        bssid = payload.get('bssid')
        if not bssid:
            return

        bssid_upper = bssid.upper()

        log_entry = {
            "bssid": bssid_upper,
            "message": payload.get("message", ""),
            "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "sensor_id": payload.get("sensor_id"),
        }

        _push_log_to_redis(bssid_upper, log_entry)

        try:
            threat = Threat.query.filter_by(
                source_mac=bssid_upper, is_resolved=False,
            ).first()
            if threat:
                db.session.add(ThreatEvent(
                    threat_id=threat.id,
                    event_data={"message": log_entry["message"]},
                ))
                db.session.commit()
        except Exception:
            db.session.rollback()
            LOGGER.exception("[SOC] Failed to persist deauth log for %s", bssid_upper)

    @socketio.on('sensor_attack_status')
    def handle_sensor_status_update(payload):
        bssid = payload.get('bssid')
        status = payload.get('status')
        if not bssid or not status:
            return

        try:
            threat = Threat.query.filter_by(source_mac=bssid).order_by(Threat.created_at.desc()).first()
            if threat:
                if status in ('KILLED', 'EVALUATING'):
                    threat.is_auto_mitigated = True
                    threat.auto_mitigated_at = datetime.now(timezone.utc)
                db.session.commit()
        except Exception:
            db.session.rollback()
            LOGGER.exception("[SOC] Failed to update attack status for %s", bssid)

        emit('stats_update_required', room=DASHBOARD_ROOM)

    @socketio.on('join_dashboard')
    def on_dashboard_join():
        from flask_socketio import join_room
        join_room(DASHBOARD_ROOM)

    @socketio.on('kill_attack')
    def handle_kill_attack(payload):
        bssid = payload.get('bssid')
        sensor_id = payload.get('sensor_id')
        operator_id = payload.get('operator_id', 'unknown')

        if not bssid or not sensor_id:
            return

        now = time.time()
        last_invoked = kill_switch_cooldowns.get(operator_id, 0)
        if now - last_invoked < 0.1:
            emit('error', {'message': 'Kill switch on cooldown.'})
            return
        kill_switch_cooldowns[operator_id] = now

        kill_token = str(uuid.uuid4())

        command_payload = {
            "type": "KILL_ATTACK",
            "bssid": bssid,
            "sensor_id": sensor_id,
            "kill_token": kill_token,
            "operator_id": operator_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            threat = Threat.query.filter_by(source_mac=bssid).order_by(Threat.created_at.desc()).first()
            if threat:
                db.session.add(MitigationAudit(
                    threat_id=threat.id,
                    bssid=bssid,
                    sensor_id=sensor_id,
                    action_type="kill_switch",
                    operator_id=operator_id,
                    details={"kill_token": kill_token},
                ))
                db.session.commit()
        except Exception:
            db.session.rollback()
            LOGGER.exception("[SOC] Failed to persist kill_attack audit for %s", bssid)

        emit('execute_kill', command_payload, room=_sensor_room(sensor_id))