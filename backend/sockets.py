import collections
import time
import json
import os
import redis
from datetime import datetime
from flask import request
from flask_socketio import emit
from models import db, Threat, MitigationAudit

# الاتصال بـ Redis (بما إنك شغال محلي)
redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=6379, db=0, decode_responses=True)

# Rate limiting map for kill switch: operator_id -> last_invoked_timestamp
kill_switch_cooldowns = {}

DASHBOARD_ROOM = "dashboards"

def _sensor_room(sensor_id: int) -> str:
    return f"sensor:{sensor_id}"

def register_soc_sockets(socketio):
    
    @socketio.on('join_terminal')
    def on_join_terminal(payload):
        """الاشتراك في غرفة خاصة بلوجات شبكة معينة فقط لمنع تداخل اللوجات"""
        bssid = payload.get('bssid')
        if bssid:
            from flask_socketio import join_room
            join_room(f"terminal:{bssid}")
            print(f"[Socket] Client joined terminal room: {bssid}")

    @socketio.on('deauth_log')
    def handle_deauth_log(payload):
        bssid = payload.get('bssid')
        if not bssid: return
        
        # توحيد التنسيق (Uppercase) ليطابق ما يطلبه الـ UI في الصورة
        bssid_upper = bssid.upper() 
        
        # 1. إرسال اللوج للغرفة الخاصة بالـ Terminal اللي إنت فاتحها
        # الاسم لازم يكون 'deauth_log_specific' والـ room لازم يكون 'terminal:MAC_ADDRESS'
        emit('deauth_log_specific', payload, room=f"terminal:{bssid_upper}")
        
        # 2. حفظ في الـ History (الداتابيز)
        from models import db, Threat, ThreatEvent
        threat = Threat.query.filter_by(source_mac=bssid_upper, is_resolved=False).first()
        if threat:
            db.session.add(ThreatEvent(threat_id=threat.id, event_data={'message': payload.get('message')}))
            db.session.commit()

    @socketio.on('sensor_attack_status')
    def handle_sensor_status_update(payload):
        """تحديث حالة الهجوم في قاعدة البيانات وإبلاغ الداشبورد"""
        bssid = payload.get('bssid')
        status = payload.get('status')
        if not bssid or not status:
            return

        # 1. تحديث حالة التهديد في PostgreSQL فوراً لضمان مزامنة البيانات
        threat = Threat.query.filter_by(source_mac=bssid).order_by(Threat.created_at.desc()).first()
        if threat:
            threat.action_status = status
            # أرشفة التهديد إذا انتهى الهجوم بنجاح أو تدخل المشغل
            if status in ['KILLED', 'EVALUATING']:
                threat.is_auto_mitigated = True
                threat.auto_mitigated_at = datetime.utcnow()
            db.session.commit()
            print(f"[DB Update] Threat {bssid} status changed to {status}")

        # 2. إرسال الخبر للداشبورد لتحديث حالة الشبكة في الجدول (ألوان الـ UI)
        emit('attack_state_change', payload, room=DASHBOARD_ROOM)
        
        # 3. إجبار الكروت (Stats) على تحديث الأرقام فوراً
        emit('stats_update_required', room=DASHBOARD_ROOM)

    @socketio.on('join_dashboard')
    def on_dashboard_join():
        from flask_socketio import join_room
        join_room(DASHBOARD_ROOM)
        print(f"[Socket] Client joined dashboard room: {request.sid}")

    @socketio.on('request_log_history')
    def handle_log_history(payload):
        """استرجاع اللوجات القديمة من Redis لما الداشبورد تفتح"""
        bssid = payload.get('bssid')
        if not bssid:
            return
            
        redis_key = f"zeinaguard:logs:{bssid}"
        raw_logs = redis_client.lrange(redis_key, 0, 49)
        logs = [json.loads(log) for log in raw_logs]
        emit('log_history_response', {'bssid': bssid, 'history': logs})

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
            
        import uuid
        kill_token = str(uuid.uuid4())
        
        command_payload = {
            "type": "KILL_ATTACK",
            "bssid": bssid,
            "sensor_id": sensor_id,
            "kill_token": kill_token,
            "operator_id": operator_id,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        threat = Threat.query.filter_by(source_mac=bssid).order_by(Threat.created_at.desc()).first()
        if threat:
            audit = MitigationAudit(
                threat_id=threat.id,
                bssid=bssid,
                sensor_id=sensor_id,
                action_type="kill_switch",
                operator_id=operator_id,
                details={"kill_token": kill_token}
            )
            db.session.add(audit)
            db.session.commit()
            
        emit('execute_kill', command_payload, room=_sensor_room(sensor_id))