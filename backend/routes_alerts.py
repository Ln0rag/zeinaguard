from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import desc

from models import Alert, AlertRule, db

alerts_bp = Blueprint('alerts', __name__, url_prefix='/api/alerts')


@alerts_bp.route('', methods=['GET'])
@alerts_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def get_alerts():
    alerts = Alert.query.order_by(desc(Alert.created_at)).limit(100).all()
    data = [
        {
            'id': alert.id,
            'rule_name': alert.rule.name if alert.rule else 'Alert',
            'trigger_condition': alert.rule.description if alert.rule and alert.rule.description else (alert.message or ''),
            'severity': (alert.rule.severity if alert.rule and alert.rule.severity else 'medium'),
            'is_active': not bool(alert.is_acknowledged),
            'is_read': bool(alert.is_read),
            'is_acknowledged': bool(alert.is_acknowledged),
            'message': alert.message,
            'created_at': alert.created_at.isoformat() if alert.created_at else None,
        }
        for alert in alerts
    ]
    return jsonify(data), 200


@alerts_bp.route('/<int:alert_id>/acknowledge', methods=['POST'])
@jwt_required(optional=True)
def acknowledge_alert(alert_id: int):
    alert = Alert.query.get(alert_id)
    if alert is None:
        return jsonify({'error': 'Alert not found'}), 404

    alert.is_acknowledged = True
    alert.is_read = True
    db.session.commit()
    return jsonify({'status': 'ok', 'alert_id': alert_id}), 200
