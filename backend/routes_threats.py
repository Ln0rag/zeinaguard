"""
Threats API Routes for ZeinaGuard Pro
Handles threat event retrieval, resolution, and simulation
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from models import db, Threat, ThreatEvent, Sensor
from websocket_server import broadcast_threat_event

threats_bp = Blueprint('threats', __name__, url_prefix='/api/threats')


@threats_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def get_threats():
    """Get list of threats from the database"""
    try:
        limit = request.args.get('limit', default=50, type=int)
        severity = request.args.get('severity', type=str)
        is_resolved = request.args.get('resolved', type=lambda v: v.lower() == 'true')

        query = Threat.query

        if severity:
            query = query.filter_by(severity=severity)

        if is_resolved is not None:
            query = query.filter_by(is_resolved=is_resolved)

        threats = query.order_by(Threat.created_at.desc()).limit(limit).all()

        result = []
        for t in threats:
            result.append({
                'id': t.id,
                'threat_type': t.threat_type,
                'severity': t.severity,
                'source_mac': t.source_mac,
                'ssid': t.ssid,
                'detected_by': t.detected_by,
                'description': t.description,
                'is_resolved': t.is_resolved,
                'created_at': t.created_at.isoformat()
            })

        return jsonify({
            'success': True,
            'data': result,
            'total': len(result)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threats_bp.route('/<int:threat_id>', methods=['GET'])
@jwt_required(optional=True)
def get_threat(threat_id):
    """Get detailed information for a specific threat"""
    try:
        threat = Threat.query.get(threat_id)
        if not threat:
            return jsonify({'error': 'Threat not found'}), 404

        return jsonify({
            'id': threat.id,
            'threat_type': threat.threat_type,
            'severity': threat.severity,
            'source_mac': threat.source_mac,
            'ssid': threat.ssid,
            'description': threat.description,
            'is_resolved': threat.is_resolved,
            'created_at': threat.created_at.isoformat(),
            'events': [{
                'id': e.id,
                'timestamp': e.created_at.isoformat(),
                'signal_strength': e.signal_strength,
                'packet_count': e.packet_count
            } for e in threat.events]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threats_bp.route('/<int:threat_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_threat(threat_id):
    """Mark a threat as resolved in the database"""
    try:
        threat = Threat.query.get(threat_id)
        if not threat:
            return jsonify({'error': 'Threat not found'}), 404

        threat.is_resolved = True
        threat.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            'message': 'Threat resolved successfully',
            'threat_id': threat_id,
            'resolved_at': threat.updated_at.isoformat()
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@threats_bp.route('/demo/simulate-threat', methods=['POST'])
@jwt_required(optional=True)
def simulate_threat():
    """
    Demo endpoint to simulate a threat detection
    Saves to database and broadcasts via WebSocket
    """
    try:
        # Get or create a default sensor
        sensor = Sensor.query.first()
        sensor_id = sensor.id if sensor else 1

        new_threat = Threat(
            threat_type='rogue_ap',
            severity='critical',
            source_mac='00:11:22:33:44:55',
            ssid='FreeWiFi-Trap',
            detected_by=sensor_id,
            description='Critical rogue access point detected (SIMULATED)',
            is_resolved=False
        )

        db.session.add(new_threat)
        db.session.commit()

        threat_data = {
            'id': new_threat.id,
            'threat_type': new_threat.threat_type,
            'severity': new_threat.severity,
            'source_mac': new_threat.source_mac,
            'ssid': new_threat.ssid,
            'description': new_threat.description,
            'created_at': new_threat.created_at.isoformat(),
            'signal_strength': -35,
            'packet_count': 150
        }

        broadcast_threat_event(threat_data)

        return jsonify({
            'message': 'Threat simulated and saved',
            'threat': threat_data
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500