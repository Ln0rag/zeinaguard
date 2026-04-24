"""
ZeinaGuard Pro Dashboard Routes
Provides real-time metrics, threat assessment, and event data
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import random
from ..auth import token_required
from ..database import db

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')

# Mock data generator (replace with database queries in production)
def generate_mock_threats():
    """Generate mock threat data for development"""
    threat_types = [
        'Rogue AP', 'Evil Twin', 'Deauth Attack',
        'Weak Encryption', 'Packet Injection', 'MITM'
    ]
    return [
        {
            'threat_type': threat_type,
            'risk_score': random.uniform(30, 95),
            'detection_rate': random.uniform(70, 100),
            'mitigation_status': random.choice(['mitigated', 'pending', 'monitoring']),
            'count': random.randint(1, 20)
        }
        for threat_type in threat_types[:random.randint(2, 5)]
    ]

def generate_mock_sensors():
    """Generate mock sensor data for development"""
    sensors = []
    for i in range(1, 4):
        status = random.choice(['online', 'degraded', 'offline'])
        sensors.append({
            'sensor_id': i,
            'name': f'Sensor-Room{i}',
            'status': status,
            'signal_strength': random.randint(-90, -30) if status != 'offline' else -120,
            'cpu_usage': random.uniform(20, 95) if status != 'offline' else 0,
            'memory_usage': random.uniform(30, 92) if status != 'offline' else 0,
            'threat_count': random.randint(0, 15),
            'last_seen': datetime.utcnow().isoformat() + 'Z'
        })
    return sensors

def generate_mock_events():
    """Generate mock threat events"""
    threat_types = ['Rogue AP', 'Evil Twin', 'Deauth Attack']
    severities = ['critical', 'high', 'medium', 'low']
    events = []
    
    for i in range(10):
        base_time = datetime.utcnow() - timedelta(minutes=i*2)
        events.append({
            'id': 1000 + i,
            'threat_type': random.choice(threat_types),
            'ssid': random.choice(['FreeWifi', 'Guest', 'AppleStore']),
            'source_mac': f'{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}',
            'signal_strength': random.randint(-90, -30),
            'detected_by': random.randint(1, 3),
            'created_at': base_time.isoformat() + 'Z',
            'is_resolved': random.random() > 0.6,
            'action_taken': random.choice(['Detected', 'Deauth sent', 'Blocked']),
            'severity': random.choice(severities)
        })
    
    return sorted(events, key=lambda x: x['created_at'], reverse=True)

# ============================================================================
# SYSTEM METRICS ENDPOINT
# ============================================================================

@dashboard_bp.route('/system-metrics', methods=['GET'])
@token_required
def get_system_metrics(current_user):
    """
    Fetch real-time system performance metrics
    
    Returns:
        - network_health: 0-100% (sensor connectivity)
        - detection_efficiency: 0-100% (threat detection rate)
        - mitigation_rate: 0-100% (successful mitigations)
        - sensor_reliability: 0-100% (online sensors)
    """
    try:
        # In production, query database:
        # sensors = Sensor.query.filter_by(user_id=current_user.id)
        # threats = ThreatEvent.query.filter_by(user_id=current_user.id)
        
        # For now, use mock data
        sensors = generate_mock_sensors()
        threats = generate_mock_threats()
        
        # Calculate metrics
        online_sensors = sum(1 for s in sensors if s['status'] != 'offline')
        total_sensors = len(sensors)
        
        avg_signal = sum(s['signal_strength'] for s in sensors if s['status'] != 'offline') / max(online_sensors, 1)
        network_health = max(0, min(100, 100 + avg_signal))  # -90 dBm = 10%, -30 dBm = 100%
        
        detection_efficiency = sum(t['detection_rate'] for t in threats) / len(threats) if threats else 0
        mitigation_rate = sum(
            100 if t['mitigation_status'] == 'mitigated' else 50 if t['mitigation_status'] == 'pending' else 0
            for t in threats
        ) / len(threats) if threats else 0
        
        sensor_reliability = (online_sensors / total_sensors * 100) if total_sensors > 0 else 0
        
        return jsonify({
            'metrics': {
                'network_health': round(network_health, 1),
                'detection_efficiency': round(detection_efficiency, 1),
                'mitigation_rate': round(mitigation_rate, 1),
                'sensor_reliability': round(sensor_reliability, 1),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# THREAT ASSESSMENT ENDPOINT
# ============================================================================

@dashboard_bp.route('/threat-assessment', methods=['GET'])
@token_required
def get_threat_assessment(current_user):
    """
    Get AI-driven threat risk scores by type
    
    Returns:
        - overall_risk_score: Weighted average of all threats
        - threats: Array of threat types with risk scores
    """
    try:
        threats = generate_mock_threats()
        
        # Calculate overall risk score as weighted average
        if threats:
            overall_score = sum(t['risk_score'] * (t['count'] / sum(th['count'] for th in threats)) 
                              for t in threats)
        else:
            overall_score = 0
        
        return jsonify({
            'overall_risk_score': round(overall_score, 1),
            'threats': [
                {
                    'threat_type': t['threat_type'],
                    'risk_score': round(t['risk_score'], 1),
                    'detection_rate': round(t['detection_rate'], 1),
                    'mitigation_status': t['mitigation_status'],
                    'count': t['count']
                }
                for t in threats
            ]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# THREAT EVENTS ENDPOINT
# ============================================================================

@dashboard_bp.route('/threat-events', methods=['GET'])
@token_required
def get_threat_events(current_user):
    """
    Get recent threat detection events
    
    Query Parameters:
        - limit: Number of events to return (default: 10, max: 100)
        - severity: Filter by severity (critical|high|medium|low)
    """
    try:
        limit = request.args.get('limit', default=10, type=int)
        severity = request.args.get('severity', default=None, type=str)
        
        limit = min(limit, 100)  # Cap at 100
        
        events = generate_mock_events()
        
        # Filter by severity if provided
        if severity:
            events = [e for e in events if e['severity'] == severity]
        
        # Return limited events
        return jsonify({
            'events': events[:limit],
            'total': len(events),
            'returned': len(events[:limit])
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# BLOCK THREAT ENDPOINT (DEAUTH ACTION)
# ============================================================================

@dashboard_bp.route('/threats/<int:threat_id>/block', methods=['POST'])
@token_required
def block_threat(current_user, threat_id):
    """
    Send deauthentication command to Raspberry Pi
    
    Request Body:
        {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "threat_type": "Rogue AP",
            "action": "deauth"
        }
    
    Returns:
        - success: Boolean indicating if command was queued
        - command_id: ID for tracking command execution
        - status: Current status of mitigation
    """
    try:
        data = request.get_json()
        
        if not data or 'mac_address' not in data or 'action' not in data:
            return jsonify({'error': 'Missing required fields'}), 422
        
        mac_address = data['mac_address']
        action = data['action']
        threat_type = data.get('threat_type', 'Unknown')
        
        # Validate MAC address format
        if not is_valid_mac(mac_address):
            return jsonify({'error': 'Invalid MAC address format'}), 422
        
        # In production:
        # 1. Queue command to Raspberry Pi:
        #    Command.create(user_id=current_user.id, target_mac=mac_address, action=action)
        # 2. Update threat status:
        #    threat = ThreatEvent.query.get(threat_id)
        #    threat.is_resolved = True
        #    threat.action_taken = 'Deauth sent'
        #    db.session.commit()
        # 3. Emit WebSocket event to all connected clients
        
        command_id = f"cmd_{threat_id}_{datetime.utcnow().timestamp()}"
        
        return jsonify({
            'success': True,
            'threat_id': threat_id,
            'message': f'Deauth command queued for {mac_address}',
            'command_id': command_id,
            'status': 'queued'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def is_valid_mac(mac):
    """Validate MAC address format"""
    import re
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac))

# ============================================================================
# SENSOR HEALTH ENDPOINT
# ============================================================================

@dashboard_bp.route('/sensors/health', methods=['GET'])
@token_required
def get_sensor_health(current_user):
    """
    Get health status of all sensors
    
    Returns sensor array with:
        - status: online|degraded|offline
        - cpu_usage: Percentage
        - memory_usage: Percentage
        - signal_strength: dBm
        - threat_count: Number of threats detected
    """
    try:
        sensors = generate_mock_sensors()
        
        return jsonify({
            'sensors': sensors,
            'total': len(sensors),
            'online': sum(1 for s in sensors if s['status'] == 'online'),
            'degraded': sum(1 for s in sensors if s['status'] == 'degraded'),
            'offline': sum(1 for s in sensors if s['status'] == 'offline')
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

@dashboard_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@dashboard_bp.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403
