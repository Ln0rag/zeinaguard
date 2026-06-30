import os
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, desc, case
from models import (
    db, Threat, ThreatEvent, Sensor, SensorHealth, WiFiNetwork
)
from websocket_server import get_connected_sensors_snapshot, _utc_iso
from realtime_state import get_active_network_snapshot as get_realtime_active_network_snapshot

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/api/dashboard')
active_networks_bp = Blueprint('active_networks', __name__)
SENSOR_HEARTBEAT_STALE_SECONDS = int(os.getenv('SENSOR_HEARTBEAT_STALE_SECONDS', '30'))
ACTIVE_NETWORK_WINDOW_SECONDS = int(os.getenv('LIVE_NETWORK_TTL_SECONDS', '60'))
WIFI_HISTORY_MAX_RECORDS = int(os.getenv('WIFI_HISTORY_MAX_RECORDS', '5000'))
WIFI_HISTORY_DAYS = int(os.getenv('WIFI_HISTORY_DAYS', '365'))


def _format_live_network(network: WiFiNetwork):
    classification = (network.classification or 'LEGIT').upper()
    if classification not in {'ROGUE', 'SUSPICIOUS', 'LEGIT'}:
        classification = 'LEGIT'

    manufacturer = (network.manufacturer or '').strip() or None
    if manufacturer and manufacturer.lower() in {'unknown', 'unknown mfr', 'n/a', 'none'}:
        manufacturer = None

    raw_data = network.raw_data or {}

    return {
        'sensor_id': network.sensor_id,
        'ssid': network.ssid or 'Hidden',
        'bssid': network.bssid,
        'signal': network.signal_strength,
        'channel': network.channel,
        'frequency': network.frequency,
        'classification': classification,
        'last_seen': network.last_seen.isoformat() if network.last_seen else None,
        'timestamp': network.last_seen.isoformat() if network.last_seen else None,
        'manufacturer': manufacturer,
        'clients_count': max(network.clients_count or 0, 0),
        'auth': network.auth_type,
        'wps': network.wps_info,
        'encryption': network.encryption,
        'uptime': network.uptime_seconds or 0,
        'score': network.risk_score or 0,
        'was_hidden': bool(raw_data.get('was_hidden', False)),
        'is_active': bool(network.is_active),
        }


def _active_network_cutoff():
    return datetime.utcnow() - timedelta(seconds=ACTIVE_NETWORK_WINDOW_SECONDS)


def _query_active_network_rows(limit: int, classification: str):
    cutoff = _active_network_cutoff()
    query = WiFiNetwork.query.filter(
        WiFiNetwork.is_active.is_(True),
        WiFiNetwork.last_seen >= cutoff,
    ).order_by(
        desc(WiFiNetwork.last_seen),
        desc(WiFiNetwork.signal_strength),
    )
    if classification in {'ROGUE', 'SUSPICIOUS', 'LEGIT'}:
        query = query.filter(func.upper(WiFiNetwork.classification) == classification)
    return query.limit(limit).all()


def _effective_sensor_status(sensor: Sensor, latest_health: SensorHealth | None, realtime_status: dict | None = None):
    if realtime_status:
        realtime_heartbeat = realtime_status.get('last_heartbeat')
        if realtime_heartbeat:
            try:
                heartbeat_text = realtime_heartbeat[:-1] + '+00:00' if str(realtime_heartbeat).endswith('Z') else realtime_heartbeat
                heartbeat = datetime.fromisoformat(heartbeat_text)
            except ValueError:
                heartbeat = None
            if heartbeat and heartbeat.tzinfo is not None:
                heartbeat = heartbeat.astimezone(timezone.utc).replace(tzinfo=None)
            if heartbeat and (datetime.utcnow() - heartbeat).total_seconds() <= SENSOR_HEARTBEAT_STALE_SECONDS:
                status = (realtime_status.get('status') or 'online').lower()
                if realtime_status.get('connected', True) and status != 'offline':
                    return status

    if sensor.last_heartbeat is not None:
        if (datetime.utcnow() - sensor.last_heartbeat).total_seconds() <= SENSOR_HEARTBEAT_STALE_SECONDS and sensor.is_active:
            return 'online'

    if latest_health is None:
        return 'offline'

    heartbeat = latest_health.last_heartbeat
    if heartbeat is None:
        return 'offline'

    if (datetime.utcnow() - heartbeat).total_seconds() > SENSOR_HEARTBEAT_STALE_SECONDS:
        return 'offline'

    if not sensor.is_active:
        return 'offline'

    return latest_health.status or 'offline'


@dashboard_bp.route('/overview', methods=['GET'])
def get_overview():
    """Get dashboard overview metrics"""
    try:
       
        # Threat metrics
        total_threats = Threat.query.count()
        critical_threats = Threat.query.filter_by(severity='critical', is_resolved=False).count()
        high_threats = Threat.query.filter_by(severity='high', is_resolved=False).count()
        resolved_threats = Threat.query.filter_by(is_resolved=True).count()
        
        # Today's threats
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_threats = Threat.query.filter(Threat.created_at >= today_start).count()
        
        realtime_sensors = get_connected_sensors_snapshot()
        sensor_rows = Sensor.query.all()
        effective_statuses = {}
        for sensor in sensor_rows:
            latest_health = SensorHealth.query\
                .filter_by(sensor_id=sensor.id)\
                .order_by(desc(SensorHealth.created_at))\
                .first()
            effective_statuses[sensor.id] = _effective_sensor_status(
                sensor,
                latest_health,
                realtime_sensors.get(sensor.id),
            )

        # Sensor metrics
        total_sensors = Sensor.query.count()
        online_sensors = sum(1 for status in effective_statuses.values() if status != 'offline')
        offline_sensors = max(total_sensors - online_sensors, 0)
        

        from sqlalchemy import text as _text
        latest_health_raw = db.session.execute(_text("""
            SELECT DISTINCT ON (s.id)
                s.id,
                s.name,
                sh.status,
                sh.signal_strength,
                sh.cpu_usage,
                sh.memory_usage,
                sh.last_heartbeat
            FROM sensors s
            JOIN sensor_health sh ON sh.sensor_id = s.id
            ORDER BY s.id, sh.created_at DESC
        """)).fetchall()
        latest_health = latest_health_raw
        
        
        return jsonify({
            'threats': {
                'total': total_threats,
                'critical': critical_threats,
                'high': high_threats,
                'resolved': resolved_threats,
                'today': today_threats
            },
            'sensors': {
                'total': total_sensors,
                'online': online_sensors,
                'offline': offline_sensors,
                'recent': [
                    {
                        'sensor_id': h[0],
                        'name': h[1],
                        'status': h[2],
                        'signal_strength': h[3],
                        'cpu_usage': h[4],
                        'memory_usage': h[5],
                        'last_heartbeat': _utc_iso(h[6])
                    } for h in latest_health
                ]
            },
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get overview: {str(e)}'}), 500


@dashboard_bp.route('/networks', methods=['GET'])
def get_live_networks():
    """Return active networks for non-WebSocket consumers."""
    try:
        limit = max(1, min(int(request.args.get('limit', 500)), 1000))
        classification = (request.args.get('classification') or '').upper()
        networks = _query_active_network_rows(limit, classification)
        return jsonify({
            'networks': [_format_live_network(network) for network in networks],
            'count': len(networks),
            'generated_at': _utc_iso(datetime.utcnow()),
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get live networks: {str(e)}'}), 500


@active_networks_bp.route('/networks/active', methods=['GET'])
def get_active_networks():
    """Return networks seen within the active realtime window, unioning DB + realtime state."""
    try:
        limit = max(1, min(int(request.args.get('limit', 500)), 1000))
        classification = (request.args.get('classification') or '').upper()

        # Always start with DB rows as the authoritative base
        database_rows = _query_active_network_rows(limit, classification)
        db_bssids = {n.bssid for n in database_rows}
        networks = [_format_live_network(n) for n in database_rows]

        # Layer in realtime-state rows that are NOT already in the DB result
        realtime_rows = get_realtime_active_network_snapshot(max_age_seconds=ACTIVE_NETWORK_WINDOW_SECONDS)
        if realtime_rows:
            if classification in {'ROGUE', 'SUSPICIOUS', 'LEGIT'}:
                realtime_rows = [n for n in realtime_rows if n.get('classification') == classification]
            for rt in realtime_rows:
                if rt.get('bssid') not in db_bssids:
                    networks.append(rt)

        networks = networks[:limit]
        return jsonify({
            'networks': networks,
            'count': len(networks),
            'generated_at': datetime.utcnow().isoformat(),
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get active networks: {str(e)}'}), 500


@active_networks_bp.route('/api/wifi-networks/history', methods=['GET'])
def get_wifi_network_history():
    """Return up to 1 year of historical WiFi network records (no active-only filter).

    Safe payload cap: WIFI_HISTORY_MAX_RECORDS (default 5 000) prevents crushing
    the frontend with an unbounded dump.  Records are ordered newest-first.
    """
    try:
        limit = max(1, min(int(request.args.get('limit', WIFI_HISTORY_MAX_RECORDS)), WIFI_HISTORY_MAX_RECORDS))
        classification = (request.args.get('classification') or '').upper()

        cutoff = datetime.utcnow() - timedelta(days=WIFI_HISTORY_DAYS)
        query = WiFiNetwork.query.filter(
            WiFiNetwork.last_seen >= cutoff,
        ).order_by(
            desc(WiFiNetwork.last_seen),
            desc(WiFiNetwork.signal_strength),
        )
        if classification in {'ROGUE', 'SUSPICIOUS', 'LEGIT'}:
            query = query.filter(func.upper(WiFiNetwork.classification) == classification)

        networks = query.limit(limit).all()
        return jsonify({
            'networks': [_format_live_network(n) for n in networks],
            'count': len(networks),
            'generated_at': _utc_iso(datetime.utcnow()),
            'history_days': WIFI_HISTORY_DAYS,
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get wifi network history: {str(e)}'}), 500


@dashboard_bp.route('/threat-events', methods=['GET'])
def get_recent_threat_events():
    """Bootstrap the dashboard event feed with recent threat records."""
    try:
        limit = max(1, min(int(request.args.get('limit', 20)), 100))
        threats = Threat.query.order_by(desc(Threat.created_at)).limit(limit).all()
        events = [
            {
                'sensor_id': threat.detected_by,
                'ssid': threat.ssid or 'Hidden',
                'bssid': threat.source_mac,
                'signal': None,
                'channel': None,
                'classification': 'ROGUE' if threat.severity in {'critical', 'high'} else 'SUSPICIOUS',
                'timestamp': _utc_iso(threat.created_at),
                'manufacturer': None,
                'threat_id': threat.id,
                'severity': threat.severity,
            }
            for threat in threats
        ]
        return jsonify({
            'events': events,
            'count': len(events),
            'generated_at': _utc_iso(datetime.utcnow()),
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to get threat events: {str(e)}'}), 500


@dashboard_bp.route('/threat-timeline', methods=['GET'])
def get_threat_timeline():
    """Get threat events timeline for last 24 hours"""
    try:
        hours_back = 24
        time_threshold = datetime.utcnow() - timedelta(hours=hours_back)
        
        # Get threats grouped by hour
        threats = db.session.query(
            func.date_trunc('hour', Threat.created_at).label('hour'),
            Threat.severity,
            func.count(Threat.id).label('count')
        ).filter(
            Threat.created_at >= time_threshold
        ).group_by('hour', Threat.severity).order_by('hour').all()
        
        # Format for timeline chart
        timeline = {}
        for hour_start in (time_threshold + timedelta(hours=i) for i in range(hours_back)):
            hour_key = hour_start.strftime('%Y-%m-%d %H:00')
            timeline[hour_key] = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        
        for threat in threats:
            hour_key = threat[0].strftime('%Y-%m-%d %H:00')
            if hour_key in timeline:
                timeline[hour_key][threat[1]] = threat[2]
        
        return jsonify({
            'timeline': timeline,
            'period': f'Last {hours_back} hours'
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get timeline: {str(e)}'}), 500


@dashboard_bp.route('/threat-summary', methods=['GET'])
def get_threat_summary():
    """Get threat type summary and statistics"""
    try:
        # Group threats by type and severity
        threat_summary = db.session.query(
            Threat.threat_type,
            Threat.severity,
            func.count(Threat.id).label('count')
        ).group_by(Threat.threat_type, Threat.severity).all()
        
        summary_data = {}
        for threat_type, severity, count in threat_summary:
            if threat_type not in summary_data:
                summary_data[threat_type] = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0,
                    'total': 0
                }
            summary_data[threat_type][severity] = count
            summary_data[threat_type]['total'] += count
        
        # Sort by total count
        sorted_summary = sorted(
            summary_data.items(),
            key=lambda x: x[1]['total'],
            reverse=True
        )
        
        return jsonify({
            'threats': dict(sorted_summary),
            'total_types': len(summary_data)
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get summary: {str(e)}'}), 500


@dashboard_bp.route('/sensor-health', methods=['GET'])
def get_sensor_health():
    """Get the authoritative in-memory live sensor snapshot."""
    try:
        sensors_health = list(get_connected_sensors_snapshot().values())
        if sensors_health:
            avg_signal = 0
            avg_cpu = sum(s.get('cpu') or 0 for s in sensors_health) / len(sensors_health)
            avg_memory = sum(s.get('memory') or 0 for s in sensors_health) / len(sensors_health)
        else:
            avg_signal = avg_cpu = avg_memory = 0

        return jsonify({
            'sensors': sensors_health,
            'averages': {
                'signal_strength': round(avg_signal, 1),
                'cpu_usage': round(avg_cpu, 1),
                'memory_usage': round(avg_memory, 1)
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get sensor health: {str(e)}'}), 500


@dashboard_bp.route('/top-threats', methods=['GET'])
def get_top_threats():
    """Get top active threats"""
    try:
        top_threats = Threat.query\
            .filter_by(is_resolved=False)\
            .order_by(desc(Threat.created_at))\
            .limit(10).all()
        
        threats_data = []
        for threat in top_threats:
            threats_data.append({
                'id': threat.id,
                'threat_type': threat.threat_type,
                'severity': threat.severity,
                'ssid': threat.ssid,
                'source_mac': threat.source_mac,
                'description': threat.description,
                'detected_by': threat.detected_by,
                'created_at': threat.created_at.isoformat(),
                'event_count': len(threat.events)
            })
        
        return jsonify({
            'threats': threats_data,
            'count': len(threats_data)
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get top threats: {str(e)}'}), 500


@dashboard_bp.route('/stats', methods=['GET'])
def get_statistics():
    """Get comprehensive statistics"""
    try:
        # Calculate statistics for different time periods
        now = datetime.utcnow()
        one_day_ago = now - timedelta(days=1)
        one_week_ago = now - timedelta(days=7)
        one_month_ago = now - timedelta(days=30)
        
        counts = db.session.query(
            func.count(Threat.id).label('all_time'),
            func.count(case([(Threat.created_at >= one_day_ago, Threat.id)])).label('today'),
            func.count(case([(Threat.created_at >= one_week_ago, Threat.id)])).label('this_week'),
            func.count(case([(Threat.created_at >= one_month_ago, Threat.id)])).label('this_month')
        ).first()

        stats = {
            'today': {'threats': counts.today},
            'this_week': {'threats': counts.this_week},
            'this_month': {'threats': counts.this_month},
            'all_time': {'threats': counts.all_time}
        }
        
        # Calculate trends
        if stats['this_week']['threats'] > 0 and stats['this_month']['threats'] > 0:
            week_trend = (stats['this_week']['threats'] / stats['this_month']['threats'] * 100)
        else:
            week_trend = 0
        
        return jsonify({
            'statistics': stats,
            'trend': {
                'week_vs_month': round(week_trend, 1)
            }
        }), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500
