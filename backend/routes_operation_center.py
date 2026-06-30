import os
import csv
from flask import Blueprint, jsonify, request, send_from_directory
from sqlalchemy import desc, case, func
from datetime import datetime, timedelta
from models import db, Threat, MitigationAudit, WiFiNetwork

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PURGED_REPORTS_DIR = os.path.join(PROJECT_ROOT, 'sensor', 'data_logs', 'purged_reports')

operation_center_bp = Blueprint('operation_center', __name__, url_prefix='/api/operation-center')

@operation_center_bp.route('/threats', methods=['GET'])
def get_threats():
    page = request.args.get('page', 1, type=int)
    limit = max(1, min(request.args.get('limit', 50, type=int), 500))
    
    search = request.args.get('search', '').strip()
    severity_param = request.args.get('severity', 'CRITICAL,HIGH').strip().upper()
    status = request.args.get('status', 'ALL')
    base_query = db.session.query(Threat).distinct(Threat.source_mac)
    base_query = base_query.filter(func.upper(Threat.severity) != 'LOW')

    query = base_query
    if search:
        query = query.filter((Threat.ssid.ilike(f'%{search}%')) | (Threat.source_mac.ilike(f'%{search}%')))
        
    if severity_param and severity_param != 'ALL':
        _sev_list = [s.strip() for s in severity_param.split(',') if s.strip()]
        if _sev_list:
            query = query.filter(func.upper(Threat.severity).in_(_sev_list))


    count_query = db.session.query(func.count(db.distinct(Threat.source_mac)))
    count_query = count_query.filter(func.upper(Threat.severity) != 'LOW')
    if search:
        count_query = count_query.filter((Threat.ssid.ilike(f'%{search}%')) | (Threat.source_mac.ilike(f'%{search}%')))
    if severity_param and severity_param != 'ALL':
        _sev_list = [s.strip() for s in severity_param.split(',') if s.strip()]
        if _sev_list:
            count_query = count_query.filter(func.upper(Threat.severity).in_(_sev_list))

    total_items = count_query.scalar() or 0
    total_pages = (total_items + limit - 1) // limit

    query = query.order_by(Threat.source_mac, desc(Threat.updated_at))
    items = query.limit(limit).offset((page - 1) * limit).all()
    
    mac_addresses = [t.source_mac for t in items if t.source_mac]
    net_map = {}
    
    if mac_addresses:
        networks = WiFiNetwork.query.filter(WiFiNetwork.bssid.in_(mac_addresses)).order_by(desc(WiFiNetwork.last_seen)).all()
        # Prevent older network records from overwriting the newest ones in the dict
        for n in networks:
            if n.bssid not in net_map:
                net_map[n.bssid] = n

    def _get_band(channel):
        if not channel: return "Unknown"
        ch = int(channel)
        if 1 <= ch <= 14: return "2.4 GHz"
        if 36 <= ch <= 165: return "5 GHz"
        if ch > 165: return "6 GHz"
        return "Unknown"

    def _get_wps_status(wps_info):
        if not wps_info: return "DISABLED"
        if isinstance(wps_info, dict):
            if wps_info.get("locked"): return "LOCKED"
            return "UNLOCKED"
        return "DISABLED"

    def _get_tags(t, net):
        tags = []
        if t.threat_type:
            tags.append(t.threat_type.replace('_', ' ').upper())
        return tags

    def _derive_action_status(threat) -> str:
        if getattr(threat, 'is_auto_mitigated', False):
            return 'AUTO_MITIGATED'
        if getattr(threat, 'is_resolved', False):
            return 'RESOLVED'
        return 'ACTIVE'

    threats = []
    for t in items:
        net = net_map.get(t.source_mac) if t.source_mac else None
        threats.append({
            "id": t.id,
            "threat_type": t.threat_type,
            "severity": t.severity,
            "source_mac": t.source_mac,
            "ssid": t.ssid,
            "detected_by": t.detected_by,
            "node_id": t.detected_by or (net.sensor_id if net else None),
            "description": t.description,
            "action_status": _derive_action_status(t),
            "is_auto_mitigated": t.is_auto_mitigated,
            "auto_mitigated_at": t.auto_mitigated_at.isoformat() if t.auto_mitigated_at else None,
            "mitigated_by_sensor_id": t.mitigated_by_sensor_id,
            "created_at": t.created_at.isoformat() + "Z" if t.created_at else None,
            "updated_at": t.updated_at.isoformat() + "Z" if t.updated_at else None,
            "channel": net.channel if net else None,
            "band": _get_band(net.channel) if net else "Unknown",
            "signal": net.signal_strength if net else None,
            "auth": net.auth_type if net else None,
            "encryption": net.encryption if net else None,
            "wps_status": _get_wps_status(net.wps_info) if net else "DISABLED",
            "risk_score": net.risk_score if net else None,
            "vendor": net.manufacturer if net else "Unknown",
            "clients_count": net.clients_count if net else 0,
            "packet_count": net.seen_count if net else 0,
            "tags": _get_tags(t, net),
            "is_active": net.is_active if net else False,
            "ap_uptime": t.ap_uptime or (net.ap_uptime if net else None)
        })
        
    return jsonify({
        "total": total_items,
        "pages": total_pages,
        "page": page,
        "limit": limit,
        "threats": threats
    })

@operation_center_bp.route('/purge', methods=['POST'])
def purge_threats():
    data = request.json or {}
    purge_type = data.get('type', 'today')
    
    query = Threat.query
    now = datetime.utcnow()
    
    if purge_type == 'today':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        query = query.filter(Threat.created_at >= start_date)
    elif purge_type == 'weekly':
        start_date = now - timedelta(days=7)
        query = query.filter(Threat.created_at >= start_date)
    elif purge_type == 'monthly':
        start_date = now - timedelta(days=30)
        query = query.filter(Threat.created_at >= start_date)
    elif purge_type == 'range':
        start_str = data.get('start_date')
        end_str = data.get('end_date')
        if start_str and end_str:
            try:
                start_date = datetime.fromisoformat(start_str.replace('Z', '+00:00')).replace(tzinfo=None)
                end_date = datetime.fromisoformat(end_str.replace('Z', '+00:00')).replace(hour=23, minute=59, second=59, tzinfo=None)
                query = query.filter(Threat.created_at >= start_date, Threat.created_at <= end_date)
            except ValueError:
                return jsonify({"error": "Invalid date format"}), 400
        else:
            return jsonify({"error": "Missing start_date or end_date for range"}), 400
    elif purge_type == 'all':
        pass
    else:
        return jsonify({"error": "Invalid type"}), 400

    count = query.count()
    
    if count == 0:
        return jsonify({"count": 0, "message": "No records found"}), 200

    report_name = f"purge_report_{now.strftime('%Y%m%d_%H%M%S')}.csv"
    report_path = os.path.join(PURGED_REPORTS_DIR, report_name)
    
    try:
        os.makedirs(PURGED_REPORTS_DIR, exist_ok=True)

        threats_list = query.all()
        mac_addresses = list(set(t.source_mac for t in threats_list if t.source_mac))
        net_map = {}
        if mac_addresses:
            networks = WiFiNetwork.query.filter(WiFiNetwork.bssid.in_(mac_addresses)).order_by(desc(WiFiNetwork.last_seen)).all()
            for n in networks:
                if n.bssid not in net_map:
                    net_map[n.bssid] = n

        with open(report_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'First Seen', 'Last Seen', 'SSID', 'BSSID', 'Node ID', 'Vendor',
                'Channel/Band', 'RSSI (dBm)', 'Security', 'WPS Status', 'Clients', 'Severity'
            ])

            def _get_band(channel):
                if not channel:
                    return "Unknown"
                ch = int(channel)
                if 1 <= ch <= 14:
                    return "2.4 GHz"
                if 36 <= ch <= 165:
                    return "5 GHz"
                if ch > 165:
                    return "6 GHz"
                return "Unknown"

            def _get_wps_status(wps_info):
                if not wps_info:
                    return "DISABLED"
                if isinstance(wps_info, dict):
                    if wps_info.get("locked"):
                        return "LOCKED"
                    return "UNLOCKED"
                return "DISABLED"

            def _fmt_dt(dt):
                if not dt:
                    return 'N/A'
                return dt.strftime('%I:%M:%S %p - %d/%m/%Y')

            for t in threats_list:
                net = net_map.get(t.source_mac) if t.source_mac else None

                first_seen = _fmt_dt(t.created_at)
                last_seen = _fmt_dt(t.updated_at)
                ssid = t.ssid or 'Hidden'
                bssid = t.source_mac or 'N/A'

                node_id = t.detected_by or (net.sensor_id if net else None)
                node_id_str = str(node_id).zfill(2) if node_id is not None else 'N/A'

                vendor = net.manufacturer if net and net.manufacturer else 'Unknown'
                ch_band = f"{net.channel} / {_get_band(net.channel)}" if net and net.channel else "N/A"
                rssi = net.signal_strength if net and net.signal_strength else 'N/A'

                sec_set = set()
                if net:
                    if net.auth_type and str(net.auth_type).upper().strip() not in ('UNKNOWN', 'N/A', ''):
                        sec_set.add(str(net.auth_type).upper().strip())
                    if net.encryption and str(net.encryption).upper().strip() not in ('UNKNOWN', 'N/A', ''):
                        sec_set.add(str(net.encryption).upper().strip())
                security = " / ".join(sec_set) if sec_set else "UNKNOWN"

                wps = _get_wps_status(net.wps_info) if net else 'DISABLED'
                clients = str(net.clients_count or 0) if net else '0'
                severity = str(t.severity or 'UNKNOWN').upper()

                writer.writerow([
                    first_seen, last_seen, ssid, bssid, node_id_str, vendor,
                    ch_band, rssi, security, wps, clients, severity
                ])

        query.delete(synchronize_session=False)
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        if os.path.exists(report_path):
            os.remove(report_path)
        return jsonify({"error": f"Purge failed and rolled back: {str(e)}"}), 500
    
    return jsonify({
        "count": count,
        "report_name": report_name,
        "download_url": f"/api/operation-center/purge-report/{report_name}"
    }), 200

@operation_center_bp.route('/purge-report/<filename>', methods=['GET'])
def download_purge_report(filename):
    return send_from_directory(os.path.abspath(PURGED_REPORTS_DIR), filename, as_attachment=True)