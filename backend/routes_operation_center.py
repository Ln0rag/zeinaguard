import os
import csv
import io
from flask import Blueprint, jsonify, request, Response, stream_with_context, send_from_directory
from sqlalchemy import desc, case, func
from datetime import datetime, timedelta
from models import db, Threat, MitigationAudit, WiFiNetwork

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PURGED_REPORTS_DIR = os.path.join(PROJECT_ROOT, 'sensor', 'data_logs', 'purged_reports')
os.makedirs(PURGED_REPORTS_DIR, exist_ok=True)

operation_center_bp = Blueprint('operation_center', __name__, url_prefix='/api/operation-center')

@operation_center_bp.route('/threats', methods=['GET'])
def get_threats():
    page = request.args.get('page', 1, type=int)
    limit = max(1, min(request.args.get('limit', 50, type=int), 500))
    
    search = request.args.get('search', '').strip()
    severity = request.args.get('severity', 'ACTIONABLE').upper()
    status = request.args.get('status', 'ALL')

    # 1. السكربت الصح لمنع التكرار (بنستخدم scalar_subquery للحماية من أي أخطاء في مكتبة SQLAlchemy)
    latest_ids_subq = db.session.query(func.max(Threat.id)).group_by(Threat.source_mac).scalar_subquery()
    
    # 2. نبني الـ Query الأساسي
    base_query = Threat.query.filter(Threat.id.in_(latest_ids_subq))

    # 3. حساب الإحصائيات (KPIs)
    kpi_active = base_query.filter(Threat.action_status == 'ATTACKING').count()
    kpi_mitigated = base_query.filter(Threat.is_auto_mitigated == True).count()
    kpi_total = base_query.count()

    # 4. تطبيق الفلاتر على العرض
    query = base_query
    if search:
        query = query.filter((Threat.ssid.ilike(f'%{search}%')) | (Threat.source_mac.ilike(f'%{search}%')))
        
    if severity == 'ACTIONABLE':
        query = query.filter(func.upper(Threat.severity).in_(['HIGH', 'CRITICAL']))
    elif severity != 'ALL':
        query = query.filter(func.upper(Threat.severity) == severity)
        
    if status != 'ALL':
        if status == 'IDLE':
            query = query.filter((Threat.action_status.is_(None)) | (Threat.action_status == 'IDLE'))
        else:
            query = query.filter(Threat.action_status == status)

    # 5. الترتيب (الأخطر فالأحدث)
    priority = case(
        (Threat.action_status == 'ATTACKING', 0),
        (Threat.action_status == 'EVALUATING', 1),
        (Threat.action_status == 'MONITORING', 2),
        else_=3
    )
    
    query = query.order_by(
        priority,
        desc(Threat.severity),
        desc(Threat.created_at)
    )
    
    pagination = query.paginate(page=page, per_page=limit, error_out=False)
    
    # 6. إحضار الداتا المرتبطة
    mac_addresses = [t.source_mac for t in pagination.items if t.source_mac]
    count_map = {}
    net_map = {}
    
    if mac_addresses:
        counts_query = db.session.query(Threat.source_mac, func.count(Threat.id))\
            .filter(Threat.source_mac.in_(mac_addresses))\
            .group_by(Threat.source_mac).all()
        count_map = {mac: count for mac, count in counts_query}

        networks = WiFiNetwork.query.filter(WiFiNetwork.bssid.in_(mac_addresses)).order_by(desc(WiFiNetwork.last_seen)).all()
        net_map = {n.bssid: n for n in networks}

    threats = []
    for t in pagination.items:
        net = net_map.get(t.source_mac)
        threats.append({
            "id": t.id,
            "threat_type": t.threat_type,
            "severity": t.severity,
            "source_mac": t.source_mac,
            "ssid": t.ssid,
            "detected_by": t.detected_by,
            "description": t.description,
            "action_status": t.action_status,
            "is_auto_mitigated": t.is_auto_mitigated,
            "auto_mitigated_at": t.auto_mitigated_at.isoformat() if t.auto_mitigated_at else None,
            "mitigated_by_sensor_id": t.mitigated_by_sensor_id,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "channel": net.channel if net else None,
            "signal": net.signal_strength if net else None,
            "encryption": net.encryption if net else None,
            "risk_score": net.risk_score if net else None,
            "threat_count": count_map.get(t.source_mac, 1)
        })
        
    return jsonify({
        "total": pagination.total,
        "pages": pagination.pages,
        "page": page,
        "limit": limit,
        "kpis": {
            "active": kpi_active,
            "mitigated": kpi_mitigated,
            "total_unique": kpi_total
        },
        "threats": threats
    })

@operation_center_bp.route('/export', methods=['GET'])
def export_reports():
    timeframe = request.args.get('timeframe', 'all')
    format_type = request.args.get('format', 'csv').lower()
    
    latest_ids_subq = db.session.query(func.max(Threat.id)).group_by(Threat.source_mac).scalar_subquery()
    query = Threat.query.filter(Threat.id.in_(latest_ids_subq))
    
    if timeframe != 'all':
        now = datetime.utcnow()
        if timeframe == 'daily':
            start_date = now - timedelta(days=1)
        elif timeframe == 'weekly':
            start_date = now - timedelta(days=7)
        elif timeframe == 'monthly':
            start_date = now - timedelta(days=30)
        else:
            start_date = None
            
        if start_date:
            query = query.filter(Threat.created_at >= start_date)
            
    if format_type == 'csv':
        def generate_csv():
            yield 'Last Detection,SSID,BSSID,Threat Type,Severity,Sensor ID,Action Status,Mitigated,Detections,Description\n'
            
            hit_counts = db.session.query(Threat.source_mac, func.count(Threat.id)).group_by(Threat.source_mac).all()
            hit_map = {mac: count for mac, count in hit_counts}
            
            for t in query.order_by(desc(Threat.created_at)).yield_per(1000):
                is_mitigated = 'Yes' if t.is_auto_mitigated else 'No'
                safe_ssid = str(t.ssid or '').replace(',', ' ')
                safe_desc = str(t.description or '').replace(',', ' ').replace('\n', ' ')
                date_str = t.created_at.strftime('%Y-%m-%d %H:%M:%S') if t.created_at else ''
                hits = hit_map.get(t.source_mac, 1)
                
                yield f"{date_str},{safe_ssid},{t.source_mac or ''},{t.threat_type or ''},{t.severity or ''},{t.detected_by or ''},{t.action_status or 'IDLE'},{is_mitigated},{hits},{safe_desc}\n"

        return Response(
            stream_with_context(generate_csv()),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=operation_center_export.csv"}
        )
        
    elif format_type == 'pdf':
        threat_count = query.count()
        return jsonify({
            "message": "PDF generation requires ReportLab/WeasyPrint and is not fully implemented in this stub.",
            "data_summary": f"Total UNIQUE threats in timeframe '{timeframe}': {threat_count}",
            "pdf_hook_instructions": "Integrate PDF generation library here to render the queried data."
        }), 200
        
    else:
        return jsonify({"error": "Unsupported format"}), 400

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
                start_date = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
                # Include the entire end date by setting time to 23:59:59
                end_date = datetime.fromisoformat(end_str.replace('Z', '+00:00')).replace(hour=23, minute=59, second=59)
                query = query.filter(Threat.created_at >= start_date, Threat.created_at <= end_date)
            except ValueError:
                return jsonify({"error": "Invalid date format"}), 400
        else:
            return jsonify({"error": "Missing start_date or end_date for range"}), 400
    elif purge_type == 'all':
        pass
    else:
        return jsonify({"error": "Invalid type"}), 400

    records = query.all()
    count = len(records)
    
    if count == 0:
        return jsonify({"count": 0, "message": "No records found"}), 200

    report_name = f"purge_report_{now.strftime('%Y%m%d_%H%M%S')}.csv"
    report_path = os.path.join(PURGED_REPORTS_DIR, report_name)
    
    try:
        # 1. كتابة الملف بالكامل أولاً والتأكد من إغلاقه وسلامته
        with open(report_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Date', 'SSID', 'BSSID', 'Type', 'Severity', 'Status', 'Description'])
            for t in records:
                writer.writerow([
                    t.created_at.isoformat() if t.created_at else '',
                    t.ssid,
                    t.source_mac,
                    t.threat_type,
                    t.severity,
                    t.action_status,
                    t.description
                ])
        
        # 2. لو الملف اتكتب تمام، نمسح الداتا من الداتابيز في Transaction واحدة
        # ده بيضمن إن لو المسح فشل، الداتا هتفضل في الداتابيز ومش هتضيع
        for t in records:
            db.session.delete(t)
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        # لو حصل فشل، نمسح ملف الـ CSV الناقص عشان ميبقاش فيه داتا غلط
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