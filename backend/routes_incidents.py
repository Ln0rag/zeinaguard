from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import desc

from models import Incident

incidents_bp = Blueprint('incidents', __name__, url_prefix='/api/incidents')


@incidents_bp.route('', methods=['GET'])
@incidents_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def get_incidents():
    incidents = Incident.query.order_by(desc(Incident.created_at)).limit(100).all()
    data = [
        {
            'id': incident.id,
            'title': incident.title,
            'description': incident.description or '',
            'severity': incident.severity or 'medium',
            'status': incident.status or 'open',
            'created_at': incident.created_at.isoformat() if incident.created_at else None,
            'updated_at': incident.updated_at.isoformat() if incident.updated_at else None,
            'assigned_to': incident.assigned_to,
        }
        for incident in incidents
    ]
    return jsonify(data), 200
