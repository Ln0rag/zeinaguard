from flask import Blueprint, request, jsonify
from models import db, NotificationConfig
import logging

# Create blueprint
notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')
logger = logging.getLogger(__name__)


@notifications_bp.route('/settings', methods=['GET'])
def get_settings():
    """Get notification settings"""
    try:
        config = NotificationConfig.query.first()
        if not config:
            # Create default config if none exists
            config = NotificationConfig(
                sounds_enabled=True
            )
            db.session.add(config)
            db.session.commit()
        
        return jsonify({
            'sounds_enabled': config.sounds_enabled
        }), 200
    except Exception as e:
        logger.error(f'Error getting settings: {str(e)}')
        return jsonify({'error': str(e)}), 500


@notifications_bp.route('/settings', methods=['POST'])
def update_settings():
    """Update notification settings"""
    try:
        data = request.get_json()
        config = NotificationConfig.query.first()
        
        if not config:
            config = NotificationConfig()
            db.session.add(config)

        if 'sounds_enabled' in data:
            config.sounds_enabled = data['sounds_enabled']
            
        db.session.commit()
        return jsonify({'message': 'Settings updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error updating settings: {str(e)}')
        return jsonify({'error': str(e)}), 500
