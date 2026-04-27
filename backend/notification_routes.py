"""
Notification Routes for ZeinaGuard
Handles email configuration endpoints
"""

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
                alert_email='',
                sounds_enabled=True
            )
            db.session.add(config)
            db.session.commit()
        
        return jsonify({
            'alert_email': config.alert_email,
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
        
        if 'alert_email' in data:
            config.alert_email = data['alert_email']
        if 'sounds_enabled' in data:
            config.sounds_enabled = data['sounds_enabled']
            
        db.session.commit()
        return jsonify({'message': 'Settings updated successfully'}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f'Error updating settings: {str(e)}')
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/email-test', methods=['POST'])
def test_email():
    """
    Test email configuration
    Logs the email address for testing purposes
    """
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email address required'}), 400
        
        
        status_code = 200 if result['success'] else 400
        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'data': result.get('data', {})
        }), status_code
        
    except Exception as e:
        logger.error(f'Email test error: {str(e)}')
        return jsonify({
            'error': str(e),
            'message': 'Failed to test email'
        }), 500


@notifications_bp.route('/send-email', methods=['POST'])
def send_email_notification():
    """
    Send a notification via email
    """
    try:
        data = request.get_json()
        email = data.get('email')
        notification = data.get('notification')
        
        if not email or not notification:
            return jsonify({'error': 'Email and notification data required'}), 400
        
        result = notification_service.send_email(email, notification)
        
        status_code = 200 if result['success'] else 400
        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'data': result.get('data', {})
        }), status_code
        
    except Exception as e:
        logger.error(f'Email send error: {str(e)}')
        return jsonify({
            'error': str(e),
            'message': 'Failed to send email notification'
        }), 500

