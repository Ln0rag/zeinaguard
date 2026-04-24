"""
Notification Routes for ZeinaGuard Pro
Handles webhook and email configuration endpoints
"""

from flask import Blueprint, request, jsonify
from notifications_mock import notification_service
import logging

# Create blueprint
notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')
logger = logging.getLogger(__name__)


@notifications_bp.route('/webhook-test', methods=['POST'])
def test_webhook():
    """
    Test webhook connection
    Logs the webhook URL for testing purposes
    """
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'Webhook URL required'}), 400
        
        result = notification_service.test_webhook(url)
        
        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'data': result.get('data', {})
        }), 200
        
    except Exception as e:
        logger.error(f'Webhook test error: {str(e)}')
        return jsonify({
            'error': str(e),
            'message': 'Failed to test webhook'
        }), 500


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
        
        result = notification_service.test_email(email)
        
        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'data': result.get('data', {})
        }), 200
        
    except Exception as e:
        logger.error(f'Email test error: {str(e)}')
        return jsonify({
            'error': str(e),
            'message': 'Failed to test email'
        }), 500


@notifications_bp.route('/send-webhook', methods=['POST'])
def send_webhook_notification():
    """
    Send a notification via webhook
    """
    try:
        data = request.get_json()
        url = data.get('url')
        notification = data.get('notification')
        
        if not url or not notification:
            return jsonify({'error': 'URL and notification data required'}), 400
        
        result = notification_service.send_webhook(url, notification)
        
        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'data': result.get('data', {})
        }), 200
        
    except Exception as e:
        logger.error(f'Webhook send error: {str(e)}')
        return jsonify({
            'error': str(e),
            'message': 'Failed to send webhook notification'
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
        
        return jsonify({
            'success': result['success'],
            'message': result['message'],
            'data': result.get('data', {})
        }), 200
        
    except Exception as e:
        logger.error(f'Email send error: {str(e)}')
        return jsonify({
            'error': str(e),
            'message': 'Failed to send email notification'
        }), 500


def register_notification_blueprint(app):
    """Register the notifications blueprint with the Flask app"""
    app.register_blueprint(notifications_bp)
