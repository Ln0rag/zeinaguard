"""
Mock notification service for external integrations
Logs webhook and email notifications without actually sending them
"""

import json
import logging
from datetime import datetime
from typing import Optional

# Setup logging
logger = logging.getLogger(__name__)


class NotificationServiceMock:
    """
    Mock notification service that logs webhooks and emails
    In production, replace these with actual Slack/Discord/Email services
    """

    @staticmethod
    def send_webhook(url: str, notification_data: dict) -> dict:
        """
        Mock webhook send - logs instead of posting
        In production, use: requests.post(url, json=notification_data)
        """
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "service": "WEBHOOK",
                "url": url,
                "payload": notification_data,
                "status": "logged (mock)",
            }
            
            logger.info(f"📤 WEBHOOK MOCK: {json.dumps(log_entry, indent=2)}")
            
            return {
                "success": True,
                "message": f"Webhook logged for {url}",
                "data": log_entry,
            }
        except Exception as e:
            logger.error(f"Error logging webhook: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to log webhook: {str(e)}",
            }

    @staticmethod
    def send_email(email: str, notification_data: dict) -> dict:
        """
        Mock email send - logs instead of sending
        In production, use: Flask-Mail or SendGrid or similar
        """
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "service": "EMAIL",
                "recipient": email,
                "subject": notification_data.get("title", "ZeinaGuard Alert"),
                "body": notification_data.get("message", ""),
                "type": notification_data.get("type", "info"),
                "status": "logged (mock)",
            }
            
            logger.info(f"📧 EMAIL MOCK: {json.dumps(log_entry, indent=2)}")
            
            return {
                "success": True,
                "message": f"Email logged for {email}",
                "data": log_entry,
            }
        except Exception as e:
            logger.error(f"Error logging email: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to log email: {str(e)}",
            }

    @staticmethod
    def test_webhook(url: str) -> dict:
        """
        Test webhook connection (mock)
        """
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "service": "WEBHOOK_TEST",
                "url": url,
                "status": "test_logged (mock)",
            }
            
            logger.info(f"🧪 WEBHOOK TEST: {json.dumps(log_entry, indent=2)}")
            
            return {
                "success": True,
                "message": f"Webhook test logged for {url}",
                "data": log_entry,
            }
        except Exception as e:
            logger.error(f"Error testing webhook: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to test webhook: {str(e)}",
            }

    @staticmethod
    def test_email(email: str) -> dict:
        """
        Test email address (mock)
        """
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "service": "EMAIL_TEST",
                "recipient": email,
                "status": "test_logged (mock)",
            }
            
            logger.info(f"🧪 EMAIL TEST: {json.dumps(log_entry, indent=2)}")
            
            return {
                "success": True,
                "message": f"Email test logged for {email}",
                "data": log_entry,
            }
        except Exception as e:
            logger.error(f"Error testing email: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to test email: {str(e)}",
            }


# Singleton instance
notification_service = NotificationServiceMock()
