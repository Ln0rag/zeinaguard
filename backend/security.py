"""
Security hardening utilities for ZeinaGuard Pro backend
- Rate limiting
- Input validation
- CORS security
- Security headers
"""

from flask import request, jsonify
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import re

# Rate limiting store (in production, use Redis)
request_counts = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 60
MAX_REQUESTS_PER_HOUR = 1000


def rate_limit(max_per_minute: int = MAX_REQUESTS_PER_MINUTE):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = datetime.now()
            
            # Clean old requests
            request_counts[client_ip] = [
                req_time for req_time in request_counts[client_ip]
                if (now - req_time).seconds < 60
            ]
            
            # Check limit
            if len(request_counts[client_ip]) >= max_per_minute:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            request_counts[client_ip].append(now)
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format"""
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, mac))


def validate_ssid(ssid: str) -> bool:
    """Validate SSID (network name)"""
    if not ssid or len(ssid) > 32:
        return False
    # SSID can contain most printable characters
    return True


def validate_ip_address(ip: str) -> bool:
    """Validate IP address"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def sanitize_input(user_input: str, max_length: int = 255) -> str:
    """Sanitize user input to prevent injection attacks"""
    if not isinstance(user_input, str):
        return ""

    user_input = user_input.replace("\x00", "")

    # Limit length
    user_input = user_input[:max_length]
    
    # Remove potentially dangerous characters
    user_input = user_input.replace('<', '&lt;')
    user_input = user_input.replace('>', '&gt;')
    user_input = user_input.replace('"', '&quot;')
    user_input = user_input.replace("'", '&#x27;')
    
    return user_input.strip()


def sanitize_json_payload(data):
    """Recursively remove null bytes from JSON-like payloads."""
    if isinstance(data, str):
        return data.replace("\x00", "")

    if isinstance(data, bytes):
        return data.decode("utf-8", errors="ignore").replace("\x00", "")

    if isinstance(data, dict):
        return {
            sanitize_json_payload(key) if isinstance(key, (str, bytes)) else key: sanitize_json_payload(value)
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [sanitize_json_payload(item) for item in data]

    if isinstance(data, tuple):
        return tuple(sanitize_json_payload(item) for item in data)

    return data


def add_security_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response


def validate_request_json(required_fields: list):
    """Validate incoming JSON request"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            
            for field in required_fields:
                if field not in data or data[field] is None:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


class SecurityConfig:
    """Security configuration for production"""
    
    # CORS Settings
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:5000',
    ]
    
    # JWT Settings
    JWT_ALGORITHM = 'HS256'
    JWT_EXPIRATION_HOURS = 24
    REFRESH_TOKEN_EXPIRATION_DAYS = 30
    
    # Password Policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    
    # Rate Limiting
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_ATTEMPT_WINDOW_MINUTES = 15
    ACCOUNT_LOCKOUT_MINUTES = 30
    
    # Session Security
    SESSION_TIMEOUT_MINUTES = 60
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Audit Logging
    LOG_AUTH_EVENTS = True
    LOG_API_REQUESTS = True
    LOG_RETENTION_DAYS = 90


def check_password_strength(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    config = SecurityConfig()
    
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f'Password must be at least {config.MIN_PASSWORD_LENGTH} characters'
    
    if config.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, 'Password must contain uppercase letters'
    
    if config.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False, 'Password must contain lowercase letters'
    
    if config.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
        return False, 'Password must contain digits'
    
    if config.REQUIRE_SPECIAL_CHARS and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, 'Password must contain special characters'
    
    return True, 'Password is strong'
