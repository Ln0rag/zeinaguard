"""
Auth Module for ZeinaGuard Pro - Final Comprehensive Version
Includes all functions required by app.py and routes.py
"""
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, 
    get_jwt_identity, get_jwt
)

# 1. Define Blueprint (required for routes.py)
auth_bp = Blueprint('auth', __name__)
HASH_METHOD = 'pbkdf2:sha256'

# 2. Authentication and encryption functions
def hash_password(password: str) -> str:
    return generate_password_hash(password, method=HASH_METHOD)

def verify_password(stored_hash: str, provided_password: str) -> bool:
    return check_password_hash(stored_hash, provided_password)

def authenticate_user(username: str, password: str):
    user = MOCK_USERS.get(username)
    if user and verify_password(user['password_hash'], password):
        return user
    return None

def get_user_by_id(user_id: int):
    """The function that was missing and causing the problem"""
    for user in MOCK_USERS.values():
        if user['user_id'] == user_id:
            return user
    return None

# 3. Decorators (required for routes.py)
def token_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()
        return f(current_user, *args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user = get_jwt_identity()
        if not current_user or not current_user.get('is_admin'):
            return jsonify({'error': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated_function

# 4. AuthService class (required for app.py)
class AuthService:
    def __init__(self, app=None):
        self.app = app
        self.jwt = None
        if app: self.init_app(app)
    
    def init_app(self, app):
        self.jwt = JWTManager(app)

    @staticmethod
    def create_tokens(user_id, username, email, is_admin=False):
        identity = {'user_id': user_id, 'username': username, 'email': email, 'is_admin': is_admin}
        access_token = create_access_token(identity=identity, expires_delta=timedelta(hours=24))
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 86400,
            'user': {'id': user_id, 'username': username, 'email': email, 'is_admin': is_admin}
        }

# 5. Mock users (for testing login with admin/admin123)
MOCK_USERS = {
    'admin': {
        'user_id': 1,
        'username': 'admin',
        'email': 'admin@zeinaguard.local',
        'password_hash': generate_password_hash('admin123', method=HASH_METHOD),
        'is_admin': True,
        'is_active': True
    }
}

# 6. API routes
@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data: return jsonify({'error': 'Missing JSON'}), 400
    user = authenticate_user(data.get('username'), data.get('password'))
    if not user: return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify(AuthService.create_tokens(user['user_id'], user['username'], user['email'], user['is_admin']))