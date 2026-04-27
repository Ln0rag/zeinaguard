"""
JWT Authentication Module for ZeinaGuard Pro
"""
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models import db, User

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

class AuthService:
    """
    Class to handle user authentication and token management
    """
    
    @staticmethod
    def verify_password(stored_hash: str, provided_password: str) -> bool:
        if not stored_hash or not provided_password:
            return False
        return check_password_hash(stored_hash, provided_password)

    @staticmethod
    def authenticate_user(username: str, password: str):
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"[AUTH] User not found: {username}")
            return None
        
        if not user.is_active:
            print(f"[AUTH] User inactive: {username}")
            return None
        
        if not AuthService.verify_password(user.password_hash, password):
            print(f"[AUTH] Password mismatch for user: {username}")
            return None
        
        print(f"[AUTH] User authenticated: {username}")
        return user

    @staticmethod
    def create_tokens(user_id, username, is_admin):  # شيلنا الـ email من هنا
        """
        Generates JWT tokens for the authenticated user
        """
        # Put important data inside the Identity
        additional_claims = {
            "username": username,
            "is_admin": is_admin
        }
        
        access_token = create_access_token(
            identity=str(user_id), 
            additional_claims=additional_claims,
            expires_delta=timedelta(hours=24)
        )
        
        return {
            'access_token': access_token,
            'user': {
                'id': user_id,
                'username': username,
                'is_admin': is_admin
            }
        }
@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing request body'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        user = AuthService.authenticate_user(username, password)
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
            
        # نادينـا على الدالة من غير الـ email
        auth_data = AuthService.create_tokens(
            user_id=user.id,
            username=user.username,
            is_admin=user.is_admin
        )
        
        return jsonify(auth_data), 200
        
    except Exception as e:
        print(f"[AUTH] Critical error during login: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500