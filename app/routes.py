from flask import Blueprint, request, jsonify, current_app
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db
from app.auth_logic import AuthLogic
from app.models import User

auth_bp = Blueprint('auth', __name__)

def get_auth_logic():
    """Get AuthLogic instance with current database session"""
    return AuthLogic(db.session)

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.json
    email = data.get('email') if data else None
    password = data.get('password') if data else None
    username = data.get('username') if data else None
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    auth_logic = get_auth_logic()
    result = auth_logic.register_user(email, password, username)
    
    # Log email sending status for debugging
    if result.get('email_sent') is False:
        print(f"WARNING: Email was not sent to {email}. Check Resend configuration.")
    
    if result['success']:
        return jsonify(result), 201
    return jsonify(result), 400

@auth_bp.route('/verify-email', methods=['GET'])
def verify_email():
    """Verify email with token"""
    token = request.args.get('token')
    if not token:
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Verification Failed</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h2>Verification Failed</h2>
            <p>No verification token provided.</p>
        </body>
        </html>
        """, 400
    
    auth_logic = get_auth_logic()
    result = auth_logic.verify_email(token)
    
    if result['success']:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verified</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px;
                    background: #f5f5f5;
                }
                .container {
                    max-width: 500px;
                    margin: 0 auto;
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                .success {
                    color: #4CAF50;
                    font-size: 48px;
                    margin-bottom: 20px;
                }
                h2 {
                    color: #333;
                    margin-bottom: 20px;
                }
                p {
                    color: #666;
                    line-height: 1.6;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="success">✓</div>
                <h2>Email Verified Successfully!</h2>
                <p>Your email address has been verified. You can now log in to Catnip.</p>
                <p style="margin-top: 30px; font-size: 14px; color: #999;">
                    You can close this window and return to the app.
                </p>
            </div>
        </body>
        </html>
        """, 200
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Verification Failed</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: Arial, sans-serif;
                text-align: center;
                padding: 50px;
                background: #f5f5f5;
            }}
            .container {{
                max-width: 500px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .error {{
                color: #f44336;
                font-size: 48px;
                margin-bottom: 20px;
            }}
            h2 {{
                color: #333;
                margin-bottom: 20px;
            }}
            p {{
                color: #666;
                line-height: 1.6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="error">✗</div>
            <h2>Verification Failed</h2>
            <p>{result.get('error', 'Invalid or expired verification token.')}</p>
            <p style="margin-top: 30px; font-size: 14px; color: #999;">
                Please request a new verification email if needed.
            </p>
        </div>
    </body>
    </html>
    """, 400

@auth_bp.route('/login', methods=['POST'])
def login():
    """Login with email/password"""
    data = request.json
    email = data.get('email') if data else None
    password = data.get('password') if data else None
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    auth_logic = get_auth_logic()
    result = auth_logic.login(email, password)
    
    if result['success']:
        return jsonify(result), 200
    return jsonify(result), 401

@auth_bp.route('/google-login', methods=['POST'])
def google_login():
    """Login with Google OAuth token"""
    data = request.json
    google_token = data.get('token') if data else None
    
    if not google_token:
        return jsonify({'success': False, 'error': 'Google token required'}), 400
    
    auth_logic = get_auth_logic()
    result = auth_logic.google_login(google_token)
    
    if result['success']:
        return jsonify(result), 200
    return jsonify(result), 401

@auth_bp.route('/verify-token', methods=['POST'])
def verify_token():
    """
    Verify JWT token (used by local server)
    
    This endpoint is called by the local server to validate tokens
    """
    data = request.json
    token = data.get('token') if data else None
    
    if not token:
        return jsonify({'success': False, 'error': 'Token required'}), 400
    
    auth_logic = get_auth_logic()
    payload = auth_logic.verify_jwt_token(token)
    
    if payload:
        # Optionally verify user still exists and is active
        user = db.session.query(User).filter_by(id=payload['user_id']).first()
        if user and user.is_active:
            return jsonify({
                'success': True,
                'user_id': payload['user_id'],
                'email': payload['email']
            }), 200
    
    return jsonify({'success': False, 'error': 'Invalid token'}), 401

