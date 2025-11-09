import bcrypt
import jwt
import sys
import os
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models import User
from config import Config
from app.email_service import EmailService
from app.oauth_logic import GoogleOAuthService

class AuthLogic:
    """Business logic for authentication"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.secret_key = Config.SECRET_KEY
        self.email_service = EmailService()
        self.oauth_service = GoogleOAuthService()
        self.token_expiry = timedelta(days=Config.JWT_EXPIRATION_DAYS)
    
    def normalize_email(self, email: str) -> str:
			"""Normalize email for case-insensitive comparison and plus-addressing rules.
			
			- Always trims and lowercases.
			- If plus addressing is disallowed (Config.ALLOW_PLUS_ADDRESSING is False),
			  strips the '+tag' from the local part, e.g., 'user+news@example.com' -> 'user@example.com'.
			"""
			if not email:
				return email
			e = email.strip().lower()
			if not Config.ALLOW_PLUS_ADDRESSING:
				if '@' in e:
					local, domain = e.split('@', 1)
					if '+' in local:
						local = local.split('+', 1)[0]
					e = f"{local}@{domain}"
			return e
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def create_jwt_token(self, user_id: int, email: str) -> str:
        """Create JWT token for user"""
        payload = {
            'user_id': user_id,
            'email': email,
            'exp': datetime.utcnow() + self.token_expiry,
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> dict | None:
        """
        Verify JWT token
        
        Returns:
            dict with user_id and email if valid,
            {'expired': True} if signature expired,
            None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return {'expired': True}
        except jwt.InvalidTokenError:
            return None
    
    def register_user(self, email: str, password: str, username: str = None) -> dict:
        """
        Register new user with email/password
        
        Returns:
            dict with success status and message/user_id
        """
        # Normalize email to lowercase
        email = self.normalize_email(email)
        
        # Check if user exists (case-insensitive)
        existing = self.db.query(User).filter(func.lower(User.email) == email.lower()).first()
        if existing:
            # Normalize existing user's email if needed
            if existing.email != email:
                existing.email = email
                self.db.commit()
            return {'success': False, 'error': 'Email already registered'}
        
        # Create verification token
        verification_token = self.email_service.generate_verification_token()
        
        # Create user
        user = User(
            email=email,
            username=username,
            password_hash=self.hash_password(password),
            email_verification_token=verification_token,
            email_verification_sent_at=datetime.utcnow()
        )
        
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        
        # Send verification email
        email_sent = self.email_service.send_verification_email(email, verification_token)
        
        return {
            'success': True,
            'user_id': user.id,
            'message': 'Registration successful. Please check your email to verify your account.',
            'email_sent': email_sent
        }
    
    def verify_email(self, token: str) -> dict:
        """
        Verify user email with token
        
        Returns:
            dict with success status and message
        """
        user = self.db.query(User).filter_by(email_verification_token=token).first()
        if not user:
            return {'success': False, 'error': 'Invalid verification token'}
        
        user.email_verified = True
        user.email_verification_token = None
        self.db.commit()
        
        return {'success': True, 'message': 'Email verified successfully'}
    
    def login(self, email: str, password: str) -> dict:
        """
        Login with email/password
        
        Returns:
            dict with success status, token, and user info
        """
        # Normalize email to lowercase
        normalized_email = self.normalize_email(email)
        
        # Find user case-insensitively
        user = self.db.query(User).filter(func.lower(User.email) == normalized_email.lower()).first()
        
        if not user or not user.password_hash:
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Normalize user's email in database if needed
        if user.email != normalized_email:
            user.email = normalized_email
            self.db.commit()
        
        if not self.verify_password(password, user.password_hash):
            return {'success': False, 'error': 'Invalid credentials'}
        
        if not user.email_verified:
            return {
                'success': False,
                'error': 'Email not verified',
                'requires_verification': True
            }
        
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        token = self.create_jwt_token(user.id, user.email)
        
        return {
            'success': True,
            'token': token,
            'user': user.to_dict()
        }

    def request_password_reset(self, email: str) -> dict:
        """Generate password reset token and send reset email. Always return success."""
        # Normalize email to lowercase
        normalized_email = self.normalize_email(email)
        
        # Find user case-insensitively
        user = self.db.query(User).filter(func.lower(User.email) == normalized_email.lower()).first()
        if not user:
            # Do not reveal whether email exists
            return {'success': True, 'message': 'If the email exists, a reset link has been sent.'}

        # Normalize user's email in database if needed
        if user.email != normalized_email:
            user.email = normalized_email
            self.db.commit()

        reset_token = self.email_service.generate_verification_token()
        user.password_reset_token = reset_token
        user.password_reset_sent_at = datetime.utcnow()
        user.password_reset_expires_at = datetime.utcnow() + timedelta(hours=1)
        self.db.commit()

        # Send email to normalized (lowercase) email
        self.email_service.send_password_reset_email(normalized_email, reset_token)
        return {'success': True, 'message': 'If the email exists, a reset link has been sent.'}

    def reset_password(self, token: str, new_password: str) -> dict:
        """Reset the password using a valid, non-expired token."""
        user = self.db.query(User).filter_by(password_reset_token=token).first()
        if not user:
            return {'success': False, 'error': 'Invalid or expired reset token'}

        if user.password_reset_expires_at and user.password_reset_expires_at < datetime.utcnow():
            return {'success': False, 'error': 'Reset token has expired'}

        user.password_hash = self.hash_password(new_password)
        user.password_reset_token = None
        user.password_reset_sent_at = None
        user.password_reset_expires_at = None
        self.db.commit()
        return {'success': True, 'message': 'Password reset successfully'}
    
    def google_login(self, google_token: str) -> dict:
        """
        Login/register with Google OAuth token
        
        Returns:
            dict with success status, token, and user info
        """
        google_info = self.oauth_service.verify_google_token(google_token)
        if not google_info:
            return {'success': False, 'error': 'Invalid Google token'}
        
        # Normalize email to lowercase
        google_email = self.normalize_email(google_info['email'])
        
        # Check if user exists by Google ID
        user = self.db.query(User).filter_by(google_id=google_info['google_id']).first()
        
        if not user:
            # Check if email already exists (case-insensitive)
            existing = self.db.query(User).filter(func.lower(User.email) == google_email.lower()).first()
            if existing:
                # Normalize existing user's email if needed
                if existing.email != google_email:
                    existing.email = google_email
                # Link Google account to existing user
                existing.google_id = google_info['google_id']
                existing.google_email = google_email
                existing.email_verified = True  # Google emails are pre-verified
                user = existing
            else:
                # Create new user
                user = User(
                    email=google_email,
                    username=google_info.get('name'),
                    google_id=google_info['google_id'],
                    google_email=google_email,
                    email_verified=True  # Google emails are verified
                )
                self.db.add(user)
        
        user.last_login = datetime.utcnow()
        self.db.commit()
        self.db.refresh(user)
        
        token = self.create_jwt_token(user.id, user.email)
        
        return {
            'success': True,
            'token': token,
            'user': user.to_dict()
        }

