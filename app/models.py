from database import db
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime

# Use Flask-SQLAlchemy's declarative base
Base = db.Model

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=True)  # None if Google-only user
    
    # Email verification
    email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String(100), unique=True, nullable=True)
    email_verification_sent_at = Column(DateTime, nullable=True)
    
    # Google OAuth
    google_id = Column(String(255), unique=True, nullable=True, index=True)
    google_email = Column(String(255), nullable=True)
    
    # Account info
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'email_verified': self.email_verified,
            'has_google_auth': self.google_id is not None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

