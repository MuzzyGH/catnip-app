import os

class Config:
    """Configuration for authentication server"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///auth.db')
    # Heroku provides postgres:// but SQLAlchemy needs postgresql://
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,  # Verify connections before using
        'pool_recycle': 300,    # Recycle connections after 5 minutes
    }
    
    # Email configuration (Resend)
    RESEND_API_KEY = os.environ.get('RESEND_API_KEY')
    FROM_EMAIL = os.environ.get('FROM_EMAIL', 'noreply@updates.catnip.be')  # Using verified subdomain
    VERIFICATION_BASE_URL = os.environ.get('VERIFICATION_BASE_URL', 'https://api.catnip.be')  # Using subdomain for API/auth endpoints
    
    # Fallback SMTP (if Resend not available)
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USER = os.environ.get('SMTP_USER')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    
    # Google OAuth
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    # CORS - Allow Electron app origins
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # JWT settings
    JWT_EXPIRATION_DAYS = 30

    # Email normalization rules
    # Disallow plus-addressing (treat user+tag@example.com as user@example.com) when False
    ALLOW_PLUS_ADDRESSING = os.environ.get('ALLOW_PLUS_ADDRESSING', 'false').strip().lower() in ('1', 'true', 'yes')

# Backwards/explicit lower-case alias as requested
allow_plus_addressing = Config.ALLOW_PLUS_ADDRESSING

