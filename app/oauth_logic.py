from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests as http_requests
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class GoogleOAuthService:
    """Service for handling Google OAuth authentication"""
    
    def __init__(self):
        self.client_id = Config.GOOGLE_CLIENT_ID
        self.client_secret = Config.GOOGLE_CLIENT_SECRET
    
    def verify_google_token(self, token: str) -> dict | None:
        """
        Verify Google ID token and return user info
        
        Args:
            token: Google ID token from client
            
        Returns:
            dict with google_id, email, name, picture, email_verified if valid, None otherwise
        """
        if not self.client_id:
            return None
        
        try:
            request = google_requests.Request()
            idinfo = id_token.verify_oauth2_token(
                token, request, self.client_id
            )
            
            # Verify the issuer
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')
            
            return {
                'google_id': idinfo['sub'],
                'email': idinfo['email'],
                'name': idinfo.get('name'),
                'picture': idinfo.get('picture'),
                'email_verified': idinfo.get('email_verified', False)
            }
        except ValueError as e:
            print(f"Google token verification error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error verifying Google token: {e}")
            return None
    
    def get_google_user_info(self, access_token: str) -> dict | None:
        """
        Get user info using OAuth access token (alternative method)
        
        Args:
            access_token: Google OAuth access token
            
        Returns:
            dict with user info if successful, None otherwise
        """
        google_userinfo_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        try:
            response = http_requests.get(
                google_userinfo_url,
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Error getting Google user info: {e}")
            return None

