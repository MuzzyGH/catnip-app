import secrets
import os
import sys
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

class EmailService:
    """Email service for sending verification emails using Resend or SMTP fallback"""
    
    def __init__(self):
        self.resend_api_key = Config.RESEND_API_KEY
        self.from_email = Config.FROM_EMAIL
        self.base_url = Config.VERIFICATION_BASE_URL
        
        # SMTP fallback
        self.smtp_server = Config.SMTP_SERVER
        self.smtp_port = Config.SMTP_PORT
        self.smtp_user = Config.SMTP_USER
        self.smtp_password = Config.SMTP_PASSWORD
    
    def generate_verification_token(self):
        """Generate a secure verification token"""
        return secrets.token_urlsafe(32)
    
    def send_verification_email(self, email: str, token: str) -> bool:
        """
        Send email verification email using Resend (preferred) or SMTP fallback
        
        Args:
            email: Recipient email address
            token: Verification token
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        verification_link = f"{self.base_url}/verify-email?token={token}"
        
        # Try Resend first
        if self.resend_api_key:
            try:
                import resend
                resend.api_key = self.resend_api_key
                
                resend.Emails.send({
                    "from": self.from_email,
                    "to": email,
                    "subject": "Verify Your Catnip Account",
                    "html": f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #333;">Welcome to Catnip!</h2>
                        <p>Please verify your email address by clicking the button below:</p>
                        <p style="text-align: center; margin: 30px 0;">
                            <a href="{verification_link}" 
                               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                                      text-decoration: none; border-radius: 5px; display: inline-block;">
                                Verify Email
                            </a>
                        </p>
                        <p>Or copy this link into your browser:</p>
                        <p style="word-break: break-all; color: #666;">{verification_link}</p>
                        <p style="margin-top: 30px; color: #999; font-size: 12px;">
                            If you didn't create this account, please ignore this email.
                        </p>
                    </body>
                    </html>
                    """
                })
                return True
            except Exception as e:
                print(f"Resend email error: {e}")
                # Fall through to SMTP
        
        # Fallback to SMTP
        if self.smtp_user and self.smtp_password:
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                
                msg = MIMEMultipart('alternative')
                msg['Subject'] = 'Verify Your Catnip Account'
                msg['From'] = self.from_email
                msg['To'] = email
                
                text = f"""Welcome to Catnip!
                
Please verify your email by clicking this link:
{verification_link}

If you didn't create this account, please ignore this email.
"""
                
                html = f"""<html>
<body style="font-family: Arial, sans-serif;">
<h2>Welcome to Catnip!</h2>
<p>Please verify your email by clicking the link below:</p>
<p><a href="{verification_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
<p>Or copy this link: {verification_link}</p>
<p>If you didn't create this account, please ignore this email.</p>
</body>
</html>"""
                
                msg.attach(MIMEText(text, 'plain'))
                msg.attach(MIMEText(html, 'html'))
                
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
                server.quit()
                return True
            except Exception as e:
                print(f"SMTP email error: {e}")
                return False
        
        print("No email service configured (neither Resend nor SMTP)")
        return False

