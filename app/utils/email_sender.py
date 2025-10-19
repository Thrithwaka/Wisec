"""
Email Functionality Module - FULLY FIXED VERSION
Purpose: Handle all email communications for Wi-Fi Security System

CRITICAL FIXES:
- Proper environment variable loading
- Fixed SMTP authentication and connection handling
- Added comprehensive error handling with detailed logging
- Fixed email template rendering
- Added email queue with proper error handling
- Fixed Flask-Mail integration
"""

import smtplib
import ssl
import logging
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import re
import threading
import time
from queue import Queue, Empty
import json
from jinja2 import Template
from flask import current_app
from werkzeug.utils import secure_filename
import smtplib
from email.message import EmailMessage
import logging


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class EmailTemplate:
    """Email template management class"""
    
    def __init__(self):
        self.templates = self._load_default_templates()
        
    def _load_default_templates(self) -> Dict[str, str]:
        """Load default email templates"""
        return {
            'verification': """
            <html>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px;">
                        <h2 style="color: #333; text-align: center;">Wi-Fi Security System</h2>
                        <h3 style="color: #2c5aa0;">Email Verification Required</h3>
                        <p>Hello {{ user_name }},</p>
                        <p>Thank you for registering with Wi-Fi Security System. Please verify your email address by clicking the link below:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{{ verification_link }}" style="background-color: #2c5aa0; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email Address</a>
                        </div>
                        <p>This verification link will expire in 24 hours.</p>
                        <p>If you did not create this account, please ignore this email.</p>
                        <hr style="margin: 30px 0;">
                        <p style="font-size: 12px; color: #666;">Wi-Fi Security System - Automated Email</p>
                    </div>
                </body>
            </html>
            """,
            
            'password_reset': """
            <html>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px;">
                        <h2 style="color: #333; text-align: center;">Wi-Fi Security System</h2>
                        <h3 style="color: #d9534f;">Password Reset Request</h3>
                        <p>Hello {{ user_name }},</p>
                        <p>We received a request to reset your password. Click the link below to set a new password:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{{ reset_link }}" style="background-color: #d9534f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                        </div>
                        <p>This reset link will expire in 1 hour.</p>
                        <p>If you did not request a password reset, please ignore this email and your password will remain unchanged.</p>
                        <hr style="margin: 30px 0;">
                        <p style="font-size: 12px; color: #666;">Wi-Fi Security System - Automated Email</p>
                    </div>
                </body>
            </html>
            """,
            
            'test_email': """
            <html>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px;">
                        <h2 style="color: #333; text-align: center;">Wi-Fi Security System</h2>
                        <h3 style="color: #5cb85c;">Email Test Successful</h3>
                        <p>Hello {{ user_name | default('User') }},</p>
                        <p>This is a test email from the Wi-Fi Security System. If you received this email, the email configuration is working correctly.</p>
                        <p><strong>Test Details:</strong></p>
                        <ul>
                            <li>Timestamp: {{ timestamp }}</li>
                            <li>Server: {{ mail_server }}</li>
                            <li>Port: {{ mail_port }}</li>
                        </ul>
                        <hr style="margin: 30px 0;">
                        <p style="font-size: 12px; color: #666;">Wi-Fi Security System - Test Email</p>
                    </div>
                </body>
            </html>
            """
        }
    
    def get_template(self, template_name: str) -> Optional[str]:
        """Get template by name"""
        return self.templates.get(template_name)
    
    def render_template(self, template_name: str, **kwargs) -> str:
        """Render template with variables"""
        template_content = self.get_template(template_name)
        if not template_content:
            raise ValueError(f"Template '{template_name}' not found")
        
        template = Template(template_content)
        return template.render(**kwargs)
    
    def add_custom_template(self, name: str, content: str):
        """Add custom template"""
        self.templates[name] = content


class EmailQueue:
    """Email queue management for asynchronous sending"""
    
    def __init__(self, max_size: int = 1000):
        self.queue = Queue(maxsize=max_size)
        self.failed_queue = Queue(maxsize=max_size)
        self.is_processing = False
        self.worker_thread = None
        self.retry_attempts = 3
        self.retry_delay = 60  # seconds
        
    def add_email(self, email_data: Dict[str, Any]) -> bool:
        """Add email to queue"""
        try:
            email_data['queued_at'] = datetime.utcnow()
            email_data['attempts'] = 0
            self.queue.put(email_data, block=False)
            logger.info(f"Email added to queue: {email_data.get('subject', 'No subject')}")
            return True
        except Exception as e:
            logger.error(f"Failed to add email to queue: {str(e)}")
            return False
    
    def start_processing(self, email_sender):
        """Start email queue processing"""
        if not self.is_processing:
            self.is_processing = True
            self.worker_thread = threading.Thread(
                target=self._process_queue, 
                args=(email_sender,), 
                daemon=True
            )
            self.worker_thread.start()
            logger.info("Email queue processing started")
    
    def stop_processing(self, reason="Unknown"):
        """Stop email queue processing"""
        self.is_processing = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info(f"Email queue processing stopped. Reason: {reason}")

    
    def _process_queue(self, email_sender):
        """Process email queue"""
        while self.is_processing:
            try:
                email_data = self.queue.get(timeout=1)
                success = self._send_email_from_queue(email_sender, email_data)
                
                if not success:
                    email_data['attempts'] += 1
                    if email_data['attempts'] < self.retry_attempts:
                        # Retry after delay
                        time.sleep(self.retry_delay)
                        self.queue.put(email_data)
                        logger.info(f"Email retry queued: attempt {email_data['attempts']}")
                    else:
                        # Move to failed queue
                        self.failed_queue.put(email_data)
                        logger.error(f"Email failed after {self.retry_attempts} attempts")
                
                self.queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing email queue: {str(e)}")
    
    def _send_email_from_queue(self, email_sender, email_data: Dict[str, Any]) -> bool:
        """Send email from queue data"""
        try:
            return email_sender._send_email_direct(**email_data)
        except Exception as e:
            logger.error(f"Failed to send queued email: {str(e)}")
            return False
    
    def get_queue_status(self) -> Dict[str, int]:
        """Get queue status"""
        return {
            'pending': self.queue.qsize(),
            'failed': self.failed_queue.qsize(),
            'is_processing': self.is_processing
        }


class EmailValidator:
    """Email validation utilities"""
    
    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_multiple_emails(emails: List[str]) -> Dict[str, bool]:
        """Validate multiple email addresses"""
        results = {}
        for email in emails:
            results[email] = EmailValidator.validate_email_format(email)
        return results
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Sanitize email address"""
        return email.strip().lower()
    
    @staticmethod
    def validate_email_domain(email: str, allowed_domains: Optional[List[str]] = None) -> bool:
        """Validate email domain against allowed list"""
        if not allowed_domains:
            return True
        
        domain = email.split('@')[-1].lower()
        return domain in [d.lower() for d in allowed_domains]


class EmailSender:
    """Main email sending class - FULLY FIXED"""
    
    def __init__(self, app=None):
        self.app = app
        self.smtp_server = None
        self.smtp_port = None
        self.username = None
        self.password = None
        self.use_tls = True
        self.use_ssl = False
        self.template_manager = EmailTemplate()
        self.email_queue = EmailQueue()
        self.delivery_tracking = {}
        self._connection_pool = {}
        self._is_configured = False
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app - CRITICAL FIX"""
        self.app = app
        
        # Get configuration from app config (which should have environment variables loaded)
        self.smtp_server = app.config.get('MAIL_SERVER', 'smtp.gmail.com')
        self.smtp_port = app.config.get('MAIL_PORT', 587)
        self.username = app.config.get('MAIL_USERNAME')
        self.password = app.config.get('MAIL_PASSWORD')
        self.use_tls = app.config.get('MAIL_USE_TLS', True)
        self.use_ssl = app.config.get('MAIL_USE_SSL', False)
        
        # Log configuration for debugging
        logger.info(f"🔧 EmailSender Configuration:")
        logger.info(f"  SMTP Server: {self.smtp_server}")
        logger.info(f"  SMTP Port: {self.smtp_port}")
        logger.info(f"  Username: {self.username}")
        logger.info(f"  Password: {'SET' if self.password else 'NOT SET'}")
        logger.info(f"  Use TLS: {self.use_tls}")
        logger.info(f"  Use SSL: {self.use_ssl}")
        
        # Also try to get from environment variables directly as fallback
        if not self.username:
            self.username = os.environ.get('MAIL_USERNAME')
            logger.info(f"  Username from ENV: {self.username}")
        
        if not self.password:
            self.password = os.environ.get('MAIL_PASSWORD')
            logger.info(f"  Password from ENV: {'SET' if self.password else 'NOT SET'}")
        
        # Validate configuration
        if not self.username or not self.password:
            logger.error("❌ Email credentials not configured. Email functionality will be disabled.")
            logger.error(f"MAIL_USERNAME: {self.username}")
            logger.error(f"MAIL_PASSWORD: {'SET' if self.password else 'NOT SET'}")
            self._is_configured = False
            return
        
        # Test connection
        if self._test_connection():
            logger.info("✅ Email service initialized successfully")
            self._is_configured = True
            # Start queue processing
            self.email_queue.start_processing(self)
        else:
            logger.error("❌ Email service initialization failed - connection test failed")
            self._is_configured = False
        
        # Register teardown handler
        #app.teardown_appcontext(self._teardown)
    
    def _test_connection(self) -> bool:
        """Test SMTP connection with detailed error logging"""
        try:
            logger.info(f"🔍 Testing SMTP connection to {self.smtp_server}:{self.smtp_port}")
            
            if self.use_ssl:
                logger.info("Using SSL connection")
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context, timeout=30) as server:
                    server.set_debuglevel(1)  # Enable debug output
                    logger.info("SSL connection established, attempting login...")
                    server.login(self.username, self.password)
                    logger.info("SSL login successful")
            else:
                logger.info("Using SMTP connection with TLS")
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                    server.set_debuglevel(1)  # Enable debug output
                    logger.info("SMTP connection established")
                    
                    if self.use_tls:
                        logger.info("Starting TLS...")
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        logger.info("TLS started successfully")
                    
                    logger.info("Attempting login...")
                    server.login(self.username, self.password)
                    logger.info("Login successful")
            
            logger.info("✅ SMTP connection test successful")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ SMTP Authentication failed: {str(e)}")
            logger.error("Check your email username and password (use App Password for Gmail)")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"❌ SMTP Connection failed: {str(e)}")
            logger.error("Check server settings and network connectivity")
            return False
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"❌ SMTP Server disconnected: {str(e)}")
            return False
        except ssl.SSLError as e:
            logger.error(f"❌ SSL Error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"❌ SMTP connection test failed: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            return False
    
    def _teardown(self, exception):
        """Cleanup on app teardown"""
        self.email_queue.stop_processing()
    
    def send_email(self, to_email: str, subject: str, body: str, 
                   html_body: Optional[str] = None, 
                   attachments: Optional[List[str]] = None,
                   cc: Optional[List[str]] = None,
                   bcc: Optional[List[str]] = None,
                   async_send: bool = True) -> bool:
        """Send individual email"""
        
        # Check if email service is configured
        if not self._is_configured:
            logger.error("❌ Email service not configured - cannot send email")
            return False
        
        # Validate email format
        if not EmailValidator.validate_email_format(to_email):
            logger.error(f"❌ Invalid email format: {to_email}")
            return False
        
        email_data = {
            'to_email': to_email,
            'subject': subject,
            'body': body,
            'html_body': html_body,
            'attachments': attachments or [],
            'cc': cc or [],
            'bcc': bcc or [],
            'from_email': self.username,
            'timestamp': datetime.utcnow()
        }
        
        if async_send:
            return self.queue_email(email_data)
        else:
            return self._send_email_direct(**email_data)
    
    def send_bulk_email(self, recipients: List[str], subject: str, body: str,
                       html_body: Optional[str] = None,
                       batch_size: int = 50) -> Dict[str, Any]:
        """Send bulk emails in batches"""
        
        results = {
            'total': len(recipients),
            'queued': 0,
            'failed': 0,
            'invalid_emails': []
        }
        
        # Check if email service is configured
        if not self._is_configured:
            logger.error("❌ Email service not configured - cannot send bulk email")
            results['failed'] = len(recipients)
            return results
        
        # Validate all emails first
        valid_emails = []
        for email in recipients:
            if EmailValidator.validate_email_format(email):
                valid_emails.append(EmailValidator.sanitize_email(email))
            else:
                results['invalid_emails'].append(email)
                results['failed'] += 1
        
        # Send in batches
        for i in range(0, len(valid_emails), batch_size):
            batch = valid_emails[i:i + batch_size]
            for email in batch:
                success = self.send_email(
                    to_email=email,
                    subject=subject,
                    body=body,
                    html_body=html_body,
                    async_send=True
                )
                
                if success:
                    results['queued'] += 1
                else:
                    results['failed'] += 1
            
            # Small delay between batches
            time.sleep(1)
        
        logger.info(f"Bulk email queued: {results['queued']} emails")
        return results
    
    def send_verification_email(self, user):
        """Send email verification to user - FIXED"""
        try:
            # Generate verification token if not exists
            if not user.verification_token:
                user.generate_verification_token()
                user.save()
            
            # Get user's first name for personalization
            profile_data = user.get_profile_data()
            user_name = profile_data.get('first_name', user.email.split('@')[0])
            
            # Use Flask app's email_sender instead of global one
            if hasattr(current_app, 'email_sender') and current_app.email_sender:
                success = current_app.email_sender.send_verification_email(
                    user_email=user.email,
                    user_name=user_name,
                    verification_token=user.verification_token
                )
            else:
                current_app.logger.error("❌ Email sender not available in app context")
                return False
            
            if success:
                current_app.logger.info(f"✅ Verification email sent successfully to {user.email}")
                return True
            else:
                current_app.logger.error(f"❌ Failed to send verification email to {user.email}")
                return False
            
        except Exception as e:
            current_app.logger.error(f"Email verification sending failed: {str(e)}")
            return False
    
    def send_password_reset_email(self, user_email: str, user_name: str, 
                                 reset_token: str) -> bool:
        """Send password reset email"""
        
        try:
            if hasattr(current_app, 'config'):
                base_url = current_app.config.get('FRONTEND_URL', 'http://localhost:5000')
            else:
                base_url = 'http://localhost:5000'
                
            reset_link = f"{base_url}/auth/reset-password/{reset_token}"
            
            html_body = self.template_manager.render_template(
                'password_reset',
                user_name=user_name,
                reset_link=reset_link
            )
            
            return self.send_email(
                to_email=user_email,
                subject="Wi-Fi Security System - Password Reset Request",
                body=f"Reset your password by visiting: {reset_link}",
                html_body=html_body,
                async_send=False  # Send synchronously for immediate password reset
            )
        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            return False
    
    def send_test_email(self, test_email: str) -> bool:
        """Send test email with configuration details"""
        try:
            html_body = self.template_manager.render_template(
                'test_email',
                user_name="Test User",
                timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                mail_server=self.smtp_server,
                mail_port=self.smtp_port
            )
            
            return self.send_email(
                to_email=test_email,
                subject="Wi-Fi Security System - Email Test",
                body="This is a test email from the Wi-Fi Security System. Email configuration is working correctly!",
                html_body=html_body,
                async_send=False  # Send synchronously for immediate testing
            )
        except Exception as e:
            logger.error(f"Failed to send test email: {str(e)}")
            return False
    
    def queue_email(self, email_data: Dict[str, Any]) -> bool:
        """Queue email for asynchronous sending"""
        return self.email_queue.add_email(email_data)
    
    def validate_email_address(self, email: str) -> bool:
        """Validate email address format"""
        return EmailValidator.validate_email_format(email)
    
    def track_email_delivery(self, email_id: str, status: str, details: Optional[str] = None):
        """Track email delivery status"""
        self.delivery_tracking[email_id] = {
            'status': status,
            'timestamp': datetime.utcnow(),
            'details': details
        }
        
        # Keep only recent tracking data (last 1000 entries)
        if len(self.delivery_tracking) > 1000:
            oldest_keys = sorted(self.delivery_tracking.keys())[:100]
            for key in oldest_keys:
                del self.delivery_tracking[key]
    
    def get_delivery_status(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Get email delivery status"""
        return self.delivery_tracking.get(email_id)
    
    def manage_templates(self) -> EmailTemplate:
        """Get template manager for custom template management"""
        return self.template_manager
    
    def get_queue_status(self) -> Dict[str, int]:
        """Get email queue status"""
        return self.email_queue.get_queue_status()
    
    def is_configured(self) -> bool:
        """Check if email service is properly configured"""
        return self._is_configured
    
    def get_configuration_status(self) -> Dict[str, Any]:
        """Get detailed configuration status"""
        return {
            'is_configured': self._is_configured,
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'username': self.username,
            'password_set': bool(self.password),
            'use_tls': self.use_tls,
            'use_ssl': self.use_ssl,
            'templates_available': len(self.template_manager.templates),
            'queue_processing': self.email_queue.is_processing
        }
    
    def _send_email_direct(self, to_email: str, subject: str, body: str,
                          html_body: Optional[str] = None,
                          attachments: Optional[List[str]] = None,
                          cc: Optional[List[str]] = None,
                          bcc: Optional[List[str]] = None,
                          from_email: Optional[str] = None,
                          **kwargs) -> bool:
        """Send email directly (synchronous) - FULLY FIXED"""
        
        try:
            # Check if email service is configured
            if not self._is_configured:
                logger.error("❌ Email service not configured - please set MAIL_USERNAME and MAIL_PASSWORD")
                return False
            
            logger.info(f"📧 Sending email to {to_email}: {subject}")
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = from_email or self.username
            msg['To'] = to_email
            msg['Subject'] = subject
            
            if cc:
                msg['Cc'] = ', '.join(cc)
            
            # Add body
            text_part = MIMEText(body, 'plain', 'utf-8')
            msg.attach(text_part)
            
            if html_body:
                html_part = MIMEText(html_body, 'html', 'utf-8')
                msg.attach(html_part)
            
            # Add attachments
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= {secure_filename(os.path.basename(file_path))}'
                            )
                            msg.attach(part)
            
            # Prepare recipient list
            recipients = [to_email]
            recipients.extend(cc or [])
            recipients.extend(bcc or [])
            
            # Send email with proper connection handling
            if self.use_ssl:
                logger.info("📧 Using SSL connection...")
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, context=context, timeout=30) as server:
                    if logger.level <= logging.DEBUG:
                        server.set_debuglevel(1)
                    logger.info("📧 SSL connection established, logging in...")
                    server.login(self.username, self.password)
                    logger.info("📧 SSL login successful, sending message...")
                    server.send_message(msg, to_addrs=recipients)
            else:
                logger.info("📧 Using SMTP connection...")
                with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                    if logger.level <= logging.DEBUG:
                        server.set_debuglevel(1)
                    logger.info("📧 SMTP connection established")
                    
                    if self.use_tls:
                        logger.info("📧 Starting TLS...")
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                        logger.info("📧 TLS started successfully")
                    
                    logger.info("📧 Logging in...")
                    server.login(self.username, self.password)
                    logger.info("📧 Login successful, sending message...")
                    server.send_message(msg, to_addrs=recipients)
            
            logger.info(f"✅ Email sent successfully to {to_email}: {subject}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"❌ SMTP Authentication failed: {str(e)} - Check email credentials")
            logger.error("💡 For Gmail, make sure you're using an App Password, not your regular password")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"❌ SMTP Connection failed: {str(e)} - Check server settings")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"❌ SMTP Recipients refused: {str(e)} - Check recipient email address")
            return False
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"❌ SMTP Server disconnected: {str(e)}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP Error: {str(e)}")
            return False
        except ssl.SSLError as e:
            logger.error(f"❌ SSL Error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"❌ Failed to send email to {to_email}: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            return False


# Global email sender instance
email_sender = EmailSender()


def init_email_sender(app):
    """Initialize email sender with Flask app"""
    global email_sender
    email_sender.init_app(app)
    return email_sender


# Convenience functions for backward compatibility
def send_email(to_email: str, subject: str, body: str, **kwargs) -> bool:
    """Send email using global email sender"""
    return email_sender.send_email(to_email, subject, body, **kwargs)


def send_verification_email(user_email: str, user_name: str, verification_token: str) -> bool:
    """Send verification email using global email sender"""
    return email_sender.send_verification_email(user_email, user_name, verification_token)


def send_password_reset_email(user_email: str, user_name: str, reset_token: str) -> bool:
    """Send password reset email using global email sender"""
    return email_sender.send_password_reset_email(user_email, user_name, reset_token)


def send_test_email(test_email: str) -> bool:
    """Send test email using global email sender"""
    return email_sender.send_test_email(test_email)


def validate_email_address(email: str) -> bool:
    """Validate email address using global email sender"""
    return email_sender.validate_email_address(email)


def get_queue_status() -> Dict[str, int]:
    """Get email queue status using global email sender"""
    return email_sender.get_queue_status()


def is_email_configured() -> bool:
    """Check if email is properly configured"""
    return email_sender.is_configured()


def get_email_configuration_status() -> Dict[str, Any]:
    """Get detailed email configuration status"""
    return email_sender.get_configuration_status()


# Test email functionality (for development/testing)
def test_email_functionality(test_email: str = None):
    """Test email functionality (for development/testing)"""
    try:
        if not test_email:
            logger.warning("No test email provided - skipping email test")
            return False
        
        logger.info(f"🧪 Testing email functionality with {test_email}")
        
        # Check configuration first
        config_status = get_email_configuration_status()
        logger.info(f"📊 Email configuration status: {config_status}")
        
        if not config_status['is_configured']:
            logger.error("❌ Email not configured - cannot run test")
            return False
        
        # Test basic email sending
        test_result = send_test_email(test_email)
        
        logger.info(f"📧 Test email result: {'✅ SUCCESS' if test_result else '❌ FAILED'}")
        
        # Test template rendering
        template_manager = email_sender.manage_templates()
        try:
            rendered = template_manager.render_template(
                'verification',
                user_name="Test User",
                verification_link="https://example.com/verify/token123"
            )
            logger.info("✅ Template rendering successful")
        except Exception as e:
            logger.error(f"❌ Template rendering failed: {e}")
        
        # Test email validation
        valid_emails = [
            "user@example.com",
            "test.email+tag@domain.co.uk", 
            "invalid-email",
            "@invalid.com",
            "valid@domain.org"
        ]
        
        logger.info("🔍 Testing email validation:")
        for email in valid_emails:
            is_valid = validate_email_address(email)
            logger.info(f"  {email}: {'✅ VALID' if is_valid else '❌ INVALID'}")
        
        return test_result
        
    except Exception as e:
        logger.error(f"❌ Email functionality test failed: {str(e)}")
        return False


def get_email_statistics() -> Dict[str, Any]:
    """Get email system statistics"""
    try:
        config_status = get_email_configuration_status()
        queue_status = email_sender.get_queue_status()
        tracking_count = len(email_sender.delivery_tracking)
        
        # Calculate success rate from tracking data
        successful_deliveries = sum(
            1 for data in email_sender.delivery_tracking.values() 
            if data['status'] == 'delivered'
        )
        
        success_rate = (successful_deliveries / tracking_count * 100) if tracking_count > 0 else 0
        
        stats = {
            'configuration': config_status,
            'queue_status': queue_status,
            'tracking_records': tracking_count,
            'successful_deliveries': successful_deliveries,
            'success_rate': round(success_rate, 2),
            'system_status': 'operational' if config_status['is_configured'] and queue_status['is_processing'] else 'degraded'
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get email statistics: {str(e)}")
        return {
            'error': str(e),
            'system_status': 'error'
        }


def cleanup_old_tracking_data():
    """Cleanup old email tracking data"""
    try:
        current_time = datetime.utcnow()
        cleanup_threshold = current_time - timedelta(days=7)  # Keep 7 days of data
        
        old_keys = []
        for email_id, tracking_data in email_sender.delivery_tracking.items():
            if tracking_data['timestamp'] < cleanup_threshold:
                old_keys.append(email_id)
        
        for key in old_keys:
            del email_sender.delivery_tracking[key]
        
        logger.info(f"Cleaned up {len(old_keys)} old email tracking records")
        return len(old_keys)
        
    except Exception as e:
        logger.error(f"Failed to cleanup email tracking data: {str(e)}")
        return 0


# Configuration validation
def validate_email_configuration(app_config=None):
    """Validate email configuration"""
    if app_config is None:
        # Use environment variables
        config_to_check = {
            'MAIL_SERVER': os.environ.get('MAIL_SERVER'),
            'MAIL_PORT': os.environ.get('MAIL_PORT'),
            'MAIL_USERNAME': os.environ.get('MAIL_USERNAME'),
            'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD')
        }
    else:
        config_to_check = {
            'MAIL_SERVER': app_config.get('MAIL_SERVER'),
            'MAIL_PORT': app_config.get('MAIL_PORT'),
            'MAIL_USERNAME': app_config.get('MAIL_USERNAME'),
            'MAIL_PASSWORD': app_config.get('MAIL_PASSWORD')
        }
    
    required_settings = ['MAIL_SERVER', 'MAIL_PORT', 'MAIL_USERNAME', 'MAIL_PASSWORD']
    missing_settings = []
    
    for setting in required_settings:
        if not config_to_check.get(setting):
            missing_settings.append(setting)
    
    if missing_settings:
        logger.warning(f"❌ Missing email configuration: {', '.join(missing_settings)}")
        return False, missing_settings
    
    logger.info("✅ Email configuration validation passed")
    return True, []


def configure_email_for_development():
    """Configure email settings for development environment"""
    development_config = {
        'MAIL_SERVER': 'smtp.gmail.com',
        'MAIL_PORT': 587,
        'MAIL_USE_TLS': True,
        'MAIL_USE_SSL': False,
        'MAIL_USERNAME': 'wisecxai@gmail.com',  # Your Gmail address
        'MAIL_PASSWORD': 'cvpm kfnc okpr rtrf',    # Your Gmail app password
    }
    
    logger.info("📧 Development email configuration:")
    for key, value in development_config.items():
        if 'PASSWORD' in key:
            logger.info(f"  {key}: {'SET' if value else 'NOT SET'}")
        else:
            logger.info(f"  {key}: {value}")
    
    return development_config


def setup_gmail_instructions():
    """Print Gmail setup instructions"""
    instructions = """
    📧 Gmail Setup Instructions:
    
    1. Enable 2-Factor Authentication on your Gmail account
    2. Go to your Google Account settings
    3. Security → 2-Step Verification → App passwords
    4. Generate an App Password for "Mail"
    5. Use your Gmail address as MAIL_USERNAME
    6. Use the generated App Password as MAIL_PASSWORD
    
    Environment Variables:
    MAIL_SERVER=smtp.gmail.com
    MAIL_PORT=587
    MAIL_USE_TLS=True
    MAIL_USERNAME=your-email@gmail.com
    MAIL_PASSWORD=your-app-password
    """
    
    print(instructions)
    logger.info("Gmail setup instructions displayed")


# Module initialization
if __name__ == "__main__":
    # Test the email functionality when run directly
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("🧪 Testing email functionality...")
    
    # Show Gmail setup instructions
    setup_gmail_instructions()
    
    # Show configuration template
    configure_email_for_development()
    
    # Test if configuration is valid using environment variables
    is_valid, missing = validate_email_configuration()
    if not is_valid:
        logger.warning(f"❌ Configuration invalid - missing: {missing}")
        logger.info("💡 Set the missing environment variables and try again")
    else:
        logger.info("✅ Configuration looks valid")
        
        # If a test email is provided as command line argument
        import sys
        if len(sys.argv) > 1:
            test_email_addr = sys.argv[1]
            logger.info(f"🧪 Running email test with {test_email_addr}")
            
            # Create a temporary app context for testing
            from flask import Flask
            temp_app = Flask(__name__)
            temp_app.config.update(configure_email_for_development())
            
            with temp_app.app_context():
                init_email_sender(temp_app)
                test_result = test_email_functionality(test_email_addr)
                logger.info(f"📧 Test result: {'✅ SUCCESS' if test_result else '❌ FAILED'}")
        else:
            logger.info("💡 To test email functionality, run: python email_sender.py your-email@gmail.com")