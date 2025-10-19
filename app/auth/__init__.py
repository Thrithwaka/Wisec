"""
Authentication Blueprint Initialization
Wi-Fi Security System - Flask Application

This module initializes the authentication blueprint for user registration,
login, email verification, and password reset functionality.

Key Components:
- Blueprint registration and configuration
- Authentication utilities import
- Route registration
- Error handling setup
"""

from flask import Blueprint

# Create authentication blueprint
auth = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth',
    template_folder='../templates/auth',
    static_folder='../static'
)
from app.auth import routes
from . import routes

# Import authentication utilities and classes
from app.auth.utils import (
    TokenGenerator,
    PasswordManager,
    EmailValidator
)

# Import authentication forms
from app.auth.forms import (
    RegistrationForm,
    LoginForm,
    EmailVerificationForm,
    ForgotPasswordForm,
    ResetPasswordForm
)

# Import authentication routes (must be imported after blueprint creation)
from app.auth import routes

# Authentication configuration
AUTH_CONFIG = {
    'TOKEN_EXPIRY': 3600,  # 1 hour in seconds
    'MAX_LOGIN_ATTEMPTS': 5,
    'RATE_LIMIT_WINDOW': 300,  # 5 minutes in seconds
    'PASSWORD_MIN_LENGTH': 8,
    'REQUIRE_EMAIL_VERIFICATION': True,
    'SESSION_TIMEOUT': 7200,  # 2 hours in seconds
}

# Initialize authentication components
def init_auth_components():
    """
    Initialize authentication components and utilities.
    
    This function sets up the core authentication utilities that will be
    used throughout the authentication module.
    
    Returns:
        dict: Dictionary containing initialized auth components
    """
    components = {
        'token_generator': TokenGenerator(),
        'password_manager': PasswordManager(),
        'email_validator': EmailValidator()
    }
    
    return components

# Authentication error handlers
@auth.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized access attempts."""
    from flask import render_template, request
    
    if request.is_json:
        return {'error': 'Unauthorized access', 'code': 401}, 401
    return render_template('errors/401.html'), 401

@auth.errorhandler(403)
def forbidden(error):
    """Handle forbidden access attempts."""
    from flask import render_template, request
    
    if request.is_json:
        return {'error': 'Forbidden access', 'code': 403}, 403
    return render_template('errors/403.html'), 403

# Authentication helper functions
def get_auth_config():
    """
    Get authentication configuration settings.
    
    Returns:
        dict: Authentication configuration dictionary
    """
    return AUTH_CONFIG.copy()

def is_authenticated(user):
    """
    Check if user is authenticated and verified.
    
    Args:
        user: User object to check
        
    Returns:
        bool: True if user is authenticated and verified
    """
    if not user:
        return False
    
    return user.is_authenticated and user.is_verified

def requires_admin_approval(user):
    """
    Check if user requires admin approval for advanced features.
    
    Args:
        user: User object to check
        
    Returns:
        bool: True if user needs admin approval
    """
    if not user:
        return True
    
    return not user.is_admin_approved

# Authentication logging setup
def setup_auth_logging():
    """
    Setup authentication-specific logging configuration.
    
    This function configures logging for authentication events,
    security incidents, and audit trails.
    """
    import logging
    from app.utils.decorators import log_activity
    
    # Create auth-specific logger
    auth_logger = logging.getLogger('auth')
    auth_logger.setLevel(logging.INFO)
    
    # Create file handler for auth logs
    if not auth_logger.handlers:
        from logging.handlers import RotatingFileHandler
        import os
        
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
        
        handler = RotatingFileHandler(
            'logs/auth.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        )
        handler.setFormatter(formatter)
        
        auth_logger.addHandler(handler)
    
    return auth_logger

# Initialize authentication logger
auth_logger = setup_auth_logging()

# Authentication event logging functions
def log_auth_event(event_type, user_email=None, ip_address=None, details=None):
    """
    Log authentication events for security monitoring.
    
    Args:
        event_type (str): Type of authentication event
        user_email (str, optional): User email involved
        ip_address (str, optional): IP address of the request
        details (dict, optional): Additional event details
    """
    log_message = f"AUTH_EVENT: {event_type}"
    
    if user_email:
        log_message += f" | User: {user_email}"
    
    if ip_address:
        log_message += f" | IP: {ip_address}"
    
    if details:
        log_message += f" | Details: {details}"
    
    auth_logger.info(log_message)

def log_security_incident(incident_type, user_email=None, ip_address=None, severity='MEDIUM'):
    """
    Log security incidents for immediate attention.
    
    Args:
        incident_type (str): Type of security incident
        user_email (str, optional): User email involved
        ip_address (str, optional): IP address of the request
        severity (str): Severity level (LOW, MEDIUM, HIGH, CRITICAL)
    """
    log_message = f"SECURITY_INCIDENT: {incident_type} | Severity: {severity}"
    
    if user_email:
        log_message += f" | User: {user_email}"
    
    if ip_address:
        log_message += f" | IP: {ip_address}"
    
    if severity in ['HIGH', 'CRITICAL']:
        auth_logger.error(log_message)
    else:
        auth_logger.warning(log_message)

# Authentication rate limiting setup
def setup_rate_limiting():
    """
    Setup rate limiting for authentication endpoints.
    
    This function configures rate limiting to prevent brute force attacks
    and other authentication-related abuse.
    """
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from flask import current_app
    
    # Rate limiting configuration
    RATE_LIMITS = {
        'login': '5 per minute',
        'register': '3 per minute',
        'password_reset': '2 per minute',
        'email_verification': '3 per minute'
    }
    
    return RATE_LIMITS

# Get rate limiting configuration
RATE_LIMITS = setup_rate_limiting()

# Authentication middleware functions
def before_auth_request():
    """
    Function to run before each authentication request.
    
    This function handles common authentication setup tasks
    like session validation and security checks.
    """
    from flask import request, session, current_app
    import time
    
    # Update session activity timestamp
    session.permanent = True
    session['last_activity'] = time.time()
    
    # Log authentication requests for monitoring
    log_auth_event(
        'REQUEST',
        user_email=session.get('user_email'),
        ip_address=request.remote_addr,
        details={'endpoint': request.endpoint, 'method': request.method}
    )

# Register before request handler
@auth.before_request
def auth_before_request():
    """Register before request handler for authentication blueprint."""
    before_auth_request()

# Authentication success/failure tracking
class AuthTracker:
    """
    Track authentication attempts and success/failure rates.
    
    This class provides methods to track authentication events
    for security monitoring and analytics.
    """
    
    @staticmethod
    def track_login_attempt(email, success=False, ip_address=None):
        """
        Track login attempts for security monitoring.
        
        Args:
            email (str): User email
            success (bool): Whether login was successful
            ip_address (str, optional): IP address of attempt
        """
        event_type = 'LOGIN_SUCCESS' if success else 'LOGIN_FAILURE'
        log_auth_event(event_type, email, ip_address)
        
        # Track failed attempts for potential security incidents
        if not success:
            AuthTracker._check_brute_force(email, ip_address)
    
    @staticmethod
    def track_registration(email, success=False, ip_address=None):
        """
        Track registration attempts.
        
        Args:
            email (str): User email
            success (bool): Whether registration was successful
            ip_address (str, optional): IP address of attempt
        """
        event_type = 'REGISTRATION_SUCCESS' if success else 'REGISTRATION_FAILURE'
        log_auth_event(event_type, email, ip_address)
    
    @staticmethod
    def track_password_reset(email, success=False, ip_address=None):
        """
        Track password reset attempts.
        
        Args:
            email (str): User email
            success (bool): Whether reset was successful
            ip_address (str, optional): IP address of attempt
        """
        event_type = 'PASSWORD_RESET_SUCCESS' if success else 'PASSWORD_RESET_FAILURE'
        log_auth_event(event_type, email, ip_address)
    
    @staticmethod
    def _check_brute_force(email, ip_address):
        """
        Check for potential brute force attacks.
        
        Args:
            email (str): User email
            ip_address (str): IP address of attempt
        """
        # This would integrate with a more sophisticated tracking system
        # For now, just log as a security incident
        log_security_incident(
            'POTENTIAL_BRUTE_FORCE',
            email,
            ip_address,
            'MEDIUM'
        )

# Export authentication components and utilities
__all__ = [
    'auth',
    'AUTH_CONFIG',
    'init_auth_components',
    'get_auth_config',
    'is_authenticated',
    'requires_admin_approval',
    'log_auth_event',
    'log_security_incident',
    'AuthTracker',
    'RATE_LIMITS'
]