"""
Authentication Utilities - FIXED VERSION
Purpose: Authentication helper functions for Wi-Fi Security System
Integrated with email_sender.py for proper email functionality
"""

import secrets
import hashlib
import time
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app, request, session


class TokenGenerator:
    """Token generation and validation utilities"""
    
    def __init__(self):
        pass
    
    def generate_verification_token(self, email: str) -> str:
        """
        Generate email verification token
        
        Args:
            email (str): User email address
            
        Returns:
            str: Verification token
        """
        try:
            # Create a simple token using timestamp and email hash
            timestamp = str(int(time.time()))
            email_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
            random_part = secrets.token_urlsafe(16)
            
            token = f"{timestamp}-{email_hash}-{random_part}"
            return token
            
        except Exception as e:
            current_app.logger.error(f"Token generation error: {str(e)}")
            return None
    
    def generate_password_reset_token(self, email: str) -> str:
        """
        Generate password reset token
        
        Args:
            email (str): User email address
            
        Returns:
            str: Password reset token
        """
        try:
            # Similar to verification token but with different prefix
            timestamp = str(int(time.time()))
            email_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
            random_part = secrets.token_urlsafe(16)
            
            token = f"reset-{timestamp}-{email_hash}-{random_part}"
            return token
            
        except Exception as e:
            current_app.logger.error(f"Password reset token generation error: {str(e)}")
            return None
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure token
        
        Args:
            length (int): Token length in bytes
            
        Returns:
            str: URL-safe token
        """
        return secrets.token_urlsafe(length)
    
    def validate_token(self, token: str, token_type: str = None, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        """
        Validate token
        
        Args:
            token (str): Token to validate
            token_type (str): Expected token type
            max_age_hours (int): Maximum age in hours
            
        Returns:
            dict: Token payload if valid, None if invalid
        """
        try:
            # Parse the token
            parts = token.split('-')
            if len(parts) < 3:
                current_app.logger.warning("Invalid token format")
                return None
            
            # Check if it's a reset token
            if token_type == 'password_reset' and not token.startswith('reset-'):
                current_app.logger.warning("Token type mismatch")
                return None
            
            # Extract timestamp
            timestamp_str = parts[1] if token.startswith('reset-') else parts[0]
            try:
                token_timestamp = int(timestamp_str)
            except ValueError:
                current_app.logger.warning("Invalid token timestamp")
                return None
            
            # Check if token is expired
            current_timestamp = int(time.time())
            max_age_seconds = max_age_hours * 3600
            
            if current_timestamp - token_timestamp > max_age_seconds:
                current_app.logger.warning("Token has expired")
                return None
            
            return {
                'timestamp': token_timestamp,
                'valid': True,
                'type': token_type or 'verification'
            }
            
        except Exception as e:
            current_app.logger.error(f"Token validation error: {str(e)}")
            return None


class PasswordManager:
    """Password hashing and validation utilities"""
    
    def __init__(self):
        pass
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using werkzeug
        
        Args:
            password (str): Plain text password
            
        Returns:
            str: Hashed password
        """
        try:
            return generate_password_hash(password)
        except Exception as e:
            current_app.logger.error(f"Password hashing error: {str(e)}")
            raise
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password (str): Plain text password
            hashed_password (str): Stored password hash
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            return check_password_hash(hashed_password, password)
        except Exception as e:
            current_app.logger.error(f"Password verification error: {str(e)}")
            return False
    
    def validate_password_strength(self, password: str) -> bool:
        """
        Validate password strength
        
        Args:
            password (str): Password to validate
            
        Returns:
            bool: True if password meets requirements
        """
        min_length = current_app.config.get('PASSWORD_MIN_LENGTH', 8) if current_app else 8
        
        # Length check
        if len(password) < min_length:
            return False
        
        # Uppercase letter check
        if not re.search(r'[A-Z]', password):
            return False
        
        # Lowercase letter check
        if not re.search(r'[a-z]', password):
            return False
        
        # Digit check
        if not re.search(r'\d', password):
            return False
        
        # Special character check
        if not re.search(r'[@$!%*?&]', password):
            return False
        
        # Common password check
        common_passwords = ['password', '123456', 'password123', 'admin', 'letmein']
        if password.lower() in common_passwords:
            return False
        
        return True


class EmailValidator:
    """Email validation utilities - FIXED to work with email_sender.py"""
    
    def __init__(self):
        pass
    
    def validate_email_format(self, email: str) -> bool:
        """
        Validate email format using the same logic as email_sender.py
        
        Args:
            email (str): Email address to validate
            
        Returns:
            bool: True if valid email format
        """
        try:
            # Use the same validation logic as EmailValidator in email_sender.py
            from ..utils.email_sender import EmailValidator as EmailSenderValidator
            return EmailSenderValidator.validate_email_format(email)
        except ImportError:
            # Fallback to local validation if import fails
            return self._local_email_validation(email)
    
    def _local_email_validation(self, email: str) -> bool:
        """
        Local email validation as fallback
        
        Args:
            email (str): Email address to validate
            
        Returns:
            bool: True if valid email format
        """
        try:
            # Basic email regex pattern
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            if not re.match(email_pattern, email):
                return False
            
            # Check domain restrictions if configured
            if current_app:
                allowed_domains = current_app.config.get('ALLOWED_EMAIL_DOMAINS', [])
                blocked_domains = current_app.config.get('BLOCKED_EMAIL_DOMAINS', [])
                
                domain = email.split('@')[1].lower()
                
                # Check if domain is blocked
                if blocked_domains and domain in blocked_domains:
                    return False
                
                # Check if domain is in allowed list (if specified)
                if allowed_domains and domain not in allowed_domains:
                    return False
            
            return True
            
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Email validation error: {str(e)}")
            return False
    
    def is_disposable_email(self, email: str) -> bool:
        """
        Check if email is from a disposable email provider
        
        Args:
            email (str): Email address to check
            
        Returns:
            bool: True if disposable, False otherwise
        """
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'temp-mail.org',
            'throwaway.email', 'fakeinbox.com'
        ]
        
        try:
            domain = email.split('@')[1].lower()
            return domain in disposable_domains
        except:
            return False


class RateLimiter:
    """Rate limiting for authentication attempts"""
    
    def __init__(self):
        # Simple in-memory storage for development
        self._attempts = {}
        max_attempts = 5
        lockout_duration = 15
        
        if current_app:
            max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
            lockout_duration = current_app.config.get('LOCKOUT_DURATION_MINUTES', 15)
        
        self._max_attempts = max_attempts
        self._lockout_duration = lockout_duration
    
    def check_rate_limit(self, identifier: str, attempt_type: str = 'login') -> Tuple[bool, int]:
        """
        Check if request is within rate limits
        
        Args:
            identifier (str): IP address or user identifier
            attempt_type (str): Type of attempt (login, register, etc.)
            
        Returns:
            tuple: (is_allowed, remaining_attempts)
        """
        key = f"{attempt_type}:{identifier}"
        current_time = time.time()
        
        try:
            # Clean old attempts
            if key in self._attempts:
                self._attempts[key] = [
                    timestamp for timestamp in self._attempts[key]
                    if current_time - timestamp < self._lockout_duration * 60
                ]
            
            # Check current attempts count
            current_attempts = len(self._attempts.get(key, []))
            
            if current_attempts >= self._max_attempts:
                return False, 0
            
            return True, self._max_attempts - current_attempts
            
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Rate limit check error: {str(e)}")
            return True, self._max_attempts  # Allow on error
    
    def record_attempt(self, identifier: str, attempt_type: str = 'login', success: bool = False):
        """
        Record authentication attempt
        
        Args:
            identifier (str): IP address or user identifier
            attempt_type (str): Type of attempt
            success (bool): Whether attempt was successful
        """
        key = f"{attempt_type}:{identifier}"
        current_time = time.time()
        
        try:
            if success:
                # Clear rate limit on successful attempt
                self._attempts.pop(key, None)
            else:
                # Record failed attempt
                if key not in self._attempts:
                    self._attempts[key] = []
                self._attempts[key].append(current_time)
                
        except Exception as e:
            if current_app:
                current_app.logger.error(f"Rate limit recording error: {str(e)}")


# Utility functions - FIXED to work with email_sender.py

def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure token
    
    Args:
        length (int): Token length in bytes
        
    Returns:
        str: URL-safe token
    """
    return secrets.token_urlsafe(length)


def generate_verification_token(email: str) -> str:
    """
    Generate email verification token (wrapper function)
    
    Args:
        email (str): User email
        
    Returns:
        str: Verification token
    """
    generator = TokenGenerator()
    return generator.generate_verification_token(email)


def validate_token(token: str, token_type: str = None) -> Optional[Dict[str, Any]]:
    """
    Validate token (wrapper function)
    
    Args:
        token (str): Token to validate
        token_type (str): Expected token type
        
    Returns:
        dict: Token payload if valid
    """
    generator = TokenGenerator()
    return generator.validate_token(token, token_type)


def hash_password(password: str) -> str:
    """
    Hash password (wrapper function)
    
    Args:
        password (str): Plain text password
        
    Returns:
        str: Hashed password
    """
    manager = PasswordManager()
    return manager.hash_password(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify password (wrapper function)
    
    Args:
        password (str): Plain text password
        hashed_password (str): Stored hash
        
    Returns:
        bool: True if password matches
    """
    manager = PasswordManager()
    return manager.verify_password(password, hashed_password)


def check_rate_limit(identifier: str = None, attempt_type: str = 'login') -> Tuple[bool, int]:
    """
    Check rate limit (wrapper function)
    
    Args:
        identifier (str): Identifier (defaults to IP address)
        attempt_type (str): Attempt type
        
    Returns:
        tuple: (is_allowed, remaining_attempts)
    """
    if identifier is None:
        identifier = get_client_ip()
    
    limiter = RateLimiter()
    return limiter.check_rate_limit(identifier, attempt_type)


def get_client_ip() -> str:
    """
    Get client IP address
    
    Returns:
        str: Client IP address
    """
    # Check for forwarded headers (behind proxy/load balancer)
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '127.0.0.1'


def create_session_data(user_data) -> Dict[str, Any]:
    """
    Create session data for authenticated user
    
    Args:
        user_data: User data dictionary
        
    Returns:
        dict: Session data
    """
    return {
        'user_email': user_data.get('email'),
        'user_id': user_data.get('id'),
        'role': user_data.get('role', 'user'),
        'is_admin_approved': user_data.get('is_admin_approved', False),
        'login_timestamp': datetime.utcnow().isoformat(),
        'session_token': generate_secure_token(16)
    }


def validate_session_token(session_token: str, user_id: str = None) -> bool:
    """
    Validate session token
    
    Args:
        session_token (str): Session token
        user_id (str): User ID
        
    Returns:
        bool: True if valid
    """
    # Basic validation - in production, this would check against stored tokens
    if not session_token or len(session_token) < 16:
        return False
    
    return True


def generate_csrf_token() -> str:
    """
    Generate CSRF token for forms
    
    Returns:
        str: CSRF token
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_secure_token(16)
    return session['csrf_token']


def validate_csrf_token(token: str) -> bool:
    """
    Validate CSRF token
    
    Args:
        token (str): CSRF token to validate
        
    Returns:
        bool: True if valid
    """
    return token and session.get('csrf_token') == token


def log_security_event(event_type: str, details: Dict[str, Any], user_id: str = None):
    """
    Log security-related events
    
    Args:
        event_type (str): Type of security event
        details (dict): Event details
        user_id (str): User ID if applicable
    """
    try:
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'details': details,
            'user_id': user_id,
            'ip_address': get_client_ip(),
            'user_agent': request.headers.get('User-Agent', 'Unknown')
        }
        
        if current_app:
            current_app.logger.info(f"Security Event: {log_data}")
        
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Security logging error: {str(e)}")


def sanitize_input(data: str) -> str:
    """
    General input sanitization function
    
    Args:
        data (str): Input data to sanitize
        
    Returns:
        str: Sanitized data
    """
    if not data:
        return ""
    
    # Remove leading/trailing whitespace
    data = data.strip()
    
    # Remove null bytes
    data = data.replace('\x00', '')
    
    # Remove or escape potentially dangerous characters for basic XSS prevention
    dangerous_chars = ['<script', '</script', 'javascript:', 'onload=', 'onerror=']
    for char in dangerous_chars:
        data = data.replace(char, '')
    
    return data


def validate_password_strength_detailed(password: str) -> Tuple[bool, str, int]:
    """
    Comprehensive password strength validation
    Returns: (is_valid: bool, error_message: str, strength_score: int)
    """
    if not password:
        return False, "Password is required", 0
    
    score = 0
    errors = []
    
    # Length check
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    elif len(password) >= 8:
        score += 1
    
    if len(password) >= 12:
        score += 1
    
    # Character variety checks
    if re.search(r'[a-z]', password):
        score += 1
    else:
        errors.append("Password must contain lowercase letters")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        errors.append("Password must contain uppercase letters")
    
    if re.search(r'\d', password):
        score += 1
    else:
        errors.append("Password must contain numbers")
    
    if re.search(r'[@$!%*?&]', password):
        score += 1
    else:
        errors.append("Password must contain special characters (@$!%*?&)")
    
    # Common password check
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey'
    ]
    
    if password.lower() in common_passwords:
        errors.append("Password is too common")
        score = max(0, score - 2)
    
    # Sequential characters check
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
        errors.append("Password should not contain sequential characters")
        score = max(0, score - 1)
    
    if errors:
        return False, "; ".join(errors), score
    
    return True, "", score


def validate_email_format(email: str) -> bool:
    """
    Validate email format using EmailValidator
    
    Args:
        email (str): Email to validate
        
    Returns:
        bool: True if valid
    """
    validator = EmailValidator()
    return validator.validate_email_format(email)


def send_verification_email_helper(user_email: str, user_name: str, verification_token: str) -> bool:
    """
    Helper function to send verification email using global email_sender
    
    Args:
        user_email (str): User's email address
        user_name (str): User's name
        verification_token (str): Verification token
        
    Returns:
        bool: True if email sent successfully
    """
    try:
        from ..utils.email_sender import email_sender
        return email_sender.send_verification_email(user_email, user_name, verification_token)
    except ImportError as e:
        if current_app:
            current_app.logger.error(f"Failed to import email_sender: {str(e)}")
        return False
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to send verification email: {str(e)}")
        return False


def send_password_reset_email_helper(user_email: str, user_name: str, reset_token: str) -> bool:
    """
    Helper function to send password reset email using global email_sender
    
    Args:
        user_email (str): User's email address
        user_name (str): User's name
        reset_token (str): Password reset token
        
    Returns:
        bool: True if email sent successfully
    """
    try:
        from ..utils.email_sender import email_sender
        return email_sender.send_password_reset_email(user_email, user_name, reset_token)
    except ImportError as e:
        if current_app:
            current_app.logger.error(f"Failed to import email_sender: {str(e)}")
        return False
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Failed to send password reset email: {str(e)}")
        return False


def check_email_configuration() -> bool:
    """
    Check if email is properly configured
    
    Returns:
        bool: True if email is configured
    """
    try:
        from ..utils.email_sender import email_sender
        return email_sender.is_configured()
    except ImportError:
        if current_app:
            current_app.logger.warning("email_sender module not available")
        return False
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Error checking email configuration: {str(e)}")
        return False


def get_email_configuration_status() -> Dict[str, Any]:
    """
    Get detailed email configuration status
    
    Returns:
        dict: Configuration status details
    """
    try:
        from ..utils.email_sender import email_sender
        return email_sender.get_configuration_status()
    except ImportError:
        return {
            'is_configured': False,
            'error': 'email_sender module not available'
        }
    except Exception as e:
        return {
            'is_configured': False,
            'error': str(e)
        }


# Authentication workflow helpers

def complete_user_registration_workflow(user, send_verification=True):
    """
    Complete user registration workflow including email verification
    
    Args:
        user: User object
        send_verification (bool): Whether to send verification email
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        if not send_verification:
            return True, "User registered successfully"
        
        # Check if email service is configured
        if not check_email_configuration():
            if current_app:
                current_app.logger.warning("Email service not configured - skipping verification email")
            return True, "User registered successfully (email verification disabled)"
        
        # Get user profile data for personalization
        profile_data = user.get_profile_data()
        user_name = profile_data.get('first_name', user.email.split('@')[0])
        
        # Send verification email
        if send_verification_email_helper(user.email, user_name, user.verification_token):
            return True, "Registration successful! Please check your email to verify your account."
        else:
            return False, "Registration successful, but verification email failed to send."
            
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Registration workflow error: {str(e)}")
        return False, "An error occurred during registration."


def complete_password_reset_workflow(user):
    """
    Complete password reset workflow including email sending
    
    Args:
        user: User object
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Check if email service is configured
        if not check_email_configuration():
            if current_app:
                current_app.logger.warning("Email service not configured - cannot send reset email")
            return False, "Password reset service is currently unavailable."
        
        # Generate reset token
        reset_token = user.generate_reset_token()
        if not reset_token:
            return False, "Failed to generate reset token."
        
        user.save()
        
        # Get user profile data for personalization
        profile_data = user.get_profile_data()
        user_name = profile_data.get('first_name', user.email.split('@')[0])
        
        # Send password reset email
        if send_password_reset_email_helper(user.email, user_name, reset_token):
            return True, "Password reset instructions sent to your email."
        else:
            return False, "Failed to send password reset email."
            
    except Exception as e:
        if current_app:
            current_app.logger.error(f"Password reset workflow error: {str(e)}")
        return False, "An error occurred during password reset."


# Security utilities

def generate_secure_password(length: int = 12) -> str:
    """
    Generate a secure password
    
    Args:
        length (int): Password length
        
    Returns:
        str: Generated secure password
    """
    import string
    
    # Ensure minimum requirements
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "@$!%*?&"
    
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Verify it meets strength requirements
        manager = PasswordManager()
        if manager.validate_password_strength(password):
            return password


def mask_email(email: str) -> str:
    """
    Mask email address for logging/display
    
    Args:
        email (str): Email to mask
        
    Returns:
        str: Masked email
    """
    try:
        if '@' not in email:
            return email[:2] + '*' * (len(email) - 2)
        
        local, domain = email.split('@', 1)
        
        if len(local) <= 2:
            masked_local = local[0] + '*' * (len(local) - 1)
        else:
            masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
        
        return f"{masked_local}@{domain}"
    except:
        return "***@***.***"


def get_password_strength_score(password: str) -> int:
    """
    Get password strength score (0-5)
    
    Args:
        password (str): Password to score
        
    Returns:
        int: Strength score
    """
    _, _, score = validate_password_strength_detailed(password)
    return min(score, 5)  # Cap at 5


def is_password_commonly_used(password: str) -> bool:
    """
    Check if password is commonly used
    
    Args:
        password (str): Password to check
        
    Returns:
        bool: True if commonly used
    """
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        '1234567890', 'password1', 'iloveyou', '123456789',
        'welcome123', 'admin123', 'root', 'toor', 'pass'
    ]
    
    return password.lower() in common_passwords


# Input validation helpers

def validate_name(name: str) -> bool:
    """
    Validate name field
    
    Args:
        name (str): Name to validate
        
    Returns:
        bool: True if valid
    """
    if not name or not name.strip():
        return False
    
    # Check length
    if len(name.strip()) < 1 or len(name.strip()) > 50:
        return False
    
    # Check for valid characters (letters, spaces, hyphens, apostrophes)
    if not re.match(r"^[a-zA-Z\s\-']+$", name.strip()):
        return False
    
    return True


def validate_organization(organization: str) -> bool:
    """
    Validate organization field
    
    Args:
        organization (str): Organization to validate
        
    Returns:
        bool: True if valid
    """
    if not organization:
        return True  # Organization is optional
    
    # Check length
    if len(organization.strip()) > 100:
        return False
    
    # Check for reasonable characters
    if not re.match(r"^[a-zA-Z0-9\s\-_.&,()]+$", organization.strip()):
        return False
    
    return True


def clean_and_validate_input(data: Dict[str, str]) -> Dict[str, Any]:
    """
    Clean and validate input data
    
    Args:
        data (dict): Input data to validate
        
    Returns:
        dict: Validation results
    """
    results = {
        'valid': True,
        'errors': [],
        'cleaned_data': {}
    }
    
    for field, value in data.items():
        if isinstance(value, str):
            cleaned_value = sanitize_input(value)
            results['cleaned_data'][field] = cleaned_value
            
            # Field-specific validation
            if field == 'email':
                if not validate_email_format(cleaned_value):
                    results['valid'] = False
                    results['errors'].append(f"Invalid email format: {field}")
            
            elif field in ['first_name', 'last_name']:
                if not validate_name(cleaned_value):
                    results['valid'] = False
                    results['errors'].append(f"Invalid name format: {field}")
            
            elif field == 'organization':
                if not validate_organization(cleaned_value):
                    results['valid'] = False
                    results['errors'].append(f"Invalid organization format: {field}")
            
            elif field == 'password':
                manager = PasswordManager()
                if not manager.validate_password_strength(cleaned_value):
                    results['valid'] = False
                    results['errors'].append("Password does not meet security requirements")
        else:
            results['cleaned_data'][field] = value
    
    return results