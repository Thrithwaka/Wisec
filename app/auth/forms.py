"""
Wi-Fi Security System - Authentication Forms
File: app/auth/forms.py
Purpose: WTForms for user input validation in authentication system
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo, ValidationError, Regexp
)
import re


class RegistrationForm(FlaskForm):
    """User registration form with comprehensive validation"""
    
    email = StringField(
        'Email Address', 
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address'),
            Length(min=6, max=120, message='Email must be between 6 and 120 characters')
        ],
        render_kw={
            'placeholder': 'Enter your email address',
            'class': 'form-control',
            'autocomplete': 'email'
        }
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, max=128, message='Password must be between 8 and 128 characters'),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character'
            )
        ],
        render_kw={
            'placeholder': 'Enter a strong password',
            'class': 'form-control',
            'autocomplete': 'new-password'
        }
    )
    
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={
            'placeholder': 'Confirm your password',
            'class': 'form-control',
            'autocomplete': 'new-password'
        }
    )
    
    first_name = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(min=2, max=50, message='First name must be between 2 and 50 characters'),
            Regexp(r'^[A-Za-z\s\-\']+$', message='First name can only contain letters, spaces, hyphens, and apostrophes')
        ],
        render_kw={
            'placeholder': 'Enter your first name',
            'class': 'form-control',
            'autocomplete': 'given-name'
        }
    )
    
    last_name = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(min=2, max=50, message='Last name must be between 2 and 50 characters'),
            Regexp(r'^[A-Za-z\s\-\']+$', message='Last name can only contain letters, spaces, hyphens, and apostrophes')
        ],
        render_kw={
            'placeholder': 'Enter your last name',
            'class': 'form-control',
            'autocomplete': 'family-name'
        }
    )
    
    organization = StringField(
        'Organization (Optional)',
        validators=[
            Length(max=100, message='Organization name cannot exceed 100 characters')
        ],
        render_kw={
            'placeholder': 'Enter your organization',
            'class': 'form-control',
            'autocomplete': 'organization'
        }
    )
    
    purpose = TextAreaField(
        'Purpose of Use',
        validators=[
            DataRequired(message='Please describe your intended use'),
            Length(min=20, max=500, message='Purpose description must be between 20 and 500 characters')
        ],
        render_kw={
            'placeholder': 'Describe your intended use of the Wi-Fi security system (minimum 20 characters)',
            'class': 'form-control',
            'rows': 4
        }
    )
    
    terms_accepted = BooleanField(
        'I agree to the Terms of Service and Privacy Policy',
        validators=[
            DataRequired(message='You must accept the terms and conditions')
        ],
        render_kw={'class': 'form-check-input'}
    )
    
    submit = SubmitField(
        'Register Account',
        render_kw={'class': 'btn btn-primary btn-lg w-100'}
    )
    
    def validate_email(self, field):
        """Custom email validation to check uniqueness"""
        # Import here to avoid circular imports
        try:
            from app.models.user import User
            if User.query.filter_by(email=field.data.lower()).first():
                raise ValidationError('This email address is already registered. Please use a different email or try logging in.')
        except ImportError:
            # If User model is not available, skip this validation
            pass
    
    def validate_password(self, field):
        """Enhanced password strength validation"""
        password = field.data
        
        # Check for common passwords
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ]
        
        if password.lower() in common_passwords:
            raise ValidationError('Please choose a less common password')
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            raise ValidationError('Password should not contain sequential characters')
    
    def sanitize_input(self):
        """Sanitize all form inputs"""
        if self.email.data:
            self.email.data = self.email.data.strip().lower()
        if self.first_name.data:
            self.first_name.data = self.first_name.data.strip().title()
        if self.last_name.data:
            self.last_name.data = self.last_name.data.strip().title()
        if self.organization.data:
            self.organization.data = self.organization.data.strip()
        if self.purpose.data:
            self.purpose.data = self.purpose.data.strip()


class LoginForm(FlaskForm):
    """User login form with security features"""
    
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ],
        render_kw={
            'placeholder': 'Enter your email address',
            'class': 'form-control',
            'autocomplete': 'email'
        }
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required')
        ],
        render_kw={
            'placeholder': 'Enter your password',
            'class': 'form-control',
            'autocomplete': 'current-password'
        }
    )
    
    remember_me = BooleanField(
        'Remember me for 30 days',
        render_kw={'class': 'form-check-input'}
    )
    
    submit = SubmitField(
        'Sign In',
        render_kw={'class': 'btn btn-primary btn-lg w-100'}
    )
    
    def sanitize_input(self):
        """Sanitize login inputs"""
        if self.email.data:
            self.email.data = self.email.data.strip().lower()


class EmailVerificationForm(FlaskForm):
    """Email verification form for manual token entry"""
    
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ],
        render_kw={
            'placeholder': 'Enter your email address',
            'class': 'form-control',
            'autocomplete': 'email'
        }
    )
    
    verification_code = StringField(
        'Verification Code',
        validators=[
            Length(min=6, max=6, message='Verification code must be exactly 6 characters'),
            Regexp(r'^[A-Z0-9]{6}$', message='Verification code must contain only uppercase letters and numbers')
        ],
        render_kw={
            'placeholder': 'Enter 6-digit verification code (optional)',
            'class': 'form-control text-center',
            'style': 'letter-spacing: 0.5em; font-size: 1.2em;',
            'maxlength': '6',
            'autocomplete': 'one-time-code'
        }
    )
    
    submit = SubmitField(
        'Resend Verification Email',
        render_kw={'class': 'btn btn-primary btn-lg w-100'}
    )
    
    def sanitize_input(self):
        """Sanitize verification inputs"""
        if self.email.data:
            self.email.data = self.email.data.strip().lower()
        if self.verification_code.data:
            self.verification_code.data = self.verification_code.data.strip().upper()


class ForgotPasswordForm(FlaskForm):
    """Password reset request form"""
    
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ],
        render_kw={
            'placeholder': 'Enter your registered email address',
            'class': 'form-control',
            'autocomplete': 'email'
        }
    )
    
    submit = SubmitField(
        'Send Reset Link',
        render_kw={'class': 'btn btn-warning btn-lg w-100'}
    )
    
    def sanitize_input(self):
        """Sanitize email input"""
        if self.email.data:
            self.email.data = self.email.data.strip().lower()


class ResetPasswordForm(FlaskForm):
    """Password reset form with new password"""
    
    password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='New password is required'),
            Length(min=8, max=128, message='Password must be between 8 and 128 characters'),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character'
            )
        ],
        render_kw={
            'placeholder': 'Enter your new password',
            'class': 'form-control',
            'autocomplete': 'new-password'
        }
    )
    
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Please confirm your new password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={
            'placeholder': 'Confirm your new password',
            'class': 'form-control',
            'autocomplete': 'new-password'
        }
    )
    
    submit = SubmitField(
        'Reset Password',
        render_kw={'class': 'btn btn-success btn-lg w-100'}
    )
    
    def validate_password(self, field):
        """Enhanced password strength validation for reset"""
        password = field.data
        
        # Check for common passwords
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ]
        
        if password.lower() in common_passwords:
            raise ValidationError('Please choose a less common password')
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            raise ValidationError('Password should not contain sequential characters')


class ResendVerificationForm(FlaskForm):
    """Form to resend email verification"""
    
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ],
        render_kw={
            'placeholder': 'Enter your email address',
            'class': 'form-control',
            'autocomplete': 'email'
        }
    )
    
    submit = SubmitField(
        'Resend Verification Email',
        render_kw={'class': 'btn btn-info btn-lg w-100'}
    )
    
    def sanitize_input(self):
        """Sanitize email input"""
        if self.email.data:
            self.email.data = self.email.data.strip().lower()


class ChangePasswordForm(FlaskForm):
    """Form for authenticated users to change password"""
    
    current_password = PasswordField(
        'Current Password',
        validators=[
            DataRequired(message='Current password is required')
        ],
        render_kw={
            'placeholder': 'Enter your current password',
            'class': 'form-control',
            'autocomplete': 'current-password'
        }
    )
    
    new_password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='New password is required'),
            Length(min=8, max=128, message='Password must be between 8 and 128 characters'),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character'
            )
        ],
        render_kw={
            'placeholder': 'Enter your new password',
            'class': 'form-control',
            'autocomplete': 'new-password'
        }
    )
    
    confirm_new_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Please confirm your new password'),
            EqualTo('new_password', message='Passwords must match')
        ],
        render_kw={
            'placeholder': 'Confirm your new password',
            'class': 'form-control',
            'autocomplete': 'new-password'
        }
    )
    
    submit = SubmitField(
        'Change Password',
        render_kw={'class': 'btn btn-primary btn-lg w-100'}
    )
    
    def validate_new_password(self, field):
        """Validate new password strength"""
        password = field.data
        
        # Check for common passwords
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        ]
        
        if password.lower() in common_passwords:
            raise ValidationError('Please choose a less common password')
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            raise ValidationError('Password should not contain sequential characters')


# Utility functions for form validation
def validate_email_format(email):
    """
    Enhanced email format validation
    Returns: (is_valid: bool, error_message: str)
    """
    if not email:
        return False, "Email is required"
    
    # Basic format check
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'\.{2,}',  # Multiple consecutive dots
        r'^\.|\.$',  # Starting or ending with dot
        r'@.*@',  # Multiple @ symbols
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, email):
            return False, "Invalid email format"
    
    return True, ""


def validate_password_strength(password):
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


def sanitize_input_data(data):
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
    
    # Remove or escape potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&']
    for char in dangerous_chars:
        data = data.replace(char, '')
    
    return data


def validate_unique_email(email):
    """
    Check if email is unique in the database
    Args:
        email (str): Email to check
    Returns:
        bool: True if unique, False if already exists
    """
    try:
        from app.models.user import User
        existing_user = User.query.filter_by(email=email.lower()).first()
        return existing_user is None
    except ImportError:
        # If User model is not available, assume unique
        return True