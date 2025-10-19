"""
Wi-Fi Security System - Authentication Routes - FIXED VERSION
Purpose: Handle user registration, login, email verification, and password management

FIXES:
- Fixed email integration with email_sender.py
- Removed duplicate EmailSender initialization
- Fixed email verification handler to use global email_sender
- Improved error handling and logging
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
import secrets
import re
from functools import wraps

# Import forms and utilities
from .forms import RegistrationForm, LoginForm, EmailVerificationForm, ForgotPasswordForm, ResetPasswordForm
from .utils import TokenGenerator, PasswordManager, EmailValidator
from ..models.user import User
from ..models.audit_logs import AuditLog
from ..utils.validators import InputValidator
from ..utils.decorators import rate_limit, log_activity

# Import the global email sender from email_sender.py
from ..utils.email_sender import email_sender

# Create authentication blueprint
from app.auth import auth

class AuthenticationManager:
    """Main authentication management class"""
    
    def __init__(self):
        self.token_generator = TokenGenerator()
        self.password_manager = PasswordManager()
        self.email_validator = EmailValidator()
        self.input_validator = InputValidator()
        
    def create_user_session(self, user):
        """Create secure user session"""
        try:
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['is_admin'] = user.is_admin()  # Use actual admin role check
            session['login_time'] = datetime.utcnow().isoformat()
            session.permanent = True
            
            # Update user last login
            user.last_login = datetime.utcnow()
            user.save()
            
            return True
        except Exception as e:
            current_app.logger.error(f"Session creation failed: {str(e)}")
            return False
    
    def validate_user_input(self, form_data):
        """Validate user input data"""
        errors = []
        
        # Email validation
        if 'email' in form_data:
            if not self.email_validator.validate_email_format(form_data['email']):
                errors.append("Invalid email format")
        
        # Password validation
        if 'password' in form_data:
            if not self.password_manager.validate_password_strength(form_data['password']):
                errors.append("Password does not meet security requirements")
        
        return errors


# MODIFICATION 1: Update the EmailVerificationHandler class in routes.py

class EmailVerificationHandler:
    """Email verification logic handler - COMPLETELY FIXED"""
    
    def __init__(self):
        self.token_generator = TokenGenerator()
    
    def send_verification_email(self, user):
        """Send email verification to user - FIXED VERSION"""
        try:
            current_app.logger.info(f"🔄 Starting verification email process for {user.email}")
            
            # Generate verification token if not exists
            if not user.verification_token:
                user.generate_verification_token()
                user.save()
                current_app.logger.info(f"✅ Generated verification token for {user.email}")
            
            # Get user's first name for personalization
            profile_data = user.get_profile_data()
            user_name = profile_data.get('first_name', user.email.split('@')[0])
            
            # CRITICAL FIX: Use the global email_sender instead of current_app.email_sender
            from ..utils.email_sender import email_sender
            
            # Check if email sender is configured
            if not email_sender.is_configured():
                current_app.logger.error("❌ Email sender not configured properly")
                config_status = email_sender.get_configuration_status()
                current_app.logger.error(f"Config status: {config_status}")
                return False
            
            current_app.logger.info(f"📧 Attempting to send verification email to {user.email}")
            
            # Generate verification link
            if hasattr(current_app, 'config'):
                base_url = current_app.config.get('FRONTEND_URL', 'http://localhost:5000')
            else:
                base_url = 'http://localhost:5000'
                
            verification_link = f"{base_url}/auth/verify-email/{user.verification_token}"
            
            # Send the verification email using the template
            html_body = email_sender.template_manager.render_template(
                'verification',
                user_name=user_name,
                verification_link=verification_link
            )
            
            success = email_sender.send_email(
                to_email=user.email,
                subject="Wi-Fi Security System - Email Verification Required",
                body=f"Please verify your email by visiting: {verification_link}",
                html_body=html_body,
                async_send=False  # Send synchronously for immediate verification
            )
            
            if success:
                current_app.logger.info(f"✅ Verification email sent successfully to {user.email}")
                return True
            else:
                current_app.logger.error(f"❌ Failed to send verification email to {user.email}")
                return False
            
        except Exception as e:
            current_app.logger.error(f"❌ Email verification sending failed: {str(e)}")
            import traceback
            current_app.logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    def verify_token(self, token):
        """Verify email verification token"""
        try:
            user = User.query.filter_by(verification_token=token).first()
            
            if not user:
                return None, "Invalid verification token"
            
            if user.verification_token_expires < datetime.utcnow():
                return None, "Verification token has expired"
            
            if user.is_verified:
                return user, "Email already verified"
            
            return user, "valid"
            
        except Exception as e:
            current_app.logger.error(f"Token verification failed: {str(e)}")
            return None, "Token verification failed"


class SessionManager:
    """User session management"""
    
    @staticmethod
    def create_secure_session(user):
        """Create secure user session"""
        session['user_id'] = user.id
        session['email'] = user.email
        session['is_verified'] = user.is_verified
        session['is_admin'] = user.is_admin()  # Use actual admin role check
        session['login_timestamp'] = datetime.utcnow().isoformat()
        session['session_token'] = secrets.token_urlsafe(32)
        session.permanent = True
    
    @staticmethod
    def clear_session():
        """Clear user session"""
        session.clear()
    
    @staticmethod
    def is_session_valid():
        """Check if current session is valid"""
        if 'user_id' not in session:
            return False
        
        try:
            login_time = datetime.fromisoformat(session.get('login_timestamp', ''))
            if datetime.utcnow() - login_time > timedelta(hours=12):
                return False
        except:
            return False
        
        return True


# Initialize managers
auth_manager = AuthenticationManager()
email_handler = EmailVerificationHandler()
session_manager = SessionManager()


@auth.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=5, per_seconds=15*60)
@log_activity('user_registration_attempt')
def register():
    """User registration route - FIXED"""
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            # Sanitize form inputs
            form.sanitize_input()
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=form.email.data.lower()).first()
            if existing_user:
                flash('An account with this email already exists', 'error')
                return render_template('auth/register.html', form=form)
            
            # Create new user
            user_data = {
                'first_name': form.first_name.data,
                'last_name': form.last_name.data,
                'organization': form.organization.data or "",
                'bio': form.purpose.data,  # Store purpose in bio field
                'role': 'user'
            }
            
            # Create user using the User.create_user method
            user = User.create_user(
                email=form.email.data.lower().strip(),
                password=form.password.data,
                **user_data
            )
            
            if user:
                # Send verification email using the fixed handler
                current_app.logger.info(f"📧 Attempting to send verification email to {user.email}")
                
                if email_handler.send_verification_email(user):
                    flash('Registration successful! Please check your email to verify your account.', 'success')
                    
                    # Log successful registration
                    log_auth_attempt(user.email, 'registration_success', request.remote_addr)
                    
                    return redirect(url_for('auth.resend_verification'))
                else:
                    flash('Registration successful, but verification email failed to send. Please use resend verification.', 'warning')
                    return redirect(url_for('auth.resend_verification'))
            else:
                flash('Registration failed. Please try again.', 'error')
                
        except Exception as e:
            current_app.logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('auth/register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=10, per_seconds=15*60)
@log_activity('user_login_attempt')
def login():
    """User login route"""
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            user = authenticate_user(form.email.data, form.password.data)
            
            if user:
                if not user.is_verified:
                    flash('Please verify your email address before logging in.', 'warning')
                    return redirect(url_for('auth.resend_verification'))
                
                if auth_manager.create_user_session(user):
                    login_user(user, remember=form.remember_me.data)
                    log_auth_attempt(user.email, 'login_success', request.remote_addr)
                    flash('Login successful!', 'success')
                    
                    # QUICK FIX: Use absolute redirect instead of url_for
                    next_page = request.args.get('next')
                    if next_page:
                        return redirect(next_page)
                    return redirect('/dashboard')  # Direct URL instead of url_for
                else:
                    flash('Session creation failed. Please try again.', 'error')
            else:
                log_auth_attempt(form.email.data, 'login_failed', request.remote_addr)
                flash('Invalid email or password.', 'error')
                
        except Exception as e:
            current_app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('auth/login.html', form=form, current_year=datetime.now().year)


@auth.route('/logout')
@login_required
@log_activity('user_logout')
def logout():
    """User logout route"""
    try:
        # Log logout attempt
        if current_user.is_authenticated:
            log_auth_attempt(current_user.email, 'logout', request.remote_addr)
        
        # Clear session and logout
        logout_user()
        session_manager.clear_session()
        
        flash('You have been logged out successfully.', 'info')
        # Redirect to index page (home page) instead of rendering login template
        return redirect('/')
        
    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        flash('An error occurred during logout.', 'error')
        # Redirect to index page even on error for security
        return redirect('/')


@auth.route('/verify-email/<token>')
@log_activity('email_verification_attempt')
def verify_email(token):
    """Email verification route"""
    try:
        user, message = email_handler.verify_token(token)
        
        if user and message == "valid":
            # Mark user as verified using the User model method
            if user.verify_email_token(token):
                user.save()
                
                # Log successful verification
                log_auth_attempt(user.email, 'email_verified', request.remote_addr)
                
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Email verification failed. Please try again.', 'error')
                return redirect(url_for('auth.resend_verification'))
            
        elif user and message == "Email already verified":
            flash('Email is already verified. You can log in.', 'info')
            return redirect(url_for('auth.login'))
            
        else:
            flash(f'Email verification failed: {message}', 'error')
            return redirect(url_for('auth.resend_verification'))
            
    except Exception as e:
        current_app.logger.error(f"Email verification error: {str(e)}")
        flash('An error occurred during email verification.', 'error')
        return redirect(url_for('auth.resend_verification'))


@auth.route('/resend-verification', methods=['GET', 'POST'])
@rate_limit(max_requests=3, per_seconds=30*60)
@log_activity('resend_verification_attempt')
def resend_verification():
    """Resend verification email route - COMPLETELY FIXED"""
    form = EmailVerificationForm()
    
    if form.validate_on_submit():
        try:
            current_app.logger.info(f"🔄 Processing resend verification for {form.email.data}")
            
            user = User.query.filter_by(email=form.email.data.lower()).first()
            
            if not user:
                flash('No account found with this email address.', 'error')
                current_app.logger.warning(f"⚠️ No user found for email: {form.email.data}")
                return render_template('auth/verify_email.html', form=form)
            
            if user.is_verified:
                flash('This email is already verified.', 'info')
                current_app.logger.info(f"ℹ️ Email already verified: {user.email}")
                return redirect(url_for('auth.login'))
            
            # Send verification email using the fixed handler
            current_app.logger.info(f"📧 Resending verification email to {user.email}")
            
            if email_handler.send_verification_email(user):
                flash('Verification email sent! Please check your inbox and spam folder.', 'success')
                log_auth_attempt(user.email, 'verification_resent', request.remote_addr)
                current_app.logger.info(f"✅ Verification email resent successfully to {user.email}")
            else:
                flash('Failed to send verification email. Please try again later.', 'error')
                current_app.logger.error(f"❌ Failed to resend verification email to {user.email}")
                
        except Exception as e:
            current_app.logger.error(f"❌ Resend verification error: {str(e)}")
            import traceback
            current_app.logger.error(f"Full traceback: {traceback.format_exc()}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('auth/verify_email.html', form=form)


# MODIFICATION 2: Update the forgot_password route in routes.py

@auth.route('/forgot-password', methods=['GET', 'POST'])
@rate_limit(max_requests=5, per_seconds=30*60)
@log_activity('forgot_password_attempt')
def forgot_password():
    """Forgot password route - FIXED to use global email_sender"""
    form = ForgotPasswordForm()
    
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data.lower()).first()
            
            if user:
                # Generate reset token using User model method
                reset_token = user.generate_reset_token()
                
                if reset_token:
                    user.save()
                    
                    # Get user's name for personalization
                    profile_data = user.get_profile_data()
                    user_name = profile_data.get('first_name', user.email.split('@')[0])
                    
                    # CRITICAL FIX: Use the global email_sender directly
                    from ..utils.email_sender import email_sender
                    
                    current_app.logger.info(f"📧 Attempting to send password reset email to {user.email}")
                    
                    # Generate reset link
                    if hasattr(current_app, 'config'):
                        base_url = current_app.config.get('FRONTEND_URL', 'http://localhost:5000')
                    else:
                        base_url = 'http://localhost:5000'
                        
                    reset_link = f"{base_url}/auth/reset-password/{reset_token}"
                    
                    # Send the reset email using the template
                    html_body = email_sender.template_manager.render_template(
                        'password_reset',
                        user_name=user_name,
                        reset_link=reset_link
                    )
                    
                    success = email_sender.send_email(
                        to_email=user.email,
                        subject="Wi-Fi Security System - Password Reset Request",
                        body=f"Reset your password by visiting: {reset_link}",
                        html_body=html_body,
                        async_send=False  # Send synchronously for immediate password reset
                    )
                    
                    if success:
                        log_auth_attempt(user.email, 'password_reset_requested', request.remote_addr)
                        flash('Password reset instructions sent to your email.', 'success')
                        current_app.logger.info(f"✅ Password reset email sent successfully to {user.email}")
                    else:
                        flash('Failed to send reset email. Please try again.', 'error')
                        current_app.logger.error(f"❌ Failed to send password reset email to {user.email}")
                else:
                    flash('Failed to generate reset token. Please try again.', 'error')
            else:
                # Don't reveal if email exists or not for security
                flash('If an account with this email exists, password reset instructions have been sent.', 'info')
                
        except Exception as e:
            current_app.logger.error(f"Forgot password error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('auth/forgot_password.html', form=form)


@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
@log_activity('password_reset_attempt')
def reset_password(token):
    """Password reset route"""
    form = ResetPasswordForm()
    
    # Verify token first
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    if form.validate_on_submit():
        try:
            # Reset password using User model method
            if user.reset_password(form.password.data, token):
                user.save()
                
                # Log password reset
                log_auth_attempt(user.email, 'password_reset_completed', request.remote_addr)
                
                flash('Password reset successful! You can now log in with your new password.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Password reset failed. Please try again.', 'error')
            
        except Exception as e:
            current_app.logger.error(f"Password reset error: {str(e)}")
            flash('An error occurred during password reset. Please try again.', 'error')
    
    return render_template('auth/reset_password.html', form=form, token=token)


# API endpoint for checking verification status
@auth.route('/api/check-verification-status', methods=['GET'])
def check_verification_status():
    """Check email verification status"""
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({'error': 'Email parameter required'}), 400
        
        user = User.query.filter_by(email=email.lower()).first()
        if not user:
            return jsonify({'verified': False, 'message': 'User not found'}), 404
        
        return jsonify({
            'verified': user.is_verified,
            'message': 'Email verified' if user.is_verified else 'Email not verified'
        })
        
    except Exception as e:
        current_app.logger.error(f"Verification status check error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


# Helper Functions

def register_user(email, password):
    """Process user registration - DEPRECATED: Use User.create_user instead"""
    try:
        return User.create_user(email, password, role='user')
    except Exception as e:
        current_app.logger.error(f"User registration failed: {str(e)}")
        return None


def authenticate_user(email, password):
    """User login validation"""
    try:
        return User.authenticate(email, password)
    except Exception as e:
        current_app.logger.error(f"User authentication failed: {str(e)}")
        return None


def generate_reset_token(user):
    """Password reset token generation - DEPRECATED: Use user.generate_reset_token() instead"""
    try:
        return user.generate_reset_token()
    except Exception as e:
        current_app.logger.error(f"Reset token generation failed: {str(e)}")
        return None


def log_auth_attempt(email, action, ip_address, success=True):
    """Authentication attempt logging"""
    try:
        log_entry = AuditLog(
            timestamp=datetime.utcnow(),
            event_type='authentication',
            details={
                'email': email,
                'action': action,
                'success': success,
                'ip_address': ip_address,
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            },
            security_level='medium' if success else 'high',
            ip_address=ip_address
        )
        
        log_entry.save()
        
    except Exception as e:
        current_app.logger.error(f"Auth logging failed: {str(e)}")


# API Endpoints for Authentication

@auth.route('/api/check-session', methods=['GET'])
def check_session():
    """Check if user session is valid"""
    try:
        if current_user.is_authenticated:
            return jsonify({
                'valid': True,
                'user': {
                    'id': current_user.id,
                    'email': current_user.email,
                    'role': 'Admin' if current_user.is_admin() else ('Moderator' if current_user.is_moderator() else 'User')
                }
            })
        else:
            return jsonify({'valid': False}), 401
            
    except Exception as e:
        current_app.logger.error(f"Session check error: {str(e)}")
        return jsonify({'error': 'Session check failed'}), 500

@auth.route('/api/validate-email', methods=['POST'])
@rate_limit(max_requests=20, per_seconds=10*60)
def validate_email_api():
    """API endpoint for email validation"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'valid': False, 'message': 'Email is required'}), 400
        
        # Check email format using global email_sender
        if not email_sender.validate_email_address(email):
            return jsonify({'valid': False, 'message': 'Invalid email format'}), 400
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'valid': False, 'message': 'Email already registered'}), 400
        
        return jsonify({'valid': True, 'message': 'Email is available'})
        
    except Exception as e:
        current_app.logger.error(f"Email validation API error: {str(e)}")
        return jsonify({'error': 'Email validation failed'}), 500


@auth.route('/api/validate-password', methods=['POST'])
@rate_limit(max_requests=20, per_seconds=10*60)
def validate_password_api():
    """API endpoint for password validation"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'valid': False, 'message': 'Password is required'}), 400
        
        is_valid = auth_manager.password_manager.validate_password_strength(password)
        
        if is_valid:
            return jsonify({'valid': True, 'message': 'Password meets requirements'})
        else:
            return jsonify({
                'valid': False,
                'message': 'Password must be at least 8 characters with uppercase, lowercase, number, and special character'
            }), 400
            
    except Exception as e:
        current_app.logger.error(f"Password validation API error: {str(e)}")
        return jsonify({'error': 'Password validation failed'}), 500


# Test email functionality endpoint (for development)
# MODIFICATION 3: Update the test_email_functionality route in routes.py

@auth.route('/api/test-email', methods=['POST'])
@rate_limit(max_requests=3, per_seconds=30*60)
def test_email_functionality():
    """Test email functionality endpoint - FIXED"""
    try:
        data = request.get_json()
        test_email = data.get('email')
        
        if not test_email:
            return jsonify({'error': 'Email parameter required'}), 400
        
        # CRITICAL FIX: Use the global email_sender directly
        from ..utils.email_sender import email_sender
        
        # Check if email service is configured
        if not email_sender.is_configured():
            return jsonify({
                'success': False, 
                'message': 'Email service not configured'
            }), 503
        
        # Send test email using the same method as the working test route
        success = email_sender.send_email(
            to_email=test_email,
            subject="Wi-Fi Security System - Test Email",
            body="This is a test email from the Wi-Fi Security System. Email configuration is working correctly!",
            html_body="<p>This is a <strong>test email</strong> from the Wi-Fi Security System</p>",
            async_send=False  # Send synchronously for immediate testing
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Test email sent successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send test email'
            }), 500
            
    except Exception as e:
        current_app.logger.error(f"Test email API error: {str(e)}")
        return jsonify({'error': 'Test email failed'}), 500


# Error handlers for authentication blueprint

@auth.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limit exceeded"""
    flash('Too many requests. Please try again later.', 'error')
    return redirect(url_for('auth.login')), 429


@auth.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    current_app.logger.error(f"Internal auth error: {str(error)}")
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('auth.login')), 500


# Security headers for authentication routes

@auth.after_request
def add_security_headers(response):
    """Add security headers to authentication responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response