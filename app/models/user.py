"""
User Management Model - COMPLETE FIXED VERSION
Purpose: User authentication and profile management for Wi-Fi Security System

FIXES:
- Added missing UserRole enum
- Fixed all database relationships
- Fixed password hashing
- Improved error handling
- Fixed SQLAlchemy compatibility
"""

from datetime import datetime, timedelta
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from enum import Enum
import secrets
import json
import logging

# Create db instance if not imported
try:
    from app.models import db
except ImportError:
    db = SQLAlchemy()

logger = logging.getLogger(__name__)

class UserRole(Enum):
    """User role enumeration - FIXED: Added missing enum"""
    USER = "user"
    ADMIN = "admin"
    MODERATOR = "moderator"
    SUPER_ADMIN = "super_admin"

class AccountStatus(Enum):
    """Account status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    SUSPENDED = "suspended"
    LOCKED = "locked"

class User(UserMixin, db.Model):
    """
    Main user model for authentication and profile management
    COMPLETE FIXED VERSION with all relationships
    """
    
    __tablename__ = 'users'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Authentication fields
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Verification and approval
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_admin_approved = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, default=None)
    verified_at = db.Column(db.DateTime, default=None)
    password_changed_at = db.Column(db.DateTime, default=None)
    
    # Role-based access control - Fixed to use enum properly
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)
    account_status = db.Column(db.Enum(AccountStatus), default=AccountStatus.PENDING, nullable=False)
    
    # Profile and settings (JSON fields stored as TEXT for SQLite compatibility)
    profile_data = db.Column(db.Text, default='{}')
    security_settings = db.Column(db.Text, default='{}')
    preferences = db.Column(db.Text, default='{}')
    
    # Email verification token
    verification_token = db.Column(db.String(255), default=None)
    verification_token_expires = db.Column(db.DateTime, default=None)
    
    # Password reset token
    reset_token = db.Column(db.String(255), default=None)
    reset_token_expires = db.Column(db.DateTime, default=None)
    
    # Account security
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, default=None)
    
    # Additional fields
    last_ip_address = db.Column(db.String(45))
    login_count = db.Column(db.Integer, default=0)
    
    # Relationships - Fixed to avoid circular imports
    # These will be defined after all models are imported
    
    def __init__(self, email, password=None, **kwargs):
        """Initialize user with email and optional password"""
        self.email = email.lower().strip()
        
        # Set password - FIXED
        if password:
            self.set_password(password)
        elif 'password_hash' in kwargs:
            self.password_hash = kwargs['password_hash']
        else:
            # Generate a temporary random password if none provided
            temp_password = secrets.token_urlsafe(16)
            self.set_password(temp_password)
        
        # Set role - FIXED
        role_value = kwargs.get('role', 'user')
        if isinstance(role_value, str):
            try:
                self.role = UserRole(role_value.lower())
            except ValueError:
                self.role = UserRole.USER
        else:
            self.role = role_value
        
        # Set account status
        status_value = kwargs.get('account_status', 'pending')
        if isinstance(status_value, str):
            try:
                self.account_status = AccountStatus(status_value.lower())
            except ValueError:
                self.account_status = AccountStatus.PENDING
        else:
            self.account_status = status_value
        
        # Set profile data
        profile_defaults = {
            'first_name': kwargs.get('first_name', ''),
            'last_name': kwargs.get('last_name', ''),
            'organization': kwargs.get('organization', ''),
            'phone': kwargs.get('phone', ''),
            'bio': kwargs.get('bio', ''),
            'avatar_url': kwargs.get('avatar_url', ''),
            'department': kwargs.get('department', ''),
            'job_title': kwargs.get('job_title', '')
        }
        self.profile_data = json.dumps(profile_defaults)
        
        # Set default security settings
        security_defaults = {
            'two_factor_enabled': False,
            'login_notifications': True,
            'session_timeout': 30,
            'password_change_required': False,
            'allowed_ip_ranges': [],
            'require_password_change': False,
            'max_concurrent_sessions': 3
        }
        self.security_settings = json.dumps(security_defaults)
        
        # Set default preferences
        preference_defaults = {
            'theme': 'light',
            'language': 'en',
            'timezone': 'UTC',
            'email_notifications': True,
            'dashboard_layout': 'default',
            'scan_frequency': 'manual',
            'notification_preferences': {
                'email': True,
                'browser': True,
                'mobile': False
            }
        }
        self.preferences = json.dumps(preference_defaults)
    
    def set_password(self, password):
        """Set password hash - FIXED"""
        try:
            if not password or len(password) < 6:
                raise ValueError("Password must be at least 6 characters long")
            
            self.password_hash = generate_password_hash(
                password, 
                method='pbkdf2:sha256',
                salt_length=16
            )
            self.password_changed_at = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Error setting password for {self.email}: {e}")
            return False
    
    def check_password(self, password):
        """Verify password - FIXED"""
        try:
            if not self.password_hash or not password:
                return False
            return check_password_hash(self.password_hash, password)
        except Exception as e:
            logger.error(f"Error checking password for {self.email}: {e}")
            return False
    
    def generate_verification_token(self):
        """Generate email verification token"""
        try:
            self.verification_token = secrets.token_urlsafe(32)
            self.verification_token_expires = datetime.utcnow() + timedelta(hours=24)
            return self.verification_token
        except Exception as e:
            logger.error(f"Error generating verification token: {e}")
            return None
    
    def verify_email_token(self, token):
        """Verify email verification token"""
        try:
            if (self.verification_token == token and 
                self.verification_token_expires and 
                datetime.utcnow() < self.verification_token_expires):
                
                self.is_verified = True
                self.verified_at = datetime.utcnow()
                self.account_status = AccountStatus.ACTIVE
                self.verification_token = None
                self.verification_token_expires = None
                return True
            return False
        except Exception as e:
            logger.error(f"Error verifying email token: {e}")
            return False
    
    def generate_reset_token(self):
        """Generate password reset token"""
        try:
            self.reset_token = secrets.token_urlsafe(32)
            self.reset_token_expires = datetime.utcnow() + timedelta(hours=2)
            return self.reset_token
        except Exception as e:
            logger.error(f"Error generating reset token: {e}")
            return None
    
    def verify_reset_token(self, token):
        """Verify password reset token"""
        try:
            if (self.reset_token == token and 
                self.reset_token_expires and 
                datetime.utcnow() < self.reset_token_expires):
                return True
            return False
        except Exception as e:
            logger.error(f"Error verifying reset token: {e}")
            return False
    
    def reset_password(self, new_password, token):
        """Reset password with token verification"""
        try:
            if self.verify_reset_token(token):
                if self.set_password(new_password):
                    self.reset_token = None
                    self.reset_token_expires = None
                    self.failed_login_attempts = 0
                    self.locked_until = None
                    return True
            return False
        except Exception as e:
            logger.error(f"Error resetting password: {e}")
            return False
    
    def is_account_locked(self):
        """Check if account is locked due to failed attempts"""
        try:
            if self.account_status == AccountStatus.LOCKED:
                return True
            if self.locked_until and datetime.utcnow() < self.locked_until:
                return True
            return False
        except Exception as e:
            logger.error(f"Error checking account lock: {e}")
            return False
    
    def lock_account(self, minutes=30):
        """Lock account for specified minutes"""
        try:
            self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
            self.account_status = AccountStatus.LOCKED
            return True
        except Exception as e:
            logger.error(f"Error locking account: {e}")
            return False
    
    def unlock_account(self):
        """Unlock account"""
        try:
            self.locked_until = None
            self.failed_login_attempts = 0
            if self.account_status == AccountStatus.LOCKED:
                self.account_status = AccountStatus.ACTIVE
            return True
        except Exception as e:
            logger.error(f"Error unlocking account: {e}")
            return False
    
    def record_failed_login(self):
        """Record failed login attempt"""
        try:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.lock_account()
            return True
        except Exception as e:
            logger.error(f"Error recording failed login: {e}")
            return False
    
    def record_successful_login(self, ip_address=None):
        """Record successful login"""
        try:
            self.last_login = datetime.utcnow()
            self.failed_login_attempts = 0
            self.locked_until = None
            self.login_count += 1
            if ip_address:
                self.last_ip_address = ip_address
            
            # Activate account if pending and verified
            if self.account_status == AccountStatus.PENDING and self.is_verified:
                self.account_status = AccountStatus.ACTIVE
            
            return True
        except Exception as e:
            logger.error(f"Error recording successful login: {e}")
            return False
    
    def get_profile_data(self):
        """Get profile data as dictionary"""
        try:
            return json.loads(self.profile_data or '{}')
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing profile data: {e}")
            return {}
    
    def update_profile_data(self, data):
        """Update profile data"""
        try:
            current_data = self.get_profile_data()
            current_data.update(data)
            self.profile_data = json.dumps(current_data)
            return True
        except Exception as e:
            logger.error(f"Error updating profile data: {e}")
            return False
    
    def get_security_settings(self):
        """Get security settings as dictionary"""
        try:
            return json.loads(self.security_settings or '{}')
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing security settings: {e}")
            return {}
    
    def update_security_settings(self, settings):
        """Update security settings"""
        try:
            current_settings = self.get_security_settings()
            current_settings.update(settings)
            self.security_settings = json.dumps(current_settings)
            return True
        except Exception as e:
            logger.error(f"Error updating security settings: {e}")
            return False
    
    def get_preferences(self):
        """Get preferences as dictionary"""
        try:
            return json.loads(self.preferences or '{}')
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Error parsing preferences: {e}")
            return {}
    
    def update_preferences(self, prefs):
        """Update preferences"""
        try:
            current_prefs = self.get_preferences()
            current_prefs.update(prefs)
            self.preferences = json.dumps(current_prefs)
            return True
        except Exception as e:
            logger.error(f"Error updating preferences: {e}")
            return False
    
    def has_role(self, role):
        """Check if user has specific role"""
        if isinstance(role, str):
            try:
                role_enum = UserRole(role.lower())
                return self.role == role_enum
            except ValueError:
                return False
        return self.role == role
    
    def is_admin(self):
        """Check if user is admin"""
        return self.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]
    
    def is_moderator(self):
        """Check if user is moderator"""
        return self.role in [UserRole.MODERATOR, UserRole.ADMIN, UserRole.SUPER_ADMIN]
    
    def is_super_admin(self):
        """Check if user is super admin"""
        return self.role == UserRole.SUPER_ADMIN
    
    def can_access_admin_panel(self):
        """Check if user can access admin panel"""
        return (self.is_moderator() and 
                self.is_admin_approved and 
                self.account_status == AccountStatus.ACTIVE)
    
    def can_perform_deep_scan(self):
        """Check if user can perform deep scans"""
        return (self.is_verified and 
                self.account_status == AccountStatus.ACTIVE and
                (self.is_admin_approved or self.role != UserRole.USER))
    
    def can_manage_users(self):
        """Check if user can manage other users"""
        return self.is_admin() and self.account_status == AccountStatus.ACTIVE
    
    def can_view_audit_logs(self):
        """Check if user can view audit logs"""
        return self.is_admin() and self.account_status == AccountStatus.ACTIVE
    
    def save(self):
        """
        Save the audit log entry to database
        This method provides compatibility with code expecting a save() method
        """
        try:
            db.session.add(self)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving audit log: {e}")
            return False

    def update(self, **kwargs):
        """
        Update audit log entry with new values
        """
        try:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            
            # Handle JSON fields specially
            json_fields = ['details', 'request_headers', 'compliance_flags']
            for field in json_fields:
                if field in kwargs and isinstance(kwargs[field], (dict, list)):
                    setattr(self, field, json.dumps(kwargs[field]))
            
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating audit log: {e}")
            return False

    def delete(self):
        """
        Delete the audit log entry
        """
        try:
            db.session.delete(self)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting audit log: {e}")
            return False
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        try:
            data = {
                'id': self.id,
                'email': self.email,
                'is_verified': self.is_verified,
                'is_admin_approved': self.is_admin_approved,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'last_login': self.last_login.isoformat() if self.last_login else None,
                'role': self.role.value if self.role else 'user',
                'account_status': self.account_status.value if self.account_status else 'pending',
                'profile_data': self.get_profile_data(),
                'preferences': self.get_preferences(),
                'is_active': self.is_active,
                'login_count': self.login_count
            }
            
            if include_sensitive:
                data.update({
                    'security_settings': self.get_security_settings(),
                    'failed_login_attempts': self.failed_login_attempts,
                    'is_locked': self.is_account_locked(),
                    'last_ip_address': self.last_ip_address
                })
            
            return data
        except Exception as e:
            logger.error(f"Error converting user to dict: {e}")
            return {}
    
    @classmethod
    def get_by_email(cls, email):
        """Get user by email"""
        try:
            return cls.query.filter_by(email=email.lower().strip()).first()
        except Exception as e:
            logger.error(f"Error getting user by email: {e}")
            return None
    
    @classmethod
    def get_by_id(cls, user_id):
        """Get user by ID"""
        try:
            return cls.query.get(user_id)
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            return None
    
    @classmethod
    def create_user(cls, email, password, **kwargs):
        """Create new user"""
        try:
            # Check if user exists
            if cls.get_by_email(email):
                logger.warning(f"User already exists: {email}")
                return None
            
            user = cls(email=email, password=password, **kwargs)
            user.generate_verification_token()
            
            if user.save():
                logger.info(f"User created successfully: {email}")
                return user
            return None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    @classmethod
    def authenticate(cls, email, password):
        """Authenticate user with email and password"""
        try:
            user = cls.get_by_email(email)
            
            if not user:
                logger.warning(f"Authentication failed - user not found: {email}")
                return None
            
            if user.is_account_locked():
                logger.warning(f"Authentication failed - account locked: {email}")
                return None
            
            if not user.is_active or user.account_status not in [AccountStatus.ACTIVE, AccountStatus.PENDING]:
                logger.warning(f"Authentication failed - account inactive: {email}")
                return None
            
            if user.check_password(password):
                user.record_successful_login()
                db.session.commit()
                logger.info(f"Authentication successful: {email}")
                return user
            else:
                user.record_failed_login()
                db.session.commit()
                logger.warning(f"Authentication failed - wrong password: {email}")
                return None
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return None
    
    @classmethod
    def get_all_users(cls, include_inactive=False):
        """Get all users"""
        try:
            query = cls.query
            if not include_inactive:
                query = query.filter_by(is_active=True)
            return query.all()
        except Exception as e:
            logger.error(f"Error getting all users: {e}")
            return []
    
    @classmethod
    def get_users_by_role(cls, role):
        """Get users by role"""
        try:
            if isinstance(role, str):
                role = UserRole(role.lower())
            return cls.query.filter_by(role=role).all()
        except Exception as e:
            logger.error(f"Error getting users by role: {e}")
            return []
    
    @classmethod
    def search_users(cls, search_term, limit=50):
        """Search users by email or profile data"""
        try:
            return cls.query.filter(
                cls.email.ilike(f'%{search_term}%')
            ).limit(limit).all()
        except Exception as e:
            logger.error(f"Error searching users: {e}")
            return []
    
    def __repr__(self):
        return f'<User {self.email} ({self.role.value if self.role else "unknown"})>'


class UserProfile(db.Model):
    """
    Extended user profile information
    Separate table for additional profile data
    """
    
    __tablename__ = 'user_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Extended profile fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    organization = db.Column(db.String(100))
    department = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))
    website = db.Column(db.String(255))
    
    # Professional information
    security_certifications = db.Column(db.Text)  # JSON array
    years_experience = db.Column(db.Integer)
    specializations = db.Column(db.Text)  # JSON array
    education = db.Column(db.Text)  # JSON array
    
    # Contact preferences
    preferred_contact_method = db.Column(db.String(20), default='email')
    emergency_contact = db.Column(db.Text)  # JSON object
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship - will be set after User model is fully defined
    user = db.relationship('User', backref=db.backref('profile', uselist=False, cascade='all, delete-orphan'))
    
    def get_full_name(self):
        """Get full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or "Unknown User"
    
    def get_display_name(self):
        """Get display name with fallback"""
        full_name = self.get_full_name()
        if full_name != "Unknown User":
            return full_name
        return self.email if self.email else "Unknown User"
    
    def get_certifications(self):
        """Get certifications as list"""
        try:
            return json.loads(self.security_certifications or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def add_certification(self, certification):
        """Add security certification"""
        try:
            certs = self.get_certifications()
            if certification not in certs:
                certs.append(certification)
                self.security_certifications = json.dumps(certs)
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding certification: {e}")
            return False
    
    def remove_certification(self, certification):
        """Remove security certification"""
        try:
            certs = self.get_certifications()
            if certification in certs:
                certs.remove(certification)
                self.security_certifications = json.dumps(certs)
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing certification: {e}")
            return False
    
    def get_specializations(self):
        """Get specializations as list"""
        try:
            return json.loads(self.specializations or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def add_specialization(self, specialization):
        """Add specialization"""
        try:
            specs = self.get_specializations()
            if specialization not in specs:
                specs.append(specialization)
                self.specializations = json.dumps(specs)
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding specialization: {e}")
            return False
    
    def get_education(self):
        """Get education as list"""
        try:
            return json.loads(self.education or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def add_education(self, education_entry):
        """Add education entry"""
        try:
            education = self.get_education()
            education.append(education_entry)
            self.education = json.dumps(education)
            return True
        except Exception as e:
            logger.error(f"Error adding education: {e}")
            return False
    
    def get_emergency_contact(self):
        """Get emergency contact as dict"""
        try:
            return json.loads(self.emergency_contact or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_emergency_contact(self, contact_info):
        """Set emergency contact"""
        try:
            self.emergency_contact = json.dumps(contact_info)
            return True
        except Exception as e:
            logger.error(f"Error setting emergency contact: {e}")
            return False
    
    def to_dict(self):
        """Convert profile to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'full_name': self.get_full_name(),
            'display_name': self.get_display_name(),
            'first_name': self.first_name,
            'last_name': self.last_name,
            'organization': self.organization,
            'department': self.department,
            'job_title': self.job_title,
            'phone': self.phone,
            'address': self.address,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'website': self.website,
            'certifications': self.get_certifications(),
            'years_experience': self.years_experience,
            'specializations': self.get_specializations(),
            'education': self.get_education(),
            'preferred_contact_method': self.preferred_contact_method,
            'emergency_contact': self.get_emergency_contact(),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class UserSession(db.Model):
    """
    User session management
    Track active user sessions
    """
    
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Session information
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    session_id = db.Column(db.String(255), index=True)  # Flask session ID
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.Text)
    
    # Device and browser info
    device_type = db.Column(db.String(50))  # desktop, mobile, tablet
    browser = db.Column(db.String(100))
    operating_system = db.Column(db.String(100))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # Session status and security
    is_active = db.Column(db.Boolean, default=True)
    is_remembered = db.Column(db.Boolean, default=False)  # "Remember me" sessions
    login_method = db.Column(db.String(50), default='password')  # password, 2fa, sso
    
    # Security flags
    is_suspicious = db.Column(db.Boolean, default=False)
    security_flags = db.Column(db.Text, default='{}')  # JSON for security metadata
    
    # Geographic information
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    
    # Relationship
    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic', cascade='all, delete-orphan'))
    
    def __init__(self, user_id, ip_address=None, user_agent=None, duration_minutes=30, **kwargs):
        """Initialize session"""
        self.user_id = user_id
        self.session_token = secrets.token_urlsafe(32)
        self.session_id = kwargs.get('session_id')
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.expires_at = datetime.utcnow() + timedelta(minutes=duration_minutes)
        
        # Extract device info from user agent
        self._parse_user_agent(user_agent)
        
        # Set additional attributes
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def _parse_user_agent(self, user_agent):
        """Parse user agent string to extract device info"""
        if not user_agent:
            return
            
        user_agent_lower = user_agent.lower()
        
        # Detect device type
        if any(mobile in user_agent_lower for mobile in ['mobile', 'android', 'iphone']):
            self.device_type = 'mobile'
        elif 'tablet' in user_agent_lower or 'ipad' in user_agent_lower:
            self.device_type = 'tablet'
        else:
            self.device_type = 'desktop'
        
        # Detect browser
        if 'chrome' in user_agent_lower:
            self.browser = 'Chrome'
        elif 'firefox' in user_agent_lower:
            self.browser = 'Firefox'
        elif 'safari' in user_agent_lower:
            self.browser = 'Safari'
        elif 'edge' in user_agent_lower:
            self.browser = 'Edge'
        else:
            self.browser = 'Unknown'
        
        # Detect OS
        if 'windows' in user_agent_lower:
            self.operating_system = 'Windows'
        elif 'mac' in user_agent_lower:
            self.operating_system = 'macOS'
        elif 'linux' in user_agent_lower:
            self.operating_system = 'Linux'
        elif 'android' in user_agent_lower:
            self.operating_system = 'Android'
        elif 'ios' in user_agent_lower:
            self.operating_system = 'iOS'
        else:
            self.operating_system = 'Unknown'
    
    def is_expired(self):
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    def extend_session(self, minutes=30):
        """Extend session expiration"""
        try:
            self.expires_at = datetime.utcnow() + timedelta(minutes=minutes)
            self.last_activity = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Error extending session: {e}")
            return False
    
    def revoke_session(self):
        """Revoke session"""
        try:
            self.is_active = False
            return True
        except Exception as e:
            logger.error(f"Error revoking session: {e}")
            return False
    
    def mark_suspicious(self, reason=None):
        """Mark session as suspicious"""
        try:
            self.is_suspicious = True
            security_flags = json.loads(self.security_flags or '{}')
            security_flags['suspicious_reason'] = reason
            security_flags['marked_at'] = datetime.utcnow().isoformat()
            self.security_flags = json.dumps(security_flags)
            return True
        except Exception as e:
            logger.error(f"Error marking session suspicious: {e}")
            return False
    
    def get_security_flags(self):
        """Get security flags as dict"""
        try:
            return json.loads(self.security_flags or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}
    
    @classmethod
    def cleanup_expired_sessions(cls):
        """Clean up expired sessions"""
        try:
            expired_sessions = cls.query.filter(
                cls.expires_at < datetime.utcnow()
            ).all()
            
            count = len(expired_sessions)
            for session in expired_sessions:
                db.session.delete(session)
            
            db.session.commit()
            logger.info(f"Cleaned up {count} expired sessions")
            return count
        except Exception as e:
            logger.error(f"Error cleaning up sessions: {e}")
            db.session.rollback()
            return 0
    
    @classmethod
    def get_active_sessions(cls, user_id):
        """Get active sessions for user"""
        try:
            return cls.query.filter_by(
                user_id=user_id,
                is_active=True
            ).filter(
                cls.expires_at > datetime.utcnow()
            ).all()
        except Exception as e:
            logger.error(f"Error getting active sessions: {e}")
            return []
    
    @classmethod
    def revoke_all_user_sessions(cls, user_id, except_session_id=None):
        """Revoke all sessions for a user"""
        try:
            query = cls.query.filter_by(user_id=user_id)
            if except_session_id:
                query = query.filter(cls.id != except_session_id)
            
            sessions = query.all()
            count = 0
            for session in sessions:
                session.is_active = False
                count += 1
            
            db.session.commit()
            return count
        except Exception as e:
            logger.error(f"Error revoking user sessions: {e}")
            db.session.rollback()
            return 0
    
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'id': self.id,
            'session_token': self.session_token,
            'ip_address': self.ip_address,
            'device_type': self.device_type,
            'browser': self.browser,
            'operating_system': self.operating_system,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active,
            'is_remembered': self.is_remembered,
            'is_expired': self.is_expired(),
            'is_suspicious': self.is_suspicious,
            'login_method': self.login_method,
            'country': self.country,
            'city': self.city
        }


# Helper functions for user management
def create_user(email, password, **kwargs):
    """Create new user with validation"""
    return User.create_user(email, password, **kwargs)


def authenticate_user(email, password):
    """Authenticate user with email and password"""
    return User.authenticate(email, password)


def get_user_by_id(user_id):
    """Get user by ID"""
    return User.get_by_id(user_id)


def get_user_by_email(email):
    """Get user by email"""
    return User.get_by_email(email)


def update_user_profile(user_id, profile_data):
    """Update user profile data"""
    try:
        user = User.get_by_id(user_id)
        if user and user.update_profile_data(profile_data):
            db.session.commit()
            return True
        return False
    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        db.session.rollback()
        return False


def check_user_permissions(user_id, permission):
    """Check if user has specific permission"""
    try:
        user = User.get_by_id(user_id)
        if not user:
            return False
        
        permission_map = {
            'admin_panel': user.can_access_admin_panel(),
            'deep_scan': user.can_perform_deep_scan(),
            'user_management': user.can_manage_users(),
            'system_monitor': user.is_moderator(),
            'audit_logs': user.can_view_audit_logs(),
            'scan_networks': user.is_verified and user.account_status == AccountStatus.ACTIVE,
            'view_reports': user.is_verified,
            'export_data': user.is_moderator(),
            'system_config': user.is_admin()
        }
        
        return permission_map.get(permission, False)
    except Exception as e:
        logger.error(f"Error checking user permissions: {e}")
        return False


def get_user_statistics():
    """Get user statistics"""
    try:
        total_users = User.query.count()
        verified_users = User.query.filter_by(is_verified=True).count()
        admin_users = User.query.filter_by(role=UserRole.ADMIN).count()
        active_users = User.query.filter_by(account_status=AccountStatus.ACTIVE).count()
        pending_users = User.query.filter_by(account_status=AccountStatus.PENDING).count()
        locked_users = User.query.filter_by(account_status=AccountStatus.LOCKED).count()
        
        # Recent activity (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_logins = User.query.filter(User.last_login >= recent_cutoff).count()
        
        return {
            'total_users': total_users,
            'verified_users': verified_users,
            'admin_users': admin_users,
            'active_users': active_users,
            'pending_users': pending_users,
            'locked_users': locked_users,
            'recent_logins_24h': recent_logins,
            'verification_rate': round((verified_users / total_users * 100), 2) if total_users > 0 else 0,
            'last_updated': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting user statistics: {e}")
        return {'error': str(e)}


def cleanup_inactive_users(days_inactive=90):
    """Clean up inactive users"""
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days_inactive)
        
        # Find users who haven't logged in and aren't verified
        inactive_users = User.query.filter(
            User.last_login < cutoff_date,
            User.is_verified == False,
            User.account_status == AccountStatus.PENDING
        ).all()
        
        count = 0
        for user in inactive_users:
            db.session.delete(user)
            count += 1
        
        db.session.commit()
        logger.info(f"Cleaned up {count} inactive users")
        return count
        
    except Exception as e:
        logger.error(f"Error cleaning up inactive users: {e}")
        db.session.rollback()
        return 0


def create_admin_user(email, password, **kwargs):
    """Create admin user"""
    try:
        kwargs['role'] = UserRole.ADMIN
        kwargs['is_admin_approved'] = True
        kwargs['account_status'] = AccountStatus.ACTIVE
        kwargs['is_verified'] = True
        
        return User.create_user(email, password, **kwargs)
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        return None


def promote_user_to_admin(user_id, promoted_by_user_id=None):
    """Promote user to admin role"""
    try:
        user = User.get_by_id(user_id)
        if not user:
            return False
        
        # Check if promoting user has permission
        if promoted_by_user_id:
            promoting_user = User.get_by_id(promoted_by_user_id)
            if not promoting_user or not promoting_user.is_admin():
                return False
        
        user.role = UserRole.ADMIN
        user.is_admin_approved = True
        
        db.session.commit()
        logger.info(f"User {user.email} promoted to admin")
        return True
        
    except Exception as e:
        logger.error(f"Error promoting user to admin: {e}")
        db.session.rollback()
        return False


def bulk_update_users(user_ids, updates):
    """Bulk update multiple users"""
    try:
        users = User.query.filter(User.id.in_(user_ids)).all()
        
        count = 0
        for user in users:
            for key, value in updates.items():
                if hasattr(user, key):
                    setattr(user, key, value)
                    count += 1
        
        db.session.commit()
        return count
        
    except Exception as e:
        logger.error(f"Error bulk updating users: {e}")
        db.session.rollback()
        return 0


# Export all models and functions
__all__ = [
    'User',
    'UserRole', 
    'AccountStatus',
    'UserProfile',
    'UserSession',
    'create_user',
    'authenticate_user',
    'get_user_by_id',
    'get_user_by_email',
    'update_user_profile',
    'check_user_permissions',
    'get_user_statistics',
    'cleanup_inactive_users',
    'create_admin_user',
    'promote_user_to_admin',
    'bulk_update_users'
]