"""
app/admin/forms.py - Administrative Forms

Purpose: Administrative forms and validation for the Wi-Fi Security System
Key Classes: UserApprovalForm, UserManagementForm, SecuritySettingsForm, BulkOperationsForm
Key Functions: Validation methods for admin operations
APIs Called: Validation APIs, Security policy APIs
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import (
    StringField, TextAreaField, SelectField, BooleanField,
    IntegerField, DateTimeField, SubmitField, HiddenField,
    SelectMultipleField, DecimalField, PasswordField
)
from wtforms.validators import (
    DataRequired, Email, Length, NumberRange, Optional,
    ValidationError, Regexp, URL
)
from wtforms.widgets import CheckboxInput, ListWidget
from datetime import datetime, timedelta
import re


class MultiCheckboxField(SelectMultipleField):
    """Custom field for multiple checkbox selections"""
    widget = ListWidget(prefix_label=False)
    option_widget = CheckboxInput()


class UserApprovalForm(FlaskForm):
    """User approval form for admin access requests"""
    
    # Hidden field for user ID
    user_id = HiddenField('User ID', validators=[DataRequired()])
    
    # Approval decision
    approval_decision = SelectField(
        'Approval Decision',
        choices=[
            ('approve', 'Approve Request'),
            ('reject', 'Reject Request'),
            ('pending', 'Keep Pending'),
            ('request_more_info', 'Request More Information')
        ],
        validators=[DataRequired()],
        default='pending'
    )
    
    # Admin comments
    admin_comments = TextAreaField(
        'Admin Comments',
        validators=[
            Length(min=10, max=1000, message="Comments must be between 10-1000 characters")
        ],
        render_kw={'rows': 4, 'placeholder': 'Provide detailed reasoning for your decision...'}
    )
    
    # Access level (if approved)
    access_level = SelectField(
        'Access Level',
        choices=[
            ('basic', 'Basic User Access'),
            ('advanced', 'Advanced User Access'),
            ('lab_access', 'Lab Environment Access'),
            ('admin', 'Administrator Access')
        ],
        validators=[Optional()],
        default='basic'
    )
    
    # Permission flags
    permissions = MultiCheckboxField(
        'Specific Permissions',
        choices=[
            ('wifi_scan', 'Wi-Fi Network Scanning'),
            ('deep_scan', 'Deep Vulnerability Analysis'),
            ('network_connect', 'Network Connection'),
            ('passive_scan', 'Passive Reconnaissance (Lab Only)'),
            ('report_download', 'Report Download'),
            ('api_access', 'API Access'),
            ('bulk_operations', 'Bulk Operations'),
            ('system_monitor', 'System Monitoring')
        ]
    )
    
    # Expiry date for access
    access_expiry = DateTimeField(
        'Access Expiry Date',
        validators=[Optional()],
        format='%Y-%m-%d',
        render_kw={'type': 'date'}
    )
    
    # Security clearance level
    security_clearance = SelectField(
        'Security Clearance',
        choices=[
            ('standard', 'Standard Clearance'),
            ('elevated', 'Elevated Clearance'),
            ('restricted', 'Restricted Access'),
            ('confidential', 'Confidential Level')
        ],
        validators=[Optional()],
        default='standard'
    )
    
    # Notification settings
    notify_user = BooleanField(
        'Send Notification to User',
        default=True
    )
    
    submit = SubmitField('Process Approval Request')
    
    def validate_approval_decision(self, field):
        """Validate approval decision logic"""
        if field.data == 'approve':
            if not self.admin_comments.data or len(self.admin_comments.data.strip()) < 10:
                raise ValidationError('Detailed comments required for approval decisions')
        
        if field.data == 'reject':
            if not self.admin_comments.data or len(self.admin_comments.data.strip()) < 20:
                raise ValidationError('Detailed rejection reason required (minimum 20 characters)')
    
    def validate_access_expiry(self, field):
        """Validate access expiry date"""
        if field.data and self.approval_decision.data == 'approve':
            if field.data <= datetime.now().date():
                raise ValidationError('Expiry date must be in the future')
            
            # Maximum 2 years from now
            max_date = datetime.now().date() + timedelta(days=730)
            if field.data > max_date:
                raise ValidationError('Maximum access period is 2 years')


class UserManagementForm(FlaskForm):
    """User management form for modifying user accounts"""
    
    # User identification
    user_id = HiddenField('User ID', validators=[DataRequired()])
    
    # Basic user information
    email = StringField(
        'Email Address',
        validators=[
            DataRequired(),
            Email(message='Invalid email address'),
            Length(max=120)
        ]
    )
    
    # User status
    is_active = BooleanField('Account Active', default=True)
    is_verified = BooleanField('Email Verified', default=False)
    is_admin_approved = BooleanField('Admin Approved', default=False)
    
    # Role assignment
    role = SelectField(
        'User Role',
        choices=[
            ('user', 'Standard User'),
            ('advanced_user', 'Advanced User'),
            ('lab_user', 'Lab User'),
            ('admin', 'Administrator'),
            ('super_admin', 'Super Administrator')
        ],
        validators=[DataRequired()],
        default='user'
    )
    
    # Account settings
    max_scans_per_day = IntegerField(
        'Max Scans Per Day',
        validators=[
            NumberRange(min=1, max=100, message="Must be between 1-100 scans")
        ],
        default=10
    )
    
    api_rate_limit = IntegerField(
        'API Rate Limit (requests/hour)',
        validators=[
            NumberRange(min=10, max=1000, message="Must be between 10-1000 requests")
        ],
        default=100
    )
    
    # Security settings
    two_factor_enabled = BooleanField('Two-Factor Authentication', default=False)
    session_timeout = IntegerField(
        'Session Timeout (minutes)',
        validators=[
            NumberRange(min=5, max=1440, message="Must be between 5-1440 minutes")
        ],
        default=60
    )
    
    # User permissions
    permissions = MultiCheckboxField(
        'User Permissions',
        choices=[
            ('basic_scan', 'Basic Wi-Fi Scanning'),
            ('advanced_scan', 'Advanced Scanning'),
            ('deep_analysis', 'Deep Vulnerability Analysis'),
            ('network_connect', 'Network Connection'),
            ('passive_recon', 'Passive Reconnaissance'),
            ('report_generation', 'Report Generation'),
            ('api_access', 'API Access'),
            ('lab_features', 'Lab Environment Features'),
            ('admin_panel', 'Admin Panel Access'),
            ('user_management', 'User Management'),
            ('system_config', 'System Configuration'),
            ('audit_logs', 'Audit Log Access')
        ]
    )
    
    # Account notes
    admin_notes = TextAreaField(
        'Admin Notes',
        validators=[Length(max=2000)],
        render_kw={'rows': 3, 'placeholder': 'Internal notes about this user...'}
    )
    
    # Account actions
    reset_password = BooleanField('Force Password Reset on Next Login')
    send_welcome_email = BooleanField('Send Welcome Email')
    
    submit = SubmitField('Update User Account')
    
    def validate_role(self, field):
        """Validate role assignment"""
        restricted_roles = ['admin', 'super_admin']
        if field.data in restricted_roles:
            if not self.is_admin_approved.data:
                raise ValidationError('Admin approval required for elevated roles')
    
    def validate_permissions(self, field):
        """Validate permission assignments"""
        admin_permissions = ['admin_panel', 'user_management', 'system_config']
        lab_permissions = ['passive_recon', 'lab_features']
        
        selected_permissions = field.data or []
        
        # Check admin permissions
        if any(perm in selected_permissions for perm in admin_permissions):
            if self.role.data not in ['admin', 'super_admin']:
                raise ValidationError('Admin role required for admin permissions')
        
        # Check lab permissions
        if any(perm in selected_permissions for perm in lab_permissions):
            if self.role.data not in ['lab_user', 'admin', 'super_admin']:
                raise ValidationError('Lab user role or higher required for lab permissions')


class SecuritySettingsForm(FlaskForm):
    """Security configuration form"""
    
    # Authentication settings
    password_min_length = IntegerField(
        'Minimum Password Length',
        validators=[
            DataRequired(),
            NumberRange(min=8, max=64, message="Must be between 8-64 characters")
        ],
        default=12
    )
    
    password_require_uppercase = BooleanField('Require Uppercase Letters', default=True)
    password_require_lowercase = BooleanField('Require Lowercase Letters', default=True)
    password_require_numbers = BooleanField('Require Numbers', default=True)
    password_require_symbols = BooleanField('Require Special Characters', default=True)
    
    # Session management
    session_timeout_minutes = IntegerField(
        'Default Session Timeout (minutes)',
        validators=[
            DataRequired(),
            NumberRange(min=5, max=1440, message="Must be between 5-1440 minutes")
        ],
        default=60
    )
    
    max_concurrent_sessions = IntegerField(
        'Max Concurrent Sessions per User',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=10, message="Must be between 1-10 sessions")
        ],
        default=3
    )
    
    # Rate limiting
    login_attempt_limit = IntegerField(
        'Max Login Attempts',
        validators=[
            DataRequired(),
            NumberRange(min=3, max=20, message="Must be between 3-20 attempts")
        ],
        default=5
    )
    
    lockout_duration_minutes = IntegerField(
        'Account Lockout Duration (minutes)',
        validators=[
            DataRequired(),
            NumberRange(min=5, max=1440, message="Must be between 5-1440 minutes")
        ],
        default=30
    )
    
    # API security
    api_rate_limit_per_hour = IntegerField(
        'API Rate Limit (requests/hour)',
        validators=[
            DataRequired(),
            NumberRange(min=50, max=10000, message="Must be between 50-10000 requests")
        ],
        default=1000
    )
    
    require_api_key = BooleanField('Require API Key for Access', default=True)
    
    # System security
    enable_audit_logging = BooleanField('Enable Comprehensive Audit Logging', default=True)
    log_retention_days = IntegerField(
        'Log Retention Period (days)',
        validators=[
            DataRequired(),
            NumberRange(min=30, max=365, message="Must be between 30-365 days")
        ],
        default=90
    )
    
    # Network security
    allowed_ip_ranges = TextAreaField(
        'Allowed IP Ranges (CIDR notation, one per line)',
        validators=[Length(max=2000)],
        render_kw={'rows': 5, 'placeholder': '192.168.1.0/24\n10.0.0.0/8'}
    )
    
    blocked_ip_ranges = TextAreaField(
        'Blocked IP Ranges (CIDR notation, one per line)',
        validators=[Length(max=2000)],
        render_kw={'rows': 3}
    )
    
    # Lab environment security
    lab_environment_enabled = BooleanField('Enable Lab Environment Features')
    lab_access_requires_approval = BooleanField('Lab Access Requires Admin Approval', default=True)
    
    # File upload security
    max_file_size_mb = IntegerField(
        'Maximum File Upload Size (MB)',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=100, message="Must be between 1-100 MB")
        ],
        default=10
    )
    
    allowed_file_extensions = StringField(
        'Allowed File Extensions (comma-separated)',
        validators=[Length(max=200)],
        default='pdf,txt,jpg,png,csv'
    )
    
    submit = SubmitField('Update Security Settings')
    
    def validate_allowed_ip_ranges(self, field):
        """Validate IP range format"""
        if field.data:
            ranges = [line.strip() for line in field.data.split('\n') if line.strip()]
            cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
            
            for ip_range in ranges:
                if not re.match(cidr_pattern, ip_range):
                    raise ValidationError(f'Invalid CIDR notation: {ip_range}')
    
    def validate_blocked_ip_ranges(self, field):
        """Validate blocked IP range format"""
        if field.data:
            ranges = [line.strip() for line in field.data.split('\n') if line.strip()]
            cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
            
            for ip_range in ranges:
                if not re.match(cidr_pattern, ip_range):
                    raise ValidationError(f'Invalid CIDR notation: {ip_range}')


class BulkOperationsForm(FlaskForm):
    """Bulk operations form for managing multiple users"""
    
    # User selection
    selected_users = MultiCheckboxField(
        'Select Users',
        choices=[],  # Will be populated dynamically
        validators=[DataRequired(message='At least one user must be selected')]
    )
    
    # Bulk operation type
    operation_type = SelectField(
        'Bulk Operation',
        choices=[
            ('activate', 'Activate Accounts'),
            ('deactivate', 'Deactivate Accounts'),
            ('approve', 'Approve for Admin Access'),
            ('revoke_approval', 'Revoke Admin Approval'),
            ('reset_passwords', 'Force Password Reset'),
            ('update_permissions', 'Update Permissions'),
            ('update_role', 'Update Role'),
            ('send_notification', 'Send Notification'),
            ('export_data', 'Export User Data'),
            ('delete_accounts', 'Delete Accounts (Careful!)')
        ],
        validators=[DataRequired()]
    )
    
    # Conditional fields based on operation type
    new_role = SelectField(
        'New Role (for role updates)',
        choices=[
            ('user', 'Standard User'),
            ('advanced_user', 'Advanced User'),
            ('lab_user', 'Lab User'),
            ('admin', 'Administrator')
        ],
        validators=[Optional()]
    )
    
    permissions_to_add = MultiCheckboxField(
        'Permissions to Add',
        choices=[
            ('basic_scan', 'Basic Scanning'),
            ('advanced_scan', 'Advanced Scanning'),
            ('deep_analysis', 'Deep Analysis'),
            ('network_connect', 'Network Connection'),
            ('report_generation', 'Report Generation'),
            ('api_access', 'API Access'),
            ('lab_features', 'Lab Features')
        ]
    )
    
    permissions_to_remove = MultiCheckboxField(
        'Permissions to Remove',
        choices=[
            ('basic_scan', 'Basic Scanning'),
            ('advanced_scan', 'Advanced Scanning'),
            ('deep_analysis', 'Deep Analysis'),
            ('network_connect', 'Network Connection'),
            ('report_generation', 'Report Generation'),
            ('api_access', 'API Access'),
            ('lab_features', 'Lab Features')
        ]
    )
    
    # Notification settings for bulk operations
    notification_subject = StringField(
        'Notification Subject',
        validators=[Length(max=200)],
        default='Account Update Notification'
    )
    
    notification_message = TextAreaField(
        'Notification Message',
        validators=[Length(max=2000)],
        render_kw={'rows': 5}
    )
    
    # Confirmation and safety
    confirm_operation = BooleanField(
        'I confirm this bulk operation',
        validators=[DataRequired(message='Please confirm the bulk operation')]
    )
    
    admin_password = PasswordField(
        'Admin Password (for confirmation)',
        validators=[DataRequired(message='Admin password required for bulk operations')]
    )
    
    # Operation notes
    operation_notes = TextAreaField(
        'Operation Notes',
        validators=[Length(max=1000)],
        render_kw={'rows': 3, 'placeholder': 'Document the reason for this bulk operation...'}
    )
    
    submit = SubmitField('Execute Bulk Operation')
    
    def validate_selected_users(self, field):
        """Validate user selection"""
        if not field.data:
            raise ValidationError('At least one user must be selected')
        
        # Limit bulk operations to reasonable size
        if len(field.data) > 100:
            raise ValidationError('Maximum 100 users can be processed in one bulk operation')
    
    def validate_operation_type(self, field):
        """Validate operation type and required fields"""
        if field.data == 'update_role' and not self.new_role.data:
            raise ValidationError('New role must be specified for role update operations')
        
        if field.data == 'send_notification':
            if not self.notification_subject.data or not self.notification_message.data:
                raise ValidationError('Subject and message required for notification operations')
        
        if field.data == 'delete_accounts':
            if not self.operation_notes.data:
                raise ValidationError('Detailed notes required for account deletion operations')


class SystemMonitoringForm(FlaskForm):
    """System monitoring configuration form"""
    
    # Monitoring settings
    enable_real_time_monitoring = BooleanField('Enable Real-time System Monitoring', default=True)
    
    monitoring_interval_seconds = IntegerField(
        'Monitoring Interval (seconds)',
        validators=[
            DataRequired(),
            NumberRange(min=10, max=300, message="Must be between 10-300 seconds")
        ],
        default=30
    )
    
    # Alert thresholds
    cpu_alert_threshold = IntegerField(
        'CPU Usage Alert Threshold (%)',
        validators=[
            DataRequired(),
            NumberRange(min=50, max=95, message="Must be between 50-95%")
        ],
        default=80
    )
    
    memory_alert_threshold = IntegerField(
        'Memory Usage Alert Threshold (%)',
        validators=[
            DataRequired(),
            NumberRange(min=50, max=95, message="Must be between 50-95%")
        ],
        default=85
    )
    
    disk_alert_threshold = IntegerField(
        'Disk Usage Alert Threshold (%)',
        validators=[
            DataRequired(),
            NumberRange(min=70, max=95, message="Must be between 70-95%")
        ],
        default=90
    )
    
    # Model performance monitoring
    model_accuracy_threshold = DecimalField(
        'Model Accuracy Alert Threshold',
        validators=[
            DataRequired(),
            NumberRange(min=0.5, max=0.99, message="Must be between 0.5-0.99")
        ],
        default=0.85,
        places=2
    )
    
    model_latency_threshold_ms = IntegerField(
        'Model Response Time Alert Threshold (ms)',
        validators=[
            DataRequired(),
            NumberRange(min=50, max=5000, message="Must be between 50-5000 ms")
        ],
        default=200
    )
    
    # Alert notifications
    enable_email_alerts = BooleanField('Enable Email Alerts', default=True)
    alert_email_addresses = TextAreaField(
        'Alert Email Addresses (one per line)',
        validators=[Length(max=1000)],
        render_kw={'rows': 3}
    )
    
    # System maintenance
    auto_cleanup_logs = BooleanField('Automatically Clean Old Logs', default=True)
    auto_backup_database = BooleanField('Automatically Backup Database', default=True)
    
    backup_interval_hours = IntegerField(
        'Backup Interval (hours)',
        validators=[
            NumberRange(min=1, max=168, message="Must be between 1-168 hours")
        ],
        default=24
    )
    
    submit = SubmitField('Update Monitoring Settings')
    
    def validate_alert_email_addresses(self, field):
        """Validate email addresses"""
        if field.data:
            emails = [email.strip() for email in field.data.split('\n') if email.strip()]
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            
            for email in emails:
                if not re.match(email_pattern, email):
                    raise ValidationError(f'Invalid email address: {email}')


class ModelPerformanceForm(FlaskForm):
    """AI model performance monitoring form"""
    
    # Model selection for monitoring
    selected_models = MultiCheckboxField(
        'Models to Monitor',
        choices=[
            ('cnn_model', 'Core CNN Model (Vulnerability Detection)'),
            ('lstm_model', 'Main LSTM Model (Behavioral Analysis)'),
            ('lstm_production', 'Production LSTM Model'),
            ('gnn_model', 'GNN Model (Topology Analysis)'),
            ('crypto_bert', 'Crypto-BERT Model (Protocol Analysis)'),
            ('cnn_lstm_hybrid', 'CNN-LSTM Hybrid Model'),
            ('attention_model', 'Attention Model'),
            ('random_forest', 'Random Forest Model'),
            ('gradient_boosting', 'Gradient Boosting Model'),
            ('ensemble_fusion', 'Ensemble Fusion Model')
        ],
        default=['cnn_model', 'lstm_model', 'ensemble_fusion']
    )
    
    # Performance metrics to track
    metrics_to_track = MultiCheckboxField(
        'Performance Metrics',
        choices=[
            ('accuracy', 'Prediction Accuracy'),
            ('precision', 'Precision Score'),
            ('recall', 'Recall Score'),
            ('f1_score', 'F1 Score'),
            ('inference_time', 'Inference Time'),
            ('memory_usage', 'Memory Usage'),
            ('confidence_scores', 'Confidence Scores'),
            ('model_agreement', 'Inter-model Agreement')
        ],
        default=['accuracy', 'inference_time', 'confidence_scores']
    )
    
    # Monitoring time range
    monitoring_period = SelectField(
        'Monitoring Period',
        choices=[
            ('1_hour', 'Last 1 Hour'),
            ('6_hours', 'Last 6 Hours'),
            ('24_hours', 'Last 24 Hours'),
            ('7_days', 'Last 7 Days'),
            ('30_days', 'Last 30 Days')
        ],
        default='24_hours'
    )
    
    # Alert settings
    enable_performance_alerts = BooleanField('Enable Performance Alerts', default=True)
    
    accuracy_drop_threshold = DecimalField(
        'Accuracy Drop Alert Threshold',
        validators=[
            NumberRange(min=0.01, max=0.5, message="Must be between 0.01-0.5")
        ],
        default=0.05,
        places=2
    )
    
    latency_increase_threshold = IntegerField(
        'Latency Increase Alert Threshold (%)',
        validators=[
            NumberRange(min=10, max=500, message="Must be between 10-500%")
        ],
        default=50
    )
    
    # Model retraining settings
    auto_retrain_enabled = BooleanField('Enable Automatic Model Retraining')
    retrain_accuracy_threshold = DecimalField(
        'Retrain if Accuracy Below',
        validators=[
            NumberRange(min=0.5, max=0.95, message="Must be between 0.5-0.95")
        ],
        default=0.80,
        places=2
    )
    
    submit = SubmitField('Update Model Monitoring')


# Form validation helper functions
def validate_approval_decision(form, field):
    """Custom validator for approval decisions"""
    if field.data == 'approve' and not form.admin_comments.data:
        raise ValidationError('Comments required for approval decisions')


def validate_bulk_operation_safety(form, field):
    """Custom validator for bulk operations safety"""
    dangerous_operations = ['delete_accounts', 'deactivate']
    if field.data in dangerous_operations:
        if not form.operation_notes.data or len(form.operation_notes.data) < 50:
            raise ValidationError('Detailed notes (50+ characters) required for dangerous operations')


def validate_network_settings(form, field):
    """Custom validator for network configuration"""
    if field.data and not re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', field.data):
        raise ValidationError('Invalid network format. Use CIDR notation (e.g., 192.168.1.0/24)')