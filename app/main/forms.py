"""
Wi-Fi Security System - Main Application Forms
File: app/main/forms.py
Purpose: Forms for main application functionality including Wi-Fi scanning, 
         network connection, admin approval requests, and report configuration
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, TextAreaField, SelectField, BooleanField, IntegerField, PasswordField
from wtforms.validators import DataRequired, Length, ValidationError, Optional, NumberRange, Email
from wtforms.widgets import TextArea
import re


class WiFiScanForm(FlaskForm):
    """Wi-Fi scanning configuration form"""
    
    # Scan configuration options
    scan_type = SelectField(
        'Scan Type',
        choices=[
            ('quick', 'Quick Scan - Basic network discovery'),
            ('deep', 'Deep Scan - AI-powered vulnerability analysis'),
            ('advanced', 'Advanced Scan - Comprehensive security audit')
        ],
        default='quick',
        validators=[DataRequired()]
    )
    
    # Target network specification (optional)
    target_ssid = StringField(
        'Target Network (Optional)',
        validators=[
            Optional(),
            Length(min=1, max=32, message="SSID must be between 1 and 32 characters")
        ],
        render_kw={
            "placeholder": "Leave empty to scan all networks",
            "class": "form-control"
        }
    )
    
    # Scan duration settings
    scan_duration = SelectField(
        'Scan Duration',
        choices=[
            ('30', '30 seconds - Quick discovery'),
            ('60', '1 minute - Standard scan'),
            ('120', '2 minutes - Thorough scan'),
            ('300', '5 minutes - Deep analysis')
        ],
        default='60',
        validators=[DataRequired()]
    )
    
    # Channel specification
    scan_channels = StringField(
        'Specific Channels (Optional)',
        validators=[
            Optional(),
            Length(max=50, message="Channel specification too long")
        ],
        render_kw={
            "placeholder": "e.g., 1,6,11 or leave empty for all channels",
            "class": "form-control"
        }
    )
    
    # Advanced scanning options
    include_hidden = BooleanField(
        'Scan for Hidden Networks',
        default=False,
        render_kw={"class": "form-check-input"}
    )
    
    passive_scan = BooleanField(
        'Enable Passive Scanning (Admin Only)',
        default=False,
        render_kw={"class": "form-check-input"}
    )
    
    ai_analysis = BooleanField(
        'Enable AI Vulnerability Analysis',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    def validate_scan_channels(self, field):
        """Validate channel specification format"""
        if field.data:
            # Check if channels are valid numbers separated by commas
            channels = field.data.replace(' ', '').split(',')
            for channel in channels:
                if channel:  # Skip empty strings
                    try:
                        ch_num = int(channel)
                        if not (1 <= ch_num <= 165):  # Valid Wi-Fi channels
                            raise ValidationError(f"Invalid channel number: {ch_num}")
                    except ValueError:
                        raise ValidationError(f"Invalid channel format: {channel}")
    
    def validate_scan_parameters(self):
        """Validate overall scan parameters"""
        # Custom validation logic for scan parameters
        if self.scan_type.data == 'advanced' and not self.ai_analysis.data:
            raise ValidationError("Advanced scan requires AI analysis to be enabled")
        
        if self.passive_scan.data and self.scan_type.data == 'quick':
            raise ValidationError("Passive scanning is not available for quick scans")


class NetworkConnectionForm(FlaskForm):
    """Network connection form for Wi-Fi networks"""
    
    # Network identification
    ssid = StringField(
        'Network Name (SSID)',
        validators=[
            DataRequired(message="Network name is required"),
            Length(min=1, max=32, message="SSID must be between 1 and 32 characters")
        ],
        render_kw={
            "placeholder": "Enter network name",
            "class": "form-control"
        }
    )
    
    # Security type selection
    security_type = SelectField(
        'Security Type',
        choices=[
            ('open', 'Open Network (No password)'),
            ('wep', 'WEP (Legacy encryption)'),
            ('wpa', 'WPA Personal'),
            ('wpa2', 'WPA2 Personal'),
            ('wpa3', 'WPA3 Personal'),
            ('enterprise', 'Enterprise (802.1X)')
        ],
        validators=[DataRequired()],
        render_kw={"class": "form-select"}
    )
    
    # Network password
    password = PasswordField(
        'Network Password',
        validators=[
            Optional(),
            Length(min=8, max=63, message="Wi-Fi password must be between 8 and 63 characters")
        ],
        render_kw={
            "placeholder": "Enter network password",
            "class": "form-control"
        }
    )
    
    # Enterprise authentication fields
    username = StringField(
        'Username (Enterprise only)',
        validators=[Optional()],
        render_kw={
            "placeholder": "Enterprise username",
            "class": "form-control"
        }
    )
    
    # Connection options
    auto_connect = BooleanField(
        'Connect Automatically',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    save_profile = BooleanField(
        'Save Connection Profile',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    test_connectivity = BooleanField(
        'Test Internet Connectivity',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    def validate_network_credentials(self):
        """Validate network credentials based on security type"""
        if self.security_type.data in ['wep', 'wpa', 'wpa2', 'wpa3']:
            if not self.password.data:
                raise ValidationError("Password is required for secured networks")
        
        if self.security_type.data == 'enterprise':
            if not self.username.data:
                raise ValidationError("Username is required for enterprise networks")
            if not self.password.data:
                raise ValidationError("Password is required for enterprise networks")
        
        if self.security_type.data == 'open' and self.password.data:
            raise ValidationError("Open networks do not require a password")
    
    def validate_password(self, field):
        """Validate Wi-Fi password strength and format"""
        if field.data and self.security_type.data in ['wpa', 'wpa2', 'wpa3']:
            password = field.data
            
            # Check for common weak passwords
            weak_passwords = [
                'password', '12345678', 'qwerty123', 'admin123',
                'password123', 'welcome123', 'internet'
            ]
            
            if password.lower() in weak_passwords:
                raise ValidationError("Please choose a stronger password")
            
            # WPA/WPA2/WPA3 password requirements
            if len(password) < 8:
                raise ValidationError("WPA passwords must be at least 8 characters long")
    
    def sanitize_network_input(self):
        """Sanitize network input data"""
        if self.ssid.data:
            # Remove potentially dangerous characters from SSID
            self.ssid.data = re.sub(r'[<>"\']', '', self.ssid.data.strip())
        
        if self.username.data:
            self.username.data = self.username.data.strip()


class AdminApprovalRequestForm(FlaskForm):
    """Admin approval request form for advanced features"""
    
    # Request type
    request_type = SelectField(
        'Request Type',
        choices=[
            ('deep_scan', 'Deep Vulnerability Scanning'),
            ('passive_scan', 'Passive Network Monitoring'),
            ('advanced_features', 'Advanced Security Features'),
            ('lab_access', 'Laboratory Testing Access'),
            ('api_access', 'Extended API Access')
        ],
        validators=[DataRequired()],
        render_kw={"class": "form-select"}
    )
    
    # Justification
    justification = TextAreaField(
        'Justification',
        validators=[
            DataRequired(message="Please provide justification for your request"),
            Length(min=50, max=1000, message="Justification must be between 50 and 1000 characters")
        ],
        render_kw={
            "placeholder": "Please explain why you need access to these advanced features...",
            "class": "form-control",
            "rows": 6
        }
    )
    
    # Contact information
    contact_email = StringField(
        'Contact Email',
        validators=[
            DataRequired(message="Contact email is required"),
            Email(message="Please enter a valid email address")
        ],
        render_kw={
            "placeholder": "your.email@domain.com",
            "class": "form-control"
        }
    )
    
    organization = StringField(
        'Organization/Institution',
        validators=[
            Optional(),
            Length(max=100, message="Organization name too long")
        ],
        render_kw={
            "placeholder": "Your organization or institution",
            "class": "form-control"
        }
    )
    
    # Supporting documentation
    evidence_file = FileField(
        'Supporting Documentation (Optional)',
        validators=[
            Optional(),
            FileAllowed(['pdf', 'doc', 'docx', 'txt'], 'Only PDF, DOC, DOCX, and TXT files allowed')
        ],
        render_kw={"class": "form-control"}
    )
    
    # Agreement checkboxes
    terms_agreement = BooleanField(
        'I agree to use these features responsibly and in accordance with applicable laws',
        validators=[DataRequired(message="You must agree to the terms")],
        render_kw={"class": "form-check-input"}
    )
    
    ethical_use = BooleanField(
        'I confirm this request is for legitimate security research or testing purposes',
        validators=[DataRequired(message="You must confirm ethical use")],
        render_kw={"class": "form-check-input"}
    )
    
    def validate_approval_request(self):
        """Validate the approval request"""
        # Additional validation for specific request types
        if self.request_type.data == 'lab_access':
            if not self.organization.data:
                raise ValidationError("Organization is required for lab access requests")
        
        # Check justification quality
        if self.justification.data:
            words = len(self.justification.data.split())
            if words < 20:
                raise ValidationError("Please provide a more detailed justification (at least 20 words)")


class ReportConfigurationForm(FlaskForm):
    """Report generation configuration form"""
    
    # Report type
    report_type = SelectField(
        'Report Type',
        choices=[
            ('summary', 'Executive Summary'),
            ('detailed', 'Detailed Technical Report'),
            ('compliance', 'Compliance Report'),
            ('custom', 'Custom Report')
        ],
        validators=[DataRequired()],
        render_kw={"class": "form-select"}
    )
    
    # Report format
    format_type = SelectField(
        'Report Format',
        choices=[
            ('pdf', 'PDF Document'),
            ('html', 'HTML Report'),
            ('json', 'JSON Data Export')
        ],
        default='pdf',
        validators=[DataRequired()],
        render_kw={"class": "form-select"}
    )
    
    # Content sections to include
    include_network_topology = BooleanField(
        'Include Network Topology Diagram',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    include_vulnerability_details = BooleanField(
        'Include Detailed Vulnerability Analysis',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    include_recommendations = BooleanField(
        'Include Security Recommendations',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    include_ai_predictions = BooleanField(
        'Include AI Model Predictions',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    include_risk_assessment = BooleanField(
        'Include Risk Assessment Matrix',
        default=True,
        render_kw={"class": "form-check-input"}
    )
    
    include_technical_appendix = BooleanField(
        'Include Technical Appendix',
        default=False,
        render_kw={"class": "form-check-input"}
    )
    
    # Custom report title
    custom_title = StringField(
        'Custom Report Title (Optional)',
        validators=[
            Optional(),
            Length(max=100, message="Title too long")
        ],
        render_kw={
            "placeholder": "Custom title for your report",
            "class": "form-control"
        }
    )
    
    # Additional notes
    additional_notes = TextAreaField(
        'Additional Notes (Optional)',
        validators=[
            Optional(),
            Length(max=500, message="Notes too long")
        ],
        render_kw={
            "placeholder": "Any additional information to include in the report...",
            "class": "form-control",
            "rows": 3
        }
    )
    
    def validate_report_configuration(self):
        """Validate report configuration"""
        # Ensure at least one content section is selected
        content_sections = [
            self.include_network_topology.data,
            self.include_vulnerability_details.data,
            self.include_recommendations.data,
            self.include_ai_predictions.data,
            self.include_risk_assessment.data,
            self.include_technical_appendix.data
        ]
        
        if not any(content_sections):
            raise ValidationError("Please select at least one content section for the report")


# Additional utility functions for form validation
def validate_network_ssid(ssid):
    """Validate SSID format and characters"""
    if not ssid:
        return False
    
    # SSID length check
    if len(ssid) > 32:
        return False
    
    # Check for invalid characters (basic validation)
    invalid_chars = ['<', '>', '"', "'", '&']
    for char in invalid_chars:
        if char in ssid:
            return False
    
    return True


def sanitize_form_input(input_string):
    """Sanitize form input to prevent XSS and injection attacks"""
    if not input_string:
        return input_string
    
    # Remove dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`']
    sanitized = input_string
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()


def validate_file_upload_security(filename):
    """Validate uploaded file security"""
    if not filename:
        return False
    
    # Check file extension
    allowed_extensions = ['.pdf', '.doc', '.docx', '.txt']
    file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    if f'.{file_ext}' not in allowed_extensions:
        return False
    
    # Check for potentially dangerous filenames
    dangerous_patterns = ['..', '/', '\\', '<', '>', '|', ':', '*', '?', '"']
    
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False
    
    return True