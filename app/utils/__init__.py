"""
Wi-Fi Security System - Utilities Package
=========================================

This package contains all utility modules for the Wi-Fi Security System.
Provides centralized access to email functionality, PDF generation, validation,
decorators, and helper functions as specified in the project documentation.

Available Modules:
- email_sender: Email functionality and communication
- pdf_generator: PDF report generation for scan results
- validators: Comprehensive data validation utilities
- decorators: Custom Flask decorators for common functionality
- helpers: General utility and helper functions

Usage:
    from app.utils import EmailSender, PDFGenerator, InputValidator
    from app.utils.decorators import login_required, admin_required
    from app.utils.helpers import format_timestamp, generate_unique_id
"""


#app/utils/__init__.py

# Import all utility classes and functions for easy access
from .email_sender import (
    EmailSender,
    EmailTemplate,
    EmailQueue,
    EmailValidator
)

from .pdf_generator import (
    PDFGenerator,
    ReportTemplate,
    ChartGenerator,
    ReportFormatter
)

from .validators import (
    InputValidator,
    NetworkValidator,
    SecurityValidator,
    FileValidator
)

from .decorators import (
    AuthDecorator,
    RateLimitDecorator,
    LoggingDecorator,
    CacheDecorator,
    login_required,
    admin_required,
    rate_limit,
    log_activity,
    cache_result,
    validate_json,
    require_api_key,
    measure_performance
)

from .helpers import (
    UtilityHelper,
    FormatHelper,
    DateTimeHelper,
    SecurityHelper,
    format_timestamp,
    calculate_time_difference,
    generate_unique_id,
    format_file_size,
    encrypt_data,
    decrypt_data,
    generate_secure_filename,
    create_backup
)

# Package version and metadata
__version__ = "1.0.0"
__author__ = "Wi-Fi Security System Team"
__description__ = "Utility modules for Wi-Fi vulnerability detection and security analysis"

# Export all utility classes and functions
__all__ = [
    # Email functionality
    'EmailSender',
    'EmailTemplate', 
    'EmailQueue',
    'EmailValidator',
    
    # PDF generation
    'PDFGenerator',
    'ReportTemplate',
    'ChartGenerator',
    'ReportFormatter',
    
    # Validation utilities
    'InputValidator',
    'NetworkValidator',
    'SecurityValidator',
    'FileValidator',
    
    # Decorator classes
    'AuthDecorator',
    'RateLimitDecorator',
    'LoggingDecorator',
    'CacheDecorator',
    
    # Decorator functions
    'login_required',
    'admin_required',
    'rate_limit',
    'log_activity',
    'cache_result',
    'validate_json',
    'require_api_key',
    'measure_performance',
    
    # Helper classes
    'UtilityHelper',
    'FormatHelper',
    'DateTimeHelper',
    'SecurityHelper',
    
    # Helper functions
    'format_timestamp',
    'calculate_time_difference',
    'generate_unique_id',
    'format_file_size',
    'encrypt_sensitive_data',
    'decrypt_sensitive_data',
    'generate_secure_filename',
    'create_backup'
]

# Package initialization function
def initialize_utils(app=None):
    """
    Initialize utilities package with Flask app configuration.
    
    Args:
        app: Flask application instance
        
    Returns:
        dict: Initialized utility instances
    """
    if app is None:
        return None
        
    # Initialize utility instances with app config
    utils = {
        'email_sender': EmailSender(app),
        'pdf_generator': PDFGenerator(app),
        'input_validator': InputValidator(app),
        'network_validator': NetworkValidator(app),
        'security_validator': SecurityValidator(app),
        'file_validator': FileValidator(app)
    }
    
    # Set up utility configurations
    configure_utilities(app, utils)
    
    return utils

def configure_utilities(app, utils):
    """
    Configure utility instances with application settings.
    
    Args:
        app: Flask application instance
        utils: Dictionary of utility instances
    """
    # Configure email settings
    if hasattr(app.config, 'MAIL_SERVER'):
        utils['email_sender'].configure_smtp(
            server=app.config.get('MAIL_SERVER'),
            port=app.config.get('MAIL_PORT', 587),
            username=app.config.get('MAIL_USERNAME'),
            password=app.config.get('MAIL_PASSWORD'),
            use_tls=app.config.get('MAIL_USE_TLS', True)
        )
    
    # Configure PDF generation settings
    utils['pdf_generator'].configure_templates(
        template_dir=app.config.get('PDF_TEMPLATE_DIR', 'templates/pdf'),
        output_dir=app.config.get('PDF_OUTPUT_DIR', 'reports'),
        company_logo=app.config.get('COMPANY_LOGO_PATH'),
        company_name=app.config.get('COMPANY_NAME', 'Wi-Fi Security System')
    )
    
    # Configure validation settings
    utils['security_validator'].configure_security(
        max_file_size=app.config.get('MAX_FILE_SIZE', 16 * 1024 * 1024),  # 16MB
        allowed_extensions=app.config.get('ALLOWED_EXTENSIONS', ['.pdf', '.txt', '.jpg', '.png']),
        password_min_length=app.config.get('PASSWORD_MIN_LENGTH', 8),
        require_special_chars=app.config.get('REQUIRE_SPECIAL_CHARS', True)
    )

# Utility function to get all available validators
def get_validators():
    """
    Get all available validator instances.
    
    Returns:
        dict: Dictionary of validator instances
    """
    return {
        'input': InputValidator(),
        'network': NetworkValidator(),
        'security': SecurityValidator(),
        'file': FileValidator()
    }

# Utility function to get all available decorators
def get_decorators():
    """
    Get all available decorator functions.
    
    Returns:
        dict: Dictionary of decorator functions
    """
    return {
        'login_required': login_required,
        'admin_required': admin_required,
        'rate_limit': rate_limit,
        'log_activity': log_activity,
        'cache_result': cache_result,
        'validate_json': validate_json,
        'require_api_key': require_api_key,
        'measure_performance': measure_performance
    }

# Utility function to get all helper functions
def get_helpers():
    """
    Get all available helper functions.
    
    Returns:
        dict: Dictionary of helper functions
    """
    return {
        'format_timestamp': format_timestamp,
        'calculate_time_difference': calculate_time_difference,
        'generate_unique_id': generate_unique_id,
        'format_file_size': format_file_size,
        'encrypt_sensitive_data': encrypt_data,
        'decrypt_sensitive_data': decrypt_data,
        'generate_secure_filename': generate_secure_filename,
        'create_backup': create_backup
    }

# Package information
def get_package_info():
    """
    Get package information and metadata.
    
    Returns:
        dict: Package information
    """
    return {
        'name': 'app.utils',
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'modules': [
            'email_sender',
            'pdf_generator', 
            'validators',
            'decorators',
            'helpers'
        ],
        'classes': len([cls for cls in __all__ if cls.endswith('Validator') or cls.endswith('Generator') or cls.endswith('Sender') or cls.endswith('Helper') or cls.endswith('Decorator')]),
        'functions': len([func for func in __all__ if not func.endswith('Validator') and not func.endswith('Generator') and not func.endswith('Sender') and not func.endswith('Helper') and not func.endswith('Decorator')])
    }