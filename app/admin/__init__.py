"""
Admin Blueprint Initialization
Wi-Fi Security System - Admin Panel Module

This module initializes the admin blueprint for administrative functions
including user management, approval workflow, and system monitoring.

Author: Wi-Fi Security System
Version: 1.0
"""

from flask import Blueprint

# Create admin blueprint
admin_bp = Blueprint(
    'admin', 
    __name__, 
    template_folder='../templates/admin',
    static_folder='../static'
)

# Import routes after blueprint creation to avoid circular imports
try:
    from . import simple_routes
    print("[OK] Simple admin routes imported successfully")
except Exception as e:
    print(f"[ERROR] Simple admin routes import failed: {e}")
    import traceback
    traceback.print_exc()

try:
    from . import routes
    print("[OK] Admin routes imported successfully")
except Exception as e:
    print(f"[ERROR] Admin routes import failed: {e}")
    import traceback
    traceback.print_exc()

try:
    from . import forms
    print("[OK] Admin forms imported successfully") 
except Exception as e:
    print(f"[ERROR] Admin forms import failed: {e}")

try:
    from . import utils
    print("[OK] Admin utils imported successfully")
except Exception as e:
    print(f"[ERROR] Admin utils import failed: {e}")

try:
    from . import advanced_routes
    print("[OK] Advanced admin routes imported successfully")
except Exception as e:
    print(f"[ERROR] Advanced admin routes import failed: {e}")
    import traceback
    traceback.print_exc()

# Admin blueprint configuration
admin_bp.config = {
    'ADMIN_REQUIRED': True,
    'APPROVAL_WORKFLOW_ENABLED': True,
    'SYSTEM_MONITORING_ENABLED': True,
    'AUDIT_LOGGING_ENABLED': True,
}

# Admin panel features
ADMIN_FEATURES = {
    'user_management': True,
    'approval_requests': True, 
    'system_monitoring': True,
    'model_performance': True,
    'audit_logs': True,
    'security_settings': True,
    'bulk_operations': True,
}

# Admin routes configuration
ADMIN_ROUTES = {
    'dashboard': '/dashboard',
    'users': '/users',
    'approvals': '/approvals', 
    'system_monitor': '/system-monitor',
    'model_performance': '/model-performance',
    'audit_logs': '/audit-logs',
    'security_settings': '/security-settings',
    'bulk_operations': '/bulk-operations',
}

def init_admin_module():
    """
    Initialize admin module with required configurations
    """
    # Set up admin-specific logging
    import logging
    admin_logger = logging.getLogger('admin')
    admin_logger.setLevel(logging.INFO)
    
    # Configure admin session settings
    admin_bp.config['SESSION_TIMEOUT'] = 3600  # 1 hour
    admin_bp.config['MAX_CONCURRENT_ADMINS'] = 10
    
    return admin_bp

def register_admin_handlers():
    """
    Register admin-specific error handlers and context processors
    """
    @admin_bp.errorhandler(403)
    def admin_forbidden(error):
        from flask import render_template
        return render_template('errors/403.html'), 403
    
    @admin_bp.errorhandler(404)
    def admin_not_found(error):
        from flask import render_template
        return render_template('errors/404.html'), 404
    
    @admin_bp.context_processor
    def inject_admin_context():
        """Inject admin-specific context variables"""
        return {
            'admin_features': ADMIN_FEATURES,
            'admin_routes': ADMIN_ROUTES,
        }

# Initialize admin handlers
register_admin_handlers()

# Export admin blueprint
__all__ = ['admin_bp', 'init_admin_module', 'ADMIN_FEATURES', 'ADMIN_ROUTES']