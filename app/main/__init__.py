"""
Main Application Blueprint - Wi-Fi Security System
Purpose: Main application routes blueprint initialization
Contains: Dashboard and core functionality routes
"""

from flask import Blueprint

# Create main blueprint
bp = Blueprint('main', __name__)


# Import routes after blueprint creation to avoid circular imports
from . import routes, forms, utils

# Import advanced features routes
try:
    from . import advanced_features
    print("[OK] Advanced features routes imported successfully")
except Exception as e:
    print(f"[ERROR] Advanced features routes import failed: {e}")
    import traceback
    traceback.print_exc()

# Blueprint configuration
bp.config = {
    'BLUEPRINT_NAME': 'main',
    'URL_PREFIX': None,  # Main routes don't need prefix
    'TEMPLATE_FOLDER': 'templates/main',
    'STATIC_FOLDER': 'static',
    'STATIC_URL_PATH': '/main/static'
}

# Blueprint metadata for the application
BLUEPRINT_INFO = {
    'name': 'main',
    'description': 'Main application functionality including dashboard and core routes',
    'version': '1.0.0',
    'routes': [
        '/dashboard',
        '/current-wifi',
        '/deep-scan',
        '/search-wifi',
        '/connect-wifi',
        '/download-report/<scan_id>',
        '/scan-history',
        '/network-topology'
    ],
    'dependencies': [
        'app.models.user',
        'app.models.scan_results',
        'app.api.wifi_scanner',
        'app.api.vulnerability_analyzer',
        'app.api.model_predictor',
        'app.utils.decorators',
        'app.utils.helpers'
    ]
}

def init_main_blueprint(app):
    """
    Initialize the main blueprint with the Flask application
    
    Args:
        app: Flask application instance
        
    Returns:
        Blueprint: Configured main blueprint
    """
    # Register the blueprint with the application
    app.register_blueprint(bp)
    
    # Add any blueprint-specific configuration
    with app.app_context():
        # Initialize any main-specific components
        _setup_main_components()
    
    return bp

def _setup_main_components():
    """
    Setup main blueprint specific components
    Private function to initialize main application components
    """
    # Import components needed for main blueprint
    try:
        from app.wifi_core.scanner import WiFiScanner
        from app.ai_engine.model_loader import ModelLoader
        from app.utils.helpers import UtilityHelper
        
        # Initialize core components
        # Note: Actual initialization will be handled by respective modules
        pass
        
    except ImportError as e:
        # Handle import errors gracefully during development
        print(f"Warning: Could not import all main blueprint components: {e}")
        pass

# Export the blueprint for use in app factory
__all__ = ['bp', 'init_main_blueprint', 'BLUEPRINT_INFO']