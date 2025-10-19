"""
Wi-Fi Security System - Flask Application Factory
Main application initialization with AI model integration
"""
#app/__init__.py

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
from flask import Flask

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
cache = Cache()
limiter = Limiter(key_func=get_remote_address)



def create_app(config_name=None):
    """
    Application factory function for creating Flask app instances
    
    Args:
        config_name (str): Configuration environment name
        
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Load configuration
    configure_app(app, config_name)
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Configure logging
    configure_logging(app)
    
    # Setup database (must be after extensions are initialized)
    setup_database(app)
    
    # Initialize AI models (after database setup)
    initialize_ai_models(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Configure error handlers
    configure_error_handlers(app)
    
    # Setup security headers
    configure_security_headers(app)
    
    # Initialize monitoring
    initialize_monitoring(app)
    
    return app

def configure_app(app, config_name):
    """
    Configure Flask application settings
    
    Args:
        app (Flask): Flask application instance
        config_name (str): Configuration environment name
    """
    try:
        from config import get_config
        
        # Determine configuration
        if config_name is None:
            config_name = os.environ.get('FLASK_ENV', 'development')
        
        config = get_config(config_name)
        app.config.from_object(config)
        
    except ImportError:
        # Fallback configuration if config.py doesn't exist
        app.config.update({
            'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
            'SQLALCHEMY_DATABASE_URI': os.environ.get('DATABASE_URL', 'sqlite:///wifi_security.db'),
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'MAIL_SERVER': os.environ.get('MAIL_SERVER', 'smtp.gmail.com'),
            'MAIL_PORT': int(os.environ.get('MAIL_PORT', 587)),
            'MAIL_USE_TLS': True,
            'MAIL_USERNAME': os.environ.get('MAIL_USERNAME'),
            'MAIL_PASSWORD': os.environ.get('MAIL_PASSWORD'),
            'ADMIN_EMAIL': os.environ.get('ADMIN_EMAIL', 'admin@wifisecurity.com'),
            'ADMIN_PASSWORD': os.environ.get('ADMIN_PASSWORD', 'AdminPassword123!'),
            'CACHE_TYPE': 'simple',
            'RATELIMIT_STORAGE_URL': 'memory://'
        })
    
    # Validate critical configuration
    validate_config(app)

def initialize_extensions(app):
    """
    Initialize Flask extensions
    
    Args:
        app (Flask): Flask application instance
    """
    try:
        # Database - Initialize first
        db.init_app(app)
        migrate.init_app(app, db)
        
        # Authentication
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
        login_manager.login_message_category = 'info'
        
        # User loader callback - Fixed to handle app context properly
        @login_manager.user_loader
        def load_user(user_id):
            try:
                from app.models.user import User
                return User.query.get(int(user_id))
            except ImportError:
                return None
            except Exception as e:
                app.logger.error(f"Error loading user {user_id}: {str(e)}")
                return None
        
        # Mail
        mail.init_app(app)
        
        # CSRF Protection
        csrf.init_app(app)
        
        # Caching
        cache.init_app(app)
        
        # Rate limiting
        limiter.init_app(app)
        
        app.logger.info("Extensions initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Failed to initialize extensions: {str(e)}")
        # Continue without failing extensions

def configure_logging(app):
    """
    Configure application logging
    
    Args:
        app (Flask): Flask application instance
    """
    if not app.debug and not app.testing:
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Main application log
        file_handler = RotatingFileHandler(
            'logs/app.log', 
            maxBytes=10240000, 
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        # Security log
        security_handler = RotatingFileHandler(
            'logs/security.log',
            maxBytes=10240000,
            backupCount=10
        )
        security_handler.setFormatter(logging.Formatter(
            '%(asctime)s SECURITY: %(message)s'
        ))
        security_handler.setLevel(logging.WARNING)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Wi-Fi Security System startup')

def setup_database(app):
    """
    Setup database tables and initial data
    
    Args:
        app (Flask): Flask application instance
    """
    with app.app_context():
        try:
            # Import all models to ensure they're registered
            models_imported = []
            
            try:
                from app.models.user import User
                models_imported.append("User")
            except ImportError:
                pass
            
            try:
                from app.models.scan_results import ScanResult
                models_imported.append("ScanResult")
            except ImportError:
                pass
            
            try:
                from app.models.admin_requests import AdminRequest
                models_imported.append("AdminRequest")
            except ImportError:
                pass
            
            try:
                from app.models.audit_logs import AuditLog
                models_imported.append("AuditLog")
            except ImportError:
                pass
            
            # Create all tables
            db.create_all()
            
            # Create default admin user if User model exists
            try:
                from app.models.user import User
                
                # Check if admin user already exists
                admin_email = app.config.get('ADMIN_EMAIL', 'admin@wifisecurity.com')
                existing_admin = User.query.filter_by(email=admin_email).first()
                
                if not existing_admin:
                    admin_user = User(
                        email=admin_email,
                        is_verified=True,
                        is_admin_approved=True,
                        role='admin',
                        created_at=datetime.utcnow()
                    )
                    admin_user.set_password(app.config.get('ADMIN_PASSWORD', 'AdminPassword123!'))
                    
                    # Use db session properly within app context
                    db.session.add(admin_user)
                    db.session.commit()
                    app.logger.info(f'Default admin user created: {admin_email}')
                else:
                    app.logger.info(f'Admin user already exists: {admin_email}')
                    
            except ImportError:
                app.logger.warning('User model not available, skipping admin user creation')
            except Exception as e:
                app.logger.error(f'Failed to create admin user: {str(e)}')
                db.session.rollback()
            
            app.logger.info(f'Database setup complete. Models imported: {models_imported}')
            
        except Exception as e:
            app.logger.error(f'Database setup failed: {str(e)}')
            try:
                db.session.rollback()
            except:
                pass

def initialize_ai_models(app):
    """
    Initialize AI models for vulnerability detection
    
    Args:
        app (Flask): Flask application instance
    """
    app.logger.info('Initializing AI models...')
    
    try:
        # Try to import AI modules
        try:
            from app.ai_engine.model_loader import ModelLoader
            
            # Initialize model loader (singleton pattern)
            model_loader = ModelLoader()
            
            # Load all AI models
            models = model_loader.load_all_models()
            
            # Store in app context
            app.model_loader = model_loader
            app.ensemble = None  # Initialize later if needed
            app.model_monitor = None  # Initialize later if needed
            
            # Count successfully loaded models
            loaded_count = sum(1 for success in models.values() if success)
            app.logger.info(f'AI initialization complete. Loaded {loaded_count}/{len(models)} models')
            
            # Initialize ensemble and monitoring only if models are loaded
            if loaded_count > 0:
                try:
                    from app.ai_engine.ensemble_predictor import EnsembleFusionModel
                    from app.ai_engine.model_monitor import ModelMonitor
                    
                    # Initialize ensemble fusion system
                    ensemble = EnsembleFusionModel()
                    app.ensemble = ensemble
                    
                    # Initialize model monitoring
                    model_monitor = ModelMonitor()
                    model_monitor.start_monitoring()
                    app.model_monitor = model_monitor
                    
                    app.logger.info('Ensemble and monitoring systems initialized')
                    
                except ImportError as e:
                    app.logger.warning(f'Ensemble/monitoring modules not available: {str(e)}')
        
        except ImportError as e:
            app.logger.warning(f'AI modules not available: {str(e)}')
            # Continue without AI models for basic functionality
            app.model_loader = None
            app.ensemble = None
            app.model_monitor = None
        
    except Exception as e:
        app.logger.error(f'AI model initialization failed: {str(e)}')
        # Continue without AI models for basic functionality
        app.model_loader = None
        app.ensemble = None
        app.model_monitor = None

def register_blueprints(app):
    """
    Register application blueprints
         
    Args:
        app (Flask): Flask application instance
    """
    blueprints_registered = 0
         
    # Authentication blueprint
    try:
        from app.auth import auth as auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
        blueprints_registered += 1
        app.logger.info("Auth blueprint registered successfully")
    except ImportError as e:
        app.logger.warning(f'Auth blueprint not available: {str(e)}')
         
    # Main application blueprint
    try:
        from app.main import bp as main_bp
        app.register_blueprint(main_bp)
        blueprints_registered += 1
        app.logger.info("Main blueprint registered successfully")
    except ImportError as e:
        app.logger.warning(f'Main blueprint not available: {str(e)}')
         
    # Admin panel blueprint (optional)
    try:
        from app.admin import admin_bp as admin_bp
        app.register_blueprint(admin_bp, url_prefix='/admin')
        blueprints_registered += 1
        app.logger.info("Admin blueprint registered successfully")
    except ImportError as e:
        app.logger.warning(f'Admin blueprint not available: {str(e)}')
         
    # API endpoints blueprint (optional)
    try:
        from app.api import api as api_bp
        app.register_blueprint(api_bp, url_prefix='/api')
        blueprints_registered += 1
        app.logger.info("API blueprint registered successfully")
    except ImportError as e:
        app.logger.warning(f'API blueprint not available: {str(e)}')
         
    # WiFi Scanner API blueprint - FIXED: Remove url_prefix since routes already include /api/wifi
    try:
        app.logger.info("Attempting to import WiFi Scanner blueprint...")
        from app.api.wifi_scanner import wifi_scanner_bp
        app.logger.info(f"WiFi Scanner blueprint imported: {wifi_scanner_bp}")
        
        # OPTION A: Remove url_prefix since routes already include /api/wifi/
        app.register_blueprint(wifi_scanner_bp, url_prefix='/api/wifi')  # NO url_prefix here
        
        blueprints_registered += 1
        app.logger.info("WiFi Scanner blueprint registered successfully")
        app.logger.info(f"WiFi Scanner blueprint rules: {[rule.rule for rule in wifi_scanner_bp.url_map.iter_rules()]}")
    except ImportError as e:
        app.logger.error(f'WiFi Scanner blueprint import failed: {str(e)}')
        app.logger.error(f'ImportError details: {type(e).__name__}: {e}')
    except Exception as e:
        app.logger.error(f'WiFi Scanner blueprint registration failed: {str(e)}')
        app.logger.error(f'Exception details: {type(e).__name__}: {e}')
         
    # Vulnerability Analyzer API blueprint (optional)
    try:
        from app.api.vulnerability_analyzer import vulnerability_bp
        app.register_blueprint(vulnerability_bp, url_prefix='/api/vulnerability')
        blueprints_registered += 1
        app.logger.info("Vulnerability Analyzer blueprint registered successfully")
    except ImportError as e:
        app.logger.warning(f'Vulnerability Analyzer blueprint not available: {str(e)}')
         
    # Model Predictor API blueprint (optional)
    try:
        from app.api.model_predictor import api_bp as model_api_bp
        app.register_blueprint(model_api_bp, url_prefix='/api/model')
        blueprints_registered += 1
        app.logger.info("Model Predictor blueprint registered successfully")
    except ImportError as e:
        app.logger.warning(f'Model Predictor blueprint not available: {str(e)}')
         
    # Register basic routes if no main blueprint is available
    if blueprints_registered == 0 or not any(bp.name == 'main' for bp in app.blueprints.values()):
        register_basic_routes(app)
         
    app.logger.info(f'{blueprints_registered} blueprints registered successfully')

def register_basic_routes(app):
    """Register basic routes if blueprints are not available"""
    
    @app.route('/')
    def index():
        """Basic landing page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Wi-Fi Security System</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                .container { max-width: 600px; margin: 0 auto; }
                .btn { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 5px; }
                .btn:hover { background-color: #0056b3; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Wi-Fi Security System</h1>
                <p>Welcome to the Wi-Fi Security System. Please login or register to continue.</p>
                <div>
                    <a href="/auth/login" class="btn">Login</a>
                    <a href="/auth/register" class="btn">Register</a>
                </div>
            </div>
        </body>
        </html>
        """
    
    @app.route('/dashboard')
    def dashboard():
        """Basic dashboard"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Wi-Fi Security System</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Dashboard</h1>
                <p>Welcome to your dashboard!</p>
                <a href="/auth/logout">Logout</a>
            </div>
        </body>
        </html>
        """

def configure_error_handlers(app):
    """
    Configure custom error handlers
    
    Args:
        app (Flask): Flask application instance
    """
    @app.errorhandler(404)
    def not_found_error(error):
        try:
            from flask import render_template
            return render_template('errors/404.html'), 404
        except:
            return """
            <html><body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1>404 - Page Not Found</h1>
            <p>The page you're looking for doesn't exist.</p>
            <a href="/">Go Home</a>
            </body></html>
            """, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        try:
            db.session.rollback()
        except:
            pass
        
        app.logger.error(f"Internal server error: {str(error)}")
        
        try:
            from flask import render_template
            return render_template('errors/500.html'), 500
        except:
            return """
            <html><body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1>500 - Internal Server Error</h1>
            <p>Something went wrong on our end.</p>
            <a href="/">Go Home</a>
            </body></html>
            """, 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        try:
            from flask import render_template
            return render_template('errors/403.html'), 403
        except:
            return """
            <html><body style="font-family: Arial; text-align: center; margin: 50px;">
            <h1>403 - Access Forbidden</h1>
            <p>You don't have permission to access this resource.</p>
            <a href="/">Go Home</a>
            </body></html>
            """, 403
    
    @app.errorhandler(429)
    def rate_limit_handler(e):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': getattr(e, 'retry_after', 60)
        }), 429

def configure_security_headers(app):
    """
    Configure security headers and middleware
    
    Args:
        app (Flask): Flask application instance
    """
    @app.after_request
    def security_headers(response):
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:;"
        )
        
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response
    
    @app.before_request
    def log_request_info():
        # Log security-relevant requests
        if request.endpoint and any(request.endpoint.startswith(prefix) for prefix in ['auth.', 'admin.', 'api.']):
            app.logger.info(f'Security request: {request.endpoint} from {request.remote_addr}')

def initialize_monitoring(app):
    """
    Initialize system monitoring and health checks
    
    Args:
        app (Flask): Flask application instance
    """
    @app.route('/health')
    def health_check():
        """Health check endpoint for monitoring"""
        try:
            # Check database connectivity
            with app.app_context():
                db.session.execute('SELECT 1')
            
            # Check AI models status
            models_status = 'healthy' if getattr(app, 'model_loader', None) else 'disabled'
            
            # Check cache connectivity
            cache_status = 'healthy'
            try:
                cache.get('health_check')
            except:
                cache_status = 'degraded'
            
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'database': 'connected',
                'ai_models': models_status,
                'cache': cache_status,
                'version': app.config.get('APP_VERSION', '1.0.0')
            })
            
        except Exception as e:
            app.logger.error(f'Health check failed: {str(e)}')
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 503
    
    @app.route('/metrics')
    def metrics():
        """Metrics endpoint for monitoring"""
        try:
            metrics_data = {
                'total_users': 0,
                'total_scans': 0,
                'active_sessions': 0,
                'model_performance': {},
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Try to get actual metrics if models are available
            try:
                from app.models.user import User
                with app.app_context():
                    metrics_data['total_users'] = User.query.count()
            except ImportError:
                pass
            
            try:
                from app.models.scan_results import ScanResult
                with app.app_context():
                    metrics_data['total_scans'] = ScanResult.query.count()
            except ImportError:
                pass
            
            return jsonify(metrics_data)
            
        except Exception as e:
            app.logger.error(f'Metrics collection failed: {str(e)}')
            return jsonify({'error': 'Metrics unavailable'}), 500

def validate_config(app):
    """
    Validate critical configuration settings
    
    Args:
        app (Flask): Flask application instance
    """
    required_configs = [
        'SECRET_KEY',
        'SQLALCHEMY_DATABASE_URI'
    ]
    
    # Optional configs with warnings
    optional_configs = [
        'MAIL_SERVER',
        'MAIL_USERNAME'
    ]
    
    missing_configs = []
    for config in required_configs:
        if not app.config.get(config):
            missing_configs.append(config)
    
    if missing_configs:
        app.logger.error(f'Missing required configuration: {missing_configs}')
        raise ValueError(f'Missing required configuration: {missing_configs}')
    
    # Check optional configs
    missing_optional = []
    for config in optional_configs:
        if not app.config.get(config):
            missing_optional.append(config)
    
    if missing_optional:
        app.logger.warning(f'Missing optional configuration: {missing_optional}')
    
    app.logger.info('Configuration validation passed')

# Context processors for templates
def register_context_processors(app):
    """
    Register template context processors
    
    Args:
        app (Flask): Flask application instance
    """
    @app.context_processor
    def inject_config():
        return {
            'APP_NAME': app.config.get('APP_NAME', 'Wi-Fi Security System'),
            'APP_VERSION': app.config.get('APP_VERSION', '1.0.0'),
            'CURRENT_YEAR': datetime.utcnow().year
        }
    
    @app.context_processor
    def inject_ai_status():
        loaded_models = []
        if getattr(app, 'model_loader', None):
            try:
                loaded_models = app.model_loader.get_loaded_models()
            except:
                loaded_models = []
        
        return {
            'AI_MODELS_LOADED': getattr(app, 'model_loader', None) is not None,
            'MODEL_COUNT': len(loaded_models)
        }


def register_template_filters(app):
    """
    Register custom template filters
    
    Args:
        app (Flask): Flask application instance
    """
    @app.template_filter('user_advanced_access')
    def user_advanced_access_filter(user_id):
        """Template filter to check user's advanced access status"""
        try:
            from app.models.approval_system import ApprovalSystemManager
            return ApprovalSystemManager.get_user_access_status(user_id)
        except Exception as e:
            # Log the error for debugging
            app.logger.error(f"Template filter error: {str(e)}")
            return {
                'has_access': False,
                'access_level': 'basic',
                'features': [],
                'can_use': False
            }
    
    # Add debug logging to confirm registration
    app.logger.info("Template filter 'user_advanced_access' registered successfully")

# CLI commands for management
def register_cli_commands(app):
    """
    Register CLI commands for application management
    
    Args:
        app (Flask): Flask application instance
    """
    @app.cli.command()
    def init_db():
        """Initialize the database."""
        with app.app_context():
            db.create_all()
            print('Database initialized.')
    
    @app.cli.command()
    def create_admin():
        """Create admin user."""
        try:
            from app.models.user import User
            
            email = input('Admin email: ')
            password = input('Admin password: ')
            
            with app.app_context():
                admin = User(
                    email=email,
                    is_verified=True,
                    is_admin_approved=True,
                    role='admin'
                )
                admin.set_password(password)
                
                db.session.add(admin)
                db.session.commit()
                print('Admin user created.')
        except ImportError:
            print('User model not available.')
    
    @app.cli.command()
    def reload_models():
        """Reload AI models."""
        if getattr(app, 'model_loader', None):
            app.model_loader.load_all_models()
            print('AI models reloaded.')
        else:
            print('AI models not initialized.')

# Initialize the application factory components
def init_app_components(app):
    """
    Initialize additional application components
    
    Args:
        app (Flask): Flask application instance
    """
    register_context_processors(app)
    register_template_filters(app)
    register_cli_commands(app)
    
    # Initialize WebSocket support for real-time updates
    try:
        from flask_socketio import SocketIO
        socketio = SocketIO(app, cors_allowed_origins="*")
        app.socketio = socketio
        
        @socketio.on('connect')
        def handle_connect():
            app.logger.info(f'Client connected: {request.sid}')
        
        @socketio.on('disconnect')
        def handle_disconnect():
            app.logger.info(f'Client disconnected: {request.sid}')
            
    except ImportError:
        app.logger.warning('SocketIO not available, real-time updates disabled')
        app.socketio = None

# Application factory with full initialization
def create_app_with_monitoring(config_name=None):
    """
    Enhanced application factory with comprehensive monitoring
    
    Args:
        config_name (str): Configuration environment name
        
    Returns:
        Flask: Fully configured Flask application instance
    """
    app = create_app(config_name)
    
    # Initialize additional components
    init_app_components(app)
    
    return app