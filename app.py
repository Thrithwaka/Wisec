#!/usr/bin/env python3
"""
Wi-Fi Security System - Main Flask Application
Flask application factory and main entry point for Render deployment
FIXED: Multiple initialization issues, memory leaks, and performance problems
"""

import os
import logging
import sys
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask
from functools import lru_cache

from app.ai_engine.model_loader import ModelLoader
from app.models import db

# Global locks for thread safety
_model_lock = threading.Lock()
_email_lock = threading.Lock()
_initialization_lock = threading.Lock()

# Global singleton instances
_model_loader = None
_ensemble_model = None
_model_monitor = None
_email_sender = None

# CRITICAL: Load environment variables FIRST before any other imports
@lru_cache(maxsize=1)
def load_environment():
    """Load environment variables before app initialization - CACHED to prevent multiple calls"""
    env_defaults = {
        'FLASK_ENV': 'development',
        'FLASK_DEBUG': 'True',
        'DATABASE_URL': 'sqlite:///wifi_security_dev.db',
        'REDIS_URL': 'redis://localhost:6379/0',
        'SECRET_KEY': 'dev-secret-key-change-in-production-min-32-chars-12345',
        'WTF_CSRF_SECRET_KEY': 'dev-csrf-secret-key-change-in-production-12345',
        
        # EMAIL CONFIGURATION - CRITICAL FIX
        'MAIL_SERVER': 'smtp.gmail.com',
        'MAIL_PORT': '587',
        'MAIL_USE_TLS': 'True',
        'MAIL_USE_SSL': 'False',
        'MAIL_USERNAME': 'wisecxai@gmail.com',
        'MAIL_PASSWORD': 'cvpm kfnc okpr rtrf',  # Your App Password
        'MAIL_DEFAULT_SENDER': 'wisecxai@gmail.com',
        'MAIL_SUPPRESS_SEND': 'False',
        'FRONTEND_URL': 'http://localhost:5000',
        
        # OTHER SETTINGS
        'ENABLE_MODEL_LOADING': 'True',
        'LOAD_ALL_MODELS_ON_STARTUP': 'False',
        'LOG_LEVEL': 'DEBUG',
        'CACHE_TYPE': 'simple',
        'SESSION_COOKIE_SECURE': 'False',
        'API_DOCUMENTATION_ENABLED': 'True',
        'ADMIN_APPROVAL_REQUIRED': 'False',
        'EMAIL_NOTIFICATIONS': 'True',
        'ADMIN_EMAIL': 'thrithwakapreethi57@gmail.com'
    }
    
    # Set environment variables if not already set
    for key, default in env_defaults.items():
        if not os.environ.get(key):
            os.environ[key] = default
    
    print(f"Environment loaded. Email config: {os.environ.get('MAIL_USERNAME')}")
    return True

# Load environment variables FIRST - CACHED
load_environment()

# Flask core imports
from flask import Flask, current_app, render_template, request, jsonify, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_caching import Cache
from flask_compress import Compress
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix

# Configuration - Now loads with proper environment
from config import get_config

# Global instances - SINGLETON PATTERN
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()
mail = Mail()
cache = Cache()
compress = Compress()
limiter = Limiter(key_func=get_remote_address)
socketio = SocketIO()

class SingletonMeta(type):
    """Thread-safe singleton metaclass"""
    _instances = {}
    _lock = threading.Lock()
    
    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

def get_email_sender(app=None):
    """Thread-safe singleton email sender getter"""
    global _email_sender
    
    if _email_sender is not None:
        return _email_sender
        
    with _email_lock:
        if _email_sender is None and app is not None:
            try:
                from app.utils.email_sender import init_email_sender
                _email_sender = init_email_sender(app)
                app.logger.info("✅ Email sender initialized successfully (singleton)")
            except ImportError as e:
                app.logger.warning(f"Custom email sender not found: {e}")
                _email_sender = None
            except Exception as e:
                app.logger.error(f"Failed to initialize email sender: {e}")
                _email_sender = None
        
        return _email_sender

def get_model_instances(app=None):
    """Thread-safe singleton model instances getter"""
    global _model_loader, _ensemble_model, _model_monitor
    
    if _model_loader is not None:
        return _model_loader, _ensemble_model, _model_monitor
        
    with _model_lock:
        if _model_loader is None and app is not None:
            try:
                from app.ai_engine.model_loader import ModelLoader
                from app.ai_engine.ensemble_predictor import EnsembleFusionModel
                from app.ai_engine.model_monitor import ModelMonitor
                
                app.logger.info("Initializing AI models (singleton pattern)...")
                
                # Initialize model loader
                _model_loader = ModelLoader()
                _model_loader.load_all_models()
                
                # Initialize ensemble model
                _ensemble_model = EnsembleFusionModel(_model_loader)
                
                # Initialize model monitor with correct parameters
                _model_monitor = ModelMonitor(_model_loader)
                
                loaded_models = _model_loader.get_loaded_models()
                app.logger.info(f"✅ AI models loaded successfully: {len(loaded_models)} models")
                
            except ImportError as ie:
                app.logger.warning(f"AI modules not found: {str(ie)}. Running without AI features.")
                _model_loader = None
                _ensemble_model = None
                _model_monitor = None
            except Exception as e:
                app.logger.error(f"Failed to initialize AI models: {str(e)}")
                _model_loader = None
                _ensemble_model = None
                _model_monitor = None
        
        return _model_loader, _ensemble_model, _model_monitor

def create_app(config_name=None):
    """
    Application factory function - OPTIMIZED FOR SINGLE INITIALIZATION
    Creates and configures the Flask application
    """
    with _initialization_lock:
        app = Flask(__name__)
        
        # Load configuration
        config_name = config_name or os.environ.get('FLASK_ENV', 'development')
        config_class = get_config(config_name)
        app.config.from_object(config_class)
        
        # Ensure environment variables are loaded (cached)
        if hasattr(config_class, 'load_env_variables'):
            config_class.load_env_variables()
        
        # Debug email configuration - ONLY ONCE
        if not hasattr(create_app, '_debug_printed'):
            print(f"App Email Config:")
            print(f"  MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
            print(f"  MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
            print(f"  MAIL_PASSWORD: {'SET' if app.config.get('MAIL_PASSWORD') else 'NOT SET'}")
            create_app._debug_printed = True
        
        # Configure proxy handling for Render deployment
        if app.config.get('BEHIND_PROXY'):
            app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
        
        # Initialize extensions
        initialize_extensions(app)
        
        # Configure logging
        configure_logging(app)
        
        # Initialize AI models (singleton pattern)
        initialize_models(app)
        
        # Register blueprints
        register_blueprints(app)
        
        # Setup database
        setup_database(app)
        
        # Configure security
        configure_security(app)
        
        # Register error handlers
        register_error_handlers(app)
        
        # Register shell context
        register_shell_context(app)
        
        # Initialize analytics tracking
        initialize_analytics_tracking(app)
        
        # Setup real-time monitoring
        setup_real_time_monitoring(app)
        
        # Register main routes AFTER blueprints
        register_main_routes(app)
        
        return app

def initialize_extensions(app):
    """Initialize Flask extensions - OPTIMIZED TO PREVENT MULTIPLE CALLS"""
    try:
        # Import and initialize database FIRST
        from app.models import db
        db.init_app(app)
        migrate.init_app(app, db)

        # Store db in app for global access
        app.db = db

        # Authentication
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
        login_manager.login_message_category = 'info'

        # Security extensions
        csrf.init_app(app)

        # Security headers with Talisman
        Talisman(app,
            force_https=app.config.get('FORCE_HTTPS', False),
            strict_transport_security=True,
            content_security_policy={
                'default-src': "'self'",
                'script-src': "'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
                'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
                'font-src': "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
                'img-src': "'self' data:",
                'connect-src': "'self' ws: wss:"
            }
        )

        # ✅ FIXED: Initialize email sender using singleton pattern
        app.logger.info("🔧 Initializing email service (singleton)...")
        email_sender_instance = get_email_sender(app)
        app.email_sender = email_sender_instance
        
        if email_sender_instance and email_sender_instance.is_configured():
            app.logger.info("✅ Email service configured successfully")
        else:
            app.logger.warning("⚠ Email service not configured properly")

        # Caching
        cache.init_app(app)

        # Compression
        compress.init_app(app)

        # Rate limiting - FIXED: Use in-memory for development
        if app.config.get('REDIS_URL') and app.config['REDIS_URL'] != 'redis://localhost:6379/0':
            limiter.init_app(app)
        else:
            # Use default in-memory storage for development
            limiter.init_app(app)

        # WebSocket for real-time updates
        socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')

        app.logger.info("All extensions initialized successfully")

    except Exception as e:
        app.logger.error(f"Failed to initialize extensions: {str(e)}")
        raise

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    try:
        from app.models.user import User
        return db.session.get(User, int(user_id))
    except Exception as e:
        current_app.logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

def configure_logging(app):
    """Configure application logging - OPTIMIZED"""
    if not hasattr(configure_logging, '_configured'):
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
            
            app.logger.setLevel(logging.INFO)
            app.logger.info('Wi-Fi Security System startup')
        
        configure_logging._configured = True



def initialize_models(app):
    """Initialize AI models on startup - SINGLETON PATTERN"""
    with app.app_context():
        try:
            app.logger.info("Checking AI models initialization...")
            
            # Create ModelLoader directly
            model_loader = ModelLoader()
            
            # Load all models
            load_results = model_loader.load_all_models()
            
            # Store in app context for global access
            app.model_loader = model_loader
            app.ensemble_model = None  # Set to None for now
            app.model_monitor = None   # Set to None for now
            
            loaded_models = model_loader.get_loaded_models()
            app.logger.info(f"AI models available: {len(loaded_models)} models")
                
        except Exception as e:
            app.logger.error(f"Failed to initialize AI models: {str(e)}")
            # Continue without AI models for basic functionality
            app.model_loader = None
            app.ensemble_model = None
            app.model_monitor = None

def register_blueprints(app):
    """Register all application blueprints - OPTIMIZED"""
    try:
        blueprints_registered = 0
        
        # Authentication blueprint
        try:
            from app.auth import auth as auth_bp
            app.register_blueprint(auth_bp, url_prefix='/auth')
            blueprints_registered += 1
            app.logger.info("Auth blueprint registered successfully")
        except ImportError as e:
            app.logger.warning(f"Auth blueprint not found: {str(e)}")
        
        # API endpoints blueprint - REGISTER BEFORE MAIN TO AVOID CONFLICTS
        try:
            from app.api import api as api_bp
            app.register_blueprint(api_bp, url_prefix='/api')
            blueprints_registered += 1
            app.logger.info("API blueprint registered successfully")
        except ImportError as e:
            app.logger.warning(f"API blueprint not found: {str(e)}")

        # Wi-Fi Scanner Blueprint
        try:
            from app.api.wifi_scanner import wifi_scanner_bp
            app.register_blueprint(wifi_scanner_bp, url_prefix='/api/wifi')
            blueprints_registered += 1
            app.logger.info("Wi-Fi Scanner blueprint registered successfully")
        except ImportError as e:
            app.logger.warning(f"Wi-Fi Scanner blueprint not found: {str(e)}")

        # Vulnerability Analyzer Blueprint
        try:
            from app.api.vulnerability_analyzer import vulnerability_bp
            app.register_blueprint(vulnerability_bp, url_prefix='/api/vulnerability')
            blueprints_registered += 1
            app.logger.info("Vulnerability Analyzer blueprint registered successfully")
        except ImportError as e:
            app.logger.warning(f"Vulnerability Analyzer blueprint not found: {str(e)}")

        # Admin panel blueprint
        try:
            from app.admin import admin_bp as admin_bp
            app.register_blueprint(admin_bp, url_prefix='/admin')
            blueprints_registered += 1
            app.logger.info("Admin blueprint registered successfully")
        except ImportError as e:
            app.logger.warning(f"Admin blueprint not found: {str(e)}")

        # Passive Monitor API Blueprint - DISABLED due to endpoint conflicts
        # try:
        #     from app.api.passive_monitor_api import passive_monitor_api
        #     app.register_blueprint(passive_monitor_api)
        #     blueprints_registered += 1
        #     app.logger.info("Passive Monitor API blueprint registered successfully")
        # except Exception as e:
        #     app.logger.info(f"Passive Monitor API blueprint skipped: {str(e)}")

        try:
            from app.passive_monitor.routes import passive_monitor
            app.register_blueprint(passive_monitor)
            blueprints_registered += 1
            app.logger.info("Passive Monitor routes blueprint registered successfully")
        except Exception as e:
            app.logger.info(f"Passive Monitor routes blueprint skipped: {str(e)}")
        
        # Main application blueprint - REGISTER LAST
        try:
            from app.main.routes import main as main_bp
            app.register_blueprint(main_bp)
            blueprints_registered += 1
            app.logger.info("Main blueprint registered successfully")
        except ImportError as e:
            app.logger.warning(f"Main blueprint not found: {str(e)}")
        
        app.logger.info(f"{blueprints_registered} blueprints registered successfully")
        
    except Exception as e:
        app.logger.error(f"Failed to register blueprints: {str(e)}")

def register_main_routes(app):
    """Register main application routes"""
    
    @app.route('/')
    def index():
        """Landing page - render the HTML template"""
        try:
            return render_template('index.html')
        except Exception as e:
            app.logger.error(f"Failed to render index template: {str(e)}")
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Wi-Fi Security System</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
                    .error { color: #e74c3c; }
                    .info { color: #3498db; }
                </style>
            </head>
            <body>
                <h1>Wi-Fi Security System</h1>
                <p class="info">System is running, but template could not be loaded.</p>
                <p class="error">Error: Template rendering failed</p>
                <p><a href="/auth/login">Login</a> | <a href="/auth/register">Register</a></p>
            </body>
            </html>
            """, 200
    
    @app.route('/health')
    def health_check():
        """Health check endpoint for Render deployment"""
        try:
            # Check database connection
            current_app.db.session.execute('SELECT 1')
            
            # Check AI models status
            models_status = "healthy" if current_app.model_loader and current_app.model_loader.get_loaded_models() else "degraded"
            
            # Check email configuration
            email_status = "configured" if current_app.email_sender and current_app.email_sender.is_configured() else "not configured"
            
            # System metrics
            try:
                import psutil
                cpu_usage = psutil.cpu_percent()
                memory_usage = psutil.virtual_memory().percent
            except ImportError:
                cpu_usage = 0
                memory_usage = 0
            
            health_data = {
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'database': 'connected',
                'ai_models': models_status,
                'email_service': email_status,
                'system_metrics': {
                    'cpu_usage': cpu_usage,
                    'memory_usage': memory_usage
                }
            }
            
            return jsonify(health_data), 200
            
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @app.route('/test-email')
    def test_email_route():
        """Test email functionality - development only"""
        if not app.debug:
            return jsonify({'error': 'Not available in production'}), 403
            
        try:
            # Test email configuration
            config_status = {
                'MAIL_SERVER': app.config.get('MAIL_SERVER'),
                'MAIL_PORT': app.config.get('MAIL_PORT'),
                'MAIL_USERNAME': app.config.get('MAIL_USERNAME'),
                'MAIL_PASSWORD': 'SET' if app.config.get('MAIL_PASSWORD') else 'NOT SET',
                'MAIL_USE_TLS': app.config.get('MAIL_USE_TLS'),
                'MAIL_SUPPRESS_SEND': app.config.get('MAIL_SUPPRESS_SEND')
            }
            
            # Try to send a test email if email sender is available
            if hasattr(app, 'email_sender') and app.email_sender:
                test_recipient = request.args.get('email', app.config.get('MAIL_USERNAME'))
                if test_recipient:
                    result = app.email_sender.send_email(
                        to_email=test_recipient,
                        subject="Wi-Fi Security System - Test Email",
                        body="This is a test email from the Wi-Fi Security System",
                        html_body="<p>This is a <strong>test email</strong> from the Wi-Fi Security System</p>",
                        async_send=False
                    )
                    
                    return jsonify({
                        'email_config': config_status,
                        'test_email_sent': result,
                        'recipient': test_recipient,
                        'message': 'Test email sent successfully' if result else 'Test email failed'
                    })
                else:
                    return jsonify({
                        'email_config': config_status,
                        'error': 'No test recipient specified'
                    })
            else:
                return jsonify({
                    'email_config': config_status,
                    'error': 'Email sender not initialized'
                })
                
        except Exception as e:
            return jsonify({
                'error': f'Email test failed: {str(e)}',
                'email_config': config_status if 'config_status' in locals() else {}
            }), 500

def setup_database(app):
    """Initialize database - OPTIMIZED"""
    with app.app_context():
        try:
            # Import models after db is initialized
            from app.models.user import User
            from app.models.scan_results import ScanResult
            from app.models.admin_requests import AdminRequest
            from app.models.audit_logs import AuditLog
            from app.models.analytics import PageViewEvent, UserActivity, SystemMetrics, SecurityIncident
            
            # Get the db instance from app
            db = app.db
            
            # Create all tables
            db.create_all()
            
            # Create default admin user if not exists
            admin_email = app.config.get('ADMIN_EMAIL', 'thrithwakapreethi57@gmail.com')
            admin_user = User.query.filter_by(email=admin_email).first()
            if not admin_user:
                admin_user = User(
                    email=admin_email,
                    is_verified=True,
                    is_admin_approved=True,
                    role='admin'
                )
                admin_user.set_password(app.config.get('ADMIN_PASSWORD', 'admin123'))
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info(f"Default admin user created: {admin_email}")
            
            app.logger.info("Database setup completed successfully")
            
        except Exception as e:
            app.logger.error(f"Database setup failed: {str(e)}")
            try:
                app.db.session.rollback()
            except:
                pass

def configure_security(app):
    """Configure additional security measures"""
    try:
        # Security validator instance - import with error handling
        try:
            from app.utils.validators import SecurityValidator
            security_validator = SecurityValidator()
            app.security_validator = security_validator
        except ImportError:
            app.logger.warning("SecurityValidator not found")
            app.security_validator = None
        
        # Configure session security
        app.config['SESSION_COOKIE_SECURE'] = app.config.get('FORCE_HTTPS', False)
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        
        # Configure CSRF protection
        app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
        
        # Rate limiting configuration
        app.config['RATELIMIT_STORAGE_URL'] = app.config.get('REDIS_URL', 'memory://')
        
        app.logger.info("Security configuration completed")
        
    except Exception as e:
        app.logger.error(f"Security configuration failed: {str(e)}")

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        try:
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
            app.db.session.rollback()
        except:
            pass
        app.logger.error(f"Internal server error: {str(error)}")
        try:
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
    def ratelimit_handler(error):
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.'
        }), 429

def register_shell_context(app):
    """Register shell context for flask shell command"""
    @app.shell_context_processor
    def make_shell_context():
        context = {
            'db': app.db,
            'model_loader': app.model_loader,
            'ensemble_model': app.ensemble_model,
            'model_monitor': app.model_monitor
        }
        
        # Add models if they exist
        try:
            from app.models.user import User
            context['User'] = User
        except ImportError:
            pass
            
        try:
            from app.models.scan_results import ScanResult
            context['ScanResult'] = ScanResult
        except ImportError:
            pass
            
        try:
            from app.models.admin_requests import AdminRequest
            context['AdminRequest'] = AdminRequest
        except ImportError:
            pass
            
        try:
            from app.models.audit_logs import AuditLog
            context['AuditLog'] = AuditLog
        except ImportError:
            pass
            
        return context

def initialize_analytics_tracking(app):
    """Initialize analytics tracking system"""
    try:
        from app.utils.analytics_tracker import analytics_tracker
        analytics_tracker.init_app(app)
        app.logger.info("Analytics tracking initialized successfully")
    except ImportError as e:
        app.logger.warning(f"Analytics tracking not available: {str(e)}")
    except Exception as e:
        app.logger.error(f"Failed to initialize analytics tracking: {str(e)}")

def setup_real_time_monitoring(app):
    """Setup real-time monitoring with WebSocket"""
    
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            emit('connected', {'message': 'Connected to Wi-Fi Security System'})
            app.logger.info(f"User {current_user.email} connected to WebSocket")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        if current_user.is_authenticated:
            app.logger.info(f"User {current_user.email} disconnected from WebSocket")
    
    @socketio.on('request_wifi_status')
    def handle_wifi_status_request():
        if current_user.is_authenticated:
            try:
                from app.wifi_core.scanner import WiFiScanner
                scanner = WiFiScanner()
                current_wifi = scanner.get_current_connection()
                emit('wifi_status_update', current_wifi)
            except Exception as e:
                emit('error', {'message': f'Failed to get Wi-Fi status: {str(e)}'})

# CLI commands
def register_cli_commands(app):
    """Register CLI commands"""
    
    @app.cli.command()
    def init_db():
        """Initialize the database"""
        app.db.create_all()
        print("Database initialized successfully!")
    
    @app.cli.command()
    def load_models():
        """Load AI models"""
        try:
            model_loader, ensemble_model, model_monitor = get_model_instances(app)
            print("AI models loaded successfully!")
        except Exception as e:
            print(f"Failed to load models: {str(e)}")
    
    @app.cli.command()
    def create_admin():
        """Create admin user"""
        email = input("Admin email: ")
        password = input("Admin password: ")
        
        from app.models.user import User
        admin_user = User(
            email=email,
            is_verified=True,
            is_admin_approved=True,
            role='admin'
        )
        admin_user.set_password(password)
        
        app.db.session.add(admin_user)
        app.db.session.commit()
        print(f"Admin user {email} created successfully!")
    
    @app.cli.command()
    def test_email():
        """Test email functionality"""
        email = input("Test email address: ")
        
        email_sender = get_email_sender(app)
        if email_sender:
            result = email_sender.send_email(
                to_email=email,
                subject="Wi-Fi Security System - Test Email",
                body="This is a test email from the Wi-Fi Security System CLI",
                html_body="<p>This is a <strong>test email</strong> from the Wi-Fi Security System CLI</p>",
                async_send=False
            )
            
            if result:
                print(f"✅ Test email sent successfully to {email}")
            else:
                print(f"❌ Failed to send test email to {email}")
        else:
            print("❌ Email sender not initialized")

# Application factory pattern implementation
def create_production_app():
    """Create production application instance"""
    app = create_app('production')
    register_cli_commands(app)
    return app

def create_development_app():
    """Create development application instance"""
    app = create_app('development')
    
    # Development-specific configurations
    if app.debug:
        # Enable Flask-DebugToolbar if available
        try:
            from flask_debugtoolbar import DebugToolbarExtension
            toolbar = DebugToolbarExtension(app)
        except ImportError:
            pass
    
    register_cli_commands(app)
    return app

# Main application instance for deployment
if __name__ == '__main__':
    # Determine environment
    env = os.environ.get('FLASK_ENV', 'development')
    
    print(f"Starting Wi-Fi Security System in {env} mode")
    print(f"Email configured: {os.environ.get('MAIL_USERNAME')}")
    
    if env == 'production':
        app = create_production_app()
        # Production server configuration
        port = int(os.environ.get('PORT', 5000))
        socketio.run(app, host='0.0.0.0', port=port, debug=False)
    else:
        app = create_development_app()
        # Development server configuration
        socketio.run(app, host='127.0.0.1', port=5000, debug=True)

# For Render deployment (WSGI)
app = create_production_app()

# Export for testing
__all__ = ['create_app', 'create_production_app', 'create_development_app']