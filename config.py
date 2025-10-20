import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration class with common settings"""
    
    # Application Settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    APP_NAME = 'Wi-Fi Security System'
    VERSION = '1.0.0'
    
    # Security and Lab Mode Configuration
    LAB_MODE_ENABLED = os.environ.get('LAB_MODE_ENABLED', 'True').lower() in ('true', '1', 'yes', 'on')
    ADMIN_USERS = os.environ.get('ADMIN_USERS', '1,admin,thrithwakapreethi57@gmail.com').split(',')
    
    # Database Configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    DATABASE_QUERY_TIMEOUT = 30
    
    # AI Model Configuration
    MODEL_BASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
    
    # AI Model Files and Specifications
    AI_MODELS = {
        'cnn_model': {
            'file': 'wifi_vulnerability_cnn_final.h5',
            'size': '20.5MB',
            'params': '2.3M',
            'input_dims': 32,
            'output_classes': 12,
            'accuracy_target': (94, 97),
            'inference_time': 50,  # milliseconds
            'description': 'Pattern recognition in network traffic and signal analysis'
        },
        'lstm_model': {
            'file': 'wifi_lstm_model.h5',
            'size': '17.9MB',
            'params': '1.8M',
            'input_dims': 48,
            'output_classes': 10,
            'accuracy_target': (91, 94),
            'inference_time': 60,
            'description': 'Temporal analysis of network behavior and attack sequence detection'
        },
        'lstm_production': {
            'file': 'wifi_lstm_production.h5',
            'size': '17.9MB',
            'params': '1.8M',
            'input_dims': 48,
            'output_classes': 10,
            'accuracy_target': (91, 94),
            'inference_time': 60,
            'description': 'Production-optimized temporal analysis with enhanced stability'
        },
        'gnn_model': {
            'file': 'gnn_wifi_vulnerability_model.h5',
            'size': '391KB',
            'params': '1.2M',
            'node_features': 24,
            'edge_features': 16,
            'output_classes': 8,
            'accuracy_target': (88, 92),
            'inference_time': 40,
            'description': 'Network topology analysis and vulnerability propagation modeling'
        },
        # 'crypto_bert': {
        #     'file': 'crypto_bert_enhanced.h5',
        #     'size': '110.5MB',
        #     'params': '4.2M',
        #     'max_tokens': 512,
        #     'output_classes': 15,
        #     'accuracy_target': (95, 98),
        #     'inference_time': 80,
        #     'description': 'Protocol analysis and cryptographic vulnerability detection'
        # },
        'cnn_lstm_hybrid': {
            'file': 'wifi_cnn_lstm_model.h5',
            'size': '2.8MB',
            'input_dims': 80,  # Combined CNN (32) + LSTM (48)
            'output_classes': 15,
            'accuracy_target': (92, 95),
            'inference_time': 70,
            'description': 'Combined spatial and temporal feature learning'
        },
        'attention_model': {
            'file': 'wifi_attention_model.h5',
            'size': '1KB',
            'input_dims': 32,
            'output_classes': 8,
            'accuracy_target': (90, 93),
            'inference_time': 30,
            'description': 'Attention-focused sequence analysis'
        },
        # 'random_forest': {
        #     'file': 'wifi_random_forest_model.pkl',
        #     'size': '125MB',
        #     'trees': 500,
        #     'input_dims': 64,
        #     'output_classes': 10,
        #     'accuracy_target': (85, 88),
        #     'inference_time': 20,
        #     'description': 'Tree-based ensemble classification'
        # },
        'gradient_boosting': {
            'file': 'wifi_gradient_boosting_model.pkl',
            'size': '647KB',
            'input_dims': 64,
            'output_classes': 10,
            'accuracy_target': (87, 90),
            'inference_time': 25,
            'description': 'Sequential model improvement with boosting'
        },
        'ensemble_metadata': {
            'file': 'wifi_ensemble_metadata.json',
            'size': '1KB',
            'description': 'Ensemble configuration and weights'
        }
    }
    
    # Ensemble Configuration
    ENSEMBLE_CONFIG = {
        'fusion_layers': [256, 128, 64],
        'confidence_layers': [32, 16],
        'severity_layers': [64, 32, 16],
        'total_params': '0.8M',
        'accuracy_target': (96, 99),
        'confidence_threshold': 0.90,
        'max_inference_time': 100,  # milliseconds
        'output_classes': 20
    }
    
    # Model Performance Monitoring
    MODEL_MONITORING = {
        'accuracy_threshold': 0.85,
        'drift_detection_window': 1000,
        'performance_check_interval': 3600,  # seconds
        'alert_threshold': 0.05,  # 5% performance drop
        'metrics_retention_days': 30
    }
    
    # CRITICAL FIX: Email configuration is set at class level
    # This ensures it's available when the class is loaded
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'wisecxai@gmail.com'
    MAIL_PASSWORD = 'cvpm kfnc okpr rtrf'
    MAIL_DEFAULT_SENDER = 'wisecxai@gmail.com'
    MAIL_SUPPRESS_SEND = False
    MAIL_ASCII_ATTACHMENTS = False
    
    # Frontend URL for email links
    FRONTEND_URL = os.environ.get('FRONTEND_URL') or 'http://localhost:5000'
    
    # Email Templates
    EMAIL_TEMPLATES = {
        'verification': 'email/verification.html',
        'password_reset': 'email/password_reset.html',
        'admin_notification': 'email/admin_notification.html',
        'scan_report': 'email/scan_report.html'
    }
    
    TEST_MAIL_CONNECTION = False
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Will be overridden in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security Settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    RATELIMIT_DEFAULT = "100 per hour"
    
    # Rate Limits for Different Operations
    RATE_LIMITS = {
        'login': '5 per minute',
        'register': '3 per minute',
        'scan': '10 per hour',
        'api_general': '100 per hour',
        'password_reset': '3 per hour',
        'email_verification': '5 per hour'
    }
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'pcap'}
    
    # PDF Report Configuration
    PDF_REPORT_CONFIG = {
        'page_size': 'A4',
        'margins': {'top': 1, 'right': 1, 'bottom': 1, 'left': 1},
        'font_family': 'Arial',
        'font_size': 12,
        'include_charts': True,
        'include_topology': True,
        'include_recommendations': True
    }
    
    # Wi-Fi Scanning Configuration
    WIFI_SCAN_CONFIG = {
        'timeout': 60,  # seconds - increased for deep scans
        'max_networks': 100,
        'include_hidden': True,
        'signal_threshold': -90,  # dBm
        'scan_interval': 5,  # seconds for real-time updates
        'channel_range': range(1, 15),  # Wi-Fi channels to scan
        'passive_scan_duration': 60  # seconds
    }
    
    # Network Analysis Configuration
    NETWORK_ANALYSIS = {
        'packet_capture_timeout': 60,
        'max_packet_count': 10000,
        'analysis_window': 300,  # seconds
        'anomaly_threshold': 0.95,
        'traffic_sampling_rate': 0.1
    }
    
    # Security Validation
    SECURITY_CONFIG = {
        'password_min_length': 8,
        'password_require_uppercase': True,
        'password_require_lowercase': True,
        'password_require_numbers': True,
        'password_require_special': True,
        'max_login_attempts': 5,
        'lockout_duration': 900,  # 15 minutes
        'session_timeout': 3600,  # 1 hour
        'csrf_token_expiry': 3600
    }
    
    # Logging Configuration
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
            },
            'detailed': {
                'format': '[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s',
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
                'formatter': 'default',
                'stream': 'ext://sys.stdout'
            },
            'file': {
                'class': 'logging.FileHandler',
                'level': 'DEBUG',
                'formatter': 'detailed',
                'filename': 'logs/app.log',
                'mode': 'a'
            },
            'security': {
                'class': 'logging.FileHandler',
                'level': 'WARNING',
                'formatter': 'detailed',
                'filename': 'logs/security.log',
                'mode': 'a'
            },
            'model_performance': {
                'class': 'logging.FileHandler',
                'level': 'INFO',
                'formatter': 'detailed',
                'filename': 'logs/model_performance.log',
                'mode': 'a'
            }
        },
        'loggers': {
            '': {
                'handlers': ['console', 'file'],
                'level': 'DEBUG',
                'propagate': False
            },
            'security': {
                'handlers': ['security'],
                'level': 'WARNING',
                'propagate': False
            },
            'model_performance': {
                'handlers': ['model_performance'],
                'level': 'INFO',
                'propagate': False
            }
        }
    }
    
    # Cache Configuration
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Performance Targets
    PERFORMANCE_TARGETS = {
        'web_response_time': 2.0,  # seconds
        'api_response_time': 0.5,  # seconds
        'concurrent_users': 50,
        'uptime_target': 99.9,  # percentage
        'model_memory_limit': 3.0,  # GB
        'ensemble_inference_time': 100  # milliseconds
    }
    
    @staticmethod
    def get_bool_env(var_name, default=False):
        """Convert environment variable string to boolean"""
        value = os.environ.get(var_name, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    # Passive Monitoring Configuration
    LAB_MODE_ENABLED = os.environ.get('LAB_MODE_ENABLED', 'False').lower() in ('true', '1', 'yes', 'on')
    ADMIN_USERS = os.environ.get('ADMIN_USERS', 'admin,superuser').split(',')
    NETWORK_ALLOWLIST_PATH = os.environ.get('NETWORK_ALLOWLIST_PATH', 'config/network_allowlist.json')
    
    # Passive Monitoring Limits
    MAX_CAPTURE_DURATION = int(os.environ.get('MAX_CAPTURE_DURATION', '3600'))  # 1 hour max
    MAX_CONCURRENT_CAPTURES = int(os.environ.get('MAX_CONCURRENT_CAPTURES', '3'))
    PACKET_BUFFER_SIZE = int(os.environ.get('PACKET_BUFFER_SIZE', '50000'))
    
    # Security thresholds for passive monitoring
    DEAUTH_ATTACK_THRESHOLD = int(os.environ.get('DEAUTH_ATTACK_THRESHOLD', '10'))
    PROBE_REQUEST_THRESHOLD = int(os.environ.get('PROBE_REQUEST_THRESHOLD', '50'))
    SIGNAL_ANOMALY_THRESHOLD = int(os.environ.get('SIGNAL_ANOMALY_THRESHOLD', '20'))
    
    @classmethod
    def init_app(cls, app):
        """Initialize app with email configuration - CRITICAL FIX"""
        import logging
        logger = logging.getLogger(__name__)
        
        # Force set email configuration directly on app config
        app.config.update({
            'MAIL_SERVER': cls.MAIL_SERVER,
            'MAIL_PORT': cls.MAIL_PORT,
            'MAIL_USE_TLS': cls.MAIL_USE_TLS,
            'MAIL_USE_SSL': cls.MAIL_USE_SSL,
            'MAIL_USERNAME': cls.MAIL_USERNAME,
            'MAIL_PASSWORD': cls.MAIL_PASSWORD,
            'MAIL_DEFAULT_SENDER': cls.MAIL_DEFAULT_SENDER,
            'MAIL_SUPPRESS_SEND': cls.MAIL_SUPPRESS_SEND,
            'MAIL_ASCII_ATTACHMENTS': cls.MAIL_ASCII_ATTACHMENTS,
            'FRONTEND_URL': cls.FRONTEND_URL
        })
        
        logger.info(f"🔧 Email configuration forced in app:")
        logger.info(f"  MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
        logger.info(f"  MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}")
        logger.info(f"  MAIL_PASSWORD: {'SET' if app.config.get('MAIL_PASSWORD') else 'NOT SET'}")
        logger.info(f"  MAIL_SUPPRESS_SEND: {app.config.get('MAIL_SUPPRESS_SEND')}")
    
    @staticmethod
    def get_model_path(model_name):
        """Get full path for AI model file"""
        if model_name in Config.AI_MODELS:
            return os.path.join(Config.MODEL_BASE_PATH, Config.AI_MODELS[model_name]['file'])
        return None
    
    @staticmethod
    def get_bool_env(var_name, default=False):
        """Convert environment variable string to boolean"""
        value = os.environ.get(var_name, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    @staticmethod
    def get_int_env(var_name, default=0):
        """Convert environment variable string to integer"""
        try:
            return int(os.environ.get(var_name, default))
        except (ValueError, TypeError):
            return default
    
    @staticmethod
    def get_list_env(var_name, default=None, separator=','):
        """Convert environment variable string to list"""
        if default is None:
            default = []
        value = os.environ.get(var_name, '')
        if not value:
            return default
        return [item.strip() for item in value.split(separator) if item.strip()]
    
    @staticmethod
    def validate_config():
        """Validate configuration settings"""
        validation_results = {
            'valid': True,
            'warnings': [],
            'errors': []
        }
        
        # Check critical email settings - now they're hardcoded so should always be valid
        if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
            validation_results['errors'].append("Missing critical email settings")
            validation_results['valid'] = False
        
        # Check secret key
        secret_key = os.environ.get('SECRET_KEY')
        if not secret_key or len(secret_key) < 32:
            validation_results['warnings'].append("SECRET_KEY should be at least 32 characters long")
        
        # Validate model files exist (only if model loading is enabled)
        if Config.get_bool_env('ENABLE_MODEL_LOADING', True):
            missing_models = []
            for model_name, config in Config.AI_MODELS.items():
                if 'file' in config:
                    model_path = Config.get_model_path(model_name)
                    if model_path and not os.path.exists(model_path):
                        missing_models.append(config['file'])
            
            if missing_models:
                validation_results['warnings'].append(f"Missing model files: {', '.join(missing_models)}")
        
        # Log validation results
        import logging
        logger = logging.getLogger(__name__)
        
        if validation_results['errors']:
            for error in validation_results['errors']:
                logger.error(error)
        
        if validation_results['warnings']:
            for warning in validation_results['warnings']:
                logger.warning(warning)
        
        if validation_results['valid'] and not validation_results['warnings']:
            logger.info("Configuration validation passed successfully")
        
        return validation_results['valid']


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Database - Fixed the malformed URL issue
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi_security_dev.db')
    
    # CSRF settings based on environment
    WTF_CSRF_ENABLED = Config.get_bool_env('WTF_CSRF_ENABLED', False)
    
    # Security settings for development
    SESSION_COOKIE_SECURE = Config.get_bool_env('SESSION_COOKIE_SECURE', False)
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
    
    # Rate limiting - more relaxed for development
    RATE_LIMITS = {
        'login': os.environ.get('RATE_LIMIT_AUTH', '10 per minute'),
        'register': '5 per minute',
        'scan': os.environ.get('RATE_LIMIT_SCAN', '20 per hour'),
        'api_general': os.environ.get('RATE_LIMIT_API', '200 per hour'),
        'password_reset': '5 per hour',
        'email_verification': '10 per hour'
    }
    
    # Model loading configuration
    ENABLE_MODEL_LOADING = Config.get_bool_env('ENABLE_MODEL_LOADING', True)
    LOAD_ALL_MODELS_ON_STARTUP = Config.get_bool_env('LOAD_ALL_MODELS_ON_STARTUP', False)
    
    # Feature flags
    API_DOCUMENTATION_ENABLED = Config.get_bool_env('API_DOCUMENTATION_ENABLED', True)
    EMAIL_NOTIFICATIONS = Config.get_bool_env('EMAIL_NOTIFICATIONS', True)
    ADMIN_APPROVAL_REQUIRED = Config.get_bool_env('ADMIN_APPROVAL_REQUIRED', False)
    
    # Cache configuration
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    
    # Development tools
    DEV_TOOLS_ENABLED = Config.get_bool_env('DEV_TOOLS_ENABLED', True)
    SQLALCHEMY_ECHO = Config.get_bool_env('SQLALCHEMY_ECHO', False)
    
    # Email settings for development - ENSURE EMAILS ARE SENT
    MAIL_SUPPRESS_SEND = False  # Critical: Allow email sending in development
    
    @classmethod
    def init_app(cls, app):
        """Initialize development app with forced email config"""
        # Call parent init_app first
        Config.init_app(app)
        
        # Additional development-specific setup
        import logging
        logger = logging.getLogger(__name__)
        logger.info("🔧 Development configuration initialized with email support")


class ProductionConfig(Config):
    """Production configuration for Render deployment"""
    DEBUG = False
    TESTING = False
    
    # Database - Use PostgreSQL on Render with proper URL validation
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # Fix for Heroku/Render postgres:// URL issue
    @staticmethod
    def init_app(app):
        # Call parent init_app first
        Config.init_app(app)
        
        # Handle postgres:// to postgresql:// conversion for newer SQLAlchemy
        uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if uri and uri.startswith('postgres://'):
            app.config['SQLALCHEMY_DATABASE_URI'] = uri.replace('postgres://', 'postgresql://', 1)
        
        # Production email settings override
        app.config.update({
            'FRONTEND_URL': os.environ.get('FRONTEND_URL') or 'https://your-app.onrender.com',
            'SESSION_COOKIE_SECURE': True,
            'MAIL_SUPPRESS_SEND': False  # Ensure emails are sent in production
        })
    
    # Security settings
    SESSION_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    
    # Strict security
    WTF_CSRF_ENABLED = True
    
    # Production logging
    LOG_LEVEL = 'INFO'
    
    # Production rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL')
    
    # Enable all model loading
    ENABLE_MODEL_LOADING = True
    LOAD_ALL_MODELS_ON_STARTUP = True
    
    # Production performance settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Cache configuration for production
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')
    
    # Email settings for production - ENSURE EMAILS ARE SENT
    MAIL_SUPPRESS_SEND = False  # Critical: Allow email sending in production


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Disable email sending in tests
    MAIL_SUPPRESS_SEND = True
    
    # Disable model loading for faster tests
    ENABLE_MODEL_LOADING = False
    LOAD_ALL_MODELS_ON_STARTUP = False
    
    # Fast rate limiting for tests
    RATELIMIT_STORAGE_URL = 'memory://'
    
    # Test-specific settings
    LOGIN_DISABLED = False
    SECRET_KEY = 'test-secret-key'


def get_config(config_name=None):
    """Get configuration class based on environment"""
    config_name = config_name or os.environ.get('FLASK_ENV', 'development')
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig,
        'default': DevelopmentConfig
    }
    
    return configs.get(config_name, configs['default'])


# Initialize configuration validation
if __name__ == '__main__':
    # Get and validate configuration
    config = get_config()
    if config.validate_config():
        print("✅ Configuration validation passed!")
    else:
        print("❌ Configuration validation failed - check missing environment variables and model files")
    
    # Show email configuration
    print("\n📧 Email Configuration:")
    print(f"  Server: {Config.MAIL_SERVER}")
    print(f"  Port: {Config.MAIL_PORT}")
    print(f"  Username: {Config.MAIL_USERNAME}")
    print(f"  Password: {'SET' if Config.MAIL_PASSWORD else 'NOT SET'}")
    print(f"  TLS: {Config.MAIL_USE_TLS}")
    print(f"  Suppress Send: {Config.MAIL_SUPPRESS_SEND}")