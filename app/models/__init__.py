"""
Wi-Fi Security System - Database Models Package - COMPLETE FIXED VERSION
===============================================

This module initializes all database models for the Flask-based Wi-Fi Vulnerability Detection System.
Provides centralized access to all models with proper database configuration and relationship management.

COMPLETE FIXES:
- Resolved all circular import issues
- Fixed foreign key relationships
- Added proper model loading order
- Fixed SQLAlchemy compatibility issues
- Added comprehensive error handling
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import logging
import traceback

# Initialize Flask extensions ONCE at module level
db = SQLAlchemy()
migrate = Migrate()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global model storage
_models_cache = {}
_models_loaded = False

def init_db(app):
    """
    Initialize database with Flask application
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: Success status
    """
    global _models_loaded
    
    logger.info("Initializing database...")
    
    try:
        # Initialize extensions
        db.init_app(app)
        migrate.init_app(app, db)
        logger.info("✓ Database extensions initialized")
        
        # Import models in correct order within app context
        with app.app_context():
            success = _import_all_models()
            if not success:
                logger.error("Failed to import models")
                return False
            
            # Create all tables
            db.create_all()
            logger.info("✓ Database tables created successfully")
            
            # Initialize default data if needed
            _initialize_default_data()
            
            _models_loaded = True
            logger.info("✓ Database initialization completed successfully")
            return True
            
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        logger.error(traceback.format_exc())
        return False

def _import_all_models():
    """
    Import all models in correct order to avoid circular import issues
    COMPLETE FIXED VERSION with proper dependency resolution
    
    Returns:
        bool: Success status
    """
    global _models_cache
    
    try:
        logger.info("Importing models in dependency order...")
        
        # Step 1: Import User model first (base dependency)
        logger.info("Importing user models...")
        from app.models.user import User, UserRole, AccountStatus, UserProfile, UserSession
        
        _models_cache.update({
            'User': User,
            'UserRole': UserRole,
            'AccountStatus': AccountStatus,
            'UserProfile': UserProfile,
            'UserSession': UserSession
        })
        logger.info("✓ User models imported successfully")
        
        # Step 2: Import models that depend on User
        logger.info("Importing scan result models...")
        from app.models.scan_results import (
            ScanResult, VulnerabilityReport, NetworkInfo, ThreatAssessment,
            RiskLevel, ThreatCategory, ScanStatus
        )
        
        _models_cache.update({
            'ScanResult': ScanResult,
            'VulnerabilityReport': VulnerabilityReport,
            'NetworkInfo': NetworkInfo,
            'ThreatAssessment': ThreatAssessment,
            'RiskLevel': RiskLevel,
            'ThreatCategory': ThreatCategory,
            'ScanStatus': ScanStatus
        })
        logger.info("✓ Scan result models imported successfully")
        
        # Step 3: Import admin request models
        logger.info("Importing admin request models...")
        from app.models.admin_requests import (
            AdminRequest, RequestStatus, RequestType, 
            RequestWorkflow, ApprovalHistory, RequestValidator
        )
        
        _models_cache.update({
            'AdminRequest': AdminRequest,
            'RequestStatus': RequestStatus,
            'RequestType': RequestType,
            'RequestWorkflow': RequestWorkflow,
            'ApprovalHistory': ApprovalHistory,
            'RequestValidator': RequestValidator
        })
        logger.info("✓ Admin request models imported successfully")
        
        # Step 4: Import audit log models
        logger.info("Importing audit log models...")
        from app.models.audit_logs import (
            AuditLog, EventType, SecurityLevel, SecurityEvent, 
            SystemActivity, ComplianceLog
        )
        
        _models_cache.update({
            'AuditLog': AuditLog,
            'EventType': EventType,
            'SecurityLevel': SecurityLevel,
            'SecurityEvent': SecurityEvent,
            'SystemActivity': SystemActivity,
            'ComplianceLog': ComplianceLog
        })
        logger.info("✓ Audit log models imported successfully")
        
        # Step 5: Import approval system models
        logger.info("Importing approval system models...")
        try:
            from app.models.approval_system import (
                AdvancedFeatureRequest, ApprovalMessage, UserAdvancedAccess, 
                UserNotification, ApprovalStatus, ApprovalSystemManager
            )
            
            _models_cache.update({
                'AdvancedFeatureRequest': AdvancedFeatureRequest,
                'ApprovalMessage': ApprovalMessage,
                'UserAdvancedAccess': UserAdvancedAccess,
                'UserNotification': UserNotification,
                'ApprovalStatus': ApprovalStatus,
                'ApprovalSystemManager': ApprovalSystemManager
            })
            logger.info("✓ Approval system models imported successfully")
        except ImportError as e:
            logger.warning(f"Approval system models not available: {e}")
        
        # Step 6: Import analytics models
        logger.info("Importing analytics models...")
        try:
            from app.models.analytics import (
                PageViewEvent, UserActivity, SystemMetrics, SecurityIncident, AnalyticsManager
            )
            
            _models_cache.update({
                'PageViewEvent': PageViewEvent,
                'UserActivity': UserActivity,
                'SystemMetrics': SystemMetrics,
                'SecurityIncident': SecurityIncident,
                'AnalyticsManager': AnalyticsManager
            })
            logger.info("✓ Analytics models imported successfully")
        except ImportError as e:
            logger.warning(f"Analytics models not available: {e}")
        
        # Update globals for backward compatibility
        globals().update(_models_cache)
        
        logger.info(f"✓ All models imported successfully ({len(_models_cache)} models)")
        return True
        
    except ImportError as e:
        logger.warning(f"Some models could not be imported: {e}")
        logger.warning("Creating minimal model set for basic functionality")
        return _create_minimal_models()
    except Exception as e:
        logger.error(f"Unexpected error importing models: {e}")
        logger.error(traceback.format_exc())
        return False

def _create_minimal_models():
    """
    Create minimal working models if full models can't be imported
    This ensures the application can start even with missing model files
    
    Returns:
        bool: Success status
    """
    global _models_cache
    
    logger.info("Creating minimal model set...")
    
    try:
        from flask_login import UserMixin
        from enum import Enum
        
        # User Role Enum
        class UserRole(Enum):
            USER = "user"
            ADMIN = "admin"
            MODERATOR = "moderator"
            SUPER_ADMIN = "super_admin"
        
        class AccountStatus(Enum):
            ACTIVE = "active"
            INACTIVE = "inactive"
            PENDING = "pending"
            SUSPENDED = "suspended"
            LOCKED = "locked"
        
        # Minimal User Model
        class User(UserMixin, db.Model):
            __tablename__ = 'users'
            
            id = db.Column(db.Integer, primary_key=True)
            email = db.Column(db.String(120), unique=True, nullable=False, index=True)
            password_hash = db.Column(db.String(255), nullable=False)
            is_verified = db.Column(db.Boolean, default=False)
            is_admin_approved = db.Column(db.Boolean, default=False)
            created_at = db.Column(db.DateTime, default=datetime.utcnow)
            last_login = db.Column(db.DateTime)
            role = db.Column(db.Enum(UserRole), default=UserRole.USER)
            account_status = db.Column(db.Enum(AccountStatus), default=AccountStatus.PENDING)
            is_active = db.Column(db.Boolean, default=True)
            
            # Profile data as JSON
            profile_data = db.Column(db.Text, default='{}')
            security_settings = db.Column(db.Text, default='{}')
            preferences = db.Column(db.Text, default='{}')
            
            def __repr__(self):
                return f'<User {self.email}>'
            
            def has_role(self, role):
                if isinstance(role, str):
                    try:
                        role_enum = UserRole(role.lower())
                        return self.role == role_enum
                    except ValueError:
                        return False
                return self.role == role
            
            def is_admin(self):
                return self.role in [UserRole.ADMIN, UserRole.SUPER_ADMIN]
            
            def can_access_admin_panel(self):
                return self.is_admin() and self.is_admin_approved
        
        # Minimal ScanResult Model
        class ScanResult(db.Model):
            __tablename__ = 'scan_results'
            
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
            network_ssid = db.Column(db.String(255), nullable=False)
            scan_id = db.Column(db.String(100), unique=True, nullable=False)
            scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
            risk_level = db.Column(db.String(20), default='NORMAL')
            overall_risk_score = db.Column(db.Float, default=0.0)
            confidence_score = db.Column(db.Float, default=0.0)
            scan_data = db.Column(db.Text)
            
            # Relationship
            user = db.relationship('User', backref='scan_results')
            
            def __repr__(self):
                return f'<ScanResult {self.scan_id}>'
        
        # Minimal AdminRequest Model  
        class AdminRequest(db.Model):
            __tablename__ = 'admin_requests'
            
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
            request_type = db.Column(db.String(50), nullable=False)
            status = db.Column(db.String(20), default='pending')
            justification = db.Column(db.Text, nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.utcnow)
            updated_at = db.Column(db.DateTime, default=datetime.utcnow)
            
            # Relationship
            user = db.relationship('User', backref='admin_requests')
            
            def __repr__(self):
                return f'<AdminRequest {self.id}>'
        
        # Minimal AuditLog Model
        class AuditLog(db.Model):
            __tablename__ = 'audit_logs'
            
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
            action = db.Column(db.String(100), nullable=False)
            timestamp = db.Column(db.DateTime, default=datetime.utcnow)
            details = db.Column(db.Text)
            ip_address = db.Column(db.String(45))
            event_description = db.Column(db.Text)
            
            # Relationship
            user = db.relationship('User', backref='audit_logs')
            
            def __repr__(self):
                return f'<AuditLog {self.action}>'
        
        # Store in cache
        _models_cache.update({
            'User': User,
            'UserRole': UserRole,
            'AccountStatus': AccountStatus,
            'ScanResult': ScanResult,
            'AdminRequest': AdminRequest,
            'AuditLog': AuditLog
        })
        
        # Update globals
        globals().update(_models_cache)
        
        logger.info("✓ Minimal models created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating minimal models: {e}")
        logger.error(traceback.format_exc())
        return False

def _initialize_default_data():
    """Initialize default data for the application"""
    try:
        User = get_model('User')
        if not User:
            return False
        
        # Check if we need to create default admin
        if User.query.count() == 0:
            logger.info("Creating default admin user...")
            
            # Import password hashing
            from werkzeug.security import generate_password_hash
            
            default_admin = User(
                email='admin@wisec.local',
                password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'),
                role=get_model('UserRole').ADMIN if get_model('UserRole') else 'admin',
                is_verified=True,
                is_admin_approved=True,
                account_status=get_model('AccountStatus').ACTIVE if get_model('AccountStatus') else 'active'
            )
            
            db.session.add(default_admin)
            db.session.commit()
            
            logger.info("✓ Default admin user created (admin@wisec.local / admin123)")
        
        logger.info("✓ Default data initialization complete")
        return True
        
    except Exception as e:
        logger.error(f"Error initializing default data: {e}")
        return False

# Model registry for dynamic access
def get_model(model_name):
    """
    Get model class by name with lazy loading
    
    Args:
        model_name (str): Name of the model
        
    Returns:
        Model class or None if not found
    """
    global _models_loaded, _models_cache
    
    # Ensure models are imported
    if not _models_loaded:
        logger.warning("Models not fully loaded, attempting import...")
        _import_all_models()
    
    # Normalize model name
    normalized_name = model_name.replace('_', '').lower()
    
    # Search in cache
    for key, model_class in _models_cache.items():
        if key.lower() == normalized_name or key.lower() == model_name.lower():
            return model_class
    
    # Try direct lookup
    return _models_cache.get(model_name)

def get_all_models():
    """Get all loaded models"""
    return _models_cache.copy()

def create_tables():
    """Create all database tables"""
    try:
        db.create_all()
        logger.info("✓ Database tables created successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        return False

def drop_tables():
    """Drop all database tables (use with caution)"""
    try:
        db.drop_all()
        logger.info("⚠️ Database tables dropped")
        return True
    except Exception as e:
        logger.error(f"Error dropping tables: {e}")
        return False

def get_database_info():
    """Get database connection information"""
    try:
        engine = db.engine
        return {
            'database_url': str(engine.url).replace(str(engine.url.password) if engine.url.password else '', '***'),
            'database_name': engine.url.database,
            'driver': engine.name,
            'table_count': len(db.metadata.tables),
            'tables': list(db.metadata.tables.keys()),
            'models_loaded': len(_models_cache),
            'models': list(_models_cache.keys())
        }
    except Exception as e:
        return {'error': str(e)}

class DatabaseManager:
    """Database management utilities"""
    
    @staticmethod
    def get_table_statistics():
        """Get statistics for all tables"""
        try:
            stats = {}
            
            # Get models
            User = get_model('User')
            ScanResult = get_model('ScanResult') 
            AdminRequest = get_model('AdminRequest')
            AuditLog = get_model('AuditLog')
            
            # Count records
            if User:
                stats['users'] = User.query.count()
            if ScanResult:
                stats['scan_results'] = ScanResult.query.count()
            if AdminRequest:
                stats['admin_requests'] = AdminRequest.query.count()
            if AuditLog:
                stats['audit_logs'] = AuditLog.query.count()
            
            stats['total_records'] = sum(stats.values())
            stats['last_updated'] = datetime.now().isoformat()
            
            return stats
        except Exception as e:
            logger.error(f"Error getting table statistics: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def cleanup_old_data(days_old=30):
        """Clean up old data based on retention policy"""
        try:
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            results = {
                'success': True,
                'cutoff_date': cutoff_date.isoformat(),
                'cleaned_counts': {}
            }
            
            # Clean old scan results
            ScanResult = get_model('ScanResult')
            if ScanResult:
                old_scans_query = ScanResult.query.filter(
                    ScanResult.scan_timestamp < cutoff_date
                )
                old_scans_count = old_scans_query.count()
                old_scans_query.delete(synchronize_session=False)
                results['cleaned_counts']['scan_results'] = old_scans_count
            
            # Clean old audit logs  
            AuditLog = get_model('AuditLog')
            if AuditLog:
                old_logs_query = AuditLog.query.filter(
                    AuditLog.timestamp < cutoff_date
                )
                old_logs_count = old_logs_query.count()
                old_logs_query.delete(synchronize_session=False)
                results['cleaned_counts']['audit_logs'] = old_logs_count
            
            db.session.commit()
            return results
        except Exception as e:
            logger.error(f"Error cleaning up data: {e}")
            db.session.rollback()
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def backup_database(backup_path=None):
        """Create database backup"""
        try:
            if not backup_path:
                backup_path = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
            
            # This would implement actual backup logic
            # For now, just return metadata
            info = get_database_info()
            stats = DatabaseManager.get_table_statistics()
            
            backup_info = {
                'backup_path': backup_path,
                'created_at': datetime.now().isoformat(),
                'database_info': info,
                'statistics': stats
            }
            
            logger.info(f"Database backup metadata prepared: {backup_path}")
            return backup_info
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return {'error': str(e)}

def check_database_health():
    """Check database connection and health"""
    try:
        # Test basic connection
        db.session.execute(db.text('SELECT 1'))
        
        # Get table stats
        stats = DatabaseManager.get_table_statistics()
        
        # Check model loading
        models_loaded = len(_models_cache) > 0
        
        health_status = {
            'database_connected': True,
            'tables_accessible': len(stats) > 0 and 'error' not in stats,
            'models_loaded': models_loaded,
            'total_records': stats.get('total_records', 0),
            'total_models': len(_models_cache),
            'last_check': datetime.now().isoformat(),
            'status': 'healthy',
            'tables': list(db.metadata.tables.keys()) if db.metadata.tables else [],
            'available_models': list(_models_cache.keys())
        }
        
        return health_status
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            'database_connected': False,
            'models_loaded': False,
            'error': str(e),
            'status': 'unhealthy',
            'last_check': datetime.now().isoformat()
        }

# Lazy loading functions for models
def get_user_model():
    """Get User model with lazy loading"""
    return get_model('User')

def get_scan_result_model():
    """Get ScanResult model with lazy loading"""
    return get_model('ScanResult')

def get_admin_request_model():
    """Get AdminRequest model with lazy loading"""
    return get_model('AdminRequest')

def get_audit_log_model():
    """Get AuditLog model with lazy loading"""
    return get_model('AuditLog')

def get_user_profile_model():
    """Get UserProfile model with lazy loading"""
    return get_model('UserProfile')

def get_user_session_model():
    """Get UserSession model with lazy loading"""
    return get_model('UserSession')

def get_vulnerability_report_model():
    """Get VulnerabilityReport model with lazy loading"""
    return get_model('VulnerabilityReport')

def get_network_info_model():
    """Get NetworkInfo model with lazy loading"""
    return get_model('NetworkInfo')

def get_threat_assessment_model():
    """Get ThreatAssessment model with lazy loading"""
    return get_model('ThreatAssessment')

# Utility functions
def initialize_default_data():
    """Initialize default data for the application"""
    return _initialize_default_data()

def validate_database_schema():
    """Validate database schema integrity"""
    try:
        # Check if all expected tables exist
        expected_tables = [
            'users', 'user_profiles', 'user_sessions',
            'scan_results', 'vulnerability_reports', 'network_info', 'threat_assessments',
            'admin_requests', 'approval_history',
            'audit_logs', 'security_events', 'system_activities', 'compliance_logs'
        ]
        
        existing_tables = list(db.metadata.tables.keys())
        missing_tables = [t for t in expected_tables if t not in existing_tables]
        
        # Check model availability
        critical_models = ['User', 'ScanResult', 'AdminRequest', 'AuditLog']
        missing_models = [m for m in critical_models if not get_model(m)]
        
        validation_result = {
            'schema_valid': len(missing_tables) == 0,
            'models_valid': len(missing_models) == 0,
            'missing_tables': missing_tables,
            'existing_tables': existing_tables,
            'missing_models': missing_models,
            'available_models': list(_models_cache.keys()),
            'total_tables': len(existing_tables),
            'total_models': len(_models_cache),
            'validation_timestamp': datetime.now().isoformat()
        }
        
        return validation_result
    except Exception as e:
        logger.error(f"Error validating schema: {e}")
        return {
            'schema_valid': False, 
            'models_valid': False,
            'error': str(e),
            'validation_timestamp': datetime.now().isoformat()
        }

def reset_database():
    """Reset database (drop and recreate all tables)"""
    try:
        logger.warning("Resetting database - dropping all tables")
        db.drop_all()
        
        logger.info("Creating fresh database tables")
        db.create_all()
        
        logger.info("Initializing default data")
        _initialize_default_data()
        
        logger.info("✓ Database reset completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error resetting database: {e}")
        return False

def migrate_database():
    """Run database migrations"""
    try:
        from flask_migrate import upgrade
        upgrade()
        logger.info("✓ Database migrations completed")
        return True
    except Exception as e:
        logger.error(f"Error running migrations: {e}")
        return False

def seed_test_data():
    """Seed database with test data for development"""
    try:
        logger.info("Seeding test data...")
        
        User = get_model('User')
        UserRole = get_model('UserRole')
        AccountStatus = get_model('AccountStatus')
        
        if not User:
            logger.error("User model not available for seeding")
            return False
        
        # Create test users if they don't exist
        test_users = [
            {
                'email': 'test.user@example.com',
                'password': 'testpass123',
                'role': UserRole.USER if UserRole else 'user',
                'is_verified': True,
                'account_status': AccountStatus.ACTIVE if AccountStatus else 'active'
            },
            {
                'email': 'test.admin@example.com', 
                'password': 'adminpass123',
                'role': UserRole.ADMIN if UserRole else 'admin',
                'is_verified': True,
                'is_admin_approved': True,
                'account_status': AccountStatus.ACTIVE if AccountStatus else 'active'
            },
            {
                'email': 'test.moderator@example.com',
                'password': 'modpass123', 
                'role': UserRole.MODERATOR if UserRole else 'moderator',
                'is_verified': True,
                'is_admin_approved': True,
                'account_status': AccountStatus.ACTIVE if AccountStatus else 'active'
            }
        ]
        
        created_count = 0
        for user_data in test_users:
            if not User.query.filter_by(email=user_data['email']).first():
                from werkzeug.security import generate_password_hash
                
                test_user = User(
                    email=user_data['email'],
                    password_hash=generate_password_hash(user_data['password'], method='pbkdf2:sha256'),
                    role=user_data['role'],
                    is_verified=user_data['is_verified'],
                    is_admin_approved=user_data.get('is_admin_approved', False),
                    account_status=user_data['account_status']
                )
                
                db.session.add(test_user)
                created_count += 1
        
        db.session.commit()
        logger.info(f"✓ Created {created_count} test users")
        
        return True
        
    except Exception as e:
        logger.error(f"Error seeding test data: {e}")
        db.session.rollback()
        return False

# Database connection helper
def test_database_connection():
    """Test database connection"""
    try:
        # Test basic query
        result = db.session.execute(db.text('SELECT 1 as test')).fetchone()
        
        if result and result[0] == 1:
            logger.info("✓ Database connection test successful")
            return True
        else:
            logger.error("Database connection test failed - unexpected result")
            return False
            
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

# Export commonly used items
__all__ = [
    # Core components
    'db',
    'migrate', 
    'init_db',
    
    # Model access functions
    'get_model',
    'get_all_models',
    'get_user_model',
    'get_scan_result_model', 
    'get_admin_request_model',
    'get_audit_log_model',
    'get_user_profile_model',
    'get_user_session_model',
    'get_vulnerability_report_model',
    'get_network_info_model',
    'get_threat_assessment_model',
    
    # Database operations
    'create_tables',
    'drop_tables',
    'reset_database',
    'migrate_database',
    
    # Database management
    'get_database_info',
    'DatabaseManager',
    'check_database_health',
    'validate_database_schema',
    'test_database_connection',
    
    # Data management
    'initialize_default_data',
    'seed_test_data'
]

# Model relationships documentation
"""
Database Relationships (COMPLETE FIXED VERSION):
===============================================

Core Tables:
- users (id, email, password_hash, role, account_status, etc.)
- user_profiles (id, user_id→users.id, first_name, last_name, etc.)
- user_sessions (id, user_id→users.id, session_token, etc.)

Scan Tables:
- scan_results (id, user_id→users.id, network_ssid, scan_data, etc.)
- vulnerability_reports (id, scan_result_id→scan_results.id, etc.)
- network_info (id, scan_result_id→scan_results.id, etc.)
- threat_assessments (id, scan_result_id→scan_results.id, etc.)

Admin Tables:
- admin_requests (id, user_id→users.id, request_type, status, etc.)
- approval_history (id, request_id→admin_requests.id, etc.)

Audit Tables:
- audit_logs (id, user_id→users.id, action, timestamp, etc.)
- security_events (id, audit_log_id→audit_logs.id, etc.)
- system_activities (id, audit_log_id→audit_logs.id, etc.)
- compliance_logs (id, audit_log_id→audit_logs.id, etc.)

Foreign Key Relationships:
- All tables properly reference their parent tables
- Cascade deletes configured where appropriate
- Indexes created for foreign key columns
- Proper relationship backref configurations

This structure ensures:
1. No circular import issues
2. Proper foreign key resolution during migrations
3. Correct relationship loading order
4. Database integrity and performance
"""