"""
Wi-Fi Security System - Audit Logs Model - COMPLETE FIXED VERSION
System Audit Logs for comprehensive logging and compliance tracking

FIXES:
- Fixed User relationship import issue
- Proper SQLAlchemy relationship configuration
- Fixed foreign key references
- Added proper error handling
- Compatible with database initialization system
"""

from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, text
from sqlalchemy.dialects.postgresql import JSON
from enum import Enum
import json
import csv
import io
import logging

# Import db from models package to avoid circular imports
try:
    from app.models import db
except ImportError:
    from flask_sqlalchemy import SQLAlchemy
    db = SQLAlchemy()

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Event type enumeration for categorizing audit events"""
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    USER_REGISTRATION = "USER_REGISTRATION"
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    PASSWORD_RESET = "PASSWORD_RESET"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PROFILE_UPDATE = "PROFILE_UPDATE"
    WIFI_SCAN = "WIFI_SCAN"
    VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    ADMIN_APPROVAL = "ADMIN_APPROVAL"
    MODEL_PREDICTION = "MODEL_PREDICTION"
    REPORT_GENERATION = "REPORT_GENERATION"
    REPORT_DOWNLOAD = "REPORT_DOWNLOAD"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    API_ACCESS = "API_ACCESS"
    DATA_EXPORT = "DATA_EXPORT"
    DATA_IMPORT = "DATA_IMPORT"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"
    USER_MANAGEMENT = "USER_MANAGEMENT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    SESSION_START = "SESSION_START"
    SESSION_END = "SESSION_END"
    FILE_UPLOAD = "FILE_UPLOAD"
    FILE_DELETE = "FILE_DELETE"

class SecurityLevel(Enum):
    """Security level classification for events"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AuditLog(db.Model):
    """
    Main audit log entry for comprehensive system logging
    Purpose: Track all system activities for security and compliance
    FIXED: Proper relationship configuration
    """
    __tablename__ = 'audit_logs'
    
    # Primary key and identification
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # User and session information - FIXED foreign key reference
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    session_id = db.Column(db.String(255), nullable=True)
    
    # Event classification
    event_type = db.Column(db.Enum(EventType), nullable=False, index=True)
    event_category = db.Column(db.String(50), nullable=False, index=True)
    event_description = db.Column(db.Text, nullable=False)
    
    # Technical details - Use Text for SQLite compatibility
    details = db.Column(db.Text, nullable=True)  # JSON stored as text
    
    # Network and request information
    ip_address = db.Column(db.String(45), nullable=True, index=True)  # Support IPv6
    user_agent = db.Column(db.Text, nullable=True)
    request_method = db.Column(db.String(10), nullable=True)
    request_url = db.Column(db.Text, nullable=True)
    request_headers = db.Column(db.Text, nullable=True)  # JSON stored as text
    
    # Resource and operation details
    resource_accessed = db.Column(db.String(255), nullable=True, index=True)
    operation_performed = db.Column(db.String(100), nullable=True)
    operation_result = db.Column(db.String(50), nullable=True)  # SUCCESS, FAILURE, ERROR
    
    # Security classification
    security_level = db.Column(db.Enum(SecurityLevel), default=SecurityLevel.LOW, nullable=False, index=True)
    risk_score = db.Column(db.Float, default=0.0)
    
    # Compliance and regulatory
    compliance_flags = db.Column(db.Text, nullable=True)  # JSON stored as text
    regulatory_category = db.Column(db.String(50), nullable=True)
    
    # Additional metadata
    application_module = db.Column(db.String(50), nullable=True)
    api_endpoint = db.Column(db.String(255), nullable=True)
    processing_time_ms = db.Column(db.Integer, nullable=True)
    
    # Error tracking
    error_code = db.Column(db.String(50), nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    stack_trace = db.Column(db.Text, nullable=True)
    
    # Relationships - FIXED: Proper relationship configuration
    # Note: We'll set up relationships after all models are imported to avoid circular imports
    
    # Indexes for performance
    __table_args__ = (
        db.Index('idx_audit_timestamp_user', 'timestamp', 'user_id'),
        db.Index('idx_audit_event_security', 'event_type', 'security_level'),
        db.Index('idx_audit_ip_timestamp', 'ip_address', 'timestamp'),
        db.Index('idx_audit_resource_operation', 'resource_accessed', 'operation_performed'),
    )
    
    def __init__(self, **kwargs):
        """Initialize audit log entry with proper JSON handling"""
        # Handle JSON fields for SQLite compatibility
        json_fields = ['details', 'request_headers', 'compliance_flags']
        for field in json_fields:
            if field in kwargs and isinstance(kwargs[field], (dict, list)):
                kwargs[field] = json.dumps(kwargs[field])
        
        super().__init__(**kwargs)
    
    def get_details(self):
        """Get details as dictionary"""
        try:
            return json.loads(self.details or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_details(self, details_dict):
        """Set details from dictionary"""
        try:
            self.details = json.dumps(details_dict) if details_dict else '{}'
        except Exception as e:
            logger.error(f"Error setting details: {e}")
            self.details = '{}'
    
    def get_request_headers(self):
        """Get request headers as dictionary"""
        try:
            return json.loads(self.request_headers or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_request_headers(self, headers_dict):
        """Set request headers from dictionary"""
        try:
            self.request_headers = json.dumps(headers_dict) if headers_dict else '{}'
        except Exception as e:
            logger.error(f"Error setting request headers: {e}")
            self.request_headers = '{}'
    
    def get_compliance_flags(self):
        """Get compliance flags as dictionary"""
        try:
            return json.loads(self.compliance_flags or '{}')
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_compliance_flags(self, flags_dict):
        """Set compliance flags from dictionary"""
        try:
            self.compliance_flags = json.dumps(flags_dict) if flags_dict else '{}'
        except Exception as e:
            logger.error(f"Error setting compliance flags: {e}")
            self.compliance_flags = '{}'
    
    def __repr__(self):
        return f'<AuditLog {self.id}: {self.event_type.value} at {self.timestamp}>'
    
    @classmethod
    def log_event(cls, event_type, event_description, user_id=None, ip_address=None, 
                  user_agent=None, resource_accessed=None, details=None, 
                  security_level=SecurityLevel.LOW, **kwargs):
        """
        Log system events with comprehensive details
        
        Args:
            event_type: EventType enum value
            event_description: Human-readable description
            user_id: User ID if applicable
            ip_address: Client IP address
            user_agent: Client user agent
            resource_accessed: Resource that was accessed
            details: Additional event details as dict
            security_level: Security level classification
            **kwargs: Additional fields
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            # Ensure event_type is an EventType enum
            if isinstance(event_type, str):
                try:
                    event_type = EventType(event_type.upper())
                except ValueError:
                    event_type = EventType.SYSTEM_ERROR
            
            # Ensure security_level is a SecurityLevel enum
            if isinstance(security_level, str):
                try:
                    security_level = SecurityLevel(security_level.upper())
                except ValueError:
                    security_level = SecurityLevel.LOW
            
            # Create audit log entry
            audit_log = cls(
                event_type=event_type,
                event_category=event_type.value.split('_')[0],  # Extract category from event type
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource_accessed=resource_accessed,
                security_level=security_level,
                **kwargs
            )
            
            # Set details
            if details:
                audit_log.set_details(details)
            
            # Calculate risk score based on event type and security level
            audit_log.risk_score = cls._calculate_risk_score(event_type, security_level)
            
            # Set compliance flags if applicable
            compliance_flags = cls._determine_compliance_flags(event_type, details)
            if compliance_flags:
                audit_log.set_compliance_flags(compliance_flags)
            
            db.session.add(audit_log)
            db.session.commit()
            
            # Trigger alert for high-risk events
            if security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                cls._trigger_security_alert(audit_log)
            
            return audit_log
            
        except Exception as e:
            db.session.rollback()
            # Log the error but don't raise to avoid cascading failures
            logger.error(f"Error logging audit event: {str(e)}")
            return None
    @classmethod
    def log_network_topology_event(cls, topology_data=None, analysis_result=None, user_id=None, 
                                ip_address=None, error_message=None, **kwargs):
        """
        Log network topology analysis events with proper error handling
        
        Args:
            topology_data: Network topology information
            analysis_result: Analysis results or error details
            user_id: User ID performing the analysis
            ip_address: Client IP address
            error_message: Error message if analysis failed
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            # Determine event description based on success/failure
            if error_message:
                event_description = f"Network topology analysis failed: {error_message}"
                operation_result = "FAILURE"
                security_level = SecurityLevel.MEDIUM
            else:
                event_description = "Network topology analysis completed successfully"
                operation_result = "SUCCESS"
                security_level = SecurityLevel.LOW
            
            # Prepare details
            details = {
                'topology_analysis': True,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if topology_data:
                details['topology_summary'] = {
                    'device_count': len(topology_data.get('devices', [])) if isinstance(topology_data, dict) else 'unknown',
                    'network_segments': topology_data.get('segments', 'unknown') if isinstance(topology_data, dict) else 'unknown'
                }
            
            if analysis_result:
                details['analysis_result'] = analysis_result
                
            if error_message:
                details['error_details'] = error_message
            
            # Log the event
            return cls.log_event(
                event_type=EventType.NETWORK_CONNECTION,
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                security_level=security_level,
                operation_result=operation_result,
                resource_accessed="network_topology",
                application_module="ai_enhanced_topology",
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"Failed to log network topology event: {e}")
            # Fallback logging
            try:
                return cls.log_event(
                    event_type=EventType.SYSTEM_ERROR,
                    event_description=f"Failed to log network topology event: {str(e)}",
                    details={'original_error': error_message, 'logging_error': str(e)},
                    security_level=SecurityLevel.MEDIUM,
                    operation_result="ERROR"
                )
            except:
                return None

    @classmethod
    def log_wifi_scan_event(cls, scan_results=None, scan_duration=None, networks_found=None,
                        user_id=None, ip_address=None, error_message=None, **kwargs):
        """
        Log Wi-Fi scanning events with comprehensive details
        
        Args:
            scan_results: Wi-Fi scan results
            scan_duration: Time taken for scan
            networks_found: Number of networks discovered
            user_id: User performing the scan
            ip_address: Client IP address
            error_message: Error message if scan failed
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            if error_message:
                event_description = f"Wi-Fi scan failed: {error_message}"
                operation_result = "FAILURE"
                security_level = SecurityLevel.MEDIUM
            else:
                event_description = f"Wi-Fi scan completed - {networks_found or 0} networks found"
                operation_result = "SUCCESS"
                security_level = SecurityLevel.LOW
            
            details = {
                'scan_type': 'wifi',
                'networks_found': networks_found or 0,
                'scan_duration_seconds': scan_duration,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if scan_results and isinstance(scan_results, list):
                details['security_summary'] = {
                    'open_networks': len([n for n in scan_results if n.get('security') == 'Open']),
                    'wep_networks': len([n for n in scan_results if 'WEP' in str(n.get('security', ''))]),
                    'wpa_networks': len([n for n in scan_results if 'WPA' in str(n.get('security', ''))]),
                    'total_networks': len(scan_results)
                }
            
            if error_message:
                details['error_details'] = error_message
            
            return cls.log_event(
                event_type=EventType.WIFI_SCAN,
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                security_level=security_level,
                operation_result=operation_result,
                resource_accessed="wifi_networks",
                processing_time_ms=int(scan_duration * 1000) if scan_duration else None,
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"Failed to log Wi-Fi scan event: {e}")
            return None

    @classmethod
    def log_vulnerability_analysis_event(cls, analysis_type=None, vulnerabilities_found=None, 
                                        severity_breakdown=None, user_id=None, ip_address=None, 
                                        error_message=None, **kwargs):
        """
        Log vulnerability analysis events
        
        Args:
            analysis_type: Type of vulnerability analysis
            vulnerabilities_found: Number of vulnerabilities found
            severity_breakdown: Breakdown by severity level
            user_id: User performing analysis
            ip_address: Client IP address
            error_message: Error message if analysis failed
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            if error_message:
                event_description = f"Vulnerability analysis failed: {error_message}"
                operation_result = "FAILURE"
                security_level = SecurityLevel.HIGH
            else:
                vuln_count = vulnerabilities_found or 0
                event_description = f"Vulnerability analysis completed - {vuln_count} vulnerabilities found"
                operation_result = "SUCCESS"
                
                # Determine security level based on findings
                if vuln_count == 0:
                    security_level = SecurityLevel.LOW
                elif vuln_count < 5:
                    security_level = SecurityLevel.MEDIUM
                else:
                    security_level = SecurityLevel.HIGH
            
            details = {
                'analysis_type': analysis_type or 'general',
                'vulnerabilities_found': vulnerabilities_found or 0,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if severity_breakdown:
                details['severity_breakdown'] = severity_breakdown
            
            if error_message:
                details['error_details'] = error_message
            
            return cls.log_event(
                event_type=EventType.VULNERABILITY_ANALYSIS,
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                security_level=security_level,
                operation_result=operation_result,
                resource_accessed="vulnerability_scanner",
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"Failed to log vulnerability analysis event: {e}")
            return None

    @classmethod
    def log_model_prediction_event(cls, model_type=None, prediction_result=None, confidence_score=None,
                                processing_time=None, user_id=None, ip_address=None, 
                                error_message=None, **kwargs):
        """
        Log ML model prediction events
        
        Args:
            model_type: Type of ML model used
            prediction_result: Prediction result
            confidence_score: Confidence score of prediction
            processing_time: Time taken for prediction
            user_id: User requesting prediction
            ip_address: Client IP address
            error_message: Error message if prediction failed
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            if error_message:
                event_description = f"Model prediction failed: {error_message}"
                operation_result = "FAILURE"
                security_level = SecurityLevel.MEDIUM
            else:
                event_description = f"Model prediction completed using {model_type or 'unknown'} model"
                operation_result = "SUCCESS"
                security_level = SecurityLevel.LOW
            
            details = {
                'model_type': model_type,
                'prediction_successful': error_message is None,
                'confidence_score': confidence_score,
                'processing_time_seconds': processing_time,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if prediction_result:
                details['prediction_summary'] = str(prediction_result)[:200]  # Truncate for storage
            
            if error_message:
                details['error_details'] = error_message
            
            return cls.log_event(
                event_type=EventType.MODEL_PREDICTION,
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                security_level=security_level,
                operation_result=operation_result,
                resource_accessed="ml_model",
                processing_time_ms=int(processing_time * 1000) if processing_time else None,
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"Failed to log model prediction event: {e}")
            return None

    @classmethod
    def log_api_access_event(cls, endpoint=None, method=None, status_code=None, response_time=None,
                            user_id=None, ip_address=None, user_agent=None, request_size=None,
                            response_size=None, **kwargs):
        """
        Log API access events with detailed information
        
        Args:
            endpoint: API endpoint accessed
            method: HTTP method used
            status_code: HTTP status code returned
            response_time: Response time in milliseconds
            user_id: User making the request
            ip_address: Client IP address
            user_agent: Client user agent
            request_size: Size of request in bytes
            response_size: Size of response in bytes
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            # Determine event description and result
            if status_code and 200 <= status_code < 300:
                event_description = f"API access successful: {method} {endpoint}"
                operation_result = "SUCCESS"
                security_level = SecurityLevel.LOW
            elif status_code and 400 <= status_code < 500:
                event_description = f"API access failed - client error: {method} {endpoint} ({status_code})"
                operation_result = "FAILURE"
                security_level = SecurityLevel.MEDIUM
            elif status_code and status_code >= 500:
                event_description = f"API access failed - server error: {method} {endpoint} ({status_code})"
                operation_result = "ERROR"
                security_level = SecurityLevel.HIGH
            else:
                event_description = f"API access: {method} {endpoint}"
                operation_result = "UNKNOWN"
                security_level = SecurityLevel.LOW
            
            details = {
                'http_method': method,
                'status_code': status_code,
                'response_time_ms': response_time,
                'request_size_bytes': request_size,
                'response_size_bytes': response_size,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return cls.log_event(
                event_type=EventType.API_ACCESS,
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details,
                security_level=security_level,
                operation_result=operation_result,
                resource_accessed=endpoint,
                api_endpoint=endpoint,
                request_method=method,
                processing_time_ms=response_time,
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"Failed to log API access event: {e}")
            return None

    @classmethod
    def log_system_error_event(cls, error_type=None, error_message=None, module=None, 
                            stack_trace=None, user_id=None, ip_address=None, **kwargs):
        """
        Log system error events with detailed error information
        
        Args:
            error_type: Type of error (e.g., "DatabaseError", "ValidationError")
            error_message: Error message
            module: Module/component where error occurred
            stack_trace: Full stack trace
            user_id: User ID if applicable
            ip_address: Client IP if applicable
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry
        """
        try:
            event_description = f"System error in {module or 'unknown module'}: {error_message or 'Unknown error'}"
            
            details = {
                'error_type': error_type,
                'module': module,
                'has_stack_trace': bool(stack_trace),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Determine security level based on error type
            critical_errors = ['SecurityError', 'AuthenticationError', 'AuthorizationError']
            if error_type in critical_errors:
                security_level = SecurityLevel.CRITICAL
            else:
                security_level = SecurityLevel.MEDIUM
            
            return cls.log_event(
                event_type=EventType.SYSTEM_ERROR,
                event_description=event_description,
                user_id=user_id,
                ip_address=ip_address,
                details=details,
                security_level=security_level,
                operation_result="ERROR",
                application_module=module,
                error_code=error_type,
                error_message=error_message,
                stack_trace=stack_trace[:2000] if stack_trace else None,  # Truncate stack trace
                **kwargs
            )
            
        except Exception as e:
            logger.error(f"Failed to log system error event: {e}")
            return None

    @classmethod
    def safe_log_event(cls, event_type, event_description=None, fallback_description="System event occurred", **kwargs):
        """
        Safely log events with fallback handling to prevent cascading failures
        
        Args:
            event_type: EventType enum or string
            event_description: Event description (optional)
            fallback_description: Fallback description if main description is None
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log entry or None if failed
        """
        try:
            # Ensure we have an event description
            if not event_description:
                event_description = fallback_description
            
            # Ensure event_type is an EventType enum
            if isinstance(event_type, str):
                try:
                    event_type = EventType(event_type.upper())
                except ValueError:
                    event_type = EventType.SYSTEM_ERROR
                    event_description = f"Unknown event type logged: {event_description}"
            
            return cls.log_event(event_type=event_type, event_description=event_description, **kwargs)
            
        except Exception as e:
            logger.error(f"Failed to safely log event: {e}")
            # Last resort - try to log the logging failure
            try:
                basic_log = cls(
                    event_type=EventType.SYSTEM_ERROR,
                    event_category="SYSTEM",
                    event_description=f"Audit logging failure: {str(e)}",
                    security_level=SecurityLevel.MEDIUM,
                    timestamp=datetime.utcnow()
                )
                db.session.add(basic_log)
                db.session.commit()
                return basic_log
            except:
                # If even basic logging fails, just return None
                return None

    @classmethod
    def get_recent_errors(cls, hours=24, limit=50):
        """
        Get recent system errors for monitoring
        
        Args:
            hours: Number of hours to look back
            limit: Maximum number of errors to return
        
        Returns:
            list: Recent error audit logs
        """
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            errors = cls.query.filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.event_type == EventType.SYSTEM_ERROR
                )
            ).order_by(cls.timestamp.desc()).limit(limit).all()
            
            return [error.to_dict() for error in errors]
            
        except Exception as e:
            logger.error(f"Failed to get recent errors: {e}")
            return []

    @classmethod
    def get_security_dashboard_data(cls, hours=24):
        """
        Get data for security dashboard
        
        Args:
            hours: Number of hours to analyze
        
        Returns:
            dict: Security dashboard data
        """
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            
            # Get security events
            security_events = cls.query.filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.security_level.in_([SecurityLevel.HIGH, SecurityLevel.CRITICAL])
                )
            ).count()
            
            # Get failed logins
            failed_logins = cls.query.filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.event_type == EventType.USER_LOGIN,
                    cls.operation_result == 'FAILURE'
                )
            ).count()
            
            # Get API access attempts
            api_access = cls.query.filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.event_type == EventType.API_ACCESS
                )
            ).count()
            
            return {
                'time_period_hours': hours,
                'security_events': security_events,
                'failed_logins': failed_logins,
                'api_access_attempts': api_access,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get security dashboard data: {e}")
            return {'error': str(e)}
        
    @classmethod
    def get_user_activities(cls, user_id, limit=10):
        """Get recent activities for a user"""
        try:
            activities = cls.query.filter_by(user_id=user_id)\
                                .order_by(cls.timestamp.desc())\
                                .limit(limit)\
                                .all()
            return [activity.to_dict() for activity in activities]
        except Exception as e:
            logger.error(f"Failed to get user activities: {e}")
            return []

    def to_dict(self):
        """Convert AuditLog to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'event_description': self.event_description,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'ip_address': getattr(self, 'ip_address', None),
            'user_agent': getattr(self, 'user_agent', None)
        }
    
    @classmethod
    def log_security_event(cls, event_description, threat_type, severity, 
                          user_id=None, ip_address=None, details=None):
        """
        Log security-specific events with enhanced tracking
        
        Args:
            event_description: Security event description
            threat_type: Type of security threat
            severity: Severity level (HIGH, CRITICAL)
            user_id: User ID if applicable
            ip_address: Source IP address
            details: Additional security details
        
        Returns:
            AuditLog: Created security audit log
        """
        security_details = {
            'threat_type': threat_type,
            'severity': severity,
            'detection_timestamp': datetime.utcnow().isoformat(),
            **(details or {})
        }
        
        security_level = SecurityLevel.CRITICAL if severity == 'CRITICAL' else SecurityLevel.HIGH
        
        return cls.log_event(
            event_type=EventType.SECURITY_VIOLATION,
            event_description=f"Security Event: {event_description}",
            user_id=user_id,
            ip_address=ip_address,
            details=security_details,
            security_level=security_level,
            event_category='SECURITY',
            regulatory_category='SECURITY_INCIDENT'
        )
    
    @classmethod
    def log_user_activity(cls, user_id, activity_type, description, ip_address=None, **kwargs):
        """
        Log user activity events
        
        Args:
            user_id: User ID
            activity_type: Type of activity (LOGIN, LOGOUT, etc.)
            description: Activity description
            ip_address: User's IP address
            **kwargs: Additional parameters
        
        Returns:
            AuditLog: Created audit log
        """
        try:
            event_type = EventType(f"USER_{activity_type.upper()}")
        except ValueError:
            event_type = EventType.USER_LOGIN
        
        return cls.log_event(
            event_type=event_type,
            event_description=description,
            user_id=user_id,
            ip_address=ip_address,
            event_category='USER',
            **kwargs
        )
    
    @classmethod
    def search_logs(cls, start_date=None, end_date=None, user_id=None, 
                   event_type=None, security_level=None, ip_address=None, 
                   search_term=None, limit=1000, offset=0):
        """
        Search audit logs with multiple criteria
        
        Args:
            start_date: Start date for search
            end_date: End date for search
            user_id: Filter by user ID
            event_type: Filter by event type
            security_level: Filter by security level
            ip_address: Filter by IP address
            search_term: Text search in description
            limit: Result limit
            offset: Result offset
        
        Returns:
            list: Matching audit log entries
        """
        try:
            query = cls.query
            
            # Date range filter
            if start_date:
                query = query.filter(cls.timestamp >= start_date)
            if end_date:
                query = query.filter(cls.timestamp <= end_date)
            
            # User filter
            if user_id:
                query = query.filter(cls.user_id == user_id)
            
            # Event type filter
            if event_type:
                if isinstance(event_type, str):
                    try:
                        event_type = EventType(event_type.upper())
                    except ValueError:
                        pass
                query = query.filter(cls.event_type == event_type)
            
            # Security level filter
            if security_level:
                if isinstance(security_level, str):
                    try:
                        security_level = SecurityLevel(security_level.upper())
                    except ValueError:
                        pass
                query = query.filter(cls.security_level == security_level)
            
            # IP address filter
            if ip_address:
                query = query.filter(cls.ip_address == ip_address)
            
            # Text search
            if search_term:
                search_filter = or_(
                    cls.event_description.ilike(f'%{search_term}%'),
                    cls.resource_accessed.ilike(f'%{search_term}%'),
                    cls.details.ilike(f'%{search_term}%')
                )
                query = query.filter(search_filter)
            
            # Order by timestamp descending
            query = query.order_by(cls.timestamp.desc())
            
            # Apply pagination
            return query.offset(offset).limit(limit).all()
            
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return []
    
    @classmethod
    def generate_audit_report(cls, start_date, end_date, report_type='SUMMARY'):
        """
        Generate comprehensive audit reports
        
        Args:
            start_date: Report start date
            end_date: Report end date
            report_type: Type of report (SUMMARY, DETAILED, SECURITY)
        
        Returns:
            dict: Report data
        """
        try:
            base_query = cls.query.filter(
                and_(cls.timestamp >= start_date, cls.timestamp <= end_date)
            )
            
            report_data = {
                'report_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'report_type': report_type
                },
                'summary': {
                    'total_events': base_query.count(),
                    'unique_users': base_query.with_entities(cls.user_id).distinct().count(),
                    'unique_ips': base_query.with_entities(cls.ip_address).distinct().count()
                }
            }
            
            # Event type breakdown
            event_type_stats = db.session.query(
                cls.event_type, func.count(cls.id).label('count')
            ).filter(
                and_(cls.timestamp >= start_date, cls.timestamp <= end_date)
            ).group_by(cls.event_type).all()
            
            report_data['event_breakdown'] = {
                event_type.value: count for event_type, count in event_type_stats
            }
            
            # Security level breakdown
            security_stats = db.session.query(
                cls.security_level, func.count(cls.id).label('count')
            ).filter(
                and_(cls.timestamp >= start_date, cls.timestamp <= end_date)
            ).group_by(cls.security_level).all()
            
            report_data['security_breakdown'] = {
                level.value: count for level, count in security_stats
            }
            
            # Top users by activity
            top_users = db.session.query(
                cls.user_id, func.count(cls.id).label('activity_count')
            ).filter(
                and_(cls.timestamp >= start_date, cls.timestamp <= end_date, cls.user_id.isnot(None))
            ).group_by(cls.user_id).order_by(func.count(cls.id).desc()).limit(10).all()
            
            report_data['top_users'] = [
                {'user_id': user_id, 'activity_count': count} 
                for user_id, count in top_users
            ]
            
            # Security incidents
            if report_type in ['SECURITY', 'DETAILED']:
                security_incidents = base_query.filter(
                    cls.security_level.in_([SecurityLevel.HIGH, SecurityLevel.CRITICAL])
                ).order_by(cls.timestamp.desc()).limit(50).all()
                
                report_data['security_incidents'] = [
                    {
                        'id': incident.id,
                        'timestamp': incident.timestamp.isoformat(),
                        'event_type': incident.event_type.value,
                        'description': incident.event_description,
                        'security_level': incident.security_level.value,
                        'user_id': incident.user_id,
                        'ip_address': incident.ip_address,
                        'risk_score': incident.risk_score
                    }
                    for incident in security_incidents
                ]
            
            return report_data
            
        except Exception as e:
            logger.error(f"Error generating audit report: {e}")
            return {'error': str(e)}
    
    @classmethod
    def monitor_suspicious_activity(cls, time_window_hours=24, threshold_multiplier=3):
        """
        Monitor for suspicious activity patterns
        
        Args:
            time_window_hours: Time window for analysis
            threshold_multiplier: Multiplier for determining suspicious activity
        
        Returns:
            list: Suspicious activity alerts
        """
        try:
            time_threshold = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            suspicious_activities = []
            
            # Check for unusual login patterns
            login_attempts = db.session.query(
                cls.ip_address, func.count(cls.id).label('attempt_count')
            ).filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.event_type == EventType.USER_LOGIN,
                    cls.operation_result == 'FAILURE'
                )
            ).group_by(cls.ip_address).having(func.count(cls.id) > 10).all()
            
            for ip, count in login_attempts:
                suspicious_activities.append({
                    'type': 'EXCESSIVE_LOGIN_FAILURES',
                    'ip_address': ip,
                    'count': count,
                    'severity': 'HIGH' if count > 50 else 'MEDIUM',
                    'time_window': time_window_hours,
                    'detected_at': datetime.utcnow().isoformat()
                })
            
            # Check for rapid API access patterns
            api_access = db.session.query(
                cls.ip_address, func.count(cls.id).label('request_count')
            ).filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.event_type == EventType.API_ACCESS
                )
            ).group_by(cls.ip_address).having(func.count(cls.id) > 1000).all()
            
            for ip, count in api_access:
                suspicious_activities.append({
                    'type': 'EXCESSIVE_API_REQUESTS',
                    'ip_address': ip,
                    'count': count,
                    'severity': 'HIGH' if count > 5000 else 'MEDIUM',
                    'time_window': time_window_hours,
                    'detected_at': datetime.utcnow().isoformat()
                })
            
            # Check for unusual data export activity
            data_exports = db.session.query(
                cls.user_id, func.count(cls.id).label('export_count')
            ).filter(
                and_(
                    cls.timestamp >= time_threshold,
                    cls.event_type == EventType.DATA_EXPORT,
                    cls.user_id.isnot(None)
                )
            ).group_by(cls.user_id).having(func.count(cls.id) > 10).all()
            
            for user_id, count in data_exports:
                suspicious_activities.append({
                    'type': 'EXCESSIVE_DATA_EXPORTS',
                    'user_id': user_id,
                    'count': count,
                    'severity': 'HIGH',
                    'time_window': time_window_hours,
                    'detected_at': datetime.utcnow().isoformat()
                })
            
            return suspicious_activities
            
        except Exception as e:
            logger.error(f"Error monitoring suspicious activity: {e}")
            return []
    
    @classmethod
    def export_logs(cls, start_date, end_date, format='CSV', filters=None):
        """
        Export audit logs in various formats
        
        Args:
            start_date: Export start date
            end_date: Export end date
            format: Export format (CSV, JSON)
            filters: Additional filters
        
        Returns:
            str: Exported data
        """
        try:
            query = cls.query.filter(
                and_(cls.timestamp >= start_date, cls.timestamp <= end_date)
            )
            
            # Apply additional filters if provided
            if filters:
                if filters.get('event_type'):
                    event_type = filters['event_type']
                    if isinstance(event_type, str):
                        try:
                            event_type = EventType(event_type.upper())
                        except ValueError:
                            pass
                    query = query.filter(cls.event_type == event_type)
                    
                if filters.get('security_level'):
                    security_level = filters['security_level']
                    if isinstance(security_level, str):
                        try:
                            security_level = SecurityLevel(security_level.upper())
                        except ValueError:
                            pass
                    query = query.filter(cls.security_level == security_level)
                    
                if filters.get('user_id'):
                    query = query.filter(cls.user_id == filters['user_id'])
                    
                if filters.get('ip_address'):
                    query = query.filter(cls.ip_address == filters['ip_address'])
            
            logs = query.order_by(cls.timestamp.desc()).all()
            
            if format.upper() == 'CSV':
                return cls._export_to_csv(logs)
            elif format.upper() == 'JSON':
                return cls._export_to_json(logs)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return None
    
    @classmethod
    def archive_logs(cls, older_than_days=90):
        """
        Archive old logs to maintain performance
        
        Args:
            older_than_days: Archive logs older than specified days
        
        Returns:
            int: Number of logs archived
        """
        try:
            archive_date = datetime.utcnow() - timedelta(days=older_than_days)
            
            # Count logs to be archived
            logs_to_archive = cls.query.filter(cls.timestamp < archive_date).count()
            
            # In a real implementation, you might move these to a separate archive table
            # For now, we'll just delete them after export
            if logs_to_archive > 0:
                # Export before deletion
                export_data = cls.export_logs(
                    start_date=datetime.min,
                    end_date=archive_date,
                    format='JSON'
                )
                
                # Store export data (implementation depends on storage solution)
                # This would typically go to cold storage or archive database
                
                # Delete old logs
                cls.query.filter(cls.timestamp < archive_date).delete(synchronize_session=False)
                db.session.commit()
                
                logger.info(f"Archived {logs_to_archive} audit logs")
            
            return logs_to_archive
            
        except Exception as e:
            logger.error(f"Error archiving logs: {e}")
            db.session.rollback()
            return 0
    
    @classmethod
    def compliance_reporting(cls, regulation_type='GDPR', start_date=None, end_date=None):
        """
        Generate compliance reports for various regulations
        
        Args:
            regulation_type: Type of regulation (GDPR, HIPAA, SOX)
            start_date: Report start date
            end_date: Report end date
        
        Returns:
            dict: Compliance report data
        """
        try:
            if not start_date:
                start_date = datetime.utcnow() - timedelta(days=30)
            if not end_date:
                end_date = datetime.utcnow()
            
            base_query = cls.query.filter(
                and_(cls.timestamp >= start_date, cls.timestamp <= end_date)
            )
            
            compliance_report = {
                'regulation_type': regulation_type,
                'report_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'compliance_metrics': {},
                'generated_at': datetime.utcnow().isoformat()
            }
            
            if regulation_type == 'GDPR':
                # GDPR-specific metrics
                data_access_events = base_query.filter(
                    cls.event_type.in_([EventType.DATA_EXPORT, EventType.USER_REGISTRATION])
                ).count()
                
                compliance_report['compliance_metrics'] = {
                    'data_access_events': data_access_events,
                    'user_consent_events': base_query.filter(
                        cls.event_type == EventType.EMAIL_VERIFICATION
                    ).count(),
                    'data_processing_activities': base_query.filter(
                        cls.event_category == 'DATA'
                    ).count(),
                    'data_deletion_requests': base_query.filter(
                        cls.event_type == EventType.FILE_DELETE
                    ).count()
                }
            
            elif regulation_type == 'SOX':
                # SOX compliance metrics
                compliance_report['compliance_metrics'] = {
                    'financial_data_access': base_query.filter(
                        cls.resource_accessed.ilike('%financial%')
                    ).count(),
                    'audit_trail_completeness': base_query.count(),
                    'admin_activities': base_query.filter(
                        cls.event_type == EventType.USER_MANAGEMENT
                    ).count(),
                    'configuration_changes': base_query.filter(
                        cls.event_type == EventType.CONFIG_CHANGE
                    ).count()
                }
            
            return compliance_report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _calculate_risk_score(event_type, security_level):
        """Calculate risk score based on event type and security level"""
        base_scores = {
            EventType.USER_LOGIN: 1.0,
            EventType.USER_LOGOUT: 0.5,
            EventType.USER_REGISTRATION: 2.0,
            EventType.PASSWORD_RESET: 3.0,
            EventType.PASSWORD_CHANGE: 2.5,
            EventType.WIFI_SCAN: 2.0,
            EventType.VULNERABILITY_ANALYSIS: 3.0,
            EventType.NETWORK_CONNECTION: 2.5,
            EventType.SECURITY_VIOLATION: 8.0,
            EventType.SUSPICIOUS_ACTIVITY: 7.0,
            EventType.API_ACCESS: 1.5,
            EventType.DATA_EXPORT: 4.0,
            EventType.DATA_IMPORT: 3.5,
            EventType.CONFIG_CHANGE: 5.0,
            EventType.SYSTEM_ERROR: 3.0,
            EventType.USER_MANAGEMENT: 6.0,
            EventType.PERMISSION_CHANGE: 5.5
        }
        
        level_multipliers = {
            SecurityLevel.LOW: 1.0,
            SecurityLevel.MEDIUM: 2.0,
            SecurityLevel.HIGH: 4.0,
            SecurityLevel.CRITICAL: 8.0
        }
        
        base_score = base_scores.get(event_type, 1.0)
        multiplier = level_multipliers.get(security_level, 1.0)
        
        return base_score * multiplier
    
    @staticmethod
    def _determine_compliance_flags(event_type, details):
        """Determine compliance flags based on event type and details"""
        flags = {}
        
        # GDPR compliance flags
        if event_type in [EventType.USER_REGISTRATION, EventType.DATA_EXPORT, EventType.EMAIL_VERIFICATION]:
            flags['gdpr_relevant'] = True
        
        # Security compliance flags
        if event_type == EventType.SECURITY_VIOLATION:
            flags['security_incident'] = True
            flags['requires_notification'] = True
        
        # Data access flags
        if event_type in [EventType.DATA_EXPORT, EventType.REPORT_GENERATION, EventType.DATA_IMPORT]:
            flags['data_access'] = True
        
        # Financial compliance flags
        if event_type in [EventType.CONFIG_CHANGE, EventType.USER_MANAGEMENT]:
            flags['sox_relevant'] = True
        
        # Privacy flags
        if event_type in [EventType.PROFILE_UPDATE, EventType.USER_REGISTRATION]:
            flags['privacy_relevant'] = True
        
        return flags if flags else None
    
    @staticmethod
    def _trigger_security_alert(audit_log):
        """Trigger security alerts for high-risk events"""
        try:
            # This would integrate with your alerting system
            alert_data = {
                'alert_id': f"ALERT_{audit_log.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                'event_id': audit_log.id,
                'event_type': audit_log.event_type.value,
                'description': audit_log.event_description,
                'security_level': audit_log.security_level.value,
                'risk_score': audit_log.risk_score,
                'user_id': audit_log.user_id,
                'ip_address': audit_log.ip_address,
                'timestamp': audit_log.timestamp.isoformat(),
                'requires_immediate_attention': audit_log.security_level == SecurityLevel.CRITICAL
            }
            
            logger.warning(f"SECURITY ALERT: {audit_log.event_description} "
                         f"(Risk Score: {audit_log.risk_score}, Level: {audit_log.security_level.value})")
            
            # Here you would typically:
            # 1. Send email alerts
            # 2. Create dashboard notifications
            # 3. Integrate with SIEM systems
            # 4. Send to monitoring systems
            
            return alert_data
            
        except Exception as e:
            logger.error(f"Error triggering security alert: {e}")
            return None
    
    @classmethod
    def _export_to_csv(cls, logs):
        """Export logs to CSV format"""
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            header = [
                'ID', 'Timestamp', 'User ID', 'Event Type', 'Event Category', 
                'Event Description', 'IP Address', 'Security Level', 'Risk Score', 
                'Resource Accessed', 'Operation Result', 'Application Module',
                'Processing Time (ms)', 'Error Code', 'Error Message'
            ]
            writer.writerow(header)
            
            # Write data
            for log in logs:
                writer.writerow([
                    log.id,
                    log.timestamp.isoformat() if log.timestamp else '',
                    log.user_id or '',
                    log.event_type.value if log.event_type else '',
                    log.event_category or '',
                    log.event_description or '',
                    log.ip_address or '',
                    log.security_level.value if log.security_level else '',
                    log.risk_score or 0,
                    log.resource_accessed or '',
                    log.operation_result or '',
                    log.application_module or '',
                    log.processing_time_ms or '',
                    log.error_code or '',
                    log.error_message or ''
                ])
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return None
    
    @classmethod
    def _export_to_json(cls, logs):
        """Export logs to JSON format"""
        try:
            log_data = []
            for log in logs:
                log_entry = {
                    'id': log.id,
                    'timestamp': log.timestamp.isoformat() if log.timestamp else None,
                    'user_id': log.user_id,
                    'session_id': log.session_id,
                    'event_type': log.event_type.value if log.event_type else None,
                    'event_category': log.event_category,
                    'event_description': log.event_description,
                    'details': log.get_details(),
                    'ip_address': log.ip_address,
                    'user_agent': log.user_agent,
                    'request_method': log.request_method,
                    'request_url': log.request_url,
                    'request_headers': log.get_request_headers(),
                    'resource_accessed': log.resource_accessed,
                    'operation_performed': log.operation_performed,
                    'operation_result': log.operation_result,
                    'security_level': log.security_level.value if log.security_level else None,
                    'risk_score': log.risk_score,
                    'compliance_flags': log.get_compliance_flags(),
                    'regulatory_category': log.regulatory_category,
                    'application_module': log.application_module,
                    'api_endpoint': log.api_endpoint,
                    'processing_time_ms': log.processing_time_ms,
                    'error_code': log.error_code,
                    'error_message': log.error_message
                }
                log_data.append(log_entry)
            
            return json.dumps(log_data, indent=2, default=str)
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return None

    def to_dict(self):
        """Convert audit log to dictionary"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'event_type': self.event_type.value if self.event_type else None,
            'event_category': self.event_category,
            'event_description': self.event_description,
            'details': self.get_details(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'resource_accessed': self.resource_accessed,
            'operation_performed': self.operation_performed,
            'operation_result': self.operation_result,
            'security_level': self.security_level.value if self.security_level else None,
            'risk_score': self.risk_score,
            'compliance_flags': self.get_compliance_flags(),
            'processing_time_ms': self.processing_time_ms,
            'error_code': self.error_code,
            'error_message': self.error_message
        }


class SecurityEvent(db.Model):
    """
    Security-specific events with enhanced tracking
    Purpose: Specialized logging for security incidents
    """
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    audit_log_id = db.Column(db.Integer, db.ForeignKey('audit_logs.id'), nullable=False)
    
    # Security-specific fields
    threat_type = db.Column(db.String(100), nullable=False)
    attack_vector = db.Column(db.String(100), nullable=True)
    affected_resources = db.Column(db.Text, nullable=True)  # JSON stored as text
    mitigation_actions = db.Column(db.Text, nullable=True)  # JSON stored as text
    
    # Incident response
    incident_id = db.Column(db.String(50), nullable=True, unique=True)
    response_status = db.Column(db.String(50), default='OPEN')
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    resolution_notes = db.Column(db.Text, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Severity and impact
    severity_score = db.Column(db.Float, default=0.0)
    business_impact = db.Column(db.String(20), default='LOW')  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships will be set after model loading
    
    def get_affected_resources(self):
        """Get affected resources as list"""
        try:
            return json.loads(self.affected_resources or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_affected_resources(self, resources):
        """Set affected resources from list"""
        try:
            self.affected_resources = json.dumps(resources) if resources else '[]'
        except Exception as e:
            logger.error(f"Error setting affected resources: {e}")
            self.affected_resources = '[]'
    
    def get_mitigation_actions(self):
        """Get mitigation actions as list"""
        try:
            return json.loads(self.mitigation_actions or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_mitigation_actions(self, actions):
        """Set mitigation actions from list"""
        try:
            self.mitigation_actions = json.dumps(actions) if actions else '[]'
        except Exception as e:
            logger.error(f"Error setting mitigation actions: {e}")
            self.mitigation_actions = '[]'
    
    def __repr__(self):
        return f'<SecurityEvent {self.id}: {self.threat_type} - {self.response_status}>'


class SystemActivity(db.Model):
    """
    System activity tracking for performance and health monitoring
    Purpose: Track system performance and health metrics
    """
    __tablename__ = 'system_activities'
    
    id = db.Column(db.Integer, primary_key=True)
    audit_log_id = db.Column(db.Integer, db.ForeignKey('audit_logs.id'), nullable=False)
    
    # Performance metrics
    cpu_usage = db.Column(db.Float, nullable=True)
    memory_usage = db.Column(db.Float, nullable=True)
    disk_usage = db.Column(db.Float, nullable=True)
    network_io = db.Column(db.Float, nullable=True)
    
    # Application metrics
    active_sessions = db.Column(db.Integer, nullable=True)
    concurrent_scans = db.Column(db.Integer, nullable=True)
    model_inference_time = db.Column(db.Float, nullable=True)
    database_connections = db.Column(db.Integer, nullable=True)
    
    # Health indicators
    health_status = db.Column(db.String(20), default='HEALTHY')
    error_count = db.Column(db.Integer, default=0)
    warning_count = db.Column(db.Integer, default=0)
    
    # Additional metrics
    response_time_avg = db.Column(db.Float, nullable=True)
    throughput = db.Column(db.Float, nullable=True)
    uptime_seconds = db.Column(db.Integer, nullable=True)
    
    # Timestamps
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships will be set after model loading
    
    def __repr__(self):
        return f'<SystemActivity {self.id}: {self.health_status} at {self.recorded_at}>'


class ComplianceLog(db.Model):
    """
    Compliance logging for regulatory requirements
    Purpose: Track compliance-related activities and audits
    """
    __tablename__ = 'compliance_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    audit_log_id = db.Column(db.Integer, db.ForeignKey('audit_logs.id'), nullable=False)
    
    # Compliance details
    regulation_type = db.Column(db.String(50), nullable=False)  # GDPR, HIPAA, SOX, etc.
    compliance_requirement = db.Column(db.String(200), nullable=False)
    compliance_status = db.Column(db.String(20), nullable=False)  # COMPLIANT, NON_COMPLIANT, PENDING
    
    # Assessment details
    assessment_date = db.Column(db.DateTime, default=datetime.utcnow)
    assessor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    assessment_notes = db.Column(db.Text, nullable=True)
    evidence_provided = db.Column(db.Text, nullable=True)  # JSON stored as text
    
    # Remediation
    remediation_required = db.Column(db.Boolean, default=False)
    remediation_deadline = db.Column(db.DateTime, nullable=True)
    remediation_status = db.Column(db.String(20), nullable=True)
    remediation_notes = db.Column(db.Text, nullable=True)
    
    # Risk assessment
    compliance_risk_level = db.Column(db.String(20), default='LOW')
    potential_penalties = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships will be set after model loading
    
    def get_evidence_provided(self):
        """Get evidence as list"""
        try:
            return json.loads(self.evidence_provided or '[]')
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_evidence_provided(self, evidence):
        """Set evidence from list"""
        try:
            self.evidence_provided = json.dumps(evidence) if evidence else '[]'
        except Exception as e:
            logger.error(f"Error setting evidence: {e}")
            self.evidence_provided = '[]'
    
    def __repr__(self):
        return f'<ComplianceLog {self.id}: {self.regulation_type} - {self.compliance_status}>'


# Helper functions for audit logging
def log_user_activity(user_id, activity_type, description, ip_address=None, **kwargs):
    """Helper function to log user activities"""
    return AuditLog.log_user_activity(user_id, activity_type, description, ip_address, **kwargs)


def log_security_event(description, threat_type, severity, user_id=None, ip_address=None, details=None):
    """Helper function to log security events"""
    return AuditLog.log_security_event(description, threat_type, severity, user_id, ip_address, details)


def log_system_event(event_type, description, details=None, **kwargs):
    """Helper function to log system events"""
    return AuditLog.log_event(event_type, description, details=details, **kwargs)


def search_audit_logs(filters, limit=1000, offset=0):
    """Helper function to search audit logs"""
    return AuditLog.search_logs(limit=limit, offset=offset, **filters)


def generate_compliance_report(regulation_type, start_date=None, end_date=None):
    """Helper function to generate compliance reports"""
    return AuditLog.compliance_reporting(regulation_type, start_date, end_date)


# Export all models and functions
__all__ = [
    'AuditLog',
    'EventType',
    'SecurityLevel',
    'SecurityEvent',
    'SystemActivity',
    'ComplianceLog',
    'log_user_activity',
    'log_security_event',
    'log_system_event',
    'search_audit_logs',
    'generate_compliance_report'
]