"""
Wi-Fi Security System - Custom Decorators
Purpose: Custom Flask decorators for common functionality including authentication,
rate limiting, logging, caching, and performance monitoring.
"""

import time
import json
import hashlib
from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
from flask import session, request, jsonify, current_app, g
from flask_login import current_user
from werkzeug.exceptions import Unauthorized, Forbidden, TooManyRequests


class AuthDecorator:
    """Authentication decorators for access control"""
    
    @staticmethod
    def login_required(f):
        """Decorator to require user authentication"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                return current_app.login_manager.unauthorized()
            
            # Log authentication check
            current_app.logger.info(f"Auth check passed for user {session['user_id']} accessing {request.endpoint}")
            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def admin_required(f):
        """Decorator to require admin access - Only actual admin role users"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                return current_app.login_manager.unauthorized()
            
            # Check actual admin role (not just admin approval)
            from flask_login import current_user
            if not current_user.is_authenticated or not current_user.is_admin():
                current_app.logger.warning(f"Unauthorized admin access attempt by user {session.get('user_id', 'unknown')}")
                if request.is_json:
                    return jsonify({'error': 'Admin role required'}), 403
                raise Forbidden('Admin role required')
            
            # Log admin access
            current_app.logger.info(f"Admin access granted to user {current_user.email} ({current_user.role.value if current_user.role else 'unknown'}) for {request.endpoint}")
            return f(*args, **kwargs)
        return decorated_function


class RateLimitDecorator:
    """Rate limiting decorators for API protection"""
    
    # In-memory rate limit storage (use Redis in production)
    _rate_limits = defaultdict(list)
    
    @classmethod
    def rate_limit(cls, max_requests=60, per_seconds=3600, key_func=None):
        """
        Rate limiting decorator
        Args:
            max_requests: Maximum requests allowed
            per_seconds: Time window in seconds
            key_func: Function to generate rate limit key
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Generate rate limit key
                if key_func:
                    key = key_func()
                else:
                    key = f"{request.remote_addr}:{request.endpoint}"
                
                # Get current time
                now = datetime.utcnow()
                
                # Clean old entries
                cls._rate_limits[key] = [
                    timestamp for timestamp in cls._rate_limits[key]
                    if now - timestamp < timedelta(seconds=per_seconds)
                ]
                
                # Check rate limit
                if len(cls._rate_limits[key]) >= max_requests:
                    current_app.logger.warning(f"Rate limit exceeded for key: {key}")
                    if request.is_json:
                        return jsonify({
                            'error': 'Rate limit exceeded',
                            'retry_after': per_seconds
                        }), 429
                    raise TooManyRequests('Rate limit exceeded')
                
                # Add current request
                cls._rate_limits[key].append(now)
                
                # Execute function
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    @classmethod
    def api_rate_limit(cls, f):
        """Specific rate limit for API endpoints"""
        return cls.rate_limit(max_requests=100, per_seconds=3600)(f)


class LoggingDecorator:
    """Logging decorators for activity tracking"""
    
    @staticmethod
    def log_activity(activity_type=None, log_args=False, log_result=False):
        """
        Activity logging decorator
        Args:
            activity_type: Type of activity being logged
            log_args: Whether to log function arguments
            log_result: Whether to log function result
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                start_time = time.time()
                
                # Prepare log data
                log_data = {
                    'function': f.__name__,
                    'activity_type': activity_type or f.__name__,
                    'user_id': session.get('user_id'),
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'timestamp': datetime.utcnow().isoformat(),
                    'endpoint': request.endpoint,
                    'method': request.method
                }
                
                # Log arguments if requested
                if log_args and args:
                    log_data['args'] = str(args)
                if log_args and kwargs:
                    log_data['kwargs'] = {k: str(v) for k, v in kwargs.items()}
                
                try:
                    # Execute function
                    result = f(*args, **kwargs)
                    
                    # Calculate execution time
                    execution_time = time.time() - start_time
                    log_data['execution_time'] = execution_time
                    log_data['status'] = 'success'
                    
                    # Log result if requested
                    if log_result:
                        log_data['result'] = str(result)[:500]  # Truncate long results
                    
                    # Log activity
                    current_app.logger.info(f"Activity logged: {json.dumps(log_data)}")
                    
                    return result
                    
                except Exception as e:
                    # Log error
                    execution_time = time.time() - start_time
                    log_data['execution_time'] = execution_time
                    log_data['status'] = 'error'
                    log_data['error'] = str(e)
                    
                    current_app.logger.error(f"Activity error logged: {json.dumps(log_data)}")
                    raise
                    
            return decorated_function
        return decorator
    
    @staticmethod
    def security_log(f):
        """Security-specific logging decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            security_data = {
                'function': f.__name__,
                'user_id': session.get('user_id'),
                'ip_address': request.remote_addr,
                'timestamp': datetime.utcnow().isoformat(),
                'endpoint': request.endpoint,
                'security_level': 'HIGH'
            }
            
            try:
                result = f(*args, **kwargs)
                security_data['status'] = 'success'
                current_app.logger.info(f"Security event: {json.dumps(security_data)}")
                return result
            except Exception as e:
                security_data['status'] = 'failed'
                security_data['error'] = str(e)
                current_app.logger.warning(f"Security event failed: {json.dumps(security_data)}")
                raise
                
        return decorated_function


class CacheDecorator:
    """Caching decorators for performance optimization"""
    
    # In-memory cache storage (use Redis in production)
    _cache = {}
    _cache_timestamps = {}
    
    @classmethod
    def cache_result(cls, timeout=300, key_func=None):
        """
        Result caching decorator
        Args:
            timeout: Cache timeout in seconds
            key_func: Function to generate cache key
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    # Create key from function name and arguments
                    key_parts = [f.__name__]
                    key_parts.extend([str(arg) for arg in args])
                    key_parts.extend([f"{k}:{v}" for k, v in sorted(kwargs.items())])
                    cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()
                
                # Check cache
                now = time.time()
                if (cache_key in cls._cache and 
                    cache_key in cls._cache_timestamps and
                    now - cls._cache_timestamps[cache_key] < timeout):
                    
                    current_app.logger.debug(f"Cache hit for key: {cache_key}")
                    return cls._cache[cache_key]
                
                # Execute function and cache result
                result = f(*args, **kwargs)
                cls._cache[cache_key] = result
                cls._cache_timestamps[cache_key] = now
                
                current_app.logger.debug(f"Cache miss, stored result for key: {cache_key}")
                return result
                
            return decorated_function
        return decorator
    
    @classmethod
    def cache_network_scan(cls, f):
        """Specific caching for network scan results"""
        return cls.cache_result(timeout=60, key_func=lambda: f"network_scan:{request.remote_addr}")(f)


class ValidationDecorator:
    """Validation decorators for input validation"""
    
    @staticmethod
    def validate_json(required_fields=None):
        """
        JSON validation decorator
        Args:
            required_fields: List of required JSON fields
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not request.is_json:
                    return jsonify({'error': 'Content-Type must be application/json'}), 400
                
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No JSON data provided'}), 400
                
                # Check required fields
                if required_fields:
                    missing_fields = [field for field in required_fields if field not in data]
                    if missing_fields:
                        return jsonify({
                            'error': 'Missing required fields',
                            'missing_fields': missing_fields
                        }), 400
                
                # Add validated data to request context
                g.json_data = data
                return f(*args, **kwargs)
                
            return decorated_function
        return decorator
    
    @staticmethod
    def require_api_key(f):
        """API key validation decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            if not api_key:
                return jsonify({'error': 'API key required'}), 401
            
            # Validate API key (implement your validation logic)
            if not ValidationDecorator._validate_api_key(api_key):
                current_app.logger.warning(f"Invalid API key attempt: {api_key[:8]}...")
                return jsonify({'error': 'Invalid API key'}), 401
            
            return f(*args, **kwargs)
        return decorated_function
    
    @staticmethod
    def _validate_api_key(api_key):
        """Validate API key - implement your logic"""
        # For now, accept any non-empty key
        # In production, validate against database
        return bool(api_key)


class PerformanceDecorator:
    """Performance monitoring decorators"""
    
    @staticmethod
    def measure_performance(f):
        """Performance measurement decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            start_memory = current_app.config.get('MEMORY_USAGE', 0)  # Placeholder
            
            try:
                result = f(*args, **kwargs)
                
                # Calculate metrics
                execution_time = time.time() - start_time
                memory_used = 0  # Placeholder for memory calculation
                
                # Log performance metrics
                performance_data = {
                    'function': f.__name__,
                    'execution_time': execution_time,
                    'memory_used': memory_used,
                    'timestamp': datetime.utcnow().isoformat(),
                    'user_id': session.get('user_id'),
                    'endpoint': request.endpoint
                }
                
                current_app.logger.info(f"Performance metrics: {json.dumps(performance_data)}")
                
                # Add performance headers
                if hasattr(result, 'headers'):
                    result.headers['X-Execution-Time'] = str(execution_time)
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                current_app.logger.error(f"Performance measurement failed for {f.__name__}: {str(e)} (time: {execution_time}s)")
                raise
                
        return decorated_function
    
    @staticmethod
    def monitor_ai_model_performance(f):
        """AI model performance monitoring decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            
            try:
                # Execute AI model function
                result = f(*args, **kwargs)
                
                # Calculate inference time
                inference_time = time.time() - start_time
                
                # Log AI model performance
                ai_performance_data = {
                    'model_function': f.__name__,
                    'inference_time': inference_time,
                    'timestamp': datetime.utcnow().isoformat(),
                    'user_id': session.get('user_id'),
                    'performance_target': 0.1,  # 100ms target
                    'within_target': inference_time < 0.1
                }
                
                # Log to model performance log
                current_app.logger.info(f"AI Model Performance: {json.dumps(ai_performance_data)}")
                
                # Alert if performance degrades
                if inference_time > 0.2:  # 200ms threshold
                    current_app.logger.warning(f"AI model performance degradation: {f.__name__} took {inference_time:.3f}s")
                
                return result
                
            except Exception as e:
                inference_time = time.time() - start_time
                current_app.logger.error(f"AI model error in {f.__name__}: {str(e)} (time: {inference_time}s)")
                raise
                
        return decorated_function


# Convenience functions for commonly used decorator combinations
def api_endpoint(max_requests=100, require_auth=True, cache_timeout=None):
    """
    Combined decorator for API endpoints
    Args:
        max_requests: Rate limit
        require_auth: Whether authentication is required
        cache_timeout: Cache timeout in seconds
    """
    def decorator(f):
        # Apply decorators in reverse order
        decorated = f
        
        # Performance monitoring
        decorated = PerformanceDecorator.measure_performance(decorated)
        
        # Caching (if specified)
        if cache_timeout:
            decorated = CacheDecorator.cache_result(timeout=cache_timeout)(decorated)
        
        # Activity logging
        decorated = LoggingDecorator.log_activity(activity_type='api_call')(decorated)
        
        # Rate limiting
        decorated = RateLimitDecorator.rate_limit(max_requests=max_requests, per_seconds=3600)(decorated)
        
        # Authentication (if required)
        if require_auth:
            decorated = AuthDecorator.login_required(decorated)
        
        return decorated
    return decorator


def admin_api_endpoint(max_requests=50):
    """
    Combined decorator for admin API endpoints
    """
    def decorator(f):
        decorated = f
        decorated = PerformanceDecorator.measure_performance(decorated)
        decorated = LoggingDecorator.security_log(decorated)
        decorated = RateLimitDecorator.rate_limit(max_requests=max_requests, per_seconds=3600)(decorated)
        decorated = AuthDecorator.admin_required(decorated)
        return decorated
    return decorator


def ai_model_endpoint(cache_timeout=300):
    """
    Combined decorator for AI model endpoints
    """
    def decorator(f):
        decorated = f
        decorated = PerformanceDecorator.monitor_ai_model_performance(decorated)
        decorated = CacheDecorator.cache_result(timeout=cache_timeout)(decorated)
        decorated = LoggingDecorator.log_activity(activity_type='ai_prediction')(decorated)
        decorated = RateLimitDecorator.rate_limit(max_requests=200, per_seconds=3600)(decorated)
        decorated = AuthDecorator.login_required(decorated)
        return decorated
    return decorator


def wifi_operation_endpoint():
    """
    Combined decorator for Wi-Fi operation endpoints
    """
    def decorator(f):
        decorated = f
        decorated = PerformanceDecorator.measure_performance(decorated)
        decorated = LoggingDecorator.security_log(decorated)
        decorated = RateLimitDecorator.rate_limit(max_requests=30, per_seconds=3600)(decorated)
        decorated = AuthDecorator.login_required(decorated)
        return decorated
    return decorator


# Export the specific functions that are being imported
login_required = AuthDecorator.login_required
admin_required = AuthDecorator.admin_required
rate_limit = RateLimitDecorator.rate_limit
log_activity = LoggingDecorator.log_activity
security_log = LoggingDecorator.security_log
cache_result = CacheDecorator.cache_result
validate_json = ValidationDecorator.validate_json
require_api_key = ValidationDecorator.require_api_key
measure_performance = PerformanceDecorator.measure_performance