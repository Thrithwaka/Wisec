"""
Wi-Fi Security System - Comprehensive Error Handling
app/utils/error_handling.py

ROBUST ERROR HANDLING:
- Centralized error management
- Graceful fallbacks and recovery
- Performance monitoring
- User-friendly error messages
- Security-aware error logging
"""

import logging
import traceback
import time
import threading
from typing import Dict, Any, Optional, Callable
from functools import wraps
from datetime import datetime
import inspect
import sys

logger = logging.getLogger(__name__)

class ErrorTracker:
    """Track and analyze application errors"""
    
    def __init__(self):
        self.error_counts = {}
        self.error_history = []
        self.max_history = 1000
        self._lock = threading.Lock()
    
    def record_error(self, error_type: str, error_message: str, context: Dict = None):
        """Record an error occurrence"""
        with self._lock:
            # Update count
            if error_type not in self.error_counts:
                self.error_counts[error_type] = 0
            self.error_counts[error_type] += 1
            
            # Add to history
            error_record = {
                'timestamp': time.time(),
                'type': error_type,
                'message': error_message,
                'context': context or {}
            }
            
            self.error_history.append(error_record)
            
            # Trim history if too long
            if len(self.error_history) > self.max_history:
                self.error_history = self.error_history[-self.max_history:]
    
    def get_error_stats(self) -> Dict:
        """Get error statistics"""
        with self._lock:
            recent_errors = [
                err for err in self.error_history 
                if time.time() - err['timestamp'] < 3600  # Last hour
            ]
            
            return {
                'total_errors': len(self.error_history),
                'recent_errors': len(recent_errors),
                'error_counts': self.error_counts.copy(),
                'last_error': self.error_history[-1] if self.error_history else None
            }

# Global error tracker
error_tracker = ErrorTracker()

class WisecError(Exception):
    """Base exception for Wisec application"""
    
    def __init__(self, message: str, error_code: str = None, context: Dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or 'WISEC_ERROR'
        self.context = context or {}
        self.timestamp = time.time()
        
        # Record the error
        error_tracker.record_error(self.error_code, message, context)

class WiFiScanError(WisecError):
    """WiFi scanning related errors"""
    pass

class ModelLoadError(WisecError):
    """AI model loading errors"""
    pass

class CacheError(WisecError):
    """Caching system errors"""
    pass

class AuthError(WisecError):
    """Authentication errors"""
    pass

class ValidationError(WisecError):
    """Input validation errors"""
    pass

def safe_execute(fallback_value=None, log_errors=True, reraise=False):
    """Decorator for safe function execution with fallbacks"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_context = {
                    'function': func.__name__,
                    'args_count': len(args),
                    'kwargs_keys': list(kwargs.keys()),
                    'exception_type': type(e).__name__
                }
                
                if log_errors:
                    logger.error(f"Error in {func.__name__}: {str(e)}", extra=error_context)
                
                error_tracker.record_error(
                    f"{func.__name__}_error",
                    str(e),
                    error_context
                )
                
                if reraise:
                    raise
                
                return fallback_value
        
        return wrapper
    return decorator

def handle_api_errors(func):
    """Decorator for API endpoint error handling"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValidationError as e:
            return {
                'status': 'error',
                'error': 'validation_error',
                'message': str(e),
                'timestamp': time.time()
            }, 400
        except AuthError as e:
            return {
                'status': 'error',
                'error': 'auth_error',
                'message': str(e),
                'timestamp': time.time()
            }, 401
        except WiFiScanError as e:
            return {
                'status': 'error',
                'error': 'wifi_scan_error',
                'message': str(e),
                'timestamp': time.time()
            }, 503
        except ModelLoadError as e:
            return {
                'status': 'error',
                'error': 'model_error',
                'message': str(e),
                'timestamp': time.time()
            }, 503
        except Exception as e:
            # Log unexpected errors with full traceback
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}", 
                        exc_info=True)
            
            error_tracker.record_error(
                'unexpected_api_error',
                str(e),
                {'endpoint': func.__name__}
            )
            
            return {
                'status': 'error',
                'error': 'internal_error',
                'message': 'An unexpected error occurred',
                'timestamp': time.time()
            }, 500
    
    return wrapper

class GracefulFallback:
    """Provides graceful fallbacks for various system components"""
    
    @staticmethod
    @safe_execute(fallback_value=[])
    def get_wifi_networks():
        """Fallback for WiFi network retrieval"""
        return [
            {
                'ssid': 'Fallback Network',
                'bssid': '00:00:00:00:00:00',
                'signal_strength': -50,
                'channel': 1,
                'encryption': 'Unknown',
                'security': 'Unknown',
                'quality': 50.0,
                'vendor': 'Unknown',
                'is_hidden': False
            }
        ]
    
    @staticmethod
    @safe_execute(fallback_value={'status': 'unavailable'})
    def get_model_prediction(model_name: str, features: list):
        """Fallback for AI model predictions"""
        logger.warning(f"Using fallback prediction for model {model_name}")
        return {
            'status': 'fallback',
            'model': model_name,
            'prediction': {
                'result': 'low_risk',
                'confidence': 0.5,
                'fallback_used': True
            }
        }
    
    @staticmethod
    @safe_execute(fallback_value={'connected': False})
    def get_current_wifi():
        """Fallback for current WiFi connection"""
        return {
            'connected': False,
            'ssid': None,
            'fallback_used': True
        }

class PerformanceMonitor:
    """Monitor system performance and detect issues"""
    
    def __init__(self):
        self.operation_times = {}
        self.slow_operations = []
        self._lock = threading.Lock()
    
    def record_operation(self, operation_name: str, duration: float):
        """Record operation duration"""
        with self._lock:
            if operation_name not in self.operation_times:
                self.operation_times[operation_name] = []
            
            self.operation_times[operation_name].append(duration)
            
            # Keep only recent times (last 100)
            if len(self.operation_times[operation_name]) > 100:
                self.operation_times[operation_name] = self.operation_times[operation_name][-100:]
            
            # Record slow operations
            if duration > 10.0:  # More than 10 seconds
                self.slow_operations.append({
                    'operation': operation_name,
                    'duration': duration,
                    'timestamp': time.time()
                })
                
                # Keep only recent slow operations
                if len(self.slow_operations) > 50:
                    self.slow_operations = self.slow_operations[-50:]
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics"""
        with self._lock:
            stats = {}
            
            for operation, times in self.operation_times.items():
                if times:
                    stats[operation] = {
                        'avg_duration': sum(times) / len(times),
                        'max_duration': max(times),
                        'min_duration': min(times),
                        'sample_count': len(times)
                    }
            
            return {
                'operation_stats': stats,
                'slow_operations': self.slow_operations[-10:],  # Last 10 slow ops
                'total_operations': sum(len(times) for times in self.operation_times.values())
            }

# Global performance monitor
performance_monitor = PerformanceMonitor()

def monitor_performance(threshold: float = 5.0):
    """Decorator to monitor function performance"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                performance_monitor.record_operation(func.__name__, duration)
                
                if duration > threshold:
                    logger.warning(f"Slow operation: {func.__name__} took {duration:.2f}s")
        
        return wrapper
    return decorator

class SystemHealthChecker:
    """Check system health and detect issues"""
    
    def __init__(self):
        self.health_checks = {}
        self.last_check = None
    
    def register_health_check(self, name: str, check_func: Callable):
        """Register a health check function"""
        self.health_checks[name] = check_func
    
    @safe_execute(fallback_value={'status': 'error', 'message': 'Health check failed'})
    def run_health_checks(self) -> Dict:
        """Run all registered health checks"""
        results = {}
        overall_status = 'healthy'
        
        for name, check_func in self.health_checks.items():
            try:
                start_time = time.time()
                result = check_func()
                duration = time.time() - start_time
                
                if isinstance(result, dict):
                    result['check_duration'] = duration
                else:
                    result = {'status': result, 'check_duration': duration}
                
                results[name] = result
                
                # Update overall status
                if result.get('status') in ['error', 'critical']:
                    overall_status = 'unhealthy'
                elif result.get('status') == 'warning' and overall_status == 'healthy':
                    overall_status = 'degraded'
                
            except Exception as e:
                logger.error(f"Health check {name} failed: {e}")
                results[name] = {
                    'status': 'error',
                    'message': str(e),
                    'check_duration': 0
                }
                overall_status = 'unhealthy'
        
        self.last_check = time.time()
        
        return {
            'overall_status': overall_status,
            'checks': results,
            'timestamp': self.last_check,
            'error_stats': error_tracker.get_error_stats(),
            'performance_stats': performance_monitor.get_performance_stats()
        }

# Global health checker
health_checker = SystemHealthChecker()

def setup_default_health_checks():
    """Setup default system health checks"""
    
    def database_health():
        try:
            from flask import current_app
            if hasattr(current_app, 'db'):
                current_app.db.session.execute('SELECT 1')
                return {'status': 'healthy', 'message': 'Database connected'}
            return {'status': 'warning', 'message': 'Database not initialized'}
        except Exception as e:
            return {'status': 'error', 'message': f'Database error: {str(e)}'}
    
    def wifi_scanner_health():
        try:
            from flask import current_app
            if hasattr(current_app, '_wifi_scanner'):
                scanner = current_app._wifi_scanner
                stats = scanner.get_scan_statistics()
                return {'status': 'healthy', 'message': f"Scanner active, {stats['latest_scan_count']} networks cached"}
            return {'status': 'warning', 'message': 'WiFi scanner not initialized'}
        except Exception as e:
            return {'status': 'error', 'message': f'WiFi scanner error: {str(e)}'}
    
    def model_loader_health():
        try:
            from flask import current_app
            if hasattr(current_app, '_model_loader'):
                loader = current_app._model_loader
                health = loader.health_check()
                return {'status': health['status'], 'message': f"Models: {health.get('models_loaded', 0)} loaded"}
            return {'status': 'warning', 'message': 'Model loader not initialized'}
        except Exception as e:
            return {'status': 'error', 'message': f'Model loader error: {str(e)}'}
    
    def memory_health():
        try:
            import psutil
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                return {'status': 'critical', 'message': f'High memory usage: {memory.percent}%'}
            elif memory.percent > 80:
                return {'status': 'warning', 'message': f'Memory usage: {memory.percent}%'}
            else:
                return {'status': 'healthy', 'message': f'Memory usage: {memory.percent}%'}
        except ImportError:
            return {'status': 'unknown', 'message': 'psutil not available'}
        except Exception as e:
            return {'status': 'error', 'message': f'Memory check error: {str(e)}'}
    
    # Register health checks
    health_checker.register_health_check('database', database_health)
    health_checker.register_health_check('wifi_scanner', wifi_scanner_health)
    health_checker.register_health_check('model_loader', model_loader_health)
    health_checker.register_health_check('memory', memory_health)

# Context manager for error handling
class ErrorContext:
    """Context manager for handling errors in code blocks"""
    
    def __init__(self, operation_name: str, fallback_value=None, log_errors=True):
        self.operation_name = operation_name
        self.fallback_value = fallback_value
        self.log_errors = log_errors
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        performance_monitor.record_operation(self.operation_name, duration)
        
        if exc_type is not None:
            if self.log_errors:
                logger.error(f"Error in {self.operation_name}: {str(exc_val)}")
            
            error_tracker.record_error(
                f"{self.operation_name}_error",
                str(exc_val),
                {'exception_type': exc_type.__name__}
            )
            
            # Return True to suppress the exception if we have a fallback
            return self.fallback_value is not None
        
        return False

# Initialize default health checks
setup_default_health_checks()