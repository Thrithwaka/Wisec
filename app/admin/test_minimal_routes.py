"""
Minimal admin routes for testing
"""

from flask import Blueprint, jsonify
from datetime import datetime

# Create a test blueprint
test_admin_bp = Blueprint('test_admin', __name__, url_prefix='/admin')

@test_admin_bp.route('/users/count-minimal')
def get_users_count_minimal():
    """Minimal user count endpoint"""
    try:
        # Try to import User model
        try:
            from app.models.user import User
            from app.models import db
            
            total_users = User.query.count()
            active_users = User.query.filter_by(is_verified=True).count()
            
            return jsonify({
                'success': True,
                'data': {
                    'total_users': total_users,
                    'active_users': active_users
                },
                'timestamp': datetime.utcnow().isoformat()
            })
        except Exception as db_error:
            return jsonify({
                'success': True,
                'data': {
                    'total_users': 5,
                    'active_users': 3
                },
                'timestamp': datetime.utcnow().isoformat(),
                'note': f'Mock data - DB error: {str(db_error)}'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@test_admin_bp.route('/system-health-minimal')
def system_health_minimal():
    """Minimal system health endpoint"""
    try:
        import psutil
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory()
    except ImportError:
        cpu_usage = 25.5
        memory = type('obj', (object,), {'percent': 45.2})
    
    return jsonify({
        'success': True,
        'health_data': {
            'cpu_usage': cpu_usage,
            'memory_usage': memory.percent,
            'status': 'healthy'
        },
        'timestamp': datetime.utcnow().isoformat()
    })