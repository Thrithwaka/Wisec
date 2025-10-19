"""
Template filters for Jinja2 templates
"""

from app.models.approval_system import ApprovalSystemManager


def user_advanced_access(user_id):
    """
    Template filter to check user's advanced access status
    Usage in template: {{ current_user.id | user_advanced_access }}
    """
    try:
        return ApprovalSystemManager.get_user_access_status(user_id)
    except Exception:
        return {
            'has_access': False,
            'access_level': 'basic',
            'features': [],
            'can_use': False
        }


def register_template_filters(app):
    """Register template filters with Flask app"""
    app.jinja_env.filters['user_advanced_access'] = user_advanced_access