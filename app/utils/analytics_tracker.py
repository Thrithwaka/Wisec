"""
Analytics Tracking Utilities - Track page views and user activities
Purpose: Automatic tracking for admin dashboard analytics
"""

from flask import request, session, g
from flask_login import current_user
from datetime import datetime, timedelta
import re
try:
    from user_agents import parse
except ImportError:
    # Fallback if user_agents library is not available
    def parse(user_agent_string):
        class MockUserAgent:
            is_mobile = False
            is_tablet = False
            is_pc = True
            browser = type('obj', (object,), {'family': 'Unknown', 'version_string': ''})()
        return MockUserAgent()

from app.models.analytics import PageViewEvent, UserActivity, SecurityIncident
from app.models import db
import logging

logger = logging.getLogger(__name__)


class AnalyticsTracker:
    """Analytics tracking utility class"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize analytics tracking with Flask app"""
        app.before_request(self.track_page_view)
        app.after_request(self.track_response)
    
    def track_page_view(self):
        """Track page view before request processing"""
        try:
            # Skip tracking for static files and API endpoints that don't need tracking
            if self._should_skip_tracking():
                return
            
            # Parse user agent
            user_agent = parse(request.headers.get('User-Agent', ''))
            
            # Get user information
            user_id = current_user.id if current_user.is_authenticated else None
            session_id = session.get('session_id', request.remote_addr)
            
            # Extract device and browser information
            device_type = self._get_device_type(user_agent)
            browser_name = f"{user_agent.browser.family} {user_agent.browser.version_string}"
            
            # Track the page view
            page_view = PageViewEvent.track_page_view(
                page_path=request.path,
                page_title=self._extract_page_title(request.path),
                user_id=user_id,
                session_id=session_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                referrer=request.headers.get('Referer'),
                device_type=device_type,
                browser_name=browser_name,
                timestamp=datetime.utcnow()
            )
            
            # Store in request context for potential use
            g.page_view_id = page_view.id
            
            # Track specific activities for important pages
            if request.path == '/':
                self._track_index_page_visit(user_id)
            elif request.path.startswith('/admin'):
                self._track_admin_access(user_id)
                
        except Exception as e:
            logger.error(f"Analytics tracking error: {str(e)}")
    
    def track_response(self, response):
        """Track response information after request processing"""
        try:
            if hasattr(g, 'page_view_id') and g.page_view_id:
                # Update page view with response information
                page_view = PageViewEvent.query.get(g.page_view_id)
                if page_view:
                    # Calculate load time if available
                    if hasattr(g, 'request_start_time'):
                        load_time = (datetime.utcnow() - g.request_start_time).total_seconds()
                        page_view.load_time = load_time
                    
                    db.session.commit()
            
            return response
            
        except Exception as e:
            logger.error(f"Response tracking error: {str(e)}")
            return response
    
    def _should_skip_tracking(self):
        """Determine if tracking should be skipped for this request"""
        skip_patterns = [
            r'/static/',
            r'/favicon\.ico',
            r'/robots\.txt',
            r'\.css$',
            r'\.js$',
            r'\.png$',
            r'\.jpg$',
            r'\.jpeg$',
            r'\.gif$',
            r'\.svg$',
            r'/api/health$',
            r'/api/heartbeat$'
        ]
        
        path = request.path
        return any(re.search(pattern, path) for pattern in skip_patterns)
    
    def _get_device_type(self, user_agent):
        """Determine device type from user agent"""
        if user_agent.is_mobile:
            return 'mobile'
        elif user_agent.is_tablet:
            return 'tablet'
        elif user_agent.is_pc:
            return 'desktop'
        else:
            return 'unknown'
    
    def _extract_page_title(self, path):
        """Extract readable page title from path"""
        titles = {
            '/': 'Home Page',
            '/login': 'Login',
            '/register': 'Register',
            '/dashboard': 'User Dashboard',
            '/admin/dashboard': 'Admin Dashboard',
            '/admin/users': 'User Management',
            '/admin/analytics': 'Analytics',
            '/scan': 'Wi-Fi Scan',
            '/deep-scan': 'Deep Scan',
            '/network-topology': 'Network Topology',
            '/scan-history': 'Scan History',
            '/profile': 'User Profile'
        }
        
        return titles.get(path, f"Page: {path}")
    
    def _track_index_page_visit(self, user_id):
        """Track specific analytics for index page visits"""
        UserActivity.log_activity(
            user_id=user_id,
            activity_type='INDEX_PAGE_VISIT',
            details={
                'path': '/',
                'timestamp': datetime.utcnow().isoformat(),
                'user_agent': request.headers.get('User-Agent'),
                'referrer': request.headers.get('Referer')
            },
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
    
    def _track_admin_access(self, user_id):
        """Track admin panel access"""
        if user_id:
            UserActivity.log_activity(
                user_id=user_id,
                activity_type='ADMIN_ACCESS',
                details={
                    'path': request.path,
                    'method': request.method,
                    'timestamp': datetime.utcnow().isoformat()
                },
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )


def track_user_activity(activity_type, details=None, user_id=None):
    """Utility function to track specific user activities"""
    try:
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        
        if user_id:
            UserActivity.log_activity(
                user_id=user_id,
                activity_type=activity_type,
                details=details,
                ip_address=request.remote_addr if request else None,
                user_agent=request.headers.get('User-Agent') if request else None
            )
    except Exception as e:
        logger.error(f"Activity tracking error: {str(e)}")


def track_security_incident(incident_type, severity, title, description=None, **kwargs):
    """Utility function to track security incidents"""
    try:
        SecurityIncident.report_incident(
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            user_id=current_user.id if current_user.is_authenticated else None,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None,
            **kwargs
        )
    except Exception as e:
        logger.error(f"Security incident tracking error: {str(e)}")


def get_real_time_stats():
    """Get real-time statistics for admin dashboard"""
    try:
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        stats = {
            'current_active_users': UserActivity.query.filter(
                UserActivity.timestamp >= hour_ago
            ).with_entities(UserActivity.user_id).distinct().count(),
            
            'page_views_last_hour': PageViewEvent.query.filter(
                PageViewEvent.timestamp >= hour_ago
            ).count(),
            
            'page_views_today': PageViewEvent.query.filter(
                PageViewEvent.timestamp >= day_ago
            ).count(),
            
            'index_views_today': PageViewEvent.query.filter(
                PageViewEvent.page_path == '/',
                PageViewEvent.timestamp >= day_ago
            ).count(),
            
            'security_incidents_today': SecurityIncident.query.filter(
                SecurityIncident.timestamp >= day_ago
            ).count(),
            
            'unique_visitors_today': PageViewEvent.query.filter(
                PageViewEvent.timestamp >= day_ago
            ).with_entities(PageViewEvent.ip_address).distinct().count()
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Real-time stats error: {str(e)}")
        return {
            'current_active_users': 0,
            'page_views_last_hour': 0,
            'page_views_today': 0,
            'index_views_today': 0,
            'security_incidents_today': 0,
            'unique_visitors_today': 0
        }


# Create global instance
analytics_tracker = AnalyticsTracker()