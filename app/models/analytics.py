"""
Analytics Models - Track page views, user behavior, and system metrics
Purpose: Comprehensive analytics and monitoring for admin dashboard
"""

from app.models import db
from datetime import datetime, timedelta
from sqlalchemy import func, text
from enum import Enum
import json


class PageViewEvent(db.Model):
    """Track page view events for analytics"""
    __tablename__ = 'page_view_events'
    
    id = db.Column(db.Integer, primary_key=True)
    page_path = db.Column(db.String(255), nullable=False, index=True)
    page_title = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    session_id = db.Column(db.String(100), index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    referrer = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Additional tracking data
    load_time = db.Column(db.Float)  # Page load time in seconds
    screen_resolution = db.Column(db.String(20))
    device_type = db.Column(db.String(50))
    browser_name = db.Column(db.String(100))
    country_code = db.Column(db.String(5))
    city = db.Column(db.String(100))
    
    @classmethod
    def track_page_view(cls, page_path, user_id=None, session_id=None, **kwargs):
        """Track a page view event"""
        page_view = cls(
            page_path=page_path,
            user_id=user_id,
            session_id=session_id,
            **kwargs
        )
        db.session.add(page_view)
        db.session.commit()
        return page_view
    
    @classmethod
    def get_page_analytics(cls, page_path=None, days=30):
        """Get analytics for a specific page or all pages"""
        query = cls.query.filter(
            cls.timestamp >= datetime.utcnow() - timedelta(days=days)
        )
        
        if page_path:
            query = query.filter(cls.page_path == page_path)
            
        return query


class UserActivity(db.Model):
    """Track detailed user activities"""
    __tablename__ = 'user_activities'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    activity_type = db.Column(db.String(100), nullable=False, index=True)
    activity_details = db.Column(db.Text)  # JSON data
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Activity metadata
    duration = db.Column(db.Integer)  # Duration in seconds
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    
    @classmethod
    def log_activity(cls, user_id, activity_type, details=None, **kwargs):
        """Log user activity"""
        activity = cls(
            user_id=user_id,
            activity_type=activity_type,
            activity_details=json.dumps(details) if details else None,
            **kwargs
        )
        db.session.add(activity)
        db.session.commit()
        return activity


class SystemMetrics(db.Model):
    """Track system performance metrics"""
    __tablename__ = 'system_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    metric_type = db.Column(db.String(100), nullable=False, index=True)
    metric_value = db.Column(db.Float, nullable=False)
    metric_unit = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Additional metadata
    hostname = db.Column(db.String(255))
    component = db.Column(db.String(100))  # Database, API, AI Engine, etc.
    metric_metadata = db.Column(db.Text)  # JSON data
    
    @classmethod
    def record_metric(cls, metric_type, value, unit=None, **kwargs):
        """Record a system metric"""
        metric = cls(
            metric_type=metric_type,
            metric_value=value,
            metric_unit=unit,
            **kwargs
        )
        db.session.add(metric)
        db.session.commit()
        return metric


class SecurityIncident(db.Model):
    """Track security incidents and suspicious activities"""
    __tablename__ = 'security_incidents'
    
    class IncidentType(Enum):
        FAILED_LOGIN = "failed_login"
        RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
        SUSPICIOUS_ACTIVITY = "suspicious_activity"
        UNAUTHORIZED_ACCESS = "unauthorized_access"
        VULNERABILITY_DETECTED = "vulnerability_detected"
        SYSTEM_COMPROMISE = "system_compromise"
    
    class Severity(Enum):
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.Enum(IncidentType), nullable=False, index=True)
    severity = db.Column(db.Enum(Severity), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    
    # Associated data
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    ip_address = db.Column(db.String(45), index=True)
    user_agent = db.Column(db.Text)
    
    # Incident details
    incident_data = db.Column(db.Text)  # JSON data
    resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    @classmethod
    def report_incident(cls, incident_type, severity, title, description=None, **kwargs):
        """Report a security incident"""
        incident = cls(
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            **kwargs
        )
        db.session.add(incident)
        db.session.commit()
        return incident


class AnalyticsManager:
    """Manager class for analytics operations"""
    
    @staticmethod
    def get_dashboard_analytics(days=30):
        """Get comprehensive analytics for admin dashboard"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Page view analytics
        page_views = PageViewEvent.query.filter(
            PageViewEvent.timestamp >= start_date
        ).all()
        
        # User activity analytics
        user_activities = UserActivity.query.filter(
            UserActivity.timestamp >= start_date
        ).all()
        
        # System metrics
        system_metrics = SystemMetrics.query.filter(
            SystemMetrics.timestamp >= start_date
        ).all()
        
        # Security incidents
        security_incidents = SecurityIncident.query.filter(
            SecurityIncident.timestamp >= start_date
        ).all()
        
        return {
            'page_views': page_views,
            'user_activities': user_activities,
            'system_metrics': system_metrics,
            'security_incidents': security_incidents,
            'period': {'start': start_date, 'end': end_date}
        }
    
    @staticmethod
    def get_index_page_analytics(days=30):
        """Get specific analytics for index.html page"""
        index_views = PageViewEvent.get_page_analytics('/', days=days).all()
        
        # Calculate metrics
        total_views = len(index_views)
        unique_visitors = len(set(view.ip_address for view in index_views if view.ip_address))
        
        # Daily breakdown
        daily_views = {}
        for view in index_views:
            date_key = view.timestamp.date().isoformat()
            daily_views[date_key] = daily_views.get(date_key, 0) + 1
        
        # Browser breakdown
        browser_stats = {}
        for view in index_views:
            browser = view.browser_name or 'Unknown'
            browser_stats[browser] = browser_stats.get(browser, 0) + 1
        
        return {
            'total_views': total_views,
            'unique_visitors': unique_visitors,
            'daily_views': daily_views,
            'browser_stats': browser_stats,
            'recent_views': index_views[:50]  # Last 50 views
        }
    
    @staticmethod
    def get_user_behavior_analytics(days=30):
        """Get user behavior analytics"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Active users per day
        daily_active_users = db.session.query(
            func.date(UserActivity.timestamp).label('date'),
            func.count(func.distinct(UserActivity.user_id)).label('active_users')
        ).filter(
            UserActivity.timestamp >= start_date
        ).group_by(func.date(UserActivity.timestamp)).all()
        
        # Most popular activities
        popular_activities = db.session.query(
            UserActivity.activity_type,
            func.count(UserActivity.id).label('count')
        ).filter(
            UserActivity.timestamp >= start_date
        ).group_by(UserActivity.activity_type).order_by(
            func.count(UserActivity.id).desc()
        ).limit(10).all()
        
        return {
            'daily_active_users': dict(daily_active_users),
            'popular_activities': dict(popular_activities)
        }