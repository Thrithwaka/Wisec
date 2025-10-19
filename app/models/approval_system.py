"""
Advanced Features Approval System Models
Industry-level approval workflow for advanced feature access
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from enum import Enum
import json

# Import db from models
try:
    from app.models import db
except ImportError:
    db = SQLAlchemy()


class ApprovalStatus(Enum):
    """Approval request status"""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class RequestType(Enum):
    """Type of approval request"""
    ADVANCED_FEATURES = "advanced_features"
    SPECIAL_ACCESS = "special_access"
    API_ACCESS = "api_access"
    BULK_OPERATIONS = "bulk_operations"
    ADMIN_TOOLS = "admin_tools"


class Priority(Enum):
    """Request priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class AdvancedFeatureRequest(db.Model):
    """
    Model for advanced features approval requests
    """
    __tablename__ = 'advanced_feature_requests'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User information
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Request details
    request_type = db.Column(db.Enum(RequestType), default=RequestType.ADVANCED_FEATURES, nullable=False)
    priority = db.Column(db.Enum(Priority), default=Priority.MEDIUM, nullable=False)
    
    # User submitted information
    purpose = db.Column(db.Text, nullable=False)  # Why they need access
    organization = db.Column(db.String(200), nullable=True)  # Organization name
    organization_role = db.Column(db.String(100), nullable=True)  # User's role in organization
    use_case = db.Column(db.Text, nullable=False)  # Specific use case
    expected_usage = db.Column(db.Text, nullable=True)  # Expected usage patterns
    
    # Document uploads (file paths)
    organization_document = db.Column(db.String(500), nullable=True)  # Path to uploaded document
    identification_document = db.Column(db.String(500), nullable=True)  # ID verification
    additional_documents = db.Column(db.Text, nullable=True)  # JSON array of additional document paths
    
    # Request status and workflow
    status = db.Column(db.Enum(ApprovalStatus), default=ApprovalStatus.PENDING, nullable=False)
    admin_notes = db.Column(db.Text, nullable=True)  # Admin's review notes
    rejection_reason = db.Column(db.Text, nullable=True)  # If rejected, why
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # When approval expires
    
    # Admin who reviewed
    reviewed_by_admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Additional metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    request_metadata = db.Column(db.Text, default='{}')  # JSON for additional data
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='feature_requests')
    reviewed_by = db.relationship('User', foreign_keys=[reviewed_by_admin_id])
    messages = db.relationship('ApprovalMessage', backref='request', cascade='all, delete-orphan')
    
    def __init__(self, user_id, purpose, use_case, **kwargs):
        self.user_id = user_id
        self.purpose = purpose
        self.use_case = use_case
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else None,
            'user_email': self.user.email if self.user else None,
            'request_type': self.request_type.value,
            'priority': self.priority.value,
            'purpose': self.purpose,
            'organization': self.organization,
            'organization_role': self.organization_role,
            'use_case': self.use_case,
            'expected_usage': self.expected_usage,
            'status': self.status.value,
            'admin_notes': self.admin_notes,
            'rejection_reason': self.rejection_reason,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'reviewed_by_admin_id': self.reviewed_by_admin_id,
            'reviewed_by_name': self.reviewed_by.username if self.reviewed_by else None,
            'has_documents': bool(self.organization_document or self.identification_document),
            'message_count': len(self.messages) if self.messages else 0
        }
    
    @property
    def days_pending(self):
        """Calculate days since request was created"""
        if self.created_at:
            return (datetime.utcnow() - self.created_at).days
        return 0
    
    @property
    def is_expired(self):
        """Check if approved access has expired"""
        if self.expires_at and self.status == ApprovalStatus.APPROVED:
            return datetime.utcnow() > self.expires_at
        return False
    
    def approve(self, admin_id, notes=None, expires_in_days=365):
        """Approve the request"""
        self.status = ApprovalStatus.APPROVED
        self.reviewed_by_admin_id = admin_id
        self.reviewed_at = datetime.utcnow()
        self.approved_at = datetime.utcnow()
        self.admin_notes = notes
        self.expires_at = datetime.utcnow().replace(year=datetime.utcnow().year + 1) if expires_in_days else None
        self.updated_at = datetime.utcnow()
    
    def reject(self, admin_id, reason, notes=None):
        """Reject the request"""
        self.status = ApprovalStatus.REJECTED
        self.reviewed_by_admin_id = admin_id
        self.reviewed_at = datetime.utcnow()
        self.rejection_reason = reason
        self.admin_notes = notes
        self.updated_at = datetime.utcnow()
    
    def set_under_review(self, admin_id):
        """Mark request as under review"""
        self.status = ApprovalStatus.UNDER_REVIEW
        self.reviewed_by_admin_id = admin_id
        self.reviewed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()


class ApprovalMessage(db.Model):
    """
    Messages between admin and user regarding approval requests
    """
    __tablename__ = 'approval_messages'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # Related request
    request_id = db.Column(db.Integer, db.ForeignKey('advanced_feature_requests.id'), nullable=False)
    
    # Message details
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_from_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    
    # Attachments (if any)
    attachments = db.Column(db.Text, nullable=True)  # JSON array of file paths
    
    # Relationships
    sender = db.relationship('User', backref='approval_messages')
    
    def __init__(self, request_id, sender_id, message, is_from_admin=False):
        self.request_id = request_id
        self.sender_id = sender_id
        self.message = message
        self.is_from_admin = is_from_admin
    
    def mark_as_read(self):
        """Mark message as read"""
        self.is_read = True
        self.read_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'request_id': self.request_id,
            'sender_id': self.sender_id,
            'sender_name': self.sender.username if self.sender else None,
            'message': self.message,
            'is_from_admin': self.is_from_admin,
            'is_read': self.is_read,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'attachments': json.loads(self.attachments) if self.attachments else []
        }


class UserAdvancedAccess(db.Model):
    """
    Track users' advanced feature access status
    """
    __tablename__ = 'user_advanced_access'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Access details
    has_advanced_access = db.Column(db.Boolean, default=False, nullable=False)
    access_level = db.Column(db.String(50), default='basic', nullable=False)  # basic, advanced, premium
    granted_features = db.Column(db.Text, default='[]')  # JSON array of granted features
    
    # Approval details
    approved_request_id = db.Column(db.Integer, db.ForeignKey('advanced_feature_requests.id'), nullable=True)
    approved_by_admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    # Timestamps
    granted_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used_at = db.Column(db.DateTime, nullable=True)
    
    # Usage tracking
    usage_count = db.Column(db.Integer, default=0)
    usage_limit = db.Column(db.Integer, nullable=True)  # Optional usage limit
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='advanced_access')
    approved_by = db.relationship('User', foreign_keys=[approved_by_admin_id])
    approved_request = db.relationship('AdvancedFeatureRequest')
    
    def __init__(self, user_id, **kwargs):
        self.user_id = user_id
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def is_expired(self):
        """Check if access has expired"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    @property
    def is_usage_limit_reached(self):
        """Check if usage limit has been reached"""
        if self.usage_limit:
            return self.usage_count >= self.usage_limit
        return False
    
    @property
    def can_use_advanced_features(self):
        """Check if user can currently use advanced features"""
        return (self.has_advanced_access and 
                not self.is_expired and 
                not self.is_usage_limit_reached)
    
    def grant_access(self, features=None, access_level='advanced', expires_in_days=365):
        """Grant advanced access to user"""
        self.has_advanced_access = True
        self.access_level = access_level
        self.granted_features = json.dumps(features or [])
        self.granted_at = datetime.utcnow()
        if expires_in_days:
            self.expires_at = datetime.utcnow().replace(year=datetime.utcnow().year + 1)
    
    def revoke_access(self):
        """Revoke advanced access"""
        self.has_advanced_access = False
        self.access_level = 'basic'
        self.granted_features = '[]'
    
    def record_usage(self):
        """Record feature usage"""
        self.usage_count += 1
        self.last_used_at = datetime.utcnow()
    
    def get_granted_features(self):
        """Get list of granted features"""
        try:
            return json.loads(self.granted_features or '[]')
        except:
            return []
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_name': self.user.username if self.user else None,
            'has_advanced_access': self.has_advanced_access,
            'access_level': self.access_level,
            'granted_features': self.get_granted_features(),
            'granted_at': self.granted_at.isoformat() if self.granted_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'usage_count': self.usage_count,
            'usage_limit': self.usage_limit,
            'is_expired': self.is_expired,
            'is_usage_limit_reached': self.is_usage_limit_reached,
            'can_use_advanced_features': self.can_use_advanced_features
        }


class UserNotification(db.Model):
    """
    User notifications system
    """
    __tablename__ = 'user_notifications'
    
    # Primary key
    id = db.Column(db.Integer, primary_key=True)
    
    # User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Notification details
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), default='info', nullable=False)  # info, success, warning, error
    
    # Status
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    is_dismissed = db.Column(db.Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    
    # Optional related data
    related_request_id = db.Column(db.Integer, db.ForeignKey('advanced_feature_requests.id'), nullable=True)
    action_url = db.Column(db.String(500), nullable=True)  # URL for action button
    action_text = db.Column(db.String(100), nullable=True)  # Text for action button
    
    # Relationships
    user = db.relationship('User', backref='notifications')
    related_request = db.relationship('AdvancedFeatureRequest')
    
    def __init__(self, user_id, title, message, **kwargs):
        self.user_id = user_id
        self.title = title
        self.message = message
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def mark_as_read(self):
        """Mark notification as read"""
        self.is_read = True
        self.read_at = datetime.utcnow()
    
    def dismiss(self):
        """Dismiss notification"""
        self.is_dismissed = True
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'is_read': self.is_read,
            'is_dismissed': self.is_dismissed,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'related_request_id': self.related_request_id,
            'action_url': self.action_url,
            'action_text': self.action_text
        }


# Utility functions for the approval system
class ApprovalSystemManager:
    """
    Manager class for approval system operations
    """
    
    @staticmethod
    def create_request(user_id, purpose, use_case, **kwargs):
        """Create a new approval request"""
        request = AdvancedFeatureRequest(
            user_id=user_id,
            purpose=purpose,
            use_case=use_case,
            **kwargs
        )
        db.session.add(request)
        db.session.commit()
        
        # Create notification for user
        ApprovalSystemManager.notify_user(
            user_id=user_id,
            title="Feature Request Submitted",
            message="Your advanced features request has been submitted and is pending review.",
            type="info",
            related_request_id=request.id
        )
        
        return request
    
    @staticmethod
    def get_pending_requests():
        """Get all pending approval requests"""
        return AdvancedFeatureRequest.query.filter_by(
            status=ApprovalStatus.PENDING
        ).order_by(AdvancedFeatureRequest.created_at.desc()).all()
    
    @staticmethod
    def approve_request(request_id, admin_id, notes=None):
        """Approve a request and grant access"""
        request = AdvancedFeatureRequest.query.get(request_id)
        if not request:
            return False
        
        # Approve the request
        request.approve(admin_id, notes)
        
        # Grant access to user
        access = UserAdvancedAccess.query.filter_by(user_id=request.user_id).first()
        if not access:
            access = UserAdvancedAccess(user_id=request.user_id)
            db.session.add(access)
        
        access.grant_access(
            features=['advanced_scan', 'bulk_operations', 'api_access'],
            access_level='advanced',
            expires_in_days=365
        )
        
        # Set approval details separately
        access.approved_request_id = request_id
        access.approved_by_admin_id = admin_id
        
        # Notify user
        ApprovalSystemManager.notify_user(
            user_id=request.user_id,
            title="Feature Request Approved!",
            message="Congratulations! Your advanced features request has been approved. You now have access to advanced features.",
            type="success",
            related_request_id=request_id,
            action_url="/advanced-features",
            action_text="Access Features"
        )
        
        db.session.commit()
        return True
    
    @staticmethod
    def reject_request(request_id, admin_id, reason, notes=None):
        """Reject a request"""
        request = AdvancedFeatureRequest.query.get(request_id)
        if not request:
            return False
        
        request.reject(admin_id, reason, notes)
        
        # Notify user
        ApprovalSystemManager.notify_user(
            user_id=request.user_id,
            title="Feature Request Update",
            message=f"Your advanced features request has been reviewed. Reason: {reason}",
            type="warning",
            related_request_id=request_id,
            action_url=f"/request-status/{request_id}",
            action_text="View Details"
        )
        
        db.session.commit()
        return True
    
    @staticmethod
    def notify_user(user_id, title, message, type="info", **kwargs):
        """Create a notification for user"""
        notification = UserNotification(
            user_id=user_id,
            title=title,
            message=message,
            type=type,
            **kwargs
        )
        db.session.add(notification)
        return notification
    
    @staticmethod
    def get_user_access_status(user_id):
        """Get user's advanced access status"""
        access = UserAdvancedAccess.query.filter_by(user_id=user_id).first()
        if not access:
            return {
                'has_access': False,
                'access_level': 'basic',
                'features': [],
                'can_use': False
            }
        
        return {
            'has_access': access.has_advanced_access,
            'access_level': access.access_level,
            'features': access.get_granted_features(),
            'can_use': access.can_use_advanced_features,
            'expires_at': access.expires_at,
            'usage_count': access.usage_count,
            'usage_limit': access.usage_limit
        }
    
    @staticmethod
    def can_user_access_feature(user_id, feature_name):
        """Check if user can access specific feature"""
        access = UserAdvancedAccess.query.filter_by(user_id=user_id).first()
        if not access or not access.can_use_advanced_features:
            return False
        
        granted_features = access.get_granted_features()
        return feature_name in granted_features or 'all_features' in granted_features
    
    @staticmethod
    def record_feature_usage(user_id, feature_name):
        """Record that user used an advanced feature"""
        access = UserAdvancedAccess.query.filter_by(user_id=user_id).first()
        if access:
            access.record_usage()
            db.session.commit()