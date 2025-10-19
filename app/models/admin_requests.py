"""
Admin Approval Requests Model
Purpose: Manage admin approval workflow for enhanced scanning capabilities
"""

from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.postgresql import UUID
import uuid
import os
import json

Base = declarative_base()

class RequestStatus(Enum):
    """Request status enumeration"""
    PENDING = "pending"
    UNDER_REVIEW = "under_review" 
    APPROVED = "approved"
    REJECTED = "rejected"
    ADDITIONAL_INFO_REQUIRED = "additional_info_required"

class RequestType(Enum):
    """Request type enumeration"""
    DEEP_SCAN_ACCESS = "deep_scan_access"
    PASSIVE_MONITORING = "passive_monitoring"
    ADVANCED_FEATURES = "advanced_features"
    ADMIN_PRIVILEGES = "admin_privileges"

class AdminRequest(Base):
    """
    Admin approval request model
    Purpose: Store and manage admin approval requests
    """
    __tablename__ = 'admin_requests'
    
    # Primary key and identification
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    
    # Request details
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    request_type = Column(String(50), nullable=False)  # RequestType enum values
    status = Column(String(30), default=RequestStatus.PENDING.value, nullable=False)
    
    # Timestamps
    submitted_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    approval_date = Column(DateTime(timezone=True), nullable=True)
    
    # Request content
    justification = Column(Text, nullable=False)
    evidence_files = Column(JSON, default=list)  # Store file paths/metadata
    additional_info = Column(Text, nullable=True)
    
    # Admin response
    admin_response = Column(Text, nullable=True)
    reviewer_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    
    # Workflow tracking
    workflow_stage = Column(String(50), default="initial_submission")
    priority_level = Column(String(20), default="normal")  # low, normal, high, urgent
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="admin_requests")
    reviewer = relationship("User", foreign_keys=[reviewer_id])
    
    def __init__(self, user_id, request_type, justification, evidence_files=None, priority_level="normal"):
        """Initialize admin request"""
        self.user_id = user_id
        self.request_type = request_type
        self.justification = justification
        self.evidence_files = evidence_files or []
        self.priority_level = priority_level
        self.status = RequestStatus.PENDING.value
        self.workflow_stage = "initial_submission"
        
    def __repr__(self):
        return f'<AdminRequest {self.request_uuid}: {self.request_type} - {self.status}>'

class RequestWorkflow:
    """
    Approval workflow management
    Purpose: Manage the admin approval workflow process
    """
    
    def __init__(self, db_session):
        """Initialize workflow manager"""
        self.db_session = db_session
        self.workflow_stages = [
            "initial_submission",
            "document_review", 
            "technical_assessment",
            "security_clearance",
            "final_approval",
            "completed"
        ]
    
    def advance_workflow_stage(self, request_id, reviewer_id=None):
        """
        Advance request to next workflow stage
        
        Args:
            request_id: ID of the request
            reviewer_id: ID of the reviewing admin
            
        Returns:
            bool: Success status
        """
        try:
            request = self.db_session.query(AdminRequest).filter_by(id=request_id).first()
            if not request:
                return False
                
            current_stage_index = self.workflow_stages.index(request.workflow_stage)
            if current_stage_index < len(self.workflow_stages) - 1:
                request.workflow_stage = self.workflow_stages[current_stage_index + 1]
                request.updated_at = datetime.now(timezone.utc)
                
                if reviewer_id:
                    request.reviewer_id = reviewer_id
                    
                self.db_session.commit()
                return True
            return False
            
        except Exception as e:
            self.db_session.rollback()
            print(f"Error advancing workflow stage: {str(e)}")
            return False
    
    def get_workflow_progress(self, request_id):
        """
        Get workflow progress percentage
        
        Args:
            request_id: ID of the request
            
        Returns:
            dict: Progress information
        """
        try:
            request = self.db_session.query(AdminRequest).filter_by(id=request_id).first()
            if not request:
                return {"progress": 0, "stage": "unknown"}
                
            current_index = self.workflow_stages.index(request.workflow_stage)
            progress = ((current_index + 1) / len(self.workflow_stages)) * 100
            
            return {
                "progress": round(progress, 2),
                "stage": request.workflow_stage,
                "stage_number": current_index + 1,
                "total_stages": len(self.workflow_stages)
            }
            
        except Exception as e:
            print(f"Error getting workflow progress: {str(e)}")
            return {"progress": 0, "stage": "error"}

class ApprovalHistory(Base):
    """
    Approval history tracking
    Purpose: Track all changes and decisions in approval process
    """
    __tablename__ = 'approval_history'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Request reference
    request_id = Column(Integer, ForeignKey('admin_requests.id'), nullable=False)
    
    # History details
    action_type = Column(String(50), nullable=False)  # status_change, comment_added, document_uploaded
    action_details = Column(Text, nullable=False)
    performed_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    performed_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False)
    
    # Additional metadata
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Relationships
    request = relationship("AdminRequest")
    performer = relationship("User")
    
    def __repr__(self):
        return f'<ApprovalHistory {self.id}: {self.action_type} at {self.performed_at}>'

class RequestValidator:
    """
    Request validation utilities
    Purpose: Validate admin approval requests
    """
    
    @staticmethod
    def validate_request_type(request_type):
        """
        Validate request type
        
        Args:
            request_type: Request type string
            
        Returns:
            bool: Validation result
        """
        valid_types = [rt.value for rt in RequestType]
        return request_type in valid_types
    
    @staticmethod
    def validate_justification(justification):
        """
        Validate justification text
        
        Args:
            justification: Justification text
            
        Returns:
            dict: Validation result with errors
        """
        errors = []
        
        if not justification or len(justification.strip()) < 50:
            errors.append("Justification must be at least 50 characters long")
            
        if len(justification) > 2000:
            errors.append("Justification cannot exceed 2000 characters")
            
        # Check for required keywords based on request type
        required_keywords = ["purpose", "network", "security", "research"]
        if not any(keyword.lower() in justification.lower() for keyword in required_keywords):
            errors.append("Justification should include purpose, network context, or security details")
            
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    @staticmethod
    def validate_evidence_files(evidence_files):
        """
        Validate evidence files
        
        Args:
            evidence_files: List of file metadata
            
        Returns:
            dict: Validation result
        """
        errors = []
        
        if not evidence_files:
            errors.append("At least one evidence file is required")
            return {"valid": False, "errors": errors}
            
        allowed_extensions = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.txt']
        max_file_size = 10 * 1024 * 1024  # 10MB
        
        for file_info in evidence_files:
            if not isinstance(file_info, dict):
                continue
                
            filename = file_info.get('filename', '')
            file_size = file_info.get('size', 0)
            
            # Check file extension
            if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
                errors.append(f"File {filename} has unsupported extension")
                
            # Check file size
            if file_size > max_file_size:
                errors.append(f"File {filename} exceeds maximum size limit")
                
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

# Main AdminRequest class methods
def submit_request(db_session, user_id, request_type, justification, evidence_files=None, priority_level="normal"):
    """
    Submit approval request
    
    Args:
        db_session: Database session
        user_id: User ID submitting request
        request_type: Type of request
        justification: Request justification
        evidence_files: Supporting evidence files
        priority_level: Request priority
        
    Returns:
        dict: Submission result
    """
    try:
        # Validate inputs
        if not RequestValidator.validate_request_type(request_type):
            return {"success": False, "error": "Invalid request type"}
            
        justification_validation = RequestValidator.validate_justification(justification)
        if not justification_validation["valid"]:
            return {"success": False, "errors": justification_validation["errors"]}
            
        if evidence_files:
            file_validation = RequestValidator.validate_evidence_files(evidence_files)
            if not file_validation["valid"]:
                return {"success": False, "errors": file_validation["errors"]}
        
        # Create new request
        new_request = AdminRequest(
            user_id=user_id,
            request_type=request_type,
            justification=justification,
            evidence_files=evidence_files or [],
            priority_level=priority_level
        )
        
        db_session.add(new_request)
        db_session.commit()
        
        # Log submission in history
        history_entry = ApprovalHistory(
            request_id=new_request.id,
            action_type="request_submitted",
            action_details=f"New {request_type} request submitted",
            performed_by=user_id
        )
        db_session.add(history_entry)
        db_session.commit()
        
        return {
            "success": True,
            "request_id": new_request.id,
            "request_uuid": str(new_request.request_uuid)
        }
        
    except Exception as e:
        db_session.rollback()
        return {"success": False, "error": f"Database error: {str(e)}"}

def process_request(db_session, request_id, admin_id, action, admin_response=None, rejection_reason=None):
    """
    Process approval request
    
    Args:
        db_session: Database session
        request_id: Request ID to process
        admin_id: Admin processing the request
        action: Action to take (approve/reject/request_info)
        admin_response: Admin response text
        rejection_reason: Reason for rejection
        
    Returns:
        dict: Processing result
    """
    try:
        request = db_session.query(AdminRequest).filter_by(id=request_id).first()
        if not request:
            return {"success": False, "error": "Request not found"}
            
        # Update request based on action
        if action == "approve":
            request.status = RequestStatus.APPROVED.value
            request.approval_date = datetime.now(timezone.utc)
            history_action = "request_approved"
            
        elif action == "reject":
            request.status = RequestStatus.REJECTED.value
            request.rejection_reason = rejection_reason
            history_action = "request_rejected"
            
        elif action == "request_info":
            request.status = RequestStatus.ADDITIONAL_INFO_REQUIRED.value
            history_action = "additional_info_requested"
            
        else:
            return {"success": False, "error": "Invalid action"}
            
        request.admin_response = admin_response
        request.reviewer_id = admin_id
        request.updated_at = datetime.now(timezone.utc)
        
        # Log action in history
        history_entry = ApprovalHistory(
            request_id=request_id,
            action_type=history_action,
            action_details=admin_response or f"Request {action}",
            performed_by=admin_id,
            old_value=request.status,
            new_value=action
        )
        db_session.add(history_entry)
        db_session.commit()
        
        return {"success": True, "new_status": request.status}
        
    except Exception as e:
        db_session.rollback()
        return {"success": False, "error": f"Processing error: {str(e)}"}

def update_status(db_session, request_id, new_status, admin_id=None):
    """
    Update request status
    
    Args:
        db_session: Database session
        request_id: Request ID
        new_status: New status value
        admin_id: Admin updating status
        
    Returns:
        bool: Update success
    """
    try:
        request = db_session.query(AdminRequest).filter_by(id=request_id).first()
        if not request:
            return False
            
        old_status = request.status
        request.status = new_status
        request.updated_at = datetime.now(timezone.utc)
        
        if admin_id:
            request.reviewer_id = admin_id
            
        # Log status change
        history_entry = ApprovalHistory(
            request_id=request_id,
            action_type="status_updated",
            action_details=f"Status changed from {old_status} to {new_status}",
            performed_by=admin_id or request.user_id,
            old_value=old_status,
            new_value=new_status
        )
        db_session.add(history_entry)
        db_session.commit()
        
        return True
        
    except Exception as e:
        db_session.rollback()
        print(f"Error updating status: {str(e)}")
        return False

def add_evidence(db_session, request_id, file_info, user_id):
    """
    Add evidence file to request
    
    Args:
        db_session: Database session
        request_id: Request ID
        file_info: File information dictionary
        user_id: User adding evidence
        
    Returns:
        bool: Addition success
    """
    try:
        request = db_session.query(AdminRequest).filter_by(id=request_id).first()
        if not request:
            return False
            
        # Validate file
        file_validation = RequestValidator.validate_evidence_files([file_info])
        if not file_validation["valid"]:
            return False
            
        # Add file to evidence list
        if not request.evidence_files:
            request.evidence_files = []
            
        request.evidence_files.append(file_info)
        request.updated_at = datetime.now(timezone.utc)
        
        # Log evidence addition
        history_entry = ApprovalHistory(
            request_id=request_id,
            action_type="evidence_added",
            action_details=f"Evidence file added: {file_info.get('filename', 'unknown')}",
            performed_by=user_id
        )
        db_session.add(history_entry)
        db_session.commit()
        
        return True
        
    except Exception as e:
        db_session.rollback()
        print(f"Error adding evidence: {str(e)}")
        return False

def send_notifications(db_session, request_id, notification_type, recipient_id=None):
    """
    Send notifications for request updates
    
    Args:
        db_session: Database session
        request_id: Request ID
        notification_type: Type of notification
        recipient_id: Notification recipient
        
    Returns:
        bool: Notification success
    """
    try:
        request = db_session.query(AdminRequest).filter_by(id=request_id).first()
        if not request:
            return False
        
        # Notification logic would integrate with email system
        # For now, log the notification
        history_entry = ApprovalHistory(
            request_id=request_id,
            action_type="notification_sent",
            action_details=f"Notification sent: {notification_type}",
            performed_by=recipient_id or request.reviewer_id or 1  # system user
        )
        db_session.add(history_entry)
        db_session.commit()
        
        return True
        
    except Exception as e:
        db_session.rollback()
        print(f"Error sending notification: {str(e)}")
        return False

def track_workflow(db_session, request_id):
    """
    Track workflow progress
    
    Args:
        db_session: Database session
        request_id: Request ID
        
    Returns:
        dict: Workflow tracking information
    """
    try:
        request = db_session.query(AdminRequest).filter_by(id=request_id).first()
        if not request:
            return {"error": "Request not found"}
            
        workflow_manager = RequestWorkflow(db_session)
        progress = workflow_manager.get_workflow_progress(request_id)
        
        # Get history entries
        history = db_session.query(ApprovalHistory).filter_by(
            request_id=request_id
        ).order_by(ApprovalHistory.performed_at.desc()).limit(10).all()
        
        return {
            "request_status": request.status,
            "workflow_progress": progress,
            "recent_activity": [
                {
                    "action": h.action_type,
                    "details": h.action_details,
                    "timestamp": h.performed_at.isoformat(),
                    "performer_id": h.performed_by
                } for h in history
            ]
        }
        
    except Exception as e:
        return {"error": f"Tracking error: {str(e)}"}

def generate_approval_reports(db_session, date_range=None, status_filter=None):
    """
    Generate approval reports
    
    Args:
        db_session: Database session
        date_range: Date range tuple (start, end)
        status_filter: Status to filter by
        
    Returns:
        dict: Report data
    """
    try:
        query = db_session.query(AdminRequest)
        
        if date_range:
            start_date, end_date = date_range
            query = query.filter(
                AdminRequest.submitted_at >= start_date,
                AdminRequest.submitted_at <= end_date
            )
            
        if status_filter:
            query = query.filter(AdminRequest.status == status_filter)
            
        requests = query.all()
        
        # Calculate statistics
        total_requests = len(requests)
        status_counts = {}
        type_counts = {}
        
        for req in requests:
            status_counts[req.status] = status_counts.get(req.status, 0) + 1
            type_counts[req.request_type] = type_counts.get(req.request_type, 0) + 1
            
        return {
            "total_requests": total_requests,
            "status_distribution": status_counts,
            "type_distribution": type_counts,
            "requests": [
                {
                    "id": req.id,
                    "uuid": str(req.request_uuid),
                    "type": req.request_type,
                    "status": req.status,
                    "submitted_at": req.submitted_at.isoformat(),
                    "user_id": req.user_id
                } for req in requests
            ]
        }
        
    except Exception as e:
        return {"error": f"Report generation error: {str(e)}"}

def validate_request(db_session, request_id):
    """
    Validate request completeness
    
    Args:
        db_session: Database session
        request_id: Request ID to validate
        
    Returns:
        dict: Validation result
    """
    try:
        request = db_session.query(AdminRequest).filter_by(id=request_id).first()
        if not request:
            return {"valid": False, "errors": ["Request not found"]}
            
        errors = []
        
        # Check required fields
        if not request.justification or len(request.justification.strip()) < 50:
            errors.append("Insufficient justification provided")
            
        if not request.evidence_files:
            errors.append("No evidence files provided")
            
        # Check file validity
        if request.evidence_files:
            file_validation = RequestValidator.validate_evidence_files(request.evidence_files)
            if not file_validation["valid"]:
                errors.extend(file_validation["errors"])
                
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "request_id": request_id
        }
        
    except Exception as e:
        return {"valid": False, "errors": [f"Validation error: {str(e)}"]}