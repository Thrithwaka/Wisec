"""
User-facing Advanced Features Routes
Handle user requests for advanced features access
"""

from flask import render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime
import os
from werkzeug.utils import secure_filename

from . import bp as main_bp
from app.models.approval_system import (
    AdvancedFeatureRequest, ApprovalMessage, UserAdvancedAccess, 
    UserNotification, ApprovalStatus, ApprovalSystemManager, RequestType, Priority
)
from app.models import db


@main_bp.route('/advanced-features')
@login_required
def advanced_features():
    """Advanced features page - check access and show appropriate content"""
    try:
        # Get user's access status
        access_status = ApprovalSystemManager.get_user_access_status(current_user.id)
        
        # Get user's pending/existing requests
        existing_request = AdvancedFeatureRequest.query.filter_by(
            user_id=current_user.id,
            status=ApprovalStatus.PENDING
        ).first()
        
        return render_template('main/advanced_features.html',
                             access_status=access_status,
                             existing_request=existing_request)
                             
    except Exception as e:
        flash(f'Error loading advanced features: {str(e)}', 'error')
        return redirect(url_for('main.dashboard'))


@main_bp.route('/request-advanced-access')
@login_required
def request_advanced_access():
    """Form to request advanced features access"""
    try:
        # Check if user already has access
        access_status = ApprovalSystemManager.get_user_access_status(current_user.id)
        if access_status['has_access']:
            flash('You already have access to advanced features', 'info')
            return redirect(url_for('main.advanced_features'))
        
        # Check if user has pending request
        existing_request = AdvancedFeatureRequest.query.filter_by(
            user_id=current_user.id,
            status=ApprovalStatus.PENDING
        ).first()
        
        if existing_request:
            flash('You already have a pending request for advanced features', 'info')
            return redirect(url_for('main.request_status', request_id=existing_request.id))
        
        return render_template('main/request_advanced_access.html')
        
    except Exception as e:
        flash(f'Error loading request form: {str(e)}', 'error')
        return redirect(url_for('main.advanced_features'))


@main_bp.route('/submit-advanced-access-request', methods=['POST'])
@login_required
def submit_advanced_access_request():
    """Submit advanced features access request"""
    try:
        # Get form data
        purpose = request.form.get('purpose', '').strip()
        use_case = request.form.get('use_case', '').strip()
        organization = request.form.get('organization', '').strip()
        organization_role = request.form.get('organization_role', '').strip()
        expected_usage = request.form.get('expected_usage', '').strip()
        priority = request.form.get('priority', 'medium')
        
        # Validate required fields
        if not purpose or not use_case:
            flash('Purpose and use case are required', 'error')
            return redirect(url_for('main.request_advanced_access'))
        
        if len(purpose) < 50:
            flash('Please provide a more detailed purpose (minimum 50 characters)', 'error')
            return redirect(url_for('main.request_advanced_access'))
        
        if len(use_case) < 50:
            flash('Please provide a more detailed use case (minimum 50 characters)', 'error')
            return redirect(url_for('main.request_advanced_access'))
        
        # Handle file uploads
        upload_folder = os.path.join(current_app.config.get('UPLOAD_FOLDER', 'uploads'), 'approval_documents')
        os.makedirs(upload_folder, exist_ok=True)
        
        organization_document = None
        identification_document = None
        
        # Handle organization document upload
        if 'organization_document' in request.files:
            file = request.files['organization_document']
            if file and file.filename:
                if allowed_file(file.filename):
                    filename = secure_filename(f"{current_user.id}_org_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
                    file_path = os.path.join(upload_folder, filename)
                    file.save(file_path)
                    organization_document = file_path
                else:
                    flash('Invalid file type for organization document. Please use PDF, DOC, DOCX, or image files.', 'error')
                    return redirect(url_for('main.request_advanced_access'))
        
        # Handle identification document upload
        if 'identification_document' in request.files:
            file = request.files['identification_document']
            if file and file.filename:
                if allowed_file(file.filename):
                    filename = secure_filename(f"{current_user.id}_id_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
                    file_path = os.path.join(upload_folder, filename)
                    file.save(file_path)
                    identification_document = file_path
                else:
                    flash('Invalid file type for identification document. Please use PDF, DOC, DOCX, or image files.', 'error')
                    return redirect(url_for('main.request_advanced_access'))
        
        # Create the request
        approval_request = ApprovalSystemManager.create_request(
            user_id=current_user.id,
            purpose=purpose,
            use_case=use_case,
            organization=organization,
            organization_role=organization_role,
            expected_usage=expected_usage,
            request_type=RequestType.ADVANCED_FEATURES,
            priority=Priority(priority),
            organization_document=organization_document,
            identification_document=identification_document,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        flash('Your advanced features request has been submitted successfully! You will be notified when it is reviewed.', 'success')
        return redirect(url_for('main.request_status', request_id=approval_request.id))
        
    except Exception as e:
        flash(f'Error submitting request: {str(e)}', 'error')
        return redirect(url_for('main.request_advanced_access'))


@main_bp.route('/request-status/<int:request_id>')
@login_required
def request_status(request_id):
    """View status of approval request"""
    try:
        # Get the request (ensure it belongs to current user)
        approval_request = AdvancedFeatureRequest.query.filter_by(
            id=request_id,
            user_id=current_user.id
        ).first_or_404()
        
        # Get messages for this request
        messages = ApprovalMessage.query.filter_by(
            request_id=request_id
        ).order_by(ApprovalMessage.created_at.asc()).all()
        
        # Mark user messages as read
        for message in messages:
            if not message.is_from_admin and not message.is_read:
                message.mark_as_read()
        
        db.session.commit()
        
        return render_template('main/request_status.html',
                             request=approval_request,
                             messages=messages)
                             
    except Exception as e:
        flash(f'Error loading request status: {str(e)}', 'error')
        return redirect(url_for('main.advanced_features'))


@main_bp.route('/send-message-to-admin/<int:request_id>', methods=['POST'])
@login_required
def send_message_to_admin(request_id):
    """Send message to admin about request"""
    try:
        # Verify request belongs to user
        approval_request = AdvancedFeatureRequest.query.filter_by(
            id=request_id,
            user_id=current_user.id
        ).first_or_404()
        
        message_text = request.form.get('message', '').strip()
        
        if not message_text:
            flash('Message cannot be empty', 'error')
            return redirect(url_for('main.request_status', request_id=request_id))
        
        # Create message
        message = ApprovalMessage(
            request_id=request_id,
            sender_id=current_user.id,
            message=message_text,
            is_from_admin=False
        )
        db.session.add(message)
        db.session.commit()
        
        flash('Message sent to admin', 'success')
        
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'error')
    
    return redirect(url_for('main.request_status', request_id=request_id))


@main_bp.route('/notifications')
@login_required
def user_notifications():
    """View user notifications"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        notifications = UserNotification.query.filter_by(
            user_id=current_user.id
        ).order_by(
            UserNotification.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        # Mark notifications as read when viewed
        for notification in notifications.items:
            if not notification.is_read:
                notification.mark_as_read()
        
        db.session.commit()
        
        return render_template('main/notifications.html', notifications=notifications)
        
    except Exception as e:
        flash(f'Error loading notifications: {str(e)}', 'error')
        return redirect(url_for('main.dashboard'))


@main_bp.route('/api/notification-count')
@login_required
def user_notification_count():
    """Get unread notification count for user"""
    try:
        count = UserNotification.query.filter_by(
            user_id=current_user.id,
            is_read=False,
            is_dismissed=False
        ).count()
        
        return jsonify({'count': count})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/dismiss-notification/<int:notification_id>', methods=['POST'])
@login_required
def dismiss_notification(notification_id):
    """Dismiss a notification"""
    try:
        notification = UserNotification.query.filter_by(
            id=notification_id,
            user_id=current_user.id
        ).first_or_404()
        
        notification.dismiss()
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def allowed_file(filename):
    """Check if uploaded file is allowed"""
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'txt'
    }
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Helper function to check if user can access advanced features
def user_has_advanced_access(user_id):
    """Check if user has access to advanced features"""
    return ApprovalSystemManager.can_user_access_feature(user_id, 'advanced_features')


# Decorator to require advanced access
def advanced_access_required(f):
    """Decorator to require advanced features access"""
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not user_has_advanced_access(current_user.id):
            flash('You need advanced features access to use this functionality. Please submit a request.', 'warning')
            return redirect(url_for('main.request_advanced_access'))
        
        # Record feature usage
        ApprovalSystemManager.record_feature_usage(current_user.id, 'advanced_features')
        
        return f(*args, **kwargs)
    return decorated_function