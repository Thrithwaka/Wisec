"""
Advanced Admin Routes - Industry Level Admin Panel
Complete admin functionality for WiFi Security System
"""

from flask import render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename

from app.admin import admin_bp
from app.utils.decorators import admin_required
from app.models.user import User, UserRole, AccountStatus
from app.models.approval_system import (
    AdvancedFeatureRequest, ApprovalMessage, UserAdvancedAccess, 
    UserNotification, ApprovalStatus, ApprovalSystemManager
)
from app.models.analytics import PageViewEvent, UserActivity
from app.models import db


@admin_bp.route('/api/notification-counts')
@login_required
@admin_required
def notification_counts():
    """API endpoint for real-time notification counts"""
    try:
        pending_requests = AdvancedFeatureRequest.query.filter_by(
            status=ApprovalStatus.PENDING
        ).count()
        
        unread_messages = ApprovalMessage.query.filter(
            ApprovalMessage.is_from_admin == False,
            ApprovalMessage.is_read == False
        ).count()
        
        total_notifications = pending_requests + unread_messages
        
        return jsonify({
            'total': total_notifications,
            'pending_requests': pending_requests,
            'unread_messages': unread_messages
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@admin_bp.route('/approval-requests')
@login_required
@admin_required
def approval_requests():
    """View all approval requests"""
    try:
        # Get filter parameters
        status_filter = request.args.get('status', 'all')
        priority_filter = request.args.get('priority', 'all')
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Build query
        query = AdvancedFeatureRequest.query
        
        if status_filter != 'all':
            query = query.filter(AdvancedFeatureRequest.status == ApprovalStatus(status_filter))
        
        if priority_filter != 'all':
            query = query.filter(AdvancedFeatureRequest.priority == priority_filter)
        
        # Order by priority and creation date
        query = query.order_by(
            AdvancedFeatureRequest.priority.desc(),
            AdvancedFeatureRequest.created_at.desc()
        )
        
        # Paginate
        requests = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Get statistics
        stats = {
            'total': AdvancedFeatureRequest.query.count(),
            'pending': AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.PENDING).count(),
            'approved': AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.APPROVED).count(),
            'rejected': AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.REJECTED).count(),
            'under_review': AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.UNDER_REVIEW).count()
        }
        
        return render_template('admin/approval_requests1.html',
                             requests=requests,
                             stats=stats,
                             status_filter=status_filter,
                             priority_filter=priority_filter)
                             
    except Exception as e:
        flash(f'Error loading approval requests: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/approval-request/<int:request_id>')
@admin_bp.route('/request-details/<int:request_id>')  # Alternative URL pattern
@login_required
@admin_required
def view_approval_request(request_id):
    """View detailed approval request"""
    try:
        approval_request = AdvancedFeatureRequest.query.get_or_404(request_id)
        
        # Get messages for this request
        messages = ApprovalMessage.query.filter_by(
            request_id=request_id
        ).order_by(ApprovalMessage.created_at.asc()).all()
        
        # Mark admin messages as read
        for message in messages:
            if not message.is_from_admin and not message.is_read:
                message.mark_as_read()
        
        db.session.commit()
        
        return render_template('admin/approval_request_detail.html',
                             request=approval_request,
                             messages=messages)
                             
    except Exception as e:
        flash(f'Error loading request details: {str(e)}', 'error')
        return redirect(url_for('admin.approval_requests'))


@admin_bp.route('/approval-request/<int:request_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_request(request_id):
    """Approve an approval request"""
    try:
        notes = request.form.get('notes', '')
        expires_in_days = request.form.get('expires_in_days', 365, type=int)
        
        success = ApprovalSystemManager.approve_request(
            request_id=request_id,
            admin_id=current_user.id,
            notes=notes
        )
        
        if success:
            flash('Request approved successfully!', 'success')
            
            # Add admin message
            message = ApprovalMessage(
                request_id=request_id,
                sender_id=current_user.id,
                message=f"Request approved. {notes}" if notes else "Request approved.",
                is_from_admin=True
            )
            db.session.add(message)
            db.session.commit()
        else:
            flash('Error approving request', 'error')
            
    except Exception as e:
        flash(f'Error approving request: {str(e)}', 'error')
    
    return redirect(url_for('admin.view_approval_request', request_id=request_id))


@admin_bp.route('/approval-request/<int:request_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_request(request_id):
    """Reject an approval request"""
    try:
        reason = request.form.get('reason', 'Request rejected by admin')
        notes = request.form.get('notes', '')
        
        success = ApprovalSystemManager.reject_request(
            request_id=request_id,
            admin_id=current_user.id,
            reason=reason,
            notes=notes
        )
        
        if success:
            flash('Request rejected', 'warning')
            
            # Add admin message
            message = ApprovalMessage(
                request_id=request_id,
                sender_id=current_user.id,
                message=f"Request rejected. Reason: {reason}. {notes}" if notes else f"Request rejected. Reason: {reason}",
                is_from_admin=True
            )
            db.session.add(message)
            db.session.commit()
        else:
            flash('Error rejecting request', 'error')
            
    except Exception as e:
        flash(f'Error rejecting request: {str(e)}', 'error')
    
    return redirect(url_for('admin.view_approval_request', request_id=request_id))


@admin_bp.route('/approval-request/<int:request_id>/message', methods=['POST'])
@login_required
@admin_required
def send_message_to_user(request_id):
    """Send message to user about their request"""
    try:
        message_text = request.form.get('message', '').strip()
        
        if not message_text:
            flash('Message cannot be empty', 'error')
            return redirect(url_for('admin.view_approval_request', request_id=request_id))
        
        # Create message
        message = ApprovalMessage(
            request_id=request_id,
            sender_id=current_user.id,
            message=message_text,
            is_from_admin=True
        )
        db.session.add(message)
        
        # Get the request to notify user
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if approval_request:
            # Create notification
            ApprovalSystemManager.notify_user(
                user_id=approval_request.user_id,
                title="New Message from Admin",
                message=f"Admin sent you a message about your feature request: {message_text[:100]}...",
                type="info",
                related_request_id=request_id,
                action_url=f"/request-status/{request_id}",
                action_text="View Message"
            )
        
        db.session.commit()
        flash('Message sent to user', 'success')
        
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'error')
    
    return redirect(url_for('admin.view_approval_request', request_id=request_id))


@admin_bp.route('/user-roles-management')
@login_required
@admin_required
def user_roles_management():
    """Manage user roles and permissions"""
    try:
        # Get filter parameters
        role_filter = request.args.get('role', 'all')
        status_filter = request.args.get('status', 'all')
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Build query
        query = User.query
        
        if role_filter != 'all':
            query = query.filter(User.role == UserRole(role_filter))
        
        if status_filter != 'all':
            query = query.filter(User.account_status == AccountStatus(status_filter))
        
        # Order by creation date
        query = query.order_by(User.created_at.desc())
        
        # Paginate
        users = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Get statistics
        stats = {
            'total_users': User.query.count(),
            'admin_users': User.query.filter(User.role == UserRole.ADMIN).count(),
            'regular_users': User.query.filter(User.role == UserRole.USER).count(),
            'active_users': User.query.filter(User.account_status == AccountStatus.ACTIVE).count(),
            'pending_users': User.query.filter(User.account_status == AccountStatus.PENDING).count(),
            'suspended_users': User.query.filter(User.account_status == AccountStatus.SUSPENDED).count()
        }
        
        return render_template('admin/user_roles_management.html',
                             users=users,
                             stats=stats,
                             role_filter=role_filter,
                             status_filter=status_filter,
                             UserRole=UserRole,
                             AccountStatus=AccountStatus)
                             
    except Exception as e:
        flash(f'Error loading user management: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/user/<int:user_id>/change-role', methods=['POST'])
@login_required
@admin_required
def change_user_role(user_id):
    """Change user's role"""
    try:
        user = User.query.get_or_404(user_id)
        new_role = request.form.get('role')
        notes = request.form.get('notes', '')
        
        if not new_role or new_role not in [role.value for role in UserRole]:
            flash('Invalid role selected', 'error')
            return redirect(url_for('admin.user_roles_management'))
        
        old_role = user.role.value
        user.role = UserRole(new_role)
        
        # Log the change
        activity = UserActivity(
            user_id=user_id,
            activity_type='role_change',
            activity_data={
                'old_role': old_role,
                'new_role': new_role,
                'changed_by_admin': current_user.id,
                'notes': notes
            }
        )
        db.session.add(activity)
        
        # Notify user
        ApprovalSystemManager.notify_user(
            user_id=user_id,
            title="Account Role Updated",
            message=f"Your account role has been changed from {old_role} to {new_role}.",
            type="info"
        )
        
        db.session.commit()
        flash(f'User role changed from {old_role} to {new_role}', 'success')
        
    except Exception as e:
        flash(f'Error changing user role: {str(e)}', 'error')
    
    return redirect(url_for('admin.user_roles_management'))


@admin_bp.route('/user/<int:user_id>/change-status', methods=['POST'])
@login_required
@admin_required
def change_user_status(user_id):
    """Change user's account status"""
    try:
        user = User.query.get_or_404(user_id)
        new_status = request.form.get('status')
        reason = request.form.get('reason', '')
        
        if not new_status or new_status not in [status.value for status in AccountStatus]:
            flash('Invalid status selected', 'error')
            return redirect(url_for('admin.user_roles_management'))
        
        old_status = user.account_status.value
        user.account_status = AccountStatus(new_status)
        
        # Log the change
        activity = UserActivity(
            user_id=user_id,
            activity_type='status_change',
            activity_data={
                'old_status': old_status,
                'new_status': new_status,
                'changed_by_admin': current_user.id,
                'reason': reason
            }
        )
        db.session.add(activity)
        
        # Notify user
        status_messages = {
            'active': 'Your account has been activated.',
            'suspended': 'Your account has been suspended.',
            'locked': 'Your account has been locked.',
            'inactive': 'Your account has been deactivated.'
        }
        
        ApprovalSystemManager.notify_user(
            user_id=user_id,
            title="Account Status Updated",
            message=status_messages.get(new_status, f"Your account status has been changed to {new_status}.") + 
                   (f" Reason: {reason}" if reason else ""),
            type="warning" if new_status in ['suspended', 'locked'] else "info"
        )
        
        db.session.commit()
        flash(f'User status changed from {old_status} to {new_status}', 'success')
        
    except Exception as e:
        flash(f'Error changing user status: {str(e)}', 'error')
    
    return redirect(url_for('admin.user_roles_management'))


@admin_bp.route('/user-activity-tracking')
@login_required
@admin_required
def user_activity_tracking():
    """Track all user activities"""
    try:
        # Get filter parameters
        user_id = request.args.get('user_id', type=int)
        activity_type = request.args.get('activity_type', 'all')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        # Build query
        query = UserActivity.query
        
        if user_id:
            query = query.filter(UserActivity.user_id == user_id)
        
        if activity_type != 'all':
            query = query.filter(UserActivity.activity_type == activity_type)
        
        if date_from:
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d')
                query = query.filter(UserActivity.created_at >= date_from)
            except ValueError:
                pass
        
        if date_to:
            try:
                date_to = datetime.strptime(date_to, '%Y-%m-%d')
                query = query.filter(UserActivity.created_at <= date_to)
            except ValueError:
                pass
        
        # Order by creation date (newest first)
        query = query.order_by(UserActivity.created_at.desc())
        
        # Paginate
        activities = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Get users for filter dropdown
        users = User.query.order_by(User.email).all()
        
        # Get activity types for filter dropdown
        activity_types = db.session.query(UserActivity.activity_type).distinct().all()
        activity_types = [at[0] for at in activity_types if at[0]]
        
        # Get statistics
        stats = {
            'total_activities': UserActivity.query.count(),
            'activities_today': UserActivity.query.filter(
                UserActivity.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0)
            ).count(),
            'activities_this_week': UserActivity.query.filter(
                UserActivity.created_at >= datetime.utcnow() - timedelta(days=7)
            ).count(),
            'unique_users_active': db.session.query(UserActivity.user_id).distinct().count()
        }
        
        return render_template('admin/user_activity_tracking.html',
                             activities=activities,
                             users=users,
                             activity_types=activity_types,
                             stats=stats,
                             filters={
                                 'user_id': user_id,
                                 'activity_type': activity_type,
                                 'date_from': date_from,
                                 'date_to': date_to
                             })
                             
    except Exception as e:
        flash(f'Error loading activity tracking: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/user-messages')
@login_required
@admin_required
def user_messages():
    """View and manage user messages"""
    try:
        # Get filter parameters
        request_id = request.args.get('request_id', type=int)
        unread_only = request.args.get('unread_only', 'false') == 'true'
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        # Build query
        query = ApprovalMessage.query
        
        if request_id:
            query = query.filter(ApprovalMessage.request_id == request_id)
        
        if unread_only:
            query = query.filter(ApprovalMessage.is_read == False)
        
        # Order by creation date (newest first)
        query = query.order_by(ApprovalMessage.created_at.desc())
        
        # Paginate
        messages = query.paginate(page=page, per_page=per_page, error_out=False)
        
        # Get requests for filter dropdown
        requests = db.session.query(
            AdvancedFeatureRequest.id, 
            AdvancedFeatureRequest.purpose
        ).all()
        
        return render_template('admin/user_messages.html',
                             messages=messages,
                             requests=requests,
                             filters={
                                 'request_id': request_id,
                                 'unread_only': unread_only
                             })
                             
    except Exception as e:
        flash(f'Error loading messages: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/send-announcement')
@login_required
@admin_required
def send_announcement():
    """Send announcements to users"""
    try:
        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            message = request.form.get('message', '').strip()
            recipient_type = request.form.get('recipient_type', 'all')
            
            if not title or not message:
                flash('Title and message are required', 'error')
                return render_template('admin/send_announcement.html')
            
            # Get recipients based on type
            if recipient_type == 'all':
                users = User.query.all()
            elif recipient_type == 'admins':
                users = User.query.filter(User.role == UserRole.ADMIN).all()
            elif recipient_type == 'users':
                users = User.query.filter(User.role == UserRole.USER).all()
            elif recipient_type == 'advanced_users':
                # Users with advanced access
                advanced_access = UserAdvancedAccess.query.filter(
                    UserAdvancedAccess.has_advanced_access == True
                ).all()
                user_ids = [access.user_id for access in advanced_access]
                users = User.query.filter(User.id.in_(user_ids)).all()
            else:
                users = User.query.all()
            
            # Send notifications to all recipients
            for user in users:
                ApprovalSystemManager.notify_user(
                    user_id=user.id,
                    title=f"Announcement: {title}",
                    message=message,
                    type="info"
                )
            
            db.session.commit()
            flash(f'Announcement sent to {len(users)} users', 'success')
            return redirect(url_for('admin.send_announcement'))
        
        return render_template('admin/send_announcement.html')
        
    except Exception as e:
        flash(f'Error sending announcement: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/approval-history')
@login_required
@admin_required
def approval_history():
    """View approval request history"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        requests = AdvancedFeatureRequest.query.filter(
            AdvancedFeatureRequest.status.in_([
                ApprovalStatus.APPROVED, 
                ApprovalStatus.REJECTED
            ])
        ).order_by(
            AdvancedFeatureRequest.reviewed_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template('admin/approval_history.html', requests=requests)
        
    except Exception as e:
        flash(f'Error loading approval history: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    """View system audit logs"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        # Get all user activities (comprehensive audit log)
        activities = UserActivity.query.order_by(
            UserActivity.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        return render_template('admin/audit_logs.html', activities=activities)
        
    except Exception as e:
        flash(f'Error loading audit logs: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))


@admin_bp.route('/ai-models-management')
@login_required
@admin_required
def ai_models_management():
    """Manage AI models and performance"""
    try:
        # This would integrate with your AI model management system
        # For now, return a placeholder template
        return render_template('admin/ai_models_management.html')
        
    except Exception as e:
        flash(f'Error loading AI models management: {str(e)}', 'error')
        return redirect(url_for('admin.admin_dashboard_simple'))