"""
Simple admin routes for admin panel functionality
"""

from flask import render_template, flash, redirect, url_for, request, jsonify
from flask_login import login_required
from app.admin import admin_bp
from app.utils.decorators import admin_required
from datetime import datetime, timedelta


@admin_bp.route('/test')
def admin_test():
    """Simple test route"""
    return "Admin test route works!"


@admin_bp.route('/users/count')
def get_users_count():
    """Get user count statistics for dashboard"""
    from app.models.user import User
    from app.models import db
    
    total_users = User.query.count()
    active_users = User.query.filter_by(is_verified=True).count()
    admin_users = User.query.filter_by(role='admin').count()
    pending_users = User.query.filter_by(is_verified=False).count()
    
    # Get pending approval requests from database
    try:
        from app.models.approval_system import AdvancedFeatureRequest, ApprovalStatus
        pending_approvals = AdvancedFeatureRequest.query.filter_by(
            status=ApprovalStatus.PENDING
        ).count()
    except Exception:
        # Fallback if table doesn't exist
        pending_approvals = 0
    
    # Return data in format expected by dashboard template
    return jsonify({
        'success': True,
        'total': total_users,
        'pending_approvals': pending_approvals,
        'active_users': active_users,
        'admin_users': admin_users,
        'pending_users': pending_users,
        'timestamp': datetime.utcnow().isoformat()
    })


@admin_bp.route('/system-health')
def system_health_check():
    """System health check - Get real-time system status"""
    import psutil
    
    # Get actual system metrics
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    health_data = {
        'cpu_usage': cpu_usage,
        'memory_usage': memory.percent,
        'disk_usage': (disk.used / disk.total) * 100,
        'status': 'healthy' if cpu_usage < 80 and memory.percent < 80 else 'warning',
        'uptime': 'Available'
    }
    
    return jsonify({
        'success': True,
        'health_data': health_data,
        'timestamp': datetime.utcnow().isoformat()
    })


@admin_bp.route('/dashboard-simple')
@login_required
@admin_required
def admin_dashboard_simple():
    """Admin dashboard with real data"""
    from app.models.user import User
    from app.models.scan_results import ScanResult
    from app.models import db
    
    # Get real dashboard metrics
    total_users = User.query.count()
    
    # Get pending approval requests
    try:
        from app.models.approval_system import AdvancedFeatureRequest, ApprovalStatus
        pending_approvals = AdvancedFeatureRequest.query.filter_by(
            status=ApprovalStatus.PENDING
        ).count()
    except Exception:
        pending_approvals = 0
    
    # Get today's scans
    today = datetime.utcnow().date()
    active_scans = ScanResult.query.filter(
        ScanResult.scan_timestamp >= today
    ).count()
    
    # Get security alerts (high risk scans in last 24h)
    yesterday = datetime.utcnow() - timedelta(hours=24)
    security_alerts = ScanResult.query.filter(
        ScanResult.scan_timestamp >= yesterday,
        ScanResult.risk_level.in_(['HIGH_RISK', 'CRITICAL'])
    ).count()
    
    # Get recent activities
    recent_activities = []
    
    return render_template('admin/admin_dashboard.html',
                          metrics={
                              'total_users': total_users,
                              'pending_approvals': pending_approvals,
                              'active_scans': active_scans,
                              'security_alerts': security_alerts
                          },
                          recent_activities=recent_activities,
                          pending_count=pending_approvals)


@admin_bp.route('/users-simple')
@login_required
@admin_required
def users_simple():
    """User management page"""
    from app.models.user import User
    from datetime import datetime, timedelta
    
    # Get paginated users
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=20, error_out=False)
    
    # Get user stats
    total_users = User.query.count()
    active_users = User.query.filter_by(is_verified=True).count()
    admin_users = User.query.filter_by(role='admin').count()
    
    # New users in last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_users = User.query.filter(User.created_at >= thirty_days_ago).count()
    
    # Advanced access users (could be based on role or permissions)
    advanced_access_users = User.query.filter_by(role='admin').count()
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'admin_users': admin_users,
        'new_users': new_users,
        'advanced_access_users': advanced_access_users
    }
    
    return render_template('admin/user_management.html', 
                         users=users, 
                         stats=stats)


@admin_bp.route('/approvals-simple')
@login_required
@admin_required
def approvals_simple():
    """Approval requests page"""
    from app.models import db
    
    try:
        from app.models.approval_system import AdvancedFeatureRequest, ApprovalStatus
        
        # Get all requests counts
        pending_count = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.PENDING).count()
        under_review_count = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.UNDER_REVIEW).count()
        approved_count = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.APPROVED).count()
        rejected_count = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.REJECTED).count()
        total_count = AdvancedFeatureRequest.query.count()
        
        # Get status filter from query params - default to 'all' to show everything
        status_filter = request.args.get('status', 'all')
        
        # Get requests for display based on filter - limit to avoid timeout  
        query = AdvancedFeatureRequest.query
        
        if status_filter == 'pending':
            query = query.filter_by(status=ApprovalStatus.PENDING)
        elif status_filter == 'under_review':
            query = query.filter_by(status=ApprovalStatus.UNDER_REVIEW)
        elif status_filter == 'approved':
            query = query.filter_by(status=ApprovalStatus.APPROVED)
        elif status_filter == 'rejected':
            query = query.filter_by(status=ApprovalStatus.REJECTED)
        # 'all' shows all statuses - no additional filter needed
        
        filtered_requests_objs = query.order_by(AdvancedFeatureRequest.created_at.desc()).limit(50).all()
        
        # Convert to dict format for template compatibility
        filtered_requests = []
        for req in filtered_requests_objs:
            filtered_requests.append({
                'id': req.id,
                'user_id': req.user_id,
                'user_name': req.user.email.split('@')[0] if req.user and req.user.email else 'Unknown',
                'user_email': req.user.email if req.user else 'Unknown',
                'request_type': req.request_type.value,
                'status': req.status.value,
                'submitted_at': req.created_at,
                'justification': req.purpose,
                'admin_notes': req.admin_notes,
                'priority': req.priority.value,
                'organization': req.organization,
                'days_pending': req.days_pending
            })
        
    except Exception as e:
        print(f"Database error in approvals: {e}")
        import traceback
        traceback.print_exc()
        filtered_requests = []
        pending_count = under_review_count = approved_count = rejected_count = total_count = 0
        status_filter = 'all'
    
    # Prepare stats for template
    stats = {
        'pending': pending_count,
        'under_review': under_review_count,
        'approved': approved_count,
        'rejected': rejected_count,
        'total': total_count
    }
    
    return render_template('admin/approval_requests.html', 
                         requests=filtered_requests,
                         stats=stats,
                         status_filter=status_filter)


@admin_bp.route('/analytics-simple')
@login_required  
@admin_required
def analytics_simple():
    """Analytics dashboard page"""
    from app.models import db
    
    # Get basic analytics stats
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    today = datetime.utcnow().date()
    
    try:
        # Get page views from database
        page_views_30d = db.session.execute(
            "SELECT COUNT(*) FROM page_view_events WHERE timestamp >= %s",
            (thirty_days_ago,)
        ).scalar() or 0
        
        page_views_today = db.session.execute(
            "SELECT COUNT(*) FROM page_view_events WHERE timestamp >= %s",
            (today,)
        ).scalar() or 0
        
        # Get user activities
        user_activities_30d = db.session.execute(
            "SELECT COUNT(*) FROM user_activities WHERE timestamp >= %s",
            (thirty_days_ago,)
        ).scalar() or 0
        
    except Exception:
        page_views_30d = 0
        page_views_today = 0
        user_activities_30d = 0
    
    analytics_data = {
        'page_views': page_views_30d,
        'user_activities': user_activities_30d
    }
    
    stats = {
        'total_page_views': page_views_30d,
        'active_users': user_activities_30d,
        'page_views_today': page_views_today
    }
    
    # Additional stats for analytics template
    stats.update({
        'active_users': user_activities_30d,
        'new_registrations': 0,  # Can be calculated from users table
        'total_scans': analytics_data['page_views'],
        'vulnerabilities_found': 0,  # Can be calculated from scan_results
        'critical_threats': 0,
        'resolved_threats': 0,
        'predictions_made': 0,
        'accuracy_rate': 95,
        'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'scans': [5, 8, 12, 6, 9, 15, 10],
        'threats': [2, 1, 3, 0, 1, 2, 1],
        'accuracy': [92, 94, 96, 95, 97, 96, 98]
    })
    
    return render_template('admin/analytics_dashboard.html',
                         analytics=analytics_data,
                         stats=stats)


@admin_bp.route('/live-monitoring-simple')
@login_required
@admin_required 
def live_monitoring_simple():
    """Live monitoring page"""
    import psutil
    
    # Get current system stats
    system_stats = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent if psutil.disk_usage('/') else 0
    }
    
    return render_template('admin/live_monitoring.html', system_stats=system_stats)


@admin_bp.route('/security-simple')
@login_required
@admin_required
def security_simple():
    """Security incidents page"""
    from app.models import db
    
    try:
        # Get security incidents from database
        incidents = db.session.execute(
            """SELECT id, incident_type, severity, timestamp, resolved, description 
               FROM security_incidents 
               ORDER BY timestamp DESC 
               LIMIT 50"""
        ).fetchall()
        
        total_count = db.session.execute(
            "SELECT COUNT(*) FROM security_incidents"
        ).scalar() or 0
        
        critical_count = db.session.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE severity = 'CRITICAL'"
        ).scalar() or 0
        
        unresolved_count = db.session.execute(
            "SELECT COUNT(*) FROM security_incidents WHERE resolved = false"
        ).scalar() or 0
        
    except Exception:
        incidents = []
        total_count = 0
        critical_count = 0
        unresolved_count = 0
    
    stats = {
        'total_count': total_count,
        'critical_count': critical_count,
        'high_count': 0,  # Add high severity count
        'medium_count': 0,  # Add medium severity count
        'low_count': 0,  # Add low severity count
        'unresolved_count': unresolved_count
    }
    
    return render_template('admin/security_incidents.html',
                         incidents=incidents,
                         stats=stats)


@admin_bp.route('/system-simple')
@login_required
@admin_required
def system_simple():
    """System monitoring page"""
    import psutil
    from app.models import db
    
    # Get current system metrics
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    network = psutil.net_io_counters()
    
    system_stats = {
        'cpu_usage': psutil.cpu_percent(),
        'cpu_cores': psutil.cpu_count(),
        'cpu_frequency': psutil.cpu_freq().current / 1000.0 if psutil.cpu_freq() else 0,
        'memory_usage': memory.percent,
        'memory_used': memory.used / (1024**3),  # GB
        'memory_total': memory.total / (1024**3),  # GB
        'disk_usage': (disk.used / disk.total) * 100,
        'disk_used': disk.used / (1024**3),  # GB
        'disk_free': disk.free / (1024**3),  # GB
        'network_activity': (network.bytes_sent + network.bytes_recv) / (1024**2),  # MB
        'network_down': network.bytes_recv / (1024**2),  # MB
        'network_up': network.bytes_sent / (1024**2),  # MB
        'temperature': 45,  # Mock temperature
        'temp_status': 'Normal',
        'temp_max': 85,
        'ai_models_loaded': 9,
        'ai_models_total': 10,
        'ai_memory_usage': 512,  # MB
        'ai_active_models': 9,
        'boot_time': psutil.boot_time()
    }
    
    try:
        # Get recent system metrics from database
        recent_metrics = db.session.execute(
            """SELECT timestamp, cpu_usage, memory_usage, disk_usage 
               FROM system_metrics 
               ORDER BY timestamp DESC 
               LIMIT 100"""
        ).fetchall()
    except Exception:
        recent_metrics = []
    
    return render_template('admin/system_monitoring.html',
                         metrics=recent_metrics,
                         system_stats=system_stats)


@admin_bp.route('/approve-request-simple/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def approve_request_simple(request_id):
    """Approve an advanced features request"""
    try:
        from app.models.approval_system import ApprovalSystemManager, AdvancedFeatureRequest, UserAdvancedAccess
        from flask_login import current_user
        from app.models import db
        
        notes = request.form.get('admin_notes', '').strip()
        
        # Get the request
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if not approval_request:
            flash('Request not found', 'error')
            return redirect(url_for('admin.approvals_simple'))
        
        # Approve the request using the ApprovalSystemManager
        success = ApprovalSystemManager.approve_request(
            request_id=request_id,
            admin_id=current_user.id,
            notes=notes
        )
        
        print(f"DEBUG: Approval request success: {success}")
        
        if success:
            # Ensure the user actually gets advanced access
            user_access = UserAdvancedAccess.query.filter_by(user_id=approval_request.user_id).first()
            print(f"DEBUG: Existing user_access: {user_access}")
            
            if not user_access:
                # Create new access record
                user_access = UserAdvancedAccess(user_id=approval_request.user_id)
                db.session.add(user_access)
                print(f"DEBUG: Created new UserAdvancedAccess for user {approval_request.user_id}")
            
            # Grant access with full features
            user_access.grant_access(
                features=['advanced_scan', 'deep_network_analysis', 'real_time_monitoring', 'ai_analytics', 'bulk_operations', 'api_access', 'advanced_reporting'],
                access_level='advanced',
                expires_in_days=365
            )
            user_access.approved_request_id = request_id
            user_access.approved_by_admin_id = current_user.id
            
            # IMPORTANT: Update the user's is_admin_approved field
            user = approval_request.user
            if user:
                user.is_admin_approved = True
                print(f"DEBUG: Updated user {user.id} ({user.email}) is_admin_approved to True")
            
            print(f"DEBUG: User access granted - has_access: {user_access.has_advanced_access}, features: {user_access.granted_features}")
            
            db.session.commit()
            
            # Send additional notification to user with explicit creation
            try:
                from app.models.approval_system import UserNotification
                
                notification = UserNotification(
                    user_id=approval_request.user_id,
                    title="🎉 Advanced Features Activated!",
                    message=f"Congratulations! Your advanced features request has been approved and your account has been upgraded. You now have access to all advanced security features including deep network analysis, real-time monitoring, AI-powered analytics, and more. Start using these powerful tools right away!",
                    type="success",
                    related_request_id=request_id,
                    action_url="/advanced-features",
                    action_text="Explore Advanced Features"
                )
                
                db.session.add(notification)
                db.session.commit()
                
                print(f"DEBUG: Created approval notification ID {notification.id} for user {approval_request.user_id}")
                
            except Exception as notification_error:
                print(f"ERROR creating approval notification: {notification_error}")
            
            flash(f'Request approved successfully! User {approval_request.user.email} now has advanced features access.', 'success')
        else:
            flash('Request not found or already processed', 'error')
            
    except Exception as e:
        print(f"Error approving request: {str(e)}")
        flash(f'Error approving request: {str(e)}', 'error')
        db.session.rollback()
    
    return redirect(url_for('admin.approvals_simple'))


@admin_bp.route('/reject-request-simple/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def reject_request_simple(request_id):
    """Reject an advanced features request"""
    try:
        from app.models.approval_system import ApprovalSystemManager, AdvancedFeatureRequest
        from flask_login import current_user
        
        reason = request.form.get('rejection_reason', '').strip()
        notes = request.form.get('admin_notes', '').strip()
        
        if not reason:
            flash('Rejection reason is required', 'error')
            return redirect(url_for('admin.approvals_simple'))
        
        # Get the request for user info
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if not approval_request:
            flash('Request not found', 'error')
            return redirect(url_for('admin.approvals_simple'))
        
        success = ApprovalSystemManager.reject_request(
            request_id=request_id,
            admin_id=current_user.id,
            reason=reason,
            notes=notes
        )
        
        if success:
            # Send detailed notification to user about rejection
            ApprovalSystemManager.notify_user(
                user_id=approval_request.user_id,
                title="Advanced Features Request Update",
                message=f"Your advanced features request has been reviewed and requires additional information. Reason: {reason}. You may submit a new request with the required documentation or corrections.",
                type="warning",
                related_request_id=request_id,
                action_url="/request-advanced-access",
                action_text="Submit New Request"
            )
            
            flash(f'Request rejected successfully. User {approval_request.user.email} has been notified.', 'success')
        else:
            flash('Request not found or already processed', 'error')
            
    except Exception as e:
        flash(f'Error rejecting request: {str(e)}', 'error')
    
    return redirect(url_for('admin.approvals_simple'))


@admin_bp.route('/review-request-simple/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def review_request_simple(request_id):
    """Mark request as under review"""
    try:
        from app.models.approval_system import AdvancedFeatureRequest, ApprovalSystemManager
        from flask_login import current_user
        from app.models import db
        
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if approval_request:
            approval_request.set_under_review(current_user.id)
            db.session.commit()
            
            # Notify user that request is being reviewed
            ApprovalSystemManager.notify_user(
                user_id=approval_request.user_id,
                title="Request Under Review",
                message=f"Your advanced features request (#{request_id}) is now under review by our admin team. We are carefully examining your verification documents and will provide a decision within 2-3 business days. Thank you for your patience.",
                type="info",
                related_request_id=request_id,
                action_url="/dashboard",
                action_text="View Dashboard"
            )
            
            flash(f'Request marked as under review. User {approval_request.user.email} has been notified.', 'success')
        else:
            flash('Request not found', 'error')
            
    except Exception as e:
        flash(f'Error updating request: {str(e)}', 'error')
    
    return redirect(url_for('admin.approvals_simple'))


@admin_bp.route('/delete-request-simple/<int:request_id>', methods=['POST'])
@login_required
@admin_required
def delete_request_simple(request_id):
    """Delete an advanced features request"""
    try:
        from app.models.approval_system import AdvancedFeatureRequest
        from flask_login import current_user
        from app.models import db
        
        # Check for confirmation
        confirmation = request.form.get('confirmation', '').strip()
        if confirmation != 'DELETE':
            flash('Invalid confirmation. Request not deleted.', 'error')
            return redirect(url_for('admin.approvals_simple'))
        
        # Find the request
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if not approval_request:
            flash('Request not found', 'error')
            return redirect(url_for('admin.approvals_simple'))
        
        # Store request info for logging before deletion
        user_email = approval_request.user.email if approval_request.user else 'Unknown'
        request_type = approval_request.request_type.value if approval_request.request_type else 'Unknown'
        
        # Delete the request
        db.session.delete(approval_request)
        db.session.commit()
        
        # Log the deletion
        print(f"Admin {current_user.email} deleted request ID {request_id} from user {user_email} (type: {request_type})")
        
        flash(f'Request #{request_id} has been permanently deleted', 'success')
        
    except Exception as e:
        print(f"Error deleting request {request_id}: {str(e)}")
        flash(f'Error deleting request: {str(e)}', 'error')
        # Rollback in case of error
        from app.models import db
        db.session.rollback()
    
    return redirect(url_for('admin.approvals_simple'))


@admin_bp.route('/api/request-details/<int:request_id>')
@login_required
@admin_required
def get_request_details(request_id):
    """Get detailed request information for modal display"""
    try:
        from app.models.approval_system import AdvancedFeatureRequest
        from app.models.user import User
        
        # Get the request with user information
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if not approval_request:
            return jsonify({'success': False, 'error': 'Request not found'}), 404
        
        # Get user information
        user = approval_request.user
        
        # Prepare response data
        request_data = {
            'id': approval_request.id,
            'user_id': approval_request.user_id,
            'user_email': user.email if user else 'Unknown',
            'user_name': user.email.split('@')[0] if user and user.email else 'Unknown',
            'user_registered_date': user.created_at.strftime('%Y-%m-%d %H:%M') if user and user.created_at else 'N/A',
            'request_type': approval_request.request_type.value if approval_request.request_type else 'advanced_features',
            'status': approval_request.status.value if approval_request.status else 'pending',
            'priority': approval_request.priority.value if approval_request.priority else 'medium',
            'purpose': approval_request.purpose,
            'use_case': approval_request.use_case,
            'organization': approval_request.organization,
            'organization_role': approval_request.organization_role,
            'expected_usage': approval_request.expected_usage,
            'submitted_date': approval_request.created_at.strftime('%Y-%m-%d %H:%M') if approval_request.created_at else 'N/A',
            'updated_date': approval_request.updated_at.strftime('%Y-%m-%d %H:%M') if approval_request.updated_at else 'N/A',
            'admin_notes': approval_request.admin_notes,
            'rejection_reason': approval_request.rejection_reason,
            'verification_document': approval_request.organization_document,  # This is where we stored the verification doc
            'verification_document_name': approval_request.organization_document.split('/')[-1] if approval_request.organization_document else None,
            'organization_document': approval_request.organization_document,  # Same document for compatibility
            'organization_document_name': approval_request.organization_document.split('/')[-1] if approval_request.organization_document else None,
            'additional_documents': [],
            'days_pending': approval_request.days_pending
        }
        
        # Parse additional documents if they exist
        if approval_request.additional_documents:
            try:
                import json
                additional_docs = json.loads(approval_request.additional_documents)
                if isinstance(additional_docs, list):
                    request_data['additional_documents'] = additional_docs
            except:
                pass
        
        return jsonify({
            'success': True,
            'request': request_data
        })
        
    except Exception as e:
        print(f"Error getting request details: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Error retrieving request details: {str(e)}'
        }), 500


@admin_bp.route('/download-document/<int:request_id>/<document_type>')
@admin_bp.route('/download-document/<int:request_id>/<document_type>/<int:doc_index>')
@login_required
@admin_required
def download_document(request_id, document_type, doc_index=0):
    """Download uploaded documents"""
    try:
        from app.models.approval_system import AdvancedFeatureRequest
        from flask import send_file
        import os
        
        approval_request = AdvancedFeatureRequest.query.get(request_id)
        if not approval_request:
            return jsonify({'error': 'Request not found'}), 404
        
        file_path = None
        
        if document_type == 'verification':
            file_path = approval_request.organization_document
        elif document_type == 'organization':
            file_path = approval_request.identification_document
        elif document_type == 'additional':
            if approval_request.additional_documents:
                try:
                    import json
                    additional_docs = json.loads(approval_request.additional_documents)
                    if isinstance(additional_docs, list) and doc_index < len(additional_docs):
                        file_path = additional_docs[doc_index].get('path') or additional_docs[doc_index].get('file_path')
                except:
                    pass
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'Document not found'}), 404
        
        return send_file(file_path, as_attachment=True)
        
    except Exception as e:
        print(f"Error downloading document: {str(e)}")
        return jsonify({'error': 'Error downloading document'}), 500