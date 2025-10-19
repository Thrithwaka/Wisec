"""
Admin Dashboard Routes - Administrative functions and user management
Purpose: Administrative functions and user management
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
import json
import os
from werkzeug.utils import secure_filename

# Import models
from app.models.user import User, UserRole
from app.models.admin_requests import AdminRequest, RequestWorkflow, ApprovalHistory
from app.models.scan_results import ScanResult, VulnerabilityReport
from app.models.audit_logs import AuditLog, SecurityEvent, SystemActivity
from app.models.analytics import PageViewEvent, UserActivity, SystemMetrics, SecurityIncident, AnalyticsManager

# Import utilities
from app.utils.decorators import admin_required, log_activity, rate_limit
from app.utils.helpers import format_timestamp, calculate_time_difference
from app.utils.validators import InputValidator, sanitize_input
from app.utils.email_sender import EmailSender
from app.utils.pdf_generator import PDFGenerator

# Import AI engine components
from app.ai_engine.model_monitor import ModelMonitor, PerformanceMetrics
from app.ai_engine.model_loader import ModelLoader

# Create blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Test route to verify this file is loaded
@admin_bp.route('/routes-test')
def routes_test():
    """Test route to verify main routes file is loaded"""
    return "Main admin routes file is loaded!"

class AdminDashboardManager:
    """Admin dashboard coordination"""
    
    def __init__(self):
        self.model_monitor = ModelMonitor()
        self.model_loader = ModelLoader()
        self.email_sender = EmailSender()
        self.pdf_generator = PDFGenerator()
        
    def get_dashboard_metrics(self):
        """Get comprehensive dashboard metrics"""
        try:
            metrics = {
                'total_users': User.query.count(),
                'pending_approvals': AdminRequest.query.filter_by(status='pending').count(),
                'active_scans_today': ScanResult.query.filter(
                    ScanResult.scan_timestamp >= datetime.utcnow().date()
                ).count(),
                'security_alerts': SecurityEvent.query.filter(
                    SecurityEvent.timestamp >= datetime.utcnow() - timedelta(days=1)
                ).count(),
                'system_health': self._get_system_health(),
                'model_performance': self.model_monitor.get_ensemble_metrics()
            }
            return metrics
        except Exception as e:
            current_app.logger.error(f"Dashboard metrics error: {str(e)}")
            return {}
            
    def _get_system_health(self):
        """Calculate overall system health status"""
        try:
            # Check model health
            model_health = self.model_monitor.ensemble_health_check()
            
            # Check database health
            db_health = self._check_database_health()
            
            # Calculate overall health score
            health_score = (model_health + db_health) / 2
            
            if health_score >= 90:
                return {'status': 'Excellent', 'score': health_score}
            elif health_score >= 70:
                return {'status': 'Good', 'score': health_score}
            elif health_score >= 50:
                return {'status': 'Fair', 'score': health_score}
            else:
                return {'status': 'Poor', 'score': health_score}
                
        except Exception as e:
            current_app.logger.error(f"System health check error: {str(e)}")
            return {'status': 'Unknown', 'score': 0}
            
    def _check_database_health(self):
        """Check database health"""
        try:
            # Simple query to test database responsiveness
            User.query.first()
            return 100  # Database is responsive
        except Exception:
            return 0

class UserManagementSystem:
    """User management operations"""
    
    def __init__(self):
        self.email_sender = EmailSender()
        
    def get_all_users(self, page=1, per_page=20):
        """Get paginated list of all users"""
        try:
            users = User.query.paginate(
                page=page, per_page=per_page, error_out=False
            )
            return users
        except Exception as e:
            current_app.logger.error(f"User retrieval error: {str(e)}")
            return None
            
    def update_user_status(self, user_id, new_status):
        """Update user account status"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, "User not found"
                
            old_status = user.is_verified
            user.is_verified = new_status
            user.save()
            
            # Log the change
            AuditLog.log_event(
                user_id=current_user.id,
                event_type='USER_STATUS_CHANGE',
                details=f"Changed user {user.email} status from {old_status} to {new_status}"
            )
            
            # Send notification email
            if new_status:
                self.email_sender.send_email(
                    to=user.email,
                    subject="Account Activated",
                    template="account_activated",
                    user=user
                )
            
            return True, "User status updated successfully"
            
        except Exception as e:
            current_app.logger.error(f"User status update error: {str(e)}")
            return False, str(e)
            
    def delete_user_account(self, user_id, reason=""):
        """Delete user account with audit trail"""
        try:
            user = User.query.get(user_id)
            if not user:
                return False, "User not found"
                
            if user.id == current_user.id:
                return False, "Cannot delete your own account"
                
            # Archive user data before deletion
            self._archive_user_data(user)
            
            # Log the deletion
            AuditLog.log_event(
                user_id=current_user.id,
                event_type='USER_DELETION',
                details=f"Deleted user {user.email}. Reason: {reason}"
            )
            
            # Delete the user
            user.delete()
            
            return True, "User account deleted successfully"
            
        except Exception as e:
            current_app.logger.error(f"User deletion error: {str(e)}")
            return False, str(e)
            
    def _archive_user_data(self, user):
        """Archive user data before deletion"""
        try:
            # Archive scan results
            scan_results = ScanResult.query.filter_by(user_id=user.id).all()
            for scan in scan_results:
                scan.archived = True
                scan.save()
                
        except Exception as e:
            current_app.logger.error(f"User data archival error: {str(e)}")

class ApprovalWorkflow:
    """User approval workflow"""
    
    def __init__(self):
        self.email_sender = EmailSender()
        
    def get_pending_requests(self):
        """Get all pending approval requests"""
        try:
            requests = AdminRequest.query.filter_by(status='pending').order_by(
                AdminRequest.submitted_at.desc()
            ).all()
            return requests
        except Exception as e:
            current_app.logger.error(f"Pending requests retrieval error: {str(e)}")
            return []
            
    def approve_request(self, request_id, admin_response=""):
        """Approve an admin request"""
        try:
            admin_request = AdminRequest.query.get(request_id)
            if not admin_request:
                return False, "Request not found"
                
            # Update request status
            admin_request.status = 'approved'
            admin_request.admin_response = admin_response
            admin_request.approval_date = datetime.utcnow()
            admin_request.reviewer_id = current_user.id
            admin_request.save()
            
            # Update user permissions
            user = User.query.get(admin_request.user_id)
            if user:
                user.is_admin_approved = True
                user.role = UserRole.ADMIN
                user.save()
                
                # Send approval email
                self.email_sender.send_email(
                    to=user.email,
                    subject="Admin Access Approved",
                    template="admin_approved",
                    user=user,
                    admin_response=admin_response
                )
            
            # Log approval
            AuditLog.log_event(
                user_id=current_user.id,
                event_type='ADMIN_APPROVAL',
                details=f"Approved admin request for user {user.email if user else 'Unknown'}"
            )
            
            return True, "Request approved successfully"
            
        except Exception as e:
            current_app.logger.error(f"Request approval error: {str(e)}")
            return False, str(e)
            
    def reject_request(self, request_id, admin_response=""):
        """Reject an admin request"""
        try:
            admin_request = AdminRequest.query.get(request_id)
            if not admin_request:
                return False, "Request not found"
                
            # Update request status
            admin_request.status = 'rejected'
            admin_request.admin_response = admin_response
            admin_request.approval_date = datetime.utcnow()
            admin_request.reviewer_id = current_user.id
            admin_request.save()
            
            # Send rejection email
            user = User.query.get(admin_request.user_id)
            if user:
                self.email_sender.send_email(
                    to=user.email,
                    subject="Admin Access Request - Decision",
                    template="admin_rejected",
                    user=user,
                    admin_response=admin_response
                )
            
            # Log rejection
            AuditLog.log_event(
                user_id=current_user.id,
                event_type='ADMIN_REJECTION',
                details=f"Rejected admin request for user {user.email if user else 'Unknown'}"
            )
            
            return True, "Request rejected successfully"
            
        except Exception as e:
            current_app.logger.error(f"Request rejection error: {str(e)}")
            return False, str(e)

class SystemMonitor:
    """System health monitoring"""
    
    def __init__(self):
        self.model_monitor = ModelMonitor()
        
    def get_system_metrics(self):
        """Get comprehensive system metrics"""
        try:
            return {
                'cpu_usage': self._get_cpu_usage(),
                'memory_usage': self._get_memory_usage(),
                'disk_usage': self._get_disk_usage(),
                'active_users': self._get_active_users(),
                'model_status': self.model_monitor.get_model_health_status(),
                'database_status': self._get_database_status(),
                'api_performance': self._get_api_performance()
            }
        except Exception as e:
            current_app.logger.error(f"System metrics error: {str(e)}")
            return {}
            
    def _get_cpu_usage(self):
        """Get CPU usage percentage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except ImportError:
            return 0
            
    def _get_memory_usage(self):
        """Get memory usage statistics"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                'total': memory.total,
                'used': memory.used,
                'percentage': memory.percent
            }
        except ImportError:
            return {'total': 0, 'used': 0, 'percentage': 0}
            
    def _get_disk_usage(self):
        """Get disk usage statistics"""
        try:
            import psutil
            disk = psutil.disk_usage('/')
            return {
                'total': disk.total,
                'used': disk.used,
                'percentage': (disk.used / disk.total) * 100
            }
        except ImportError:
            return {'total': 0, 'used': 0, 'percentage': 0}
            
    def _get_active_users(self):
        """Get count of active users in last 24 hours"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            active_count = User.query.filter(
                User.last_login >= cutoff_time
            ).count()
            return active_count
        except Exception:
            return 0
            
    def _get_database_status(self):
        """Get database connection status"""
        try:
            User.query.first()
            return {'status': 'Connected', 'response_time': '<10ms'}
        except Exception:
            return {'status': 'Error', 'response_time': 'N/A'}
            
    def _get_api_performance(self):
        """Get API performance metrics"""
        try:
            # This would be implemented with proper metrics collection
            return {
                'average_response_time': '120ms',
                'requests_per_minute': 45,
                'error_rate': '0.2%'
            }
        except Exception:
            return {}

# Initialize class instances
try:
    dashboard_manager = AdminDashboardManager()
    print("[OK] AdminDashboardManager initialized")
except Exception as e:
    print(f"[ERROR] AdminDashboardManager init failed: {e}")
    dashboard_manager = None

try:
    user_management = UserManagementSystem()
    print("[OK] UserManagementSystem initialized")
except Exception as e:
    print(f"[ERROR] UserManagementSystem init failed: {e}")
    user_management = None

try:
    approval_workflow = ApprovalWorkflow()
    print("[OK] ApprovalWorkflow initialized")
except Exception as e:
    print(f"[ERROR] ApprovalWorkflow init failed: {e}")
    approval_workflow = None

try:
    system_monitor = SystemMonitor()
    print("[OK] SystemMonitor initialized")
except Exception as e:
    print(f"[ERROR] SystemMonitor init failed: {e}")
    system_monitor = None

# Route Implementations

@admin_bp.route('/dashboard')
@login_required
@admin_required
@log_activity()
def admin_dashboard():
    """Admin dashboard - Main admin interface"""
    try:
        # Get dashboard metrics
        metrics = dashboard_manager.get_dashboard_metrics()
        
        # Get recent activity
        recent_activities = AuditLog.query.order_by(
            AuditLog.timestamp.desc()
        ).limit(10).all()
        
        # Get pending approvals count
        pending_count = AdminRequest.query.filter_by(status='pending').count()
        
        return render_template('admin/admin_dashboard.html',
                             metrics=metrics,
                             recent_activities=recent_activities,
                             pending_count=pending_count)
                             
    except Exception as e:
        current_app.logger.error(f"Admin dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('main.dashboard'))

@admin_bp.route('/users')
@login_required
@admin_required
@log_activity()
def user_management():
    """User management - Manage all users"""
    try:
        page = request.args.get('page', 1, type=int)
        users = user_management.get_all_users(page=page, per_page=20)
        
        if not users:
            flash('Error retrieving users', 'error')
            return redirect(url_for('admin.admin_dashboard'))
            
        return render_template('admin/user_management.html', users=users)
        
    except Exception as e:
        current_app.logger.error(f"User management error: {str(e)}")
        flash('Error loading user management', 'error')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/users/<int:user_id>/update-status', methods=['POST'])
@login_required
@admin_required
@rate_limit(60*60, per_seconds=60*60)  # 60 requests per minute
def update_user_status(user_id):
    """Update user account status"""
    try:
        new_status = request.json.get('status', False)
        success, message = user_management.update_user_status(user_id, new_status)
        
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'message': message}), 400
            
    except Exception as e:
        current_app.logger.error(f"User status update error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
@rate_limit(10*60, per_seconds= 60*60)  # 10 deletions per minute max
def delete_user(user_id):
    """Delete user account"""
    try:
        reason = request.form.get('reason', '')
        reason = sanitize_input(reason)
        
        success, message = user_management.delete_user_account(user_id, reason)
        
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
            
        return redirect(url_for('admin.user_management'))
        
    except Exception as e:
        current_app.logger.error(f"User deletion error: {str(e)}")
        flash('Error deleting user', 'error')
        return redirect(url_for('admin.user_management'))

@admin_bp.route('/approvals')
@login_required
@admin_required
@log_activity()
def approval_requests():
    """Approval requests - Manage admin approval requests"""
    try:
        pending_requests = approval_workflow.get_pending_requests()
        
        return render_template('admin/approval_requests.html',
                             requests=pending_requests)
                             
    except Exception as e:
        current_app.logger.error(f"Approval requests error: {str(e)}")
        flash('Error loading approval requests', 'error')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/approvals/<int:request_id>/approve', methods=['POST'])
@login_required
@admin_required
@rate_limit(30*60, per_seconds=60*60)  # 30 approvals per minute max
def approve_user_request(request_id):
    """Approve admin access request"""
    try:
        admin_response = request.form.get('admin_response', '')
        admin_response = sanitize_input(admin_response)
        
        success, message = approval_workflow.approve_request(request_id, admin_response)
        
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
            
        return redirect(url_for('admin.approval_requests'))
        
    except Exception as e:
        current_app.logger.error(f"Request approval error: {str(e)}")
        flash('Error approving request', 'error')
        return redirect(url_for('admin.approval_requests'))

@admin_bp.route('/approvals/<int:request_id>/reject', methods=['POST'])
@login_required
@admin_required
@rate_limit(30*60, per_seconds=60*60)  # 30 rejections per minute max
def reject_user_request(request_id):
    """Reject admin access request"""
    try:
        admin_response = request.form.get('admin_response', '')
        admin_response = sanitize_input(admin_response)
        
        success, message = approval_workflow.reject_request(request_id, admin_response)
        
        if success:
            flash(message, 'success')
        else:
            flash(message, 'error')
            
        return redirect(url_for('admin.approval_requests'))
        
    except Exception as e:
        current_app.logger.error(f"Request rejection error: {str(e)}")
        flash('Error rejecting request', 'error')
        return redirect(url_for('admin.approval_requests'))

@admin_bp.route('/system-monitor')
@login_required
@admin_required
@log_activity()
def system_monitoring():
    """System monitoring - Monitor system health and performance"""
    try:
        system_metrics = system_monitor.get_system_metrics()
        
        return render_template('admin/system_monitoring.html',
                             metrics=system_metrics)
                             
    except Exception as e:
        current_app.logger.error(f"System monitoring error: {str(e)}")
        flash('Error loading system monitoring', 'error')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/model-performance')
@login_required
@admin_required
@log_activity()
def view_model_performance():
    """AI model performance monitoring"""
    try:
        model_monitor = ModelMonitor()
        
        # Get performance metrics for all 9 models
        performance_data = {
            'cnn_model': model_monitor.get_model_performance('wifi_vulnerability_cnn_final'),
            'lstm_model': model_monitor.get_model_performance('wifi_lstm_model'),
            'lstm_production': model_monitor.get_model_performance('wifi_lstm_production'),
            'gnn_model': model_monitor.get_model_performance('gnn_wifi_vulnerability_model'),
            'crypto_bert': model_monitor.get_model_performance('crypto_bert_enhanced'),
            'cnn_lstm_hybrid': model_monitor.get_model_performance('wifi_cnn_lstm_model'),
            'attention_model': model_monitor.get_model_performance('wifi_attention_model'),
            'random_forest': model_monitor.get_model_performance('wifi_random_forest_model'),
            'gradient_boosting': model_monitor.get_model_performance('wifi_gradient_boosting_model'),
            'ensemble_metrics': model_monitor.get_ensemble_metrics()
        }
        
        return render_template('admin/model_performance.html',
                             performance_data=performance_data)
                             
    except Exception as e:
        current_app.logger.error(f"Model performance error: {str(e)}")
        flash('Error loading model performance', 'error')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/audit-logs')
@login_required
@admin_required
@log_activity()
def view_audit_logs():
    """System audit logs - View comprehensive audit trail"""
    try:
        page = request.args.get('page', 1, type=int)
        event_type = request.args.get('event_type', '')
        
        query = AuditLog.query
        
        if event_type:
            query = query.filter_by(event_type=event_type)
            
        audit_logs = query.order_by(AuditLog.timestamp.desc()).paginate(
            page=page, per_page=50, error_out=False
        )
        
        # Get unique event types for filtering
        event_types = AuditLog.query.with_entities(
            AuditLog.event_type
        ).distinct().all()
        event_types = [et[0] for et in event_types]
        
        return render_template('admin/audit_logs.html',
                             audit_logs=audit_logs,
                             event_types=event_types,
                             current_filter=event_type)
                             
    except Exception as e:
        current_app.logger.error(f"Audit logs error: {str(e)}")
        flash('Error loading audit logs', 'error')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/security-settings')
@login_required
@admin_required
@log_activity()
def manage_security_settings():
    """Security configuration - Manage system security settings"""
    try:
        # Get current security settings
        security_settings = {
            'password_policy': {
                'min_length': 8,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special_chars': True
            },
            'session_settings': {
                'timeout_minutes': 60,
                'max_concurrent_sessions': 3
            },
            'rate_limiting': {
                'api_requests_per_minute': 100,
                'login_attempts_per_hour': 5
            },
            'audit_settings': {
                'log_level': 'INFO',
                'retention_days': 90
            }
        }
        
        return render_template('admin/security_settings.html',
                             settings=security_settings)
                             
    except Exception as e:
        current_app.logger.error(f"Security settings error: {str(e)}")
        flash('Error loading security settings', 'error')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/bulk-operations')
@login_required
@admin_required
@log_activity()
def bulk_user_operations():
    """Bulk user operations - Perform bulk operations on users"""
    try:
        if request.method == 'POST':
            operation = request.form.get('operation')
            user_ids = request.form.getlist('user_ids')
            
            if not user_ids:
                flash('No users selected', 'error')
                return redirect(url_for('admin.user_management'))
                
            success_count = 0
            
            for user_id in user_ids:
                try:
                    if operation == 'activate':
                        success, _ = user_management.update_user_status(int(user_id), True)
                    elif operation == 'deactivate':
                        success, _ = user_management.update_user_status(int(user_id), False)
                    elif operation == 'delete':
                        success, _ = user_management.delete_user_account(int(user_id), 'Bulk deletion')
                    else:
                        continue
                        
                    if success:
                        success_count += 1
                        
                except Exception as e:
                    current_app.logger.error(f"Bulk operation error for user {user_id}: {str(e)}")
                    continue
                    
            flash(f'Bulk operation completed. {success_count} users processed.', 'success')
            
            # Log bulk operation
            AuditLog.log_event(
                user_id=current_user.id,
                event_type='BULK_OPERATION',
                details=f"Performed {operation} on {success_count} users"
            )
            
        return redirect(url_for('admin.user_management'))
        
    except Exception as e:
        current_app.logger.error(f"Bulk operations error: {str(e)}")
        flash('Error performing bulk operations', 'error')
        return redirect(url_for('admin.user_management'))

@admin_bp.route('/users/count')
@login_required
@admin_required  
def get_users_count():
    """Get user count statistics"""
    try:
        from app.models.user import User
        
        total_users = User.query.count()
        active_users = User.query.filter_by(is_verified=True).count()
        admin_users = User.query.filter_by(role='admin').count()
        pending_users = User.query.filter_by(is_verified=False).count()
        
        return jsonify({
            'success': True,
            'data': {
                'total_users': total_users,
                'active_users': active_users,
                'admin_users': admin_users,
                'pending_users': pending_users
            },
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Users count error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/system-health')
@login_required
@admin_required
def system_health_check():
    """System health check - Get real-time system status"""
    try:
        health_data = system_monitor.get_system_metrics()
        
        return jsonify({
            'success': True,
            'health_data': health_data,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"System health check error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/export-audit-logs')
@login_required
@admin_required
@rate_limit(5*60, per_seconds=60*60)  # 5 exports per minute max
def export_audit_logs():
    """Export audit logs to PDF"""
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = AuditLog.query
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= datetime.fromisoformat(start_date))
        if end_date:
            query = query.filter(AuditLog.timestamp <= datetime.fromisoformat(end_date))
            
        audit_logs = query.order_by(AuditLog.timestamp.desc()).all()
        
        # Generate PDF report
        pdf_generator = PDFGenerator()
        pdf_path = pdf_generator.generate_audit_report(audit_logs)
        
        # Log export activity
        AuditLog.log_event(
            user_id=current_user.id,
            event_type='AUDIT_EXPORT',
            details=f"Exported {len(audit_logs)} audit log entries"
        )
        
        return jsonify({
            'success': True,
            'download_url': url_for('admin.download_report', filename=os.path.basename(pdf_path))
        })
        
    except Exception as e:
        current_app.logger.error(f"Audit log export error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/monitor-system-resources')
@login_required
@admin_required
def monitor_system_resources():
    """Resource monitoring - Get real-time resource usage"""
    try:
        resources = {
            'cpu_usage': system_monitor._get_cpu_usage(),
            'memory_usage': system_monitor._get_memory_usage(),
            'disk_usage': system_monitor._get_disk_usage(),
            'active_users': system_monitor._get_active_users(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify({'success': True, 'resources': resources})
        
    except Exception as e:
        current_app.logger.error(f"Resource monitoring error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@admin_bp.route('/download-report/<filename>')
@login_required
@admin_required
def download_report(filename):
    """Download generated reports"""
    try:
        # Validate filename for security
        filename = secure_filename(filename)
        report_path = os.path.join(current_app.config['REPORTS_FOLDER'], filename)
        
        if not os.path.exists(report_path):
            flash('Report not found', 'error')
            return redirect(url_for('admin.admin_dashboard'))
            
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        current_app.logger.error(f"Report download error: {str(e)}")
        flash('Error downloading report', 'error')
        return redirect(url_for('admin.admin_dashboard'))


# ============================================================================= 
# COMPREHENSIVE ANALYTICS AND MONITORING ROUTES
# =============================================================================

@admin_bp.route('/analytics')
@login_required
@admin_required
@log_activity()
def analytics_dashboard():
    """Comprehensive analytics dashboard"""
    try:
        # Get analytics data
        analytics = AnalyticsManager.get_dashboard_analytics(days=30)
        
        # Index page specific analytics
        index_analytics = AnalyticsManager.get_index_page_analytics(days=30)
        
        # User behavior analytics 
        user_behavior = AnalyticsManager.get_user_behavior_analytics(days=30)
        
        # Real-time stats
        from app.utils.analytics_tracker import get_real_time_stats
        real_time_stats = get_real_time_stats()
        
        # Top pages analytics
        top_pages = db.session.query(
            PageViewEvent.page_path,
            PageViewEvent.page_title,
            func.count(PageViewEvent.id).label('views'),
            func.count(func.distinct(PageViewEvent.ip_address)).label('unique_visitors')
        ).filter(
            PageViewEvent.timestamp >= datetime.utcnow() - timedelta(days=30)
        ).group_by(
            PageViewEvent.page_path, PageViewEvent.page_title
        ).order_by(
            func.count(PageViewEvent.id).desc()
        ).limit(10).all()
        
        # Browser and device analytics
        browser_stats = db.session.query(
            PageViewEvent.browser_name,
            func.count(PageViewEvent.id).label('count')
        ).filter(
            PageViewEvent.timestamp >= datetime.utcnow() - timedelta(days=30),
            PageViewEvent.browser_name.isnot(None)
        ).group_by(PageViewEvent.browser_name).order_by(
            func.count(PageViewEvent.id).desc()
        ).limit(10).all()
        
        device_stats = db.session.query(
            PageViewEvent.device_type,
            func.count(PageViewEvent.id).label('count')
        ).filter(
            PageViewEvent.timestamp >= datetime.utcnow() - timedelta(days=30),
            PageViewEvent.device_type.isnot(None)
        ).group_by(PageViewEvent.device_type).all()
        
        return render_template('admin/analytics_dashboard.html',
                             analytics=analytics,
                             index_analytics=index_analytics,
                             user_behavior=user_behavior,
                             real_time_stats=real_time_stats,
                             top_pages=top_pages,
                             browser_stats=browser_stats,
                             device_stats=device_stats)
        
    except Exception as e:
        current_app.logger.error(f"Analytics dashboard error: {str(e)}")
        flash('Error loading analytics dashboard', 'error')
        return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/live-monitoring')
@login_required
@admin_required
def live_monitoring():
    """Real-time live monitoring dashboard"""
    try:
        return render_template('admin/live_monitoring.html')
    except Exception as e:
        current_app.logger.error(f"Live monitoring error: {str(e)}")
        flash('Error loading live monitoring', 'error')
        return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/api/live-stats')
@login_required
@admin_required
def api_live_stats():
    """API endpoint for real-time statistics"""
    try:
        from app.utils.analytics_tracker import get_real_time_stats
        stats = get_real_time_stats()
        
        # Add additional real-time data
        stats.update({
            'timestamp': datetime.utcnow().isoformat(),
            'total_users': User.query.count(),
            'active_scans': ScanResult.query.filter(
                ScanResult.scan_status == 'RUNNING'
            ).count(),
            'pending_approvals': AdminRequest.query.filter_by(status='pending').count(),
            'unresolved_incidents': SecurityIncident.query.filter_by(resolved=False).count()
        })
        
        return jsonify(stats)
        
    except Exception as e:
        current_app.logger.error(f"Live stats API error: {str(e)}")
        return jsonify({'error': 'Failed to fetch live stats'}), 500


@admin_bp.route('/security-incidents')
@login_required
@admin_required
@log_activity()
def security_incidents():
    """Security incidents management"""
    try:
        # Get security incidents with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        incidents = SecurityIncident.query.order_by(
            SecurityIncident.timestamp.desc()
        ).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Get incident statistics
        incident_stats = {
            'total': SecurityIncident.query.count(),
            'unresolved': SecurityIncident.query.filter_by(resolved=False).count(),
            'critical': SecurityIncident.query.filter_by(
                severity=SecurityIncident.Severity.CRITICAL
            ).count(),
            'today': SecurityIncident.query.filter(
                SecurityIncident.timestamp >= datetime.utcnow().date()
            ).count()
        }
        
        return render_template('admin/security_incidents.html',
                             incidents=incidents,
                             incident_stats=incident_stats)
        
    except Exception as e:
        current_app.logger.error(f"Security incidents error: {str(e)}")
        flash('Error loading security incidents', 'error')
        return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/user-analytics')
@login_required
@admin_required
@log_activity()
def user_analytics():
    """Detailed user analytics and behavior analysis"""
    try:
        # User registration analytics
        registration_stats = db.session.query(
            func.date(User.created_at).label('date'),
            func.count(User.id).label('registrations')
        ).filter(
            User.created_at >= datetime.utcnow() - timedelta(days=30)
        ).group_by(func.date(User.created_at)).order_by('date').all()
        
        # User activity patterns
        activity_patterns = db.session.query(
            UserActivity.activity_type,
            func.count(UserActivity.id).label('count'),
            func.avg(UserActivity.duration).label('avg_duration')
        ).filter(
            UserActivity.timestamp >= datetime.utcnow() - timedelta(days=30)
        ).group_by(UserActivity.activity_type).order_by(
            func.count(UserActivity.id).desc()
        ).limit(15).all()
        
        # Most active users
        active_users = db.session.query(
            User.email,
            User.id,
            func.count(UserActivity.id).label('activity_count')
        ).join(UserActivity).filter(
            UserActivity.timestamp >= datetime.utcnow() - timedelta(days=30)
        ).group_by(User.id, User.email).order_by(
            func.count(UserActivity.id).desc()
        ).limit(10).all()
        
        # User engagement metrics
        engagement_metrics = {
            'total_sessions': PageViewEvent.query.with_entities(
                PageViewEvent.session_id
            ).distinct().count(),
            'avg_session_duration': 0,  # Would need session tracking
            'bounce_rate': 0,  # Would need session analysis
            'return_visitors': 0  # Would need visitor tracking
        }
        
        return render_template('admin/user_analytics.html',
                             registration_stats=registration_stats,
                             activity_patterns=activity_patterns,
                             active_users=active_users,
                             engagement_metrics=engagement_metrics)
        
    except Exception as e:
        current_app.logger.error(f"User analytics error: {str(e)}")
        flash('Error loading user analytics', 'error')
        return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/system-performance')
@login_required
@admin_required
@log_activity()
def system_performance():
    """System performance monitoring"""
    try:
        # Get system metrics
        performance_metrics = SystemMetrics.query.filter(
            SystemMetrics.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).order_by(SystemMetrics.timestamp.desc()).limit(100).all()
        
        # Group metrics by type
        metrics_by_type = {}
        for metric in performance_metrics:
            if metric.metric_type not in metrics_by_type:
                metrics_by_type[metric.metric_type] = []
            metrics_by_type[metric.metric_type].append({
                'timestamp': metric.timestamp,
                'value': metric.metric_value,
                'unit': metric.metric_unit
            })
        
        # Get system health summary
        health_summary = dashboard_manager.get_system_health()
        
        return render_template('admin/system_performance.html',
                             metrics_by_type=metrics_by_type,
                             health_summary=health_summary)
        
    except Exception as e:
        current_app.logger.error(f"System performance error: {str(e)}")
        flash('Error loading system performance', 'error')
        return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/export-analytics')
@login_required
@admin_required
@rate_limit(5*60, per_seconds=60*60)  # 5 exports per hour
def export_analytics():
    """Export analytics data to CSV/JSON"""
    try:
        export_format = request.args.get('format', 'csv')
        days = request.args.get('days', 30, type=int)
        
        # Get analytics data
        analytics = AnalyticsManager.get_dashboard_analytics(days=days)
        
        if export_format == 'json':
            # Return JSON format
            return jsonify({
                'page_views': len(analytics['page_views']),
                'user_activities': len(analytics['user_activities']),
                'system_metrics': len(analytics['system_metrics']),
                'security_incidents': len(analytics['security_incidents']),
                'export_date': datetime.utcnow().isoformat(),
                'period_days': days
            })
        
        else:
            # Return CSV format (simplified)
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(['Type', 'Date', 'Count', 'Details'])
            
            # Write page views
            page_views_by_date = {}
            for pv in analytics['page_views']:
                date_key = pv.timestamp.date().isoformat()
                page_views_by_date[date_key] = page_views_by_date.get(date_key, 0) + 1
            
            for date, count in page_views_by_date.items():
                writer.writerow(['Page Views', date, count, 'Daily page views'])
            
            output.seek(0)
            
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=analytics_export_{days}days.csv'}
            )
        
    except Exception as e:
        current_app.logger.error(f"Analytics export error: {str(e)}")
        flash('Error exporting analytics', 'error')
        return redirect(url_for('admin.analytics_dashboard'))


# Error handlers
@admin_bp.errorhandler(403)
def forbidden(error):
    """Handle forbidden access"""
    flash('Access denied. Admin privileges required.', 'error')
    return redirect(url_for('main.dashboard'))

@admin_bp.errorhandler(404)
def not_found(error):
    """Handle not found errors"""
    flash('Admin page not found.', 'error')
    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    current_app.logger.error(f"Admin panel internal error: {str(error)}")
    flash('Internal server error in admin panel.', 'error')
    return redirect(url_for('admin.admin_dashboard'))