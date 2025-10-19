"""
app/admin/utils.py - Administrative Utility Functions
Purpose: Administrative utility functions for the Wi-Fi Security System
"""

import json
import csv
import io
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from flask import current_app
import logging
from sqlalchemy import func, and_, or_
from app.models.user import User, UserRole
from app.models.scan_results import ScanResult
from app.models.admin_requests import AdminRequest
from app.models.audit_logs import AuditLog
from app.utils.pdf_generator import PDFGenerator
from app.utils.email_sender import EmailSender

logger = logging.getLogger(__name__)


class AdminUtils:
    """General admin utilities"""
    
    @staticmethod
    def calculate_system_stats() -> Dict[str, Any]:
        """Calculate system-wide statistics"""
        try:
            stats = {
                'total_users': User.query.count(),
                'verified_users': User.query.filter_by(is_verified=True).count(),
                'admin_approved_users': User.query.filter_by(is_admin_approved=True).count(),
                'pending_requests': AdminRequest.query.filter_by(status='pending').count(),
                'total_scans': ScanResult.query.count(),
                'high_risk_scans': ScanResult.query.filter_by(risk_level='HIGH_RISK').count(),
                'system_uptime': AdminUtils._calculate_uptime(),
                'last_updated': datetime.utcnow().isoformat()
            }
            
            # Calculate scan statistics by time period
            stats.update(AdminUtils._get_scan_statistics())
            
            logger.info(f"System statistics calculated: {stats['total_users']} users, {stats['total_scans']} scans")
            return stats
            
        except Exception as e:
            logger.error(f"Error calculating system stats: {str(e)}")
            return {}
    
    @staticmethod
    def _calculate_uptime() -> str:
        """Calculate system uptime"""
        # This would typically read from a system file or service
        # For now, return a placeholder implementation
        return "99.9%"
    
    @staticmethod
    def _get_scan_statistics() -> Dict[str, int]:
        """Get scan statistics for different time periods"""
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(weeks=1)
        month_ago = now - timedelta(days=30)
        
        return {
            'scans_last_24h': ScanResult.query.filter(ScanResult.scan_timestamp >= day_ago).count(),
            'scans_last_week': ScanResult.query.filter(ScanResult.scan_timestamp >= week_ago).count(),
            'scans_last_month': ScanResult.query.filter(ScanResult.scan_timestamp >= month_ago).count(),
            'high_risk_last_24h': ScanResult.query.filter(
                and_(ScanResult.scan_timestamp >= day_ago, ScanResult.risk_level == 'HIGH_RISK')
            ).count()
        }
    
    @staticmethod
    def validate_bulk_operation(operation_type: str, user_ids: List[int]) -> Dict[str, Any]:
        """Validate bulk operations before execution"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'affected_count': len(user_ids)
        }
        
        try:
            # Validate operation type
            valid_operations = ['approve', 'deny', 'deactivate', 'reactivate', 'delete']
            if operation_type not in valid_operations:
                validation_result['valid'] = False
                validation_result['errors'].append(f"Invalid operation type: {operation_type}")
                return validation_result
            
            # Validate user IDs exist
            existing_users = User.query.filter(User.id.in_(user_ids)).all()
            existing_ids = [user.id for user in existing_users]
            missing_ids = set(user_ids) - set(existing_ids)
            
            if missing_ids:
                validation_result['warnings'].append(f"Users not found: {list(missing_ids)}")
            
            # Check for admin users in delete operations
            if operation_type == 'delete':
                admin_users = [user for user in existing_users if user.role == UserRole.ADMIN]
                if admin_users:
                    validation_result['valid'] = False
                    validation_result['errors'].append("Cannot delete admin users")
            
            validation_result['affected_count'] = len(existing_ids)
            logger.info(f"Bulk operation validation: {operation_type} for {len(existing_ids)} users")
            
        except Exception as e:
            logger.error(f"Error validating bulk operation: {str(e)}")
            validation_result['valid'] = False
            validation_result['errors'].append("Validation error occurred")
        
        return validation_result
    
    @staticmethod
    def get_user_activity_summary(user_id: int) -> Dict[str, Any]:
        """Get comprehensive user activity summary"""
        try:
            user = User.query.get(user_id)
            if not user:
                return {}
            
            scans = ScanResult.query.filter_by(user_id=user_id).all()
            audit_logs = AuditLog.query.filter_by(user_id=user_id).limit(50).all()
            
            summary = {
                'user_info': {
                    'id': user.id,
                    'email': user.email,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'is_verified': user.is_verified,
                    'is_admin_approved': user.is_admin_approved,
                    'role': user.role.value if user.role else 'USER'
                },
                'scan_activity': {
                    'total_scans': len(scans),
                    'high_risk_scans': len([s for s in scans if s.risk_level == 'HIGH_RISK']),
                    'last_scan': max([s.scan_timestamp for s in scans]).isoformat() if scans else None,
                    'scan_frequency': AdminUtils._calculate_scan_frequency(scans)
                },
                'recent_activity': [
                    {
                        'timestamp': log.timestamp.isoformat(),
                        'event_type': log.event_type,
                        'details': log.details
                    }
                    for log in audit_logs[:10]
                ]
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting user activity summary: {str(e)}")
            return {}
    
    @staticmethod
    def _calculate_scan_frequency(scans: List[ScanResult]) -> str:
        """Calculate user's scan frequency"""
        if not scans or len(scans) < 2:
            return "Insufficient data"
        
        # Sort scans by timestamp
        sorted_scans = sorted(scans, key=lambda x: x.scan_timestamp)
        
        # Calculate average time between scans
        time_diffs = []
        for i in range(1, len(sorted_scans)):
            diff = sorted_scans[i].scan_timestamp - sorted_scans[i-1].scan_timestamp
            time_diffs.append(diff.total_seconds())
        
        avg_seconds = sum(time_diffs) / len(time_diffs)
        avg_days = avg_seconds / (24 * 3600)
        
        if avg_days < 1:
            return "Multiple per day"
        elif avg_days < 7:
            return "Daily"
        elif avg_days < 30:
            return "Weekly"
        else:
            return "Monthly"


class ReportingUtils:
    """Admin reporting utilities"""
    
    @staticmethod
    def generate_admin_reports(report_type: str, date_range: Dict[str, str]) -> Dict[str, Any]:
        """Generate various admin reports"""
        try:
            start_date = datetime.fromisoformat(date_range['start'])
            end_date = datetime.fromisoformat(date_range['end'])
            
            if report_type == 'user_activity':
                return ReportingUtils._generate_user_activity_report(start_date, end_date)
            elif report_type == 'scan_summary':
                return ReportingUtils._generate_scan_summary_report(start_date, end_date)
            elif report_type == 'security_incidents':
                return ReportingUtils._generate_security_incidents_report(start_date, end_date)
            elif report_type == 'system_performance':
                return ReportingUtils._generate_system_performance_report(start_date, end_date)
            else:
                logger.warning(f"Unknown report type requested: {report_type}")
                return {'error': 'Unknown report type'}
                
        except Exception as e:
            logger.error(f"Error generating admin report: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def _generate_user_activity_report(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate user activity report"""
        users = User.query.filter(
            User.created_at.between(start_date, end_date)
        ).all()
        
        logins = AuditLog.query.filter(
            and_(
                AuditLog.timestamp.between(start_date, end_date),
                AuditLog.event_type == 'user_login'
            )
        ).all()
        
        return {
            'report_type': 'user_activity',
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'metrics': {
                'new_registrations': len(users),
                'total_logins': len(logins),
                'unique_active_users': len(set(log.user_id for log in logins if log.user_id)),
                'verification_rate': sum(1 for u in users if u.is_verified) / len(users) * 100 if users else 0
            },
            'details': {
                'daily_registrations': ReportingUtils._group_by_day(users, 'created_at'),
                'daily_logins': ReportingUtils._group_by_day(logins, 'timestamp')
            }
        }
    
    @staticmethod
    def _generate_scan_summary_report(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate scan summary report"""
        scans = ScanResult.query.filter(
            ScanResult.scan_timestamp.between(start_date, end_date)
        ).all()
        
        return {
            'report_type': 'scan_summary',
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'metrics': {
                'total_scans': len(scans),
                'high_risk_scans': len([s for s in scans if s.risk_level == 'HIGH_RISK']),
                'low_risk_scans': len([s for s in scans if s.risk_level == 'LOW_RISK']),
                'normal_scans': len([s for s in scans if s.risk_level == 'NORMAL']),
                'unique_networks': len(set(s.network_ssid for s in scans)),
                'unique_users': len(set(s.user_id for s in scans))
            },
            'trends': {
                'daily_scans': ReportingUtils._group_by_day(scans, 'scan_timestamp'),
                'risk_distribution': ReportingUtils._calculate_risk_distribution(scans)
            }
        }
    
    @staticmethod
    def _generate_security_incidents_report(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate security incidents report"""
        security_logs = AuditLog.query.filter(
            and_(
                AuditLog.timestamp.between(start_date, end_date),
                AuditLog.security_level.in_(['HIGH', 'CRITICAL'])
            )
        ).all()
        
        high_risk_scans = ScanResult.query.filter(
            and_(
                ScanResult.scan_timestamp.between(start_date, end_date),
                ScanResult.risk_level == 'HIGH_RISK'
            )
        ).all()
        
        return {
            'report_type': 'security_incidents',
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'metrics': {
                'total_incidents': len(security_logs),
                'critical_incidents': len([log for log in security_logs if log.security_level == 'CRITICAL']),
                'high_risk_detections': len(high_risk_scans),
                'incident_rate': len(security_logs) / ((end_date - start_date).days or 1)
            },
            'incident_types': ReportingUtils._group_incidents_by_type(security_logs),
            'affected_networks': list(set(scan.network_ssid for scan in high_risk_scans))
        }
    
    @staticmethod
    def _generate_system_performance_report(start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate system performance report"""
        # This would typically integrate with monitoring APIs
        # For now, return placeholder data structure
        return {
            'report_type': 'system_performance',
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'metrics': {
                'avg_response_time': '245ms',
                'uptime_percentage': 99.9,
                'error_rate': 0.1,
                'peak_concurrent_users': 45,
                'model_accuracy': {
                    'cnn_model': 95.2,
                    'lstm_model': 93.8,
                    'ensemble_model': 97.1
                }
            }
        }
    
    @staticmethod
    def _group_by_day(items: List, timestamp_field: str) -> Dict[str, int]:
        """Group items by day"""
        daily_counts = {}
        for item in items:
            timestamp = getattr(item, timestamp_field)
            day_key = timestamp.strftime('%Y-%m-%d')
            daily_counts[day_key] = daily_counts.get(day_key, 0) + 1
        return daily_counts
    
    @staticmethod
    def _calculate_risk_distribution(scans: List[ScanResult]) -> Dict[str, int]:
        """Calculate risk level distribution"""
        distribution = {'HIGH_RISK': 0, 'LOW_RISK': 0, 'NORMAL': 0}
        for scan in scans:
            if scan.risk_level in distribution:
                distribution[scan.risk_level] += 1
        return distribution
    
    @staticmethod
    def _group_incidents_by_type(security_logs: List[AuditLog]) -> Dict[str, int]:
        """Group security incidents by type"""
        incident_types = {}
        for log in security_logs:
            event_type = log.event_type
            incident_types[event_type] = incident_types.get(event_type, 0) + 1
        return incident_types
    
    @staticmethod
    def export_report_to_csv(report_data: Dict[str, Any]) -> str:
        """Export report data to CSV format"""
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['Report Type', report_data.get('report_type', 'Unknown')])
            writer.writerow(['Generated At', datetime.utcnow().isoformat()])
            writer.writerow([])  # Empty row
            
            # Write metrics
            if 'metrics' in report_data:
                writer.writerow(['Metrics'])
                for key, value in report_data['metrics'].items():
                    writer.writerow([key.replace('_', ' ').title(), value])
                writer.writerow([])  # Empty row
            
            # Write additional details based on report type
            if report_data.get('report_type') == 'user_activity' and 'details' in report_data:
                writer.writerow(['Daily Activity'])
                writer.writerow(['Date', 'Registrations', 'Logins'])
                for date in sorted(set(list(report_data['details']['daily_registrations'].keys()) + 
                                     list(report_data['details']['daily_logins'].keys()))):
                    registrations = report_data['details']['daily_registrations'].get(date, 0)
                    logins = report_data['details']['daily_logins'].get(date, 0)
                    writer.writerow([date, registrations, logins])
            
            return output.getvalue()
            
        except Exception as e:
            logger.error(f"Error exporting report to CSV: {str(e)}")
            return ""


class SecurityUtils:
    """Security management utilities"""
    
    @staticmethod
    def manage_user_permissions(user_id: int, permissions: Dict[str, bool]) -> Dict[str, Any]:
        """Manage user permissions"""
        try:
            user = User.query.get(user_id)
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Update user permissions (this would typically be in a separate permissions table)
            # For now, we'll store in user profile_data as JSON
            if not hasattr(user, 'profile_data') or user.profile_data is None:
                user.profile_data = {}
            
            current_permissions = user.profile_data.get('permissions', {})
            current_permissions.update(permissions)
            user.profile_data['permissions'] = current_permissions
            
            # Log the permission change
            AuditLog.log_event(
                user_id=user_id,
                event_type='permission_change',
                details=f"Permissions updated: {permissions}",
                security_level='MEDIUM'
            )
            
            logger.info(f"Updated permissions for user {user_id}: {permissions}")
            return {'success': True, 'updated_permissions': current_permissions}
            
        except Exception as e:
            logger.error(f"Error managing user permissions: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def audit_system_changes(change_type: str, details: Dict[str, Any], admin_user_id: int) -> bool:
        """Audit system configuration changes"""
        try:
            # Log the system change
            AuditLog.log_event(
                user_id=admin_user_id,
                event_type=f'system_change_{change_type}',
                details=json.dumps(details),
                security_level='HIGH'
            )
            
            # Send notification to other admins if this is a critical change
            critical_changes = ['user_role_change', 'security_settings', 'model_configuration']
            if change_type in critical_changes:
                SecurityUtils._notify_admins_of_critical_change(change_type, details, admin_user_id)
            
            logger.info(f"System change audited: {change_type} by user {admin_user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error auditing system change: {str(e)}")
            return False
    
    @staticmethod
    def _notify_admins_of_critical_change(change_type: str, details: Dict[str, Any], admin_user_id: int):
        """Notify other admins of critical system changes"""
        try:
            # Get all admin users except the one making the change
            admin_users = User.query.filter(
                and_(User.role == UserRole.ADMIN, User.id != admin_user_id)
            ).all()
            
            admin_user = User.query.get(admin_user_id)
            admin_email = admin_user.email if admin_user else 'Unknown'
            
            email_sender = EmailSender()
            for admin in admin_users:
                email_sender.send_notification(
                    to_email=admin.email,
                    subject=f"Critical System Change: {change_type}",
                    message=f"Admin {admin_email} made a critical system change: {change_type}\n\nDetails: {json.dumps(details, indent=2)}"
                )
            
        except Exception as e:
            logger.error(f"Error notifying admins of critical change: {str(e)}")
    
    @staticmethod
    def check_suspicious_activity(user_id: int, activity_window_hours: int = 24) -> Dict[str, Any]:
        """Check for suspicious user activity patterns"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=activity_window_hours)
            
            # Get recent activity for the user
            recent_logs = AuditLog.query.filter(
                and_(
                    AuditLog.user_id == user_id,
                    AuditLog.timestamp >= cutoff_time
                )
            ).all()
            
            # Get recent scans
            recent_scans = ScanResult.query.filter(
                and_(
                    ScanResult.user_id == user_id,
                    ScanResult.scan_timestamp >= cutoff_time
                )
            ).all()
            
            suspicious_indicators = []
            
            # Check for unusual login patterns
            login_attempts = [log for log in recent_logs if log.event_type in ['user_login', 'login_failed']]
            if len(login_attempts) > 20:  # More than 20 login attempts in window
                suspicious_indicators.append('excessive_login_attempts')
            
            # Check for unusual scan frequency
            if len(recent_scans) > 50:  # More than 50 scans in window
                suspicious_indicators.append('excessive_scanning')
            
            # Check for multiple IP addresses
            ip_addresses = set(log.ip_address for log in recent_logs if log.ip_address)
            if len(ip_addresses) > 5:  # More than 5 different IPs
                suspicious_indicators.append('multiple_ip_addresses')
            
            # Check for unusual time patterns (activity during off-hours)
            off_hours_activity = [
                log for log in recent_logs 
                if log.timestamp.hour < 6 or log.timestamp.hour > 22
            ]
            if len(off_hours_activity) > len(recent_logs) * 0.7:  # More than 70% off-hours activity
                suspicious_indicators.append('off_hours_activity')
            
            risk_level = 'LOW'
            if len(suspicious_indicators) >= 3:
                risk_level = 'HIGH'
            elif len(suspicious_indicators) >= 2:
                risk_level = 'MEDIUM'
            
            result = {
                'user_id': user_id,
                'risk_level': risk_level,
                'suspicious_indicators': suspicious_indicators,
                'activity_summary': {
                    'total_events': len(recent_logs),
                    'login_attempts': len(login_attempts),
                    'scans_performed': len(recent_scans),
                    'unique_ips': len(ip_addresses),
                    'off_hours_events': len(off_hours_activity)
                },
                'analysis_window_hours': activity_window_hours,
                'analyzed_at': datetime.utcnow().isoformat()
            }
            
            # Log suspicious activity if detected
            if risk_level in ['MEDIUM', 'HIGH']:
                AuditLog.log_event(
                    user_id=user_id,
                    event_type='suspicious_activity_detected',
                    details=json.dumps(result),
                    security_level=risk_level
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error checking suspicious activity: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def export_system_data(data_type: str, date_range: Dict[str, str]) -> str:
        """Export system data for compliance or backup purposes"""
        try:
            start_date = datetime.fromisoformat(date_range['start'])
            end_date = datetime.fromisoformat(date_range['end'])
            
            if data_type == 'audit_logs':
                return SecurityUtils._export_audit_logs(start_date, end_date)
            elif data_type == 'user_data':
                return SecurityUtils._export_user_data(start_date, end_date)
            elif data_type == 'scan_results':
                return SecurityUtils._export_scan_results(start_date, end_date)
            else:
                return ""
                
        except Exception as e:
            logger.error(f"Error exporting system data: {str(e)}")
            return ""
    
    @staticmethod
    def _export_audit_logs(start_date: datetime, end_date: datetime) -> str:
        """Export audit logs as CSV"""
        logs = AuditLog.query.filter(
            AuditLog.timestamp.between(start_date, end_date)
        ).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['Timestamp', 'User ID', 'Event Type', 'Details', 'IP Address', 'Security Level'])
        
        # Data
        for log in logs:
            writer.writerow([
                log.timestamp.isoformat() if log.timestamp else '',
                log.user_id or '',
                log.event_type or '',
                log.details or '',
                log.ip_address or '',
                log.security_level or ''
            ])
        
        return output.getvalue()
    
    @staticmethod
    def _export_user_data(start_date: datetime, end_date: datetime) -> str:
        """Export user data as CSV"""
        users = User.query.filter(
            User.created_at.between(start_date, end_date)
        ).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['ID', 'Email', 'Created At', 'Last Login', 'Is Verified', 'Is Admin Approved', 'Role'])
        
        # Data
        for user in users:
            writer.writerow([
                user.id,
                user.email,
                user.created_at.isoformat() if user.created_at else '',
                user.last_login.isoformat() if user.last_login else '',
                user.is_verified,
                user.is_admin_approved,
                user.role.value if user.role else 'USER'
            ])
        
        return output.getvalue()
    
    @staticmethod
    def _export_scan_results(start_date: datetime, end_date: datetime) -> str:
        """Export scan results as CSV"""
        scans = ScanResult.query.filter(
            ScanResult.scan_timestamp.between(start_date, end_date)
        ).all()
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['ID', 'User ID', 'Network SSID', 'Scan Timestamp', 'Risk Level', 'Vulnerability Count'])
        
        # Data
        for scan in scans:
            vulnerability_count = len(scan.vulnerability_details) if scan.vulnerability_details else 0
            writer.writerow([
                scan.id,
                scan.user_id,
                scan.network_ssid,
                scan.scan_timestamp.isoformat() if scan.scan_timestamp else '',
                scan.risk_level,
                vulnerability_count
            ])
        
        return output.getvalue()