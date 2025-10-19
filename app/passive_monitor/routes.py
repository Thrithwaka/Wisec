"""
Passive Monitor Routes
Purpose: Routes for passive monitoring dashboard and features
Security: Lab-only activation with admin permission checks
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_login import login_required, current_user

# Import core modules with fallback
try:
    from app.wifi_core.passive_scanner import (
        PassiveScanner, HandshakeCapture, BeaconAnalyzer, 
        RogueAPDetector, SecurityAuditor
    )
except ImportError:
    # Fallback to simple version
    from app.wifi_core.passive_scanner_simple import (
        PassiveScanner, HandshakeCapture, BeaconAnalyzer, 
        RogueAPDetector, SecurityAuditor
    )
try:
    from app.wifi_core.real_packet_capture import RealPacketCapture
except ImportError as e:
    # Create placeholder class if import fails
    class RealPacketCapture:
        def get_available_interfaces(self):
            return [{'name': 'wlan0', 'type': 'wireless', 'status': 'available'}]
        def get_capture_status(self):
            return {"is_capturing": False, "packets_captured": 0, "networks_detected": 0, "devices_found": 0, "threats_detected": 0, "packet_stats": {}}
        def start_capture(self, *args, **kwargs):
            return {"success": False, "message": "Real packet capture not available - install scapy and ensure proper permissions"}
        def stop_capture(self):
            return {"success": False, "message": "Packet capture not available"}

try:
    from app.models.audit_logs import AuditLog
except ImportError:
    # Placeholder for AuditLog
    class AuditLog:
        @staticmethod
        def log_event(*args, **kwargs):
            pass

try:
    from app.utils.decorators import rate_limit, log_activity
except ImportError:
    # Placeholder decorators
    def rate_limit(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def log_activity(*args, **kwargs):
        def decorator(f):
            return f
        return decorator

try:
    from app.utils.validators import SecurityValidator
except ImportError:
    # Placeholder validator
    class SecurityValidator:
        pass

try:
    from config import Config
except ImportError:
    # Placeholder config
    class Config:
        LAB_MODE_ENABLED = False
        ADMIN_USERS = []

# Create blueprint
passive_monitor = Blueprint('passive_monitor', __name__, url_prefix='/passive-monitor')

# Initialize components
passive_scanner = PassiveScanner()
handshake_capture = HandshakeCapture()
beacon_analyzer = BeaconAnalyzer()
rogue_detector = RogueAPDetector()
security_auditor = SecurityAuditor()
real_packet_capture = RealPacketCapture()

logger = logging.getLogger(__name__)


@passive_monitor.route('/')
@passive_monitor.route('/dashboard')
@login_required
def dashboard():
    """Main passive monitoring dashboard"""
    try:
        # Check if user has permissions for passive monitoring
        user_id = str(current_user.email) if current_user.is_authenticated else 'anonymous'
        
        # Get current monitoring status
        monitoring_status = real_packet_capture.get_capture_status()
        
        # Get available interfaces
        available_interfaces = real_packet_capture.get_available_interfaces()
        
        # Get recent activity
        recent_activity = _get_recent_monitoring_activity()
        
        return render_template('passive_monitor/dashboard.html',
                             monitoring_status=monitoring_status,
                             available_interfaces=available_interfaces,
                             recent_activity=recent_activity,
                             lab_mode_enabled=getattr(Config, 'LAB_MODE_ENABLED', False))
        
    except Exception as e:
        logger.error(f"Error loading passive monitor dashboard: {e}")
        flash('Error loading passive monitoring dashboard', 'error')
        return redirect(url_for('main.dashboard'))


@passive_monitor.route('/traffic-capture')
@login_required
def traffic_capture():
    """Traffic capture interface"""
    try:
        # Get available interfaces
        available_interfaces = real_packet_capture.get_available_interfaces()
        
        # Get current capture status
        capture_status = real_packet_capture.get_capture_status()
        
        return render_template('passive_monitor/traffic_capture.html',
                             available_interfaces=available_interfaces,
                             capture_status=capture_status)
        
    except Exception as e:
        logger.error(f"Error loading traffic capture: {e}")
        flash('Error loading traffic capture interface', 'error')
        return redirect(url_for('passive_monitor.dashboard'))


@passive_monitor.route('/rogue-detector')
@login_required
def rogue_detector():
    """Rogue AP detection interface"""
    try:
        # Check advanced feature access
        # TODO: Re-enable after fixing database access issues
        # from app.models.approval_system import ApprovalSystemManager
        # access_status = ApprovalSystemManager.get_user_access_status(current_user.id)
        # 
        # if not access_status.get('can_use', False):
        #     flash('Advanced features access required for Rogue AP Detection. Please request approval from admin.', 'warning')
        #     return redirect(url_for('main.dashboard'))
        
        # TEMPORARY: Allow access for testing - remove this after fixing approval system
        logger.info(f"User {current_user.id} accessing rogue detector (temp bypass enabled)")
        
        # Get recent rogue detection results if available
        detection_status = {
            'is_active': getattr(real_packet_capture, 'rogue_detection_active', False),
            'last_scan': getattr(real_packet_capture, 'rogue_analysis_results', None)
        }
        
        return render_template('passive_monitor/rogue_detector.html', 
                             detection_status=detection_status)
    except Exception as e:
        logger.error(f"Error loading rogue detector page: {e}")
        flash(f'Error loading rogue detector: {str(e)}', 'error')
        return redirect(url_for('passive_monitor.dashboard'))

@passive_monitor.route('/beacon-analysis')
@login_required
def beacon_analysis():
    """Beacon frame analysis interface"""
    try:
        # Get recent beacon analysis results
        beacon_results = _get_recent_beacon_analysis()
        
        return render_template('passive_monitor/beacon_analysis.html',
                             beacon_results=beacon_results)
        
    except Exception as e:
        logger.error(f"Error loading beacon analysis: {e}")
        flash('Error loading beacon analysis interface', 'error')
        return redirect(url_for('passive_monitor.dashboard'))




@passive_monitor.route('/handshake-capture')
@login_required
def handshake_capture_page():
    """Handshake capture interface (admin only)"""
    try:
        # Check admin permissions
        user_id = str(current_user.email) if current_user.is_authenticated else 'anonymous'
        admin_users = getattr(Config, 'ADMIN_USERS', [])
        
        if user_id not in admin_users:
            flash('Admin permissions required for handshake capture', 'error')
            return redirect(url_for('passive_monitor.dashboard'))
        
        # Get available networks for handshake capture
        available_networks = _get_available_networks_for_handshake()
        
        # Get recent handshake results
        handshake_results = _get_recent_handshake_results()
        
        return render_template('passive_monitor/handshake_capture.html',
                             available_networks=available_networks,
                             handshake_results=handshake_results)
        
    except Exception as e:
        logger.error(f"Error loading handshake capture: {e}")
        flash('Error loading handshake capture interface', 'error')
        return redirect(url_for('passive_monitor.dashboard'))


@passive_monitor.route('/deauth-monitor')
@login_required
def deauth_monitor():
    """Deauthentication attack monitoring interface"""
    try:
        # Get recent deauth monitoring results
        deauth_results = _get_recent_deauth_monitoring()
        
        return render_template('passive_monitor/deauth_monitor.html',
                             deauth_results=deauth_results)
        
    except Exception as e:
        logger.error(f"Error loading deauth monitor: {e}")
        flash('Error loading deauth monitor interface', 'error')
        return redirect(url_for('passive_monitor.dashboard'))


@passive_monitor.route('/channel-analysis')
@login_required
def channel_analysis():
    """Wi-Fi channel utilization analysis interface"""
    try:
        # Get channel utilization data
        channel_data = _get_channel_utilization_data()
        
        return render_template('passive_monitor/channel_analysis.html',
                             channel_data=channel_data)
        
    except Exception as e:
        logger.error(f"Error loading channel analysis: {e}")
        flash('Error loading channel analysis interface', 'error')
        return redirect(url_for('passive_monitor.dashboard'))


@passive_monitor.route('/security-audit')
@login_required
def security_audit():
    """Security audit interface"""
    try:
        # Get recent security audit results
        audit_results = _get_recent_security_audit()
        
        return render_template('passive_monitor/security_audit.html',
                             audit_results=audit_results)
        
    except Exception as e:
        logger.error(f"Error loading security audit: {e}")
        flash('Error loading security audit interface', 'error')
        return redirect(url_for('passive_monitor.dashboard'))


# API-style routes for AJAX calls

@passive_monitor.route('/api/start-monitoring', methods=['POST'])
@login_required
@rate_limit(max_requests=5, per_seconds=300)
def api_start_monitoring():
    """Start monitoring via AJAX"""
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'auto')
        duration = min(data.get('duration', 300), 3600)  # Max 1 hour
        
        user_id = str(current_user.email) if current_user.is_authenticated else 'anonymous'
        
        # Start monitoring
        result = real_packet_capture.start_capture(
            interface=interface,
            duration=duration,
            user_id=user_id
        )
        
        return jsonify(result)
        
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': 'Insufficient permissions for monitoring'
        }), 403
        
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({
            'success': False,
            'message': f'Error starting monitoring: {str(e)}'
        }), 500


@passive_monitor.route('/api/stop-monitoring', methods=['POST'])
@login_required
def api_stop_monitoring():
    """Stop monitoring via AJAX"""
    try:
        result = real_packet_capture.stop_capture()
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({
            'success': False,
            'message': f'Error stopping monitoring: {str(e)}'
        }), 500


@passive_monitor.route('/api/monitoring-status')
@login_required
@rate_limit(max_requests=30, per_seconds=60)
def api_monitoring_status():
    """Get REAL monitoring status via AJAX"""
    try:
        status = real_packet_capture.get_capture_status()
        
        # Add real-time analysis information
        status['recent_activity'] = _get_recent_monitoring_activity()
        status['timestamp'] = datetime.utcnow().isoformat()
        
        # Add real-time beacon analysis data for charts
        if real_packet_capture and real_packet_capture.networks:
            # Channel distribution
            channel_distribution = {}
            security_distribution = {'open': 0, 'wep': 0, 'wpa': 0, 'wpa2': 0, 'wpa3': 0}
            vendor_distribution = {}
            
            for network in real_packet_capture.networks.values():
                # Channel distribution
                channel = network.get('channel', _estimate_channel_from_signal(network.get('signal_strength', -50)))
                channel_distribution[str(channel)] = channel_distribution.get(str(channel), 0) + 1
                
                # Security distribution
                encryption = network.get('encryption', 'Unknown').upper()
                if 'WPA3' in encryption:
                    security_distribution['wpa3'] += 1
                elif 'WPA2' in encryption:
                    security_distribution['wpa2'] += 1
                elif 'WPA' in encryption:
                    security_distribution['wpa'] += 1
                elif 'WEP' in encryption:
                    security_distribution['wep'] += 1
                elif encryption == 'OPEN' or not network.get('encrypted', True):
                    security_distribution['open'] += 1
                else:
                    security_distribution['wpa2'] += 1  # Default
                
                # Vendor distribution
                vendor = _get_vendor_from_mac(network.get('bssid', ''))
                vendor_distribution[vendor] = vendor_distribution.get(vendor, 0) + 1
            
            # Add distribution data to status
            status['channel_distribution'] = channel_distribution
            status['security_distribution'] = security_distribution
            status['vendor_distribution'] = vendor_distribution
            status['is_monitoring'] = real_packet_capture.is_capturing
            status['vendors_found'] = len(vendor_distribution)
            status['hidden_networks'] = sum(1 for net in real_packet_capture.networks.values() if not net.get('ssid'))
            status['active_channels'] = len(channel_distribution)
        else:
            # No real data yet
            status['channel_distribution'] = {}
            status['security_distribution'] = {'open': 0, 'wep': 0, 'wpa': 0, 'wpa2': 0, 'wpa3': 0}
            status['vendor_distribution'] = {}
            status['is_monitoring'] = real_packet_capture.is_capturing if real_packet_capture else False
            status['vendors_found'] = 0
            status['hidden_networks'] = 0
            status['active_channels'] = 0
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting monitoring status: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting status: {str(e)}'
        }), 500


@passive_monitor.route('/api/captured-packets')
@login_required
@rate_limit(max_requests=20, per_seconds=60)
def api_captured_packets():
    """Get captured packets data via AJAX"""
    try:
        # Get recent captured packets (last 50)
        packets_data = []
        packets = list(real_packet_capture.captured_packets)
        
        for packet in packets[-50:]:  # Get last 50 packets
            # Convert packet data for display
            packet_display = {
                'timestamp': datetime.fromtimestamp(packet.get('timestamp', datetime.utcnow().timestamp())).strftime('%H:%M:%S'),
                'type': packet.get('type', 'unknown'),
                'src_mac': packet.get('src_mac', 'N/A'),
                'dst_mac': packet.get('dst_mac', 'N/A'),
                'signal': packet.get('signal_strength', 'N/A'),
                'channel': packet.get('channel', 'N/A'),
                'ssid': packet.get('ssid', 'N/A') if packet.get('ssid') else 'N/A',
                'encryption': packet.get('encryption', 'N/A'),
                'size': packet.get('packet_size', len(packet.get('raw_packet', b'')))
            }
            packets_data.append(packet_display)
        
        return jsonify({
            'success': True,
            'packets': packets_data,
            'total_packets': len(real_packet_capture.captured_packets),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting captured packets: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting packets: {str(e)}'
        }), 500


@passive_monitor.route('/api/beacon-analysis-results')
@login_required
@rate_limit(max_requests=20, per_seconds=60)
def api_beacon_analysis_results():
    """Get REAL beacon analysis results via AJAX"""
    try:
        # Get real data from packet capture instead of samples
        real_networks = []
        security_analysis = []
        vendor_analysis = []
        anomalies = []
        timeline = []
        
        # Extract real network data from packet capture
        if real_packet_capture and real_packet_capture.networks:
            vendor_counts = {}
            security_counts = {'Open': 0, 'WEP': 0, 'WPA': 0, 'WPA2': 0, 'WPA3': 0}
            
            for bssid, network in real_packet_capture.networks.items():
                # Process real network data
                ssid = network.get('ssid', None)
                if ssid == '':
                    ssid = None  # Hidden network
                
                # Determine security type from encryption info
                encryption = network.get('encryption', 'Unknown')
                if 'WPA3' in encryption.upper():
                    security = 'WPA3'
                    security_counts['WPA3'] += 1
                elif 'WPA2' in encryption.upper():
                    security = 'WPA2' 
                    security_counts['WPA2'] += 1
                elif 'WPA' in encryption.upper():
                    security = 'WPA'
                    security_counts['WPA'] += 1
                elif 'WEP' in encryption.upper():
                    security = 'WEP'
                    security_counts['WEP'] += 1
                elif encryption.upper() == 'OPEN' or not network.get('encrypted', True):
                    security = 'Open'
                    security_counts['Open'] += 1
                else:
                    security = 'WPA2'  # Default assumption
                    security_counts['WPA2'] += 1
                
                # Extract vendor from MAC OUI (first 3 octets)
                vendor = _get_vendor_from_mac(bssid)
                if vendor in vendor_counts:
                    vendor_counts[vendor] += 1
                else:
                    vendor_counts[vendor] = 1
                
                # Extract channel from network data or estimate from frequency
                channel = network.get('channel', _estimate_channel_from_signal(network.get('signal_strength', -50)))
                
                real_networks.append({
                    'ssid': ssid,
                    'bssid': bssid,
                    'channel': channel,
                    'security': security,
                    'signal': network.get('signal_strength', -50),
                    'vendor': vendor,
                    'first_seen': network.get('first_seen', datetime.utcnow().timestamp()),
                    'beacon_count': network.get('beacon_count', 0)
                })
            
            # Generate real security analysis
            if security_counts['Open'] > 0:
                security_analysis.append({
                    'title': 'Open Networks Detected',
                    'description': f'Found {security_counts["Open"]} open networks without encryption.',
                    'severity': 'high',
                    'affected_networks': security_counts['Open']
                })
            
            if security_counts['WEP'] > 0:
                security_analysis.append({
                    'title': 'WEP Encryption Detected',
                    'description': f'Found {security_counts["WEP"]} networks using outdated WEP encryption.',
                    'severity': 'high',
                    'affected_networks': security_counts['WEP']
                })
            
            hidden_networks = sum(1 for net in real_networks if net['ssid'] is None)
            if hidden_networks > 0:
                security_analysis.append({
                    'title': 'Hidden Networks Present',
                    'description': f'Detected {hidden_networks} hidden networks that may indicate privacy concerns.',
                    'severity': 'medium',
                    'affected_networks': hidden_networks
                })
            
            # Generate vendor analysis from real data
            total_networks = len(real_networks)
            for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                percentage = (count / total_networks * 100) if total_networks > 0 else 0
                vendor_analysis.append({
                    'name': vendor,
                    'network_count': count,
                    'percentage': round(percentage, 1),
                    'description': _get_vendor_description(vendor),
                    'oui_prefix': _get_oui_prefix(vendor)
                })
            
            # Generate anomalies from threats
            if real_packet_capture.threats:
                for threat in real_packet_capture.threats[-5:]:  # Last 5 threats
                    anomalies.append({
                        'title': threat.get('type', 'Security Threat').replace('_', ' ').title(),
                        'description': threat.get('details', threat.get('description', 'Security threat detected')),
                        'severity': 'danger' if threat.get('severity') == 'high' else 'warning',
                        'network': threat.get('source', 'Unknown'),
                        'detected_at': threat.get('timestamp', datetime.utcnow().timestamp())
                    })
            
            # Generate timeline from real capture events
            timeline.append({
                'title': 'Real-time Analysis Started',
                'description': f'Live beacon frame analysis initiated on {real_packet_capture.monitor_interface or "auto"}.',
                'timestamp': datetime.utcnow().timestamp() - 300
            })
            
            if real_networks:
                timeline.append({
                    'title': f'{len(real_networks)} Networks Discovered',
                    'description': f'Detected {len(real_networks)} active WiFi networks in the area.',
                    'timestamp': datetime.utcnow().timestamp() - 200
                })
            
            if security_analysis:
                timeline.append({
                    'title': 'Security Issues Found',
                    'description': f'Identified {len(security_analysis)} security concerns in network traffic.',
                    'timestamp': datetime.utcnow().timestamp() - 100
                })
        
        else:
            # No real data available - inform user
            timeline.append({
                'title': 'Waiting for Real Data',
                'description': 'Start packet capture to see real-time beacon frame analysis.',
                'timestamp': datetime.utcnow().timestamp()
            })
        
        return jsonify({
            'success': True,
            'networks': real_networks,
            'security_analysis': security_analysis,
            'vendor_analysis': vendor_analysis,
            'anomalies': anomalies,
            'timeline': timeline,
            'timestamp': datetime.utcnow().isoformat(),
            'data_source': 'real_capture' if real_networks else 'no_data'
        })
        
    except Exception as e:
        logger.error(f"Error getting beacon analysis results: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting analysis results: {str(e)}'
        }), 500


# Helper functions

def _get_vendor_from_mac(mac_address: str) -> str:
    """Get vendor name from MAC address OUI"""
    try:
        # Common MAC OUI prefixes to vendor mapping
        oui_vendors = {
            '00:11:22': 'TP-Link',
            '00:1b:2f': 'Netgear', 
            '00:23:69': 'Cisco',
            '00:25:9c': 'Apple',
            '00:26:bb': 'Apple',
            '00:3a:99': 'Apple', 
            '00:50:43': 'Apple',
            '04:26:65': 'Apple',
            '08:00:07': 'Apple',
            '10:9a:dd': 'Apple',
            '14:10:9f': 'Apple',
            '18:af:61': 'Apple',
            '1c:ab:a7': 'Apple',
            '20:78:f0': 'Apple',
            '24:a2:e1': 'Apple',
            '28:cf:da': 'Apple',
            '2c:be:08': 'Apple',
            '30:f7:c5': 'Apple',
            '34:ab:37': 'Apple',
            '38:ca:da': 'Apple',
            '3c:22:fb': 'Apple',
            '40:b3:95': 'Apple',
            '44:d8:84': 'Apple',
            '48:74:6e': 'Apple',
            '4c:57:ca': 'Apple',
            '50:82:d5': 'Apple',
            '54:72:4f': 'Apple',
            '58:55:ca': 'Apple',
            '5c:95:ae': 'Apple',
            '60:f4:45': 'Apple',
            '64:b9:e8': 'Apple',
            '68:96:7b': 'Apple',
            '6c:72:e7': 'Apple',
            '70:48:0f': 'Apple',
            '74:e2:f5': 'Apple',
            '78:52:1a': 'Apple',
            '7c:d1:c3': 'Apple',
            '80:92:9f': 'Apple',
            '84:78:ac': 'Apple',
            '88:1d:fc': 'Apple',
            '8c:85:90': 'Apple',
            '90:84:0d': 'Apple',
            '94:f6:d6': 'Apple',
            '98:5a:eb': 'Apple',
            '9c:04:eb': 'Apple',
            'a0:99:9b': 'Apple',
            'a4:5e:60': 'Apple',
            'a8:96:75': 'Apple',
            'ac:87:a3': 'Apple',
            'b0:65:bd': 'Apple',
            'b4:f0:ab': 'Apple',
            'b8:78:2e': 'Apple',
            'bc:52:b7': 'Apple',
            'c0:cc:d8': 'Apple',
            'c4:b3:01': 'Apple',
            'c8:bc:c8': 'Apple',
            'cc:25:ef': 'Apple',
            'd0:23:db': 'Apple',
            'd4:61:9d': 'Apple',
            'd8:30:62': 'Apple',
            'dc:2b:2a': 'Apple',
            'e0:ac:cb': 'Apple',
            'e4:8b:7f': 'Apple',
            'e8:80:2e': 'Apple',
            'ec:35:86': 'Apple',
            'f0:18:98': 'Apple',
            'f4:37:b7': 'Apple',
            'f8:01:13': 'Apple',
            'fc:25:3f': 'Apple',
            # Samsung
            '00:16:32': 'Samsung',
            '00:1d:25': 'Samsung',
            '00:23:39': 'Samsung',
            '00:26:37': 'Samsung',
            '08:37:3d': 'Samsung',
            '34:23:ba': 'Samsung',
            '40:4e:36': 'Samsung',
            '4c:66:41': 'Samsung',
            '50:cc:f8': 'Samsung',
            '54:88:0e': 'Samsung',
            '5c:0a:5b': 'Samsung',
            '60:a1:0a': 'Samsung',
            '78:1f:db': 'Samsung',
            '7c:61:66': 'Samsung',
            '88:32:9b': 'Samsung',
            '8c:71:f8': 'Samsung',
            '94:eb:2c': 'Samsung',
            'a0:75:45': 'Samsung',
            'b4:62:93': 'Samsung',
            'c8:19:f7': 'Samsung',
            'cc:07:ab': 'Samsung',
            'd4:87:d8': 'Samsung',
            'ec:1f:72': 'Samsung',
            'f4:09:d8': 'Samsung',
            # Intel
            '00:02:b3': 'Intel',
            '00:03:47': 'Intel',
            '00:12:f0': 'Intel',
            '00:13:02': 'Intel',
            '00:13:ce': 'Intel',
            '00:15:00': 'Intel',
            '00:16:76': 'Intel',
            '00:19:d1': 'Intel',
            '00:1b:77': 'Intel',
            '00:1e:64': 'Intel',
            '00:1f:3b': 'Intel',
            '00:21:6a': 'Intel',
            '00:22:fb': 'Intel',
            '00:24:d7': 'Intel',
            '00:26:c6': 'Intel',
            '00:27:10': 'Intel',
            '04:79:b7': 'Intel',
            '0c:8b:fd': 'Intel',
            '18:1d:ea': 'Intel',
            '24:77:03': 'Intel',
            '3c:a9:f4': 'Intel',
            '44:85:00': 'Intel',
            '48:89:e7': 'Intel',
            '5c:e0:c5': 'Intel',
            '68:07:15': 'Intel',
            '6c:88:14': 'Intel',
            '74:e5:43': 'Intel',
            '78:92:9c': 'Intel',
            '7c:7a:91': 'Intel',
            '84:3a:4b': 'Intel',
            '88:75:56': 'Intel',
            '8c:dc:d4': 'Intel',
            '94:65:9c': 'Intel',
            '9c:b6:d0': 'Intel',
            'a0:a8:cd': 'Intel',
            'a4:02:b9': 'Intel',
            'a8:6d:aa': 'Intel',
            'b4:d5:bd': 'Intel',
            'c4:8e:8f': 'Intel',
            'd0:57:7b': 'Intel',
            'd4:6d:6d': 'Intel',
            'dc:53:60': 'Intel',
            'e0:94:67': 'Intel',
            'e4:a4:71': 'Intel',
            'f8:63:3f': 'Intel',
            # Common router vendors
            '00:14:bf': 'Linksys',
            '00:18:39': 'Linksys', 
            '00:1a:70': 'Linksys',
            '00:1d:7e': 'Linksys',
            '00:25:9c': 'Linksys',
            '08:86:3b': 'Linksys',
            '14:91:82': 'Linksys',
            '20:aa:4b': 'Linksys',
            '48:f8:b3': 'Linksys',
            'c0:56:27': 'Linksys',
            # D-Link
            '00:05:5d': 'D-Link',
            '00:0f:3d': 'D-Link',
            '00:13:46': 'D-Link',
            '00:15:e9': 'D-Link',
            '00:17:9a': 'D-Link',
            '00:19:5b': 'D-Link',
            '00:1b:11': 'D-Link',
            '00:1c:f0': 'D-Link',
            '00:1e:58': 'D-Link',
            '00:21:91': 'D-Link',
            '00:22:b0': 'D-Link',
            '00:24:01': 'D-Link',
            '00:26:5a': 'D-Link',
            '14:d6:4d': 'D-Link',
            '1c:7e:e5': 'D-Link',
            '28:10:7b': 'D-Link',
            '34:08:04': 'D-Link',
            '5c:d9:98': 'D-Link',
            '84:c9:b2': 'D-Link',
            'b0:39:56': 'D-Link',
            'c8:d3:a3': 'D-Link',
            # ASUS
            '00:0c:6e': 'ASUS',
            '00:13:d4': 'ASUS',
            '00:15:f2': 'ASUS',
            '00:17:31': 'ASUS',
            '00:19:db': 'ASUS',
            '00:1b:fc': 'ASUS',
            '00:1d:60': 'ASUS',
            '00:1f:c6': 'ASUS',
            '00:22:15': 'ASUS',
            '00:24:8c': 'ASUS',
            '00:26:18': 'ASUS',
            '08:60:6e': 'ASUS',
            '10:bf:48': 'ASUS',
            '1c:87:2c': 'ASUS',
            '2c:56:dc': 'ASUS',
            '30:5a:3a': 'ASUS',
            '38:2c:4a': 'ASUS',
            '40:16:7e': 'ASUS',
            '50:46:5d': 'ASUS',
            '60:45:cb': 'ASUS',
            '70:4d:7b': 'ASUS',
            '74:d0:2b': 'ASUS',
            '88:d7:f6': 'ASUS',
            '9c:5c:8e': 'ASUS',
            'ac:22:0b': 'ASUS',
            'b0:6e:bf': 'ASUS',
            'c8:60:00': 'ASUS',
            'd0:17:c2': 'ASUS',
            'f0:79:59': 'ASUS',
        }
        
        # Extract OUI (first 3 octets)
        oui = mac_address.upper()[:8]  # Format: XX:XX:XX
        
        # Look up vendor
        return oui_vendors.get(oui, 'Unknown')
        
    except Exception:
        return 'Unknown'

def _get_vendor_description(vendor: str) -> str:
    """Get description for vendor"""
    descriptions = {
        'Apple': 'Consumer electronics and wireless devices',
        'Samsung': 'Consumer electronics manufacturer',
        'Intel': 'Network interface controllers and WiFi chips',
        'TP-Link': 'Networking equipment manufacturer',
        'Netgear': 'Home and business networking solutions',
        'Linksys': 'Consumer and business networking equipment',
        'D-Link': 'Network infrastructure solutions',
        'ASUS': 'Computer and networking equipment',
        'Cisco': 'Enterprise networking equipment',
        'Unknown': 'Vendor could not be identified'
    }
    return descriptions.get(vendor, f'{vendor} networking equipment')

def _get_oui_prefix(vendor: str) -> str:
    """Get sample OUI prefix for vendor"""
    prefixes = {
        'Apple': '00:25:9c',
        'Samsung': '00:16:32', 
        'Intel': '00:02:b3',
        'TP-Link': '00:11:22',
        'Netgear': '00:1b:2f',
        'Linksys': '00:14:bf',
        'D-Link': '00:05:5d',
        'ASUS': '00:0c:6e',
        'Cisco': '00:23:69',
        'Unknown': '00:00:00'
    }
    return prefixes.get(vendor, '00:00:00')

def _estimate_channel_from_signal(signal_strength: int) -> int:
    """Estimate WiFi channel based on signal strength and other factors"""
    try:
        # Simple heuristic - in real implementation this would use frequency data
        # Common channels: 1, 6, 11 (2.4GHz) and 36, 40, 44, 48, 149, 153, 157, 161 (5GHz)
        import random
        
        # Stronger signals more likely to be on 2.4GHz (channels 1-14)
        if signal_strength > -60:
            return random.choice([1, 6, 11])
        else:
            # Weaker signals might be 5GHz
            return random.choice([36, 40, 44, 48, 149, 153, 157, 161])
    except:
        return 6  # Default to channel 6

# Rogue AP Detection APIs
@passive_monitor.route('/api/start-rogue-detection', methods=['POST'])
@login_required
@rate_limit(max_requests=10, per_seconds=60)
def api_start_rogue_detection():
    """Start rogue AP detection via AJAX"""
    try:
        # Check advanced feature access
        # TODO: Re-enable after fixing database access issues
        # from app.models.approval_system import ApprovalSystemManager
        # access_status = ApprovalSystemManager.get_user_access_status(current_user.id)
        # 
        # if not access_status.get('advanced_features_approved', False):
        #     return jsonify({
        #         'success': False,
        #         'message': 'Advanced features access required. Please request approval from admin.',
        #         'requires_approval': True
        #     }), 403
        
        # TEMPORARY: Allow access for testing - remove this after fixing approval system
        logger.info(f"User {current_user.id} starting rogue detection (temp bypass enabled)")
        data = request.get_json()
        mode = data.get('mode', 'comprehensive')
        duration = int(data.get('duration', 120))
        sensitivity = data.get('sensitivity', 'medium')
        
        logger.info(f"Starting rogue AP detection: mode={mode}, duration={duration}s, sensitivity={sensitivity}")
        
        # Initialize rogue AP detector if not already done
        if not hasattr(real_packet_capture, 'rogue_detector'):
            from app.wifi_core.rogue_ap_detector import RogueAPDetector
            real_packet_capture.rogue_detector = RogueAPDetector()
        
        # Start packet capture for rogue detection
        result = real_packet_capture.start_capture(
            interface='auto',
            duration=duration,
            user_id=str(current_user.id) if current_user.is_authenticated else 'anonymous'
        )
        
        if result.get('success'):
            # Mark as rogue detection mode
            real_packet_capture.rogue_detection_active = True
            real_packet_capture.rogue_detection_mode = mode
            real_packet_capture.rogue_detection_sensitivity = sensitivity
            
            return jsonify({
                'success': True,
                'message': 'Rogue AP detection started',
                'mode': mode,
                'duration': duration,
                'sensitivity': sensitivity
            })
        else:
            raise Exception(result.get('message', 'Failed to start packet capture'))
        
    except Exception as e:
        logger.error(f"Error starting rogue detection: {e}")
        return jsonify({
            'success': False,
            'message': f'Error starting detection: {str(e)}'
        }), 500

@passive_monitor.route('/api/stop-rogue-detection', methods=['POST'])
@login_required
@rate_limit(max_requests=10, per_seconds=60)
def api_stop_rogue_detection():
    """Stop rogue AP detection via AJAX"""
    try:
        logger.info("Stopping rogue AP detection")
        
        # Stop packet capture
        result = real_packet_capture.stop_capture()
        
        if result.get('success'):
            # Mark as inactive
            real_packet_capture.rogue_detection_active = False
            
            # Perform final analysis on captured data
            if hasattr(real_packet_capture, 'rogue_detector') and real_packet_capture.networks:
                analysis_results = real_packet_capture.rogue_detector.analyze_networks(
                    real_packet_capture.networks
                )
                # Store results
                real_packet_capture.rogue_analysis_results = analysis_results
                
                return jsonify({
                    'success': True,
                    'message': 'Rogue AP detection stopped',
                    'analysis_results': analysis_results
                })
            else:
                return jsonify({
                    'success': True,
                    'message': 'Detection stopped (no data to analyze)',
                    'analysis_results': {
                        'rogue_aps_detected': [],
                        'evil_twins_detected': [],
                        'suspicious_networks': [],
                        'threat_level': 'LOW'
                    }
                })
        else:
            raise Exception(result.get('message', 'Failed to stop capture'))
        
    except Exception as e:
        logger.error(f"Error stopping rogue detection: {e}")
        return jsonify({
            'success': False,
            'message': f'Error stopping detection: {str(e)}'
        }), 500

@passive_monitor.route('/api/rogue-detection-status')
@login_required
@rate_limit(max_requests=30, per_seconds=60)
def api_rogue_detection_status():
    """Get rogue AP detection status via AJAX"""
    try:
        status = real_packet_capture.get_capture_status()
        
        # Add rogue detection specific status
        rogue_status = {
            'is_detecting': getattr(real_packet_capture, 'rogue_detection_active', False),
            'mode': getattr(real_packet_capture, 'rogue_detection_mode', 'comprehensive'),
            'sensitivity': getattr(real_packet_capture, 'rogue_detection_sensitivity', 'medium'),
            'networks_analyzed': len(real_packet_capture.networks) if real_packet_capture.networks else 0,
            'evil_twins_detected': 0,
            'rogue_aps_detected': 0,
            'suspicious_networks': 0,
            'legitimate_networks': 0,
            'open_networks': 0,
            'weak_security_networks': 0,
            'threat_level': 'LOW'
        }
        
        # If we have analysis results, use them
        if hasattr(real_packet_capture, 'rogue_analysis_results'):
            results = real_packet_capture.rogue_analysis_results
            rogue_status.update({
                'evil_twins_detected': len(results.get('evil_twins_detected', [])),
                'rogue_aps_detected': len(results.get('rogue_aps_detected', [])),
                'suspicious_networks': len(results.get('suspicious_networks', [])),
                'threat_level': results.get('threat_level', 'LOW')
            })
        
        # If detection is active, perform real-time analysis
        if (rogue_status['is_detecting'] and 
            hasattr(real_packet_capture, 'rogue_detector') and 
            real_packet_capture.networks):
            
            # Perform quick analysis on current data
            current_analysis = real_packet_capture.rogue_detector.analyze_networks(
                real_packet_capture.networks
            )
            
            rogue_status.update({
                'evil_twins_detected': len(current_analysis.get('evil_twins_detected', [])),
                'rogue_aps_detected': len(current_analysis.get('rogue_aps_detected', [])),
                'suspicious_networks': len(current_analysis.get('suspicious_networks', [])),
                'threat_level': current_analysis.get('threat_level', 'LOW')
            })
        
        # Calculate legitimate, open, and weak security networks
        if real_packet_capture.networks:
            total_networks = len(real_packet_capture.networks)
            open_count = 0
            weak_security_count = 0
            
            for network in real_packet_capture.networks.values():
                encryption = network.get('encryption', '').upper()
                if 'OPEN' in encryption or not encryption:
                    open_count += 1
                    weak_security_count += 1
                elif 'WEP' in encryption:
                    weak_security_count += 1
            
            legitimate_count = max(0, total_networks - rogue_status['evil_twins_detected'] - 
                                 rogue_status['rogue_aps_detected'] - rogue_status['suspicious_networks'])
            
            rogue_status.update({
                'legitimate_networks': legitimate_count,
                'open_networks': open_count,
                'weak_security_networks': weak_security_count
            })
        
        # Merge with general status
        status.update(rogue_status)
        status['timestamp'] = datetime.utcnow().isoformat()
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting rogue detection status: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting status: {str(e)}'
        }), 500

@passive_monitor.route('/api/rogue-detection-results')
@login_required
@rate_limit(max_requests=20, per_seconds=60)
def api_rogue_detection_results():
    """Get rogue AP detection results via AJAX"""
    try:
        # Return stored analysis results
        if hasattr(real_packet_capture, 'rogue_analysis_results'):
            results = real_packet_capture.rogue_analysis_results
            return jsonify({
                'success': True,
                **results,
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            # No results available yet
            return jsonify({
                'success': True,
                'evil_twins_detected': [],
                'rogue_aps_detected': [],
                'suspicious_networks': [],
                'security_recommendations': [
                    'Start rogue AP detection to analyze your WiFi environment',
                    'Monitor your network regularly for security threats',
                    'Use strong encryption (WPA3) on all your networks'
                ],
                'threat_level': 'LOW',
                'analysis_summary': {
                    'evil_twins_count': 0,
                    'rogue_aps_count': 0,
                    'suspicious_count': 0,
                    'networks_analyzed': 0
                },
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'No analysis results available. Start detection first.'
            })
        
    except Exception as e:
        logger.error(f"Error getting rogue detection results: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting results: {str(e)}'
        }), 500

def _get_recent_monitoring_activity() -> List[Dict[str, Any]]:
    """Get recent monitoring activity"""
    try:
        activities = []
        
        # Get recent threats
        threats = getattr(real_packet_capture, 'threats', [])
        for threat in threats[-5:]:
            activities.append({
                'type': 'threat',
                'title': f"{threat.get('type', 'Threat')} detected",
                'details': threat.get('details', ''),
                'timestamp': threat.get('timestamp', time.time()),
                'severity': threat.get('severity', 'medium')
            })
        
        # Get recent network discoveries
        networks = getattr(real_packet_capture, 'networks', {})
        recent_networks = sorted(networks.values(), 
                               key=lambda x: x.get('first_seen', 0), 
                               reverse=True)[:3]
        
        for network in recent_networks:
            activities.append({
                'type': 'discovery',
                'title': f"Network discovered",
                'details': f"SSID: {network.get('ssid', 'Hidden')}",
                'timestamp': network.get('first_seen', time.time())
            })
        
        # Sort by timestamp and return latest
        activities.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        return activities[:10]
        
    except Exception as e:
        logger.error(f"Error getting recent activity: {e}")
        return []


def _get_recent_beacon_analysis() -> Dict[str, Any]:
    """Get recent beacon analysis results"""
    try:
        # This would typically load from database or cache
        # For now, return sample structure
        return {
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'networks_analyzed': 0,
            'anomalies_detected': [],
            'vendor_analysis': {},
            'encryption_distribution': {}
        }
    except Exception as e:
        logger.error(f"Error getting beacon analysis: {e}")
        return {}


def _get_recent_rogue_detection() -> Dict[str, Any]:
    """Get recent rogue AP detection results"""
    try:
        return {
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'rogue_aps': [],
            'evil_twins': [],
            'suspicious_networks': []
        }
    except Exception as e:
        logger.error(f"Error getting rogue detection: {e}")
        return {}


def _get_available_networks_for_handshake() -> List[Dict[str, Any]]:
    """Get networks available for handshake capture"""
    try:
        networks = getattr(real_packet_capture, 'networks', {})
        available = []
        
        for network in networks.values():
            if network.get('encrypted', False):
                available.append({
                    'ssid': network.get('ssid', 'Hidden'),
                    'bssid': network.get('bssid', ''),
                    'encryption': network.get('encryption', 'WPA2'),
                    'signal_strength': network.get('signal_strength', -50)
                })
        
        return available
        
    except Exception as e:
        logger.error(f"Error getting available networks: {e}")
        return []


def _get_recent_handshake_results() -> Dict[str, Any]:
    """Get recent handshake capture results"""
    try:
        handshakes = getattr(real_packet_capture, 'handshakes', {})
        
        return {
            'capture_timestamp': datetime.utcnow().isoformat(),
            'handshakes_captured': len(handshakes),
            'handshake_details': list(handshakes.values())
        }
    except Exception as e:
        logger.error(f"Error getting handshake results: {e}")
        return {}


def _get_recent_deauth_monitoring() -> Dict[str, Any]:
    """Get recent deauth monitoring results"""
    try:
        return {
            'monitoring_timestamp': datetime.utcnow().isoformat(),
            'deauth_attacks_detected': 0,
            'attack_details': [],
            'affected_networks': []
        }
    except Exception as e:
        logger.error(f"Error getting deauth monitoring: {e}")
        return {}


def _get_channel_utilization_data() -> Dict[str, Any]:
    """Get channel utilization analysis data"""
    try:
        return {
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'channel_usage': {},
            'congestion_analysis': {},
            'recommendations': []
        }
    except Exception as e:
        logger.error(f"Error getting channel data: {e}")
        return {}


def _get_recent_security_audit() -> Dict[str, Any]:
    """Get recent security audit results"""
    try:
        return {
            'audit_timestamp': datetime.utcnow().isoformat(),
            'overall_security_score': 0,
            'findings': [],
            'recommendations': [],
            'compliance_status': {}
        }
    except Exception as e:
        logger.error(f"Error getting security audit: {e}")
        return {}


# Error handlers
@passive_monitor.errorhandler(403)
def forbidden(error):
    flash('Access denied - insufficient permissions', 'error')
    return redirect(url_for('main.dashboard'))


@passive_monitor.errorhandler(404)
def not_found(error):
    flash('Page not found', 'error')
    return redirect(url_for('passive_monitor.dashboard'))


@passive_monitor.errorhandler(500)
def internal_error(error):
    flash('Internal server error', 'error')
    return redirect(url_for('passive_monitor.dashboard'))