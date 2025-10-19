"""
Passive Monitoring API Endpoints
Purpose: API endpoints for real-time Wi-Fi passive monitoring and analysis
Security: Lab-only activation with admin permission checks and audit logging
"""

import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user

# Import core modules with fallback to simple version
try:
    from app.wifi_core.passive_scanner import (
        PassiveScanner, HandshakeCapture, BeaconAnalyzer, 
        RogueAPDetector, SecurityAuditor, monitor_deauth_attacks,
        analyze_probe_requests, detect_evil_twins
    )
except ImportError:
    try:
        # Fallback to simple version
        from app.wifi_core.passive_scanner_simple import (
            PassiveScanner, HandshakeCapture, BeaconAnalyzer, 
            RogueAPDetector, SecurityAuditor, monitor_deauth_attacks,
            analyze_probe_requests, detect_evil_twins
        )
    except ImportError:
        # Final fallback with minimal functionality
        from app.wifi_core.passive_scanner_simple import (
            PassiveScanner, HandshakeCapture, BeaconAnalyzer, 
            RogueAPDetector, SecurityAuditor, monitor_deauth_attacks,
            analyze_probe_requests, detect_evil_twins
        )
try:
    from app.wifi_core.real_packet_capture import RealPacketCapture
except ImportError:
    # Fallback class for real packet capture
    class RealPacketCapture:
        def get_available_interfaces(self):
            return [{"name": "fallback", "type": "virtual", "status": "unavailable"}]
        def get_capture_status(self):
            return {"is_capturing": False, "packets_captured": 0, "networks_detected": 0, "devices_found": 0, "threats_detected": 0, "packet_stats": {}}
        def start_capture(self, *args, **kwargs):
            return {"success": False, "message": "Real packet capture not available - install required dependencies"}
        def stop_capture(self):
            return {"success": False, "message": "Packet capture not available"}

try:
    from app.models.audit_logs import AuditLog
except ImportError:
    class AuditLog:
        @staticmethod
        def log_event(*args, **kwargs):
            pass

try:
    from app.utils.decorators import rate_limit, log_activity, validate_json
except ImportError:
    def rate_limit(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def log_activity(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def validate_json(*args, **kwargs):
        def decorator(f):
            return f
        return decorator

try:
    from app.utils.validators import SecurityValidator
except ImportError:
    class SecurityValidator:
        pass

try:
    from config import Config
except ImportError:
    class Config:
        LAB_MODE_ENABLED = False
        ADMIN_USERS = []

# Create blueprint
passive_monitor_api = Blueprint('passive_monitor_api', __name__, url_prefix='/api/passive-monitor')

# Initialize components
passive_scanner = PassiveScanner()
handshake_capture = HandshakeCapture()
beacon_analyzer = BeaconAnalyzer()
rogue_detector = RogueAPDetector()
security_auditor = SecurityAuditor()
real_packet_capture = RealPacketCapture()

logger = logging.getLogger(__name__)


@passive_monitor_api.route('/interfaces', methods=['GET'])
@login_required
@rate_limit(max_requests=10, per_seconds=60)
def get_available_interfaces():
    """Get list of available network interfaces for monitoring"""
    try:
        interfaces = real_packet_capture.get_available_interfaces()
        
        return jsonify({
            'success': True,
            'interfaces': interfaces,
            'scapy_available': hasattr(real_packet_capture, 'SCAPY_AVAILABLE') and real_packet_capture.SCAPY_AVAILABLE
        })
        
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting interfaces: {str(e)}'
        }), 500


@passive_monitor_api.route('/start', methods=['POST'])
@login_required
@rate_limit(max_requests=5, per_seconds=300)  # Limit to 5 starts per 5 minutes
@validate_json
def start_monitoring():
    """Start passive monitoring session"""
    try:
        data = request.get_json()
        
        # Validate input
        interface = data.get('interface', 'auto')
        duration = min(data.get('duration', 300), 3600)  # Max 1 hour
        channel = data.get('channel')
        
        # Security check
        user_id = str(current_user.id) if current_user.is_authenticated else 'anonymous'
        
        # Start real packet capture
        capture_result = real_packet_capture.start_capture(
            interface=interface,
            duration=duration,
            user_id=user_id
        )
        
        if not capture_result.get('success', False):
            raise Exception(capture_result.get('message', 'Failed to start capture'))
        
        # Start passive scanner
        scanner_result = passive_scanner.passive_monitor(
            interface=interface,
            duration=duration,
            user_id=user_id
        )
        
        # Log activity
        AuditLog.log_event(
            user_id=current_user.id if current_user.is_authenticated else None,
            event_type='PASSIVE_MONITORING_START',
            details={
                'interface': interface,
                'duration': duration,
                'channel': channel
            },
            security_level='HIGH'
        )
        
        return jsonify({
            'success': True,
            'message': 'Passive monitoring started',
            'session': {
                'interface': interface,
                'duration': duration,
                'start_time': datetime.utcnow().isoformat(),
                'estimated_completion': (datetime.utcnow() + timedelta(seconds=duration)).isoformat()
            }
        })
        
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': 'Insufficient permissions for passive monitoring',
            'error': str(e)
        }), 403
        
    except Exception as e:
        logger.error(f"Error starting monitoring: {e}")
        return jsonify({
            'success': False,
            'message': f'Error starting monitoring: {str(e)}'
        }), 500


@passive_monitor_api.route('/stop', methods=['POST'])
@login_required
@rate_limit(max_requests=10, per_seconds=60)
def stop_monitoring():
    """Stop passive monitoring session"""
    try:
        # Stop real packet capture
        capture_result = real_packet_capture.stop_capture()
        
        # Log activity
        AuditLog.log_event(
            user_id=current_user.id if current_user.is_authenticated else None,
            event_type='PASSIVE_MONITORING_STOP',
            details=capture_result.get('results', {}),
            security_level='HIGH'
        )
        
        return jsonify({
            'success': True,
            'message': 'Passive monitoring stopped',
            'results': capture_result.get('results', {})
        })
        
    except Exception as e:
        logger.error(f"Error stopping monitoring: {e}")
        return jsonify({
            'success': False,
            'message': f'Error stopping monitoring: {str(e)}'
        }), 500


@passive_monitor_api.route('/status', methods=['GET'])
@login_required
@rate_limit(max_requests=30, per_seconds=60)
def get_monitoring_status():
    """Get current monitoring status and real-time statistics"""
    try:
        # Get capture status
        status = real_packet_capture.get_capture_status()
        
        # Add recent activity
        recent_activity = _generate_recent_activity()
        
        # Add security distribution
        security_distribution = _calculate_security_distribution(status)
        
        return jsonify({
            'success': True,
            'is_monitoring': status['is_capturing'],
            'packets_captured': status['packets_captured'],
            'networks_detected': status['networks_detected'],
            'devices_found': status['devices_found'],
            'threats_detected': status['threats_detected'],
            'packet_stats': status['packet_stats'],
            'recent_activity': recent_activity,
            'security_distribution': security_distribution,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting status: {str(e)}'
        }), 500


@passive_monitor_api.route('/results', methods=['GET'])
@login_required
@rate_limit(max_requests=10, per_seconds=60)
def get_monitoring_results():
    """Get comprehensive monitoring results"""
    try:
        # Get current status (includes results if monitoring is complete)
        status = real_packet_capture.get_capture_status()
        
        # Generate comprehensive analysis
        analysis = _generate_comprehensive_analysis(status)
        
        return jsonify({
            'success': True,
            'results': analysis,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting results: {str(e)}'
        }), 500


@passive_monitor_api.route('/beacon-analysis', methods=['POST'])
@login_required
@rate_limit(max_requests=5, per_seconds=300)
@validate_json
def analyze_beacons():
    """Analyze beacon frames from captured data"""
    try:
        data = request.get_json()
        beacon_data = data.get('beacon_data', [])
        
        # If no data provided, use current capture data
        if not beacon_data:
            status = real_packet_capture.get_capture_status()
            # Extract beacon frames from captured packets
            beacon_data = _extract_beacon_frames()
        
        # Analyze beacon frames
        analysis_results = beacon_analyzer.analyze_beacon_frames(beacon_data)
        
        return jsonify({
            'success': True,
            'analysis': analysis_results,
            'beacon_count': len(beacon_data),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error analyzing beacons: {e}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing beacons: {str(e)}'
        }), 500


@passive_monitor_api.route('/rogue-detection', methods=['POST'])
@login_required
@rate_limit(max_requests=5, per_seconds=300)
@validate_json
def detect_rogue_aps():
    """Detect rogue access points"""
    try:
        data = request.get_json()
        network_data = data.get('network_data', {})
        
        # If no data provided, use current capture data
        if not network_data:
            status = real_packet_capture.get_capture_status()
            network_data = {'networks': getattr(real_packet_capture, 'networks', {})}
        
        # Detect rogue APs
        rogue_aps = rogue_detector.detect_rogue_aps(network_data)
        
        # Detect evil twins
        evil_twins = detect_evil_twins(network_data)
        
        return jsonify({
            'success': True,
            'rogue_aps': rogue_aps,
            'evil_twins': evil_twins,
            'analysis_timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error detecting rogue APs: {e}")
        return jsonify({
            'success': False,
            'message': f'Error detecting rogue APs: {str(e)}'
        }), 500


@passive_monitor_api.route('/handshake-capture', methods=['POST'])
@login_required
@rate_limit(max_requests=3, per_seconds=600)  # Very limited rate for handshake capture
@validate_json
def capture_handshakes():
    """Capture WPA handshakes"""
    try:
        data = request.get_json()
        target_networks = data.get('target_networks', [])
        duration = min(data.get('duration', 600), 1800)  # Max 30 minutes
        
        user_id = str(current_user.id) if current_user.is_authenticated else 'anonymous'
        
        # Capture handshakes
        handshake_results = handshake_capture.capture_handshakes(
            target_networks=target_networks,
            duration=duration,
            user_id=user_id
        )
        
        return jsonify({
            'success': True,
            'handshakes': handshake_results,
            'capture_duration': duration,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except PermissionError as e:
        return jsonify({
            'success': False,
            'message': 'Insufficient permissions for handshake capture',
            'error': str(e)
        }), 403
        
    except Exception as e:
        logger.error(f"Error capturing handshakes: {e}")
        return jsonify({
            'success': False,
            'message': f'Error capturing handshakes: {str(e)}'
        }), 500


@passive_monitor_api.route('/deauth-monitor', methods=['POST'])
@login_required
@rate_limit(max_requests=10, per_seconds=300)
@validate_json
def monitor_deauth_attacks():
    """Monitor for deauthentication attacks"""
    try:
        data = request.get_json()
        threshold = data.get('threshold', 10)
        
        # Get captured packet stream
        packet_stream = _get_captured_packets()
        
        # Monitor deauth attacks
        deauth_attacks = monitor_deauth_attacks(packet_stream, threshold)
        
        return jsonify({
            'success': True,
            'deauth_attacks': deauth_attacks,
            'threshold': threshold,
            'packets_analyzed': len(packet_stream),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error monitoring deauth attacks: {e}")
        return jsonify({
            'success': False,
            'message': f'Error monitoring deauth attacks: {str(e)}'
        }), 500


@passive_monitor_api.route('/probe-analysis', methods=['POST'])
@login_required
@rate_limit(max_requests=10, per_seconds=300)
@validate_json
def analyze_probe_requests():
    """Analyze probe request patterns"""
    try:
        # Get captured packet stream
        packet_stream = _get_captured_packets()
        
        # Analyze probe requests
        probe_analysis = analyze_probe_requests(packet_stream)
        
        return jsonify({
            'success': True,
            'probe_analysis': probe_analysis,
            'packets_analyzed': len(packet_stream),
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error analyzing probe requests: {e}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing probe requests: {str(e)}'
        }), 500


@passive_monitor_api.route('/security-audit', methods=['POST'])
@login_required
@rate_limit(max_requests=3, per_seconds=600)
@validate_json
def perform_security_audit():
    """Perform comprehensive security audit"""
    try:
        data = request.get_json()
        user_id = str(current_user.id) if current_user.is_authenticated else 'anonymous'
        
        # Get scan data from current monitoring session
        scan_data = _get_scan_data_for_audit()
        
        # Perform security audit
        audit_results = security_auditor.audit_wireless_security(scan_data, user_id)
        
        return jsonify({
            'success': True,
            'audit_results': audit_results,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error performing security audit: {e}")
        return jsonify({
            'success': False,
            'message': f'Error performing security audit: {str(e)}'
        }), 500


@passive_monitor_api.route('/channel-analysis', methods=['GET'])
@login_required
@rate_limit(max_requests=10, per_seconds=60)
def analyze_channel_utilization():
    """Analyze Wi-Fi channel utilization"""
    try:
        # Get channel utilization data
        channel_data = _analyze_channel_utilization()
        
        return jsonify({
            'success': True,
            'channel_analysis': channel_data,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error analyzing channels: {e}")
        return jsonify({
            'success': False,
            'message': f'Error analyzing channels: {str(e)}'
        }), 500


@passive_monitor_api.route('/recent-activity', methods=['GET'])
@login_required
@rate_limit(max_requests=30, per_seconds=60)
def get_recent_activity():
    """Get recent monitoring activity"""
    try:
        activities = _generate_recent_activity()
        
        return jsonify({
            'success': True,
            'activities': activities,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting recent activity: {e}")
        return jsonify({
            'success': False,
            'message': f'Error getting recent activity: {str(e)}'
        }), 500


# Helper functions

def _generate_recent_activity() -> List[Dict[str, Any]]:
    """Generate recent activity based on captured data"""
    activities = []
    
    try:
        # Get threats from real packet capture
        threats = getattr(real_packet_capture, 'threats', [])
        
        for threat in threats[-10:]:  # Last 10 threats
            activities.append({
                'type': 'threat',
                'title': f"{threat.get('type', 'Unknown')} detected",
                'details': threat.get('details', 'Threat detected'),
                'timestamp': threat.get('timestamp', time.time()),
                'severity': threat.get('severity', 'medium')
            })
        
        # Get network discoveries
        networks = getattr(real_packet_capture, 'networks', {})
        recent_networks = sorted(networks.values(), 
                               key=lambda x: x.get('first_seen', 0), 
                               reverse=True)[:5]
        
        for network in recent_networks:
            activities.append({
                'type': 'discovery',
                'title': f"Network discovered: {network.get('ssid', 'Hidden')}",
                'details': f"BSSID: {network.get('bssid', 'Unknown')}",
                'timestamp': network.get('first_seen', time.time())
            })
        
        # Sort by timestamp
        activities.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        return activities[:10]  # Return last 10 activities
        
    except Exception as e:
        logger.error(f"Error generating recent activity: {e}")
        return []


def _calculate_security_distribution(status: Dict[str, Any]) -> Dict[str, int]:
    """Calculate security protocol distribution"""
    try:
        distribution = {
            'WPA3': 0,
            'WPA2': 0,
            'WPA': 0,
            'WEP': 0,
            'Open': 0
        }
        
        # Analyze networks from capture
        networks = getattr(real_packet_capture, 'networks', {})
        
        for network in networks.values():
            encryption = network.get('encryption', 'Open')
            if encryption in distribution:
                distribution[encryption] += 1
            elif network.get('encrypted', False):
                distribution['WPA2'] += 1  # Default for encrypted
            else:
                distribution['Open'] += 1
        
        return distribution
        
    except Exception as e:
        logger.error(f"Error calculating security distribution: {e}")
        return {'WPA3': 0, 'WPA2': 0, 'WPA': 0, 'WEP': 0, 'Open': 0}


def _generate_comprehensive_analysis(status: Dict[str, Any]) -> Dict[str, Any]:
    """Generate comprehensive monitoring analysis"""
    try:
        analysis = {
            'summary': {
                'total_packets': status.get('packets_captured', 0),
                'unique_networks': status.get('networks_detected', 0),
                'unique_devices': status.get('devices_found', 0),
                'security_threats': status.get('threats_detected', 0)
            },
            'packet_analysis': status.get('packet_stats', {}),
            'security_distribution': _calculate_security_distribution(status),
            'threat_analysis': _analyze_threats(),
            'network_analysis': _analyze_networks(),
            'device_analysis': _analyze_devices(),
            'recommendations': _generate_security_recommendations()
        }
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error generating comprehensive analysis: {e}")
        return {}


def _extract_beacon_frames() -> List[Dict[str, Any]]:
    """Extract beacon frames from captured packets"""
    beacon_frames = []
    
    try:
        captured_packets = getattr(real_packet_capture, 'captured_packets', [])
        
        for packet in captured_packets:
            if packet.get('type') == 'beacon':
                beacon_frames.append(packet)
        
        return beacon_frames
        
    except Exception as e:
        logger.error(f"Error extracting beacon frames: {e}")
        return []


def _get_captured_packets() -> List[Dict[str, Any]]:
    """Get captured packets for analysis"""
    try:
        return list(getattr(real_packet_capture, 'captured_packets', []))
    except Exception as e:
        logger.error(f"Error getting captured packets: {e}")
        return []


def _get_scan_data_for_audit() -> Dict[str, Any]:
    """Get scan data formatted for security audit"""
    try:
        return {
            'networks': getattr(real_packet_capture, 'networks', {}),
            'devices': getattr(real_packet_capture, 'devices', {}),
            'threats': getattr(real_packet_capture, 'threats', []),
            'handshakes': getattr(real_packet_capture, 'handshakes', {}),
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting scan data for audit: {e}")
        return {}


def _analyze_channel_utilization() -> Dict[str, Any]:
    """Analyze Wi-Fi channel utilization"""
    try:
        channel_data = {
            'channels': {},
            'congestion_analysis': {},
            'recommendations': []
        }
        
        # Analyze networks by channel
        networks = getattr(real_packet_capture, 'networks', {})
        
        for network in networks.values():
            channel = network.get('channel', 'Unknown')
            if channel != 'Unknown':
                if channel not in channel_data['channels']:
                    channel_data['channels'][channel] = {
                        'network_count': 0,
                        'signal_strengths': [],
                        'networks': []
                    }
                
                channel_data['channels'][channel]['network_count'] += 1
                channel_data['channels'][channel]['signal_strengths'].append(
                    network.get('signal_strength', -50)
                )
                channel_data['channels'][channel]['networks'].append(
                    network.get('ssid', 'Hidden')
                )
        
        # Analyze congestion
        for channel, data in channel_data['channels'].items():
            if data['network_count'] > 3:
                channel_data['congestion_analysis'][channel] = 'High'
                channel_data['recommendations'].append(
                    f"Channel {channel} is congested with {data['network_count']} networks"
                )
            elif data['network_count'] > 1:
                channel_data['congestion_analysis'][channel] = 'Medium'
            else:
                channel_data['congestion_analysis'][channel] = 'Low'
        
        return channel_data
        
    except Exception as e:
        logger.error(f"Error analyzing channel utilization: {e}")
        return {}


def _analyze_threats() -> Dict[str, Any]:
    """Analyze detected threats"""
    try:
        threats = getattr(real_packet_capture, 'threats', [])
        
        threat_analysis = {
            'total_threats': len(threats),
            'threat_types': {},
            'severity_distribution': {'high': 0, 'medium': 0, 'low': 0},
            'recent_threats': threats[-5:] if threats else []
        }
        
        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            severity = threat.get('severity', 'medium')
            
            threat_analysis['threat_types'][threat_type] = \
                threat_analysis['threat_types'].get(threat_type, 0) + 1
            
            threat_analysis['severity_distribution'][severity] = \
                threat_analysis['severity_distribution'].get(severity, 0) + 1
        
        return threat_analysis
        
    except Exception as e:
        logger.error(f"Error analyzing threats: {e}")
        return {}


def _analyze_networks() -> Dict[str, Any]:
    """Analyze discovered networks"""
    try:
        networks = getattr(real_packet_capture, 'networks', {})
        
        network_analysis = {
            'total_networks': len(networks),
            'hidden_networks': 0,
            'encryption_types': {},
            'signal_distribution': {'strong': 0, 'medium': 0, 'weak': 0}
        }
        
        for network in networks.values():
            # Count hidden networks
            if not network.get('ssid') or network.get('ssid') == '':
                network_analysis['hidden_networks'] += 1
            
            # Analyze encryption
            if network.get('encrypted', False):
                enc_type = network.get('encryption', 'WPA2')
                network_analysis['encryption_types'][enc_type] = \
                    network_analysis['encryption_types'].get(enc_type, 0) + 1
            else:
                network_analysis['encryption_types']['Open'] = \
                    network_analysis['encryption_types'].get('Open', 0) + 1
            
            # Analyze signal strength
            signal = network.get('signal_strength', -50)
            if isinstance(signal, (int, float)):
                if signal > -40:
                    network_analysis['signal_distribution']['strong'] += 1
                elif signal > -70:
                    network_analysis['signal_distribution']['medium'] += 1
                else:
                    network_analysis['signal_distribution']['weak'] += 1
        
        return network_analysis
        
    except Exception as e:
        logger.error(f"Error analyzing networks: {e}")
        return {}


def _analyze_devices() -> Dict[str, Any]:
    """Analyze discovered devices"""
    try:
        devices = getattr(real_packet_capture, 'devices', {})
        
        device_analysis = {
            'total_devices': len(devices),
            'active_devices': 0,
            'suspicious_devices': 0,
            'device_activity': {}
        }
        
        current_time = time.time()
        
        for device_mac, device_info in devices.items():
            # Check if device is recently active (within last 5 minutes)
            last_seen = device_info.get('last_seen', 0)
            if current_time - last_seen < 300:
                device_analysis['active_devices'] += 1
            
            # Check for suspicious activity
            probe_requests = device_info.get('probe_requests', [])
            if len(probe_requests) > 50:  # Many probe requests might be suspicious
                device_analysis['suspicious_devices'] += 1
            
            # Categorize device activity
            activity_level = 'low'
            if len(probe_requests) > 20:
                activity_level = 'high'
            elif len(probe_requests) > 5:
                activity_level = 'medium'
            
            device_analysis['device_activity'][activity_level] = \
                device_analysis['device_activity'].get(activity_level, 0) + 1
        
        return device_analysis
        
    except Exception as e:
        logger.error(f"Error analyzing devices: {e}")
        return {}


def _generate_security_recommendations() -> List[str]:
    """Generate security recommendations based on analysis"""
    recommendations = []
    
    try:
        # Analyze current data and generate recommendations
        networks = getattr(real_packet_capture, 'networks', {})
        threats = getattr(real_packet_capture, 'threats', [])
        
        # Check for open networks
        open_networks = sum(1 for network in networks.values() 
                          if not network.get('encrypted', True))
        
        if open_networks > 0:
            recommendations.append(
                f"Secure {open_networks} open network(s) with WPA2/WPA3 encryption"
            )
        
        # Check for threats
        if threats:
            recommendations.append(
                f"Investigate {len(threats)} detected security threat(s)"
            )
        
        # Check for weak encryption
        wep_networks = sum(1 for network in networks.values() 
                         if network.get('encryption') == 'WEP')
        
        if wep_networks > 0:
            recommendations.append(
                f"Upgrade {wep_networks} WEP-encrypted network(s) to WPA2/WPA3"
            )
        
        # General recommendations
        recommendations.extend([
            "Enable network monitoring for continuous security assessment",
            "Regularly audit wireless network configurations",
            "Implement strong access point passwords and authentication"
        ])
        
        return recommendations
        
    except Exception as e:
        logger.error(f"Error generating recommendations: {e}")
        return ["Enable continuous monitoring for better security insights"]


# Error handlers
@passive_monitor_api.errorhandler(403)
def forbidden(error):
    return jsonify({
        'success': False,
        'message': 'Access forbidden - insufficient permissions'
    }), 403


@passive_monitor_api.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        'success': False,
        'message': 'Rate limit exceeded - please wait before making more requests'
    }), 429


@passive_monitor_api.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500