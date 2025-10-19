"""
Wi-Fi Passive Scanner Module
Purpose: Passive network reconnaissance (Lab use only)
Security: Lab-only activation with admin permission checks and audit logging
"""

import os
import time
import json
import logging
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Any
import socket
import struct
import hashlib

# Import from project modules (as per PDF structure)
from app.models.audit_logs import AuditLog
from app.utils.validators import SecurityValidator
from config import Config


class PassiveScanner:
    """
    Passive scanning system for Wi-Fi network reconnaissance
    Lab use only with security safeguards
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_monitoring = False
        self.monitor_thread = None
        self.captured_data = defaultdict(list)
        self.lab_mode_enabled = False
        self.admin_approved = False
        self.network_allowlist = set()
        self.security_validator = SecurityValidator()
        
        # Monitoring configuration
        self.monitor_interface = None
        self.capture_duration = 300  # 5 minutes default
        self.packet_buffer = deque(maxlen=10000)
        
        # Detection thresholds
        self.deauth_threshold = 10  # deauth packets per minute
        self.probe_threshold = 50   # probe requests per minute
        
        # Initialize security safeguards
        self._initialize_security_safeguards()
    
    def _initialize_security_safeguards(self):
        """Initialize security safeguards and validation"""
        try:
            # Check lab-only activation flag from config
            self.lab_mode_enabled = getattr(Config, 'LAB_MODE_ENABLED', False)
            
            # Load network allowlist
            allowlist_path = getattr(Config, 'NETWORK_ALLOWLIST_PATH', 'config/network_allowlist.json')
            if os.path.exists(allowlist_path):
                with open(allowlist_path, 'r') as f:
                    allowlist_data = json.load(f)
                    self.network_allowlist = set(allowlist_data.get('allowed_networks', []))
            
            self.logger.info("Security safeguards initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize security safeguards: {e}")
            self.lab_mode_enabled = False
    
    def _check_permissions(self, user_id: str) -> bool:
        """Check admin permission and lab mode requirements"""
        try:
            if not self.lab_mode_enabled:
                self.logger.warning(f"Lab mode not enabled for passive scanning")
                return False
            
            # Check admin approval (would integrate with user model)
            # For now, checking config flag
            admin_users = getattr(Config, 'ADMIN_USERS', [])
            if user_id not in admin_users:
                self.logger.warning(f"User {user_id} not authorized for passive scanning")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Permission check failed: {e}")
            return False
    
    def _log_audit_event(self, event_type: str, details: Dict[str, Any], user_id: str = None):
        """Log security audit events"""
        try:
            audit_data = {
                'timestamp': datetime.utcnow(),
                'user_id': user_id,
                'event_type': f"PASSIVE_SCAN_{event_type}",
                'details': details,
                'security_level': 'HIGH',
                'source_module': 'passive_scanner'
            }
            
            # Log to audit system (would integrate with audit_logs model)
            self.logger.info(f"AUDIT: {event_type} - {details}")
            
        except Exception as e:
            self.logger.error(f"Audit logging failed: {e}")
    
    def _validate_network_allowlist(self, ssid: str) -> bool:
        """Validate network against allowlist"""
        if not self.network_allowlist:
            return True  # If no allowlist, allow all
        
        return ssid in self.network_allowlist
    
    def passive_monitor(self, interface: str, duration: int = 300, user_id: str = None) -> Dict[str, Any]:
        """
        Passive traffic monitoring
        Args:
            interface: Network interface to monitor
            duration: Monitoring duration in seconds
            user_id: User requesting the scan
        Returns:
            Monitoring results dictionary
        """
        # Security checks
        if not self._check_permissions(user_id):
            raise PermissionError("Insufficient permissions for passive monitoring")
        
        self._log_audit_event("MONITOR_START", {
            'interface': interface,
            'duration': duration,
            'user_id': user_id
        })
        
        try:
            self.monitor_interface = interface
            self.capture_duration = duration
            self.is_monitoring = True
            
            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitor_worker,
                args=(interface, duration)
            )
            self.monitor_thread.start()
            
            # Wait for monitoring to complete
            self.monitor_thread.join()
            
            # Process captured data
            results = self._process_monitoring_results()
            
            self._log_audit_event("MONITOR_COMPLETE", {
                'packets_captured': len(self.packet_buffer),
                'networks_detected': len(results.get('networks', {})),
                'threats_detected': len(results.get('threats', []))
            })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Passive monitoring failed: {e}")
            self._log_audit_event("MONITOR_ERROR", {'error': str(e)})
            raise
        
        finally:
            self.is_monitoring = False
    
    def _monitor_worker(self, interface: str, duration: int):
        """Worker thread for passive monitoring"""
        try:
            start_time = time.time()
            
            # Simulate packet capture (in real implementation would use raw sockets/pcap)
            while time.time() - start_time < duration and self.is_monitoring:
                # Simulate captured packet data
                packet_data = self._simulate_packet_capture()
                if packet_data:
                    self.packet_buffer.append(packet_data)
                
                time.sleep(0.1)  # Small delay to prevent CPU overload
                
        except Exception as e:
            self.logger.error(f"Monitor worker error: {e}")
    
    def _simulate_packet_capture(self) -> Optional[Dict[str, Any]]:
        """Simulate packet capture for demonstration"""
        # DISABLED: Mock 802.11 frame capture removed - use real network data only
        logger.warning("Mock 802.11 frame capture has been disabled - only real network data should be used")
        # This method has been disabled to prevent dummy data usage
        # Real 802.11 frame capture implementation required
        return None
    
    def _process_monitoring_results(self) -> Dict[str, Any]:
        """Process captured monitoring data"""
        results = {
            'networks': {},
            'devices': {},
            'threats': [],
            'statistics': {},
            'timeline': []
        }
        
        try:
            # Process packets
            for packet in self.packet_buffer:
                self._process_packet(packet, results)
            
            # Calculate statistics
            results['statistics'] = self._calculate_monitoring_statistics()
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error processing monitoring results: {e}")
            return results
    
    def _process_packet(self, packet: Dict[str, Any], results: Dict[str, Any]):
        """Process individual packet data"""
        try:
            packet_type = packet.get('type')
            timestamp = packet.get('timestamp')
            
            # Process based on packet type
            if packet_type == 'beacon':
                self._process_beacon_frame(packet, results)
            elif packet_type == 'probe_request':
                self._process_probe_request(packet, results)
            elif packet_type == 'deauth':
                self._process_deauth_frame(packet, results)
            
            # Add to timeline
            results['timeline'].append({
                'timestamp': timestamp,
                'type': packet_type,
                'details': packet
            })
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _process_beacon_frame(self, packet: Dict[str, Any], results: Dict[str, Any]):
        """Process beacon frame data"""
        ssid = packet.get('ssid')
        if ssid and self._validate_network_allowlist(ssid):
            if ssid not in results['networks']:
                results['networks'][ssid] = {
                    'ssid': ssid,
                    'first_seen': packet['timestamp'],
                    'last_seen': packet['timestamp'],
                    'beacon_count': 0,
                    'signal_strength': packet.get('signal_strength', 0),
                    'channel': packet.get('channel', 0)
                }
            
            results['networks'][ssid]['beacon_count'] += 1
            results['networks'][ssid]['last_seen'] = packet['timestamp']
    
    def _process_probe_request(self, packet: Dict[str, Any], results: Dict[str, Any]):
        """Process probe request data"""
        src_mac = packet.get('src_mac')
        if src_mac:
            if src_mac not in results['devices']:
                results['devices'][src_mac] = {
                    'mac': src_mac,
                    'first_seen': packet['timestamp'],
                    'last_seen': packet['timestamp'],
                    'probe_count': 0,
                    'probed_networks': set()
                }
            
            results['devices'][src_mac]['probe_count'] += 1
            results['devices'][src_mac]['last_seen'] = packet['timestamp']
            
            ssid = packet.get('ssid')
            if ssid:
                results['devices'][src_mac]['probed_networks'].add(ssid)
    
    def _process_deauth_frame(self, packet: Dict[str, Any], results: Dict[str, Any]):
        """Process deauthentication frame"""
        # Detect potential deauth attack
        threat = {
            'type': 'deauth_attack',
            'timestamp': packet['timestamp'],
            'src_mac': packet.get('src_mac'),
            'dst_mac': packet.get('dst_mac'),
            'severity': 'high'
        }
        results['threats'].append(threat)
    
    def _calculate_monitoring_statistics(self) -> Dict[str, Any]:
        """Calculate monitoring statistics"""
        return {
            'total_packets': len(self.packet_buffer),
            'monitoring_duration': self.capture_duration,
            'packets_per_second': len(self.packet_buffer) / max(self.capture_duration, 1),
            'unique_networks': len(set(p.get('ssid') for p in self.packet_buffer if p.get('ssid'))),
            'unique_devices': len(set(p.get('src_mac') for p in self.packet_buffer if p.get('src_mac')))
        }


class HandshakeCapture:
    """
    WPA handshake capture system
    Lab use only with security safeguards
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.captured_handshakes = {}
        self.security_validator = SecurityValidator()
        
    def capture_handshakes(self, target_networks: List[str], duration: int = 600, user_id: str = None) -> Dict[str, Any]:
        """
        Capture 4-way handshakes for specified networks
        Args:
            target_networks: List of target network SSIDs
            duration: Capture duration in seconds
            user_id: User requesting the capture
        Returns:
            Captured handshake data
        """
        # Security validation
        if not self._validate_handshake_capture(target_networks, user_id):
            raise PermissionError("Handshake capture not authorized")
        
        try:
            results = {}
            
            for network in target_networks:
                if self._validate_network_allowlist(network):
                    handshake_data = self._capture_network_handshake(network, duration)
                    if handshake_data:
                        results[network] = handshake_data
            
            # Log audit event
            self._log_audit_event("HANDSHAKE_CAPTURE", {
                'networks': target_networks,
                'captured': len(results),
                'user_id': user_id
            })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Handshake capture failed: {e}")
            raise
    
    def _validate_handshake_capture(self, networks: List[str], user_id: str) -> bool:
        """Validate handshake capture request"""
        # Check lab mode and permissions
        if not getattr(Config, 'LAB_MODE_ENABLED', False):
            return False
        
        # Check user authorization
        admin_users = getattr(Config, 'ADMIN_USERS', [])
        if user_id not in admin_users:
            return False
        
        # Validate networks against allowlist
        for network in networks:
            if not self._validate_network_allowlist(network):
                return False
        
        return True
    
    def _validate_network_allowlist(self, ssid: str) -> bool:
        """Validate network against allowlist"""
        # Placeholder for allowlist validation
        return True
    
    def _capture_network_handshake(self, network: str, duration: int) -> Optional[Dict[str, Any]]:
        """Capture handshake for specific network"""
        # Simulate handshake capture
        import random
        
        if random.random() > 0.3:  # 70% success rate simulation
            return {
                'network': network,
                'timestamp': time.time(),
                'handshake_frames': 4,
                'client_mac': f"client_{random.randint(1000,9999)}",
                'ap_mac': f"ap_{random.randint(1000,9999)}",
                'quality': random.choice(['complete', 'partial']),
                'encryption': 'WPA2'
            }
        
        return None
    
    def _log_audit_event(self, event_type: str, details: Dict[str, Any]):
        """Log audit events"""
        self.logger.info(f"AUDIT: {event_type} - {details}")


class BeaconAnalyzer:
    """
    Beacon frame analysis system
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.beacon_database = {}
        
    def analyze_beacon_frames(self, beacon_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze beacon frames for network information
        Args:
            beacon_data: List of beacon frame data
        Returns:
            Analysis results
        """
        try:
            analysis_results = {
                'networks': {},
                'anomalies': [],
                'vendor_analysis': {},
                'security_assessment': {}
            }
            
            for beacon in beacon_data:
                self._analyze_single_beacon(beacon, analysis_results)
            
            # Perform cross-beacon analysis
            self._perform_cross_analysis(analysis_results)
            
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Beacon analysis failed: {e}")
            return {}
    
    def _analyze_single_beacon(self, beacon: Dict[str, Any], results: Dict[str, Any]):
        """Analyze individual beacon frame"""
        ssid = beacon.get('ssid')
        if not ssid:
            return
        
        if ssid not in results['networks']:
            results['networks'][ssid] = {
                'ssid': ssid,
                'first_seen': beacon.get('timestamp'),
                'last_seen': beacon.get('timestamp'),
                'beacon_interval': beacon.get('beacon_interval', 100),
                'capabilities': beacon.get('capabilities', []),
                'encryption': self._detect_encryption(beacon),
                'vendor': self._identify_vendor(beacon.get('src_mac', '')),
                'signal_variations': []
            }
        
        # Update network information
        network_info = results['networks'][ssid]
        network_info['last_seen'] = beacon.get('timestamp')
        network_info['signal_variations'].append(beacon.get('signal_strength', 0))
        
        # Detect anomalies
        anomalies = self._detect_beacon_anomalies(beacon, network_info)
        results['anomalies'].extend(anomalies)
    
    def _detect_encryption(self, beacon: Dict[str, Any]) -> str:
        """Detect encryption type from beacon"""
        capabilities = beacon.get('capabilities', [])
        
        if 'WPA3' in capabilities:
            return 'WPA3'
        elif 'WPA2' in capabilities:
            return 'WPA2'
        elif 'WPA' in capabilities:
            return 'WPA'
        elif 'WEP' in capabilities:
            return 'WEP'
        else:
            return 'OPEN'
    
    def _identify_vendor(self, mac_address: str) -> str:
        """Identify device vendor from MAC address"""
        if not mac_address:
            return 'Unknown'
        
        # Extract OUI (first 3 octets)
        oui = mac_address[:8].upper()
        
        # Simplified vendor database
        vendor_db = {
            'AA:BB:CC': 'Cisco',
            'DD:EE:FF': 'Netgear',
            '11:22:33': 'Linksys',
            '44:55:66': 'TP-Link'
        }
        
        return vendor_db.get(oui, 'Unknown')
    
    def _detect_beacon_anomalies(self, beacon: Dict[str, Any], network_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in beacon frames"""
        anomalies = []
        
        # Check beacon interval anomalies
        expected_interval = network_info.get('beacon_interval', 100)
        current_interval = beacon.get('beacon_interval', 100)
        
        if abs(current_interval - expected_interval) > 50:
            anomalies.append({
                'type': 'beacon_interval_anomaly',
                'network': beacon.get('ssid'),
                'expected': expected_interval,
                'observed': current_interval,
                'timestamp': beacon.get('timestamp')
            })
        
        # Check signal strength anomalies
        signal_variations = network_info.get('signal_variations', [])
        if len(signal_variations) > 5:
            avg_signal = sum(signal_variations) / len(signal_variations)
            current_signal = beacon.get('signal_strength', 0)
            
            if abs(current_signal - avg_signal) > 20:
                anomalies.append({
                    'type': 'signal_anomaly',
                    'network': beacon.get('ssid'),
                    'average': avg_signal,
                    'current': current_signal,
                    'timestamp': beacon.get('timestamp')
                })
        
        return anomalies
    
    def _perform_cross_analysis(self, results: Dict[str, Any]):
        """Perform cross-beacon analysis"""
        networks = results['networks']
        
        # Detect potential evil twins
        ssid_groups = defaultdict(list)
        for network_id, network_data in networks.items():
            ssid = network_data['ssid']
            ssid_groups[ssid].append(network_data)
        
        for ssid, network_list in ssid_groups.items():
            if len(network_list) > 1:
                results['anomalies'].append({
                    'type': 'potential_evil_twin',
                    'ssid': ssid,
                    'count': len(network_list),
                    'networks': network_list
                })


class RogueAPDetector:
    """
    Rogue access point detection system
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.known_aps = {}
        self.suspicious_aps = {}
        
    def detect_rogue_aps(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect rogue access points
        Args:
            network_data: Network scan data
        Returns:
            List of detected rogue APs
        """
        try:
            rogue_aps = []
            
            for network_id, network_info in network_data.get('networks', {}).items():
                rogue_indicators = self._analyze_for_rogue_indicators(network_info)
                
                if rogue_indicators:
                    rogue_ap = {
                        'ssid': network_info.get('ssid'),
                        'mac_address': network_info.get('mac_address'),
                        'indicators': rogue_indicators,
                        'risk_level': self._calculate_rogue_risk(rogue_indicators),
                        'timestamp': network_info.get('first_seen')
                    }
                    rogue_aps.append(rogue_ap)
            
            return rogue_aps
            
        except Exception as e:
            self.logger.error(f"Rogue AP detection failed: {e}")
            return []
    
    def _analyze_for_rogue_indicators(self, network_info: Dict[str, Any]) -> List[str]:
        """Analyze network for rogue AP indicators"""
        indicators = []
        
        # Check for suspicious SSID patterns
        ssid = network_info.get('ssid', '')
        if self._is_suspicious_ssid(ssid):
            indicators.append('suspicious_ssid')
        
        # Check for signal strength anomalies
        signal_variations = network_info.get('signal_variations', [])
        if self._has_signal_anomalies(signal_variations):
            indicators.append('signal_anomalies')
        
        # Check for encryption anomalies
        encryption = network_info.get('encryption', '')
        if self._has_encryption_anomalies(encryption, ssid):
            indicators.append('encryption_anomalies')
        
        # Check for vendor anomalies
        vendor = network_info.get('vendor', '')
        if self._has_vendor_anomalies(vendor, ssid):
            indicators.append('vendor_anomalies')
        
        return indicators
    
    def _is_suspicious_ssid(self, ssid: str) -> bool:
        """Check if SSID is suspicious"""
        suspicious_patterns = [
            'free', 'wifi', 'internet', 'guest', 'public',
            'android', 'iphone', 'samsung', 'update'
        ]
        
        ssid_lower = ssid.lower()
        return any(pattern in ssid_lower for pattern in suspicious_patterns)
    
    def _has_signal_anomalies(self, signal_variations: List[float]) -> bool:
        """Check for signal strength anomalies"""
        if len(signal_variations) < 3:
            return False
        
        # Check for unusually high variations
        max_signal = max(signal_variations)
        min_signal = min(signal_variations)
        
        return (max_signal - min_signal) > 30
    
    def _has_encryption_anomalies(self, encryption: str, ssid: str) -> bool:
        """Check for encryption anomalies"""
        # Corporate networks should use WPA2/WPA3
        corporate_indicators = ['corp', 'company', 'office', 'secure']
        
        if any(indicator in ssid.lower() for indicator in corporate_indicators):
            return encryption in ['OPEN', 'WEP']
        
        return False
    
    def _has_vendor_anomalies(self, vendor: str, ssid: str) -> bool:
        """Check for vendor anomalies"""
        # Check if vendor matches expected patterns
        if vendor == 'Unknown':
            return True
        
        # Additional vendor-based checks could be implemented
        return False
    
    def _calculate_rogue_risk(self, indicators: List[str]) -> str:
        """Calculate risk level for rogue AP"""
        risk_scores = {
            'suspicious_ssid': 2,
            'signal_anomalies': 1,
            'encryption_anomalies': 3,
            'vendor_anomalies': 1
        }
        
        total_score = sum(risk_scores.get(indicator, 0) for indicator in indicators)
        
        if total_score >= 5:
            return 'HIGH'
        elif total_score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'


class SecurityAuditor:
    """
    Security audit functions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.audit_results = {}
        
    def audit_wireless_security(self, scan_data: Dict[str, Any], user_id: str = None) -> Dict[str, Any]:
        """
        Comprehensive wireless security audit
        Args:
            scan_data: Complete scan data from passive monitoring
            user_id: User requesting the audit
        Returns:
            Comprehensive security audit results
        """
        try:
            audit_results = {
                'audit_timestamp': datetime.utcnow().isoformat(),
                'user_id': user_id,
                'network_security': {},
                'device_security': {},
                'threat_assessment': {},
                'compliance_status': {},
                'recommendations': []
            }
            
            # Audit network security
            audit_results['network_security'] = self._audit_network_security(
                scan_data.get('networks', {})
            )
            
            # Audit device security
            audit_results['device_security'] = self._audit_device_security(
                scan_data.get('devices', {})
            )
            
            # Assess threats
            audit_results['threat_assessment'] = self._assess_threats(
                scan_data.get('threats', [])
            )
            
            # Check compliance
            audit_results['compliance_status'] = self._check_compliance(audit_results)
            
            # Generate recommendations
            audit_results['recommendations'] = self._generate_recommendations(audit_results)
            
            # Log audit completion
            self._log_audit_event("SECURITY_AUDIT_COMPLETE", {
                'networks_audited': len(scan_data.get('networks', {})),
                'devices_audited': len(scan_data.get('devices', {})),
                'threats_found': len(scan_data.get('threats', [])),
                'user_id': user_id
            })
            
            return audit_results
            
        except Exception as e:
            self.logger.error(f"Security audit failed: {e}")
            raise
    
    def _audit_network_security(self, networks: Dict[str, Any]) -> Dict[str, Any]:
        """Audit network security configurations"""
        network_audit = {
            'total_networks': len(networks),
            'encryption_status': {'WPA3': 0, 'WPA2': 0, 'WPA': 0, 'WEP': 0, 'OPEN': 0},
            'security_issues': [],
            'risk_score': 0
        }
        
        for network_id, network_data in networks.items():
            encryption = network_data.get('encryption', 'UNKNOWN')
            network_audit['encryption_status'][encryption] = network_audit['encryption_status'].get(encryption, 0) + 1
            
            # Check for security issues
            if encryption in ['OPEN', 'WEP']:
                network_audit['security_issues'].append({
                    'network': network_data.get('ssid'),
                    'issue': 'weak_encryption',
                    'severity': 'HIGH' if encryption == 'OPEN' else 'MEDIUM'
                })
        
        # Calculate risk score
        network_audit['risk_score'] = self._calculate_network_risk_score(network_audit)
        
        return network_audit
    
    def _audit_device_security(self, devices: Dict[str, Any]) -> Dict[str, Any]:
        """Audit device security behaviors"""
        device_audit = {
            'total_devices': len(devices),
            'suspicious_devices': [],
            'probe_analysis': {},
            'risk_score': 0
        }
        
        for device_id, device_data in devices.items():
            probe_count = device_data.get('probe_count', 0)
            probed_networks = device_data.get('probed_networks', set())
            
            # Analyze probing behavior
            if probe_count > 100 or len(probed_networks) > 20:
                device_audit['suspicious_devices'].append({
                    'device': device_id,
                    'probe_count': probe_count,
                    'networks_probed': len(probed_networks),
                    'suspicion_level': 'HIGH' if probe_count > 200 else 'MEDIUM'
                })
        
        device_audit['risk_score'] = len(device_audit['suspicious_devices']) * 10
        
        return device_audit
    
    def _assess_threats(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess identified threats"""
        threat_assessment = {
            'total_threats': len(threats),
            'threat_types': defaultdict(int),
            'severity_distribution': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'active_threats': [],
            'risk_score': 0
        }
        
        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            severity = threat.get('severity', 'LOW').upper()
            
            threat_assessment['threat_types'][threat_type] += 1
            threat_assessment['severity_distribution'][severity] += 1
            
            if severity == 'HIGH':
                threat_assessment['active_threats'].append(threat)
        
        # Calculate threat risk score
        threat_assessment['risk_score'] = (
            threat_assessment['severity_distribution']['HIGH'] * 10 +
            threat_assessment['severity_distribution']['MEDIUM'] * 5 +
            threat_assessment['severity_distribution']['LOW'] * 1
        )
        
        return threat_assessment
    
    def _check_compliance(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Check security compliance status"""
        compliance_status = {
            'overall_score': 0,
            'compliance_checks': {},
            'violations': [],
            'certifications': ['ISO27001', 'NIST', 'PCI-DSS']
        }
        
        # Check encryption compliance
        network_security = audit_results.get('network_security', {})
        encryption_status = network_security.get('encryption_status', {})
        
        total_networks = network_security.get('total_networks', 0)
        if total_networks > 0:
            secure_networks = encryption_status.get('WPA3', 0) + encryption_status.get('WPA2', 0)
            encryption_compliance = (secure_networks / total_networks) * 100
            
            compliance_status['compliance_checks']['encryption'] = {
                'score': encryption_compliance,
                'status': 'PASS' if encryption_compliance >= 80 else 'FAIL',
                'requirement': 'Minimum 80% networks with WPA2/WPA3'
            }
            
            if encryption_compliance < 80:
                compliance_status['violations'].append({
                    'type': 'encryption_compliance',
                    'description': f'Only {encryption_compliance:.1f}% networks use secure encryption',
                    'severity': 'HIGH'
                })
        
        # Check threat response compliance
        threat_assessment = audit_results.get('threat_assessment', {})
        active_threats = len(threat_assessment.get('active_threats', []))
        
        compliance_status['compliance_checks']['threat_response'] = {
            'score': 100 if active_threats == 0 else max(0, 100 - (active_threats * 20)),
            'status': 'PASS' if active_threats <= 2 else 'FAIL',
            'requirement': 'Maximum 2 active high-severity threats'
        }
        
        if active_threats > 2:
            compliance_status['violations'].append({
                'type': 'threat_response',
                'description': f'{active_threats} active high-severity threats detected',
                'severity': 'CRITICAL'
            })
        
        # Calculate overall compliance score
        checks = compliance_status['compliance_checks']
        if checks:
            total_score = sum(check['score'] for check in checks.values())
            compliance_status['overall_score'] = total_score / len(checks)
        
        return compliance_status
    
    def _generate_recommendations(self, audit_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on audit results"""
        recommendations = []
        
        # Network security recommendations
        network_security = audit_results.get('network_security', {})
        encryption_status = network_security.get('encryption_status', {})
        
        if encryption_status.get('OPEN', 0) > 0:
            recommendations.append({
                'category': 'encryption',
                'priority': 'HIGH',
                'title': 'Secure Open Networks',
                'description': f"{encryption_status['OPEN']} open networks detected. Implement WPA3/WPA2 encryption.",
                'impact': 'Data interception, unauthorized access prevention',
                'effort': 'MEDIUM'
            })
        
        if encryption_status.get('WEP', 0) > 0:
            recommendations.append({
                'category': 'encryption',
                'priority': 'HIGH',
                'title': 'Upgrade WEP Networks',
                'description': f"{encryption_status['WEP']} WEP networks detected. Upgrade to WPA3/WPA2.",
                'impact': 'Prevent easy credential cracking',
                'effort': 'MEDIUM'
            })
        
        # Device security recommendations
        device_security = audit_results.get('device_security', {})
        suspicious_devices = device_security.get('suspicious_devices', [])
        
        if len(suspicious_devices) > 0:
            recommendations.append({
                'category': 'monitoring',
                'priority': 'MEDIUM',
                'title': 'Monitor Suspicious Devices',
                'description': f"{len(suspicious_devices)} devices showing suspicious probing behavior.",
                'impact': 'Early detection of reconnaissance activities',
                'effort': 'LOW'
            })
        
        # Threat response recommendations
        threat_assessment = audit_results.get('threat_assessment', {})
        active_threats = threat_assessment.get('active_threats', [])
        
        if len(active_threats) > 0:
            recommendations.append({
                'category': 'incident_response',
                'priority': 'CRITICAL',
                'title': 'Address Active Threats',
                'description': f"{len(active_threats)} active high-severity threats require immediate attention.",
                'impact': 'Prevent security incidents and data breaches',
                'effort': 'HIGH'
            })
        
        # Compliance recommendations
        compliance_status = audit_results.get('compliance_status', {})
        violations = compliance_status.get('violations', [])
        
        for violation in violations:
            recommendations.append({
                'category': 'compliance',
                'priority': violation['severity'],
                'title': f"Address {violation['type'].replace('_', ' ').title()}",
                'description': violation['description'],
                'impact': 'Maintain regulatory compliance',
                'effort': 'MEDIUM'
            })
        
        # General security recommendations
        recommendations.extend([
            {
                'category': 'monitoring',
                'priority': 'MEDIUM',
                'title': 'Implement Continuous Monitoring',
                'description': 'Deploy continuous wireless security monitoring for real-time threat detection.',
                'impact': 'Proactive threat detection and response',
                'effort': 'HIGH'
            },
            {
                'category': 'policy',
                'priority': 'LOW',
                'title': 'Update Security Policies',
                'description': 'Review and update wireless security policies based on audit findings.',
                'impact': 'Improved security posture and compliance',
                'effort': 'LOW'
            }
        ])
        
        # Sort recommendations by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return recommendations
    
    def _calculate_network_risk_score(self, network_audit: Dict[str, Any]) -> int:
        """Calculate network risk score"""
        encryption_status = network_audit.get('encryption_status', {})
        total_networks = network_audit.get('total_networks', 0)
        
        if total_networks == 0:
            return 0
        
        # Calculate weighted risk score
        risk_weights = {'OPEN': 10, 'WEP': 7, 'WPA': 3, 'WPA2': 1, 'WPA3': 0}
        total_risk = sum(
            encryption_status.get(enc_type, 0) * weight 
            for enc_type, weight in risk_weights.items()
        )
        
        return min(100, (total_risk / total_networks) * 10)
    
    def _log_audit_event(self, event_type: str, details: Dict[str, Any]):
        """Log audit events"""
        self.logger.info(f"AUDIT: {event_type} - {details}")


# Additional utility functions for the passive scanner module

def monitor_deauth_attacks(packet_stream: List[Dict[str, Any]], threshold: int = 10) -> List[Dict[str, Any]]:
    """
    Monitor for deauthentication attacks
    Args:
        packet_stream: Stream of captured packets
        threshold: Deauth packets threshold per minute
    Returns:
        List of detected deauth attacks
    """
    deauth_attacks = []
    deauth_counts = defaultdict(int)
    time_window = 60  # 1 minute window
    
    try:
        current_time = time.time()
        
        for packet in packet_stream:
            if packet.get('type') == 'deauth':
                packet_time = packet.get('timestamp', current_time)
                
                # Only consider packets within the time window
                if current_time - packet_time <= time_window:
                    src_mac = packet.get('src_mac', 'unknown')
                    dst_mac = packet.get('dst_mac', 'unknown')
                    target_key = f"{src_mac}:{dst_mac}"
                    
                    deauth_counts[target_key] += 1
                    
                    # Check if threshold exceeded
                    if deauth_counts[target_key] >= threshold:
                        attack_info = {
                            'type': 'deauth_attack',
                            'src_mac': src_mac,
                            'dst_mac': dst_mac,
                            'packet_count': deauth_counts[target_key],
                            'time_window': time_window,
                            'severity': 'HIGH',
                            'timestamp': packet_time
                        }
                        
                        if attack_info not in deauth_attacks:
                            deauth_attacks.append(attack_info)
        
        return deauth_attacks
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Deauth attack monitoring failed: {e}")
        return []


def analyze_probe_requests(packet_stream: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze probe request patterns
    Args:
        packet_stream: Stream of captured packets
    Returns:
        Probe request analysis results
    """
    analysis_results = {
        'total_probes': 0,
        'unique_devices': set(),
        'probe_patterns': defaultdict(list),
        'suspicious_behavior': [],
        'network_discovery': defaultdict(set)
    }
    
    try:
        for packet in packet_stream:
            if packet.get('type') == 'probe_request':
                analysis_results['total_probes'] += 1
                
                src_mac = packet.get('src_mac')
                ssid = packet.get('ssid', '')
                timestamp = packet.get('timestamp', time.time())
                
                if src_mac:
                    analysis_results['unique_devices'].add(src_mac)
                    analysis_results['probe_patterns'][src_mac].append({
                        'ssid': ssid,
                        'timestamp': timestamp
                    })
                    
                    if ssid:
                        analysis_results['network_discovery'][src_mac].add(ssid)
        
        # Analyze for suspicious behavior
        for device, probes in analysis_results['probe_patterns'].items():
            probe_count = len(probes)
            unique_networks = len(analysis_results['network_discovery'][device])
            
            # Detect aggressive scanning
            if probe_count > 50 or unique_networks > 20:
                analysis_results['suspicious_behavior'].append({
                    'device': device,
                    'behavior': 'aggressive_scanning',
                    'probe_count': probe_count,
                    'networks_probed': unique_networks,
                    'severity': 'MEDIUM'
                })
            
            # Detect rapid probing
            if len(probes) >= 2:
                time_diffs = []
                for i in range(1, len(probes)):
                    time_diff = probes[i]['timestamp'] - probes[i-1]['timestamp']
                    time_diffs.append(time_diff)
                
                avg_interval = sum(time_diffs) / len(time_diffs)
                if avg_interval < 0.1:  # Less than 100ms between probes
                    analysis_results['suspicious_behavior'].append({
                        'device': device,
                        'behavior': 'rapid_probing',
                        'avg_interval': avg_interval,
                        'severity': 'LOW'
                    })
        
        # Convert sets to lists for JSON serialization
        analysis_results['unique_devices'] = list(analysis_results['unique_devices'])
        analysis_results['network_discovery'] = {
            k: list(v) for k, v in analysis_results['network_discovery'].items()
        }
        
        return analysis_results
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Probe request analysis failed: {e}")
        return analysis_results


def detect_evil_twins(network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect evil twin access points
    Args:
        network_data: Network scan data
    Returns:
        List of potential evil twin networks
    """
    evil_twins = []
    ssid_groups = defaultdict(list)
    
    try:
        # Group networks by SSID
        for network_id, network_info in network_data.get('networks', {}).items():
            ssid = network_info.get('ssid')
            if ssid:
                ssid_groups[ssid].append(network_info)
        
        # Analyze each SSID group
        for ssid, networks in ssid_groups.items():
            if len(networks) > 1:
                # Multiple networks with same SSID - potential evil twin
                suspicious_indicators = []
                
                # Check for different encryption types
                encryption_types = set(net.get('encryption', '') for net in networks)
                if len(encryption_types) > 1:
                    suspicious_indicators.append('mixed_encryption')
                
                # Check for different vendors
                vendors = set(net.get('vendor', '') for net in networks)
                if len(vendors) > 1:
                    suspicious_indicators.append('mixed_vendors')
                
                # Check for unusual signal strength patterns
                signals = [net.get('signal_strength', 0) for net in networks]
                if max(signals) - min(signals) > 20:
                    suspicious_indicators.append('signal_anomalies')
                
                # Check for timing anomalies
                first_seen_times = [net.get('first_seen', 0) for net in networks]
                if max(first_seen_times) - min(first_seen_times) < 300:  # Within 5 minutes
                    suspicious_indicators.append('simultaneous_appearance')
                
                if suspicious_indicators:
                    evil_twin_group = {
                        'ssid': ssid,
                        'network_count': len(networks),
                        'networks': networks,
                        'suspicious_indicators': suspicious_indicators,
                        'risk_level': 'HIGH' if len(suspicious_indicators) >= 3 else 'MEDIUM',
                        'detection_time': time.time()
                    }
                    evil_twins.append(evil_twin_group)
        
        return evil_twins
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Evil twin detection failed: {e}")
        return []


# Module-level configuration and initialization
def initialize_passive_scanner(config: Dict[str, Any]) -> PassiveScanner:
    """
    Initialize passive scanner with configuration
    Args:
        config: Configuration dictionary
    Returns:
        Configured PassiveScanner instance
    """
    scanner = PassiveScanner()
    
    # Apply configuration
    if 'lab_mode_enabled' in config:
        scanner.lab_mode_enabled = config['lab_mode_enabled']
    
    if 'network_allowlist' in config:
        scanner.network_allowlist = set(config['network_allowlist'])
    
    if 'capture_duration' in config:
        scanner.capture_duration = config['capture_duration']
    
    if 'detection_thresholds' in config:
        thresholds = config['detection_thresholds']
        scanner.deauth_threshold = thresholds.get('deauth', 10)
        scanner.probe_threshold = thresholds.get('probe', 50)
    
    return scanner


# Security validation functions
def validate_passive_scan_request(request_data: Dict[str, Any], user_id: str) -> bool:
    """
    Validate passive scan request for security compliance
    Args:
        request_data: Scan request data
        user_id: User making the request
    Returns:
        True if request is valid and authorized
    """
    try:
        # Check lab mode requirement
        if not getattr(Config, 'LAB_MODE_ENABLED', False):
            return False
        
        # Check user authorization
        admin_users = getattr(Config, 'ADMIN_USERS', [])
        if user_id not in admin_users:
            return False
        
        # Validate scan parameters
        duration = request_data.get('duration', 0)
        if duration > 3600:  # Max 1 hour
            return False
        
        # Validate target networks if specified
        target_networks = request_data.get('target_networks', [])
        if target_networks:
            # Check against allowlist
            allowlist_path = getattr(Config, 'NETWORK_ALLOWLIST_PATH', '')
            if os.path.exists(allowlist_path):
                with open(allowlist_path, 'r') as f:
                    allowlist_data = json.load(f)
                    allowed_networks = set(allowlist_data.get('allowed_networks', []))
                    
                    for network in target_networks:
                        if network not in allowed_networks:
                            return False
        
        return True
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Request validation failed: {e}")
        return False


# Export main classes and functions
__all__ = [
    'PassiveScanner',
    'HandshakeCapture', 
    'BeaconAnalyzer',
    'RogueAPDetector',
    'SecurityAuditor',
    'monitor_deauth_attacks',
    'analyze_probe_requests',
    'detect_evil_twins',
    'initialize_passive_scanner',
    'validate_passive_scan_request'
]