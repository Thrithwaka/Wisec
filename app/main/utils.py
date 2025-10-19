"""
Wi-Fi Security System - Main Application Utilities
Purpose: Utility functions for main application functionality

This module provides utility classes and functions for:
- Network information formatting
- Signal quality calculations
- Security level assessments
- Scan result formatting
- Security recommendations generation
- Network topology graph creation
"""

import json
import math
import statistics
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta
import networkx as nx
from flask import current_app


class NetworkUtils:
    """Network utility functions for Wi-Fi operations"""
    
    @staticmethod
    def format_network_info(network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format network information for display
        
        Args:
            network_data: Raw network data dictionary
            
        Returns:
            Formatted network information dictionary
        """
        try:
            formatted_info = {
                'ssid': network_data.get('ssid', 'Unknown Network'),
                'bssid': network_data.get('bssid', 'Unknown BSSID'),
                'signal_strength': NetworkUtils.format_signal_strength(
                    network_data.get('signal_strength', -100)
                ),
                'frequency': NetworkUtils.format_frequency(
                    network_data.get('frequency', 0)
                ),
                'channel': network_data.get('channel', 'Unknown'),
                'encryption': NetworkUtils.format_encryption_type(
                    network_data.get('encryption', 'Unknown')
                ),
                'security_protocol': network_data.get('security_protocol', 'Unknown'),
                'vendor': NetworkUtils.identify_vendor(
                    network_data.get('bssid', '')
                ),
                'device_type': NetworkUtils.determine_device_type(network_data),
                'last_seen': NetworkUtils.format_timestamp(
                    network_data.get('last_seen', datetime.now())
                ),
                'quality_score': NetworkUtils.calculate_network_quality(network_data)
            }
            
            return formatted_info
            
        except Exception as e:
            current_app.logger.error(f"Error formatting network info: {str(e)}")
            return NetworkUtils._get_default_network_info()
    
    @staticmethod
    def format_signal_strength(rssi_value: int) -> Dict[str, Any]:
        """
        Format signal strength information
        
        Args:
            rssi_value: RSSI value in dBm
            
        Returns:
            Formatted signal strength information
        """
        signal_info = {
            'rssi_dbm': rssi_value,
            'percentage': max(0, min(100, 2 * (rssi_value + 100))),
            'quality': NetworkUtils._get_signal_quality_label(rssi_value),
            'bars': NetworkUtils._calculate_signal_bars(rssi_value),
            'color_code': NetworkUtils._get_signal_color(rssi_value)
        }
        
        return signal_info
    
    @staticmethod
    def format_frequency(frequency: int) -> Dict[str, Any]:
        """
        Format frequency information
        
        Args:
            frequency: Frequency in MHz
            
        Returns:
            Formatted frequency information
        """
        band = '2.4 GHz' if 2400 <= frequency <= 2500 else '5 GHz' if 5000 <= frequency <= 6000 else 'Unknown'
        
        return {
            'frequency_mhz': frequency,
            'band': band,
            'channel': NetworkUtils._frequency_to_channel(frequency),
            'congestion_level': NetworkUtils._estimate_band_congestion(frequency)
        }
    
    @staticmethod
    def format_encryption_type(encryption: str) -> Dict[str, Any]:
        """
        Format encryption type information
        
        Args:
            encryption: Encryption type string
            
        Returns:
            Formatted encryption information
        """
        encryption_upper = encryption.upper()
        
        security_level = 'High'
        if 'WEP' in encryption_upper:
            security_level = 'Very Low'
        elif 'WPA' in encryption_upper and 'WPA2' not in encryption_upper:
            security_level = 'Low'
        elif 'WPA2' in encryption_upper and 'WPA3' not in encryption_upper:
            security_level = 'Medium'
        elif 'WPA3' in encryption_upper:
            security_level = 'High'
        elif 'OPEN' in encryption_upper or 'NONE' in encryption_upper:
            security_level = 'None'
        
        return {
            'type': encryption,
            'security_level': security_level,
            'is_secure': security_level not in ['None', 'Very Low'],
            'recommendation': NetworkUtils._get_encryption_recommendation(security_level)
        }
    
    @staticmethod
    def identify_vendor(bssid: str) -> str:
        """
        Identify device vendor from BSSID
        
        Args:
            bssid: BSSID (MAC address) string
            
        Returns:
            Vendor name or 'Unknown'
        """
        if not bssid or len(bssid) < 8:
            return 'Unknown'
        
        # Extract OUI (first 3 octets)
        oui = bssid.replace(':', '').replace('-', '').upper()[:6]
        
        # Common vendor OUI mappings
        vendor_mapping = {
            '00:50:56': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '08:00:27': 'VirtualBox',
            '00:16:3E': 'Xen',
            '00:1B:21': 'Intel',
            '00:23:AB': 'Apple',
            '00:26:BB': 'Apple',
            '3C:15:C2': 'Apple',
            '00:1F:3C': 'Compex',
            '00:90:4C': 'Epigram',
            '00:07:E9': 'Intel',
            '00:13:02': 'Intel',
            '00:15:00': 'Intel',
            '00:16:EA': 'Intel',
            '00:18:DE': 'Intel',
            '00:1B:77': 'Intel',
            '00:21:6A': 'Intel',
            '00:24:D7': 'Intel',
            '04:CE:14': 'Intel',
            '08:11:96': 'Intel',
            '0C:8B:FD': 'Intel',
            '34:13:E8': 'Intel',
            '3C:A9:F4': 'Intel',
            '7C:7A:91': 'Intel',
            '84:3A:4B': 'Intel',
            '90:48:9A': 'Intel',
            'A0:A8:CD': 'Intel',
            'B4:96:91': 'Intel',
            'CC:46:D6': 'Intel',
            'D0:57:7B': 'Intel',
            'D4:6D:6D': 'Intel',
            'E0:94:67': 'Intel',
            'F0:D5:BF': 'Intel',
            'F4:06:69': 'Intel',
            '00:03:93': 'Apple',
            '00:0A:95': 'Apple',
            '00:0D:93': 'Apple',
            '00:11:24': 'Apple',
            '00:14:51': 'Apple',
            '00:16:CB': 'Apple',
            '00:17:F2': 'Apple',
            '00:19:E3': 'Apple',
            '00:1B:63': 'Apple',
            '00:1E:C2': 'Apple',
            '00:21:E9': 'Apple',
            '00:23:12': 'Apple',
            '00:23:DF': 'Apple',
            '00:25:00': 'Apple',
            '00:25:4B': 'Apple',
            '00:25:BC': 'Apple',
            '00:26:08': 'Apple',
            '04:0C:CE': 'Apple',
            '04:15:52': 'Apple',
            '04:1E:64': 'Apple',
            '04:26:65': 'Apple',
            '04:4F:AA': 'Apple',
            '04:54:53': 'Apple',
            '04:69:F2': 'Apple',
            '04:DB:56': 'Apple',
            '04:E5:36': 'Apple',
            '04:F1:3E': 'Apple',
            '04:F7:E4': 'Apple',
            '08:74:02': 'Apple',
            '0C:30:21': 'Apple',
            '0C:3E:9F': 'Apple',
            '0C:4D:E9': 'Apple',
            '0C:71:5D': 'Apple',
            '0C:77:1A': 'Apple',
            '0C:D2:92': 'Apple',
            '10:40:F3': 'Apple',
            '10:9A:DD': 'Apple',
            '10:DD:B1': 'Apple',
            '14:10:9F': 'Apple',
            '14:20:5E': 'Apple',
            '14:5A:05': 'Apple'
        }
        
        # Check first 8 characters for exact match
        for oui_key, vendor in vendor_mapping.items():
            if oui.startswith(oui_key.replace(':', '')):
                return vendor
        
        return 'Unknown'
    
    @staticmethod
    def determine_device_type(network_data: Dict[str, Any]) -> str:
        """
        Determine device type based on network characteristics
        
        Args:
            network_data: Network information dictionary
            
        Returns:
            Device type string
        """
        ssid = network_data.get('ssid', '').upper()
        vendor = NetworkUtils.identify_vendor(network_data.get('bssid', ''))
        frequency = network_data.get('frequency', 0)
        
        # Router/Access Point indicators
        if any(keyword in ssid for keyword in ['ROUTER', 'AP', 'ACCESS', 'WIFI', 'WIRELESS']):
            return 'Access Point'
        
        # Mobile hotspot indicators
        if any(keyword in ssid for keyword in ['IPHONE', 'ANDROID', 'MOBILE', 'HOTSPOT']):
            return 'Mobile Hotspot'
        
        # IoT device indicators
        if any(keyword in ssid for keyword in ['IOT', 'SMART', 'NEST', 'ALEXA', 'CAMERA']):
            return 'IoT Device'
        
        # Enterprise indicators
        if any(keyword in ssid for keyword in ['CORP', 'ENTERPRISE', 'OFFICE', 'BUSINESS']):
            return 'Enterprise AP'
        
        # Default based on frequency
        if 5000 <= frequency <= 6000:
            return 'Modern Access Point'
        elif 2400 <= frequency <= 2500:
            return 'Legacy Access Point'
        
        return 'Unknown Device'
    
    @staticmethod
    def format_timestamp(timestamp) -> str:
        """
        Format timestamp for display
        
        Args:
            timestamp: Datetime object or timestamp
            
        Returns:
            Formatted timestamp string
        """
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except:
                return 'Unknown'
        
        if not isinstance(timestamp, datetime):
            return 'Unknown'
        
        now = datetime.now()
        diff = now - timestamp
        
        if diff.total_seconds() < 60:
            return 'Just now'
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() / 60)
            return f'{minutes} minute{"s" if minutes != 1 else ""} ago'
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f'{hours} hour{"s" if hours != 1 else ""} ago'
        else:
            return timestamp.strftime('%Y-%m-%d %H:%M')
    
    @staticmethod
    def calculate_network_quality(network_data: Dict[str, Any]) -> int:
        """
        Calculate overall network quality score
        
        Args:
            network_data: Network information dictionary
            
        Returns:
            Quality score (0-100)
        """
        score = 50  # Base score
        
        # Signal strength factor (40% weight)
        rssi = network_data.get('signal_strength', -100)
        signal_score = max(0, min(100, 2 * (rssi + 100)))
        score += (signal_score - 50) * 0.4
        
        # Security factor (30% weight)
        encryption = network_data.get('encryption', '').upper()
        if 'WPA3' in encryption:
            score += 15
        elif 'WPA2' in encryption:
            score += 10
        elif 'WPA' in encryption:
            score -= 10
        elif 'WEP' in encryption:
            score -= 20
        elif 'OPEN' in encryption:
            score -= 25
        
        # Frequency factor (20% weight)
        frequency = network_data.get('frequency', 0)
        if 5000 <= frequency <= 6000:
            score += 10  # 5GHz bonus
        
        # Vendor factor (10% weight)
        vendor = NetworkUtils.identify_vendor(network_data.get('bssid', ''))
        if vendor in ['Apple', 'Intel', 'Cisco']:
            score += 5
        
        return max(0, min(100, int(score)))
    
    # Private helper methods
    @staticmethod
    def _get_signal_quality_label(rssi: int) -> str:
        """Get signal quality label from RSSI"""
        if rssi >= -30:
            return 'Excellent'
        elif rssi >= -50:
            return 'Good'
        elif rssi >= -70:
            return 'Fair'
        elif rssi >= -80:
            return 'Poor'
        else:
            return 'Very Poor'
    
    @staticmethod
    def _calculate_signal_bars(rssi: int) -> int:
        """Calculate signal bars (1-4) from RSSI"""
        if rssi >= -50:
            return 4
        elif rssi >= -60:
            return 3
        elif rssi >= -70:
            return 2
        elif rssi >= -80:
            return 1
        else:
            return 0
    
    @staticmethod
    def _get_signal_color(rssi: int) -> str:
        """Get color code for signal strength"""
        if rssi >= -50:
            return 'green'
        elif rssi >= -70:
            return 'yellow'
        else:
            return 'red'
    
    @staticmethod
    def _frequency_to_channel(frequency: int) -> int:
        """Convert frequency to channel number"""
        if 2412 <= frequency <= 2484:
            return int((frequency - 2412) / 5) + 1
        elif 5000 <= frequency <= 6000:
            return int((frequency - 5000) / 5)
        return 0
    
    @staticmethod
    def _estimate_band_congestion(frequency: int) -> str:
        """Estimate band congestion level"""
        if 2400 <= frequency <= 2500:
            return 'High'  # 2.4GHz is typically congested
        elif 5000 <= frequency <= 6000:
            return 'Medium'  # 5GHz less congested
        return 'Unknown'
    
    @staticmethod
    def _get_encryption_recommendation(security_level: str) -> str:
        """Get encryption recommendation"""
        recommendations = {
            'None': 'Enable WPA3 encryption immediately',
            'Very Low': 'Upgrade from WEP to WPA3',
            'Low': 'Upgrade from WPA to WPA2/WPA3',
            'Medium': 'Consider upgrading to WPA3',
            'High': 'Encryption is secure'
        }
        return recommendations.get(security_level, 'Review encryption settings')
    
    @staticmethod
    def _get_default_network_info() -> Dict[str, Any]:
        """Get default network info structure"""
        return {
            'ssid': 'Unknown Network',
            'bssid': 'Unknown BSSID',
            'signal_strength': {'rssi_dbm': -100, 'percentage': 0, 'quality': 'Unknown'},
            'frequency': {'frequency_mhz': 0, 'band': 'Unknown'},
            'channel': 'Unknown',
            'encryption': {'type': 'Unknown', 'security_level': 'Unknown'},
            'security_protocol': 'Unknown',
            'vendor': 'Unknown',
            'device_type': 'Unknown',
            'last_seen': 'Unknown',
            'quality_score': 0
        }


class ScanUtils:
    """Scanning utility functions"""
    
    @staticmethod
    def format_scan_results(scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format scan results for display
        
        Args:
            scan_data: Raw scan results dictionary
            
        Returns:
            Formatted scan results
        """
        try:
            networks = scan_data.get('networks', [])
            formatted_networks = []
            
            for network in networks:
                formatted_network = NetworkUtils.format_network_info(network)
                formatted_networks.append(formatted_network)
            
            # Sort networks by signal strength
            formatted_networks.sort(
                key=lambda x: x.get('signal_strength', {}).get('rssi_dbm', -100),
                reverse=True
            )
            
            scan_summary = {
                'total_networks': len(formatted_networks),
                'secure_networks': len([n for n in formatted_networks 
                                      if n.get('encryption', {}).get('is_secure', False)]),
                'open_networks': len([n for n in formatted_networks 
                                    if n.get('encryption', {}).get('security_level') == 'None']),
                'average_signal_strength': ScanUtils._calculate_average_signal(formatted_networks),
                'frequency_distribution': ScanUtils._analyze_frequency_distribution(formatted_networks),
                'vendor_distribution': ScanUtils._analyze_vendor_distribution(formatted_networks),
                'scan_timestamp': datetime.now().isoformat(),
                'scan_duration': scan_data.get('scan_duration', 0)
            }
            
            return {
                'networks': formatted_networks,
                'summary': scan_summary,
                'recommendations': ScanUtils._generate_scan_recommendations(formatted_networks)
            }
            
        except Exception as e:
            current_app.logger.error(f"Error formatting scan results: {str(e)}")
            return ScanUtils._get_default_scan_results()
    
    @staticmethod
    def calculate_signal_quality(networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate signal quality metrics for networks
        
        Args:
            networks: List of network dictionaries
            
        Returns:
            Signal quality analysis
        """
        if not networks:
            return {'average': 0, 'best': 0, 'worst': 0, 'distribution': {}}
        
        signal_values = []
        for network in networks:
            signal_info = network.get('signal_strength', {})
            if isinstance(signal_info, dict):
                rssi = signal_info.get('rssi_dbm', -100)
            else:
                rssi = signal_info
            signal_values.append(rssi)
        
        quality_analysis = {
            'average': statistics.mean(signal_values) if signal_values else 0,
            'median': statistics.median(signal_values) if signal_values else 0,
            'best': max(signal_values) if signal_values else 0,
            'worst': min(signal_values) if signal_values else 0,
            'standard_deviation': statistics.stdev(signal_values) if len(signal_values) > 1 else 0,
            'distribution': ScanUtils._calculate_signal_distribution(signal_values)
        }
        
        return quality_analysis
    
    # Private helper methods
    @staticmethod
    def _calculate_average_signal(networks: List[Dict[str, Any]]) -> float:
        """Calculate average signal strength"""
        if not networks:
            return 0.0
        
        total_signal = 0
        count = 0
        
        for network in networks:
            signal_info = network.get('signal_strength', {})
            if isinstance(signal_info, dict):
                rssi = signal_info.get('rssi_dbm', -100)
                total_signal += rssi
                count += 1
        
        return total_signal / count if count > 0 else 0.0
    
    @staticmethod
    def _analyze_frequency_distribution(networks: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze frequency band distribution"""
        distribution = {'2.4 GHz': 0, '5 GHz': 0, 'Unknown': 0}
        
        for network in networks:
            freq_info = network.get('frequency', {})
            if isinstance(freq_info, dict):
                band = freq_info.get('band', 'Unknown')
                distribution[band] = distribution.get(band, 0) + 1
        
        return distribution
    
    @staticmethod
    def _analyze_vendor_distribution(networks: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze vendor distribution"""
        distribution = {}
        
        for network in networks:
            vendor = network.get('vendor', 'Unknown')
            distribution[vendor] = distribution.get(vendor, 0) + 1
        
        return dict(sorted(distribution.items(), key=lambda x: x[1], reverse=True)[:10])
    
    @staticmethod
    def _calculate_signal_distribution(signal_values: List[int]) -> Dict[str, int]:
        """Calculate signal strength distribution"""
        distribution = {
            'Excellent (-30 to 0 dBm)': 0,
            'Good (-50 to -30 dBm)': 0,
            'Fair (-70 to -50 dBm)': 0,
            'Poor (-80 to -70 dBm)': 0,
            'Very Poor (< -80 dBm)': 0
        }
        
        for signal in signal_values:
            if signal >= -30:
                distribution['Excellent (-30 to 0 dBm)'] += 1
            elif signal >= -50:
                distribution['Good (-50 to -30 dBm)'] += 1
            elif signal >= -70:
                distribution['Fair (-70 to -50 dBm)'] += 1
            elif signal >= -80:
                distribution['Poor (-80 to -70 dBm)'] += 1
            else:
                distribution['Very Poor (< -80 dBm)'] += 1
        
        return distribution
    
    @staticmethod
    def _generate_scan_recommendations(networks: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on scan results"""
        recommendations = []
        
        if not networks:
            recommendations.append("No networks detected. Check Wi-Fi adapter status.")
            return recommendations
        
        # Check for open networks
        open_networks = [n for n in networks if n.get('encryption', {}).get('security_level') == 'None']
        if open_networks:
            recommendations.append(f"Found {len(open_networks)} open network(s). Avoid connecting to unsecured networks.")
        
        # Check for weak encryption
        weak_networks = [n for n in networks if n.get('encryption', {}).get('security_level') in ['Very Low', 'Low']]
        if weak_networks:
            recommendations.append(f"Found {len(weak_networks)} network(s) with weak encryption. Consider using networks with WPA2/WPA3.")
        
        # Check signal quality
        poor_signal_networks = [n for n in networks 
                              if n.get('signal_strength', {}).get('rssi_dbm', -100) < -70]
        if poor_signal_networks:
            recommendations.append(f"{len(poor_signal_networks)} network(s) have poor signal strength. Move closer to access points for better performance.")
        
        # Check frequency distribution
        freq_dist = ScanUtils._analyze_frequency_distribution(networks)
        if freq_dist.get('2.4 GHz', 0) > freq_dist.get('5 GHz', 0) * 2:
            recommendations.append("Many 2.4GHz networks detected. Consider using 5GHz networks for better performance.")
        
        return recommendations
    
    @staticmethod
    def _get_default_scan_results() -> Dict[str, Any]:
        """Get default scan results structure"""
        return {
            'networks': [],
            'summary': {
                'total_networks': 0,
                'secure_networks': 0,
                'open_networks': 0,
                'average_signal_strength': 0,
                'frequency_distribution': {},
                'vendor_distribution': {},
                'scan_timestamp': datetime.now().isoformat(),
                'scan_duration': 0
            },
            'recommendations': ['No scan data available']
        }


class ReportUtils:
    """Report utility functions"""
    
    @staticmethod
    def generate_recommendations(vulnerability_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate security recommendations based on vulnerability data
        
        Args:
            vulnerability_data: Vulnerability analysis results
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        try:
            # Analyze risk level
            risk_level = vulnerability_data.get('risk_level', 'UNKNOWN')
            threats = vulnerability_data.get('threats', [])
            network_info = vulnerability_data.get('network_info', {})
            
            # High priority recommendations based on risk level
            if risk_level == 'HIGH_RISK':
                recommendations.append({
                    'priority': 'Critical',
                    'category': 'Immediate Action',
                    'title': 'Critical Security Vulnerabilities Detected',
                    'description': 'Multiple high-risk vulnerabilities found that require immediate attention.',
                    'actions': [
                        'Disconnect from this network immediately',
                        'Contact network administrator',
                        'Run additional security scans',
                        'Consider using VPN if connection is necessary'
                    ],
                    'severity': 'high',
                    'impact': 'Network compromise, data theft, credential exposure'
                })
            
            # Threat-specific recommendations
            for threat in threats:
                threat_type = threat.get('type', '')
                confidence = threat.get('confidence', 0)
                
                if confidence > 0.8:  # High confidence threats
                    if 'WEAK_ENCRYPTION' in threat_type:
                        recommendations.append({
                            'priority': 'High',
                            'category': 'Encryption',
                            'title': 'Weak Encryption Detected',
                            'description': 'Network uses outdated or weak encryption protocols.',
                            'actions': [
                                'Avoid connecting to networks with WEP encryption',
                                'Prefer networks with WPA3 encryption',
                                'Use VPN for additional security layer'
                            ],
                            'severity': 'medium',
                            'impact': 'Data interception, password cracking'
                        })
                    
                    elif 'OPEN_NETWORK' in threat_type:
                        recommendations.append({
                            'priority': 'High',
                            'category': 'Network Security',
                            'title': 'Open Network Detected',
                            'description': 'Network has no encryption protection.',
                            'actions': [
                                'Avoid transmitting sensitive data',
                                'Use HTTPS websites only',
                                'Enable VPN before connecting',
                                'Disable file sharing'
                            ],
                            'severity': 'high',
                            'impact': 'Complete data exposure, man-in-the-middle attacks'
                        })
                    
                    elif 'ROGUE_AP' in threat_type:
                        recommendations.append({
                            'priority': 'Critical',
                            'category': 'Malicious Activity',
                            'title': 'Rogue Access Point Detected',
                            'description': 'Potentially malicious access point mimicking legitimate network.',
                            'actions': [
                                'Do not connect to this network',
                                'Report to network administrator',
                                'Verify legitimate network details',
                                'Enable network verification'
                            ],
                            'severity': 'critical',
                            'impact': 'Credential theft, data interception, malware installation'
                        })
                    
                    elif 'EVIL_TWIN' in threat_type:
                        recommendations.append({
                            'priority': 'Critical',
                            'category': 'Malicious Activity',
                            'title': 'Evil Twin Attack Detected',
                            'description': 'Malicious access point impersonating legitimate network.',
                            'actions': [
                                'Disconnect immediately if connected',
                                'Change passwords for any accounts accessed',
                                'Run malware scan on device',
                                'Report incident to security team'
                            ],
                            'severity': 'critical',
                            'impact': 'Complete credential compromise, session hijacking'
                        })
                    
                    elif 'DEAUTH_ATTACK' in threat_type:
                        recommendations.append({
                            'priority': 'High',
                            'category': 'Network Attack',
                            'title': 'Deauthentication Attack Detected',
                            'description': 'Active attack attempting to disconnect clients.',
                            'actions': [
                                'Switch to different network if available',
                                'Enable 802.11w (PMF) if supported',
                                'Monitor for continued attacks',
                                'Consider wired connection'
                            ],
                            'severity': 'medium',
                            'impact': 'Service disruption, potential credential capture'
                        })
            
            # Network configuration recommendations
            encryption_info = network_info.get('encryption', {})
            if isinstance(encryption_info, dict):
                security_level = encryption_info.get('security_level', 'Unknown')
                
                if security_level in ['Very Low', 'Low']:
                    recommendations.append({
                        'priority': 'Medium',
                        'category': 'Configuration',
                        'title': 'Upgrade Network Security',
                        'description': f'Network uses {security_level.lower()} security configuration.',
                        'actions': [
                            'Contact administrator to upgrade to WPA3',
                            'Enable additional security features',
                            'Implement network segmentation',
                            'Regular security audits'
                        ],
                        'severity': 'medium',
                        'impact': 'Increased vulnerability to attacks'
                    })
            
            # Signal strength recommendations
            signal_info = network_info.get('signal_strength', {})
            if isinstance(signal_info, dict):
                rssi = signal_info.get('rssi_dbm', -100)
                if rssi < -70:
                    recommendations.append({
                        'priority': 'Low',
                        'category': 'Performance',
                        'title': 'Poor Signal Strength',
                        'description': 'Weak signal may impact security and performance.',
                        'actions': [
                            'Move closer to access point',
                            'Check for physical obstructions',
                            'Consider signal boosters',
                            'Switch to 5GHz if available'
                        ],
                        'severity': 'low',
                        'impact': 'Reduced performance, increased vulnerability'
                    })
            
            # General security recommendations
            recommendations.append({
                'priority': 'Medium',
                'category': 'Best Practices',
                'title': 'General Security Measures',
                'description': 'Recommended security practices for Wi-Fi usage.',
                'actions': [
                    'Keep device software updated',
                    'Use strong, unique passwords',
                    'Enable automatic security updates',
                    'Regularly review connected networks',
                    'Use reputable VPN service'
                ],
                'severity': 'low',
                'impact': 'Improved overall security posture'
            })
            
            # Sort recommendations by priority
            priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            recommendations.sort(key=lambda x: priority_order.get(x['priority'], 999))
            
            return recommendations
            
        except Exception as e:
            current_app.logger.error(f"Error generating recommendations: {str(e)}")
            return ReportUtils._get_default_recommendations()
    
    @staticmethod
    def create_network_graph(topology_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create network topology graph for visualization
        
        Args:
            topology_data: Network topology data
            
        Returns:
            Graph data structure for visualization
        """
        try:
            # Create NetworkX graph
            G = nx.Graph()
            
            # Add nodes from topology data
            devices = topology_data.get('devices', [])
            connections = topology_data.get('connections', [])
            
            # Add device nodes
            for device in devices:
                device_id = device.get('id', f"device_{len(G.nodes)}")
                device_type = device.get('type', 'unknown')
                device_name = device.get('name', device_id)
                
                G.add_node(device_id, 
                          name=device_name,
                          type=device_type,
                          security_level=device.get('security_level', 'unknown'),
                          risk_score=device.get('risk_score', 0),
                          ip_address=device.get('ip_address', 'unknown'),
                          mac_address=device.get('mac_address', 'unknown'))
            
            # Add connections (edges)
            for connection in connections:
                source = connection.get('source')
                target = connection.get('target')
                if source and target and G.has_node(source) and G.has_node(target):
                    G.add_edge(source, target,
                              connection_type=connection.get('type', 'unknown'),
                              strength=connection.get('strength', 1.0),
                              security=connection.get('security', 'unknown'))
            
            # Calculate graph metrics
            graph_metrics = ReportUtils._calculate_graph_metrics(G)
            
            # Generate layout positions
            pos = nx.spring_layout(G, k=1, iterations=50)
            
            # Convert to visualization format
            nodes_data = []
            for node_id, node_data in G.nodes(data=True):
                node_info = {
                    'id': node_id,
                    'name': node_data.get('name', node_id),
                    'type': node_data.get('type', 'unknown'),
                    'security_level': node_data.get('security_level', 'unknown'),
                    'risk_score': node_data.get('risk_score', 0),
                    'x': pos[node_id][0] * 500 + 250,  # Scale and center
                    'y': pos[node_id][1] * 500 + 250,
                    'size': ReportUtils._calculate_node_size(node_data),
                    'color': ReportUtils._get_node_color(node_data),
                    'details': {
                        'ip_address': node_data.get('ip_address', 'unknown'),
                        'mac_address': node_data.get('mac_address', 'unknown'),
                        'connections': len(list(G.neighbors(node_id)))
                    }
                }
                nodes_data.append(node_info)
            
            edges_data = []
            for source, target, edge_data in G.edges(data=True):
                edge_info = {
                    'source': source,
                    'target': target,
                    'type': edge_data.get('connection_type', 'unknown'),
                    'strength': edge_data.get('strength', 1.0),
                    'security': edge_data.get('security', 'unknown'),
                    'width': max(1, edge_data.get('strength', 1.0) * 3),
                    'color': ReportUtils._get_edge_color(edge_data)
                }
                edges_data.append(edge_info)
            
            return {
                'nodes': nodes_data,
                'edges': edges_data,
                'metrics': graph_metrics,
                'layout': 'spring',
                'total_nodes': len(nodes_data),
                'total_edges': len(edges_data)
            }
            
        except Exception as e:
            current_app.logger.error(f"Error creating network graph: {str(e)}")
            return ReportUtils._get_default_graph()
    
    @staticmethod
    def determine_security_level(vulnerability_data: Dict[str, Any]) -> str:
        """
        Determine overall security level based on vulnerability data
        
        Args:
            vulnerability_data: Vulnerability analysis results
            
        Returns:
            Security level string ('HIGH_RISK', 'LOW_RISK', 'NORMAL')
        """
        try:
            # Check AI model predictions
            model_predictions = vulnerability_data.get('model_predictions', {})
            ensemble_result = model_predictions.get('ensemble_prediction', {})
            
            if ensemble_result:
                predicted_class = ensemble_result.get('predicted_class', '')
                confidence = ensemble_result.get('confidence', 0)
                
                # High confidence critical threats
                if confidence > 0.9 and any(threat in predicted_class for threat in [
                    'CRITICAL_VULNERABILITY', 'ACTIVE_ATTACK_DETECTED', 
                    'NETWORK_COMPROMISE', 'SYSTEM_COMPROMISE'
                ]):
                    return 'HIGH_RISK'
                
                # Medium-high confidence serious threats
                if confidence > 0.8 and any(threat in predicted_class for threat in [
                    'HIGH_RISK_VULNERABILITY', 'CREDENTIAL_COMPROMISE',
                    'DATA_BREACH_RISK', 'APT_CAMPAIGN'
                ]):
                    return 'HIGH_RISK'
                
                # Lower severity threats
                if confidence > 0.7 and any(threat in predicted_class for threat in [
                    'MEDIUM_RISK_VULNERABILITY', 'LOW_RISK_VULNERABILITY',
                    'CONFIGURATION_ERROR', 'COMPLIANCE_VIOLATION'
                ]):
                    return 'LOW_RISK'
            
            # Check individual model predictions
            individual_predictions = model_predictions.get('individual_models', {})
            high_risk_count = 0
            total_models = len(individual_predictions)
            
            for model_name, prediction in individual_predictions.items():
                if isinstance(prediction, dict):
                    pred_class = prediction.get('predicted_class', '')
                    confidence = prediction.get('confidence', 0)
                    
                    if confidence > 0.8:
                        # CNN model threats
                        if 'cnn' in model_name.lower() and any(threat in pred_class for threat in [
                            'ROGUE_AP', 'EVIL_TWIN', 'DEAUTH_ATTACK', 'HANDSHAKE_CAPTURE'
                        ]):
                            high_risk_count += 1
                        
                        # LSTM model threats
                        elif 'lstm' in model_name.lower() and any(threat in pred_class for threat in [
                            'BRUTE_FORCE_ATTACK', 'DATA_EXFILTRATION', 'APT_BEHAVIOR'
                        ]):
                            high_risk_count += 1
                        
                        # GNN model threats
                        elif 'gnn' in model_name.lower() and any(threat in pred_class for threat in [
                            'CASCADING_RISK', 'CRITICAL_NODE', 'PRIVILEGE_ESCALATION'
                        ]):
                            high_risk_count += 1
                        
                        # Crypto-BERT threats
                        elif 'bert' in model_name.lower() and any(threat in pred_class for threat in [
                            'WEAK_CIPHER_SUITE', 'MAN_IN_MIDDLE', 'CERTIFICATE_INVALID'
                        ]):
                            high_risk_count += 1
            
            # Calculate risk ratio
            if total_models > 0:
                risk_ratio = high_risk_count / total_models
                if risk_ratio >= 0.5:
                    return 'HIGH_RISK'
                elif risk_ratio >= 0.2:
                    return 'LOW_RISK'
            
            # Check network-level indicators
            network_info = vulnerability_data.get('network_info', {})
            
            # Open network is high risk
            encryption_info = network_info.get('encryption', {})
            if isinstance(encryption_info, dict):
                security_level = encryption_info.get('security_level', 'Unknown')
                if security_level == 'None':
                    return 'HIGH_RISK'
                elif security_level in ['Very Low', 'Low']:
                    return 'LOW_RISK'
            
            # Check for specific threats
            threats = vulnerability_data.get('threats', [])
            for threat in threats:
                threat_type = threat.get('type', '')
                confidence = threat.get('confidence', 0)
                
                if confidence > 0.8 and any(high_risk_threat in threat_type for high_risk_threat in [
                    'ROGUE_AP', 'EVIL_TWIN', 'ACTIVE_ATTACK', 'CREDENTIAL_COMPROMISE'
                ]):
                    return 'HIGH_RISK'
            
            return 'NORMAL'
            
        except Exception as e:
            current_app.logger.error(f"Error determining security level: {str(e)}")
            return 'UNKNOWN'
    
    # Private helper methods
    @staticmethod
    def _calculate_graph_metrics(G) -> Dict[str, Any]:
        """Calculate graph topology metrics"""
        try:
            metrics = {
                'total_nodes': G.number_of_nodes(),
                'total_edges': G.number_of_edges(),
                'density': nx.density(G) if G.number_of_nodes() > 1 else 0,
                'average_clustering': nx.average_clustering(G) if G.number_of_nodes() > 2 else 0,
                'connected_components': nx.number_connected_components(G),
                'diameter': 0,
                'average_path_length': 0
            }
            
            # Calculate diameter and average path length for connected graphs
            if nx.is_connected(G) and G.number_of_nodes() > 1:
                metrics['diameter'] = nx.diameter(G)
                metrics['average_path_length'] = nx.average_shortest_path_length(G)
            
            return metrics
            
        except Exception as e:
            current_app.logger.error(f"Error calculating graph metrics: {str(e)}")
            return {'total_nodes': 0, 'total_edges': 0, 'density': 0}
    
    @staticmethod
    def _calculate_node_size(node_data: Dict[str, Any]) -> int:
        """Calculate node size based on importance"""
        base_size = 20
        risk_score = node_data.get('risk_score', 0)
        node_type = node_data.get('type', 'unknown').lower()
        
        # Adjust size based on risk score
        size_adjustment = risk_score * 0.3
        
        # Adjust size based on node type
        if 'router' in node_type or 'gateway' in node_type:
            size_adjustment += 10
        elif 'server' in node_type:
            size_adjustment += 8
        elif 'access' in node_type:
            size_adjustment += 5
        
        return int(base_size + size_adjustment)
    
    @staticmethod
    def _get_node_color(node_data: Dict[str, Any]) -> str:
        """Get node color based on security level"""
        security_level = node_data.get('security_level', 'unknown').lower()
        risk_score = node_data.get('risk_score', 0)
        
        if security_level == 'critical' or risk_score > 80:
            return '#ff4444'  # Red
        elif security_level == 'high' or risk_score > 60:
            return '#ff8800'  # Orange
        elif security_level == 'medium' or risk_score > 40:
            return '#ffaa00'  # Yellow
        elif security_level == 'low' or risk_score > 20:
            return '#88ff88'  # Light green
        else:
            return '#44ff44'  # Green
    
    @staticmethod
    def _get_edge_color(edge_data: Dict[str, Any]) -> str:
        """Get edge color based on connection security"""
        security = edge_data.get('security', 'unknown').lower()
        
        if security in ['encrypted', 'secure', 'wpa3']:
            return '#44aa44'  # Green
        elif security in ['wpa2', 'wpa']:
            return '#aaaa44'  # Yellow
        elif security in ['wep', 'weak']:
            return '#aa4444'  # Red
        elif security in ['open', 'none']:
            return '#ff0000'  # Bright red
        else:
            return '#888888'  # Gray
    
    @staticmethod
    def _get_default_recommendations() -> List[Dict[str, Any]]:
        """Get default recommendations when analysis fails"""
        return [{
            'priority': 'Medium',
            'category': 'General',
            'title': 'Basic Security Measures',
            'description': 'Unable to perform detailed analysis. Follow basic security practices.',
            'actions': [
                'Use networks with WPA2/WPA3 encryption',
                'Avoid open networks for sensitive activities',
                'Keep device software updated',
                'Use VPN when possible'
            ],
            'severity': 'medium',
            'impact': 'General security improvement'
        }]
    
    @staticmethod
    def _get_default_graph() -> Dict[str, Any]:
        """Get default graph structure when creation fails"""
        return {
            'nodes': [],
            'edges': [],
            'metrics': {'total_nodes': 0, 'total_edges': 0, 'density': 0},
            'layout': 'spring',
            'total_nodes': 0,
            'total_edges': 0
        }


# Additional utility functions for the main application

def calculate_risk_summary(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate overall risk summary from scan results
    
    Args:
        scan_results: Complete scan results dictionary
        
    Returns:
        Risk summary dictionary
    """
    try:
        networks = scan_results.get('networks', [])
        if not networks:
            return {
                'overall_risk': 'UNKNOWN',
                'risk_score': 0,
                'total_networks': 0,
                'high_risk_networks': 0,
                'medium_risk_networks': 0,
                'low_risk_networks': 0,
                'secure_networks': 0
            }
        
        risk_scores = []
        risk_categories = {'HIGH_RISK': 0, 'LOW_RISK': 0, 'NORMAL': 0}
        
        for network in networks:
            # Calculate individual network risk
            network_risk = _calculate_network_risk(network)
            risk_scores.append(network_risk['score'])
            risk_categories[network_risk['category']] += 1
        
        # Calculate overall metrics
        average_risk_score = statistics.mean(risk_scores) if risk_scores else 0
        max_risk_score = max(risk_scores) if risk_scores else 0
        
        # Determine overall risk level
        if max_risk_score >= 80 or risk_categories['HIGH_RISK'] > 0:
            overall_risk = 'HIGH_RISK'
        elif average_risk_score >= 40 or risk_categories['LOW_RISK'] > len(networks) * 0.3:
            overall_risk = 'LOW_RISK'
        else:
            overall_risk = 'NORMAL'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': int(average_risk_score),
            'max_risk_score': int(max_risk_score),
            'total_networks': len(networks),
            'high_risk_networks': risk_categories['HIGH_RISK'],
            'medium_risk_networks': risk_categories['LOW_RISK'],
            'low_risk_networks': risk_categories['NORMAL'],
            'secure_networks': len([n for n in networks 
                                  if n.get('encryption', {}).get('is_secure', False)]),
            'risk_distribution': risk_categories
        }
        
    except Exception as e:
        current_app.logger.error(f"Error calculating risk summary: {str(e)}")
        return {
            'overall_risk': 'UNKNOWN',
            'risk_score': 0,
            'total_networks': 0,
            'high_risk_networks': 0,
            'medium_risk_networks': 0,
            'low_risk_networks': 0,
            'secure_networks': 0
        }


def _calculate_network_risk(network: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate risk for individual network
    
    Args:
        network: Network information dictionary
        
    Returns:
        Risk assessment dictionary
    """
    risk_score = 0
    risk_factors = []
    
    # Encryption risk
    encryption_info = network.get('encryption', {})
    if isinstance(encryption_info, dict):
        security_level = encryption_info.get('security_level', 'Unknown')
        if security_level == 'None':
            risk_score += 40
            risk_factors.append('Open network')
        elif security_level == 'Very Low':
            risk_score += 30
            risk_factors.append('WEP encryption')
        elif security_level == 'Low':
            risk_score += 20
            risk_factors.append('WPA encryption')
        elif security_level == 'Medium':
            risk_score += 5
            risk_factors.append('WPA2 encryption')
    
    # Signal strength risk
    signal_info = network.get('signal_strength', {})
    if isinstance(signal_info, dict):
        rssi = signal_info.get('rssi_dbm', -100)
        if rssi < -80:
            risk_score += 5
            risk_factors.append('Poor signal strength')
    
    # Vendor risk
    vendor = network.get('vendor', 'Unknown')
    if vendor == 'Unknown':
        risk_score += 10
        risk_factors.append('Unknown vendor')
    
    # Device type risk
    device_type = network.get('device_type', 'Unknown')
    if 'Mobile Hotspot' in device_type:
        risk_score += 15
        risk_factors.append('Mobile hotspot')
    elif 'IoT Device' in device_type:
        risk_score += 10
        risk_factors.append('IoT device')
    
    # Determine risk category
    if risk_score >= 60:
        risk_category = 'HIGH_RISK'
    elif risk_score >= 20:
        risk_category = 'LOW_RISK'
    else:
        risk_category = 'NORMAL'
    
    return {
        'score': min(100, risk_score),
        'category': risk_category,
        'factors': risk_factors
    }