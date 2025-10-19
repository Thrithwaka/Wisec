"""
Wi-Fi Core Scanner Module
Purpose: Wi-Fi network discovery and information gathering

This module implements comprehensive Wi-Fi network scanning functionality
as specified in the Wi-Fi Security System documentation.
"""

import platform
import subprocess
import re
import json
import time
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import logging
from collections import defaultdict
import socket
import struct
import os

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class NetworkInfo:
    """Network information container as specified in the documentation"""
    ssid: str
    bssid: str
    signal_strength: int
    frequency: int
    channel: int
    encryption_type: str
    cipher_suite: str
    authentication: str
    vendor: str
    device_type: str
    is_hidden: bool
    beacon_interval: int
    capabilities: List[str]
    country_code: str
    quality: float
    noise_level: int
    snr: float
    bandwidth: str
    mode: str
    rates: List[str]
    last_seen: float
    
    def to_dict(self) -> Dict:
        """Convert NetworkInfo to dictionary"""
        return asdict(self)

class SignalProcessor:
    """Signal processing and analysis class"""
    
    def __init__(self):
        self.signal_history = defaultdict(list)
    
    def calculate_signal_quality(self, rssi: int, noise: int = -95) -> float:
        """
        Calculate signal quality percentage based on RSSI and noise floor
        
        Args:
            rssi: Received Signal Strength Indicator
            noise: Noise floor level (default: -95 dBm)
            
        Returns:
            Signal quality as percentage (0-100)
        """
        try:
            # Calculate SNR (Signal-to-Noise Ratio)
            snr = rssi - noise
            
            # Convert to quality percentage
            if rssi >= -50:
                quality = 100
            elif rssi >= -60:
                quality = 90 - ((rssi + 50) * 10 / 10)
            elif rssi >= -70:
                quality = 80 - ((rssi + 60) * 20 / 10)
            elif rssi >= -80:
                quality = 60 - ((rssi + 70) * 30 / 10)
            elif rssi >= -90:
                quality = 30 - ((rssi + 80) * 30 / 10)
            else:
                quality = max(0, 10 - ((rssi + 90) * 10 / 10))
            
            return min(100, max(0, quality))
        except Exception as e:
            logger.error(f"Error calculating signal quality: {e}")
            return 0.0
    
    def calculate_snr(self, signal: int, noise: int = -95) -> float:
        """Calculate Signal-to-Noise Ratio"""
        return float(signal - noise)
    
    def update_signal_history(self, bssid: str, signal: int):
        """Update signal strength history for trending"""
        self.signal_history[bssid].append({
            'timestamp': time.time(),
            'signal': signal
        })
        
        # Keep only last 10 measurements
        if len(self.signal_history[bssid]) > 10:
            self.signal_history[bssid] = self.signal_history[bssid][-10:]
    
    def get_signal_trend(self, bssid: str) -> str:
        """Get signal strength trend for a BSSID"""
        history = self.signal_history.get(bssid, [])
        if len(history) < 3:
            return 'stable'
        
        recent_signals = [entry['signal'] for entry in history[-3:]]
        if recent_signals[-1] > recent_signals[0] + 5:
            return 'improving'
        elif recent_signals[-1] < recent_signals[0] - 5:
            return 'degrading'
        else:
            return 'stable'

class ChannelAnalyzer:
    """Channel usage analysis class"""
    
    def __init__(self):
        self.channel_usage = defaultdict(list)
        self.band_info = {
            '2.4GHz': list(range(1, 15)),
            '5GHz': [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 
                    116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165],
            '6GHz': list(range(1, 234, 4))  # 6GHz channels
        }
    
    def frequency_to_channel(self, frequency: int) -> int:
        """Convert frequency to channel number"""
        if 2412 <= frequency <= 2484:
            # 2.4 GHz band
            if frequency == 2484:
                return 14
            return (frequency - 2412) // 5 + 1
        elif 5170 <= frequency <= 5825:
            # 5 GHz band
            return (frequency - 5000) // 5
        elif 5955 <= frequency <= 7115:
            # 6 GHz band
            return (frequency - 5950) // 5
        else:
            return 0
    
    def get_band_from_frequency(self, frequency: int) -> str:
        """Determine band from frequency"""
        if 2412 <= frequency <= 2484:
            return '2.4GHz'
        elif 5170 <= frequency <= 5825:
            return '5GHz'
        elif 5955 <= frequency <= 7115:
            return '6GHz'
        else:
            return 'Unknown'
    
    def analyze_channel_utilization(self, networks: List[NetworkInfo]) -> Dict:
        """Analyze channel utilization across discovered networks"""
        channel_stats = defaultdict(int)
        band_stats = defaultdict(int)
        congestion_map = defaultdict(list)
        
        for network in networks:
            channel_stats[network.channel] += 1
            band = self.get_band_from_frequency(network.frequency)
            band_stats[band] += 1
            congestion_map[network.channel].append({
                'ssid': network.ssid,
                'bssid': network.bssid,
                'signal_strength': network.signal_strength
            })
        
        return {
            'channel_distribution': dict(channel_stats),
            'band_distribution': dict(band_stats),
            'congested_channels': [ch for ch, count in channel_stats.items() if count > 3],
            'recommended_channels': self._get_recommended_channels(channel_stats),
            'channel_congestion_details': dict(congestion_map),
            'interference_analysis': self._analyze_interference(networks)
        }
    
    def _get_recommended_channels(self, channel_stats: Dict) -> List[int]:
        """Get recommended channels with least congestion"""
        # For 2.4GHz, recommend non-overlapping channels (1, 6, 11)
        non_overlapping_24 = [1, 6, 11]
        recommended = []
        
        for channel in non_overlapping_24:
            if channel_stats.get(channel, 0) < 2:
                recommended.append(channel)
        
        # For 5GHz, find channels with minimal usage
        for channel in self.band_info['5GHz'][:5]:  # Check first 5 5GHz channels
            if channel_stats.get(channel, 0) == 0:
                recommended.append(channel)
        
        return recommended[:3]  # Return top 3 recommendations
    
    def _analyze_interference(self, networks: List[NetworkInfo]) -> Dict:
        """Analyze potential interference between networks"""
        interference_analysis = {}
        channel_groups = defaultdict(list)
        
        # Group networks by channel
        for network in networks:
            channel_groups[network.channel].append(network)
        
        # Check for interference
        for channel, nets in channel_groups.items():
            if len(nets) > 1:
                # Calculate potential interference
                strong_signals = [n for n in nets if n.signal_strength > -60]
                interference_analysis[channel] = {
                    'network_count': len(nets),
                    'strong_signal_count': len(strong_signals),
                    'interference_level': 'high' if len(strong_signals) > 2 else 'medium' if len(strong_signals) > 1 else 'low',
                    'networks': [{'ssid': n.ssid, 'bssid': n.bssid, 'signal': n.signal_strength} for n in nets]
                }
        
        return interference_analysis

class NetworkDiscovery:
    """Network discovery system class"""
    
    def __init__(self, signal_processor: SignalProcessor, channel_analyzer: ChannelAnalyzer):
        self.signal_processor = signal_processor
        self.channel_analyzer = channel_analyzer
        self.vendor_db = self._load_vendor_database()
    
    def _load_vendor_database(self) -> Dict[str, str]:
        """Load MAC address vendor database (OUI lookup)"""
        # Extended vendor database for better device identification
        return {
            # Major networking vendors
            '00:00:5E': 'IEEE Registration Authority',
            '00:01:42': 'Cisco Systems',
            '00:03:7F': 'Atheros Communications',
            '00:0A:F5': 'Airspan Communications',
            '00:0F:66': 'Proxim Corporation',
            '00:11:50': 'Cisco Systems',
            '00:13:10': 'Linksys',
            '00:14:BF': 'Cisco Systems',
            '00:15:6D': 'Cisco Systems',
            '00:16:B6': 'Cisco Systems',
            '00:18:0A': 'Cisco Systems',
            '00:19:30': 'Cisco Systems',
            '00:1A:2F': 'Cisco Systems',
            '00:1B:0D': 'Cisco Systems',
            '00:1C:0E': 'Cisco Systems',
            '00:1D:70': 'Cisco Systems',
            '00:1E:13': 'Cisco Systems',
            '00:1F:6C': 'Cisco Systems',
            '00:21:1B': 'Cisco Systems',
            '00:22:90': 'Cisco Systems',
            '00:23:04': 'Cisco Systems',
            '00:24:13': 'Cisco Systems',
            '00:25:45': 'Cisco Systems',
            '00:26:08': 'Cisco Systems',
            
            # Consumer devices
            '00:50:56': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            'AC:DE:48': 'Intel Corporate',
            'B8:27:EB': 'Raspberry Pi Foundation',
            'DC:A6:32': 'Raspberry Pi Trading',
            
            # Mobile devices
            '00:1F:5B': 'Apple Inc',
            '00:25:00': 'Apple Inc',
            '28:CF:E9': 'Apple Inc',
            '3C:15:FB': 'Apple Inc',
            '40:A6:D9': 'Apple Inc',
            '58:B0:35': 'Apple Inc',
            '70:CD:60': 'Apple Inc',
            '78:4F:43': 'Apple Inc',
            '80:E6:50': 'Apple Inc',
            '84:38:35': 'Apple Inc',
            '88:63:DF': 'Apple Inc',
            '8C:58:77': 'Apple Inc',
            '90:72:40': 'Apple Inc',
            '98:FE:94': 'Apple Inc',
            'A4:5E:60': 'Apple Inc',
            'A8:86:DD': 'Apple Inc',
            'AC:87:A3': 'Apple Inc',
            'BC:52:B7': 'Apple Inc',
            'C8:BC:C8': 'Apple Inc',
            'C8:E0:EB': 'Apple Inc',
            'CC:25:EF': 'Apple Inc',
            'D0:A6:37': 'Apple Inc',
            'D4:9A:20': 'Apple Inc',
            'D8:30:62': 'Apple Inc',
            'DC:56:E7': 'Apple Inc',
            'E0:B9:BA': 'Apple Inc',
            'E4:8B:7F': 'Apple Inc',
            'E8:8D:28': 'Apple Inc',
            'EC:35:86': 'Apple Inc',
            'F0:D1:A9': 'Apple Inc',
            'F4:5C:89': 'Apple Inc',
            'F8:27:93': 'Apple Inc',
            'FC:25:3F': 'Apple Inc',
            
            # Samsung
            '00:12:FB': 'Samsung Electronics',
            '00:15:99': 'Samsung Electronics',
            '00:16:32': 'Samsung Electronics',
            '00:17:C9': 'Samsung Electronics',
            '00:18:AF': 'Samsung Electronics',
            '00:1A:8A': 'Samsung Electronics',
            '00:1B:98': 'Samsung Electronics',
            '00:1D:25': 'Samsung Electronics',
            '00:1E:7D': 'Samsung Electronics',
            '00:21:19': 'Samsung Electronics',
            '00:23:39': 'Samsung Electronics',
            '00:26:37': 'Samsung Electronics',
            
            # Router manufacturers
            '00:90:A9': 'Western Digital',
            '00:14:D1': 'TRENDnet',
            '00:1E:58': 'WistronNeweb Corporation',
            '00:26:62': 'ASRock Incorporation',
            '20:4E:7F': 'NetComm Wireless',
            '30:85:A9': 'Netgear',
            '84:1B:5E': 'Netgear',
            'A0:21:B7': 'Netgear',
            'C0:3F:0E': 'Netgear',
            '00:09:5B': 'Netgear',
            '00:0F:B5': 'Netgear',
            '00:14:6C': 'Netgear',
            '00:18:4D': 'Netgear',
            '00:1B:2F': 'Netgear',
            '00:1E:2A': 'Netgear',
            '00:22:3F': 'Netgear',
            '00:24:B2': 'Netgear',
            '00:26:F2': 'Netgear',
            '04:A1:51': 'Netgear',
            '08:BD:43': 'Netgear',
            '20:E5:2A': 'Netgear',
            '28:C6:8E': 'Netgear',
            '2C:30:33': 'Netgear',
            '44:94:FC': 'Netgear',
            '6C:CD:D6': 'Netgear',
            '74:44:01': 'Netgear',
            '9C:3D:CF': 'Netgear',
            'A0:04:60': 'Netgear',
            'E0:46:9A': 'Netgear',
            'E0:91:F5': 'Netgear',
            
            # TP-Link
            '00:27:19': 'TP-LINK Technologies',
            '14:CF:92': 'TP-LINK Technologies',
            '50:C7:BF': 'TP-LINK Technologies',
            '64:70:02': 'TP-LINK Technologies',
            '98:DE:D0': 'TP-LINK Technologies',
            'C0:25:E9': 'TP-LINK Technologies',
            'E8:DE:27': 'TP-LINK Technologies',
            'F4:EC:38': 'TP-LINK Technologies',
            
            # ASUS
            '00:15:F2': 'ASUSTeK Computer',
            '00:1F:C6': 'ASUSTeK Computer',
            '00:22:15': 'ASUSTeK Computer',
            '00:24:8C': 'ASUSTeK Computer',
            '00:26:18': 'ASUSTeK Computer',
            '20:CF:30': 'ASUSTeK Computer',
            '2C:56:DC': 'ASUSTeK Computer',
            '30:5A:3A': 'ASUSTeK Computer',
            '38:D5:47': 'ASUSTeK Computer',
            '40:16:7E': 'ASUSTeK Computer',
            '50:46:5D': 'ASUSTeK Computer',
            '54:04:A6': 'ASUSTeK Computer',
            '60:45:CB': 'ASUSTeK Computer',
            '70:8B:CD': 'ASUSTeK Computer',
            '74:D0:2B': 'ASUSTeK Computer',
            '88:D7:F6': 'ASUSTeK Computer',
            '9C:5C:8E': 'ASUSTeK Computer',
            'AC:9E:17': 'ASUSTeK Computer',
            'BC:EE:7B': 'ASUSTeK Computer',
            'D0:17:C2': 'ASUSTeK Computer',
            'E0:3F:49': 'ASUSTeK Computer',
            'F0:79:59': 'ASUSTeK Computer',
            
            # D-Link
            '00:05:5D': 'D-Link Corporation',
            '00:0D:88': 'D-Link Corporation',
            '00:0F:3D': 'D-Link Corporation',
            '00:11:95': 'D-Link Corporation',
            '00:13:46': 'D-Link Corporation',
            '00:15:E9': 'D-Link Corporation',
            '00:17:9A': 'D-Link Corporation',
            '00:19:5B': 'D-Link Corporation',
            '00:1B:11': 'D-Link Corporation',
            '00:1C:F0': 'D-Link Corporation',
            '00:1E:58': 'D-Link Corporation',
            '00:21:91': 'D-Link Corporation',
            '00:22:B0': 'D-Link Corporation',
            '00:24:01': 'D-Link Corporation',
            '00:26:5A': 'D-Link Corporation',
            '14:D6:4D': 'D-Link Corporation',
            '1C:7E:E5': 'D-Link Corporation',
            '20:CF:30': 'D-Link Corporation',
            '28:10:7B': 'D-Link Corporation',
            '34:08:04': 'D-Link Corporation',
            '5C:D9:98': 'D-Link Corporation',
            '84:C9:B2': 'D-Link Corporation',
            '90:94:E4': 'D-Link Corporation',
            'B0:C7:45': 'D-Link Corporation',
            'C8:D3:A3': 'D-Link Corporation',
            'CC:B2:55': 'D-Link Corporation',
            'E4:6F:13': 'D-Link Corporation',
            'F0:7D:68': 'D-Link Corporation'
        }
    
    def identify_vendor(self, bssid: str) -> str:
        """Identify device vendor from MAC address"""
        if not bssid or len(bssid) < 8:
            return 'Unknown'
        
        # Extract OUI (first 3 octets)
        oui = bssid[:8].upper().replace(':', '')
        oui_formatted = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
        
        return self.vendor_db.get(oui_formatted, 'Unknown')
    
    def determine_device_type(self, capabilities: List[str], vendor: str, ssid: str = '') -> str:
        """Determine device type based on capabilities, vendor, and SSID"""
        capabilities_str = ' '.join(capabilities).lower()
        vendor_lower = vendor.lower()
        ssid_lower = ssid.lower()
        
        # IoT device detection
        iot_keywords = ['raspberry', 'arduino', 'esp', 'iot', 'sensor', 'camera']
        if any(keyword in vendor_lower for keyword in iot_keywords):
            return 'IoT Device'
        
        # Smart home device detection
        smart_keywords = ['nest', 'ring', 'echo', 'alexa', 'google', 'philips']
        if any(keyword in ssid_lower for keyword in smart_keywords):
            return 'Smart Home Device'
        
        # Mobile device detection (based on vendor)
        mobile_vendors = ['apple', 'samsung', 'huawei', 'xiaomi', 'lg electronics']
        if any(vendor in vendor_lower for vendor in mobile_vendors):
            return 'Mobile Device'
        
        # Enterprise access point detection
        enterprise_vendors = ['cisco', 'aruba', 'ruckus', 'meraki', 'ubiquiti']
        if any(vendor in vendor_lower for vendor in enterprise_vendors):
            return 'Enterprise AP'
        
        # Consumer router detection
        router_vendors = ['netgear', 'tp-link', 'asus', 'd-link', 'linksys', 'belkin']
        if any(vendor in vendor_lower for vendor in router_vendors):
            return 'Consumer Router'
        
        # Check capabilities
        if 'ap' in capabilities_str or 'ess' in capabilities_str:
            return 'Access Point'
        elif 'ibss' in capabilities_str:
            return 'Ad-hoc Device'
        else:
            return 'Client Device'
    
    def analyze_security_features(self, capabilities: List[str], encryption_type: str) -> Dict:
        """Analyze security features of the network"""
        security_analysis = {
            'encryption_strength': 'weak',
            'security_features': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Analyze encryption
        if encryption_type.upper() == 'OPEN':
            security_analysis['encryption_strength'] = 'none'
            security_analysis['vulnerabilities'].append('No encryption')
            security_analysis['recommendations'].append('Enable WPA3 or WPA2 encryption')
        elif 'WEP' in encryption_type.upper():
            security_analysis['encryption_strength'] = 'very_weak'
            security_analysis['vulnerabilities'].append('WEP encryption is easily broken')
            security_analysis['recommendations'].append('Upgrade to WPA3 or WPA2')
        elif 'WPA3' in encryption_type.upper():
            security_analysis['encryption_strength'] = 'strong'
            security_analysis['security_features'].append('WPA3 encryption')
        elif 'WPA2' in encryption_type.upper():
            security_analysis['encryption_strength'] = 'good'
            security_analysis['security_features'].append('WPA2 encryption')
        elif 'WPA' in encryption_type.upper():
            security_analysis['encryption_strength'] = 'moderate'
            security_analysis['security_features'].append('WPA encryption')
            security_analysis['recommendations'].append('Consider upgrading to WPA2 or WPA3')
        
        # Check for WPS
        capabilities_str = ' '.join(capabilities).upper()
        if 'WPS' in capabilities_str:
            security_analysis['vulnerabilities'].append('WPS enabled (potential PIN attack vulnerability)')
            security_analysis['recommendations'].append('Disable WPS if not needed')
        
        # Check for PMF (Protected Management Frames)
        if 'PMF' in capabilities_str or '11W' in capabilities_str:
            security_analysis['security_features'].append('Protected Management Frames')
        
        return security_analysis

class WiFiScanner:
    """
    Main WiFi scanning engine
    
    This is the core class that orchestrates network discovery and information gathering
    as specified in the documentation.
    """
    
    def __init__(self):
        self.signal_processor = SignalProcessor()
        self.channel_analyzer = ChannelAnalyzer()
        self.network_discovery = NetworkDiscovery(self.signal_processor, self.channel_analyzer)
        self.scan_results = []
        self.is_scanning = False
        self.scan_thread = None
        
        # Initialize platform detection
        self.platform = self._detect_platform()
        logger.info(f"WiFi Scanner initialized for platform: {self.platform}")
        
    def _detect_platform(self):
        """Detect the current platform"""
        system = platform.system().lower()
        if system == 'windows':
            return 'windows'
        elif system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'darwin'  # macOS
        else:
            return 'unknown'
    
    def _get_available_interfaces(self) -> List[str]:
        """Get available wireless interfaces"""
        interfaces = []
        
        try:
            if self.platform == 'linux':
                # Check /proc/net/wireless for wireless interfaces
                if os.path.exists('/proc/net/wireless'):
                    with open('/proc/net/wireless', 'r') as f:
                        lines = f.readlines()
                        for line in lines[2:]:  # Skip header lines
                            interface = line.split(':')[0].strip()
                            if interface:
                                interfaces.append(interface)
                
                # Also check with iwconfig
                try:
                    result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'IEEE 802.11' in line or 'ESSID' in line:
                                interface = line.split()[0]
                                if interface and interface not in interfaces:
                                    interfaces.append(interface)
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass
                    
            elif self.platform == 'darwin':
                # macOS - check for en0, en1, etc.
                try:
                    result = subprocess.run(['networksetup', '-listallhardwareports'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for i, line in enumerate(lines):
                            if 'Wi-Fi' in line and i + 1 < len(lines):
                                device_line = lines[i + 1]
                                if 'Device:' in device_line:
                                    interface = device_line.split('Device:')[1].strip()
                                    interfaces.append(interface)
                except (subprocess.SubprocessError, FileNotFoundError):
                    # Fallback to common macOS interface names
                    interfaces = ['en0', 'en1']
                    
            elif self.platform == 'windows':
                # Windows - use netsh
                try:
                    result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'Name' in line and ':' in line:
                                interface = line.split(':', 1)[1].strip()
                                if interface:
                                    interfaces.append(interface)
                except (subprocess.SubprocessError, FileNotFoundError):
                    interfaces = ['Wi-Fi']  # Default Windows interface name
            
            # Default fallback interfaces
            if not interfaces:
                interfaces = ['wlan0', 'wlo1', 'wlp2s0', 'en0', 'Wi-Fi']
                
        except Exception as e:
            logger.error(f"Error detecting wireless interfaces: {e}")
            interfaces = ['wlan0', 'en0', 'Wi-Fi']  # Fallback
        
        logger.info(f"Available wireless interfaces: {interfaces}")
        return interfaces
        
    def scan_available_networks(self, interface: str = None, timeout: int = 10) -> List[NetworkInfo]:
        """
        Discover available networks
        
        Args:
            interface: Network interface to scan on (auto-detect if None)
            timeout: Scan timeout in seconds
            
        Returns:
            List of NetworkInfo objects containing discovered networks
        """
        # Auto-detect interface if not provided
        if interface is None:
            available_interfaces = self._get_available_interfaces()
            interface = available_interfaces[0] if available_interfaces else 'wlan0'
        
        logger.info(f"Starting network scan on interface {interface}")
        
        try:
            if self.platform == 'linux':
                networks = self._scan_linux(interface, timeout)
            elif self.platform == 'darwin':
                networks = self._scan_macos(interface, timeout)
            elif self.platform == 'windows':
                networks = self._scan_windows(interface, timeout)
            else:
                logger.warning(f"Unsupported platform: {self.platform}")
                networks = []
            
            # Enhance with additional analysis
            for network in networks:
                # Update signal history
                self.signal_processor.update_signal_history(network.bssid, network.signal_strength)
                
                # Calculate quality metrics
                network.quality = self.signal_processor.calculate_signal_quality(
                    network.signal_strength, network.noise_level
                )
                network.snr = self.signal_processor.calculate_snr(
                    network.signal_strength, network.noise_level
                )
                
                # Perform security analysis
                security_analysis = self.network_discovery.analyze_security_features(
                    network.capabilities, network.encryption_type
                )
                
                # Add security metadata (could be stored in a separate field if needed)
                network.capabilities.extend(security_analysis.get('security_features', []))
            
            self.scan_results = networks
            logger.info(f"Scan completed. Found {len(networks)} networks")
            return networks
            
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout after {timeout} seconds")
            return []
        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            return []
    
    def _scan_linux(self, interface: str, timeout: int) -> List[NetworkInfo]:
        """Linux-specific network scanning using iwlist"""
        try:
            # Execute iwlist scan command
            cmd = ['iwlist', interface, 'scan']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode != 0:
                logger.error(f"iwlist scan failed: {result.stderr}")
                # Try alternative methods
                return self._scan_linux_alternative(interface, timeout)
            
            # Parse scan results
            return self._parse_iwlist_output(result.stdout)
            
        except FileNotFoundError:
            logger.warning("iwlist not found, trying alternative methods")
            return self._scan_linux_alternative(interface, timeout)
        except subprocess.TimeoutExpired:
            logger.error(f"iwlist scan timeout after {timeout} seconds")
            return []
        except Exception as e:
            logger.error(f"Error in Linux scan: {e}")
            return []
    
    def _scan_linux_alternative(self, interface: str, timeout: int) -> List[NetworkInfo]:
        """Alternative Linux scanning methods"""
        networks = []
        
        # Try nmcli (NetworkManager)
        try:
            cmd = ['nmcli', '-f', 'SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY', 
                   'dev', 'wifi', 'list', '--rescan', 'yes']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0:
                networks = self._parse_nmcli_output(result.stdout)
                logger.info("Used nmcli for network scanning")
        except (FileNotFoundError, subprocess.SubprocessError):
            pass
        
        # Try iw scan if nmcli failed
        if not networks:
            try:
                cmd = ['iw', interface, 'scan']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                
                if result.returncode == 0:
                    networks = self._parse_iw_output(result.stdout)
                    logger.info("Used iw for network scanning")
            except (FileNotFoundError, subprocess.SubprocessError):
                pass
        
        return networks
    
    def _scan_macos(self, interface: str, timeout: int) -> List[NetworkInfo]:
        """macOS-specific network scanning"""
        try:
            # Use airport utility
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            
            if os.path.exists(airport_path):
                cmd = [airport_path, '-s']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                
                if result.returncode == 0:
                    return self._parse_airport_output(result.stdout)
            
            # Fallback to system_profiler
            cmd = ['system_profiler', 'SPAirPortDataType']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0:
                return self._parse_system_profiler_output(result.stdout)
            
        except Exception as e:
            logger.error(f"Error in macOS scan: {e}")
        
        return []
    
    def _scan_windows(self, interface: str, timeout: int) -> List[NetworkInfo]:
        """Windows-specific network scanning"""
        try:
            # Use netsh wlan show profiles to get available networks
            cmd = ['netsh', 'wlan', 'show', 'profiles']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0:
                # Get detailed scan
                cmd = ['netsh', 'wlan', 'show', 'profiles', 'name=*', 'key=clear']
                detailed_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                
                return self._parse_netsh_output(result.stdout, detailed_result.stdout if detailed_result.returncode == 0 else "")
            
        except Exception as e:
            logger.error(f"Error in Windows scan: {e}")
        
        return []
    
    def _parse_iwlist_output(self, output: str) -> List[NetworkInfo]:
        """Parse iwlist scan output into NetworkInfo objects"""
        networks = []
        current_network = {}
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # New cell detected
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(self._create_network_info(current_network))
                
                # Extract BSSID
                bssid_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', line)
                current_network = {
                    'bssid': bssid_match.group(1) if bssid_match else 'Unknown'
                }
            
            # ESSID (SSID)
            elif 'ESSID:' in line:
                essid_match = re.search(r'ESSID:"([^"]*)"', line)
                current_network['ssid'] = essid_match.group(1) if essid_match else 'Hidden'
                current_network['is_hidden'] = not bool(essid_match and essid_match.group(1))
            
            # Signal strength
            elif 'Signal level=' in line:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                current_network['signal_strength'] = int(signal_match.group(1)) if signal_match else -100
            
            # Frequency and channel
            elif 'Frequency:' in line:
                freq_match = re.search(r'Frequency:(\d+\.?\d*) GHz', line)
                if freq_match:
                    freq_ghz = float(freq_match.group(1))
                    frequency = int(freq_ghz * 1000)  # Convert to MHz
                    current_network['frequency'] = frequency
                    current_network['channel'] = self.channel_analyzer.frequency_to_channel(frequency)
            
            # Encryption information
            elif 'Encryption key:' in line:
                current_network['has_encryption'] = 'on' in line.lower()
            
            # Quality
            elif 'Quality=' in line:
                quality_match = re.search(r'Quality=(\d+)/(\d+)', line)
                if quality_match:
                    quality_ratio = int(quality_match.group(1)) / int(quality_match.group(2))
                    current_network['raw_quality'] = quality_ratio * 100
            
            # Bit rates
            elif 'Bit Rates:' in line:
                rates_match = re.search(r'Bit Rates:(.+)', line)
                if rates_match:
                    rates_str = rates_match.group(1)
                    rates = [rate.strip() for rate in rates_str.split(';') if rate.strip()]
                    current_network['rates'] = rates[:4]  # Take first 4 rates
            
            # IE information for detailed encryption
            elif 'IE:' in line:
                if 'WPA3' in line:
                    current_network['encryption_type'] = 'WPA3'
                elif 'WPA2' in line or 'RSN' in line:
                    current_network['encryption_type'] = 'WPA2'
                elif 'WPA' in line:
                    current_network['encryption_type'] = 'WPA'
            
            # Group cipher
            elif 'Group Cipher' in line:
                cipher_match = re.search(r'Group Cipher : (\w+)', line)
                if cipher_match:
                    current_network['group_cipher'] = cipher_match.group(1)
            
            # Pairwise ciphers
            elif 'Pairwise Ciphers' in line:
                cipher_match = re.search(r'Pairwise Ciphers.* : (.+)', line)
                if cipher_match:
                    current_network['pairwise_ciphers'] = cipher_match.group(1).strip()
        
        # Don't forget the last network
        if current_network:
            networks.append(self._create_network_info(current_network))
        
        return networks
    
    def _parse_nmcli_output(self, output: str) -> List[NetworkInfo]:
        """Parse nmcli output into NetworkInfo objects"""
        networks = []
        lines = output.strip().split('\n')
        
        # Skip header line
        if lines and 'SSID' in lines[0]:
            lines = lines[1:]
        
        for line in lines:
            if not line.strip():
                continue
                
            # Split by multiple spaces or tabs
            parts = re.split(r'\s{2,}|\t+', line.strip())
            
            if len(parts) >= 7:
                network_data = {
                    'ssid': parts[0] if parts[0] != '--' else 'Hidden',
                    'bssid': parts[1] if len(parts) > 1 and parts[1] != '--' else 'Unknown',
                    'channel': int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 1,
                    'frequency': int(float(parts[4]) * 1000) if len(parts) > 4 and parts[4] != '--' else 2412,
                    'signal_strength': int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else -100,
                    'encryption_type': parts[8] if len(parts) > 8 else 'Unknown',
                    'is_hidden': parts[0] == '--' or parts[0] == ''
                }
                
                networks.append(self._create_network_info(network_data))
        
        return networks
    
    def _parse_iw_output(self, output: str) -> List[NetworkInfo]:
        """Parse iw scan output into NetworkInfo objects"""
        networks = []
        current_network = {}
        
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # New BSS entry
            if line.startswith('BSS '):
                if current_network:
                    networks.append(self._create_network_info(current_network))
                
                bssid_match = re.search(r'BSS ([0-9a-f:]{17})', line)
                current_network = {
                    'bssid': bssid_match.group(1) if bssid_match else 'Unknown'
                }
            
            # SSID
            elif 'SSID:' in line:
                ssid_match = re.search(r'SSID: (.+)', line)
                current_network['ssid'] = ssid_match.group(1) if ssid_match else 'Hidden'
                current_network['is_hidden'] = not bool(ssid_match and ssid_match.group(1))
            
            # Signal strength
            elif 'signal:' in line:
                signal_match = re.search(r'signal: (-?\d+\.\d+) dBm', line)
                if signal_match:
                    current_network['signal_strength'] = int(float(signal_match.group(1)))
            
            # Frequency
            elif 'freq:' in line:
                freq_match = re.search(r'freq: (\d+)', line)
                if freq_match:
                    frequency = int(freq_match.group(1))
                    current_network['frequency'] = frequency
                    current_network['channel'] = self.channel_analyzer.frequency_to_channel(frequency)
            
            # Capabilities
            elif 'capability:' in line:
                cap_match = re.search(r'capability: (.+)', line)
                if cap_match:
                    current_network['capabilities_raw'] = cap_match.group(1)
            
            # RSN (WPA2) information
            elif 'RSN:' in line:
                current_network['encryption_type'] = 'WPA2'
            
            # WPA information
            elif 'WPA:' in line:
                if current_network.get('encryption_type') != 'WPA2':
                    current_network['encryption_type'] = 'WPA'
        
        # Don't forget the last network
        if current_network:
            networks.append(self._create_network_info(current_network))
        
        return networks
    
    def _parse_airport_output(self, output: str) -> List[NetworkInfo]:
        """Parse macOS airport utility output"""
        networks = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            # Parse airport output format
            parts = line.split()
            if len(parts) >= 6:
                network_data = {
                    'ssid': parts[0],
                    'bssid': parts[1],
                    'signal_strength': int(parts[2]) if parts[2].lstrip('-').isdigit() else -100,
                    'channel': int(parts[3]) if parts[3].isdigit() else 1,
                    'encryption_type': ' '.join(parts[6:]) if len(parts) > 6 else 'Open',
                    'is_hidden': False
                }
                
                # Calculate frequency from channel
                channel = network_data['channel']
                if 1 <= channel <= 14:
                    network_data['frequency'] = 2412 + (channel - 1) * 5
                else:
                    network_data['frequency'] = 5000 + channel * 5
                
                networks.append(self._create_network_info(network_data))
        
        return networks
    
    def _parse_system_profiler_output(self, output: str) -> List[NetworkInfo]:
        """Parse macOS system_profiler output"""
        networks = []
        # This would require more complex parsing of the system_profiler XML/text output
        # For now, return empty list as fallback
        logger.info("system_profiler parsing not implemented, using fallback")
        return networks
    
    def _parse_netsh_output(self, profiles_output: str, details_output: str) -> List[NetworkInfo]:
        """Parse Windows netsh output"""
        networks = []
        lines = profiles_output.split('\n')
        
        for line in lines:
            if 'All User Profile' in line:
                profile_match = re.search(r'All User Profile\s*:\s*(.+)', line)
                if profile_match:
                    ssid = profile_match.group(1).strip()
                    
                    # Create basic network info
                    network_data = {
                        'ssid': ssid,
                        'bssid': 'Unknown',  # Windows doesn't easily provide BSSID in profiles
                        'signal_strength': -70,  # Default value
                        'channel': 6,  # Default channel
                        'frequency': 2437,  # Default frequency
                        'encryption_type': 'WPA2',  # Assume WPA2 by default
                        'is_hidden': False
                    }
                    
                    networks.append(self._create_network_info(network_data))
        
        return networks
    
    def _create_network_info(self, data: Dict) -> NetworkInfo:
        """Create NetworkInfo object from parsed data"""
        # Set defaults for missing values
        ssid = data.get('ssid', 'Hidden')
        bssid = data.get('bssid', 'Unknown')
        signal_strength = data.get('signal_strength', -100)
        frequency = data.get('frequency', 2412)
        channel = data.get('channel', self.channel_analyzer.frequency_to_channel(frequency))
        
        # Determine encryption type
        if data.get('has_encryption', True):
            encryption_type = data.get('encryption_type', 'WPA2')
        else:
            encryption_type = 'Open'
        
        # Determine cipher suite and authentication
        cipher_suite = encryption_type
        if encryption_type == 'Open':
            authentication = 'Open'
        elif 'WPA3' in encryption_type:
            authentication = 'SAE'
            cipher_suite = 'AES'
        elif 'WPA2' in encryption_type:
            authentication = 'PSK'
            cipher_suite = 'AES'
        elif 'WPA' in encryption_type:
            authentication = 'PSK'
            cipher_suite = 'TKIP'
        else:
            authentication = 'PSK'
        
        # Identify vendor and device type
        vendor = self.network_discovery.identify_vendor(bssid)
        capabilities = [encryption_type]
        
        # Add additional capabilities
        if data.get('capabilities_raw'):
            capabilities.extend(data['capabilities_raw'].split())
        if data.get('group_cipher'):
            capabilities.append(f"Group: {data['group_cipher']}")
        if data.get('pairwise_ciphers'):
            capabilities.append(f"Pairwise: {data['pairwise_ciphers']}")
        
        device_type = self.network_discovery.determine_device_type(capabilities, vendor, ssid)
        
        # Get rates
        rates = data.get('rates', ['1.0', '2.0', '5.5', '11.0'])
        if not rates:
            rates = ['1.0', '2.0', '5.5', '11.0']
        
        # Calculate bandwidth based on rates and encryption
        max_rate = 54.0  # Default 802.11g
        if rates:
            try:
                # Extract numeric rates
                numeric_rates = []
                for rate in rates:
                    rate_match = re.search(r'(\d+\.?\d*)', str(rate))
                    if rate_match:
                        numeric_rates.append(float(rate_match.group(1)))
                if numeric_rates:
                    max_rate = max(numeric_rates)
            except:
                pass
        
        # Determine bandwidth
        if max_rate >= 300:
            bandwidth = '40MHz'
        elif max_rate >= 100:
            bandwidth = '20MHz'
        else:
            bandwidth = '20MHz'
        
        return NetworkInfo(
            ssid=ssid,
            bssid=bssid,
            signal_strength=signal_strength,
            frequency=frequency,
            channel=channel,
            encryption_type=encryption_type,
            cipher_suite=cipher_suite,
            authentication=authentication,
            vendor=vendor,
            device_type=device_type,
            is_hidden=data.get('is_hidden', False),
            beacon_interval=data.get('beacon_interval', 100),
            capabilities=capabilities,
            country_code=data.get('country_code', 'US'),
            quality=data.get('raw_quality', 50),
            noise_level=data.get('noise_level', -95),
            snr=signal_strength - data.get('noise_level', -95),
            bandwidth=bandwidth,
            mode=data.get('mode', 'Master'),
            rates=rates,
            last_seen=time.time()
        )
    
    def get_signal_strength(self, bssid: str) -> int:
        """
        Get signal strength measurement for specific BSSID
        
        Args:
            bssid: Target BSSID
            
        Returns:
            Signal strength in dBm
        """
        for network in self.scan_results:
            if network.bssid.lower() == bssid.lower():
                return network.signal_strength
        return -100  # No signal found
    
    def identify_encryption_type(self, network_info: NetworkInfo) -> str:
        """
        Identify encryption type from network information
        
        Args:
            network_info: NetworkInfo object
            
        Returns:
            Detailed encryption type string
        """
        encryption = network_info.encryption_type.lower()
        
        if 'wpa3' in encryption:
            return 'WPA3-SAE'
        elif 'wpa2' in encryption:
            return 'WPA2-PSK'
        elif 'wpa' in encryption:
            return 'WPA-PSK'
        elif 'wep' in encryption:
            return 'WEP'
        else:
            return 'Open'
    
    def detect_hidden_networks(self, interface: str = None) -> List[NetworkInfo]:
        """
        Detect hidden SSID networks
        
        Args:
            interface: Network interface to monitor
            
        Returns:
            List of hidden networks detected
        """
        logger.info("Scanning for hidden networks...")
        
        # First, get all networks including hidden ones
        all_networks = self.scan_available_networks(interface)
        
        # Filter for hidden networks
        hidden_networks = [net for net in all_networks if net.is_hidden or not net.ssid or net.ssid == 'Hidden']
        
        logger.info(f"Found {len(hidden_networks)} hidden networks")
        return hidden_networks
    
    def analyze_channel_usage(self) -> Dict:
        """
        Analyze channel utilization across discovered networks
        
        Returns:
            Dictionary containing channel analysis results
        """
        if not self.scan_results:
            logger.warning("No scan results available for channel analysis")
            return {}
        
        return self.channel_analyzer.analyze_channel_utilization(self.scan_results)
    
    def identify_device_types(self) -> Dict[str, List[NetworkInfo]]:
        """
        Identify and categorize connected device types
        
        Returns:
            Dictionary mapping device types to networks
        """
        device_categories = defaultdict(list)
        
        for network in self.scan_results:
            device_categories[network.device_type].append(network)
        
        return dict(device_categories)
    
    def measure_network_performance(self, ssid: str, duration: int = 30) -> Dict:
        """
        Measure network performance metrics
        
        Args:
            ssid: Target network SSID
            duration: Measurement duration in seconds
            
        Returns:
            Performance metrics dictionary
        """
        logger.info(f"Measuring performance for network: {ssid}")
        
        target_network = None
        for network in self.scan_results:
            if network.ssid == ssid:
                target_network = network
                break
        
        if not target_network:
            logger.error(f"Network {ssid} not found in scan results")
            return {}
        
        # Simulate performance measurement
        # In a real implementation, this would involve actual network testing
        performance_data = {
            'ssid': ssid,
            'bssid': target_network.bssid,
            'signal_strength': target_network.signal_strength,
            'signal_quality': target_network.quality,
            'signal_trend': self.signal_processor.get_signal_trend(target_network.bssid),
            'channel': target_network.channel,
            'frequency': target_network.frequency,
            'estimated_throughput': self._estimate_throughput(target_network),
            'latency_estimate': self._estimate_latency(target_network),
            'stability_score': self._calculate_stability_score(target_network.bssid),
            'interference_level': self._assess_interference(target_network),
            'security_score': self._calculate_security_score(target_network)
        }
        
        return performance_data
    
    def _estimate_throughput(self, network: NetworkInfo) -> float:
        """Estimate network throughput based on signal quality and encryption"""
        # Base throughput estimation
        if '802.11ac' in ' '.join(network.capabilities) or network.bandwidth == '80MHz':
            base_throughput = 433.0  # 802.11ac
        elif '802.11n' in ' '.join(network.capabilities) or network.bandwidth == '40MHz':
            base_throughput = 150.0  # 802.11n
        else:
            base_throughput = 54.0  # 802.11g/a
        
        # Adjust based on signal quality
        quality_factor = network.quality / 100.0
        
        # Adjust based on encryption overhead
        encryption_overhead = {
            'Open': 1.0,
            'WEP': 0.95,
            'WPA': 0.90,
            'WPA2': 0.85,
            'WPA3': 0.80
        }
        
        enc_factor = encryption_overhead.get(network.encryption_type, 0.85)
        
        # Adjust based on channel congestion
        channel_analysis = self.analyze_channel_usage()
        congestion_factor = 1.0
        if channel_analysis and network.channel in channel_analysis.get('congested_channels', []):
            congestion_factor = 0.7
        
        return base_throughput * quality_factor * enc_factor * congestion_factor
    
    def _estimate_latency(self, network: NetworkInfo) -> float:
        """Estimate network latency based on signal strength and interference"""
        # Base latency in milliseconds
        base_latency = 10.0
        
        # Adjust based on signal strength
        if network.signal_strength > -50:
            latency_factor = 1.0
        elif network.signal_strength > -70:
            latency_factor = 1.5
        elif network.signal_strength > -85:
            latency_factor = 2.0
        else:
            latency_factor = 3.0
        
        # Adjust based on encryption
        encryption_latency = {
            'Open': 1.0,
            'WEP': 1.1,
            'WPA': 1.2,
            'WPA2': 1.3,
            'WPA3': 1.4
        }
        
        enc_factor = encryption_latency.get(network.encryption_type, 1.3)
        
        return base_latency * latency_factor * enc_factor
    
    def _calculate_stability_score(self, bssid: str) -> float:
        """Calculate signal stability score based on history"""
        history = self.signal_processor.signal_history.get(bssid, [])
        
        if len(history) < 3:
            return 50.0  # Default score for insufficient data
        
        # Calculate signal variance
        signals = [entry['signal'] for entry in history]
        mean_signal = sum(signals) / len(signals)
        variance = sum((s - mean_signal) ** 2 for s in signals) / len(signals)
        
        # Convert variance to stability score (lower variance = higher stability)
        stability = max(0, 100 - (variance * 2))
        
        return stability
    
    def _assess_interference(self, network: NetworkInfo) -> str:
        """Assess interference level for a network"""
        channel_analysis = self.analyze_channel_usage()
        
        if not channel_analysis:
            return 'unknown'
        
        interference_details = channel_analysis.get('interference_analysis', {})
        channel_interference = interference_details.get(network.channel, {})
        
        return channel_interference.get('interference_level', 'low')
    
    def _calculate_security_score(self, network: NetworkInfo) -> float:
        """Calculate security score for a network"""
        score = 0.0
        
        # Base encryption score
        encryption_scores = {
            'Open': 0.0,
            'WEP': 20.0,
            'WPA': 60.0,
            'WPA2': 80.0,
            'WPA3': 100.0
        }
        
        score += encryption_scores.get(network.encryption_type, 50.0)
        
        # Bonus for strong cipher suites
        if 'AES' in network.cipher_suite:
            score += 10.0
        elif 'TKIP' in network.cipher_suite:
            score += 5.0
        
        # Penalty for WPS if detected
        if any('WPS' in cap for cap in network.capabilities):
            score -= 15.0
        
        # Bonus for PMF (Protected Management Frames)
        if any('PMF' in cap or '11W' in cap for cap in network.capabilities):
            score += 10.0
        
        return min(100.0, max(0.0, score))
    
    def get_scan_summary(self) -> Dict:
        """Get comprehensive scan summary"""
        if not self.scan_results:
            return {'error': 'No scan results available'}
        
        total_networks = len(self.scan_results)
        open_networks = len([n for n in self.scan_results if n.encryption_type == 'Open'])
        hidden_networks = len([n for n in self.scan_results if n.is_hidden])
        
        # Signal strength distribution
        strong_signal = len([n for n in self.scan_results if n.signal_strength > -50])
        medium_signal = len([n for n in self.scan_results if -70 <= n.signal_strength <= -50])
        weak_signal = len([n for n in self.scan_results if n.signal_strength < -70])
        
        # Security analysis
        secure_networks = len([n for n in self.scan_results if n.encryption_type in ['WPA2', 'WPA3']])
        vulnerable_networks = len([n for n in self.scan_results if n.encryption_type in ['Open', 'WEP']])
        
        # Vendor distribution
        vendor_stats = defaultdict(int)
        for network in self.scan_results:
            vendor_stats[network.vendor] += 1
        
        return {
            'total_networks': total_networks,
            'open_networks': open_networks,
            'encrypted_networks': total_networks - open_networks,
            'hidden_networks': hidden_networks,
            'secure_networks': secure_networks,
            'vulnerable_networks': vulnerable_networks,
            'signal_distribution': {
                'strong': strong_signal,
                'medium': medium_signal,
                'weak': weak_signal
            },
            'encryption_distribution': {
                enc_type: len([n for n in self.scan_results if n.encryption_type == enc_type])
                for enc_type in set(n.encryption_type for n in self.scan_results)
            },
            'vendor_distribution': dict(vendor_stats),
            'channel_analysis': self.analyze_channel_usage(),
            'device_types': {k: len(v) for k, v in self.identify_device_types().items()},
            'scan_timestamp': time.time(),
            'platform': self.platform,
            'interface_used': self._get_available_interfaces()[0] if self._get_available_interfaces() else 'unknown'
        }
    
    def get_current_connection(self):
        """Get current Wi-Fi connection information"""
        try:
            if self.platform == 'windows':
                return self._get_current_windows()
            elif self.platform == 'linux':
                return self._get_current_linux()
            elif self.platform == 'darwin':
                return self._get_current_macos()
            else:
                # Fallback for unknown platforms
                return self._get_fallback_connection()
        except Exception as e:
            logger.error(f"Error getting current connection: {e}")
            return self._get_fallback_connection()
    
    def _get_current_windows(self):
        """Get current connection on Windows"""
        try:
            # Get current connection info
            cmd = ['netsh', 'wlan', 'show', 'interfaces']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                connection_info = {}
                
                for line in lines:
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if 'name' in key and 'wi-fi' in value.lower():
                            connection_info['interface'] = value
                        elif 'description' in key:
                            connection_info['adapter'] = value
                        elif 'state' in key:
                            connection_info['state'] = value
                        elif 'ssid' in key and 'bssid' not in key:  # Match SSID but not AP BSSID
                            connection_info['ssid'] = value
                        elif 'bssid' in key:  # Matches both "AP BSSID" and "BSSID"
                            connection_info['bssid'] = value
                        elif 'signal' in key:
                            signal_match = re.search(r'(\d+)%', value)
                            if signal_match:
                                # Convert percentage to dBm (approximate)
                                signal_percent = int(signal_match.group(1))
                                signal_dbm = -100 + (signal_percent * 0.7)  # Rough conversion
                                connection_info['signal_strength'] = int(signal_dbm)
                        elif 'channel' in key:
                            connection_info['channel'] = value
                        elif 'authentication' in key:
                            connection_info['security'] = value
                
                if connection_info.get('state', '').lower() == 'connected' and connection_info.get('ssid'):
                    return {
                        'connected': True,
                        'ssid': connection_info['ssid'],
                        'bssid': connection_info.get('bssid', 'Unknown'),
                        'signal_strength': connection_info.get('signal_strength', 'Unknown'),
                        'signal_quality': f"{((connection_info.get('signal_strength', -100) + 100) * 1.4):.0f}%" if isinstance(connection_info.get('signal_strength'), int) else 'Unknown',
                        'security': connection_info.get('security', 'Unknown'),
                        'channel': connection_info.get('channel', 'Unknown'),
                        'ip_address': self._get_local_ip(),
                        'risk_level': self._assess_connection_risk(connection_info),
                        'platform': 'windows',
                        'method': 'netsh'
                    }
            
            return self._get_fallback_connection()
        except Exception as e:
            logger.error(f"Windows connection detection failed: {e}")
            return self._get_fallback_connection()
    
    def _get_current_linux(self):
        """Get current connection on Linux"""
        try:
            connection_info = {}
            
            # Try iwconfig first
            try:
                cmd = ['iwconfig']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    current_interface = None
                    
                    for line in lines:
                        if 'IEEE 802.11' in line:
                            current_interface = line.split()[0]
                        elif current_interface and 'ESSID:' in line:
                            essid_match = re.search(r'ESSID:"([^"]*)"', line)
                            if essid_match and essid_match.group(1):
                                connection_info['ssid'] = essid_match.group(1)
                                connection_info['interface'] = current_interface
                        elif current_interface and 'Access Point:' in line:
                            bssid_match = re.search(r'Access Point: ([0-9A-Fa-f:]{17})', line)
                            if bssid_match:
                                connection_info['bssid'] = bssid_match.group(1)
                        elif current_interface and 'Signal level=' in line:
                            signal_match = re.search(r'Signal level=(-?\d+)', line)
                            if signal_match:
                                connection_info['signal_strength'] = int(signal_match.group(1))
                        elif current_interface and 'Frequency:' in line:
                            freq_match = re.search(r'Frequency:(\d+\.?\d*) GHz', line)
                            if freq_match:
                                freq_ghz = float(freq_match.group(1))
                                frequency = int(freq_ghz * 1000)
                                connection_info['frequency'] = frequency
                                connection_info['channel'] = self.channel_analyzer.frequency_to_channel(frequency)
            except (FileNotFoundError, subprocess.SubprocessError):
                pass
            
            # Try nmcli if iwconfig didn't work or provide enough info
            if not connection_info.get('ssid'):
                try:
                    cmd = ['nmcli', '-t', '-f', 'ACTIVE,SSID,BSSID,SIGNAL,SECURITY', 'dev', 'wifi']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if line.startswith('yes:'):  # Active connection
                                parts = line.split(':')
                                if len(parts) >= 4:
                                    connection_info['ssid'] = parts[1]
                                    connection_info['bssid'] = parts[2]
                                    if parts[3].isdigit():
                                        connection_info['signal_strength'] = int(parts[3])
                                    if len(parts) > 4:
                                        connection_info['security'] = parts[4]
                                break
                except (FileNotFoundError, subprocess.SubprocessError):
                    pass
            
            # Try iw if other methods didn't work
            if not connection_info.get('ssid'):
                try:
                    interfaces = self._get_available_interfaces()
                    for interface in interfaces:
                        cmd = ['iw', 'dev', interface, 'info']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        
                        if result.returncode == 0 and 'type managed' in result.stdout:
                            # Get connection info with iw
                            cmd = ['iw', 'dev', interface, 'link']
                            link_result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                            
                            if link_result.returncode == 0:
                                lines = link_result.stdout.split('\n')
                                for line in lines:
                                    if 'Connected to' in line:
                                        bssid_match = re.search(r'Connected to ([0-9a-f:]{17})', line)
                                        if bssid_match:
                                            connection_info['bssid'] = bssid_match.group(1)
                                    elif 'SSID:' in line:
                                        ssid_match = re.search(r'SSID: (.+)', line)
                                        if ssid_match:
                                            connection_info['ssid'] = ssid_match.group(1).strip()
                                    elif 'freq:' in line:
                                        freq_match = re.search(r'freq: (\d+)', line)
                                        if freq_match:
                                            frequency = int(freq_match.group(1))
                                            connection_info['frequency'] = frequency
                                            connection_info['channel'] = self.channel_analyzer.frequency_to_channel(frequency)
                                    elif 'signal:' in line:
                                        signal_match = re.search(r'signal: (-?\d+)', line)
                                        if signal_match:
                                            connection_info['signal_strength'] = int(signal_match.group(1))
                            break
                except (FileNotFoundError, subprocess.SubprocessError):
                    pass
            
            if connection_info.get('ssid'):
                signal_strength = connection_info.get('signal_strength', -100)
                return {
                    'connected': True,
                    'ssid': connection_info['ssid'],
                    'bssid': connection_info.get('bssid', 'Unknown'),
                    'signal_strength': signal_strength,
                    'signal_quality': f"{self.signal_processor.calculate_signal_quality(signal_strength):.0f}%",
                    'security': connection_info.get('security', 'Unknown'),
                    'channel': connection_info.get('channel', 'Unknown'),
                    'frequency': connection_info.get('frequency', 'Unknown'),
                    'ip_address': self._get_local_ip(),
                    'risk_level': self._assess_connection_risk(connection_info),
                    'platform': 'linux',
                    'method': 'iwconfig/nmcli/iw'
                }
            
            return self._get_fallback_connection()
        except Exception as e:
            logger.error(f"Linux connection detection failed: {e}")
            return self._get_fallback_connection()
    
    def _get_current_macos(self):
        """Get current connection on macOS"""
        try:
            connection_info = {}
            
            # Try airport utility
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            
            if os.path.exists(airport_path):
                cmd = [airport_path, '-I']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        line = line.strip()
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            
                            if key == 'ssid':
                                connection_info['ssid'] = value
                            elif key == 'bssid':
                                connection_info['bssid'] = value
                            elif key == 'rssi':
                                connection_info['signal_strength'] = int(value)
                            elif key == 'channel':
                                connection_info['channel'] = int(value)
                                # Calculate frequency from channel
                                channel = int(value)
                                if 1 <= channel <= 14:
                                    connection_info['frequency'] = 2412 + (channel - 1) * 5
                                else:
                                    connection_info['frequency'] = 5000 + channel * 5
                            elif key == 'cc':
                                connection_info['country_code'] = value
            
            # Try networksetup as fallback
            if not connection_info.get('ssid'):
                try:
                    # Get current network
                    cmd = ['networksetup', '-getairportnetwork', 'en0']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        network_match = re.search(r'Current Wi-Fi Network: (.+)', result.stdout)
                        if network_match:
                            connection_info['ssid'] = network_match.group(1).strip()
                except (subprocess.SubprocessError, FileNotFoundError):
                    pass
            
            if connection_info.get('ssid'):
                signal_strength = connection_info.get('signal_strength', -100)
                return {
                    'connected': True,
                    'ssid': connection_info['ssid'],
                    'bssid': connection_info.get('bssid', 'Unknown'),
                    'signal_strength': signal_strength,
                    'signal_quality': f"{self.signal_processor.calculate_signal_quality(signal_strength):.0f}%",
                    'security': 'Unknown',  # macOS doesn't easily provide this info
                    'channel': connection_info.get('channel', 'Unknown'),
                    'frequency': connection_info.get('frequency', 'Unknown'),
                    'country_code': connection_info.get('country_code', 'Unknown'),
                    'ip_address': self._get_local_ip(),
                    'risk_level': self._assess_connection_risk(connection_info),
                    'platform': 'darwin',
                    'method': 'airport'
                }
            
            return self._get_fallback_connection()
        except Exception as e:
            logger.error(f"macOS connection detection failed: {e}")
            return self._get_fallback_connection()
    
    def _get_fallback_connection(self):
        """Fallback connection info when platform-specific methods fail"""
        try:
            # Basic connection check using socket
            local_ip = self._get_local_ip()
            if local_ip and local_ip != '127.0.0.1':
                return {
                    'connected': True,
                    'ssid': 'Unknown Network',
                    'bssid': None,
                    'signal_strength': 'Unknown',
                    'signal_quality': 'Unknown',
                    'security': 'Unknown',
                    'channel': 'Unknown',
                    'frequency': 'Unknown',
                    'ip_address': local_ip,
                    'risk_level': 'Unknown',
                    'platform': self.platform,
                    'fallback': True
                }
            else:
                return None
        except Exception as e:
            logger.error(f"Fallback connection method failed: {e}")
            return None
    
    def _assess_connection_risk(self, connection_info: Dict) -> str:
        """Assess risk level of current connection"""
        if not connection_info:
            return 'Unknown'
        
        risk_factors = []
        
        # Check security
        security = connection_info.get('security', '').lower()
        if 'open' in security or not security:
            risk_factors.append('No encryption')
        elif 'wep' in security:
            risk_factors.append('Weak encryption (WEP)')
        
        # Check signal strength
        signal = connection_info.get('signal_strength')
        if isinstance(signal, int) and signal < -80:
            risk_factors.append('Weak signal')
        
        # Check for unknown/suspicious networks
        ssid = connection_info.get('ssid', '').lower()
        suspicious_keywords = ['free', 'guest', 'public', 'open', 'wifi']
        if any(keyword in ssid for keyword in suspicious_keywords):
            risk_factors.append('Potentially public network')
        
        # Determine overall risk
        if len(risk_factors) >= 2:
            return 'HIGH'
        elif len(risk_factors) == 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_current_signal_strength(self) -> int:
        """
        Get signal strength for the currently connected network
        
        Returns:
            Signal strength in dBm, or -100 if not connected or not found
        """
        try:
            # Get current connection info
            current_conn = self.get_current_connection()
            
            if not current_conn or not current_conn.get('connected'):
                logger.warning("No current connection found")
                return -100
            
            # If we have direct signal strength from connection info
            signal_strength = current_conn.get('signal_strength')
            if isinstance(signal_strength, int):
                return signal_strength
            
            current_ssid = current_conn.get('ssid')
            current_bssid = current_conn.get('bssid')
            
            if not current_ssid or current_ssid in ['Unknown Network', 'Connected Network']:
                logger.warning("Current SSID unknown, cannot determine signal strength")
                return -100
            
            # Find the network in scan results
            for network in self.scan_results:
                if network.ssid == current_ssid:
                    if current_bssid and current_bssid != 'Unknown':
                        # Match by both SSID and BSSID if available
                        if network.bssid.lower() == current_bssid.lower():
                            return network.signal_strength
                    else:
                        # Match by SSID only
                        return network.signal_strength
            
            # If not found in current scan results, perform a quick scan
            logger.info("Current network not in scan results, performing quick scan")
            networks = self.scan_available_networks()
            
            for network in networks:
                if network.ssid == current_ssid:
                    if current_bssid and current_bssid != 'Unknown':
                        if network.bssid.lower() == current_bssid.lower():
                            return network.signal_strength
                    else:
                        return network.signal_strength
            
            logger.warning(f"Current network '{current_ssid}' not found in scan results")
            return -100
            
        except Exception as e:
            logger.error(f"Error getting current signal strength: {e}")
            return -100

    def _get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to a remote server to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
                return local_ip
        except Exception:
            return '127.0.0.1'
    
    def continuous_monitoring(self, callback=None, interval: int = 30):
        """
        Start continuous network monitoring
        
        Args:
            callback: Optional callback function for real-time updates
            interval: Monitoring interval in seconds
        """
        def monitor():
            self.is_scanning = True
            logger.info(f"Starting continuous monitoring with {interval}s interval")
            
            while self.is_scanning:
                try:
                    # Perform scan
                    networks = self.scan_available_networks()
                    
                    # Get current connection
                    current_conn = self.get_current_connection()
                    
                    # Prepare monitoring data
                    monitoring_data = {
                        'timestamp': time.time(),
                        'networks_found': len(networks),
                        'current_connection': current_conn,
                        'scan_summary': self.get_scan_summary(),
                        'signal_trends': {
                            bssid: self.signal_processor.get_signal_trend(bssid)
                            for bssid in self.signal_processor.signal_history.keys()
                        }
                    }
                    
                    # Call callback if provided
                    if callback:
                        callback(monitoring_data)
                    
                    # Wait for next scan
                    time.sleep(interval)
                    
                except Exception as e:
                    logger.error(f"Error in continuous monitoring: {e}")
                    if callback:
                        callback({'error': str(e), 'timestamp': time.time()})
                    time.sleep(interval)
        
        # Start monitoring thread
        self.scan_thread = threading.Thread(target=monitor, daemon=True)
        self.scan_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            logger.info("Stopping continuous monitoring")
            self.scan_thread.join(timeout=5)
    
    def export_results(self, format: str = 'json', filename: str = None) -> str:
        """
        Export scan results to file
        
        Args:
            format: Export format ('json', 'csv', 'txt')
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to exported file
        """
        if not self.scan_results:
            raise ValueError("No scan results to export")
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        if not filename:
            filename = f"wifi_scan_{timestamp}.{format}"
        
        try:
            if format.lower() == 'json':
                data = {
                    'scan_metadata': {
                        'timestamp': timestamp,
                        'platform': self.platform,
                        'total_networks': len(self.scan_results)
                    },
                    'networks': [network.to_dict() for network in self.scan_results],
                    'scan_summary': self.get_scan_summary()
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            
            elif format.lower() == 'csv':
                import csv
                
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    if self.scan_results:
                        writer = csv.DictWriter(f, fieldnames=self.scan_results[0].to_dict().keys())
                        writer.writeheader()
                        for network in self.scan_results:
                            writer.writerow(network.to_dict())
            
            elif format.lower() == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Wi-Fi Scan Results - {timestamp}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for i, network in enumerate(self.scan_results, 1):
                        f.write(f"Network {i}:\n")
                        f.write(f"  SSID: {network.ssid}\n")
                        f.write(f"  BSSID: {network.bssid}\n")
                        f.write(f"  Signal: {network.signal_strength} dBm\n")
                        f.write(f"  Channel: {network.channel}\n")
                        f.write(f"  Encryption: {network.encryption_type}\n")
                        f.write(f"  Vendor: {network.vendor}\n")
                        f.write(f"  Device Type: {network.device_type}\n")
                        f.write(f"  Quality: {network.quality:.1f}%\n")
                        f.write("-" * 30 + "\n")
            
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            logger.info(f"Scan results exported to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            raise

    def get_network_details(self, ssid):
        """Get detailed information about a specific network"""
        try:
            if ssid == 'current':
                return self.get_current_connection()
            
            networks = self.scan_available_networks()
            for network in networks:
                if network.get('ssid') == ssid:
                    return network
            return None
        except Exception as e:
            logger.error(f"Failed to get network details for {ssid}: {e}")
            return None
    
    def __del__(self):
        """Cleanup when scanner is destroyed"""
        if hasattr(self, 'is_scanning') and self.is_scanning:
            self.stop_monitoring()