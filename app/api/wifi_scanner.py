"""
Wi-Fi Scanner API Module
Purpose: Wi-Fi network discovery and scanning functionality
File: app/api/wifi_scanner.py
"""

import subprocess
import re
import json
import time
import threading
import functools
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
import psutil
import platform
import socket
import struct
import logging

# Import from project modules
from app.utils.decorators import rate_limit, log_activity, validate_json
from app.utils.validators import InputValidator, sanitize_input
from app.models.audit_logs import AuditLog
from app.models.scan_results import ScanResult

# Create blueprint
wifi_scanner_bp = Blueprint('wifi_scanner', __name__)

# Configure logging
logger = logging.getLogger(__name__)

class NetworkInfo:
    """Network information container"""
    
    def __init__(self, ssid, bssid, signal_strength, encryption, channel, frequency):
        self.ssid = ssid
        self.bssid = bssid
        self.signal_strength = signal_strength
        self.encryption = encryption
        self.channel = channel
        self.frequency = frequency
        self.timestamp = datetime.utcnow()
        self.quality = self._calculate_quality()
        self.vendor = self._identify_vendor()
    
    def _calculate_quality(self):
        """Calculate signal quality percentage"""
        if self.signal_strength >= -30:
            return 100
        elif self.signal_strength >= -67:
            return 70
        elif self.signal_strength >= -70:
            return 60
        elif self.signal_strength >= -80:
            return 50
        elif self.signal_strength >= -90:
            return 30
        else:
            return 10
    
    def _identify_vendor(self):
        """Identify device vendor from MAC address"""
        if not self.bssid:
            return "Unknown"
        
        # Simple vendor identification based on OUI
        oui_prefix = self.bssid.upper().replace(':', '')[:6]
        vendor_map = {
            '001B2F': 'Belkin',
            '0013CE': 'Linksys',
            '001346': 'Netgear',
            '0024A5': 'Asus',
            '001E58': 'TP-Link',
            '001AEF': 'D-Link',
            '00146C': 'Netgear',
            '001CF0': 'Apple',
            '0016EA': 'Apple',
        }
        
        return vendor_map.get(oui_prefix, "Unknown")
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'ssid': self.ssid,
            'bssid': self.bssid,
            'signal_strength': self.signal_strength,
            'signal_quality': self.quality,
            'encryption': self.encryption,
            'channel': self.channel,
            'frequency': self.frequency,
            'vendor': self.vendor,
            'timestamp': self.timestamp.isoformat()
        }

class ScanConfiguration:
    """Scan configuration management"""
    
    def __init__(self, scan_type='basic', timeout=30, channels=None, include_hidden=False):
        self.scan_type = scan_type
        self.timeout = timeout
        self.channels = channels or []
        self.include_hidden = include_hidden
        self.passive = False
        self.detailed = scan_type == 'detailed'
    
    def validate(self):
        """Validate scan configuration"""
        if self.timeout < 5 or self.timeout > 300:
            raise ValueError("Timeout must be between 5 and 300 seconds")
        
        if self.channels:
            valid_channels = list(range(1, 15))  # 2.4GHz channels
            valid_channels.extend(range(36, 166, 4))  # 5GHz channels
            for channel in self.channels:
                if channel not in valid_channels:
                    raise ValueError(f"Invalid channel: {channel}")
        
        return True

class SignalAnalyzer:
    """Signal strength analysis utilities"""
    
    @staticmethod
    def calculate_distance(signal_strength, frequency):
        """Estimate distance from signal strength"""
        # Simplified calculation
        if signal_strength == 0:
            return -1
        
        # Free space path loss formula approximation
        if frequency > 4000:  # 5GHz
            return round(10 ** ((-signal_strength - 27.55 - 20 * 2.4) / 20), 2)
        else:  # 2.4GHz
            return round(10 ** ((-signal_strength - 27.55 - 20 * 2.0) / 20), 2)
    
    @staticmethod
    def analyze_channel_overlap(networks):
        """Analyze channel overlap and interference"""
        channel_usage = {}
        for network in networks:
            channel = network.get('channel', 0)
            if channel not in channel_usage:
                channel_usage[channel] = []
            channel_usage[channel].append(network)
        
        overlaps = {}
        for channel, nets in channel_usage.items():
            if len(nets) > 1:
                overlaps[channel] = {
                    'count': len(nets),
                    'networks': [n['ssid'] for n in nets],
                    'interference_level': 'high' if len(nets) > 3 else 'medium'
                }
        
        return overlaps

class WiFiScanner:
    """Main Wi-Fi scanning engine with all methods properly integrated"""
    
    def __init__(self):
        self.scanning_active = False
        self.scan_results = []
        self.platform = platform.system().lower()
        self.interface = self._get_wireless_interface()
    
    def _get_wireless_interface(self):
        """Get wireless network interface"""
        try:
            if self.platform == 'windows':
                # Windows interface detection
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Name' in line and 'Wi-Fi' in line:
                            return line.split(':')[1].strip()
                return 'Wi-Fi'  # Default Windows interface name
            
            elif self.platform == 'linux':
                # Linux interface detection
                interfaces = psutil.net_if_stats()
                for interface in interfaces:
                    if interface.startswith(('wlan', 'wlp', 'wifi')):
                        return interface
                return 'wlan0'  # Default fallback
            
            elif self.platform == 'darwin':  # macOS
                return 'en0'  # Default macOS Wi-Fi interface
            
        except Exception as e:
            logger.error(f"Error detecting wireless interface: {e}")
            return 'wlan0'  # Safe fallback
    
    def scan_available_networks(self, config=None):
        """Discover available Wi-Fi networks"""
        if config is None:
            config = ScanConfiguration()
        
        config.validate()
        self.scanning_active = True
        networks = []
        
        try:
            if self.platform == 'windows':
                networks = self._scan_windows(config)
            elif self.platform == 'linux':
                networks = self._scan_linux(config)
            elif self.platform == 'darwin':
                networks = self._scan_macos(config)
            
            # Post-process results
            for network in networks:
                if isinstance(network, NetworkInfo):
                    network.distance = self._calculate_distance(
                        network.signal_strength, network.frequency
                    )
            
            self.scan_results = networks
            return networks
            
        except Exception as e:
            logger.error(f"Network scanning error: {e}")
            raise
        finally:
            self.scanning_active = False
    
    def _calculate_distance(self, signal_strength, frequency):
        """Estimate distance from signal strength"""
        # Simplified calculation
        if signal_strength == 0:
            return -1
        
        # Free space path loss formula approximation
        if frequency > 4000:  # 5GHz
            return round(10 ** ((-signal_strength - 27.55 - 20 * 2.4) / 20), 2)
        else:  # 2.4GHz
            return round(10 ** ((-signal_strength - 27.55 - 20 * 2.0) / 20), 2)
    
    def _scan_windows(self, config):
        """Windows-specific scanning using netsh"""
        networks = []
        try:
            # Use netsh to scan for networks
            cmd = ['netsh', 'wlan', 'show', 'profiles']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                # Parse netsh output
                for line in result.stdout.split('\n'):
                    if 'All User Profile' in line:
                        ssid = line.split(':')[1].strip()
                        if ssid:
                            network_info = self._get_network_details_windows(ssid)
                            if network_info:
                                networks.append(network_info)
            
            # Also try to get available networks
            cmd = ['netsh', 'wlan', 'show', 'available']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                networks.extend(self._parse_netsh_available(result.stdout))
                
        except subprocess.TimeoutExpired:
            logger.warning("Windows network scan timeout")
        except Exception as e:
            logger.error(f"Windows scanning error: {e}")
        
        return networks
    
    def _scan_linux(self, config):
        """Linux-specific scanning using iwlist/nmcli"""
        networks = []
        
        try:
            # Try nmcli first (NetworkManager)
            cmd = ['nmcli', '-t', '-f', 'SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY', 
                   'dev', 'wifi', 'list']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                networks = self._parse_nmcli_output(result.stdout)
            else:
                # Fallback to iwlist
                networks = self._scan_iwlist(config)
                
        except subprocess.TimeoutExpired:
            logger.warning("Linux network scan timeout")
        except FileNotFoundError:
            logger.warning("nmcli not found, trying iwlist")
            networks = self._scan_iwlist(config)
        except Exception as e:
            logger.error(f"Linux scanning error: {e}")
        
        return networks
    
    def _scan_macos(self, config):
        """macOS-specific scanning using airport utility"""
        networks = []
        
        try:
            # Use airport utility for scanning
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            cmd = [airport_path, '-s']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                networks = self._parse_airport_output(result.stdout)
                
        except subprocess.TimeoutExpired:
            logger.warning("macOS network scan timeout")
        except FileNotFoundError:
            logger.warning("airport utility not found")
        except Exception as e:
            logger.error(f"macOS scanning error: {e}")
        
        return networks
    
    def _parse_nmcli_output(self, output):
        """Parse nmcli command output"""
        networks = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
                
            fields = line.split(':')
            if len(fields) >= 9:
                ssid = fields[0] if fields[0] != '--' else 'Hidden Network'
                bssid = fields[1]
                channel = int(fields[3]) if fields[3].isdigit() else 0
                frequency = int(fields[4]) if fields[4].isdigit() else 0
                signal = int(fields[6]) if fields[6].lstrip('-').isdigit() else -100
                security = fields[8]
                
                network = NetworkInfo(
                    ssid=ssid,
                    bssid=bssid,
                    signal_strength=signal,
                    encryption=security,
                    channel=channel,
                    frequency=frequency
                )
                networks.append(network)
        
        return networks
    
    def _scan_iwlist(self, config):
        """Fallback scanning using iwlist"""
        networks = []
        
        try:
            cmd = ['iwlist', self.interface, 'scan']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=config.timeout)
            
            if result.returncode == 0:
                networks = self._parse_iwlist_output(result.stdout)
                
        except Exception as e:
            logger.error(f"iwlist scanning error: {e}")
        
        return networks
    
    def _parse_iwlist_output(self, output):
        """Parse iwlist scan output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(self._create_network_from_iwlist(current_network))
                current_network = {'bssid': line.split('Address: ')[1]}
            
            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip('"')
                current_network['ssid'] = ssid if ssid else 'Hidden Network'
            
            elif 'Signal level=' in line:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                if signal_match:
                    current_network['signal'] = int(signal_match.group(1))
            
            elif 'Channel:' in line:
                channel_match = re.search(r'Channel:(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))
            
            elif 'Encryption key:' in line:
                current_network['encryption'] = 'WEP' if 'on' in line else 'Open'
        
        if current_network:
            networks.append(self._create_network_from_iwlist(current_network))
        
        return networks
    
    def _create_network_from_iwlist(self, data):
        """Create NetworkInfo from iwlist data"""
        return NetworkInfo(
            ssid=data.get('ssid', 'Unknown'),
            bssid=data.get('bssid', ''),
            signal_strength=data.get('signal', -100),
            encryption=data.get('encryption', 'Unknown'),
            channel=data.get('channel', 0),
            frequency=data.get('channel', 0) * 5 + 2400 if data.get('channel', 0) <= 14 else 0
        )
    
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
        """Get current connection on Windows - IMPROVED VERSION"""
        try:
            # First, check if Wi-Fi is even available
            cmd = ['netsh', 'wlan', 'show', 'drivers']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                logger.warning("Wi-Fi drivers not available")
                return None
            
            # Now get interface information
            cmd = ['netsh', 'wlan', 'show', 'interfaces']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                connection_info = self._parse_netsh_interface(result.stdout)
                if connection_info and connection_info.get('connected'):
                    return connection_info
            
            logger.info("No active Wi-Fi connection found")
            return None
            
        except subprocess.TimeoutExpired:
            logger.error("Windows Wi-Fi command timeout")
            return None
        except Exception as e:
            logger.error(f"Windows current connection error: {e}")
            return None
    
    def _parse_netsh_interface(self, output):
        """Parse netsh wlan show interfaces output - FIXED VERSION"""
        try:
            connection_info = {
                'connected': False,
                'ssid': None,
                'bssid': None,
                'signal_strength': None,
                'signal_quality': None,
                'security': None,
                'security_type': None,  # Add this field
                'channel': None,
                'frequency': None,  # Add this field
                'ip_address': None,
                'gateway': None,  # Add this field
                'dns_servers': [],  # Add this field
                'connection_speed': None,  # Add this field
                'connection_time': None,  # Add this field
                'risk_level': 'Unknown'
            }
            
            lines = output.split('\n')
            current_interface = None
            
            for line in lines:
                line = line.strip()
                
                # Check for Wi-Fi interface
                if 'Name' in line and ('Wi-Fi' in line or 'Wireless' in line):
                    current_interface = line.split(':')[1].strip()
                    continue
                
                # Only process if we found a Wi-Fi interface
                if not current_interface:
                    continue
                    
                if 'State' in line:
                    state = line.split(':')[1].strip().lower()
                    connection_info['connected'] = 'connected' in state
                
                elif 'SSID' in line and 'BSSID' not in line:
                    # Extract SSID - be more careful with parsing
                    ssid_part = line.split(':', 1)
                    if len(ssid_part) > 1:
                        ssid = ssid_part[1].strip()
                        if ssid and ssid != '':
                            connection_info['ssid'] = ssid
                
                elif 'BSSID' in line:
                    bssid_part = line.split(':', 1)
                    if len(bssid_part) > 1:
                        bssid = bssid_part[1].strip()
                        if bssid and bssid != '':
                            connection_info['bssid'] = bssid
                
                elif 'Signal' in line:
                    # Extract signal percentage
                    signal_match = re.search(r'(\d+)%', line)
                    if signal_match:
                        percentage = int(signal_match.group(1))
                        # Convert percentage to dBm (more accurate conversion)
                        if percentage >= 80:
                            dbm = -30
                        elif percentage >= 60:
                            dbm = -50
                        elif percentage >= 40:
                            dbm = -67
                        elif percentage >= 20:
                            dbm = -80
                        else:
                            dbm = -90
                        
                        connection_info['signal_strength'] = f"{dbm} dBm"
                        connection_info['signal_quality'] = f"{percentage}%"
                
                elif 'Authentication' in line:
                    auth_part = line.split(':', 1)
                    if len(auth_part) > 1:
                        auth = auth_part[1].strip()
                        connection_info['security'] = auth
                        connection_info['security_type'] = auth
                
                elif 'Channel' in line:
                    channel_match = re.search(r'(\d+)', line)
                    if channel_match:
                        channel = int(channel_match.group(1))
                        connection_info['channel'] = str(channel)
                        # Calculate frequency from channel
                        if 1 <= channel <= 14:
                            freq = 2407 + (channel * 5)
                            connection_info['frequency'] = f"{freq} MHz"
                        elif channel >= 36:
                            freq = 5000 + (channel * 5)
                            connection_info['frequency'] = f"{freq} MHz"
                
                elif 'Receive rate' in line or 'Transmit rate' in line:
                    # Extract connection speed
                    speed_match = re.search(r'(\d+(?:\.\d+)?)', line)
                    if speed_match:
                        speed = float(speed_match.group(1))
                        if speed >= 1000:
                            connection_info['connection_speed'] = f"{speed/1000:.1f} Gbps"
                            connection_info['data_rate'] = f"{speed/1000:.1f} Gbps"
                        else:
                            connection_info['connection_speed'] = f"{speed} Mbps"
                            connection_info['data_rate'] = f"{speed} Mbps"
                
                elif 'Radio type' in line:
                    # Extract radio type (802.11n, 802.11ac, etc.)
                    radio_part = line.split(':', 1)
                    if len(radio_part) > 1:
                        radio_type = radio_part[1].strip()
                        connection_info['radio_type'] = radio_type
                
                elif 'Physical address' in line:
                    # Extract MAC address
                    mac_part = line.split(':', 1)
                    if len(mac_part) > 1:
                        mac_addr = mac_part[1].strip()
                        connection_info['mac_address'] = mac_addr
            
            # Get IP address and network info if connected
            if connection_info['connected']:
                connection_info['ip_address'] = self._get_local_ip()
                
                # Get gateway and DNS info
                network_info = self._get_network_details()
                if network_info:
                    connection_info.update(network_info)
                
                # Get connection time
                connection_info['connection_time'] = self._get_connection_time()
                
                # Assess risk level
                connection_info['risk_level'] = self._assess_connection_risk(connection_info)
            
            return connection_info if connection_info['connected'] else None
            
        except Exception as e:
            logger.error(f"Error parsing netsh interface output: {e}")
            return None
    
    def _parse_netsh_available(self, output):
        """Parse netsh wlan show available output"""
        networks = []
        current_network = {}
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if 'SSID' in line and 'BSSID' not in line:
                    if current_network and current_network.get('ssid'):
                        network_info = self._create_network_from_netsh(current_network)
                        if network_info:
                            networks.append(network_info)
                    
                    ssid_match = re.search(r'SSID \d+ : (.+)', line)
                    if ssid_match:
                        current_network = {'ssid': ssid_match.group(1).strip()}
                
                elif 'Signal' in line and current_network:
                    signal_match = re.search(r'(\d+)%', line)
                    if signal_match:
                        percentage = int(signal_match.group(1))
                        dbm = -100 + (percentage * 70 / 100)  # Convert to dBm
                        current_network['signal'] = int(dbm)
                
                elif 'Authentication' in line and current_network:
                    auth = line.split(':')[1].strip()
                    current_network['security'] = auth
                
                elif 'Channel' in line and current_network:
                    channel_match = re.search(r'(\d+)', line)
                    if channel_match:
                        current_network['channel'] = int(channel_match.group(1))
            
            # Add the last network if exists
            if current_network and current_network.get('ssid'):
                network_info = self._create_network_from_netsh(current_network)
                if network_info:
                    networks.append(network_info)
        
        except Exception as e:
            logger.error(f"Error parsing netsh available output: {e}")
        
        return networks
    
    def _get_network_details_windows(self, ssid):
        """Get detailed network information for a specific SSID on Windows"""
        try:
            # Get network profile details
            cmd = ['netsh', 'wlan', 'show', 'profile', ssid, 'key=clear']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return self._parse_network_profile(result.stdout, ssid)
            else:
                logger.warning(f"Could not get details for network {ssid}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout getting network details for {ssid}")
            return None
        except Exception as e:
            logger.error(f"Error getting network details for {ssid}: {e}")
            return None
    
    def _create_network_from_netsh(self, data):
        """Create NetworkInfo from netsh data"""
        try:
            return NetworkInfo(
                ssid=data.get('ssid', 'Unknown'),
                bssid=data.get('bssid', ''),
                signal_strength=data.get('signal', -100),
                encryption=data.get('security', 'Unknown'),
                channel=data.get('channel', 0),
                frequency=self._channel_to_frequency(data.get('channel', 0))
            )
        except Exception as e:
            logger.error(f"Error creating network from netsh data: {e}")
            return None
    
    def _get_network_details(self):
        """Get additional network details like gateway and DNS"""
        try:
            network_info = {
                'gateway': None,
                'dns_servers': []
            }
            
            # Get gateway info
            cmd = ['ipconfig', '/all']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                in_wifi_section = False
                
                for line in lines:
                    line = line.strip()
                    
                    # Look for Wi-Fi adapter section
                    if 'Wireless LAN adapter Wi-Fi' in line or 'Wi-Fi' in line:
                        in_wifi_section = True
                        continue
                    
                    # If we hit another adapter section, stop
                    if line.startswith('Ethernet adapter') or line.startswith('Wireless LAN adapter'):
                        if 'Wi-Fi' not in line:
                            in_wifi_section = False
                            continue
                    
                    if in_wifi_section:
                        if 'Default Gateway' in line:
                            gateway_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if gateway_match:
                                network_info['gateway'] = gateway_match.group(1)
                        
                        elif 'DNS Servers' in line:
                            dns_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if dns_match:
                                network_info['dns_servers'].append(dns_match.group(1))
            
            return network_info
            
        except Exception as e:
            logger.error(f"Error getting network details: {e}")
            return {'gateway': None, 'dns_servers': []}
        
    def _get_connection_time(self):
        """Get connection duration"""
        try:
            # This is a simplified version - Windows doesn't easily provide connection time
            # You could store connection start time when connection is detected
            return "Unknown"
        except Exception as e:
            logger.error(f"Error getting connection time: {e}")
            return "Unknown"
    
    def _parse_network_profile(self, output, ssid):
        """Parse network profile information"""
        try:
            network_info = {
                'ssid': ssid,
                'security': 'Unknown',
                'key_content': None
            }
            
            for line in output.split('\n'):
                line = line.strip()
                
                if 'Authentication' in line:
                    auth = line.split(':')[1].strip()
                    network_info['security'] = auth
                
                elif 'Key Content' in line:
                    key = line.split(':')[1].strip()
                    network_info['key_content'] = key if key != 'Absent' else None
            
            return NetworkInfo(
                ssid=ssid,
                bssid='',
                signal_strength=-50,  # Default for saved networks
                encryption=network_info['security'],
                channel=0,
                frequency=0
            )
        
        except Exception as e:
            logger.error(f"Error parsing network profile: {e}")
            return None
        
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
            
            current_ssid = current_conn.get('ssid')
            if not current_ssid or current_ssid in ['Unknown Network', 'Connected Network']:
                logger.warning("Current SSID unknown, cannot determine signal strength")
                return -100
            
            # Find the network in scan results
            for network in self.scan_results:
                if network.ssid == current_ssid:
                    return network.signal_strength
            
            # If not found in current scan results, perform a quick scan
            logger.info("Current network not in scan results, performing quick scan")
            networks = self.scan_available_networks()
            
            for network in networks:
                if network.ssid == current_ssid:
                    return network.signal_strength
            
            logger.warning(f"Current network '{current_ssid}' not found in scan results")
            return -100
            
        except Exception as e:
            logger.error(f"Error getting current signal strength: {e}")
            return -100
    
    def _get_local_ip(self):
        """Get local IP address - IMPROVED VERSION"""
        try:
            # Method 1: Try to get Wi-Fi adapter IP specifically
            cmd = ['ipconfig']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                in_wifi_section = False
                
                for line in lines:
                    if 'Wireless LAN adapter Wi-Fi' in line:
                        in_wifi_section = True
                        continue
                    elif line.startswith('Ethernet adapter') or line.startswith('Wireless LAN adapter'):
                        if 'Wi-Fi' not in line:
                            in_wifi_section = False
                            continue
                    
                    if in_wifi_section and 'IPv4 Address' in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            return ip_match.group(1)
            
            # Method 2: Fallback to socket method
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
                return local_ip
                
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return '127.0.0.1'
    
    def _assess_connection_risk(self, connection_info):
        """Assess security risk of current connection"""
        try:
            security = connection_info.get('security', '').lower()
            
            if 'wpa3' in security:
                return 'Low'
            elif 'wpa2' in security:
                return 'Low'
            elif 'wpa' in security:
                return 'Medium'
            elif 'wep' in security:
                return 'High'
            elif 'open' in security or not security:
                return 'Very High'
            else:
                return 'Unknown'
        except Exception:
            return 'Unknown'
    
    def _channel_to_frequency(self, channel):
        """Convert Wi-Fi channel to frequency"""
        if not channel or channel == 0:
            return 0
        
        # 2.4 GHz channels
        if 1 <= channel <= 14:
            return 2407 + (channel * 5)
        
        # 5 GHz channels (simplified)
        elif 36 <= channel <= 165:
            return 5000 + (channel * 5)
        
        return 0
    
    def _get_current_linux(self):
        """Get current connection on Linux"""
        try:
            cmd = ['nmcli', '-t', '-f', 'ACTIVE,SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY', 
                   'dev', 'wifi', 'list']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('yes:'):
                        return self._parse_active_connection(line)
        except Exception as e:
            logger.error(f"Linux current connection error: {e}")
        
        return None
    
    def _parse_active_connection(self, line):
        """Parse active connection from nmcli output"""
        try:
            fields = line.split(':')
            if len(fields) >= 9:
                return {
                    'connected': True,
                    'ssid': fields[1] if fields[1] != '--' else 'Hidden Network',
                    'bssid': fields[2],
                    'signal_strength': f"{fields[7]} dBm" if fields[7].lstrip('-').isdigit() else 'Unknown',
                    'signal_quality': f"{fields[7]}%" if fields[7].lstrip('-').isdigit() else 'Unknown',
                    'security': fields[8],
                    'channel': fields[4] if fields[4].isdigit() else 'Unknown',
                    'ip_address': self._get_local_ip(),
                    'risk_level': self._assess_connection_risk({'security': fields[8]})
                }
        except Exception as e:
            logger.error(f"Error parsing active connection: {e}")
        
        return None
    
    def _get_current_macos(self):
        """Get current connection on macOS"""
        try:
            # Use networksetup to get current Wi-Fi info
            cmd = ['networksetup', '-getairportnetwork', 'en0']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and 'You are not associated' not in result.stdout:
                ssid_match = re.search(r'Current Wi-Fi Network: (.+)', result.stdout)
                if ssid_match:
                    ssid = ssid_match.group(1).strip()
                    
                    # Get additional info using airport
                    airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
                    cmd = [airport_path, '-I']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        return self._parse_airport_info(result.stdout, ssid)
            
        except Exception as e:
            logger.error(f"macOS current connection error: {e}")
        
        return None
    
    def _parse_airport_info(self, output, ssid):
        """Parse airport -I output for current connection"""
        try:
            connection_info = {
                'connected': True,
                'ssid': ssid,
                'bssid': None,
                'signal_strength': None,
                'signal_quality': None,
                'security': None,
                'channel': None,
                'ip_address': self._get_local_ip(),
                'risk_level': 'Unknown'
            }
            
            for line in output.split('\n'):
                line = line.strip()
                
                if 'BSSID:' in line:
                    connection_info['bssid'] = line.split(':')[1].strip()
                
                elif 'agrCtlRSSI:' in line:
                    rssi = line.split(':')[1].strip()
                    connection_info['signal_strength'] = f"{rssi} dBm"
                    # Convert RSSI to percentage (rough approximation)
                    rssi_int = int(rssi) if rssi.lstrip('-').isdigit() else -100
                    percentage = max(0, min(100, (rssi_int + 100) * 70 / 100))
                    connection_info['signal_quality'] = f"{percentage:.0f}%"
                
                elif 'channel:' in line:
                    connection_info['channel'] = line.split(':')[1].strip()
            
            connection_info['risk_level'] = self._assess_connection_risk(connection_info)
            return connection_info
            
        except Exception as e:
            logger.error(f"Error parsing airport info: {e}")
            return None
    
    def _parse_airport_output(self, output):
        """Parse airport -s output for network scanning"""
        networks = []
        
        try:
            lines = output.split('\n')[1:]  # Skip header
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse airport scan line format
                parts = line.split()
                if len(parts) >= 6:
                    ssid = parts[0]
                    bssid = parts[1] if len(parts) > 1 else ''
                    rssi = int(parts[2]) if len(parts) > 2 and parts[2].lstrip('-').isdigit() else -100
                    channel = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                    security = ' '.join(parts[6:]) if len(parts) > 6 else 'Open'
                    
                    network = NetworkInfo(
                        ssid=ssid,
                        bssid=bssid,
                        signal_strength=rssi,
                        encryption=security,
                        channel=channel,
                        frequency=self._channel_to_frequency(channel)
                    )
                    networks.append(network)
        
        except Exception as e:
            logger.error(f"Error parsing airport output: {e}")
        
        return networks
    
    def _get_fallback_connection(self):
        """Fallback connection info when platform-specific methods fail - IMPROVED"""
        try:
            # Try to get basic network connectivity info
            local_ip = self._get_local_ip()
            
            if local_ip and local_ip != '127.0.0.1':
                # Try to determine if this is likely a Wi-Fi connection
                is_wifi = self._detect_wifi_connection()
                
                return {
                    'connected': True,
                    'ssid': 'Connected Network',  # Better than "Unknown Network"
                    'bssid': None,
                    'signal_strength': 'Unknown',
                    'signal_quality': 'Unknown',
                    'security': 'Unknown',
                    'security_type': 'Unknown',
                    'channel': 'Unknown',
                    'frequency': 'Unknown',
                    'ip_address': local_ip,
                    'gateway': 'Unknown',
                    'dns_servers': [],
                    'connection_speed': 'Unknown',
                    'connection_time': 'Unknown',
                    'risk_level': 'Unknown',
                    'platform': self.platform,
                    'fallback': True,
                    'connection_type': 'Wi-Fi' if is_wifi else 'Unknown'
                }
            else:
                return None
                
        except Exception as e:
            logger.error(f"Fallback connection method failed: {e}")
            return None
        
    def _detect_wifi_connection(self):
        """Try to detect if current connection is Wi-Fi"""
        try:
            if self.platform == 'windows':
                # Check network adapter types
                cmd = ['wmic', 'path', 'win32_networkadapter', 'get', 'name,adaptertype']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    return 'wireless' in result.stdout.lower() or 'wi-fi' in result.stdout.lower()
            
            return True  # Assume Wi-Fi by default for this scanner
            
        except Exception:
            return True  # Default assumption
    
    def detect_hidden_networks(self):
        """Detect hidden SSID networks"""
        hidden_networks = []
        
        try:
            # Look for networks with empty or hidden SSIDs
            for network in self.scan_results:
                if not network.ssid or network.ssid in ['', 'Hidden Network', '<hidden>']:
                    hidden_networks.append({
                        'bssid': network.bssid,
                        'signal_strength': network.signal_strength,
                        'encryption': network.encryption,
                        'channel': network.channel,
                        'estimated_name': f"Hidden_{network.bssid.replace(':', '')[-6:]}"
                    })
        
        except Exception as e:
            logger.error(f"Hidden network detection error: {e}")
        
        return hidden_networks
    
    def analyze_channel_usage(self, data):
        """Analyze channel usage patterns"""
        try:
            channel_usage = {}
            networks = data.get('networks', [])
            
            for network in networks:
                channel = network.get('channel', 0)
                if channel:
                    if channel not in channel_usage:
                        channel_usage[channel] = {
                            'count': 0,
                            'networks': [],
                            'signal_strengths': []
                        }
                    
                    channel_usage[channel]['count'] += 1
                    channel_usage[channel]['networks'].append(network.get('ssid', 'Unknown'))
                    signal = network.get('signal_strength', -100)
                    if isinstance(signal, (int, float)):
                        channel_usage[channel]['signal_strengths'].append(signal)
            
            # Calculate interference levels
            for channel, info in channel_usage.items():
                if info['count'] > 3:
                    info['interference_level'] = 'high'
                elif info['count'] > 1:
                    info['interference_level'] = 'medium'
                else:
                    info['interference_level'] = 'low'
                
                # Calculate average signal strength
                if info['signal_strengths']:
                    info['average_signal'] = sum(info['signal_strengths']) / len(info['signal_strengths'])
                else:
                    info['average_signal'] = -100
            
            return {
                'channel_usage': channel_usage,
                'total_channels_used': len(channel_usage),
                'most_congested_channel': max(channel_usage.items(), key=lambda x: x[1]['count'])[0] if channel_usage else None,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Channel analysis error: {e}")
            return {
                'channel_usage': {},
                'total_channels_used': 0,
                'most_congested_channel': None,
                'error': str(e),
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
    
    def get_network_security_info(self, ssid):
        """Get detailed security information for a specific network"""
        try:
            for network in self.scan_results:
                if network.ssid == ssid:
                    security_info = {
                        'ssid': network.ssid,
                        'bssid': network.bssid,
                        'encryption': network.encryption,
                        'signal_strength': network.signal_strength,
                        'channel': network.channel,
                        'frequency': network.frequency,
                        'security_level': self._get_security_level(network.encryption),
                        'recommendations': self._get_security_recommendations(network.encryption),
                        'vulnerabilities': self._check_vulnerabilities(network)
                    }
                    return security_info
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting security info for {ssid}: {e}")
            return None
    
    def _get_security_level(self, encryption):
        """Determine security level based on encryption type"""
        encryption_lower = encryption.lower()
        
        if 'wpa3' in encryption_lower:
            return 'Very High'
        elif 'wpa2' in encryption_lower:
            return 'High'
        elif 'wpa' in encryption_lower and 'wpa2' not in encryption_lower:
            return 'Medium'
        elif 'wep' in encryption_lower:
            return 'Low'
        elif 'open' in encryption_lower or not encryption:
            return 'None'
        else:
            return 'Unknown'
    
    def _get_security_recommendations(self, encryption):
        """Get security recommendations based on encryption type"""
        encryption_lower = encryption.lower()
        
        if 'wpa3' in encryption_lower:
            return ["Excellent security - no changes needed"]
        elif 'wpa2' in encryption_lower:
            return ["Good security", "Consider upgrading to WPA3 if available"]
        elif 'wpa' in encryption_lower and 'wpa2' not in encryption_lower:
            return ["Upgrade to WPA2 or WPA3 immediately", "WPA is vulnerable to attacks"]
        elif 'wep' in encryption_lower:
            return ["Extremely vulnerable - upgrade immediately", "WEP can be cracked in minutes"]
        elif 'open' in encryption_lower or not encryption:
            return ["No security - avoid for sensitive data", "All traffic is visible to others"]
        else:
            return ["Unknown security type - investigate further"]
    
    def _check_vulnerabilities(self, network):
        """Check for known vulnerabilities"""
        vulnerabilities = []
        encryption_lower = network.encryption.lower()
        
        if 'wep' in encryption_lower:
            vulnerabilities.append({
                'type': 'Weak Encryption',
                'severity': 'Critical',
                'description': 'WEP encryption is easily breakable'
            })
        
        if 'open' in encryption_lower or not network.encryption:
            vulnerabilities.append({
                'type': 'No Encryption',
                'severity': 'Critical',
                'description': 'Network traffic is unencrypted and visible'
            })
        
        if network.signal_strength > -30:
            vulnerabilities.append({
                'type': 'Very Strong Signal',
                'severity': 'Low',
                'description': 'Very close proximity - potential for easier attacks'
            })
        
        return vulnerabilities
    
    def get_signal_strength_analysis(self):
        """Analyze signal strength patterns"""
        try:
            if not self.scan_results:
                return None
            
            signals = [network.signal_strength for network in self.scan_results 
                      if isinstance(network.signal_strength, (int, float))]
            
            if not signals:
                return None
            
            analysis = {
                'total_networks': len(self.scan_results),
                'average_signal': sum(signals) / len(signals),
                'strongest_signal': max(signals),
                'weakest_signal': min(signals),
                'signal_distribution': {
                    'excellent': len([s for s in signals if s > -50]),
                    'good': len([s for s in signals if -70 <= s <= -50]),
                    'fair': len([s for s in signals if -80 <= s < -70]),
                    'poor': len([s for s in signals if s < -80])
                },
                'strongest_networks': []
            }
            
            # Get top 5 strongest networks
            sorted_networks = sorted(self.scan_results, 
                                   key=lambda x: x.signal_strength if isinstance(x.signal_strength, (int, float)) else -100, 
                                   reverse=True)
            
            for network in sorted_networks[:5]:
                if isinstance(network.signal_strength, (int, float)):
                    analysis['strongest_networks'].append({
                        'ssid': network.ssid,
                        'signal_strength': network.signal_strength,
                        'bssid': network.bssid,
                        'encryption': network.encryption
                    })
            
            return analysis
            
        except Exception as e:
            logger.error(f"Signal strength analysis error: {e}")
            return None
    
    def export_scan_results(self, format_type='json', filename=None):
        """Export scan results to file"""
        try:
            if not self.scan_results:
                logger.warning("No scan results to export")
                return None
            
            # Convert NetworkInfo objects to dictionaries
            export_data = {
                'scan_timestamp': datetime.utcnow().isoformat(),
                'platform': self.platform,
                'interface': self.interface,
                'total_networks': len(self.scan_results),
                'networks': [network.to_dict() for network in self.scan_results]
            }
            
            if filename is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"wifi_scan_{timestamp}.{format_type}"
            
            if format_type.lower() == 'json':
                import json
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
            
            elif format_type.lower() == 'csv':
                import csv
                with open(filename, 'w', newline='') as f:
                    if export_data['networks']:
                        fieldnames = export_data['networks'][0].keys()
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(export_data['networks'])
            
            else:
                raise ValueError(f"Unsupported format: {format_type}")
            
            logger.info(f"Scan results exported to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Export error: {e}")
            return None
    
    def get_network_statistics(self):
        """Get comprehensive network statistics"""
        try:
            if not self.scan_results:
                return None
            
            # Encryption type distribution
            encryption_count = {}
            channel_count = {}
            frequency_bands = {'2.4GHz': 0, '5GHz': 0, 'Other': 0}
            
            for network in self.scan_results:
                # Count encryption types
                enc_type = network.encryption.lower()
                if 'wpa3' in enc_type:
                    encryption_count['WPA3'] = encryption_count.get('WPA3', 0) + 1
                elif 'wpa2' in enc_type:
                    encryption_count['WPA2'] = encryption_count.get('WPA2', 0) + 1
                elif 'wpa' in enc_type:
                    encryption_count['WPA'] = encryption_count.get('WPA', 0) + 1
                elif 'wep' in enc_type:
                    encryption_count['WEP'] = encryption_count.get('WEP', 0) + 1
                elif 'open' in enc_type or not network.encryption:
                    encryption_count['Open'] = encryption_count.get('Open', 0) + 1
                else:
                    encryption_count['Other'] = encryption_count.get('Other', 0) + 1
                
                # Count channels
                if network.channel:
                    channel_count[network.channel] = channel_count.get(network.channel, 0) + 1
                
                # Count frequency bands
                if network.frequency:
                    if 2400 <= network.frequency <= 2500:
                        frequency_bands['2.4GHz'] += 1
                    elif 5000 <= network.frequency <= 6000:
                        frequency_bands['5GHz'] += 1
                    else:
                        frequency_bands['Other'] += 1
            
            statistics = {
                'total_networks': len(self.scan_results),
                'encryption_distribution': encryption_count,
                'channel_distribution': channel_count,
                'frequency_band_distribution': frequency_bands,
                'security_summary': {
                    'secure_networks': encryption_count.get('WPA3', 0) + encryption_count.get('WPA2', 0),
                    'vulnerable_networks': encryption_count.get('WPA', 0) + encryption_count.get('WEP', 0) + encryption_count.get('Open', 0),
                    'security_percentage': round((encryption_count.get('WPA3', 0) + encryption_count.get('WPA2', 0)) / len(self.scan_results) * 100, 1)
                },
                'most_used_channel': max(channel_count.items(), key=lambda x: x[1])[0] if channel_count else None,
                'scan_timestamp': datetime.utcnow().isoformat()
            }
            
            return statistics
            
        except Exception as e:
            logger.error(f"Statistics calculation error: {e}")
            return None
    
    def refresh_scan(self, config=None):
        """Refresh network scan with current configuration"""
        try:
            logger.info("Refreshing network scan...")
            self.scan_results = []
            return self.scan_available_networks(config)
        except Exception as e:
            logger.error(f"Refresh scan error: {e}")
            return []
    
    def is_scanning(self):
        """Check if scanning is currently active"""
        return self.scanning_active
    
    def stop_scanning(self):
        """Stop any active scanning operations"""
        try:
            self.scanning_active = False
            logger.info("Scanning stopped")
        except Exception as e:
            logger.error(f"Error stopping scan: {e}")
    
    def get_interface_info(self):
        """Get information about the wireless interface"""
        try:
            interface_info = {
                'interface_name': self.interface,
                'platform': self.platform,
                'available': False,
                'status': 'Unknown'
            }
            
            if self.platform == 'linux':
                try:
                    import psutil
                    net_stats = psutil.net_if_stats()
                    if self.interface in net_stats:
                        stats = net_stats[self.interface]
                        interface_info.update({
                            'available': True,
                            'is_up': stats.isup,
                            'speed': stats.speed,
                            'mtu': stats.mtu
                        })
                except Exception as e:
                    logger.error(f"Error getting Linux interface info: {e}")
            
            elif self.platform == 'windows':
                try:
                    cmd = ['netsh', 'wlan', 'show', 'interfaces']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        interface_info['available'] = 'Wi-Fi' in result.stdout
                        interface_info['status'] = 'Available' if interface_info['available'] else 'Not Found'
                except Exception as e:
                    logger.error(f"Error getting Windows interface info: {e}")
            
            return interface_info
            
        except Exception as e:
            logger.error(f"Interface info error: {e}")
            return {'interface_name': self.interface, 'platform': self.platform, 'available': False, 'error': str(e)}

class NetworkDiscovery:
    """Network discovery system - Fixed version"""
    
    def __init__(self):
        self.scanner = WiFiScanner()
    
    def discover_all_networks(self, config=None):
        """Comprehensive network discovery with better error handling"""
        try:
            # Perform standard scan with fallback
            try:
                networks = self.scanner.scan_available_networks(config)
            except Exception as scan_error:
                logger.error(f"Primary scan failed: {scan_error}")
                networks = []  # Fallback to empty list
            
            # Add hidden network detection with error handling
            try:
                hidden = self.scanner.detect_hidden_networks()
            except Exception as hidden_error:
                logger.error(f"Hidden network detection failed: {hidden_error}")
                hidden = []
            
            # Analyze channel usage with error handling
            try:
                network_dicts = []
                for n in networks:
                    try:
                        if hasattr(n, 'to_dict'):
                            network_dicts.append(n.to_dict())
                        elif isinstance(n, dict):
                            network_dicts.append(n)
                    except Exception as convert_error:
                        logger.error(f"Error converting network to dict: {convert_error}")
                        continue
                
                channel_analysis = SignalAnalyzer.analyze_channel_overlap(network_dicts)
            except Exception as analysis_error:
                logger.error(f"Channel analysis failed: {analysis_error}")
                channel_analysis = {}
            
            return {
                'networks': network_dicts,
                'hidden_networks': hidden,
                'channel_analysis': channel_analysis,
                'scan_timestamp': datetime.utcnow().isoformat(),
                'total_networks': len(network_dicts)
            }
            
        except Exception as e:
            logger.error(f"Network discovery error: {e}")
            # Return minimal fallback result instead of raising
            return {
                'networks': [],
                'hidden_networks': [],
                'channel_analysis': {},
                'scan_timestamp': datetime.utcnow().isoformat(),
                'total_networks': 0,
                'error': str(e),
                'fallback': True
            }
        
    def get_current_connection(self):
        """Get current Wi-Fi connection information - Fixed version"""
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

# API Routes with unique endpoint names
@wifi_scanner_bp.route('/scan', methods=['GET', 'POST'], endpoint='scan_networks')
@login_required
@rate_limit(max_requests=10, per_seconds=60)
@log_activity()
def scan_networks():
    """Scan for available Wi-Fi networks - Fixed version"""
    try:
        # Handle both GET and POST requests
        if request.method == 'POST':
            data = request.get_json() or {}
            scan_type = data.get('scan_type', 'basic')
            timeout = int(data.get('timeout', 30))
            include_hidden = data.get('include_hidden', False)
        else:
            # GET request parameters
            scan_type = request.args.get('type', 'basic')
            timeout = int(request.args.get('timeout', 30))
            include_hidden = request.args.get('include_hidden', 'false').lower() == 'true'
        
        # Create scan configuration with validation
        try:
            config = ScanConfiguration(
                scan_type=scan_type,
                timeout=timeout,
                include_hidden=include_hidden
            )
            config.validate()
        except ValueError as ve:
            return jsonify({
                'success': False,
                'error': 'Invalid parameters',
                'message': str(ve)
            }), 400
        
        # Perform network discovery with error handling
        try:
            discovery = NetworkDiscovery()
            results = discovery.discover_all_networks(config)
        except Exception as scan_error:
            logger.error(f"Network discovery failed: {scan_error}")
            # Return basic fallback results
            results = {
                'networks': [],
                'hidden_networks': [],
                'channel_analysis': {},
                'scan_timestamp': datetime.utcnow().isoformat(),
                'total_networks': 0,
                'error': str(scan_error),
                'fallback': True
            }
        
        # Log scan activity with proper error handling
        try:
            AuditLog.log_event(
                user_id=current_user.id,
                event_type='wifi_scan',
                event_description=f"Scanned {results['total_networks']} networks"
            )
        except Exception as log_error:
            logger.error(f"Error logging scan activity: {log_error}")
        
        return jsonify({
            'success': True,
            'data': results,
            'message': f"Found {results['total_networks']} networks"
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': 'Invalid parameters',
            'message': str(e)
        }), 400
        
    except Exception as e:
        logger.error(f"Scan API error: {e}")
        return jsonify({
            'success': False,
            'error': 'Scan failed',
            'message': 'An error occurred during network scanning',
            'details': str(e)
        }), 500

@wifi_scanner_bp.route('/current', methods=['GET'], endpoint='get_current_wifi')
@login_required
@rate_limit(max_requests=20, per_seconds=60)
def get_current_wifi():
    """Get current Wi-Fi connection information"""
    try:
        scanner = WiFiScanner()
        current_connection = scanner.get_current_connection()
        
        if current_connection:
            return jsonify({
                'success': True,
                'data': current_connection,
                'connected': True
            })
        else:
            return jsonify({
                'success': True,
                'data': None,
                'connected': False,
                'message': 'No active Wi-Fi connection'
            })
            
    except Exception as e:
        logger.error(f"Current WiFi API error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get connection info',
            'message': str(e)
        }), 500

@wifi_scanner_bp.route('/signal-strength', methods=['GET'], endpoint='get_signal_strength')
@login_required
@rate_limit(max_requests=30, per_seconds=60)
def get_signal_strength():
    """Get real-time signal strength monitoring"""
    try:
        ssid = request.args.get('ssid')
        if not ssid:
            return jsonify({
                'success': False,
                'error': 'SSID required'
            }), 400
        
        scanner = WiFiScanner()
        current_info = scanner.get_current_connection()
        
        if current_info and current_info.get('ssid') == ssid:
            return jsonify({
                'success': True,
                'data': {
                    'ssid': ssid,
                    'signal_strength': current_info.get('signal_strength'),
                    'signal_quality': current_info.get('signal_quality'),
                    'timestamp': datetime.utcnow().isoformat()
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Not connected to specified network'
            }), 404
            
    except Exception as e:
        logger.error(f"Signal strength API error: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get signal strength',
            'message': str(e)
        }), 500

@wifi_scanner_bp.route('/channel-analysis', methods=['GET'], endpoint='get_channel_analysis')
@login_required
@rate_limit(max_requests=5, per_seconds=60)
def get_channel_analysis():
    """Get channel usage analysis"""
    try:
        discovery = NetworkDiscovery()
        results = discovery.discover_all_networks()
        
        return jsonify({
            'success': True,
            'data': {
                'channel_analysis': results['channel_analysis'],
                'total_networks': results['total_networks'],
                'timestamp': results['scan_timestamp']
            }
        })
        
    except Exception as e:
        logger.error(f"Channel analysis API error: {e}")
        return jsonify({
            'success': False,
            'error': 'Channel analysis failed',
            'message': str(e)
        }), 500

@wifi_scanner_bp.route('/advanced-scan', methods=['POST'], endpoint='advanced_scan')
@login_required
@rate_limit(max_requests=3, per_seconds=60)
@validate_json()
def advanced_scan():
    """Advanced Wi-Fi scanning with custom parameters"""
    try:
        data = request.get_json()
        
        # Validate and sanitize input
        scan_params = {
            'scan_type': sanitize_input(data.get('scan_type', 'detailed')),
            'timeout': int(data.get('timeout', 60)),
            'channels': data.get('channels', []),
            'include_hidden': data.get('include_hidden', True)
        }
        
        # Create advanced scan configuration
        config = ScanConfiguration(**scan_params)
        
        # Perform advanced discovery
        discovery = NetworkDiscovery()
        results = discovery.discover_all_networks(config)
        
        # Extract network SSID from results (adjust based on your results structure)
        network_ssid = results.get('primary_network', {}).get('ssid', 'Unknown')
        if not network_ssid or network_ssid == 'Unknown':
            # Try to get first network SSID if available
            networks = results.get('networks', [])
            if networks:
                network_ssid = networks[0].get('ssid', 'Unknown')
        
        # Save scan results using the correct parameters
        scan_result = ScanResult.create_scan_result(
            user_id=current_user.id,
            network_ssid=network_ssid,
            scan_type='advanced',
            scan_data=json.dumps(results),  # Store results as JSON string in scan_data
            scan_timestamp=datetime.utcnow(),
            ip_address=results.get('ip_address'),  # If available in results
            network_topology=results.get('topology'),  # If available
            device_inventory=results.get('devices')  # If available
        )
        
        # Log advanced scan using helper function (alternative approach)
        from app.models.audit_logs import log_user_activity
        log_user_activity(
            user_id=current_user.id,
            activity_type='WIFI_SCAN',
            description=f"Advanced Wi-Fi scan completed: {results.get('total_networks', 0)} networks found",
            ip_address=request.remote_addr,
            details={
                'scan_type': 'advanced',
                'scan_id': scan_result.scan_id,
                'total_networks': results.get('total_networks', 0),
                'scan_duration': results.get('scan_duration'),
                'parameters': scan_params
            }
        )
        
        return jsonify({
            'success': True,
            'data': results,
            'scan_id': scan_result.scan_id,  # Use scan_id instead of id for consistency
            'message': 'Advanced scan completed successfully'
        })
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': 'Invalid scan parameters',
            'message': str(e)
        }), 400
        
    except Exception as e:
        logger.error(f"Advanced scan API error: {e}")
        return jsonify({
            'success': False,
            'error': 'Advanced scan failed',
            'message': str(e)
        }), 500

# Current network detailed endpoint for deep scan template
@wifi_scanner_bp.route('/current-network', methods=['GET'], endpoint='get_current_network_detailed')
@login_required
@rate_limit(max_requests=30, per_seconds=60)
def get_current_network_detailed():
    """Get detailed current network information for deep scan analysis"""
    try:
        scanner = WiFiScanner()
        current_connection = scanner.get_current_connection()
        
        if current_connection:
            # Get additional network details
            import subprocess
            import socket
            import psutil
            
            # Get IP configuration
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
            except:
                local_ip = "Unknown"
            
            # Get network interface statistics
            try:
                net_stats = psutil.net_io_counters()
                data_transfer = f"{net_stats.bytes_sent + net_stats.bytes_recv / (1024*1024):.1f} MB"
            except:
                data_transfer = "0 MB"
            
            # Get connected devices count (simplified)
            connected_devices = "1"  # At minimum, this device
            
            # Format response for deep scan template
            # Use the actual extracted data from Windows netsh commands
            network_info = {
                'connected': True,
                'ssid': current_connection.get('ssid', 'Unknown'),
                'encryption': current_connection.get('security', current_connection.get('security_type', 'Unknown')),
                'security': current_connection.get('security', current_connection.get('security_type', 'Unknown')),
                'signal_strength': current_connection.get('signal_strength', 'Unknown'),
                'ip_address': current_connection.get('ip_address', local_ip),
                'connected_devices': connected_devices,
                'data_transfer': data_transfer,
                'bssid': current_connection.get('bssid', 'Unknown'),
                'channel': current_connection.get('channel', 'Unknown'),
                'frequency': current_connection.get('frequency', 'Unknown'),
                'quality': current_connection.get('signal_quality', 'Unknown'),
                'mac_address': current_connection.get('mac_address', 'Unknown'),
                'gateway': current_connection.get('gateway', 'Unknown'),
                'dns_servers': ', '.join(current_connection.get('dns_servers', [])) if current_connection.get('dns_servers') else 'Unknown',
                'link_quality': current_connection.get('signal_quality', 'Unknown'),
                'data_rate': current_connection.get('data_rate', current_connection.get('connection_speed', 'Unknown')),
                'network_type': 'WiFi',
                'authentication': current_connection.get('security', current_connection.get('security_type', 'Unknown')),
                'radio_type': current_connection.get('radio_type', 'Unknown'),
                'wps_enabled': current_connection.get('wps_enabled', False),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            return jsonify(network_info)
        else:
            return jsonify({
                'connected': False,  # FIXED: Add connected field for deep scan
                'ssid': 'Not Connected',
                'encryption': 'Unknown',  # FIXED: Add encryption field for consistency
                'security': 'Unknown',
                'signal_strength': 'Unknown',
                'ip_address': 'Unknown',
                'connected_devices': '0',
                'data_transfer': '0 MB',
                'bssid': 'Unknown',
                'channel': 'Unknown',
                'frequency': 'Unknown',
                'quality': 'Unknown',
                'mac_address': 'Unknown',
                'gateway': 'Unknown',
                'dns_servers': 'Unknown',
                'link_quality': 'Unknown',
                'data_rate': 'Unknown',
                'network_type': 'Unknown',
                'authentication': 'Unknown',
                'wps_enabled': False,
                'timestamp': datetime.utcnow().isoformat()
            })
            
    except Exception as e:
        logger.error(f"Current network detailed API error: {e}")
        return jsonify({
            'connected': False,  # FIXED: Add connected field for error case
            'ssid': 'Error',
            'encryption': 'Unknown',  # FIXED: Add encryption field
            'security': 'Unknown',
            'signal_strength': 'Unknown',
            'ip_address': 'Unknown',
            'connected_devices': '0',
            'data_transfer': '0 MB',
            'bssid': 'Unknown',
            'channel': 'Unknown',
            'frequency': 'Unknown',
            'quality': 'Unknown',
            'mac_address': 'Unknown',
            'gateway': 'Unknown',
            'dns_servers': 'Unknown',
            'link_quality': 'Unknown',
            'data_rate': 'Unknown',
            'network_type': 'Unknown',
            'authentication': 'Unknown',
            'wps_enabled': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

# Error handlers
@wifi_scanner_bp.errorhandler(404)
def wifi_not_found_error(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404

@wifi_scanner_bp.errorhandler(500)
def wifi_internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500
