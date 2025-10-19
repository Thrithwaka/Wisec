"""
Wi-Fi Core Connector Module
Purpose: Manage Wi-Fi network connections
File: app/wifi_core/connector.py
"""

import subprocess
import time
import json
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import requests
import socket
import platform
import re

# Configure logging
logger = logging.getLogger(__name__)

class ConnectionStatus(Enum):
    """Connection status enumeration"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"

class ConnectionError(Enum):
    """Connection error types"""
    INVALID_CREDENTIALS = "invalid_credentials"
    NETWORK_NOT_FOUND = "network_not_found"
    TIMEOUT_ERROR = "timeout_error"
    HARDWARE_ERROR = "hardware_error"
    PERMISSION_DENIED = "permission_denied"
    UNKNOWN_ERROR = "unknown_error"

@dataclass
class ConnectionProfile:
    """Wi-Fi connection profile data structure"""
    ssid: str
    password: str
    security_type: str
    priority: int = 0
    auto_connect: bool = True
    created_at: str = ""
    last_connected: str = ""

@dataclass
class ConnectionQuality:
    """Connection quality metrics"""
    signal_strength: int
    link_speed: int
    frequency: int
    noise_level: int
    packet_loss: float
    latency: float
    throughput: float

class WiFiConnector:
    """
    Main Wi-Fi connection management class
    Handles network connections, disconnections, and monitoring
    """
    
    def __init__(self):
        self.current_connection = None
        self.connection_status = ConnectionStatus.DISCONNECTED
        self.connection_profiles = {}
        self.monitoring_thread = None
        self.is_monitoring = False
        self.platform = platform.system().lower()
        self.validator = ConnectionValidator()
        self.credential_manager = CredentialManager()
        self.connection_monitor = ConnectionMonitor()
        
        # Initialize platform-specific commands
        self._setup_platform_commands()
        
    def _setup_platform_commands(self):
        """Setup platform-specific Wi-Fi commands"""
        if self.platform == "linux":
            self.wifi_interface = self._get_wifi_interface_linux()
            self.connect_cmd_template = "nmcli dev wifi connect '{ssid}' password '{password}'"
            self.disconnect_cmd = f"nmcli dev disconnect {self.wifi_interface}"
            self.status_cmd = "nmcli -t -f active,ssid dev wifi"
        elif self.platform == "windows":
            self.connect_cmd_template = 'netsh wlan connect name="{ssid}"'
            self.disconnect_cmd = "netsh wlan disconnect"
            self.status_cmd = "netsh wlan show profiles"
        elif self.platform == "darwin":  # macOS
            self.wifi_interface = "en0"  # Default for macOS
            self.connect_cmd_template = 'networksetup -setairportnetwork {interface} "{ssid}" "{password}"'
            self.disconnect_cmd = f"sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z"
            self.status_cmd = "networksetup -getairportnetwork en0"
        else:
            logger.warning(f"Unsupported platform: {self.platform}")
            
    def _get_wifi_interface_linux(self) -> str:
        """Get Wi-Fi interface name on Linux"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    return line.split()[0]
            return "wlan0"  # Default fallback
        except Exception as e:
            logger.error(f"Error getting Wi-Fi interface: {e}")
            return "wlan0"
    
    def connect_to_network(self, ssid: str, password: str = "", security_type: str = "WPA2") -> Dict[str, Any]:
        """
        Connect to a Wi-Fi network
        
        Args:
            ssid: Network SSID
            password: Network password
            security_type: Security type (WPA2, WPA, WEP, OPEN)
            
        Returns:
            Dict containing connection result and status
        """
        try:
            logger.info(f"Attempting to connect to network: {ssid}")
            
            # Validate credentials
            validation_result = self.validator.validate_credentials(ssid, password, security_type)
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': ConnectionError.INVALID_CREDENTIALS.value,
                    'message': validation_result['message'],
                    'status': ConnectionStatus.FAILED.value
                }
            
            # Update connection status
            self.connection_status = ConnectionStatus.CONNECTING
            
            # Platform-specific connection
            connection_result = self._connect_platform_specific(ssid, password, security_type)
            
            if connection_result['success']:
                # Test internet connectivity
                internet_test = self.test_internet_connectivity()
                
                # Save connection profile
                profile = ConnectionProfile(
                    ssid=ssid,
                    password=password,
                    security_type=security_type,
                    created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                    last_connected=time.strftime("%Y-%m-%d %H:%M:%S")
                )
                self.credential_manager.save_profile(profile)
                
                self.current_connection = {
                    'ssid': ssid,
                    'security_type': security_type,
                    'connected_at': time.time(),
                    'internet_access': internet_test['has_internet']
                }
                self.connection_status = ConnectionStatus.CONNECTED
                
                # Start connection monitoring
                self._start_connection_monitoring()
                
                return {
                    'success': True,
                    'message': f"Successfully connected to {ssid}",
                    'status': ConnectionStatus.CONNECTED.value,
                    'internet_access': internet_test['has_internet'],
                    'connection_info': self.current_connection
                }
            else:
                self.connection_status = ConnectionStatus.FAILED
                return connection_result
                
        except Exception as e:
            logger.error(f"Error connecting to network {ssid}: {e}")
            self.connection_status = ConnectionStatus.ERROR
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': f"Connection error: {str(e)}",
                'status': ConnectionStatus.ERROR.value
            }
    
    def _connect_platform_specific(self, ssid: str, password: str, security_type: str) -> Dict[str, Any]:
        """Platform-specific connection implementation"""
        try:
            if self.platform == "linux":
                return self._connect_linux(ssid, password, security_type)
            elif self.platform == "windows":
                return self._connect_windows(ssid, password, security_type)
            elif self.platform == "darwin":
                return self._connect_macos(ssid, password, security_type)
            else:
                return {
                    'success': False,
                    'error': ConnectionError.HARDWARE_ERROR.value,
                    'message': f"Unsupported platform: {self.platform}"
                }
        except Exception as e:
            logger.error(f"Platform-specific connection error: {e}")
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': str(e)
            }
    
    def _connect_linux(self, ssid: str, password: str, security_type: str) -> Dict[str, Any]:
        """Linux-specific connection using NetworkManager"""
        try:
            if security_type.upper() == "OPEN":
                cmd = f"nmcli dev wifi connect '{ssid}'"
            else:
                cmd = f"nmcli dev wifi connect '{ssid}' password '{password}'"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Connection successful'}
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                return {
                    'success': False,
                    'error': ConnectionError.UNKNOWN_ERROR.value,
                    'message': f"Connection failed: {error_msg}"
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': ConnectionError.TIMEOUT_ERROR.value,
                'message': "Connection timeout"
            }
        except Exception as e:
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': str(e)
            }
    
    def _connect_windows(self, ssid: str, password: str, security_type: str) -> Dict[str, Any]:
        """Windows-specific connection using netsh"""
        try:
            # Create profile first
            profile_xml = self._create_windows_profile(ssid, password, security_type)
            profile_file = f"temp_profile_{ssid}.xml"
            
            with open(profile_file, 'w') as f:
                f.write(profile_xml)
            
            # Add profile
            add_profile_cmd = f'netsh wlan add profile filename="{profile_file}"'
            subprocess.run(add_profile_cmd, shell=True, check=True)
            
            # Connect to network
            connect_cmd = f'netsh wlan connect name="{ssid}"'
            result = subprocess.run(connect_cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            # Cleanup
            import os
            try:
                os.remove(profile_file)
            except:
                pass
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Connection successful'}
            else:
                return {
                    'success': False,
                    'error': ConnectionError.UNKNOWN_ERROR.value,
                    'message': f"Connection failed: {result.stderr}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': str(e)
            }
    
    def _connect_macos(self, ssid: str, password: str, security_type: str) -> Dict[str, Any]:
        """macOS-specific connection using networksetup"""
        try:
            if security_type.upper() == "OPEN":
                cmd = f'networksetup -setairportnetwork en0 "{ssid}"'
            else:
                cmd = f'networksetup -setairportnetwork en0 "{ssid}" "{password}"'
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return {'success': True, 'message': 'Connection successful'}
            else:
                return {
                    'success': False,
                    'error': ConnectionError.UNKNOWN_ERROR.value,
                    'message': f"Connection failed: {result.stderr}"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': str(e)
            }
    
    def _create_windows_profile(self, ssid: str, password: str, security_type: str) -> str:
        """Create Windows Wi-Fi profile XML"""
        if security_type.upper() == "OPEN":
            auth_type = "open"
            encryption = "none"
            key_material = ""
        else:
            auth_type = "WPA2PSK"
            encryption = "AES"
            key_material = f"<keyMaterial>{password}</keyMaterial>"
        
        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth_type}</authentication>
                <encryption>{encryption}</encryption>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                {key_material}
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""
    
    def disconnect_from_network(self) -> Dict[str, Any]:
        """
        Disconnect from current Wi-Fi network
        
        Returns:
            Dict containing disconnection result
        """
        try:
            logger.info("Disconnecting from current network")
            
            if self.connection_status == ConnectionStatus.DISCONNECTED:
                return {
                    'success': True,
                    'message': 'Already disconnected',
                    'status': ConnectionStatus.DISCONNECTED.value
                }
            
            # Stop monitoring
            self._stop_connection_monitoring()
            
            # Platform-specific disconnection
            result = subprocess.run(self.disconnect_cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.current_connection = None
                self.connection_status = ConnectionStatus.DISCONNECTED
                
                return {
                    'success': True,
                    'message': 'Successfully disconnected',
                    'status': ConnectionStatus.DISCONNECTED.value
                }
            else:
                return {
                    'success': False,
                    'error': ConnectionError.UNKNOWN_ERROR.value,
                    'message': f"Disconnection failed: {result.stderr}",
                    'status': self.connection_status.value
                }
                
        except Exception as e:
            logger.error(f"Error disconnecting: {e}")
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': f"Disconnection error: {str(e)}",
                'status': ConnectionStatus.ERROR.value
            }
    
    def test_internet_connectivity(self) -> Dict[str, Any]:
        """
        Test internet connectivity
        
        Returns:
            Dict containing connectivity test results
        """
        try:
            # Test multiple endpoints for reliability
            test_urls = [
                "https://www.google.com",
                "https://www.cloudflare.com",
                "https://www.github.com"
            ]
            
            connectivity_results = []
            
            for url in test_urls:
                try:
                    start_time = time.time()
                    response = requests.get(url, timeout=5)
                    end_time = time.time()
                    
                    connectivity_results.append({
                        'url': url,
                        'success': response.status_code == 200,
                        'response_time': (end_time - start_time) * 1000,  # Convert to ms
                        'status_code': response.status_code
                    })
                except Exception as e:
                    connectivity_results.append({
                        'url': url,
                        'success': False,
                        'error': str(e),
                        'response_time': None
                    })
            
            # Determine overall connectivity
            successful_tests = sum(1 for result in connectivity_results if result['success'])
            has_internet = successful_tests > 0
            
            # Calculate average response time for successful tests
            successful_times = [r['response_time'] for r in connectivity_results 
                             if r['success'] and r['response_time'] is not None]
            avg_response_time = sum(successful_times) / len(successful_times) if successful_times else None
            
            return {
                'has_internet': has_internet,
                'success_rate': successful_tests / len(test_urls),
                'average_response_time': avg_response_time,
                'detailed_results': connectivity_results,
                'test_count': len(test_urls),
                'successful_tests': successful_tests
            }
            
        except Exception as e:
            logger.error(f"Error testing internet connectivity: {e}")
            return {
                'has_internet': False,
                'error': str(e),
                'success_rate': 0.0,
                'test_count': 0,
                'successful_tests': 0
            }
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get current connection status
        
        Returns:
            Dict containing current connection information
        """
        return {
            'status': self.connection_status.value,
            'current_connection': self.current_connection,
            'is_monitoring': self.is_monitoring,
            'connection_quality': self.connection_monitor.get_quality_metrics() if self.current_connection else None
        }
    
    def _start_connection_monitoring(self):
        """Start connection quality monitoring"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitor_connection_loop, daemon=True)
            self.monitoring_thread.start()
            logger.info("Started connection monitoring")
    
    def _stop_connection_monitoring(self):
        """Stop connection monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        logger.info("Stopped connection monitoring")
    
    def _monitor_connection_loop(self):
        """Connection monitoring loop"""
        while self.is_monitoring:
            try:
                if self.current_connection:
                    # Update connection quality metrics
                    quality = self.connection_monitor.measure_quality()
                    
                    # Check if connection is still active
                    if not self._is_still_connected():
                        logger.warning("Connection lost")
                        self.connection_status = ConnectionStatus.DISCONNECTED
                        self.current_connection = None
                        break
                    
                    # Handle automatic reconnection if needed
                    if quality and quality.signal_strength < -80:  # Very weak signal
                        logger.warning("Weak signal detected")
                        self._handle_weak_signal()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in connection monitoring: {e}")
                time.sleep(10)  # Wait longer on error
    
    def _is_still_connected(self) -> bool:
        """Check if still connected to the network"""
        try:
            if self.platform == "linux":
                result = subprocess.run("nmcli -t -f active,ssid dev wifi", 
                                      shell=True, capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.startswith('yes:') and self.current_connection:
                        connected_ssid = line.split(':', 1)[1]
                        return connected_ssid == self.current_connection['ssid']
            elif self.platform == "windows":
                result = subprocess.run("netsh wlan show interfaces", 
                                      shell=True, capture_output=True, text=True)
                return "State                  : connected" in result.stdout
            elif self.platform == "darwin":
                result = subprocess.run("networksetup -getairportnetwork en0", 
                                      shell=True, capture_output=True, text=True)
                return "You are not associated with an AirPort network" not in result.stdout
            
            return False
        except Exception as e:
            logger.error(f"Error checking connection status: {e}")
            return False
    
    def _handle_weak_signal(self):
        """Handle weak signal conditions"""
        # Implementation for handling weak signals
        # Could trigger reconnection attempts or network optimization
        pass


class ConnectionValidator:
    """Connection validation utilities"""
    
    def validate_credentials(self, ssid: str, password: str, security_type: str) -> Dict[str, Any]:
        """
        Validate network credentials
        
        Args:
            ssid: Network SSID
            password: Network password
            security_type: Security type
            
        Returns:
            Dict containing validation result
        """
        try:
            errors = []
            
            # Validate SSID
            if not ssid or len(ssid.strip()) == 0:
                errors.append("SSID cannot be empty")
            elif len(ssid) > 32:
                errors.append("SSID too long (max 32 characters)")
            
            # Validate password based on security type
            if security_type.upper() != "OPEN":
                if not password:
                    errors.append("Password required for secured networks")
                elif security_type.upper() == "WEP":
                    if len(password) not in [5, 13, 10, 26]:  # WEP key lengths
                        errors.append("Invalid WEP key length")
                elif security_type.upper() in ["WPA", "WPA2", "WPA3"]:
                    if len(password) < 8 or len(password) > 63:
                        errors.append("WPA password must be 8-63 characters")
            
            # Validate security type
            valid_security_types = ["OPEN", "WEP", "WPA", "WPA2", "WPA3"]
            if security_type.upper() not in valid_security_types:
                errors.append(f"Invalid security type. Must be one of: {', '.join(valid_security_types)}")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors,
                'message': '; '.join(errors) if errors else "Credentials valid"
            }
            
        except Exception as e:
            logger.error(f"Error validating credentials: {e}")
            return {
                'valid': False,
                'errors': [str(e)],
                'message': f"Validation error: {str(e)}"
            }


class CredentialManager:
    """Credential handling and profile management"""
    
    def __init__(self):
        self.profiles_file = "wifi_profiles.json"
        self.profiles = self._load_profiles()
    
    def _load_profiles(self) -> Dict[str, ConnectionProfile]:
        """Load saved connection profiles"""
        try:
            with open(self.profiles_file, 'r') as f:
                data = json.load(f)
                profiles = {}
                for ssid, profile_data in data.items():
                    profiles[ssid] = ConnectionProfile(**profile_data)
                return profiles
        except FileNotFoundError:
            return {}
        except Exception as e:
            logger.error(f"Error loading profiles: {e}")
            return {}
    
    def _save_profiles(self):
        """Save profiles to file"""
        try:
            data = {}
            for ssid, profile in self.profiles.items():
                data[ssid] = {
                    'ssid': profile.ssid,
                    'password': profile.password,  # In production, encrypt this
                    'security_type': profile.security_type,
                    'priority': profile.priority,
                    'auto_connect': profile.auto_connect,
                    'created_at': profile.created_at,
                    'last_connected': profile.last_connected
                }
            
            with open(self.profiles_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving profiles: {e}")
    
    def save_profile(self, profile: ConnectionProfile):
        """Save a connection profile"""
        self.profiles[profile.ssid] = profile
        self._save_profiles()
    
    def get_profile(self, ssid: str) -> Optional[ConnectionProfile]:
        """Get a connection profile"""
        return self.profiles.get(ssid)
    
    def delete_profile(self, ssid: str) -> bool:
        """Delete a connection profile"""
        if ssid in self.profiles:
            del self.profiles[ssid]
            self._save_profiles()
            return True
        return False
    
    def list_profiles(self) -> List[ConnectionProfile]:
        """List all connection profiles"""
        return list(self.profiles.values())


class ConnectionMonitor:
    """Connection status monitoring"""
    
    def __init__(self):
        self.quality_history = []
        self.max_history = 100
    
    def measure_quality(self) -> Optional[ConnectionQuality]:
        """
        Measure current connection quality
        
        Returns:
            ConnectionQuality object or None if not connected
        """
        try:
            # Platform-specific quality measurement
            platform_sys = platform.system().lower()
            
            if platform_sys == "linux":
                return self._measure_quality_linux()
            elif platform_sys == "windows":
                return self._measure_quality_windows()
            elif platform_sys == "darwin":
                return self._measure_quality_macos()
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error measuring connection quality: {e}")
            return None
    
    def _measure_quality_linux(self) -> Optional[ConnectionQuality]:
        """Measure quality on Linux"""
        try:
            # Get signal strength from iwconfig
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            signal_strength = -50  # Default
            link_speed = 0
            frequency = 0
            noise_level = -90
            
            for line in result.stdout.split('\n'):
                if 'Signal level' in line:
                    match = re.search(r'Signal level=(-?\d+)', line)
                    if match:
                        signal_strength = int(match.group(1))
                
                if 'Bit Rate' in line:
                    match = re.search(r'Bit Rate=(\d+)', line)
                    if match:
                        link_speed = int(match.group(1))
                
                if 'Frequency' in line:
                    match = re.search(r'Frequency:(\d+\.\d+)', line)
                    if match:
                        frequency = int(float(match.group(1)) * 1000)  # Convert to MHz
            
            # Measure latency
            latency = self._measure_latency()
            
            # Estimate throughput (simplified)
            throughput = min(link_speed * 0.7, 100)  # Rough estimate
            
            quality = ConnectionQuality(
                signal_strength=signal_strength,
                link_speed=link_speed,
                frequency=frequency,
                noise_level=noise_level,
                packet_loss=0.0,  # Would need more complex measurement
                latency=latency,
                throughput=throughput
            )
            
            # Add to history
            self.quality_history.append(quality)
            if len(self.quality_history) > self.max_history:
                self.quality_history.pop(0)
            
            return quality
            
        except Exception as e:
            logger.error(f"Error measuring Linux quality: {e}")
            return None
    
    def _measure_quality_windows(self) -> Optional[ConnectionQuality]:
        """Measure quality on Windows"""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                  capture_output=True, text=True)
            
            signal_strength = -50
            link_speed = 0
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Signal'):
                    match = re.search(r'(\d+)%', line)
                    if match:
                        # Convert percentage to dBm (approximate)
                        percentage = int(match.group(1))
                        signal_strength = -100 + (percentage * 0.5)
                
                if line.startswith('Receive rate'):
                    match = re.search(r'(\d+)', line)
                    if match:
                        link_speed = int(match.group(1))
            
            latency = self._measure_latency()
            
            return ConnectionQuality(
                signal_strength=int(signal_strength),
                link_speed=link_speed,
                frequency=2400,  # Default 2.4GHz
                noise_level=-90,
                packet_loss=0.0,
                latency=latency,
                throughput=link_speed * 0.7
            )
            
        except Exception as e:
            logger.error(f"Error measuring Windows quality: {e}")
            return None
    
    def _measure_quality_macos(self) -> Optional[ConnectionQuality]:
        """Measure quality on macOS"""
        try:
            # Use airport utility for detailed info
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'], 
                                  capture_output=True, text=True)
            
            signal_strength = -50
            link_speed = 0
            frequency = 0
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'agrCtlRSSI:' in line:
                    signal_strength = int(line.split(':')[1].strip())
                elif 'lastTxRate:' in line:
                    link_speed = int(line.split(':')[1].strip())
                elif 'channel:' in line:
                    channel = int(line.split(':')[1].strip())
                    # Convert channel to frequency (simplified)
                    if channel <= 14:
                        frequency = 2412 + (channel - 1) * 5
                    else:
                        frequency = 5000 + channel * 5
            
            latency = self._measure_latency()
            
            return ConnectionQuality(
                signal_strength=signal_strength,
                link_speed=link_speed,
                frequency=frequency,
                noise_level=-90,
                packet_loss=0.0,
                latency=latency,
                throughput=link_speed * 0.7
            )
            
        except Exception as e:
            logger.error(f"Error measuring macOS quality: {e}")
            return None
    
    def _measure_latency(self) -> float:
        """Measure network latency"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['ping', '-n', '3', '8.8.8.8'], 
                                      capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '3', '8.8.8.8'], 
                                      capture_output=True, text=True)
            
            # Parse ping results
            times = []
            for line in result.stdout.split('\n'):
                if 'time=' in line:
                    match = re.search(r'time=(\d+\.?\d*)', line)
                    if match:
                        times.append(float(match.group(1)))
            
            return sum(times) / len(times) if times else 50.0  # Default 50ms
            
        except Exception as e:
            logger.error(f"Error measuring latency: {e}")
            return 50.0  # Default latency
    
    def get_quality_metrics(self) -> Optional[Dict[str, Any]]:
        """Get current quality metrics"""
        current_quality = self.measure_quality()
        if not current_quality:
            return None
        
        return {
            'signal_strength': current_quality.signal_strength,
            'link_speed': current_quality.link_speed,
            'frequency': current_quality.frequency,
            'noise_level': current_quality.noise_level,
            'packet_loss': current_quality.packet_loss,
            'latency': current_quality.latency,
            'throughput': current_quality.throughput,
            'quality_score': self._calculate_quality_score(current_quality)
        }
    
    def _calculate_quality_score(self, quality: ConnectionQuality) -> int:
        """Calculate overall quality score (0-100)"""
        try:
            # Signal strength score (0-40 points)
            signal_score = max(0, min(40, (quality.signal_strength + 100) * 0.4))
            
            # Speed score (0-30 points)
            speed_score = min(30, quality.link_speed / 10)
            
            # Latency score (0-20 points)
            latency_score = max(0, 20 - (quality.latency / 5))
            
            # Packet loss score (0-10 points)
            loss_score = max(0, 10 - (quality.packet_loss * 10))
            
            total_score = int(signal_score + speed_score + latency_score + loss_score)
            return min(100, max(0, total_score))
            
        except Exception as e:
            logger.error(f"Error calculating quality score: {e}")
            return 50  # Default score
    
    def get_quality_history(self) -> List[ConnectionQuality]:
        """Get connection quality history"""
        return self.quality_history.copy()
    
    def monitor_connection_quality(self) -> Dict[str, Any]:
        """Monitor connection quality and return comprehensive metrics"""
        try:
            current_quality = self.get_quality_metrics()
            if not current_quality:
                return {
                    'status': 'error',
                    'message': 'Unable to measure connection quality'
                }
            
            # Analyze quality trends
            history_analysis = self._analyze_quality_trends()
            
            # Determine connection stability
            stability = self._assess_connection_stability()
            
            return {
                'status': 'success',
                'current_quality': current_quality,
                'history_analysis': history_analysis,
                'stability': stability,
                'recommendations': self._generate_quality_recommendations(current_quality)
            }
            
        except Exception as e:
            logger.error(f"Error monitoring connection quality: {e}")
            return {
                'status': 'error',
                'message': f'Quality monitoring error: {str(e)}'
            }
    
    def _analyze_quality_trends(self) -> Dict[str, Any]:
        """Analyze quality trends from history"""
        if len(self.quality_history) < 2:
            return {'trend': 'insufficient_data'}
        
        try:
            recent_scores = [self._calculate_quality_score(q) for q in self.quality_history[-10:]]
            older_scores = [self._calculate_quality_score(q) for q in self.quality_history[-20:-10]] if len(self.quality_history) >= 20 else []
            
            recent_avg = sum(recent_scores) / len(recent_scores)
            
            if older_scores:
                older_avg = sum(older_scores) / len(older_scores)
                trend_change = recent_avg - older_avg
                
                if trend_change > 5:
                    trend = 'improving'
                elif trend_change < -5:
                    trend = 'degrading'
                else:
                    trend = 'stable'
            else:
                trend = 'stable'
            
            return {
                'trend': trend,
                'recent_average': recent_avg,
                'trend_change': trend_change if older_scores else 0,
                'data_points': len(self.quality_history)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing quality trends: {e}")
            return {'trend': 'error', 'message': str(e)}
    
    def _assess_connection_stability(self) -> Dict[str, Any]:
        """Assess connection stability"""
        if len(self.quality_history) < 5:
            return {'stability': 'insufficient_data'}
        
        try:
            signal_strengths = [q.signal_strength for q in self.quality_history[-10:]]
            latencies = [q.latency for q in self.quality_history[-10:]]
            
            # Calculate variance
            signal_variance = self._calculate_variance(signal_strengths)
            latency_variance = self._calculate_variance(latencies)
            
            # Determine stability based on variance
            if signal_variance < 25 and latency_variance < 100:
                stability = 'excellent'
            elif signal_variance < 50 and latency_variance < 200:
                stability = 'good'
            elif signal_variance < 100 and latency_variance < 500:
                stability = 'fair'
            else:
                stability = 'poor'
            
            return {
                'stability': stability,
                'signal_variance': signal_variance,
                'latency_variance': latency_variance,
                'sample_size': len(signal_strengths)
            }
            
        except Exception as e:
            logger.error(f"Error assessing stability: {e}")
            return {'stability': 'error', 'message': str(e)}
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        if not values:
            return 0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def _generate_quality_recommendations(self, quality: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on quality metrics"""
        recommendations = []
        
        try:
            signal_strength = quality.get('signal_strength', 0)
            latency = quality.get('latency', 0)
            quality_score = quality.get('quality_score', 0)
            
            if signal_strength < -70:
                recommendations.append("Move closer to the router for better signal strength")
            
            if latency > 100:
                recommendations.append("High latency detected - check for network congestion")
            
            if quality_score < 30:
                recommendations.append("Poor connection quality - consider switching to a different network")
            elif quality_score < 60:
                recommendations.append("Connection quality could be improved - try repositioning your device")
            
            if not recommendations:
                recommendations.append("Connection quality is good")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return ["Unable to generate recommendations"]


# Additional utility functions for the connector module

def handle_connection_errors(func):
    """Decorator for handling connection errors"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': ConnectionError.TIMEOUT_ERROR.value,
                'message': 'Operation timed out'
            }
        except PermissionError:
            return {
                'success': False,
                'error': ConnectionError.PERMISSION_DENIED.value,
                'message': 'Permission denied - admin rights required'
            }
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            return {
                'success': False,
                'error': ConnectionError.UNKNOWN_ERROR.value,
                'message': f'Unexpected error: {str(e)}'
            }
    return wrapper


def auto_reconnect_handler():
    """Handle automatic reconnection scenarios"""
    def reconnect_decorator(func):
        def wrapper(self, *args, **kwargs):
            result = func(self, *args, **kwargs)
            
            # If connection failed and auto-reconnect is enabled
            if not result.get('success') and hasattr(self, 'auto_reconnect_enabled') and self.auto_reconnect_enabled:
                logger.info("Attempting auto-reconnection...")
                # Implementation would go here
                pass
            
            return result
        return wrapper
    return reconnect_decorator


class WiFiConnectorManager:
    """
    Manager class for multiple WiFi connectors
    Handles connection management across different interfaces
    """
    
    def __init__(self):
        self.connectors = {}
        self.active_connector = None
        self.connection_profiles = {}
        
    def add_connector(self, interface_name: str) -> WiFiConnector:
        """Add a new WiFi connector for a specific interface"""
        connector = WiFiConnector()
        self.connectors[interface_name] = connector
        
        if not self.active_connector:
            self.active_connector = connector
            
        return connector
    
    def get_connector(self, interface_name: str = None) -> Optional[WiFiConnector]:
        """Get a specific connector or the active one"""
        if interface_name:
            return self.connectors.get(interface_name)
        return self.active_connector
    
    def manage_connection_profiles(self) -> Dict[str, List[ConnectionProfile]]:
        """Manage connection profiles across all connectors"""
        all_profiles = {}
        
        for interface, connector in self.connectors.items():
            if hasattr(connector, 'credential_manager'):
                all_profiles[interface] = connector.credential_manager.list_profiles()
        
        return all_profiles
    
    def get_best_connection(self, available_networks: List[Dict]) -> Optional[Dict]:
        """Determine the best network to connect to based on profiles and quality"""
        try:
            best_network = None
            best_score = -1
            
            for network in available_networks:
                score = 0
                
                # Signal strength score (0-50)
                signal_strength = network.get('signal_strength', -100)
                score += max(0, min(50, (signal_strength + 100) * 0.5))
                
                # Security preference score (0-30)
                security = network.get('security_type', 'OPEN')
                if security in ['WPA3', 'WPA2']:
                    score += 30
                elif security == 'WPA':
                    score += 20
                elif security == 'WEP':
                    score += 10
                # OPEN networks get 0 points
                
                # Known network bonus (0-20)
                ssid = network.get('ssid', '')
                for connector in self.connectors.values():
                    if hasattr(connector, 'credential_manager'):
                        profile = connector.credential_manager.get_profile(ssid)
                        if profile:
                            score += 20
                            break
                
                if score > best_score:
                    best_score = score
                    best_network = network
            
            return best_network
            
        except Exception as e:
            logger.error(f"Error finding best connection: {e}")
            return None


# Export main classes and functions
__all__ = [
    'WiFiConnector',
    'ConnectionValidator', 
    'CredentialManager',
    'ConnectionMonitor',
    'WiFiConnectorManager',
    'ConnectionStatus',
    'ConnectionError',
    'ConnectionProfile',
    'ConnectionQuality',
    'handle_connection_errors',
    'auto_reconnect_handler'
]