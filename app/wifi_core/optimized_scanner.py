"""
Wi-Fi Security System - Optimized High-Performance Scanner
app/wifi_core/optimized_scanner.py

PERFORMANCE OPTIMIZATIONS:
- Async scanning with threading
- Caching and result deduplication
- Platform-optimized scanning methods
- Real-time signal processing
- Background scanning capabilities
"""

import platform
import subprocess
import re
import json
import time
import threading
import asyncio
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
import logging
from collections import defaultdict, deque
import concurrent.futures
from datetime import datetime, timedelta
import hashlib

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class NetworkInfo:
    """Optimized network information container"""
    ssid: str
    bssid: str
    signal_strength: int
    frequency: int
    channel: int
    encryption: str
    security: str
    vendor: str = "Unknown"
    is_hidden: bool = False
    quality: float = 0.0
    last_seen: datetime = None
    
    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = datetime.now()
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        result['last_seen'] = self.last_seen.isoformat()
        return result
    
    @property
    def network_id(self) -> str:
        """Unique identifier for network"""
        return f"{self.bssid}_{self.ssid}"

class SignalProcessor:
    """High-performance signal processing and analysis"""
    
    def __init__(self, history_size: int = 50):
        self.signal_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history_size))
        self.noise_floor = -95  # Default noise floor in dBm
        
    def calculate_quality(self, rssi: int) -> float:
        """Calculate signal quality percentage (0-100)"""
        try:
            if rssi >= -30:
                return 100.0
            elif rssi >= -67:
                return 70.0 + (rssi + 67) * 30 / 37
            elif rssi >= -70:
                return 60.0 + (rssi + 70) * 10 / 3  
            elif rssi >= -80:
                return 30.0 + (rssi + 80) * 30 / 10
            elif rssi >= -90:
                return 10.0 + (rssi + 90) * 20 / 10
            else:
                return max(0.0, 5.0 + (rssi + 95) * 5 / 5)
        except:
            return 0.0
    
    def update_history(self, bssid: str, signal: int):
        """Update signal strength history"""
        self.signal_history[bssid].append((time.time(), signal))
    
    def get_signal_trend(self, bssid: str) -> str:
        """Get signal trend (improving/stable/degrading)"""
        if bssid not in self.signal_history or len(self.signal_history[bssid]) < 3:
            return "stable"
        
        recent_signals = list(self.signal_history[bssid])[-3:]
        if recent_signals[-1][1] > recent_signals[0][1] + 3:
            return "improving"
        elif recent_signals[-1][1] < recent_signals[0][1] - 3:
            return "degrading"
        return "stable"

class NetworkCache:
    """High-performance network result caching"""
    
    def __init__(self, cache_duration: int = 300, max_entries: int = 500):
        self.cache: Dict[str, NetworkInfo] = {}
        self.cache_times: Dict[str, datetime] = {}
        self.cache_duration = timedelta(seconds=cache_duration)
        self.max_entries = max_entries
        self._lock = threading.RLock()
    
    def _cleanup_expired(self):
        """Remove expired cache entries"""
        now = datetime.now()
        expired_keys = [
            key for key, cache_time in self.cache_times.items()
            if now - cache_time > self.cache_duration
        ]
        
        for key in expired_keys:
            self.cache.pop(key, None)
            self.cache_times.pop(key, None)
        
        # Enforce max entries
        if len(self.cache) > self.max_entries:
            # Remove oldest entries
            sorted_items = sorted(self.cache_times.items(), key=lambda x: x[1])
            remove_count = len(self.cache) - self.max_entries
            
            for key, _ in sorted_items[:remove_count]:
                self.cache.pop(key, None)
                self.cache_times.pop(key, None)
    
    def store(self, network: NetworkInfo):
        """Store network in cache"""
        with self._lock:
            key = network.network_id
            self.cache[key] = network
            self.cache_times[key] = datetime.now()
            
            # Periodic cleanup
            if len(self.cache) % 50 == 0:
                self._cleanup_expired()
    
    def get(self, network_id: str) -> Optional[NetworkInfo]:
        """Get cached network info"""
        with self._lock:
            if network_id in self.cache:
                cache_time = self.cache_times[network_id]
                if datetime.now() - cache_time < self.cache_duration:
                    return self.cache[network_id]
                else:
                    # Remove expired entry
                    self.cache.pop(network_id, None)
                    self.cache_times.pop(network_id, None)
            return None
    
    def get_all_active(self) -> List[NetworkInfo]:
        """Get all active cached networks"""
        with self._lock:
            self._cleanup_expired()
            return list(self.cache.values())
    
    def clear(self):
        """Clear all cached networks"""
        with self._lock:
            self.cache.clear()
            self.cache_times.clear()

class OptimizedWiFiScanner:
    """High-performance WiFi scanner with async capabilities"""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.signal_processor = SignalProcessor()
        self.network_cache = NetworkCache()
        self.scanning = False
        self.background_scan_active = False
        self._scan_lock = threading.Lock()
        self._scan_results_lock = threading.Lock()
        self.latest_results: List[NetworkInfo] = []
        self.vendor_cache: Dict[str, str] = {}
        
        # Platform-specific configurations
        self._setup_platform_config()
        
        logger.info(f"🔧 Optimized WiFi Scanner initialized for {self.platform}")
    
    def _setup_platform_config(self):
        """Setup platform-specific scanning configurations"""
        if self.platform == "windows":
            self.scan_command = "netsh wlan show network"
            self.detail_command = "netsh wlan show profile name=\"{}\" key=clear"
            self.current_wifi_cmd = "netsh wlan show interfaces"
        elif self.platform == "linux":
            self.scan_command = "iwlist scan"
            self.current_wifi_cmd = "iwconfig"
        elif self.platform == "darwin":  # macOS
            self.scan_command = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s"
            self.current_wifi_cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I"
        else:
            logger.warning(f"Platform {self.platform} not fully supported")
    
    def _parse_windows_networks(self, output: str) -> List[NetworkInfo]:
        """Parse Windows netsh wlan show network output"""
        networks = []
        try:
            lines = output.split('\n')
            current_network = None
            current_ssid = None
            
            for line in lines:
                line = line.strip()
                
                # Find SSID
                if line.startswith('SSID') and ':' in line:
                    if current_network:
                        networks.append(current_network)
                    
                    ssid_match = re.search(r'SSID \d+ : (.+)', line)
                    if ssid_match:
                        current_ssid = ssid_match.group(1).strip()
                        if current_ssid:
                            # Get additional details for this network from current interface info
                            interface_info = self._get_current_interface_details()
                            
                            # If this is the current network, get real data
                            if current_ssid == interface_info.get('ssid'):
                                current_network = NetworkInfo(
                                    ssid=current_ssid,
                                    bssid=interface_info.get('bssid', '00:00:00:00:00:00'),
                                    signal_strength=interface_info.get('signal_strength', -50),
                                    frequency=interface_info.get('frequency', 2400),
                                    channel=interface_info.get('channel', 1),
                                    encryption=interface_info.get('encryption', 'Unknown'),
                                    security=interface_info.get('security', 'Unknown')
                                )
                            else:
                                # For non-current networks, use defaults but with real SSID
                                current_network = NetworkInfo(
                                    ssid=current_ssid,
                                    bssid='00:00:00:00:00:00',
                                    signal_strength=-60,  # Default for visible networks
                                    frequency=2400,
                                    channel=1,
                                    encryption='Unknown',
                                    security='Unknown'
                                )
                
                # Parse network type
                elif current_network and line.startswith('Network type'):
                    if 'Infrastructure' in line:
                        current_network.security = 'Infrastructure'
                
                # Parse authentication
                elif current_network and line.startswith('Authentication'):
                    auth_match = re.search(r'Authentication\s*:\s*(.+)', line)
                    if auth_match:
                        auth_type = auth_match.group(1).strip()
                        current_network.security = auth_type
                        if 'WPA3' in auth_type:
                            current_network.encryption = 'WPA3'
                        elif 'WPA2' in auth_type:
                            current_network.encryption = 'WPA2'
                        elif 'WPA' in auth_type:
                            current_network.encryption = 'WPA'
                        elif 'Open' in auth_type:
                            current_network.encryption = 'Open'
                
                # Parse encryption
                elif current_network and line.startswith('Encryption'):
                    enc_match = re.search(r'Encryption\s*:\s*(.+)', line)
                    if enc_match:
                        encryption = enc_match.group(1).strip()
                        if encryption != 'None':
                            current_network.encryption = encryption
            
            # Add the last network
            if current_network:
                networks.append(current_network)
                
            logger.info(f"Parsed {len(networks)} networks from Windows scan")
            
        except Exception as e:
            logger.error(f"Error parsing Windows networks: {e}")
        
        return networks
    
    def _get_current_interface_details(self) -> Dict:
        """Get detailed information about current WiFi interface"""
        try:
            if self.platform == "windows":
                # Use netsh wlan show interfaces to get current connection details
                output = self._run_command("netsh wlan show interfaces")
                interface_info = {}
                
                for line in output.split('\n'):
                    line = line.strip()
                    
                    if line.startswith('SSID'):
                        ssid_match = re.search(r'SSID\s*:\s*(.+)', line)
                        if ssid_match:
                            interface_info['ssid'] = ssid_match.group(1).strip()
                    
                    elif line.startswith('AP BSSID'):
                        bssid_match = re.search(r'AP BSSID\s*:\s*(.+)', line)
                        if bssid_match:
                            interface_info['bssid'] = bssid_match.group(1).strip()
                    
                    elif line.startswith('Channel'):
                        channel_match = re.search(r'Channel\s*:\s*(\d+)', line)
                        if channel_match:
                            interface_info['channel'] = int(channel_match.group(1))
                    
                    elif line.startswith('Band'):
                        band_match = re.search(r'Band\s*:\s*(.+)', line)
                        if band_match:
                            band = band_match.group(1).strip()
                            if '2.4' in band:
                                interface_info['frequency'] = 2400 + (interface_info.get('channel', 1) - 1) * 5
                            elif '5' in band:
                                interface_info['frequency'] = 5000 + interface_info.get('channel', 36) * 5
                    
                    elif line.startswith('Signal'):
                        signal_match = re.search(r'Signal\s*:\s*(\d+)%', line)
                        if signal_match:
                            # Convert percentage to dBm (approximate)
                            signal_percent = int(signal_match.group(1))
                            # Rough conversion: 100% ≈ -30dBm, 0% ≈ -100dBm
                            interface_info['signal_strength'] = -100 + (signal_percent * 70 // 100)
                    
                    elif line.startswith('Authentication'):
                        auth_match = re.search(r'Authentication\s*:\s*(.+)', line)
                        if auth_match:
                            interface_info['security'] = auth_match.group(1).strip()
                            auth_type = auth_match.group(1).strip()
                            if 'WPA3' in auth_type:
                                interface_info['encryption'] = 'WPA3'
                            elif 'WPA2' in auth_type:
                                interface_info['encryption'] = 'WPA2'
                            elif 'WPA' in auth_type:
                                interface_info['encryption'] = 'WPA'
                            else:
                                interface_info['encryption'] = 'Open'
                    
                    elif line.startswith('Cipher'):
                        cipher_match = re.search(r'Cipher\s*:\s*(.+)', line)
                        if cipher_match:
                            interface_info['cipher'] = cipher_match.group(1).strip()
                
                return interface_info
            
            else:
                # For other platforms, return empty dict for now
                return {}
                
        except Exception as e:
            logger.error(f"Error getting current interface details: {e}")
            return {}
    
    def _parse_linux_networks(self, output: str) -> List[NetworkInfo]:
        """Parse Linux iwlist output"""
        networks = []
        try:
            current_network = None
            
            for line in output.split('\n'):
                line = line.strip()
                
                if 'Cell' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    
                    bssid_match = re.search(r'Address: ([A-Fa-f0-9:]{17})', line)
                    bssid = bssid_match.group(1) if bssid_match else "00:00:00:00:00:00"
                    
                    current_network = NetworkInfo(
                        ssid="Hidden",
                        bssid=bssid,
                        signal_strength=-100,
                        frequency=2400,
                        channel=1,
                        encryption="Unknown",
                        security="Unknown"
                    )
                
                elif current_network:
                    if 'ESSID:' in line:
                        ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                        if ssid_match:
                            current_network.ssid = ssid_match.group(1)
                            if not current_network.ssid:
                                current_network.is_hidden = True
                                current_network.ssid = f"Hidden_{current_network.bssid[-8:]}"
                    
                    elif 'Signal level=' in line:
                        signal_match = re.search(r'Signal level=(-?\d+)', line)
                        if signal_match:
                            current_network.signal_strength = int(signal_match.group(1))
                            current_network.quality = self.signal_processor.calculate_quality(current_network.signal_strength)
                    
                    elif 'Frequency:' in line:
                        freq_match = re.search(r'Frequency:(\d+\.?\d*)', line)
                        if freq_match:
                            freq_ghz = float(freq_match.group(1))
                            current_network.frequency = int(freq_ghz * 1000)
                            # Calculate channel from frequency
                            if 2400 <= current_network.frequency <= 2500:
                                current_network.channel = int((current_network.frequency - 2412) / 5) + 1
                            elif 5000 <= current_network.frequency <= 6000:
                                current_network.channel = int((current_network.frequency - 5000) / 5)
                    
                    elif 'Encryption key:' in line:
                        if 'on' in line.lower():
                            current_network.encryption = "Encrypted"
                        else:
                            current_network.encryption = "Open"
                            current_network.security = "Open"
            
            if current_network:
                networks.append(current_network)
                
        except Exception as e:
            logger.error(f"Error parsing Linux networks: {e}")
        
        return networks
    
    def _parse_macos_networks(self, output: str) -> List[NetworkInfo]:
        """Parse macOS airport output"""
        networks = []
        try:
            lines = output.split('\n')[1:]  # Skip header
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    ssid = parts[0]
                    bssid = parts[1]
                    signal_strength = int(parts[2])
                    channel = int(parts[3])
                    
                    # Calculate frequency from channel
                    if 1 <= channel <= 14:
                        frequency = 2412 + (channel - 1) * 5
                    else:
                        frequency = 5000 + channel * 5  # 5GHz approximation
                    
                    encryption = "Open" if "NONE" in line else "Encrypted"
                    security = parts[6] if len(parts) > 6 else "Unknown"
                    
                    network = NetworkInfo(
                        ssid=ssid,
                        bssid=bssid,
                        signal_strength=signal_strength,
                        frequency=frequency,
                        channel=channel,
                        encryption=encryption,
                        security=security,
                        quality=self.signal_processor.calculate_quality(signal_strength)
                    )
                    networks.append(network)
                    
        except Exception as e:
            logger.error(f"Error parsing macOS networks: {e}")
        
        return networks
    
    def _run_command(self, command: str, timeout: int = 15) -> str:
        """Run system command with timeout"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error(f"Command timeout: {command}")
            return ""
        except Exception as e:
            logger.error(f"Command failed: {command}, Error: {e}")
            return ""
    
    def _get_vendor_from_bssid(self, bssid: str) -> str:
        """Get vendor information from BSSID (OUI lookup)"""
        if bssid in self.vendor_cache:
            return self.vendor_cache[bssid]
        
        # Extract OUI (first 3 octets)
        oui = bssid[:8].upper().replace(':', '')
        
        # Basic vendor mapping (expand this with full OUI database)
        vendor_map = {
            '001ACA': 'Cisco',
            '00212F': 'Cisco',
            '000C29': 'VMware',
            '080027': 'Oracle VirtualBox',
            '000569': 'VMware',
            '001C23': 'TP-Link',
            '94DACE': 'ASUS',
            '1C872C': 'ASUS',
            '040CCE': 'ASUS',
            '2462E5': 'Xiaomi',
            '78A3E4': 'Xiaomi',
            '68DFDD': 'Apple',
            '8C8590': 'Apple',
            'F025B7': 'Apple'
        }
        
        vendor = vendor_map.get(oui, "Unknown")
        self.vendor_cache[bssid] = vendor
        return vendor
    
    def scan_networks(self, timeout: int = 30) -> List[NetworkInfo]:
        """Perform synchronous network scan"""
        with self._scan_lock:
            if self.scanning:
                logger.warning("Scan already in progress")
                return self.latest_results.copy()
            
            self.scanning = True
            
        try:
            logger.info("🔍 Starting WiFi network scan...")
            start_time = time.time()
            
            # Run platform-specific scan command
            if self.platform == "windows":
                output = self._run_command(self.scan_command, timeout)
                networks = self._parse_windows_networks(output)
            elif self.platform == "linux":
                output = self._run_command("sudo iwlist scan", timeout)
                networks = self._parse_linux_networks(output)
            elif self.platform == "darwin":
                output = self._run_command(self.scan_command, timeout)
                networks = self._parse_macos_networks(output)
            else:
                logger.error(f"Unsupported platform: {self.platform}")
                return []
            
            # Enhance network information
            for network in networks:
                network.vendor = self._get_vendor_from_bssid(network.bssid)
                self.signal_processor.update_history(network.bssid, network.signal_strength)
                self.network_cache.store(network)
            
            # Remove duplicates and sort by signal strength
            unique_networks = {}
            for network in networks:
                key = network.network_id
                if key not in unique_networks or network.signal_strength > unique_networks[key].signal_strength:
                    unique_networks[key] = network
            
            final_networks = sorted(
                unique_networks.values(), 
                key=lambda x: x.signal_strength, 
                reverse=True
            )
            
            with self._scan_results_lock:
                self.latest_results = final_networks
            
            scan_time = time.time() - start_time
            logger.info(f"✅ Scan completed in {scan_time:.2f}s. Found {len(final_networks)} networks")
            
            return final_networks
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return []
        finally:
            self.scanning = False
    
    async def scan_networks_async(self, timeout: int = 30) -> List[NetworkInfo]:
        """Perform asynchronous network scan"""
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(executor, self.scan_networks, timeout)
    
    def start_background_scan(self, interval: int = 60):
        """Start background scanning thread"""
        if self.background_scan_active:
            logger.warning("Background scan already active")
            return
        
        self.background_scan_active = True
        
        def background_scanner():
            logger.info(f"🔄 Background scanning started (interval: {interval}s)")
            while self.background_scan_active:
                try:
                    if not self.scanning:
                        self.scan_networks()
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Background scan error: {e}")
                    time.sleep(interval)
        
        thread = threading.Thread(target=background_scanner, daemon=True)
        thread.start()
    
    def stop_background_scan(self):
        """Stop background scanning"""
        self.background_scan_active = False
        logger.info("🛑 Background scanning stopped")
    
    def get_current_connection(self) -> Optional[Dict]:
        """Get current WiFi connection info"""
        try:
            output = self._run_command(self.current_wifi_cmd)
            
            if self.platform == "windows":
                # Parse Windows interface info
                for line in output.split('\n'):
                    if 'SSID' in line:
                        ssid_match = re.search(r'SSID\s*:\s*(.+)', line)
                        if ssid_match:
                            return {'ssid': ssid_match.group(1).strip()}
            elif self.platform == "linux":
                # Parse Linux iwconfig output
                for line in output.split('\n'):
                    if 'ESSID:' in line:
                        ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                        if ssid_match:
                            return {'ssid': ssid_match.group(1)}
            elif self.platform == "darwin":
                # Parse macOS airport output
                for line in output.split('\n'):
                    if 'SSID:' in line:
                        return {'ssid': line.split('SSID:')[1].strip()}
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get current connection: {e}")
            return None
    
    def get_latest_results(self) -> List[NetworkInfo]:
        """Get latest scan results"""
        with self._scan_results_lock:
            return self.latest_results.copy()
    
    def get_cached_networks(self) -> List[NetworkInfo]:
        """Get all cached networks"""
        return self.network_cache.get_all_active()
    
    def get_scan_statistics(self) -> Dict:
        """Get scanning statistics"""
        with self._scan_results_lock:
            latest_count = len(self.latest_results)
        
        cached_count = len(self.network_cache.get_all_active())
        
        return {
            'scanning': self.scanning,
            'background_scan_active': self.background_scan_active,
            'latest_scan_count': latest_count,
            'cached_networks_count': cached_count,
            'platform': self.platform,
            'vendor_cache_size': len(self.vendor_cache)
        }
    
    def clear_cache(self):
        """Clear all cached data"""
        self.network_cache.clear()
        self.vendor_cache.clear()
        self.signal_processor.signal_history.clear()
        with self._scan_results_lock:
            self.latest_results.clear()
        logger.info("🗑️ Scanner cache cleared")

# Global scanner instance
_scanner_instance = None

def get_scanner() -> OptimizedWiFiScanner:
    """Get global scanner instance"""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = OptimizedWiFiScanner()
    return _scanner_instance