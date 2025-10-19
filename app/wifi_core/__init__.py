"""
Wi-Fi Core Operations Module
============================

This module provides core Wi-Fi functionality for the Wi-Fi Vulnerability Detection System.
It includes network scanning, connection management, traffic analysis, topology mapping,
and passive reconnaissance capabilities.

Components:
-----------
- scanner.py: Wi-Fi network discovery and information gathering
- connector.py: Wi-Fi connection management and credential handling  
- analyzer.py: Network traffic analysis and monitoring
- topology_mapper.py: Network topology discovery and visualization
- passive_scanner.py: Passive reconnaissance (Lab use only)

Key Features:
-------------
- Network discovery and signal analysis
- Secure connection management
- Real-time traffic monitoring
- Network topology mapping
- Security-focused passive scanning
"""

from .scanner import (
    WiFiScanner,
    NetworkDiscovery,
    SignalProcessor,
    ChannelAnalyzer
)

from .connector import (
    WiFiConnector,
    ConnectionValidator,
    CredentialManager,
    ConnectionMonitor
)

from .analyzer import (
    TrafficAnalyzer,
    PacketCapture,
    ProtocolAnalyzer,
    FlowAnalyzer
)

from .topology_mapper import (
    TopologyMapper,
    DeviceDiscovery,
    RelationshipAnalyzer,
    GraphGenerator
)

from .passive_scanner import (
    PassiveScanner,
    HandshakeCapture,
    BeaconAnalyzer,
    RogueAPDetector,
    SecurityAuditor
)

# Version information
__version__ = "1.0.0"
__author__ = "Wi-Fi Security System Team"

# Module-level constants
DEFAULT_SCAN_TIMEOUT = 30  # seconds
MAX_CONCURRENT_CONNECTIONS = 5
SIGNAL_QUALITY_THRESHOLD = -70  # dBm
CHANNEL_ANALYSIS_DURATION = 60  # seconds

# Network security types
SECURITY_TYPES = {
    'OPEN': 'No encryption',
    'WEP': 'WEP encryption (deprecated)',
    'WPA': 'WPA encryption',
    'WPA2': 'WPA2 encryption',
    'WPA3': 'WPA3 encryption (latest)',
    'ENTERPRISE': 'Enterprise security'
}

# Risk levels for network assessment
RISK_LEVELS = {
    'HIGH': 'High risk - immediate attention required',
    'MEDIUM': 'Medium risk - should be addressed',
    'LOW': 'Low risk - monitor for changes',
    'NORMAL': 'Normal - no significant risks detected'
}

# Default configuration for Wi-Fi operations
DEFAULT_CONFIG = {
    'scan_timeout': DEFAULT_SCAN_TIMEOUT,
    'max_connections': MAX_CONCURRENT_CONNECTIONS,
    'signal_threshold': SIGNAL_QUALITY_THRESHOLD,
    'channel_analysis_duration': CHANNEL_ANALYSIS_DURATION,
    'enable_passive_scanning': False,  # Lab use only
    'enable_traffic_analysis': True,
    'enable_topology_mapping': True,
    'audit_all_operations': True
}

class WiFiCoreManager:
    """
    Central manager for all Wi-Fi core operations.
    Coordinates between scanner, connector, analyzer, and other components.
    """
    
    def __init__(self, config=None):
        """
        Initialize the Wi-Fi Core Manager.
        
        Args:
            config (dict): Configuration dictionary, uses DEFAULT_CONFIG if None
        """
        self.config = config or DEFAULT_CONFIG.copy()
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all Wi-Fi core components."""
        # Initialize scanner component
        self.scanner = WiFiScanner(
            timeout=self.config.get('scan_timeout', DEFAULT_SCAN_TIMEOUT)
        )
        
        # Initialize connector component
        self.connector = WiFiConnector(
            max_connections=self.config.get('max_connections', MAX_CONCURRENT_CONNECTIONS)
        )
        
        # Initialize analyzer component if enabled
        if self.config.get('enable_traffic_analysis', True):
            self.analyzer = TrafficAnalyzer()
        
        # Initialize topology mapper if enabled
        if self.config.get('enable_topology_mapping', True):
            self.topology_mapper = TopologyMapper()
        
        # Initialize passive scanner only if explicitly enabled (Lab use)
        if self.config.get('enable_passive_scanning', False):
            self.passive_scanner = PassiveScanner()
    
    def get_available_networks(self):
        """
        Get list of available Wi-Fi networks.
        
        Returns:
            list: List of available networks with details
        """
        return self.scanner.scan_available_networks()
    
    def connect_to_network(self, ssid, password=None, security_type=None):
        """
        Connect to a Wi-Fi network.
        
        Args:
            ssid (str): Network SSID
            password (str): Network password (if required)
            security_type (str): Security type of the network
            
        Returns:
            dict: Connection result with status and details
        """
        return self.connector.connect_to_network(ssid, password, security_type)
    
    def analyze_current_network(self):
        """
        Analyze the currently connected network.
        
        Returns:
            dict: Analysis results including traffic patterns and security assessment
        """
        if hasattr(self, 'analyzer'):
            return self.analyzer.analyze_current_connection()
        return {'error': 'Traffic analysis not enabled'}
    
    def map_network_topology(self):
        """
        Map the current network topology.
        
        Returns:
            dict: Network topology information and visualization data
        """
        if hasattr(self, 'topology_mapper'):
            return self.topology_mapper.discover_network_topology()
        return {'error': 'Topology mapping not enabled'}
    
    def perform_security_audit(self, network_ssid=None):
        """
        Perform comprehensive security audit of network.
        
        Args:
            network_ssid (str): Target network SSID, uses current if None
            
        Returns:
            dict: Security audit results
        """
        results = {}
        
        # Network scanning results
        if network_ssid:
            results['network_info'] = self.scanner.get_network_details(network_ssid)
        else:
            results['network_info'] = self.scanner.get_current_network_info()
        
        # Traffic analysis results
        if hasattr(self, 'analyzer'):
            results['traffic_analysis'] = self.analyzer.perform_security_analysis()
        
        # Topology analysis results
        if hasattr(self, 'topology_mapper'):
            results['topology_analysis'] = self.topology_mapper.analyze_security_topology()
        
        # Passive scanning results (Lab only)
        if hasattr(self, 'passive_scanner'):
            results['passive_analysis'] = self.passive_scanner.audit_wireless_security()
        
        return results
    
    def get_system_status(self):
        """
        Get current system status and component health.
        
        Returns:
            dict: System status information
        """
        status = {
            'scanner_status': 'active' if hasattr(self, 'scanner') else 'inactive',
            'connector_status': 'active' if hasattr(self, 'connector') else 'inactive',
            'analyzer_status': 'active' if hasattr(self, 'analyzer') else 'inactive',
            'topology_mapper_status': 'active' if hasattr(self, 'topology_mapper') else 'inactive',
            'passive_scanner_status': 'active' if hasattr(self, 'passive_scanner') else 'inactive',
            'config': self.config,
            'version': __version__
        }
        
        return status

# Convenience functions for quick access to core functionality
def quick_scan(timeout=None):
    """
    Perform a quick Wi-Fi network scan.
    
    Args:
        timeout (int): Scan timeout in seconds
        
    Returns:
        list: Available networks
    """
    scanner = WiFiScanner(timeout=timeout or DEFAULT_SCAN_TIMEOUT)
    return scanner.scan_available_networks()

def quick_connect(ssid, password=None):
    """
    Quick connect to a Wi-Fi network.
    
    Args:
        ssid (str): Network SSID
        password (str): Network password
        
    Returns:
        dict: Connection result
    """
    connector = WiFiConnector()
    return connector.connect_to_network(ssid, password)

def get_signal_quality(ssid):
    """
    Get signal quality for a specific network.
    
    Args:
        ssid (str): Network SSID
        
    Returns:
        dict: Signal quality information
    """
    scanner = WiFiScanner()
    return scanner.get_signal_strength(ssid)

def analyze_network_security(ssid=None):
    """
    Quick security analysis of a network.
    
    Args:
        ssid (str): Network SSID, uses current if None
        
    Returns:
        dict: Security analysis results
    """
    core_manager = WiFiCoreManager()
    return core_manager.perform_security_audit(ssid)

# Exception classes for Wi-Fi core operations
class WiFiCoreError(Exception):
    """Base exception for Wi-Fi core operations."""
    pass

class ScanningError(WiFiCoreError):
    """Exception raised during network scanning operations."""
    pass

class ConnectionError(WiFiCoreError):
    """Exception raised during network connection operations."""
    pass

class AnalysisError(WiFiCoreError):
    """Exception raised during network analysis operations."""
    pass

class TopologyMappingError(WiFiCoreError):
    """Exception raised during topology mapping operations."""
    pass

class PassiveScanningError(WiFiCoreError):
    """Exception raised during passive scanning operations."""
    pass

# Export all public components
__all__ = [
    # Main classes
    'WiFiScanner', 'NetworkDiscovery', 'SignalProcessor', 'ChannelAnalyzer',
    'WiFiConnector', 'ConnectionValidator', 'CredentialManager', 'ConnectionMonitor',
    'TrafficAnalyzer', 'PacketCapture', 'ProtocolAnalyzer', 'FlowAnalyzer',
    'TopologyMapper', 'DeviceDiscovery', 'RelationshipAnalyzer', 'GraphGenerator',
    'PassiveScanner', 'HandshakeCapture', 'BeaconAnalyzer', 'RogueAPDetector', 'SecurityAuditor',
    
    # Core manager
    'WiFiCoreManager',
    
    # Convenience functions
    'quick_scan', 'quick_connect', 'get_signal_quality', 'analyze_network_security',
    
    # Constants
    'SECURITY_TYPES', 'RISK_LEVELS', 'DEFAULT_CONFIG',
    
    # Exceptions
    'WiFiCoreError', 'ScanningError', 'ConnectionError', 'AnalysisError',
    'TopologyMappingError', 'PassiveScanningError'
]