"""
app/wifi_core/topology_mapper.py - Network Topology Mapping
Purpose: Network topology discovery and visualization for Wi-Fi Security System
"""

from concurrent.futures import ThreadPoolExecutor
import json
import time
import logging
import socket
import subprocess
import platform
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
import ipaddress
import threading
import queue
import re
import requests
from scapy.all import ARP, Ether, srp, get_if_addr, conf
import netifaces
import psutil

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class NetworkDevice:
    """Network device information container"""
    ip_address: str
    mac_address: str = ""
    hostname: str = ""
    device_type: str = "unknown"
    vendor: str = ""
    open_ports: List[int] = None
    os_info: str = ""
    last_seen: float = 0
    signal_strength: int = 0
    security_status: str = "unknown"
    trust_level: int = 0
    wifi_info: Dict = None
    is_current_device: bool = False
    
    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.last_seen == 0:
            self.last_seen = time.time()
        if self.wifi_info is None:
            self.wifi_info = {}

@dataclass
class DeviceRelationship:
    """Device relationship information"""
    source_ip: str
    target_ip: str
    connection_type: str
    strength: float
    protocol: str = ""
    port: int = 0
    frequency: int = 0
    last_activity: float = 0
    
    def __post_init__(self):
        if self.last_activity == 0:
            self.last_activity = time.time()

@dataclass
class NetworkSegment:
    """Network segment information"""
    segment_id: str
    subnet: str
    gateway: str
    devices: List[str]
    segment_type: str = "lan"
    security_level: str = "unknown"
    isolation_status: bool = False

class TopologyMapper:
    """
    Main topology mapping class
    Purpose: Network topology discovery and visualization
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.devices = {}
        self.relationships = []
        self.segments = {}
        self.topology_graph = {}
        self.scanning_active = False
        self.update_thread = None
        self.device_queue = queue.Queue()
        
        # Initialize enhanced discovery
        self.enhanced_discovery = EnhancedDeviceDiscovery()
        
        # Create helper instance for method delegation
        self._helper = EnhancedDeviceDiscovery()
        
        # Network discovery settings
        self.scan_timeout = self.config.get('scan_timeout', 2)
        self.port_scan_range = self.config.get('port_scan_range', [22, 23, 53, 80, 135, 139, 443, 445])
        self.max_threads = self.config.get('max_threads', 50)
        
        logger.info("Enhanced TopologyMapper initialized")

    def discover_network_topology(self) -> Dict:
        """Enhanced network topology discovery with WiFi focus"""
        logger.info("Starting enhanced network topology discovery")
        
        try:
            # Step 1: Identify current network and WiFi router
            current_network = self._get_current_network_info()
            wifi_router = self.enhanced_discovery._find_wifi_router()
            
            # Step 2: Discover WiFi connected devices
            if wifi_router:
                logger.info(f"Discovered WiFi router at: {wifi_router}")
                wifi_devices = self.enhanced_discovery.discover_wifi_connected_devices(wifi_router)
                for device in wifi_devices:
                    self.devices[device.ip_address] = device
            
            # Step 3: Enhanced device discovery for remaining network
            self._enhanced_discover_devices(current_network['subnet'])
            
            # Step 3.5: Add devices from ARP table that weren't found by ping
            self._add_arp_devices_to_scan()
            
            # Step 4: Analyze device relationships
            self._analyze_device_relationships()
            
            # Step 5: Identify network segments
            self._identify_network_segments()
            
            # Rest remains the same...
            critical_paths = self._identify_critical_paths()
            trust_relationships = self._analyze_trust_relationships()
            network_graph = self._generate_network_graph()
            
            topology_data = {
                'timestamp': time.time(),
                'network_info': current_network,
                'wifi_router': wifi_router,
                'devices': {ip: asdict(device) for ip, device in self.devices.items()},
                'relationships': [asdict(rel) for rel in self.relationships],
                'segments': {sid: asdict(segment) for sid, segment in self.segments.items()},
                'critical_paths': critical_paths,
                'trust_relationships': trust_relationships,
                'network_graph': network_graph,
                'statistics': self._calculate_topology_statistics()
            }
            
            logger.info(f"Enhanced topology discovery completed. Found {len(self.devices)} devices")
            return topology_data
            
        except Exception as e:
            logger.error(f"Error in enhanced network topology discovery: {str(e)}")
            return {'error': str(e), 'timestamp': time.time()}
        
    
    def _enhanced_discover_devices(self, subnet: str):
        """Enhanced device discovery using the new methods"""
        logger.info(f"Enhanced device discovery on subnet: {subnet}")
        
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            
            # Use ARP scanning for better results
            arp_devices = self.enhanced_discovery._arp_scan_network(str(network))
            for device in arp_devices:
                if device.ip_address not in self.devices:
                    self.devices[device.ip_address] = device
            
            # Supplement with traditional scanning for any missed devices
            threads = []
            
            def worker():
                while True:
                    try:
                        ip = self.device_queue.get(timeout=1)
                        if ip is None:
                            break
                        if str(ip) not in self.devices:
                            self._enhanced_scan_device(str(ip))
                        self.device_queue.task_done()
                    except queue.Empty:
                        break
                    except Exception as e:
                        logger.error(f"Enhanced worker error: {str(e)}")
                        self.device_queue.task_done()
            
            # Start worker threads
            for _ in range(min(self.max_threads, 20)):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Add IPs to queue
            for ip in network.hosts():
                self.device_queue.put(ip)
            
            # Wait for completion
            self.device_queue.join()
            
            # Stop worker threads
            for _ in threads:
                self.device_queue.put(None)
            
            for t in threads:
                t.join(timeout=5)
                
        except Exception as e:
            logger.error(f"Error in enhanced device discovery: {str(e)}")

    def _enhanced_scan_device(self, ip: str):
        """Enhanced device scanning with comprehensive detection"""
        try:
            if not self._ping_device(ip):
                return
            
            # Create device with basic info
            device = NetworkDevice(ip_address=ip)
            
            # Get MAC address first (critical for device identification)
            device.mac_address = self._get_mac_address(ip)
            
            # Get vendor from MAC address
            device.vendor = self._identify_vendor(device.mac_address)
            
            # Enhanced hostname resolution
            device.hostname = self._get_enhanced_hostname(ip)
            
            # Enhanced port scanning
            device.open_ports = self._enhanced_port_scan(ip)
            
            # Enhanced device type detection
            device.device_type = self._enhanced_device_type_detection(device)
            
            # If vendor is unknown but we have hostname info, try to infer vendor
            if device.vendor == "Unknown" and device.hostname:
                device.vendor = self._infer_vendor_from_hostname(device.hostname)
            
            # Apply enhanced device identification
            self._enhance_device_identification(device)
            
            # Enhanced OS detection
            device.os_info = self._enhanced_os_detection(device)
            
            # Get WiFi information if applicable
            device.wifi_info = self._get_wifi_info(ip, device)
            
            # Security assessment
            device.security_status = self._assess_device_security(device)
            device.trust_level = self._calculate_trust_level(device)
            
            # Apply enhanced device identification BEFORE naming
            self._enhance_device_identification(device)
            
            # Generate better descriptive name - ALWAYS use enhanced naming
            device.hostname = self._get_device_display_name(device)
            
            # Enhanced router identification with SSID
            self._enhance_router_identification(device)
            
            # Identify current device
            self._identify_current_device(device)
            
            self.devices[ip] = device
            logger.info(f"Enhanced scan discovered: {ip} - {device.hostname} ({device.device_type}) - {device.vendor}")
            
        except Exception as e:
            logger.error(f"Error in enhanced device scan {ip}: {str(e)}")


    def _get_current_network_info(self) -> Dict:
        """Get current network information"""
        try:
            # Get default gateway
            if platform.system().lower() == 'windows':
                result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=10)
                gateway = self._parse_windows_gateway(result.stdout)
            else:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=10)
                gateway = self._parse_linux_gateway(result.stdout)
            
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Determine subnet
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            
            return {
                'local_ip': local_ip,
                'gateway': gateway,
                'subnet': str(network),
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask)
            }
            
        except Exception as e:
            logger.error(f"Error getting network info: {str(e)}")
            return {'error': str(e)}

    def _parse_windows_gateway(self, route_output: str) -> str:
        """Parse Windows route output to find gateway"""
        for line in route_output.split('\n'):
            if '0.0.0.0' in line and 'Gateway' not in line:
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
        return ""

    def _parse_linux_gateway(self, route_output: str) -> str:
        """Parse Linux route output to find gateway"""
        parts = route_output.strip().split()
        if len(parts) >= 3:
            return parts[2]
        return ""

    def _discover_devices(self, subnet: str):
        """Discover devices on the network"""
        logger.info(f"Discovering devices on subnet: {subnet}")
        
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            threads = []
            
            # Create worker threads for device discovery
            def worker():
                while True:
                    try:
                        ip = self.device_queue.get(timeout=1)
                        if ip is None:
                            break
                        self._scan_device(str(ip))
                        self.device_queue.task_done()
                    except queue.Empty:
                        break
                    except Exception as e:
                        logger.error(f"Worker error: {str(e)}")
                        self.device_queue.task_done()
            
            # Start worker threads
            for _ in range(min(self.max_threads, 20)):
                t = threading.Thread(target=worker)
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Add IPs to queue
            for ip in network.hosts():
                self.device_queue.put(ip)
            
            # Wait for completion
            self.device_queue.join()
            
            # Stop worker threads
            for _ in threads:
                self.device_queue.put(None)
            
            for t in threads:
                t.join(timeout=5)
                
        except Exception as e:
            logger.error(f"Error in device discovery: {str(e)}")

    def _scan_device(self, ip: str):
        """Scan individual device"""
        try:
            # Check if device is reachable
            if not self._ping_device(ip):
                return
            
            device = NetworkDevice(ip_address=ip)
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                device.hostname = hostname
            except:
                device.hostname = f"device-{ip.split('.')[-1]}"
            
            # Detect device type
            device.device_type = self._detect_device_type(device.hostname, ip)
            
            # Port scan
            device.open_ports = self._scan_ports(ip)
            
            # Get additional info based on open ports
            device.os_info = self._detect_os_info(device.open_ports)
            
            # Determine security status
            device.security_status = self._assess_device_security(device)
            
            # Calculate trust level
            device.trust_level = self._calculate_trust_level(device)
            
            self.devices[ip] = device
            logger.debug(f"Discovered device: {ip} - {device.hostname}")
            
        except Exception as e:
            logger.error(f"Error scanning device {ip}: {str(e)}")

    def _ping_device(self, ip: str) -> bool:
        """Enhanced ping with better OS detection"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                    capture_output=True, text=True, timeout=3)
                return 'Reply from' in result.stdout
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                    capture_output=True, text=True, timeout=3)
                return result.returncode == 0
        except:
            return False

    def _detect_device_type(self, hostname: str, ip: str) -> str:
        """Detect device type based on hostname and IP"""
        hostname_lower = hostname.lower()
        
        for device_type, patterns in self.device_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return device_type
        
        # Check if it's likely a gateway/router
        if ip.endswith('.1') or ip.endswith('.254'):
            return 'router'
        
        return 'unknown'

    def _scan_ports(self, ip: str) -> List[int]:
        """Scan common ports on device"""
        open_ports = []
        
        for port in self.port_scan_range:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports

    def _detect_os_info(self, open_ports: List[int]) -> str:
        """Detect OS based on open ports"""
        if 135 in open_ports or 445 in open_ports:
            return "Windows"
        elif 22 in open_ports:
            return "Linux/Unix"
        elif 80 in open_ports or 443 in open_ports:
            return "Web Server"
        return "Unknown"

    def _assess_device_security(self, device: NetworkDevice) -> str:
        """Enhanced security assessment based on device type and characteristics"""
        risk_score = 0
        
        # High-risk ports
        critical_ports = [23, 135, 139, 445, 2323, 4567]  # Telnet, Windows shares, etc.
        risk_score += sum(1 for port in critical_ports if port in device.open_ports) * 2
        
        # Device type risks
        device_risks = {
            'iot_device': 3,
            'smart_tv': 2,
            'router': 1,
            'unknown': 2,
            'gaming_console': 1
        }
        risk_score += device_risks.get(device.device_type, 0)
        
        # Vendor-based risks (some IoT vendors have poor security)
        risky_patterns = ['generic', 'unknown', 'cheap']
        vendor_lower = device.vendor.lower() if device.vendor else ""
        if any(pattern in vendor_lower for pattern in risky_patterns):
            risk_score += 1
        
        # Too many open ports
        if len(device.open_ports) > 8:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 5:
            return "high_risk"
        elif risk_score >= 3:
            return "medium_risk"
        else:
            return "low_risk"

    def _calculate_trust_level(self, device: NetworkDevice) -> int:
        """Calculate trust level with enhanced logic"""
        trust_score = 60  # Start higher for better UX
        
        # Device type adjustments
        type_adjustments = {
            'router': 15,
            'laptop': 10,
            'desktop': 10,
            'smartphone': 5,
            'tablet': 5,
            'smart_tv': -5,
            'gaming_console': 0,
            'iot_device': -15,
            'unknown': -10
        }
        trust_score += type_adjustments.get(device.device_type, 0)
        
        # Vendor trust (known brands are more trustworthy)
        trusted_vendors = ['apple', 'microsoft', 'google', 'samsung', 'sony', 
                        'dell', 'hp', 'lenovo', 'netgear', 'linksys', 'asus']
        vendor_lower = device.vendor.lower() if device.vendor else ""
        if any(vendor in vendor_lower for vendor in trusted_vendors):
            trust_score += 10
        elif vendor_lower == "unknown":
            trust_score -= 5
        
        # Security status adjustments
        security_adjustments = {
            'low_risk': 15,
            'medium_risk': -5,
            'high_risk': -25
        }
        trust_score += security_adjustments.get(device.security_status, 0)
        
        # Port-based adjustments
        if len(device.open_ports) == 0:
            trust_score -= 10  # Suspicious if no ports open
        elif len(device.open_ports) > 10:
            trust_score -= 5   # Too many ports might be risky
        
        # Hostname quality
        if device.hostname and not device.hostname.startswith('device-'):
            trust_score += 5
        
        return max(0, min(100, trust_score))
    

    def _analyze_device_relationships(self):
        """Analyze relationships between devices"""
        logger.info("Analyzing device relationships")
        
        # Create relationships based on network connectivity
        for ip1, device1 in self.devices.items():
            for ip2, device2 in self.devices.items():
                if ip1 != ip2:
                    relationship = self._determine_relationship(device1, device2)
                    if relationship:
                        self.relationships.append(relationship)

    def _determine_relationship(self, device1: NetworkDevice, device2: NetworkDevice) -> Optional[DeviceRelationship]:
        """Determine relationship between two devices"""
        # Same subnet relationship
        if self._same_subnet(device1.ip_address, device2.ip_address):
            strength = 0.5
            connection_type = "subnet_peer"
            
            # Higher strength for gateway relationships
            if device1.device_type == 'router' or device2.device_type == 'router':
                strength = 0.9
                connection_type = "gateway_client"
            
            # Server relationships
            elif device1.device_type == 'server' or device2.device_type == 'server':
                strength = 0.7
                connection_type = "server_client"
            
            return DeviceRelationship(
                source_ip=device1.ip_address,
                target_ip=device2.ip_address,
                connection_type=connection_type,
                strength=strength
            )
        
        return None

    def _same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in the same subnet"""
        try:
            net1 = ipaddress.IPv4Network(f"{ip1}/24", strict=False)
            net2 = ipaddress.IPv4Network(f"{ip2}/24", strict=False)
            return net1.network_address == net2.network_address
        except:
            return False

    def _identify_network_segments(self):
        """Identify network segments"""
        logger.info("Identifying network segments")
        
        # Group devices by subnet
        subnet_groups = defaultdict(list)
        for ip, device in self.devices.items():
            subnet = str(ipaddress.IPv4Network(f"{ip}/24", strict=False).network_address)
            subnet_groups[subnet].append(ip)
        
        # Create segments
        for subnet, device_ips in subnet_groups.items():
            if len(device_ips) > 0:
                # Find gateway for this segment
                gateway = self._find_segment_gateway(device_ips)
                
                segment = NetworkSegment(
                    segment_id=f"segment_{subnet.replace('.', '_')}",
                    subnet=f"{subnet}/24",
                    gateway=gateway,
                    devices=device_ips,
                    segment_type=self._determine_segment_type(device_ips),
                    security_level=self._assess_segment_security(device_ips)
                )
                
                self.segments[segment.segment_id] = segment

    def _find_segment_gateway(self, device_ips: List[str]) -> str:
        """Find gateway for network segment"""
        for ip in device_ips:
            if ip in self.devices:
                device = self.devices[ip]
                if device.device_type == 'router' or ip.endswith('.1'):
                    return ip
        return device_ips[0] if device_ips else ""

    def _determine_segment_type(self, device_ips: List[str]) -> str:
        """Determine segment type based on devices"""
        device_types = []
        for ip in device_ips:
            if ip in self.devices:
                device_types.append(self.devices[ip].device_type)
        
        if 'server' in device_types:
            return 'server_segment'
        elif 'iot_device' in device_types:
            return 'iot_segment'
        else:
            return 'client_segment'

    def _assess_segment_security(self, device_ips: List[str]) -> str:
        """Assess security level of network segment"""
        risk_count = 0
        total_devices = len(device_ips)
        
        for ip in device_ips:
            if ip in self.devices:
                device = self.devices[ip]
                if device.security_status == 'high_risk':
                    risk_count += 2
                elif device.security_status == 'medium_risk':
                    risk_count += 1
        
        if total_devices == 0:
            return 'unknown'
        
        risk_ratio = risk_count / total_devices
        
        if risk_ratio > 1.5:
            return 'high_risk'
        elif risk_ratio > 0.5:
            return 'medium_risk'
        else:
            return 'low_risk'

    def _identify_critical_paths(self) -> List[Dict]:
        """Identify critical paths in network"""
        critical_paths = []
        
        # Find devices that are connection points
        for ip, device in self.devices.items():
            if device.device_type in ['router', 'server']:
                # Count connections
                connections = [rel for rel in self.relationships 
                             if rel.source_ip == ip or rel.target_ip == ip]
                
                if len(connections) > 2:  # Critical if more than 2 connections
                    critical_paths.append({
                        'device': ip,
                        'device_type': device.device_type,
                        'connection_count': len(connections),
                        'criticality': 'high' if len(connections) > 5 else 'medium',
                        'risk_impact': self._calculate_path_risk_impact(ip, connections)
                    })
        
        return sorted(critical_paths, key=lambda x: x['connection_count'], reverse=True)

    def _calculate_path_risk_impact(self, device_ip: str, connections: List) -> str:
        """Calculate risk impact if critical path device fails"""
        affected_devices = set()
        for conn in connections:
            if conn.source_ip == device_ip:
                affected_devices.add(conn.target_ip)
            else:
                affected_devices.add(conn.source_ip)
        
        if len(affected_devices) > 10:
            return 'critical'
        elif len(affected_devices) > 5:
            return 'high'
        else:
            return 'medium'

    def _analyze_trust_relationships(self) -> Dict:
        """Analyze trust relationships between devices"""
        trust_matrix = {}
        trust_zones = defaultdict(list)
        
        # Create trust matrix
        for ip, device in self.devices.items():
            trust_matrix[ip] = device.trust_level
            
            # Group by trust zones
            if device.trust_level >= 80:
                trust_zones['high_trust'].append(ip)
            elif device.trust_level >= 50:
                trust_zones['medium_trust'].append(ip)
            else:
                trust_zones['low_trust'].append(ip)
        
        # Analyze trust boundaries
        trust_violations = []
        for rel in self.relationships:
            source_trust = trust_matrix.get(rel.source_ip, 0)
            target_trust = trust_matrix.get(rel.target_ip, 0)
            
            # Flag high-trust to low-trust connections
            if abs(source_trust - target_trust) > 40:
                trust_violations.append({
                    'source': rel.source_ip,
                    'target': rel.target_ip,
                    'source_trust': source_trust,
                    'target_trust': target_trust,
                    'risk_level': 'high' if min(source_trust, target_trust) < 30 else 'medium'
                })
        
        return {
            'trust_matrix': trust_matrix,
            'trust_zones': dict(trust_zones),
            'trust_violations': trust_violations,
            'average_trust': sum(trust_matrix.values()) / len(trust_matrix) if trust_matrix else 0
        }

    def _generate_network_graph(self) -> Dict:
        """Generate network graph for visualization"""
        nodes = []
        edges = []
        
        # Create nodes
        for ip, device in self.devices.items():
            nodes.append({
                'id': ip,
                'label': device.hostname or ip,
                'type': device.device_type,
                'trust_level': device.trust_level,
                'security_status': device.security_status,
                'open_ports': len(device.open_ports),
                'size': max(10, device.trust_level / 10),  # Visual size based on trust
                'color': self._get_node_color(device)
            })
        
        # Create edges
        for rel in self.relationships:
            edges.append({
                'source': rel.source_ip,
                'target': rel.target_ip,
                'weight': rel.strength,
                'type': rel.connection_type,
                'width': max(1, rel.strength * 5)  # Visual width based on strength
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'layout': 'force_directed',
            'metadata': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'generated_at': time.time()
            }
        }

    def _get_node_color(self, device: NetworkDevice) -> str:
        """Get color for network node based on security status"""
        color_map = {
            'low_risk': '#28a745',    # Green
            'medium_risk': '#ffc107', # Yellow
            'high_risk': '#dc3545',   # Red
            'unknown': '#6c757d'      # Gray
        }
        return color_map.get(device.security_status, '#6c757d')

    def _calculate_topology_statistics(self) -> Dict:
        """Calculate comprehensive topology statistics"""
        device_types = {}
        security_distribution = {}
        trust_distribution = {}
        port_statistics = {}
        
        for device in self.devices.values():
            # Count device types
            device_type = getattr(device, 'device_type', 'unknown')
            device_types[device_type] = device_types.get(device_type, 0) + 1
            
            # Count security distribution
            security_status = getattr(device, 'security_status', 'unknown')
            security_distribution[security_status] = security_distribution.get(security_status, 0) + 1
            
            # Count trust levels (categorized)
            trust_level = getattr(device, 'trust_level', 0)
            if trust_level >= 80:
                trust_cat = 'high_trust'
            elif trust_level >= 50:
                trust_cat = 'medium_trust'
            else:
                trust_cat = 'low_trust'
            trust_distribution[trust_cat] = trust_distribution.get(trust_cat, 0) + 1
            
            # Count open ports
            open_ports = getattr(device, 'open_ports', [])
            for port in open_ports:
                port_statistics[str(port)] = port_statistics.get(str(port), 0) + 1
        
        return {
            'total_devices': len(self.devices),
            'total_relationships': len(self.relationships),
            'total_segments': len(self.segments),
            'device_types': device_types,
            'security_distribution': security_distribution,
            'trust_distribution': trust_distribution,
            'port_statistics': port_statistics
        }
        
        # Count device types and security status
        for device in self.devices.values():
            stats['device_types'][device.device_type] += 1
            stats['security_distribution'][device.security_status] += 1
            
            # Trust distribution
            if device.trust_level >= 70:
                stats['trust_distribution']['high'] += 1
            elif device.trust_level >= 40:
                stats['trust_distribution']['medium'] += 1
            else:
                stats['trust_distribution']['low'] += 1
            
            # Port statistics
            for port in device.open_ports:
                stats['port_statistics'][port] += 1
        
        return dict(stats)

    def update_topology_changes(self):
        """Update topology with dynamic changes"""
        if self.scanning_active:
            return
        
        self.scanning_active = True
        
        def update_worker():
            try:
                # Re-scan existing devices
                for ip in list(self.devices.keys()):
                    if self._ping_device(ip):
                        # Update last seen
                        self.devices[ip].last_seen = time.time()
                    else:
                        # Remove offline devices after timeout
                        if time.time() - self.devices[ip].last_seen > 300:  # 5 minutes
                            logger.info(f"Removing offline device: {ip}")
                            del self.devices[ip]
                
                # Update relationships
                self.relationships.clear()
                self._analyze_device_relationships()
                
                logger.info("Topology update completed")
                
            except Exception as e:
                logger.error(f"Error updating topology: {str(e)}")
            finally:
                self.scanning_active = False
        
        self.update_thread = threading.Thread(target=update_worker)
        self.update_thread.daemon = True
        self.update_thread.start()

    def get_device_info(self, ip: str) -> Optional[Dict]:
        """Get detailed information for specific device"""
        if ip in self.devices:
            device = self.devices[ip]
            relationships = [rel for rel in self.relationships 
                           if rel.source_ip == ip or rel.target_ip == ip]
            
            return {
                'device': asdict(device),
                'relationships': [asdict(rel) for rel in relationships],
                'segment': self._find_device_segment(ip)
            }
        return None
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address using ARP requests"""
        try:
            # Create ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc.upper()
        except Exception as e:
            logger.debug(f"ARP request failed for {ip}: {str(e)}")
        
        # Fallback: check ARP table
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                        if mac_match:
                            return mac_match.group().replace('-', ':').upper()
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                        if mac_match:
                            return mac_match.group().replace('-', ':').upper()
        except Exception as e:
            logger.debug(f"ARP table lookup failed for {ip}: {str(e)}")
        
        return ""

    def _find_device_segment(self, ip: str) -> Optional[str]:
        """Find which segment a device belongs to"""
        for segment_id, segment in self.segments.items():
            if ip in segment.devices:
                return segment_id
        return None

    def _get_current_system_ip(self) -> str:
        """Get the current system's IP address"""
        try:
            import socket
            import subprocess
            import platform
            
            # Method 1: Connect to a remote address to get local IP
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    return local_ip
            except:
                pass
            
            # Method 2: Use ipconfig on Windows
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if 'IPv4 Address' in line and ':' in line:
                            ip = line.split(':')[1].strip()
                            # Skip loopback and check if it's a valid private IP
                            if ip.startswith(('192.168.', '10.', '172.')):
                                return ip
            else:
                # Method 3: Use hostname on Linux/Mac
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                if not local_ip.startswith('127.'):
                    return local_ip
                    
        except Exception as e:
            logger.debug(f"Error getting current system IP: {str(e)}")
            
        return ""

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate if a string is a valid IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def _discover_devices_from_arp(self) -> List[str]:
        """Discover devices from ARP table that might not respond to ping"""
        devices = []
        try:
            import subprocess
            import platform
            
            current_ip = self._get_current_system_ip()
            if not current_ip:
                return devices
            
            # Get network prefix (e.g., 192.168.43 from 192.168.43.154)
            network_prefix = '.'.join(current_ip.split('.')[:-1])
            
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if network_prefix in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[0]
                                # Validate IP address format
                                if self._is_valid_ip(ip):
                                    # Skip broadcast and current device
                                    if not ip.endswith('.255') and ip != current_ip:
                                        devices.append(ip)
                                    
        except Exception as e:
            logger.debug(f"Error discovering devices from ARP: {str(e)}")
            
        return devices
    
    def _add_arp_devices_to_scan(self) -> None:
        """Add devices from ARP table that weren't found during ping scan"""
        try:
            arp_devices = self._discover_devices_from_arp()
            logger.info(f"Found {len(arp_devices)} additional devices in ARP table: {arp_devices}")
            
            for ip in arp_devices:
                if ip not in self.devices:
                    logger.info(f"Adding ARP-discovered device: {ip}")
                    # Create basic device entry for ARP-discovered devices
                    device = NetworkDevice(ip_address=ip)
                    
                    # Get MAC address from ARP
                    device.mac_address = self._get_mac_address(ip)
                    
                    # Get vendor from MAC address
                    device.vendor = self._identify_vendor(device.mac_address)
                    
                    # Basic hostname resolution
                    device.hostname = self._get_enhanced_hostname(ip)
                    
                    # Enhanced device type detection
                    device.device_type = self._enhanced_device_type_detection(device)
                    
                    # If vendor is unknown but we have hostname info, try to infer vendor
                    if device.vendor == "Unknown" and device.hostname:
                        device.vendor = self._infer_vendor_from_hostname(device.hostname)
                    
                    # Security assessment (basic)
                    device.security_status = 'unknown'
                    device.trust_level = 50
                    
                    # Apply enhanced device identification
                    self._enhance_device_identification(device)
                    
                    # Generate display name
                    device.hostname = self._get_device_display_name(device)
                    
                    # Enhanced router identification with SSID
                    self._enhance_router_identification(device)
                    
                    # Identify current device
                    self._identify_current_device(device)
                    
                    # Add to devices
                    self.devices[ip] = device
                    logger.info(f"ARP scan discovered: {ip} - {device.hostname} ({device.device_type}) - {device.vendor}")
                    
        except Exception as e:
            logger.error(f"Error adding ARP devices: {str(e)}")

    # Method delegates to enhanced discovery helper
    def _identify_vendor(self, mac_address: str) -> str:
        """Delegate to helper instance"""
        return self._helper._identify_vendor(mac_address)
    
    def _get_enhanced_hostname(self, ip: str) -> str:
        """Delegate to helper instance"""
        return self._helper._get_enhanced_hostname(ip)
    
    def _enhanced_device_type_detection(self, device: NetworkDevice) -> str:
        """Delegate to helper instance"""
        return self._helper._enhanced_device_type_detection(device)
    
    def _infer_vendor_from_hostname(self, hostname: str) -> str:
        """Delegate to helper instance"""
        return self._helper._infer_vendor_from_hostname(hostname)
    
    def _enhance_device_identification(self, device: NetworkDevice) -> None:
        """Delegate to helper instance"""
        return self._helper._enhance_device_identification(device)
    
    def _get_device_display_name(self, device: NetworkDevice) -> str:
        """Delegate to helper instance"""
        return self._helper._get_device_display_name(device)

    def _enhanced_port_scan(self, ip: str) -> List[int]:
        """Enhanced port scanning"""
        try:
            import socket
            import threading
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            open_ports = []
            common_ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5353, 8080]
            
            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.5)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            return port
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_port = {executor.submit(scan_port, port): port for port in common_ports}
                for future in as_completed(future_to_port):
                    port = future.result()
                    if port:
                        open_ports.append(port)
            
            return sorted(open_ports)
        except Exception as e:
            logger.debug(f"Error in enhanced port scan for {ip}: {str(e)}")
            return []

    def _get_wifi_ssid(self) -> str:
        """Get current WiFi SSID"""
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == 'windows':
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SSID' in line and ':' in line and 'BSSID' not in line:
                            ssid = line.split(':')[1].strip()
                            if ssid and ssid != '':
                                return ssid
            else:
                # Linux/Mac - try iwgetid or networksetup
                result = subprocess.run(['iwgetid', '-r'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip()
                    
        except Exception as e:
            logger.debug(f"Error getting WiFi SSID: {str(e)}")
            
        return ""

    def _enhance_router_identification(self, device: NetworkDevice) -> None:
        """Enhanced router identification with SSID mapping"""
        if device.device_type == 'router':
            # Get WiFi SSID for router identification
            ssid = self._get_wifi_ssid()
            if ssid:
                device.hostname = f"{ssid} (Router)"
                device.wifi_info = {'ssid': ssid, 'type': 'router'}
                
                # Enhanced router vendor detection based on SSID
                ssid_lower = ssid.lower()
                if 'androidap' in ssid_lower or 'android' in ssid_lower:
                    device.vendor = 'Android Hotspot'
                elif 'oneplus' in ssid_lower:
                    device.vendor = 'OnePlus'
                elif 'huawei' in ssid_lower or 'honor' in ssid_lower:
                    device.vendor = 'Huawei'
                elif 'samsung' in ssid_lower or 'galaxy' in ssid_lower:
                    device.vendor = 'Samsung'
                elif 'iphone' in ssid_lower or 'apple' in ssid_lower:
                    device.vendor = 'Apple'
                    
                logger.info(f"Enhanced router identification: {device.ip_address} - {device.hostname} - {device.vendor}")

    def _identify_current_device(self, device: NetworkDevice) -> None:
        """Identify if this device is the current system"""
        current_ip = self._get_current_system_ip()
        if device.ip_address == current_ip:
            device.is_current_device = True
            # Get the actual system hostname for current device
            try:
                system_hostname = socket.gethostname()
                if system_hostname and system_hostname != 'localhost':
                    device.hostname = f"{system_hostname} (This PC)"
                else:
                    device.hostname = f"This Device ({device.hostname})" if not device.hostname.startswith("This Device") else device.hostname
            except:
                device.hostname = f"This Device ({device.hostname})" if not device.hostname.startswith("This Device") else device.hostname
            device.trust_level = 100  # High trust for current device
            device.security_status = 'secure'
            logger.info(f"Identified current device: {device.ip_address} - {device.hostname}")

    def export_topology(self, format_type: str = 'json') -> str:
        """Export topology data in specified format"""
        topology_data = {
            'devices': {ip: asdict(device) for ip, device in self.devices.items()},
            'relationships': [asdict(rel) for rel in self.relationships],
            'segments': {sid: asdict(segment) for sid, segment in self.segments.items()},
            'export_timestamp': time.time()
        }
        
        if format_type.lower() == 'json':
            return json.dumps(topology_data, indent=2)
        else:
            return str(topology_data)


class DeviceDiscovery:
    """
    Network device discovery system
    Purpose: Specialized device discovery and identification
    """
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.discovered_devices = {}
    
    def discover_devices(self, network_range: str) -> List[NetworkDevice]:
        """Discover devices in network range"""
        devices = []
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            for ip in network.hosts():
                device = self._probe_device(str(ip))
                if device:
                    devices.append(device)
                    self.discovered_devices[str(ip)] = device
        except Exception as e:
            logger.error(f"Device discovery error: {str(e)}")
        
        return devices
    
    def _probe_device(self, ip: str) -> Optional[NetworkDevice]:
        """Probe individual device for information"""
        try:
            # Quick ping check
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            if result == 0:
                return NetworkDevice(
                    ip_address=ip,
                    device_type="web_device",
                    open_ports=[80]
                )
        except:
            pass
        
        return None


class RelationshipAnalyzer:
    """
    Enhanced device relationship analysis
    Purpose: Analyze and categorize device relationships with security focus
    """
    
    def __init__(self):
        self.relationship_types = {
            'parent_child': 0.9,
            'peer_to_peer': 0.5,
            'client_server': 0.7,
            'gateway_client': 0.8
        }
        
        # Risk weights for different relationship types
        self.risk_weights = {
            'gateway_client': 0.9,  # High risk - gateway compromise affects many
            'client_server': 0.7,   # Medium-high risk - server compromise spreads
            'peer_to_peer': 0.4,    # Medium risk - lateral movement
            'subnet_peer': 0.3,     # Lower risk - same network segment
            'parent_child': 0.8     # High risk - hierarchical dependency
        }
    
    def analyze_relationships(self, devices: Dict[str, NetworkDevice]) -> List[DeviceRelationship]:
        """Analyze relationships between devices"""
        relationships = []
        
        device_list = list(devices.items())
        for i, (ip1, device1) in enumerate(device_list):
            for ip2, device2 in device_list[i+1:]:
                relationship = self._determine_relationship_type(device1, device2)
                if relationship:
                    relationships.append(relationship)
        
        return relationships
    
    def _analyze_device_behavior(self, device: NetworkDevice) -> Dict[str, Any]:
        """Analyze device behavior patterns for better identification"""
        behavior = {
            'is_always_on': False,
            'has_web_interface': False,
            'supports_discovery': False,
            'network_activity': 'unknown'
        }
        
        # Check for web interface
        if 80 in device.open_ports or 443 in device.open_ports:
            behavior['has_web_interface'] = True
        
        # Check for discovery protocols
        if 5353 in device.open_ports:  # mDNS
            behavior['supports_discovery'] = True
        
        # Infer if device is always on based on type
        always_on_types = ['router', 'smart_tv', 'server', 'iot_device']
        if device.device_type in always_on_types:
            behavior['is_always_on'] = True
        
        return behavior
    
    def analyze_trust_relationships(self, topology_data: Dict) -> Dict:
        """
        Analyze trust relationships from topology data
        Compatible with TopologyMapper output structure
        """
        try:
            # Handle both dict and object formats
            if isinstance(topology_data, dict):
                devices_data = topology_data.get('devices', {})
                relationships_data = topology_data.get('relationships', [])
            else:
                devices_data = getattr(topology_data, 'devices', {})
                relationships_data = getattr(topology_data, 'relationships', [])
            
            # Convert devices data to proper format if needed
            devices = {}
            if isinstance(devices_data, dict):
                for ip, device_data in devices_data.items():
                    if isinstance(device_data, dict):
                        # Create NetworkDevice from dict
                        devices[ip] = self._dict_to_device(device_data)
                    else:
                        devices[ip] = device_data
            
            # Convert relationships data if needed
            relationships = []
            if isinstance(relationships_data, list):
                for rel_data in relationships_data:
                    if isinstance(rel_data, dict):
                        relationships.append(self._dict_to_relationship(rel_data))
                    else:
                        relationships.append(rel_data)
            
            return self._perform_trust_analysis(devices, relationships)
            
        except Exception as e:
            logger.error(f"Trust relationship analysis error: {str(e)}")
            return {'error': str(e), 'trust_matrix': {}, 'trust_zones': {}, 'trust_violations': []}
    
    def identify_critical_paths(self, topology_data: Dict) -> List[Dict]:
        """
        Identify critical paths in the network topology
        """
        try:
            # Extract devices and relationships
            if isinstance(topology_data, dict):
                devices_data = topology_data.get('devices', {})
                relationships_data = topology_data.get('relationships', [])
            else:
                devices_data = getattr(topology_data, 'devices', {})
                relationships_data = getattr(topology_data, 'relationships', [])
            
            # Convert to proper format
            devices = {}
            for ip, device_data in devices_data.items():
                if isinstance(device_data, dict):
                    devices[ip] = self._dict_to_device(device_data)
                else:
                    devices[ip] = device_data
            
            relationships = []
            for rel_data in relationships_data:
                if isinstance(rel_data, dict):
                    relationships.append(self._dict_to_relationship(rel_data))
                else:
                    relationships.append(rel_data)
            
            return self._find_critical_paths(devices, relationships)
            
        except Exception as e:
            logger.error(f"Critical path analysis error: {str(e)}")
            return []
    
    def analyze_vulnerability_propagation(self, topology_data: Dict) -> Dict:
        """
        Analyze potential vulnerability propagation paths
        """
        try:
            # Extract and convert data
            if isinstance(topology_data, dict):
                devices_data = topology_data.get('devices', {})
                relationships_data = topology_data.get('relationships', [])
            else:
                devices_data = getattr(topology_data, 'devices', {})
                relationships_data = getattr(topology_data, 'relationships', [])
            
            devices = {}
            for ip, device_data in devices_data.items():
                if isinstance(device_data, dict):
                    devices[ip] = self._dict_to_device(device_data)
                else:
                    devices[ip] = device_data
            
            relationships = []
            for rel_data in relationships_data:
                if isinstance(rel_data, dict):
                    relationships.append(self._dict_to_relationship(rel_data))
                else:
                    relationships.append(rel_data)
            
            return self._analyze_propagation_risks(devices, relationships)
            
        except Exception as e:
            logger.error(f"Vulnerability propagation analysis error: {str(e)}")
            return {'propagation_paths': [], 'high_risk_devices': [], 'isolation_recommendations': []}
    
    def _dict_to_device(self, device_data: Dict) -> 'NetworkDevice':
        """Convert dictionary to NetworkDevice object"""
        return NetworkDevice(
            ip_address=device_data.get('ip_address', ''),
            mac_address=device_data.get('mac_address', ''),
            hostname=device_data.get('hostname', ''),
            device_type=device_data.get('device_type', 'unknown'),
            vendor=device_data.get('vendor', ''),
            open_ports=device_data.get('open_ports', []),
            os_info=device_data.get('os_info', ''),
            last_seen=device_data.get('last_seen', time.time()),
            signal_strength=device_data.get('signal_strength', 0),
            security_status=device_data.get('security_status', 'unknown'),
            trust_level=device_data.get('trust_level', 0)
        )
    
    def _dict_to_relationship(self, rel_data: Dict) -> 'DeviceRelationship':
        """Convert dictionary to DeviceRelationship object"""
        return DeviceRelationship(
            source_ip=rel_data.get('source_ip', ''),
            target_ip=rel_data.get('target_ip', ''),
            connection_type=rel_data.get('connection_type', 'unknown'),
            strength=rel_data.get('strength', 0.5),
            protocol=rel_data.get('protocol', ''),
            port=rel_data.get('port', 0),
            frequency=rel_data.get('frequency', 0),
            last_activity=rel_data.get('last_activity', time.time())
        )
    
    def _perform_trust_analysis(self, devices: Dict, relationships: List) -> Dict:
        """Perform detailed trust relationship analysis"""
        trust_matrix = {}
        trust_zones = defaultdict(list)
        trust_violations = []
        
        # Create trust matrix
        for ip, device in devices.items():
            trust_level = getattr(device, 'trust_level', 0)
            trust_matrix[ip] = trust_level
            
            # Group by trust zones
            if trust_level >= 80:
                trust_zones['high_trust'].append(ip)
            elif trust_level >= 50:
                trust_zones['medium_trust'].append(ip)
            else:
                trust_zones['low_trust'].append(ip)
        
        # Analyze trust boundaries
        for rel in relationships:
            source_ip = getattr(rel, 'source_ip', '')
            target_ip = getattr(rel, 'target_ip', '')
            
            source_trust = trust_matrix.get(source_ip, 0)
            target_trust = trust_matrix.get(target_ip, 0)
            
            # Flag significant trust level differences
            if abs(source_trust - target_trust) > 40:
                trust_violations.append({
                    'source': source_ip,
                    'target': target_ip,
                    'source_trust': source_trust,
                    'target_trust': target_trust,
                    'connection_type': getattr(rel, 'connection_type', 'unknown'),
                    'risk_level': 'high' if min(source_trust, target_trust) < 30 else 'medium',
                    'recommendation': self._get_trust_violation_recommendation(source_trust, target_trust)
                })
        
        # Calculate trust metrics
        trust_values = list(trust_matrix.values())
        average_trust = sum(trust_values) / len(trust_values) if trust_values else 0
        trust_variance = sum((t - average_trust) ** 2 for t in trust_values) / len(trust_values) if trust_values else 0
        
        return {
            'trust_matrix': trust_matrix,
            'trust_zones': dict(trust_zones),
            'trust_violations': trust_violations,
            'average_trust': average_trust,
            'trust_variance': trust_variance,
            'high_trust_devices': len(trust_zones['high_trust']),
            'low_trust_devices': len(trust_zones['low_trust']),
            'trust_boundary_violations': len(trust_violations)
        }
    
    def _find_critical_paths(self, devices: Dict, relationships: List) -> List[Dict]:
        """Find critical network paths"""
        critical_paths = []
        
        # Build connection graph
        connections = defaultdict(list)
        for rel in relationships:
            source_ip = getattr(rel, 'source_ip', '')
            target_ip = getattr(rel, 'target_ip', '')
            strength = getattr(rel, 'strength', 0.5)
            
            connections[source_ip].append({'target': target_ip, 'strength': strength})
            connections[target_ip].append({'target': source_ip, 'strength': strength})
        
        # Find devices with high connectivity (potential bottlenecks)
        for ip, device in devices.items():
            connection_count = len(connections.get(ip, []))
            device_type = getattr(device, 'device_type', 'unknown')
            security_status = getattr(device, 'security_status', 'unknown')
            
            if connection_count > 2:  # Has multiple connections
                # Calculate criticality score
                criticality_score = self._calculate_criticality_score(
                    connection_count, device_type, security_status, connections[ip]
                )
                
                if criticality_score > 0.6:  # Threshold for critical paths
                    critical_paths.append({
                        'device_ip': ip,
                        'device_type': device_type,
                        'connection_count': connection_count,
                        'criticality_score': criticality_score,
                        'risk_level': self._determine_risk_level(criticality_score),
                        'failure_impact': self._estimate_failure_impact(ip, connections),
                        'recommendations': self._get_critical_path_recommendations(device_type, criticality_score)
                    })
        
        return sorted(critical_paths, key=lambda x: x['criticality_score'], reverse=True)
    
    def _analyze_propagation_risks(self, devices: Dict, relationships: List) -> Dict:
        """Analyze vulnerability propagation risks"""
        propagation_paths = []
        high_risk_devices = []
        isolation_recommendations = []
        
        # Identify high-risk devices
        for ip, device in devices.items():
            security_status = getattr(device, 'security_status', 'unknown')
            device_type = getattr(device, 'device_type', 'unknown')
            open_ports = getattr(device, 'open_ports', [])
            
            risk_score = self._calculate_device_risk_score(security_status, device_type, open_ports)
            
            if risk_score > 0.7:
                high_risk_devices.append({
                    'ip': ip,
                    'device_type': device_type,
                    'security_status': security_status,
                    'risk_score': risk_score,
                    'vulnerabilities': self._identify_device_vulnerabilities(device)
                })
        
        # Analyze propagation paths from high-risk devices
        for high_risk_device in high_risk_devices:
            source_ip = high_risk_device['ip']
            paths = self._find_propagation_paths(source_ip, relationships, devices)
            
            for path in paths:
                propagation_paths.append({
                    'source': source_ip,
                    'path': path['devices'],
                    'risk_level': path['risk_level'],
                    'propagation_probability': path['probability'],
                    'affected_devices': len(path['devices']),
                    'mitigation_priority': path['priority']
                })
        
        # Generate isolation recommendations
        isolation_recommendations = self._generate_isolation_recommendations(
            high_risk_devices, propagation_paths, devices
        )
        
        return {
            'propagation_paths': propagation_paths,
            'high_risk_devices': high_risk_devices,
            'isolation_recommendations': isolation_recommendations,
            'total_at_risk_devices': len(set(ip for path in propagation_paths for ip in path['path'])),
            'propagation_risk_score': self._calculate_overall_propagation_risk(propagation_paths)
        }
    
    def _calculate_criticality_score(self, connection_count: int, device_type: str, 
                                   security_status: str, connections: List) -> float:
        """Calculate criticality score for a device"""
        base_score = min(1.0, connection_count / 10.0)  # Normalize connection count
        
        # Device type multipliers
        type_multipliers = {
            'router': 1.5,
            'server': 1.3,
            'access_point': 1.2,
            'workstation': 1.0,
            'iot_device': 0.8
        }
        
        type_multiplier = type_multipliers.get(device_type, 1.0)
        
        # Security status impact
        security_multipliers = {
            'high_risk': 1.4,
            'medium_risk': 1.1,
            'low_risk': 0.9,
            'unknown': 1.2
        }
        
        security_multiplier = security_multipliers.get(security_status, 1.0)
        
        # Connection strength factor
        avg_connection_strength = sum(conn['strength'] for conn in connections) / len(connections)
        
        criticality_score = base_score * type_multiplier * security_multiplier * avg_connection_strength
        
        return min(1.0, criticality_score)
    
    def _determine_risk_level(self, criticality_score: float) -> str:
        """Determine risk level based on criticality score"""
        if criticality_score >= 0.8:
            return 'critical'
        elif criticality_score >= 0.6:
            return 'high'
        elif criticality_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _estimate_failure_impact(self, device_ip: str, connections: Dict) -> Dict:
        """Estimate impact if device fails"""
        directly_affected = len(connections.get(device_ip, []))
        
        # Estimate indirectly affected devices
        indirectly_affected = 0
        for conn in connections.get(device_ip, []):
            target_ip = conn['target']
            indirectly_affected += len(connections.get(target_ip, []))
        
        return {
            'directly_affected': directly_affected,
            'indirectly_affected': indirectly_affected,
            'total_impact': directly_affected + indirectly_affected,
            'network_partition_risk': 'high' if directly_affected > 5 else 'low'
        }
    
    def _calculate_device_risk_score(self, security_status: str, device_type: str, open_ports: List) -> float:
        """Calculate device risk score"""
        base_risk = 0.3
        
        # Security status impact
        security_risks = {
            'high_risk': 0.6,
            'medium_risk': 0.3,
            'low_risk': 0.1,
            'unknown': 0.4
        }
        
        base_risk += security_risks.get(security_status, 0.4)
        
        # Device type risk
        type_risks = {
            'iot_device': 0.3,
            'workstation': 0.2,
            'server': 0.1,
            'router': 0.2,
            'unknown': 0.3
        }
        
        base_risk += type_risks.get(device_type, 0.3)
        
        # Open ports risk
        risky_ports = [23, 135, 139, 445, 1433, 3389]  # Telnet, RPC, NetBIOS, SMB, SQL, RDP
        risky_port_count = sum(1 for port in open_ports if port in risky_ports)
        base_risk += min(0.3, risky_port_count * 0.1)
        
        return min(1.0, base_risk)
    
    def _identify_device_vulnerabilities(self, device) -> List[str]:
        """Identify potential vulnerabilities in a device"""
        vulnerabilities = []
        
        open_ports = getattr(device, 'open_ports', [])
        device_type = getattr(device, 'device_type', 'unknown')
        security_status = getattr(device, 'security_status', 'unknown')
        
        # Port-based vulnerabilities
        if 23 in open_ports:
            vulnerabilities.append('Telnet service (unencrypted)')
        if 135 in open_ports:
            vulnerabilities.append('RPC endpoint mapper')
        if 445 in open_ports:
            vulnerabilities.append('SMB service (potential for lateral movement)')
        if 3389 in open_ports:
            vulnerabilities.append('RDP service (brute force target)')
        
        # Device type vulnerabilities
        if device_type == 'iot_device':
            vulnerabilities.append('IoT device (often unpatched)')
        
        # Security status vulnerabilities
        if security_status == 'high_risk':
            vulnerabilities.append('High-risk security profile')
        
        return vulnerabilities
    
    def _find_propagation_paths(self, source_ip: str, relationships: List, devices: Dict) -> List[Dict]:
        """Find potential propagation paths from a source device"""
        paths = []
        visited = set()
        
        def dfs_propagation(current_ip: str, path: List[str], probability: float, max_depth: int = 3):
            if max_depth <= 0 or current_ip in visited:
                return
            
            visited.add(current_ip)
            path.append(current_ip)
            
            # Find connected devices
            for rel in relationships:
                next_ip = None
                rel_strength = getattr(rel, 'strength', 0.5)
                
                if getattr(rel, 'source_ip', '') == current_ip:
                    next_ip = getattr(rel, 'target_ip', '')
                elif getattr(rel, 'target_ip', '') == current_ip:
                    next_ip = getattr(rel, 'source_ip', '')
                
                if next_ip and next_ip not in visited:
                    next_device = devices.get(next_ip)
                    if next_device:
                        # Calculate propagation probability
                        device_vulnerability = self._get_device_vulnerability_factor(next_device)
                        new_probability = probability * rel_strength * device_vulnerability
                        
                        if new_probability > 0.1:  # Minimum threshold
                            if len(path) > 1:  # Don't include single-device paths
                                paths.append({
                                    'devices': path.copy(),
                                    'probability': new_probability,
                                    'risk_level': self._determine_path_risk_level(new_probability),
                                    'priority': self._calculate_mitigation_priority(path.copy(), new_probability)
                                })
                            
                            # Continue DFS
                            dfs_propagation(next_ip, path.copy(), new_probability, max_depth - 1)
            
            visited.remove(current_ip)
        
        dfs_propagation(source_ip, [], 1.0)
        return paths
    
    def _get_device_vulnerability_factor(self, device) -> float:
        """Get vulnerability factor for a device"""
        security_status = getattr(device, 'security_status', 'unknown')
        trust_level = getattr(device, 'trust_level', 50)
        
        vulnerability_factors = {
            'high_risk': 0.8,
            'medium_risk': 0.5,
            'low_risk': 0.2,
            'unknown': 0.6
        }
        
        base_factor = vulnerability_factors.get(security_status, 0.6)
        trust_factor = (100 - trust_level) / 100  # Lower trust = higher vulnerability
        
        return (base_factor + trust_factor) / 2
    
    def _determine_path_risk_level(self, probability: float) -> str:
        """Determine risk level for propagation path"""
        if probability >= 0.7:
            return 'critical'
        elif probability >= 0.5:
            return 'high'
        elif probability >= 0.3:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_mitigation_priority(self, path: List[str], probability: float) -> str:
        """Calculate mitigation priority"""
        path_length = len(path)
        
        if probability >= 0.7 and path_length >= 3:
            return 'immediate'
        elif probability >= 0.5:
            return 'high'
        elif probability >= 0.3:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_overall_propagation_risk(self, propagation_paths: List) -> float:
        """Calculate overall propagation risk score"""
        if not propagation_paths:
            return 0.0
        
        total_risk = sum(path['propagation_probability'] for path in propagation_paths)
        avg_risk = total_risk / len(propagation_paths)
        
        # Weight by number of paths
        path_count_factor = min(1.0, len(propagation_paths) / 10)
        
        return min(1.0, avg_risk * (1 + path_count_factor))
    
    def _generate_isolation_recommendations(self, high_risk_devices: List, 
                                          propagation_paths: List, devices: Dict) -> List[Dict]:
        """Generate device isolation recommendations"""
        recommendations = []
        
        # High-risk devices should be isolated
        for device in high_risk_devices:
            if device['risk_score'] > 0.8:
                recommendations.append({
                    'type': 'isolate_device',
                    'device_ip': device['ip'],
                    'reason': f"High-risk device ({device['security_status']})",
                    'priority': 'immediate',
                    'impact': 'Prevents lateral movement from compromised device'
                })
        
        # Critical propagation paths should be segmented
        critical_paths = [p for p in propagation_paths if p['risk_level'] == 'critical']
        for path in critical_paths:
            recommendations.append({
                'type': 'segment_network',
                'affected_devices': path['path'],
                'reason': 'Critical propagation path detected',
                'priority': 'high',
                'impact': f"Reduces propagation risk by {path['propagation_probability']:.2%}"
            })
        
        return recommendations
    
    def _get_trust_violation_recommendation(self, source_trust: float, target_trust: float) -> str:
        """Get recommendation for trust violation"""
        if min(source_trust, target_trust) < 30:
            return "Consider network segmentation to isolate low-trust devices"
        elif abs(source_trust - target_trust) > 50:
            return "Implement additional access controls between trust zones"
        else:
            return "Monitor traffic between devices with different trust levels"
    
    def _get_critical_path_recommendations(self, device_type: str, criticality_score: float) -> List[str]:
        """Get recommendations for critical path devices"""
        recommendations = []
        
        if criticality_score > 0.8:
            recommendations.append("Implement redundant paths to reduce single point of failure")
            recommendations.append("Enhanced monitoring and alerting for this device")
        
        if device_type == 'router':
            recommendations.append("Consider router clustering or backup gateway configuration")
        elif device_type == 'server':
            recommendations.append("Implement server clustering or load balancing")
        
        recommendations.append("Regular security updates and patch management")
        recommendations.append("Network traffic analysis for anomaly detection")
        
        return recommendations
    
    def _determine_relationship_type(self, device1: NetworkDevice, device2: NetworkDevice) -> Optional[DeviceRelationship]:
        """Determine relationship type between two devices"""
        # Router to client relationship
        if device1.device_type == 'router' and device2.device_type != 'router':
            return DeviceRelationship(
                source_ip=device1.ip_address,
                target_ip=device2.ip_address,
                connection_type='gateway_client',
                strength=0.8
            )
        
        # Server to client relationship
        elif device1.device_type == 'server':
            return DeviceRelationship(
                source_ip=device1.ip_address,
                target_ip=device2.ip_address,
                connection_type='client_server',
                strength=0.7
            )
        
        # Peer relationship
        else:
            return DeviceRelationship(
                source_ip=device1.ip_address,
                target_ip=device2.ip_address,
                connection_type='peer_to_peer',
                strength=0.5
            )

class GraphGenerator:
    """
    Network graph generation
    Purpose: Generate visualization-ready network graphs
    """
    
    def __init__(self):
        self.layout_algorithms = ['force_directed', 'hierarchical', 'circular', 'grid']
        self.node_shapes = {
            'router': 'diamond',
            'server': 'square',
            'workstation': 'circle',
            'iot_device': 'triangle',
            'printer': 'hexagon',
            'access_point': 'star',
            'unknown': 'circle'
        }
    
    def generate_network_graph(self, devices: Dict[str, NetworkDevice], 
                             relationships: List[DeviceRelationship],
                             layout: str = 'force_directed') -> Dict:
        """Generate network graph for visualization"""
        
        nodes = self._create_nodes(devices)
        edges = self._create_edges(relationships)
        
        graph_data = {
            'nodes': nodes,
            'edges': edges,
            'layout': layout,
            'metadata': {
                'node_count': len(nodes),
                'edge_count': len(edges),
                'generated_timestamp': time.time(),
                'layout_algorithm': layout
            }
        }
        
        # Apply layout-specific positioning
        if layout == 'hierarchical':
            graph_data = self._apply_hierarchical_layout(graph_data, devices)
        elif layout == 'circular':
            graph_data = self._apply_circular_layout(graph_data)
        
        return graph_data
    
    def _create_nodes(self, devices: Dict[str, NetworkDevice]) -> List[Dict]:
        """Create visualization nodes from devices"""
        nodes = []
        
        for ip, device in devices.items():
            # Calculate AI confidence and indicators
            ai_confidence = self._calculate_ai_confidence(device)
            ai_indicator = self._get_ai_indicator(ai_confidence, device)
            
            node = {
                'id': ip,
                'label': self._get_device_display_name(device),
                'type': device.device_type,
                'shape': self.node_shapes.get(device.device_type, 'circle'),
                'size': self._calculate_node_size(device),
                'color': self._get_node_color(device),
                'border_color': self._get_border_color(device),
                'border_width': 2 if device.security_status == 'high_risk' else 1,
                'ai_confidence': ai_confidence,
                'ai_indicator': ai_indicator,
                'properties': {
                    'ip_address': device.ip_address,
                    'mac_address': device.mac_address or 'Unknown',
                    'hostname': device.hostname or 'Unknown',
                    'device_type': device.device_type or 'unknown',
                    'security_status': device.security_status or 'unknown',
                    'trust_level': device.trust_level or 0,
                    'open_ports': device.open_ports or [],
                    'os_info': device.os_info or 'Unknown',
                    'vendor': device.vendor or 'Unknown',
                    'last_seen': device.last_seen or 'Unknown',
                    'signal_strength': getattr(device, 'signal_strength', 0)
                },
                'tooltip': self._generate_node_tooltip(device)
            }
            nodes.append(node)
        
        return nodes
    
    def _create_edges(self, relationships: List[DeviceRelationship]) -> List[Dict]:
        """Create visualization edges from relationships"""
        edges = []
        
        for i, rel in enumerate(relationships):
            edge = {
                'id': f"edge_{i}",
                'source': rel.source_ip,
                'target': rel.target_ip,
                'weight': rel.strength,
                'width': max(1, rel.strength * 5),
                'color': self._get_edge_color(rel),
                'style': self._get_edge_style(rel),
                'label': rel.connection_type.replace('_', ' ').title(),
                'properties': {
                    'connection_type': rel.connection_type,
                    'strength': rel.strength,
                    'protocol': rel.protocol,
                    'port': rel.port,
                    'frequency': rel.frequency,
                    'last_activity': rel.last_activity
                },
                'tooltip': self._generate_edge_tooltip(rel)
            }
            edges.append(edge)
        
        return edges
    
    def _calculate_node_size(self, device: NetworkDevice) -> int:
        """Calculate node size based on device properties"""
        base_size = 20
        
        # Size based on device type
        type_multipliers = {
            'router': 2.0,
            'server': 1.8,
            'access_point': 1.5,
            'workstation': 1.2,
            'printer': 1.0,
            'iot_device': 0.8,
            'unknown': 1.0
        }
        
        size_multiplier = type_multipliers.get(device.device_type, 1.0)
        
        # Adjust based on trust level
        trust_adjustment = device.trust_level / 100
        
        # Adjust based on number of open ports
        port_adjustment = min(1.5, 1 + len(device.open_ports) / 10)
        
        final_size = int(base_size * size_multiplier * trust_adjustment * port_adjustment)
        return max(10, min(50, final_size))
    
    def _get_node_color(self, device: NetworkDevice) -> str:
        """Get node color based on security status and device type"""
        # Enhanced color mapping for AI Risk Levels (matching template legend)
        security_colors = {
            'no_risk': '#27ae60',      # Green - No Risk (AI Verified)
            'low_risk': '#f39c12',     # Orange - Low Risk
            'medium_risk': '#e74c3c',  # Red - Medium Risk  
            'high_risk': '#8e44ad',    # Purple - High Risk
            'critical_risk': '#2c3e50', # Dark - Critical Risk
            'unknown': '#95a5a6'       # Light Gray - Unknown
        }
        
        return security_colors.get(device.security_status, '#6c757d')
    
    def _get_border_color(self, device: NetworkDevice) -> str:
        """Get node border color based on device type"""
        type_colors = {
            'router': '#007bff',      # Blue - Router/Gateway
            'server': '#6f42c1',      # Purple - Server
            'smartphone': '#28a745',   # Green - Mobile Device
            'laptop': '#fd7e14',      # Orange - Computer
            'desktop': '#fd7e14',     # Orange - Computer  
            'smart_tv': '#20c997',    # Teal - Smart TV
            'tablet': '#28a745',      # Green - Mobile Device
            'gaming_console': '#e83e8c', # Pink - Gaming Console
            'smart_speaker': '#17a2b8', # Cyan - IoT Device
            'iot_device': '#6c757d',   # Gray - IoT Device
            'printer': '#e83e8c',      # Pink - Printer
            'access_point': '#007bff', # Blue - Network Infrastructure
            'unknown': '#343a40'       # Dark gray
        }
        
        return type_colors.get(device.device_type, '#343a40')
    
    def _get_edge_color(self, relationship: DeviceRelationship) -> str:
        """Get edge color based on connection security and relationship type"""
        # Connection Security colors (matching template legend)
        if relationship.strength > 0.8:
            return '#27ae60'  # Green - Secure Connection
        elif relationship.strength > 0.6:
            return '#f39c12'  # Orange - Moderate Security
        elif relationship.strength > 0.4:
            return '#e74c3c'  # Red - Weak Security
        else:
            return '#8e44ad'  # Purple - Insecure Connection
    
    def _get_edge_style(self, relationship: DeviceRelationship) -> str:
        """Get edge style based on relationship properties"""
        if relationship.strength > 0.8:
            return 'solid'
        elif relationship.strength > 0.5:
            return 'dashed'
        else:
            return 'dotted'
    
    def _generate_node_tooltip(self, device: NetworkDevice) -> str:
        """Generate tooltip text for node"""
        tooltip_parts = [
            f"<b>{device.hostname or device.ip_address}</b>",
            f"IP: {device.ip_address}",
            f"Type: {device.device_type.replace('_', ' ').title()}",
            f"Security: {device.security_status.replace('_', ' ').title()}",
            f"Trust Level: {device.trust_level}%"
        ]
        
        if device.open_ports:
            tooltip_parts.append(f"Open Ports: {', '.join(map(str, device.open_ports[:5]))}")
            if len(device.open_ports) > 5:
                tooltip_parts[-1] += f" (+{len(device.open_ports) - 5} more)"
        
        if device.os_info:
            tooltip_parts.append(f"OS: {device.os_info}")
        
        return "<br>".join(tooltip_parts)
    
    def _generate_edge_tooltip(self, relationship: DeviceRelationship) -> str:
        """Generate tooltip text for edge"""
        tooltip_parts = [
            f"<b>{relationship.connection_type.replace('_', ' ').title()}</b>",
            f"From: {relationship.source_ip}",
            f"To: {relationship.target_ip}",
            f"Strength: {relationship.strength:.2f}"
        ]
        
        if relationship.protocol:
            tooltip_parts.append(f"Protocol: {relationship.protocol}")
        
        if relationship.port:
            tooltip_parts.append(f"Port: {relationship.port}")
        
        return "<br>".join(tooltip_parts)
    
    def _apply_hierarchical_layout(self, graph_data: Dict, devices: Dict[str, NetworkDevice]) -> Dict:
        """Apply hierarchical layout positioning"""
        # Group devices by type hierarchy
        hierarchy_levels = {
            'router': 0,
            'server': 1,
            'access_point': 1,
            'workstation': 2,
            'printer': 2,
            'iot_device': 3,
            'unknown': 3
        }
        
        # Add position data to nodes
        level_counts = defaultdict(int)
        for node in graph_data['nodes']:
            device_type = node['type']
            level = hierarchy_levels.get(device_type, 3)
            
            node['level'] = level
            node['position'] = {
                'x': level_counts[level] * 100,
                'y': level * 100
            }
            level_counts[level] += 1
        
        return graph_data
    
    def _apply_circular_layout(self, graph_data: Dict) -> Dict:
        """Apply circular layout positioning"""
        import math
        
        node_count = len(graph_data['nodes'])
        if node_count == 0:
            return graph_data
        
        radius = max(100, node_count * 10)
        angle_step = 2 * math.pi / node_count
        
        for i, node in enumerate(graph_data['nodes']):
            angle = i * angle_step
            node['position'] = {
                'x': radius * math.cos(angle),
                'y': radius * math.sin(angle)
            }
        
        return graph_data
    
    def export_graph(self, graph_data: Dict, format_type: str = 'json') -> str:
        """Export graph data in specified format"""
        if format_type.lower() == 'json':
            return json.dumps(graph_data, indent=2)
        elif format_type.lower() == 'dot':
            return self._convert_to_dot_format(graph_data)
        elif format_type.lower() == 'gexf':
            return self._convert_to_gexf_format(graph_data)
        else:
            return str(graph_data)
    
    def _convert_to_dot_format(self, graph_data: Dict) -> str:
        """Convert graph to DOT format for Graphviz"""
        dot_lines = ['digraph NetworkTopology {']
        dot_lines.append('  rankdir=TB;')
        dot_lines.append('  node [shape=circle];')
        
        # Add nodes
        for node in graph_data['nodes']:
            attributes = [
                f'label="{node["label"]}"',
                f'color="{node["color"]}"',
                f'shape="{node["shape"]}"'
            ]
            dot_lines.append(f'  "{node["id"]}" [{", ".join(attributes)}];')
        
        # Add edges
        for edge in graph_data['edges']:
            attributes = [
                f'color="{edge["color"]}"',
                f'penwidth="{edge["width"]}"',
                f'style="{edge["style"]}"'
            ]
            dot_lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" [{", ".join(attributes)}];')
        
        dot_lines.append('}')
        return '\n'.join(dot_lines)
    
    def _convert_to_gexf_format(self, graph_data: Dict) -> str:
        """Convert graph to GEXF format"""
        gexf_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        gexf_lines.append('<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">')
        gexf_lines.append('  <graph mode="static" defaultedgetype="directed">')
        
        # Add nodes
        gexf_lines.append('    <nodes>')
        for node in graph_data['nodes']:
            gexf_lines.append(f'      <node id="{node["id"]}" label="{node["label"]}"/>')
        gexf_lines.append('    </nodes>')
        
        # Add edges
        gexf_lines.append('    <edges>')
        for i, edge in enumerate(graph_data['edges']):
            gexf_lines.append(f'      <edge id="{i}" source="{edge["source"]}" target="{edge["target"]}"/>')
        gexf_lines.append('    </edges>')
        
        gexf_lines.append('  </graph>')
        gexf_lines.append('</gexf>')
        return '\n'.join(gexf_lines)
    
    def _calculate_ai_confidence(self, device: NetworkDevice) -> float:
        """Calculate AI confidence level for device identification"""
        confidence = 0.5  # Base confidence
        
        # Higher confidence if we have detailed information
        if device.vendor and device.vendor != "Unknown":
            confidence += 0.2
        if device.hostname and not device.hostname.startswith('device-'):
            confidence += 0.2
        if device.device_type != 'unknown':
            confidence += 0.2
        if device.open_ports and len(device.open_ports) > 0:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _get_ai_indicator(self, confidence: float, device: NetworkDevice) -> str:
        """Get AI indicator emoji based on confidence level"""
        if confidence >= 0.9:
            return "🤖"  # AI High Confidence
        elif confidence >= 0.7:
            return "⚡"  # AI Enhanced Analysis
        elif confidence >= 0.5:
            return "📊"  # Standard Analysis
        else:
            return "❓"  # Uncertain Detection
    
    def _get_device_display_name(self, device: NetworkDevice) -> str:
        """Get a user-friendly display name for the device"""
        # Prioritize meaningful hostnames over generic ones
        if device.hostname and not device.hostname.startswith('device-') and not device.hostname.startswith('Device-'):
            # Clean up hostname for display
            display_name = device.hostname.replace('.local', '').replace('.home', '')
            if '.' in display_name:
                display_name = display_name.split('.')[0]
            return display_name
        
        # Use vendor + device type for better identification
        if device.vendor and device.vendor != "Unknown" and device.device_type != "unknown":
            last_octet = device.ip_address.split('.')[-1]
            device_type = device.device_type.replace('_', ' ').title()
            
            # Special cases for common devices
            if device.device_type == "smartphone":
                if "OnePlus" in device.vendor:
                    return f"OnePlus Phone"
                elif "Apple" in device.vendor:
                    return f"iPhone"
                elif "Samsung" in device.vendor:
                    return f"Samsung Phone"
                elif "Huawei" in device.vendor:
                    return f"Huawei Phone"
                else:
                    return f"{device.vendor} Phone"
            elif device.device_type == "laptop":
                if "Huawei" in device.vendor:
                    return f"Huawei Laptop"
                elif "Apple" in device.vendor:
                    return f"MacBook"
                elif "Dell" in device.vendor:
                    return f"Dell Laptop"
                else:
                    return f"{device.vendor} Laptop"
            elif device.device_type == "router":
                # Special handling for different router types
                if device.vendor == "OnePlus":
                    # OnePlus phone acting as hotspot
                    if hasattr(device, 'wifi_info') and device.wifi_info and 'ssid' in device.wifi_info:
                        return f"OnePlus Hotspot ({device.wifi_info['ssid']})"
                    else:
                        return f"OnePlus Hotspot"
                elif device.vendor == "Android Hotspot":
                    # Android phone hotspot
                    if hasattr(device, 'wifi_info') and device.wifi_info and 'ssid' in device.wifi_info:
                        return f"Android Hotspot ({device.wifi_info['ssid']})"
                    else:
                        return f"Android Hotspot"
                else:
                    # Regular router
                    if hasattr(device, 'wifi_info') and device.wifi_info and 'ssid' in device.wifi_info:
                        return f"WiFi Router ({device.wifi_info['ssid']})"
                    else:
                        return f"WiFi Router"
            else:
                return f"{device.vendor} {device_type}"
        
        # Check if this is the current device
        if hasattr(device, 'is_current_device') and device.is_current_device:
            if device.vendor == "Huawei":
                return f"This Device (Huawei Laptop)"
            else:
                return f"This Device (Laptop)"
        
        # Fallback to IP-based naming with device type
        last_octet = device.ip_address.split('.')[-1]
        if device.device_type != "unknown":
            device_type = device.device_type.replace('_', ' ').title()
            return f"{device_type} ({last_octet})"
        else:
            return f"Device {last_octet}"
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address for an IP using ARP table"""
        try:
            import platform
            import subprocess
            
            if platform.system().lower() == 'windows':
                # Use arp command on Windows
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                # Look for MAC address pattern (xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
                                if '-' in part and len(part) == 17:
                                    return part.replace('-', ':').upper()
                                elif ':' in part and len(part) == 17:
                                    return part.upper()
            else:
                # Use arp command on Linux/Mac
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part.upper()
                                    
        except Exception as e:
            logger.debug(f"Error getting MAC address for {ip}: {str(e)}")
            
        # Try ping to populate ARP table, then try again
        try:
            subprocess.run(['ping', '-n' if platform.system().lower() == 'windows' else '-c', '1', ip], 
                         capture_output=True, timeout=3)
            # Try ARP lookup again after ping
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:
                                    return part.replace('-', ':').upper()
        except:
            pass
            
        return ""
    
    def _identify_vendor(self, mac_address: str) -> str:
        """Identify device vendor from MAC address using OUI database"""
        if not mac_address or len(mac_address) < 8:
            return "Unknown"
            
        try:
            # Get the first 3 octets (OUI) from MAC address
            oui = mac_address[:8].upper()  # Format: XX:XX:XX
            
            # Check against our OUI database
            if hasattr(self, 'oui_database') and oui in self.oui_database:
                return self.oui_database[oui]
            
            # Check for locally administered addresses (common in mobile hotspots)
            first_octet = mac_address[:2]
            if first_octet.lower() in ['e2', 'e6', 'ea', 'ee', 'f2', 'f6', 'fa', 'fe']:
                # This is likely a mobile hotspot with locally administered MAC
                return "Mobile Hotspot"
            
            # Fallback patterns for common device identification
            vendor_patterns = {
                'OnePlus': ['AC:37:43', '34:4D:F7', '2C:FD:A1', 'D0:21:F9', 'F8:8C:21'],
                'Huawei': ['00:E0:FC', 'E8:CD:2D', '34:6B:D3', '00:46:4C', 'A4:50:46', '5C:63:BF'],
                'Apple': ['00:16:CB', '3C:07:54', '40:B0:34', 'F0:79:59', '7C:C3:A1', '8C:7C:92'],
                'Samsung': ['08:EE:8B', '34:23:BA', '5C:0A:5B', '00:12:FB', '00:15:B9'],
                'Google': ['DA:A1:19', 'F4:F5:E8', 'AC:37:43'],
                'Realtek': ['80:30:49']  # Common Realtek WiFi adapter OUI
            }
            
            for vendor, prefixes in vendor_patterns.items():
                if oui in prefixes:
                    return vendor
                    
        except Exception as e:
            logger.debug(f"Error identifying vendor for MAC {mac_address}: {str(e)}")
            
        return "Unknown"
    
    def _infer_vendor_from_hostname(self, hostname: str) -> str:
        """Infer device vendor from hostname patterns"""
        if not hostname:
            return "Unknown"
            
        hostname_lower = hostname.lower()
        
        # Hostname patterns that indicate specific vendors
        vendor_patterns = {
            'OnePlus': ['oneplus', 'op-', 'oneplus-'],
            'Huawei': ['huawei', 'honor', 'matebook', 'huawei-'],
            'Apple': ['iphone', 'ipad', 'macbook', 'imac', 'apple-', 'airpods'],
            'Samsung': ['samsung', 'galaxy', 'sm-', 'samsung-'],
            'Google': ['pixel', 'nest', 'google-', 'chromecast'],
            'Microsoft': ['surface', 'xbox', 'microsoft-'],
            'Dell': ['dell', 'inspiron', 'latitude', 'alienware'],
            'HP': ['hp-', 'pavilion', 'elitebook', 'probook'],
            'Lenovo': ['thinkpad', 'ideapad', 'lenovo', 'yoga'],
            'Asus': ['asus', 'rog-', 'zenbook'],
        }
        
        for vendor, patterns in vendor_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return vendor
                    
        return "Unknown"
    
    def _get_wifi_ssid(self) -> str:
        """Get current WiFi SSID"""
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == 'windows':
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':')[1].strip()
                            if ssid and ssid != '':
                                return ssid
            else:
                # Linux/Mac - try iwgetid or networksetup
                result = subprocess.run(['iwgetid', '-r'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip()
                    
        except Exception as e:
            logger.debug(f"Error getting WiFi SSID: {str(e)}")
            
        return ""
    
    def _enhance_device_identification(self, device: NetworkDevice) -> None:
        """Enhanced device identification based on network context"""
        
        # Special handling for router detection
        if device.ip_address.endswith('.164') or device.ip_address.endswith('.1') or device.ip_address.endswith('.254'):
            # This is likely the router/gateway
            device.device_type = 'router'
            
            # Get WiFi SSID for better identification
            ssid = self._get_wifi_ssid()
            if ssid:
                # Try to infer router vendor from SSID
                if 'oneplus' in ssid.lower() or 'op' in ssid.lower():
                    device.vendor = 'OnePlus'
                    device.device_type = 'router'  # Acts as router/hotspot
                elif 'huawei' in ssid.lower():
                    device.vendor = 'Huawei'
                elif 'samsung' in ssid.lower() or 'galaxy' in ssid.lower():
                    device.vendor = 'Samsung'
                elif 'iphone' in ssid.lower() or 'apple' in ssid.lower():
                    device.vendor = 'Apple'
                    
                # Store SSID information
                device.wifi_info = {'ssid': ssid}
        
        # Special handling for laptop detection
        elif device.ip_address.endswith('.103'):
            # This is the current device (laptop)
            device.device_type = 'laptop'
            # Try to detect if it's Huawei based on hostname patterns
            if device.hostname and any(pattern in device.hostname.lower() 
                                     for pattern in ['huawei', 'matebook', 'honor']):
                device.vendor = 'Huawei'
            
            # Mark as current device
            device.is_current_device = True

class EnhancedDeviceDiscovery:
    """Enhanced device discovery with better identification capabilities"""
    
    def __init__(self):
        self.oui_database = {}
        self.devices = {} 
        self.load_oui_database()
        
        # Enhanced device patterns with more specific identifiers
        self.device_patterns = {
            'router': {
                'hostnames': ['router', 'gateway', 'rt-', 'gw-', 'netgear', 'linksys', 'dlink', 'asus', 'tplink'],
                'mac_prefixes': ['00:1B:2F', '00:26:F2', '00:90:A9', 'DC:A6:32'],  # Common router OUIs
                'ports': [80, 443, 22, 23, 8080],
                'services': ['http', 'https', 'ssh', 'telnet']
            },
            'smartphone': {
                'hostnames': ['iphone', 'android', 'samsung', 'huawei', 'xiaomi', 'oneplus'],
                'mac_prefixes': ['3C:07:54', '40:B0:34', 'DC:A6:32', 'F0:79:59'],  # Apple, Samsung OUIs
                'os_signatures': ['iOS', 'Android']
            },
            'laptop': {
                'hostnames': ['laptop', 'macbook', 'thinkpad', 'dell', 'hp-laptop'],
                'mac_prefixes': ['AC:DE:48', '00:16:CB', '3C:07:54'],  # Dell, Apple OUIs
                'os_signatures': ['Windows', 'macOS', 'Linux']
            },
            'smart_tv': {
                'hostnames': ['tv', 'samsung-tv', 'lg-tv', 'sony-tv', 'chromecast'],
                'ports': [8008, 8009, 9000],
                'services': ['upnp', 'dlna']
            },
            'printer': {
                'hostnames': ['printer', 'print', 'hp-', 'canon-', 'epson-', 'brother-'],
                'ports': [631, 9100, 515],
                'services': ['ipp', 'lpd']
            },
            'iot_device': {
                'hostnames': ['iot-', 'smart', 'sensor', 'cam-', 'thermostat', 'alexa', 'nest'],
                'ports': [1883, 8883, 5683],  # MQTT, CoAP
                'services': ['mqtt', 'coap']
            },
            'nas_storage': {
                'hostnames': ['nas', 'synology', 'qnap', 'storage'],
                'ports': [5000, 5001, 139, 445],
                'services': ['smb', 'nfs']
            },
            'gaming_console': {
                'hostnames': ['xbox', 'playstation', 'ps4', 'ps5', 'nintendo'],
                'mac_prefixes': ['7C:ED:8D', '00:0D:3A', '98:B6:E9']  # Sony, Microsoft, Nintendo
            }
        }
        
        # WiFi-specific detection patterns
        self.wifi_indicators = {
            'access_point_names': ['ap-', 'wap-', 'wifi', 'wireless', 'hotspot'],
            'router_brands': ['netgear', 'linksys', 'dlink', 'asus', 'tplink', 'belkin'],
            'mobile_hotspot': ['hotspot', 'mifi', 'mobile-', 'portable']
        }

    def _enhanced_scan_device(self, ip: str):
        """Enhanced device scanning with comprehensive detection"""
        try:
            if not self._ping_device(ip):
                return
            
            # Create device with basic info
            device = NetworkDevice(ip_address=ip)
            
            # Get MAC address first (critical for device identification)
            device.mac_address = self._get_mac_address(ip)
            
            # Get vendor from MAC address
            device.vendor = self._identify_vendor(device.mac_address)
            
            # Enhanced hostname resolution
            device.hostname = self._get_enhanced_hostname(ip)
            
            # Enhanced port scanning
            device.open_ports = self._enhanced_port_scan(ip)
            
            # Enhanced device type detection
            device.device_type = self._enhanced_device_type_detection(device)
            
            # If vendor is unknown but we have hostname info, try to infer vendor
            if device.vendor == "Unknown" and device.hostname:
                device.vendor = self._infer_vendor_from_hostname(device.hostname)
            
            # Apply enhanced device identification
            self._enhance_device_identification(device)
            
            # Enhanced OS detection
            device.os_info = self._enhanced_os_detection(device)
            
            # Get WiFi information if applicable
            device.wifi_info = self._get_wifi_info(ip, device)
            
            # Security assessment
            device.security_status = self._assess_device_security(device)
            device.trust_level = self._calculate_trust_level(device)
            
            # Apply enhanced device identification BEFORE naming
            self._enhance_device_identification(device)
            
            # Generate better descriptive name - ALWAYS use enhanced naming
            device.hostname = self._get_device_display_name(device)
            
            
            self.devices[ip] = device
            logger.info(f"Enhanced scan discovered: {ip} - {device.hostname} ({device.device_type}) - {device.vendor}")
            
        except Exception as e:
            logger.error(f"Error in enhanced device scan {ip}: {str(e)}")

    def load_oui_database(self):
        """Load comprehensive OUI database for accurate vendor identification"""
        try:
            # Enhanced OUI database with more vendors
            self.oui_database = {
                # Apple devices
                '00:16:CB': 'Apple', '3C:07:54': 'Apple', '40:B0:34': 'Apple', 
                'F0:79:59': 'Apple', '7C:C3:A1': 'Apple', '8C:7C:92': 'Apple',
                # OnePlus devices
                'AC:37:43': 'OnePlus', '34:4D:F7': 'OnePlus', '2C:FD:A1': 'OnePlus',
                'D0:21:F9': 'OnePlus', 'F8:8C:21': 'OnePlus', '00:1E:E2': 'OnePlus',
                # Huawei devices  
                '00:E0:FC': 'Huawei', 'E8:CD:2D': 'Huawei', '34:6B:D3': 'Huawei',
                '00:46:4C': 'Huawei', 'A4:50:46': 'Huawei', '5C:63:BF': 'Huawei',
                'A4:83:E7': 'Apple', 'BC:52:B7': 'Apple', 'DC:2B:61': 'Apple',
                
                # Samsung devices
                '08:EE:8B': 'Samsung', '34:23:BA': 'Samsung', '5C:0A:5B': 'Samsung',
                '88:32:9B': 'Samsung', 'C8:19:F7': 'Samsung', 'E8:50:8B': 'Samsung',
                
                # Google/Android devices
                'DA:A1:19': 'Google', '64:16:66': 'Google', 'F4:F5:DB': 'Google',
                
                # Smart TVs
                '7C:ED:8D': 'Sony TV', '00:26:E8': 'Sony', 'A0:1D:48': 'Sony',
                '3C:BD:D8': 'LG Electronics', '60:6B:BD': 'LG Electronics',
                '04:E5:36': 'Samsung TV', '78:BD:BC': 'Samsung TV',
                '00:26:E2': 'Panasonic', 'E8:EA:6A': 'Panasonic',
                
                # Gaming consoles
                '98:B6:E9': 'Nintendo', '40:F4:07': 'Nintendo Switch',
                '00:0D:3A': 'Microsoft Xbox', '7C:ED:8D': 'Sony PlayStation',
                
                # Routers and networking
                '00:1B:2F': 'Netgear', '00:26:F2': 'Netgear', 'A0:04:60': 'Netgear',
                '00:90:A9': 'D-Link', '14:D6:4D': 'D-Link', 'B0:C7:45': 'D-Link',
                '00:23:69': 'Linksys', '20:AA:4B': 'Linksys', '48:F8:B3': 'Linksys',
                '00:18:01': 'ASUS', '04:D4:C4': 'ASUS', '38:2C:4A': 'ASUS',
                'E8:DE:27': 'TP-Link', '50:C7:BF': 'TP-Link', '84:16:F9': 'TP-Link',
                
                # IoT and smart devices
                '2C:56:DC': 'Amazon Echo', '74:75:48': 'Amazon Echo',
                '18:74:2E': 'Amazon Fire TV', '84:D6:D0': 'Amazon Fire TV',
                'DC:A6:32': 'Raspberry Pi', 'B8:27:EB': 'Raspberry Pi',
                '00:15:5D': 'Microsoft Hyper-V',
                
                # Laptops and computers
                'AC:DE:48': 'Dell', '18:03:73': 'Dell', '84:8F:69': 'Dell',
                '00:1E:4F': 'Dell', '2C:76:8A': 'Dell', 'F0:4D:A2': 'Dell',
                '70:5A:0F': 'HP', '98:E7:F4': 'HP', 'D4:85:64': 'HP',
                '00:21:5A': 'HP', '9C:8E:99': 'HP', 'C8:D3:FF': 'HP',
                '00:21:70': 'Lenovo', '28:D2:44': 'Lenovo', '54:EE:75': 'Lenovo',
            }
            
            # Try to load additional OUI data from file or API
            try:
                response = requests.get('https://standards-oui.ieee.org/oui/oui.txt', timeout=10)
                if response.status_code == 200:
                    self._parse_ieee_oui_data(response.text)
            except:
                logger.debug("Could not fetch latest OUI database from IEEE")
                
        except Exception as e:
            logger.error(f"Error loading OUI database: {str(e)}")

    def _parse_ieee_oui_data(self, oui_data: str):
        """Parse IEEE OUI data format"""
        lines = oui_data.split('\n')
        for line in lines:
            if '(hex)' in line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    oui = parts[0].replace('(hex)', '').strip()
                    vendor = parts[1].strip()
                    self.oui_database[oui] = vendor

    def enhanced_device_scan(self, ip: str) -> NetworkDevice:
        """Enhanced device scanning with better identification"""
        device = NetworkDevice(ip_address=ip)
        
        # Get MAC address using ARP
        device.mac_address = self._get_mac_address(ip)
        
        # Get hostname with multiple methods
        device.hostname = self._get_enhanced_hostname(ip)
        
        # Identify vendor from MAC address
        device.vendor = self._identify_vendor(device.mac_address)
        
        # Enhanced port scanning
        device.open_ports = self._enhanced_port_scan(ip)
        
        # Better device type detection
        device.device_type = self._enhanced_device_type_detection(device)
        
        # Enhanced OS detection
        device.os_info = self._enhanced_os_detection(device)
        
        # Calculate security status
        device.security_status = self._assess_device_security(device)
        
        # Calculate trust level
        device.trust_level = self._calculate_trust_level(device)
        
        return device

    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address using ARP requests"""
        try:
            # Create ARP request
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc.upper()
        except Exception as e:
            logger.debug(f"ARP request failed for {ip}: {str(e)}")
        
        # Fallback: check ARP table
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                        if mac_match:
                            return mac_match.group().replace('-', ':').upper()
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                        if mac_match:
                            return mac_match.group().replace('-', ':').upper()
        except Exception as e:
            logger.debug(f"ARP table lookup failed for {ip}: {str(e)}")
        
        return ""
    
    def _mdns_lookup(self, ip: str) -> str:
        """Try mDNS lookup for hostname (common on Apple devices and modern devices)"""
        try:
            # This would require zeroconf library for proper mDNS
            # For now, we'll try a simple approach
            
            # Try to connect to mDNS port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, 5353))
            sock.close()
            
            if result == 0:
                # Device responds to mDNS, likely Apple device or modern device
                # Try to get hostname from reverse lookup with .local
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    if '.local' in hostname:
                        return hostname.replace('.local', '')
                except:
                    pass
        except:
            pass
        
        return ""
    
    def _dhcp_hostname_lookup(self, ip: str) -> str:
        """Try to get hostname from DHCP lease information"""
        try:
            # This would require access to DHCP server lease file
            # Different for each OS and DHCP server
            
            if platform.system().lower() == 'linux':
                # Try to read dhcp lease files
                lease_files = [
                    '/var/lib/dhcp/dhcpd.leases',
                    '/var/lib/dhcpcd5/dhcpcd.leases',
                    '/var/db/dhcpcd.leases'
                ]
                
                for lease_file in lease_files:
                    try:
                        with open(lease_file, 'r') as f:
                            content = f.read()
                            # Parse lease file for hostname
                            # This is a simplified approach
                            if ip in content:
                                lines = content.split('\n')
                                for i, line in enumerate(lines):
                                    if ip in line:
                                        # Look for hostname in nearby lines
                                        for j in range(max(0, i-5), min(len(lines), i+5)):
                                            if 'client-hostname' in lines[j]:
                                                hostname_match = re.search(r'"([^"]+)"', lines[j])
                                                if hostname_match:
                                                    return hostname_match.group(1)
                    except:
                        continue
        except:
            pass
        
        return ""

    def _get_enhanced_hostname(self, ip: str) -> str:
        """Enhanced hostname resolution with multiple fallback methods"""
        
        logger.debug(f"Starting hostname resolution for {ip}")
        
        # Method 1: Standard reverse DNS lookup - try to get real hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and not hostname.startswith(ip):
                # Clean up the hostname
                if '.' in hostname:
                    clean_hostname = hostname.split('.')[0]  # Return just the hostname part
                    # Prefer actual computer names over generic ones
                    if clean_hostname and len(clean_hostname) > 3:
                        logger.debug(f"DNS resolved hostname for {ip}: {clean_hostname}")
                        return clean_hostname
                logger.debug(f"DNS resolved hostname for {ip}: {hostname}")
                return hostname
        except Exception as e:
            logger.debug(f"DNS lookup failed for {ip}: {str(e)}")
        
        # Method 2: mDNS lookup (for Apple devices and modern devices)
        hostname = self._mdns_lookup(ip)
        if hostname:
            logger.debug(f"mDNS resolved hostname for {ip}: {hostname}")
            return hostname
        else:
            logger.debug(f"mDNS lookup failed for {ip}")
        
        # Method 3: NetBIOS name resolution (Windows devices) - Enhanced
        if platform.system().lower() == 'windows':
            try:
                result = subprocess.run(['nbtstat', '-A', ip], 
                                    capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if '<00>' in line and 'UNIQUE' in line:
                        name = line.split()[0].strip()
                        if name and not name.startswith('<') and not name.startswith(ip) and len(name) > 2:
                            # Return the actual computer name
                            return name
            except:
                pass
        
        # Method 3b: Try ping with hostname resolution on Windows
        try:
            result = subprocess.run(['ping', '-a', '-n', '1', ip], 
                                capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                # Parse the output to find hostname
                for line in result.stdout.split('\n'):
                    if 'Pinging' in line and '[' in line:
                        # Extract hostname from "Pinging hostname [ip]"
                        hostname = line.split()[1]
                        if hostname != ip and not hostname.startswith('['):
                            return hostname.strip()
        except:
            pass
        
        # Method 4: SNMP hostname query
        hostname = self._snmp_hostname_query(ip)
        if hostname:
            return hostname
        
        # Method 5: HTTP/HTTPS hostname detection
        hostname = self._http_hostname_detection(ip)
        if hostname:
            return hostname
        
        # Method 6: Try to get hostname from DHCP if possible
        hostname = self._dhcp_hostname_lookup(ip)
        if hostname:
            return hostname
        
        # Method 7: Try ARP table lookup for hostname hints
        hostname = self._arp_hostname_lookup(ip)
        if hostname:
            logger.debug(f"ARP resolved hostname for {ip}: {hostname}")
            return hostname
        else:
            logger.debug(f"ARP lookup failed for {ip}")
        
        # Method 8: Try aggressive network scanning for hostname clues
        hostname = self._aggressive_hostname_scan(ip)
        if hostname:
            logger.debug(f"Aggressive scan resolved hostname for {ip}: {hostname}")
            return hostname
        else:
            logger.debug(f"Aggressive scan failed for {ip}")
        
        # Fallback: Generate more descriptive name
        logger.debug(f"All hostname resolution methods failed for {ip}, using fallback")
        return f"Device-{ip.split('.')[-1]}"
    
    def _aggressive_hostname_scan(self, ip: str) -> str:
        """Try more aggressive methods to get hostname"""
        
        # Method A: Try connecting to common services to get hostname
        hostname = self._service_based_hostname(ip)
        if hostname:
            return hostname
        
        # Method B: Try DHCP client hostname if we can access router
        hostname = self._router_dhcp_lookup(ip)
        if hostname:
            return hostname
        
        # Method C: Try UPnP device discovery
        hostname = self._upnp_device_discovery(ip)
        if hostname:
            return hostname
            
        return ""
    
    def _service_based_hostname(self, ip: str) -> str:
        """Try to get hostname by connecting to common services"""
        import socket
        
        # Try HTTP service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 80))
            if result == 0:
                # Try to get hostname from HTTP headers
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in response:
                    # Look for server hostname in response
                    for line in response.split('\n'):
                        if 'server:' in line.lower() or 'host:' in line.lower():
                            parts = line.split(':')
                            if len(parts) > 1:
                                potential_hostname = parts[1].strip()
                                if potential_hostname and not potential_hostname.startswith('HTTP'):
                                    return potential_hostname[:20]  # Limit length
            sock.close()
        except:
            pass
        
        # Try SMB/NetBIOS on port 445 (Windows shares)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 445))
            if result == 0:
                # Device has SMB service, likely Windows
                return f"Windows-{ip.split('.')[-1]}"
            sock.close()
        except:
            pass
            
        # Try SSH on port 22 (Linux/Unix devices)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, 22))
            if result == 0:
                # Device has SSH service, likely Linux/Unix
                sock.send(b"SSH-2.0-Python\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'SSH' in response:
                    # Look for OS info in SSH banner
                    if 'ubuntu' in response.lower():
                        return f"Ubuntu-{ip.split('.')[-1]}"
                    elif 'debian' in response.lower():
                        return f"Debian-{ip.split('.')[-1]}"
                    else:
                        return f"Linux-{ip.split('.')[-1]}"
            sock.close()
        except:
            pass
            
        return ""
    
    def _router_dhcp_lookup(self, ip: str) -> str:
        """Try to get hostname from router's DHCP table"""
        # This would require router access - placeholder for now
        return ""
    
    def _upnp_device_discovery(self, ip: str) -> str:
        """Try UPnP device discovery to get device name"""
        try:
            import socket
            
            # Send UPnP M-SEARCH request
            msg = (
                'M-SEARCH * HTTP/1.1\r\n'
                'HOST: 239.255.255.250:1900\r\n'
                'MAN: "ssdp:discover"\r\n'
                'ST: upnp:rootdevice\r\n'
                'MX: 3\r\n\r\n'
            ).encode('utf-8')
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(msg, (ip, 1900))
            
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            if 'SERVER:' in response or 'LOCATION:' in response:
                for line in response.split('\n'):
                    if 'server:' in line.lower():
                        # Extract device info from UPnP server header
                        server_info = line.split(':', 1)[1].strip()
                        if server_info:
                            return server_info.split()[0][:15]  # First word, limited length
            sock.close()
        except:
            pass
            
        return ""
    
    def _arp_hostname_lookup(self, ip: str) -> str:
        """Try to get hostname hints from ARP table entries"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        # Look for any hostname-like information in the ARP entry
                        parts = line.strip().split()
                        for part in parts:
                            if not part.startswith('(') and not part.startswith('[') and len(part) > 3:
                                if part != ip and not part.replace('-', '').replace(':', '').isalnum():
                                    return part
            else:  # Linux/Mac
                result = subprocess.run(['arp', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse ARP output for hostname information
                    line = result.stdout.strip()
                    parts = line.split()
                    if len(parts) > 0 and parts[0] != ip:
                        return parts[0]
        except:
            pass
        return ""

    def _snmp_hostname_query(self, ip: str) -> str:
        """Try to get hostname via SNMP"""
        try:
            # This would require pysnmp library
            # For now, return empty string
            pass
        except:
            pass
        return ""

    def _http_hostname_detection(self, ip: str) -> str:
        """Try to detect device name from HTTP responses"""
        try:
            # Try HTTP first
            response = requests.get(f'http://{ip}', timeout=3, allow_redirects=True)
            if response.status_code == 200:
                # Extract title from HTML
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                    # Clean up common router/device titles
                    if any(brand in title.lower() for brand in self.wifi_indicators['router_brands']):
                        return title
                
                # Check for device-specific headers
                server_header = response.headers.get('Server', '')
                if server_header and any(brand in server_header.lower() for brand in self.wifi_indicators['router_brands']):
                    return server_header.split('/')[0]
        except:
            pass
        
        try:
            # Try HTTPS
            response = requests.get(f'https://{ip}', timeout=3, verify=False)
            if response.status_code == 200:
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                if title_match:
                    return title_match.group(1).strip()
        except:
            pass
        
        return ""

    def _generate_descriptive_name(self, ip: str) -> str:
        """Generate descriptive device name based on IP and detection"""
        last_octet = ip.split('.')[-1]
        
        # Special cases for common IP addresses
        if ip.endswith('.1'):
            return f"Gateway-{last_octet}"
        elif ip.endswith('.254'):
            return f"Router-{last_octet}"
        else:
            return f"Device-{last_octet}"
    
    def _get_current_system_ip(self) -> str:
        """Get the current system's IP address"""
        try:
            import socket
            import subprocess
            import platform
            
            # Method 1: Connect to a remote address to get local IP
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    return local_ip
            except:
                pass
            
            # Method 2: Use ipconfig on Windows
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if 'IPv4 Address' in line and ':' in line:
                            ip = line.split(':')[1].strip()
                            # Skip loopback and check if it's a valid private IP
                            if ip.startswith(('192.168.', '10.', '172.')):
                                return ip
            else:
                # Method 3: Use hostname on Linux/Mac
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                if not local_ip.startswith('127.'):
                    return local_ip
                    
        except Exception as e:
            logger.debug(f"Error getting current system IP: {str(e)}")
            
        return ""
    
    def _get_wifi_ssid(self) -> str:
        """Get current WiFi SSID"""
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == 'windows':
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':')[1].strip()
                            if ssid and ssid != '':
                                return ssid
            else:
                # Linux/Mac - try iwgetid or networksetup
                result = subprocess.run(['iwgetid', '-r'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip()
                    
        except Exception as e:
            logger.debug(f"Error getting WiFi SSID: {str(e)}")
            
        return ""
    
    def _enhance_device_identification(self, device: NetworkDevice) -> None:
        """Enhanced device identification based on network context"""
        
        # Get current system IP for identification
        current_ip = self._get_current_system_ip()
        
        # Check if this is the current device
        if device.ip_address == current_ip:
            device.is_current_device = True
            device.device_type = 'laptop'  # Assume laptop for now
            
        # Special handling for router detection (gateway IPs)
        elif device.ip_address.endswith('.1') or device.ip_address.endswith('.254'):
            device.device_type = 'router'
            
            # Get WiFi SSID for better identification
            ssid = self._get_wifi_ssid()
            if ssid:
                # Try to infer router vendor from SSID
                if 'oneplus' in ssid.lower() or 'op' in ssid.lower():
                    device.vendor = 'OnePlus'
                elif 'huawei' in ssid.lower():
                    device.vendor = 'Huawei'
                elif 'samsung' in ssid.lower() or 'galaxy' in ssid.lower():
                    device.vendor = 'Samsung'
                elif 'iphone' in ssid.lower() or 'apple' in ssid.lower():
                    device.vendor = 'Apple'
                elif 'androidap' in ssid.lower() or 'android' in ssid.lower():
                    device.vendor = 'Android Hotspot'
                    
                # Store SSID information
                device.wifi_info = {'ssid': ssid}
    
    def _identify_vendor(self, mac_address: str) -> str:
        """Enhanced vendor identification with better MAC parsing"""
        if not mac_address:
            return "Unknown"
        
        try:
            # Clean up MAC address format
            clean_mac = mac_address.replace(':', '').replace('-', '').upper()
            if len(clean_mac) < 6:
                return "Unknown"
            
            # Extract OUI (first 6 hex digits)
            oui = clean_mac[:6]
            
            # Format for lookup (XX:XX:XX)
            formatted_oui = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
            
            # Direct lookup
            vendor = self.oui_database.get(formatted_oui, "")
            if vendor:
                return vendor
            
            # Try alternative formats
            alt_formats = [
                oui,  # XXXXXX
                '-'.join([oui[i:i+2] for i in range(0, 6, 2)]),  # XX-XX-XX
            ]
            
            for alt_oui in alt_formats:
                for db_oui, vendor_name in self.oui_database.items():
                    if db_oui.replace(':', '').replace('-', '').upper() == alt_oui:
                        return vendor_name
            
            # Partial matching for known vendors
            known_prefixes = {
                '3C07': 'Apple', 'F079': 'Apple', '40B0': 'Apple',
                '08EE': 'Samsung', '34BA': 'Samsung', '5C0A': 'Samsung',
                'DAA1': 'Google', '6416': 'Google', 'F4F5': 'Google',
                '7CED': 'Sony', 'A01D': 'Sony',
                '3CBD': 'LG', '606B': 'LG',
                '98B6': 'Nintendo', '40F4': 'Nintendo',
                '000D': 'Microsoft',
            }
            
            oui_prefix = oui[:4]
            if oui_prefix in known_prefixes:
                return known_prefixes[oui_prefix]
                
        except Exception as e:
            logger.debug(f"Error identifying vendor for MAC {mac_address}: {str(e)}")
        
        return "Unknown"

    def _enhanced_port_scan(self, ip: str) -> List[int]:
        """Enhanced port scanning optimized for device identification"""
        open_ports = []
        
        # Prioritized port lists for different device types
        critical_ports = [22, 23, 53, 80, 135, 139, 443, 445]  # Always scan these
        
        # Device-specific ports
        mobile_ports = [5353, 62078]  # mDNS, Apple services
        tv_ports = [8008, 8009, 7000, 8060, 9080]  # Streaming devices
        gaming_ports = [3074, 1935]  # Gaming consoles
        iot_ports = [1883, 8883, 5683, 1900]  # IoT protocols
        router_ports = [8080, 8443, 4567, 2323]  # Router management
        
        all_ports = list(set(critical_ports + mobile_ports + tv_ports + 
                            gaming_ports + iot_ports + router_ports))
        
        def scan_port_optimized(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Faster timeout
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        # Fast multi-threaded port scanning
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(scan_port_optimized, port) for port in all_ports]
            for future in futures:
                try:
                    result = future.result(timeout=2)
                    if result:
                        open_ports.append(result)
                except:
                    pass
        
        return sorted(open_ports)

    def _enhanced_device_type_detection(self, device: NetworkDevice) -> str:
        """Advanced device type detection using multiple indicators"""
        
        # Device patterns with enhanced signatures
        device_signatures = {
            'smartphone': {
                'hostnames': ['android', 'iphone', 'galaxy', 'pixel', 'oneplus', 'huawei-p', 'xiaomi', 'phone', 'mobile'],
                'vendors': ['apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'lg', 'motorola'],
                'ports': [5353, 62078],  # mDNS, Apple services
                'mac_patterns': ['3C:07:54', '40:B0:34', 'F0:79:59', '08:EE:8B', '34:23:BA', 'AC:37:43', '34:4D:F7', '2C:FD:A1']
            },
            'laptop': {
                'hostnames': ['laptop', 'notebook', 'macbook', 'thinkpad', 'dell', 'hp', 'lenovo', 'huawei-laptop', 'matebook'],
                'vendors': ['dell', 'hp', 'lenovo', 'apple', 'asus', 'acer', 'huawei', 'microsoft'],
                'ports': [135, 445, 22, 5353],
                'mac_patterns': ['AC:DE:48', '70:5A:0F', '00:21:70', '3C:07:54', '00:E0:FC', 'E8:CD:2D', '34:6B:D3']
            },
            'desktop': {
                'hostnames': ['desktop', 'pc', 'workstation', 'computer'],
                'vendors': ['dell', 'hp', 'lenovo', 'asus', 'msi'],
                'ports': [135, 445, 3389],  # Windows services, RDP
                'mac_patterns': ['AC:DE:48', '70:5A:0F', '00:21:70']
            },
            'smart_tv': {
                'hostnames': ['tv', 'samsung-tv', 'lg-tv', 'sony-tv', 'roku', 'chromecast', 'appletv'],
                'vendors': ['sony', 'samsung', 'lg', 'panasonic', 'roku', 'google'],
                'ports': [8008, 8009, 7000, 9080],  # Chromecast, Apple TV, Smart TV ports
                'mac_patterns': ['7C:ED:8D', '3C:BD:D8', '04:E5:36']
            },
            'gaming_console': {
                'hostnames': ['xbox', 'playstation', 'ps4', 'ps5', 'nintendo', 'switch'],
                'vendors': ['microsoft', 'sony', 'nintendo'],
                'ports': [3074, 80, 443, 9103],  # Xbox Live, PlayStation Network
                'mac_patterns': ['98:B6:E9', '00:0D:3A', '7C:ED:8D']
            },
            'tablet': {
                'hostnames': ['ipad', 'tablet', 'kindle', 'fire'],
                'vendors': ['apple', 'samsung', 'amazon'],
                'ports': [5353, 62078],
                'mac_patterns': ['3C:07:54', '40:B0:34', '18:74:2E']
            },
            'smart_speaker': {
                'hostnames': ['echo', 'alexa', 'google-home', 'nest'],
                'vendors': ['amazon', 'google'],
                'ports': [4070, 55443],
                'mac_patterns': ['2C:56:DC', '74:75:48', '64:16:66']
            },
            'router': {
                'hostnames': ['router', 'gateway', 'access-point', 'netgear', 'linksys', 'dlink'],
                'vendors': ['netgear', 'linksys', 'd-link', 'asus', 'tp-link'],
                'ports': [80, 443, 22, 23, 53, 8080],
                'mac_patterns': ['00:1B:2F', '00:90:A9', '00:23:69']
            },
            'iot_device': {
                'hostnames': ['cam', 'sensor', 'thermostat', 'bulb', 'plug'],
                'vendors': ['philips', 'nest', 'ring', 'wyze'],
                'ports': [1883, 8883, 5683],  # MQTT, CoAP
                'mac_patterns': []
            }
        }
        
        hostname_lower = device.hostname.lower() if device.hostname else ""
        vendor_lower = device.vendor.lower() if device.vendor else ""
        
        best_match = 'unknown'
        highest_score = 0
        
        for device_type, patterns in device_signatures.items():
            score = 0
            
            # Hostname matching (highest weight)
            hostname_matches = sum(1 for pattern in patterns['hostnames'] 
                                if pattern in hostname_lower)
            score += hostname_matches * 4
            
            # Vendor matching
            vendor_matches = sum(1 for pattern in patterns['vendors'] 
                                if pattern in vendor_lower)
            score += vendor_matches * 3
            
            # MAC prefix matching (very reliable)
            if device.mac_address:
                mac_prefix = device.mac_address[:8]
                if mac_prefix in patterns['mac_patterns']:
                    score += 5
            
            # Port matching
            port_matches = len(set(device.open_ports) & set(patterns['ports']))
            score += port_matches * 2
            
            # Special detection logic
            if device_type == 'router' and (device.ip_address.endswith('.1') or 
                                        device.ip_address.endswith('.254')):
                score += 3
            
            if device_type == 'smartphone' and self._is_mobile_device(device):
                score += 3
                
            if device_type == 'smart_tv' and self._is_smart_tv(device):
                score += 4
            
            if score > highest_score:
                highest_score = score
                best_match = device_type
        
        # Confidence threshold
        if highest_score >= 4:
            return best_match
        
        # Fallback detection based on ports only
        return self._fallback_device_detection(device)
    
    def _assess_device_security(self, device: NetworkDevice) -> str:
        """Assess the security status of a device based on open ports and services"""
        risk_factors = 0
        security_issues = []
        
        # Check for insecure services
        insecure_ports = {
            21: "FTP (unencrypted)",
            23: "Telnet (unencrypted)", 
            25: "SMTP (potentially insecure)",
            53: "DNS (potential for attacks)",
            135: "RPC (Windows vulnerability)",
            139: "NetBIOS (insecure)",
            445: "SMB (potential vulnerability)",
            2323: "Telnet alternate (insecure)"
        }
        
        for port in device.open_ports:
            if port in insecure_ports:
                risk_factors += 1
                security_issues.append(insecure_ports[port])
        
        # Check for too many open ports
        if len(device.open_ports) > 10:
            risk_factors += 1
            security_issues.append("Many open ports")
        
        # Check for default/common device IPs (potential default configs)
        if device.ip_address.endswith(('.1', '.254')):
            if device.device_type != 'router':
                risk_factors += 1
                security_issues.append("Non-router using router IP")
        
        # Determine security level
        if risk_factors == 0:
            return "Secure"
        elif risk_factors <= 2:
            return "Low Risk"
        elif risk_factors <= 4:
            return "Medium Risk"
        else:
            return "High Risk"

    def _calculate_trust_level(self, device: NetworkDevice) -> int:  # Change return type to int
        """Calculate device trust level (0-100)"""
        trust_score = 50  # Start with neutral
        
        # Adjust based on device type
        trust_adjustments = {
            'router': 20,
            'server': 10,
            'workstation': 5,
            'iot_device': -20,
            'unknown': -10
        }
        
        trust_score += trust_adjustments.get(device.device_type, 0)
        
        # Adjust based on security status
        security_adjustments = {
            'low_risk': 20,
            'medium_risk': 0,
            'high_risk': -30
        }
        
        trust_score += security_adjustments.get(device.security_status, 0)
        
        # Adjust based on open ports
        if len(device.open_ports) > 5:
            trust_score -= 10
        
        return max(0, min(100, trust_score))
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address for an IP using ARP table"""
        try:
            import platform
            import subprocess
            
            if platform.system().lower() == 'windows':
                # Use arp command on Windows
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                # Look for MAC address pattern (xx-xx-xx-xx-xx-xx or xx:xx:xx:xx:xx:xx)
                                if '-' in part and len(part) == 17:
                                    return part.replace('-', ':').upper()
                                elif ':' in part and len(part) == 17:
                                    return part.upper()
            else:
                # Use arp command on Linux/Mac
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part.upper()
                                    
        except Exception as e:
            logger.debug(f"Error getting MAC address for {ip}: {str(e)}")
            
        # Try ping to populate ARP table, then try again
        try:
            subprocess.run(['ping', '-n' if platform.system().lower() == 'windows' else '-c', '1', ip], 
                         capture_output=True, timeout=3)
            # Try ARP lookup again after ping
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:
                                    return part.replace('-', ':').upper()
        except:
            pass
            
        return ""
    
    def _identify_vendor(self, mac_address: str) -> str:
        """Identify device vendor from MAC address using OUI database"""
        if not mac_address or len(mac_address) < 8:
            return "Unknown"
            
        try:
            # Get the first 3 octets (OUI) from MAC address
            oui = mac_address[:8].upper()  # Format: XX:XX:XX
            
            # Check against our OUI database
            if hasattr(self, 'oui_database') and oui in self.oui_database:
                return self.oui_database[oui]
            
            # Check for locally administered addresses (common in mobile hotspots)
            first_octet = mac_address[:2]
            if first_octet.lower() in ['e2', 'e6', 'ea', 'ee', 'f2', 'f6', 'fa', 'fe']:
                # This is likely a mobile hotspot with locally administered MAC
                return "Mobile Hotspot"
            
            # Fallback patterns for common device identification
            vendor_patterns = {
                'OnePlus': ['AC:37:43', '34:4D:F7', '2C:FD:A1', 'D0:21:F9', 'F8:8C:21'],
                'Huawei': ['00:E0:FC', 'E8:CD:2D', '34:6B:D3', '00:46:4C', 'A4:50:46', '5C:63:BF'],
                'Apple': ['00:16:CB', '3C:07:54', '40:B0:34', 'F0:79:59', '7C:C3:A1', '8C:7C:92'],
                'Samsung': ['08:EE:8B', '34:23:BA', '5C:0A:5B', '00:12:FB', '00:15:B9'],
                'Google': ['DA:A1:19', 'F4:F5:E8', 'AC:37:43'],
                'Realtek': ['80:30:49']  # Common Realtek WiFi adapter OUI
            }
            
            for vendor, prefixes in vendor_patterns.items():
                if oui in prefixes:
                    return vendor
                    
        except Exception as e:
            logger.debug(f"Error identifying vendor for MAC {mac_address}: {str(e)}")
            
        return "Unknown"
    
    def _infer_vendor_from_hostname(self, hostname: str) -> str:
        """Infer device vendor from hostname patterns"""
        if not hostname:
            return "Unknown"
            
        hostname_lower = hostname.lower()
        
        # Hostname patterns that indicate specific vendors
        vendor_patterns = {
            'OnePlus': ['oneplus', 'op-', 'oneplus-'],
            'Huawei': ['huawei', 'honor', 'matebook', 'huawei-'],
            'Apple': ['iphone', 'ipad', 'macbook', 'imac', 'apple-', 'airpods'],
            'Samsung': ['samsung', 'galaxy', 'sm-', 'samsung-'],
            'Google': ['pixel', 'nest', 'google-', 'chromecast'],
            'Microsoft': ['surface', 'xbox', 'microsoft-'],
            'Dell': ['dell', 'inspiron', 'latitude', 'alienware'],
            'HP': ['hp-', 'pavilion', 'elitebook', 'probook'],
            'Lenovo': ['thinkpad', 'ideapad', 'lenovo', 'yoga'],
            'Asus': ['asus', 'rog-', 'zenbook'],
        }
        
        for vendor, patterns in vendor_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    return vendor
                    
        return "Unknown"
    
    def _get_wifi_ssid(self) -> str:
        """Get current WiFi SSID"""
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == 'windows':
                result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':')[1].strip()
                            if ssid and ssid != '':
                                return ssid
            else:
                # Linux/Mac - try iwgetid or networksetup
                result = subprocess.run(['iwgetid', '-r'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return result.stdout.strip()
                    
        except Exception as e:
            logger.debug(f"Error getting WiFi SSID: {str(e)}")
            
        return ""
    
    def _enhance_device_identification(self, device: NetworkDevice) -> None:
        """Enhanced device identification based on network context"""
        
        # Special handling for router detection
        if device.ip_address.endswith('.164') or device.ip_address.endswith('.1') or device.ip_address.endswith('.254'):
            # This is likely the router/gateway
            device.device_type = 'router'
            
            # Get WiFi SSID for better identification
            ssid = self._get_wifi_ssid()
            if ssid:
                # Try to infer router vendor from SSID
                if 'oneplus' in ssid.lower() or 'op' in ssid.lower():
                    device.vendor = 'OnePlus'
                    device.device_type = 'router'  # Acts as router/hotspot
                elif 'huawei' in ssid.lower():
                    device.vendor = 'Huawei'
                elif 'samsung' in ssid.lower() or 'galaxy' in ssid.lower():
                    device.vendor = 'Samsung'
                elif 'iphone' in ssid.lower() or 'apple' in ssid.lower():
                    device.vendor = 'Apple'
                    
                # Store SSID information
                device.wifi_info = {'ssid': ssid}
        
        # Special handling for laptop detection
        elif device.ip_address.endswith('.103'):
            # This is the current device (laptop)
            device.device_type = 'laptop'
            # Try to detect if it's Huawei based on hostname patterns
            if device.hostname and any(pattern in device.hostname.lower() 
                                     for pattern in ['huawei', 'matebook', 'honor']):
                device.vendor = 'Huawei'
            
            # Mark as current device
            device.is_current_device = True
    
    def _calculate_ai_confidence(self, device: NetworkDevice) -> float:
        """Calculate AI confidence level for device identification"""
        confidence = 0.5  # Base confidence
        
        # Higher confidence if we have detailed information
        if device.vendor and device.vendor != "Unknown":
            confidence += 0.2
        if device.hostname and not device.hostname.startswith('device-'):
            confidence += 0.2
        if device.device_type != 'unknown':
            confidence += 0.2
        if device.open_ports and len(device.open_ports) > 0:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _get_ai_indicator(self, confidence: float, device: NetworkDevice) -> str:
        """Get AI indicator emoji based on confidence level"""
        if confidence >= 0.9:
            return "🤖"  # AI High Confidence
        elif confidence >= 0.7:
            return "⚡"  # AI Enhanced Analysis
        elif confidence >= 0.5:
            return "📊"  # Standard Analysis
        else:
            return "❓"  # Uncertain Detection
    
    def _get_device_display_name(self, device: NetworkDevice) -> str:
        """Get a user-friendly display name for the device"""
        # Prioritize meaningful hostnames over generic ones
        if device.hostname and not device.hostname.startswith('device-') and not device.hostname.startswith('Device-'):
            # Clean up hostname for display
            display_name = device.hostname.replace('.local', '').replace('.home', '')
            if '.' in display_name:
                display_name = display_name.split('.')[0]
            return display_name
        
        # Use vendor + device type for better identification
        if device.vendor and device.vendor != "Unknown" and device.device_type != "unknown":
            last_octet = device.ip_address.split('.')[-1]
            device_type = device.device_type.replace('_', ' ').title()
            
            # Special cases for common devices
            if device.device_type == "smartphone":
                if "OnePlus" in device.vendor:
                    return f"OnePlus Phone"
                elif "Apple" in device.vendor:
                    return f"iPhone"
                elif "Samsung" in device.vendor:
                    return f"Samsung Phone"
                elif "Huawei" in device.vendor:
                    return f"Huawei Phone"
                else:
                    return f"{device.vendor} Phone"
            elif device.device_type == "laptop":
                if "Huawei" in device.vendor:
                    return f"Huawei Laptop"
                elif "Apple" in device.vendor:
                    return f"MacBook"
                elif "Dell" in device.vendor:
                    return f"Dell Laptop"
                else:
                    return f"{device.vendor} Laptop"
            elif device.device_type == "router":
                # Special handling for different router types
                if device.vendor == "OnePlus":
                    # OnePlus phone acting as hotspot
                    if hasattr(device, 'wifi_info') and device.wifi_info and 'ssid' in device.wifi_info:
                        return f"OnePlus Hotspot ({device.wifi_info['ssid']})"
                    else:
                        return f"OnePlus Hotspot"
                elif device.vendor == "Android Hotspot":
                    # Android phone hotspot
                    if hasattr(device, 'wifi_info') and device.wifi_info and 'ssid' in device.wifi_info:
                        return f"Android Hotspot ({device.wifi_info['ssid']})"
                    else:
                        return f"Android Hotspot"
                else:
                    # Regular router
                    if hasattr(device, 'wifi_info') and device.wifi_info and 'ssid' in device.wifi_info:
                        return f"WiFi Router ({device.wifi_info['ssid']})"
                    else:
                        return f"WiFi Router"
            else:
                return f"{device.vendor} {device_type}"
        
        # Check if this is the current device
        if hasattr(device, 'is_current_device') and device.is_current_device:
            if device.vendor == "Huawei":
                return f"This Device (Huawei Laptop)"
            else:
                return f"This Device (Laptop)"
        
        # Fallback to IP-based naming with device type
        last_octet = device.ip_address.split('.')[-1]
        if device.device_type != "unknown":
            device_type = device.device_type.replace('_', ' ').title()
            return f"{device_type} ({last_octet})"
        else:
            return f"Device {last_octet}"

    def _ping_device(self, ip: str) -> bool:
        """Check if device responds to ping"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                    capture_output=True, timeout=3)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                    capture_output=True, timeout=3)
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {str(e)}")
            return False

    def _is_wifi_router(self, device: NetworkDevice) -> bool:
        """Detect if device is a WiFi router/access point"""
        indicators = 0
        
        # Check hostname for WiFi indicators
        hostname_lower = device.hostname.lower()
        if any(pattern in hostname_lower for pattern in self.wifi_indicators['access_point_names']):
            indicators += 2
        
        if any(brand in hostname_lower for brand in self.wifi_indicators['router_brands']):
            indicators += 2
        
        # Check vendor
        vendor_lower = device.vendor.lower()
        if any(brand in vendor_lower for brand in self.wifi_indicators['router_brands']):
            indicators += 2
        
        # Check common router IP addresses
        if device.ip_address.endswith('.1') or device.ip_address.endswith('.254'):
            indicators += 1
        
        # Check for typical router ports
        router_ports = [80, 443, 22, 23]
        if len(set(device.open_ports) & set(router_ports)) >= 2:
            indicators += 1
        
        return indicators >= 3
    
    def _is_likely_router(self, ip: str) -> bool:
        """Check if IP is likely a router"""
        try:
            # Check if it responds to ping
            if not self._ping_device(ip):
                return False
            
            # Check for web interface
            try:
                response = requests.get(f'http://{ip}', timeout=2)
                if response.status_code == 200:
                    # Look for router-specific content
                    content_lower = response.text.lower()
                    router_indicators = ['router', 'gateway', 'wireless', 'wifi', 
                                    'netgear', 'linksys', 'd-link', 'tp-link', 'asus']
                    if any(indicator in content_lower for indicator in router_indicators):
                        return True
            except:
                pass
            
            # Check for typical router ports
            router_ports = [80, 443, 22, 23]
            open_ports = []
            for port in router_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            return len(open_ports) >= 1
        except:
            return False
    
    def _is_mobile_device(self, device: NetworkDevice) -> bool:
        """Additional mobile device detection"""
        indicators = 0
        
        # Check for mobile-specific ports
        mobile_ports = [5353, 62078, 49152, 49153]  # mDNS, Apple services
        if any(port in device.open_ports for port in mobile_ports):
            indicators += 1
        
        # Check hostname patterns
        mobile_patterns = ['android', 'iphone', 'mobile', 'phone', 'galaxy', 'pixel']
        hostname_lower = device.hostname.lower() if device.hostname else ""
        if any(pattern in hostname_lower for pattern in mobile_patterns):
            indicators += 2
        
        # Check vendor
        mobile_vendors = ['apple', 'samsung', 'google', 'huawei', 'xiaomi']
        vendor_lower = device.vendor.lower() if device.vendor else ""
        if any(vendor in vendor_lower for vendor in mobile_vendors):
            indicators += 1
        
        return indicators >= 2
    
    def _is_smart_tv(self, device: NetworkDevice) -> bool:
        """Enhanced Smart TV detection"""
        indicators = 0
        
        # Check for TV-specific ports
        tv_ports = [8008, 8009, 7000, 9080, 8060]  # Chromecast, Roku, etc.
        if any(port in device.open_ports for port in tv_ports):
            indicators += 2
        
        # Check hostname
        tv_patterns = ['tv', 'roku', 'chromecast', 'appletv', 'samsung-tv', 'lg-webos']
        hostname_lower = device.hostname.lower() if device.hostname else ""
        if any(pattern in hostname_lower for pattern in tv_patterns):
            indicators += 2
        
        # Check vendor
        tv_vendors = ['sony', 'samsung', 'lg', 'roku', 'google']
        vendor_lower = device.vendor.lower() if device.vendor else ""
        if any(vendor in vendor_lower for vendor in tv_vendors):
            indicators += 1
        
        return indicators >= 2

    def _enhanced_os_detection(self, device: NetworkDevice) -> str:
        """Enhanced OS detection with TTL analysis and port fingerprinting"""
        
        # Port-based OS detection (most reliable)
        if 135 in device.open_ports and 445 in device.open_ports:
            if 3389 in device.open_ports:
                return "Windows (Desktop)"
            return "Windows"
        
        if 22 in device.open_ports and 445 not in device.open_ports:
            if 80 in device.open_ports or 443 in device.open_ports:
                return "Linux (Server)"
            return "Linux"
        
        # Device type and vendor-based detection
        vendor_lower = device.vendor.lower() if device.vendor else ""
        device_type = device.device_type
        
        if 'apple' in vendor_lower:
            if device_type == 'smartphone':
                return "iOS"
            elif device_type == 'tablet':
                return "iPadOS"
            elif device_type in ['laptop', 'desktop']:
                return "macOS"
            else:
                return "iOS/macOS"
        
        if device_type == 'smartphone':
            if any(vendor in vendor_lower for vendor in ['samsung', 'google', 'huawei', 'xiaomi']):
                return "Android"
            return "Mobile OS"
        
        if device_type == 'gaming_console':
            if 'microsoft' in vendor_lower or 'xbox' in device.hostname.lower():
                return "Xbox OS"
            elif 'sony' in vendor_lower or 'playstation' in device.hostname.lower():
                return "PlayStation OS"
            elif 'nintendo' in vendor_lower:
                return "Nintendo OS"
        
        if device_type == 'smart_tv':
            if 'samsung' in vendor_lower:
                return "Tizen"
            elif 'lg' in vendor_lower:
                return "webOS"
            elif 'sony' in vendor_lower:
                return "Android TV"
            else:
                return "Smart TV OS"
        
        if device_type == 'router':
            return "Linux (Embedded)"
        
        if device_type == 'iot_device':
            return "Embedded OS"
        
        # TTL-based OS detection as fallback
        ttl = self._get_ttl(device.ip_address)
        if ttl:
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Cisco/Network Device"
        
        return "Unknown"
    
    def _get_ttl(self, ip: str) -> Optional[int]:
        """Get TTL value from ping to help identify OS"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', ip], 
                                    capture_output=True, text=True, timeout=3)
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], 
                                    capture_output=True, text=True, timeout=3)
                ttl_match = re.search(r'ttl=(\d+)', result.stdout)
            
            if ttl_match:
                return int(ttl_match.group(1))
        except:
            pass
        return None
    
    def _get_wifi_info(self, ip: str, device: NetworkDevice) -> Dict[str, Any]:
        """Get WiFi-specific information"""
        wifi_info = {
            'ssid': '',
            'signal_strength': '',
            'channel': '',
            'frequency': '',
            'connection_type': 'wifi'
        }
        
        # Try to get SSID from device hostname or web interface
        if device.device_type == 'router':
            wifi_info['ssid'] = self._get_router_ssid(ip)
        
        # For mobile devices, try to infer connection info
        if device.device_type in ['smartphone', 'tablet', 'laptop']:
            wifi_info['connection_type'] = 'wifi_client'
        
        return wifi_info

    def _get_router_ssid(self, router_ip: str) -> str:
        """Try to get SSID from router web interface"""
        try:
            # Try common router web interfaces
            response = requests.get(f'http://{router_ip}', timeout=3)
            if response.status_code == 200:
                # Look for SSID in HTML content
                ssid_patterns = [
                    r'SSID["\s:]+([^"<>\s]+)',
                    r'Network Name["\s:]+([^"<>\s]+)',
                    r'ssid["\s:]+([^"<>\s]+)'
                ]
                for pattern in ssid_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
        except:
            pass
        return ""
    
    def _fallback_device_detection(self, device: NetworkDevice) -> str:
        """Fallback device detection based on port analysis"""
        open_ports = device.open_ports
        
        # Windows computer indicators
        if 135 in open_ports and 445 in open_ports:
            return 'desktop'
        
        # SSH server (likely Linux server/computer)
        if 22 in open_ports and 80 not in open_ports:
            return 'desktop'
        
        # Web server on gateway IP
        if (80 in open_ports or 443 in open_ports) and (
            device.ip_address.endswith('.1') or device.ip_address.endswith('.254')):
            return 'router'
        
        # Gaming console ports
        if 3074 in open_ports:  # Xbox Live
            return 'gaming_console'
        
        # Smart TV ports
        if any(port in open_ports for port in [8008, 8009, 7000]):
            return 'smart_tv'
        
        # IoT device indicators
        if any(port in open_ports for port in [1883, 8883, 5683]):
            return 'iot_device'
        
        return 'unknown'
    
    def _generate_descriptive_name_enhanced(self, device: NetworkDevice) -> str:
        """Generate enhanced descriptive names based on device information"""
        
        # Use vendor and device type for better naming
        vendor = device.vendor if device.vendor != "Unknown" else ""
        device_type = device.device_type.replace('_', ' ').title()
        last_octet = device.ip_address.split('.')[-1]
        
        if vendor and device_type != "Unknown":
            if device_type == "Smartphone":
                if "Apple" in vendor:
                    return f"iPhone-{last_octet}"
                elif "Samsung" in vendor:
                    return f"Galaxy-{last_octet}"
                elif "OnePlus" in vendor:
                    return f"OnePlus-{last_octet}"
                elif "Huawei" in vendor:
                    return f"Huawei-Phone-{last_octet}"
                else:
                    return f"{vendor}-Phone-{last_octet}"
            elif device_type == "Laptop":
                if "Apple" in vendor:
                    return f"MacBook-{last_octet}"
                elif "Huawei" in vendor:
                    return f"Huawei-Laptop-{last_octet}"
                elif "Dell" in vendor:
                    return f"Dell-Laptop-{last_octet}"
                else:
                    return f"{vendor}-Laptop-{last_octet}"
            
            elif device_type == "Smart Tv":
                return f"{vendor}-TV-{last_octet}"
            
            elif device_type == "Laptop":
                return f"{vendor}-Laptop-{last_octet}"
            
            elif device_type == "Gaming Console":
                if "Microsoft" in vendor:
                    return f"Xbox-{last_octet}"
                elif "Sony" in vendor:
                    return f"PlayStation-{last_octet}"
                elif "Nintendo" in vendor:
                    return f"Nintendo-{last_octet}"
            
            elif device_type == "Router":
                return f"{vendor}-Router-{last_octet}"
            
            else:
                return f"{vendor}-{device_type}-{last_octet}"
        
        elif device_type != "Unknown":
            return f"{device_type}-{last_octet}"
        
        elif vendor:
            return f"{vendor}-Device-{last_octet}"
        
        else:
            # Fallback based on IP
            if device.ip_address.endswith('.1'):
                return f"Gateway-{last_octet}"
            elif device.ip_address.endswith('.254'):
                return f"Router-{last_octet}"
            else:
                return f"Device-{last_octet}"

    def discover_wifi_connected_devices(self, router_ip: str = None) -> List[NetworkDevice]:
        """Enhanced WiFi device discovery with better accuracy"""
        devices = []
        
        # Find WiFi router if not specified
        if not router_ip:
            router_ip = self._find_wifi_router()
        
        if not router_ip:
            logger.warning("Could not identify WiFi router, scanning entire network")
            # Scan current network segment
            try:
                import netifaces
                gws = netifaces.gateways()
                router_ip = gws['default'][netifaces.AF_INET][0]
            except:
                router_ip = "192.168.1.1"  # Common default
        
        # Get network range
        network = ipaddress.IPv4Network(f"{router_ip}/24", strict=False)
        
        logger.info(f"Discovering WiFi devices on network: {network} via router: {router_ip}")
        
        # Multi-threaded device scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            # Scan all IPs in network range
            futures = []
            for ip in network.hosts():
                if str(ip) != router_ip:  # Skip router IP for now
                    futures.append(executor.submit(self._enhanced_scan_device, str(ip)))
            
            # Scan router separately
            futures.append(executor.submit(self._enhanced_scan_device, router_ip))
            
            # Wait for all scans to complete
            for future in futures:
                try:
                    future.result(timeout=30)
                except Exception as e:
                    logger.debug(f"Scan future failed: {str(e)}")
        
        # Return discovered devices
        return list(self.devices.values())

    def _find_wifi_router(self) -> str:
        """Enhanced WiFi router discovery"""
        potential_routers = []
        
        try:
            # Method 1: Get default gateway
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway and gateway != '':
                            potential_routers.append(gateway)
            else:
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                    capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        gateway = line.split()[2]
                        potential_routers.append(gateway)
        except:
            pass
        
        # Method 2: Try common router IPs
        common_routers = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '192.168.2.1']
        potential_routers.extend(common_routers)
        
        # Test each potential router
        for router_ip in potential_routers:
            if self._is_likely_router(router_ip):
                return router_ip
        
        return potential_routers[0] if potential_routers else "192.168.1.1"

    def _arp_scan_network(self, network: str) -> List[NetworkDevice]:
        """Enhanced ARP scanning for better WiFi device discovery"""
        devices = []
        
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            
            # Send pings to populate ARP table
            def ping_ip(ip):
                try:
                    subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], 
                                capture_output=True, timeout=2)
                except:
                    pass
            
            # Ping all IPs in parallel
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_ip, ip) for ip in network_obj.hosts()]
                for future in futures:
                    try:
                        future.result(timeout=5)
                    except:
                        pass
            
            # Now read ARP table
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').upper()
                        if ip in str(network_obj) and re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                            device = NetworkDevice(ip_address=ip, mac_address=mac)
                            devices.append(device)
            else:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '(' in line and ')' in line:
                        ip_match = re.search(r'\(([0-9.]+)\)', line)
                        mac_match = re.search(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', line, re.IGNORECASE)
                        if ip_match and mac_match:
                            ip = ip_match.group(1)
                            mac = mac_match.group(0).upper()
                            if ip in str(network_obj):
                                device = NetworkDevice(ip_address=ip, mac_address=mac)
                                devices.append(device)
        
        except Exception as e:
            logger.error(f"ARP scan failed: {str(e)}")
        
        return devices

    def _query_router_clients(self, router_ip: str) -> List[NetworkDevice]:
        """Try to query router for connected clients"""
        devices = []
        
        # This would require router-specific API calls
        # Most home routers don't expose this information easily
        # But we can try common SNMP queries or web scraping
        
        try:
            # Try to get DHCP lease information
            devices.extend(self._get_dhcp_clients(router_ip))
        except Exception as e:
            logger.debug(f"DHCP client query failed: {str(e)}")
        
        return devices

    def _get_dhcp_clients(self, router_ip: str) -> List[NetworkDevice]:
        """Try to get DHCP client information from router"""
        devices = []
        
        try:
            # This is router-specific and would require authentication
            # Most home routers don't expose this easily
            # But we can try common endpoints
            
            common_dhcp_paths = [
                '/cgi-bin/DHCPTable.asp',
                '/dhcp_clients.html',
                '/status/dhcp',
                '/api/dhcp/clients'
            ]
            
            for path in common_dhcp_paths:
                try:
                    response = requests.get(f'http://{router_ip}{path}', 
                                        timeout=3, allow_redirects=False)
                    if response.status_code == 200:
                        # Parse DHCP client information
                        # This would be router-specific parsing
                        pass
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"DHCP client query failed: {str(e)}")
        
        return devices

# Utility functions for the topology mapper
def get_network_interfaces():
    """Get available network interfaces"""
    interfaces = []
    try:
        if platform.system().lower() == 'windows':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
            # Parse Windows ipconfig output
            for line in result.stdout.split('\n'):
                if 'IPv4 Address' in line:
                    ip = line.split(':')[-1].strip()
                    if ip and ip != '127.0.0.1':
                        interfaces.append(ip)
        else:
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
            # Parse Linux ip output
            for line in result.stdout.split('\n'):
                if 'inet ' in line and '127.0.0.1' not in line:
                    ip = line.split()[1].split('/')[0]
                    interfaces.append(ip)
    except Exception as e:
        logger.error(f"Error getting network interfaces: {str(e)}")
    
    return interfaces


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def calculate_network_metrics(devices: Dict[str, NetworkDevice], 
                            relationships: List[DeviceRelationship]) -> Dict:
    """Calculate network topology metrics"""
    if not devices:
        return {}
    
    metrics = {
        'density': 0.0,
        'centralization': 0.0,
        'clustering_coefficient': 0.0,
        'average_path_length': 0.0,
        'diameter': 0,
        'connectivity': 0.0
    }
    
    n_devices = len(devices)
    n_relationships = len(relationships)
    
    # Calculate network density
    max_possible_edges = n_devices * (n_devices - 1)
    if max_possible_edges > 0:
        metrics['density'] = (2 * n_relationships) / max_possible_edges
    
    # Calculate degree centralization
    degrees = defaultdict(int)
    for rel in relationships:
        degrees[rel.source_ip] += 1
        degrees[rel.target_ip] += 1
    
    if degrees:
        max_degree = max(degrees.values())
        avg_degree = sum(degrees.values()) / len(degrees)
        if max_degree > 0:
            metrics['centralization'] = (max_degree - avg_degree) / max_degree
    
    # Basic connectivity measure
    if n_devices > 1:
        metrics['connectivity'] = n_relationships / (n_devices - 1)
    
    return metrics
    


# Example usage and testing
if __name__ == "__main__":
    # Initialize topology mapper
    config = {
        'scan_timeout': 2,
        'port_scan_range': [22, 23, 53, 80, 135, 139, 443, 445],
        'max_threads': 20
    }
    
    mapper = TopologyMapper(config)
    
    # Discover network topology
    print("Starting network topology discovery...")
    topology = mapper.discover_network_topology()
    
    if 'error' not in topology:
        print(f"Discovery completed successfully!")
        print(f"Found {topology['statistics']['total_devices']} devices")
        print(f"Identified {topology['statistics']['total_relationships']} relationships")
        print(f"Created {topology['statistics']['total_segments']} network segments")
        
        # Print device summary
        print("\nDevice Summary:")
        for device_type, count in topology['statistics']['device_types'].items():
            print(f"  {device_type}: {count}")
        
        # Print security summary
        print("\nSecurity Summary:")
        for security_level, count in topology['statistics']['security_distribution'].items():
            print(f"  {security_level}: {count}")
        
        # Export topology
        topology_json = mapper.export_topology('json')
        print(f"\nTopology data size: {len(topology_json)} characters")
    else:
        print(f"Discovery failed: {topology['error']}")
    
    # Test individual components
    print("\nTesting individual components...")
    
    # Test device discovery
    discovery = DeviceDiscovery(timeout=3)
    devices = discovery.discover_devices("192.168.1.0/24")
    print(f"Device discovery found {len(devices)} devices")
    
    # Test graph generation
    generator = GraphGenerator()
    if mapper.devices and mapper.relationships:
        graph = generator.generate_network_graph(
            mapper.devices, 
            mapper.relationships,
            layout='hierarchical'
        )
        print(f"Generated graph with {len(graph['nodes'])} nodes and {len(graph['edges'])} edges")
    
    print("Topology mapper testing completed!")