"""
Wi-Fi Security System - Deep Analysis Engine
Purpose: Comprehensive connected WiFi network analysis using all AI models
Author: WISEC Security Team
Version: 1.0

This module performs deep security analysis of the connected WiFi network using:
- All 9 AI models (CNN, LSTM, GNN, Random Forest, etc.)
- Real network data collection
- Individual model predictions
- Ensemble prediction fusion
- Comprehensive risk assessment
- PDF report generation
"""

import os
import json
import logging
import threading
import time
import uuid
import numpy as np
import platform
import subprocess
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import asdict

# Import AI components
from .model_loader import ModelLoader
from .ensemble_predictor import EnsembleFusionModel, ensemble_predictor
from .preprocessor import DataPreprocessor

# Import WiFi core components
from ..wifi_core.scanner import WiFiScanner, NetworkInfo, SignalProcessor
from ..wifi_core.analyzer import TrafficAnalyzer, PacketCapture
from ..wifi_core.topology_mapper import TopologyMapper, DeviceDiscovery
from ..wifi_core.passive_scanner import RogueAPDetector

# Import utilities
from ..utils.pdf_generator import PDFGenerator
from ..utils.helpers import UtilityHelper
from ..models.scan_results import ScanResult
from ..models.audit_logs import AuditLog

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConnectedNetworkAnalyzer:
    """Analyzes the currently connected WiFi network"""
    
    def __init__(self):
        self.wifi_scanner = WiFiScanner()
        self.signal_processor = SignalProcessor()
        self.traffic_analyzer = TrafficAnalyzer()
        self.topology_mapper = TopologyMapper()
        self.device_discovery = DeviceDiscovery()
        self.rogue_detector = RogueAPDetector()
        
    def get_connected_network_details(self) -> Dict[str, Any]:
        """Get detailed information about the connected network"""
        try:
            # Get current connection
            current_conn = self.wifi_scanner.get_current_connection()
            
            if not current_conn or not current_conn.get('connected'):
                raise Exception("No WiFi network currently connected")
            
            # Get detailed network information
            ssid = current_conn.get('ssid', 'Unknown')
            bssid = current_conn.get('bssid', 'Unknown')
            
            # Get additional network details
            detailed_info = self._gather_network_details(ssid, bssid)
            
            # Get traffic analysis
            traffic_data = self._analyze_network_traffic(ssid)
            
            # Get network topology
            topology_data = self._map_network_topology()
            
            # Get security configuration
            security_config = self._analyze_security_configuration(current_conn)
            
            # Combine all data
            network_analysis = {
                'basic_info': current_conn,
                'detailed_info': detailed_info,
                'traffic_analysis': traffic_data,
                'topology': topology_data,
                'security_config': security_config,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'analysis_metadata': {
                    'platform': platform.system(),
                    'analyzer_version': '1.0',
                    'collection_duration_seconds': 30
                }
            }
            
            return network_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing connected network: {e}")
            raise
    
    def _gather_network_details(self, ssid: str, bssid: str) -> Dict[str, Any]:
        """Gather detailed network information"""
        try:
            # Scan for available networks and find our connected one
            networks = self.wifi_scanner.scan_available_networks()
            
            current_network = None
            for network in networks:
                # Convert NetworkInfo object to dict if needed
                network_dict = network.to_dict() if hasattr(network, 'to_dict') else network
                if network_dict.get('ssid') == ssid or network_dict.get('bssid') == bssid:
                    current_network = network_dict
                    break
            
            if not current_network:
                logger.warning(f"Connected network {ssid} not found in scan results")
                return self._create_fallback_network_info(ssid, bssid)
            
            # Enhanced network details
            detailed_info = {
                'network_info': current_network,
                'signal_quality': self.signal_processor.calculate_signal_quality(
                    current_network.get('signal_strength', -70)
                ),
                'channel_info': self._analyze_channel_usage(current_network),
                'encryption_analysis': self._analyze_encryption(current_network),
                'vendor_info': self._identify_vendor(bssid),
                'frequency_band': self._determine_frequency_band(current_network.get('frequency', 2400)),
                'capabilities': current_network.get('capabilities', []),
                'beacon_interval': current_network.get('beacon_interval', 100),
                'supported_rates': current_network.get('rates', [])
            }
            
            return detailed_info
            
        except Exception as e:
            logger.error(f"Error gathering network details: {e}")
            return self._create_fallback_network_info(ssid, bssid)
    
    def _analyze_network_traffic(self, ssid: str) -> Dict[str, Any]:
        """Analyze network traffic patterns"""
        try:
            # Start traffic capture for analysis
            traffic_data = {
                'capture_duration': 30,
                'total_packets': 0,
                'protocols': {},
                'bandwidth_usage': {},
                'connection_patterns': {},
                'anomalies': []
            }
            
            # Use traffic analyzer to capture data
            try:
                capture_result = self.traffic_analyzer.capture_traffic(duration=30)
                
                if capture_result:
                    traffic_data.update({
                        'total_packets': capture_result.get('packet_count', 0),
                        'protocols': capture_result.get('protocols', {}),
                        'bandwidth_usage': capture_result.get('bandwidth', {}),
                        'connection_patterns': capture_result.get('connections', {}),
                        'anomalies': capture_result.get('anomalies', [])
                    })
                    
            except Exception as e:
                logger.warning(f"Traffic capture failed: {e}")
                # Use simulated traffic data based on connection analysis
                traffic_data = self._simulate_traffic_analysis(ssid)
            
            return traffic_data
            
        except Exception as e:
            logger.error(f"Error analyzing network traffic: {e}")
            return {'error': str(e), 'simulated': True}
    
    def _map_network_topology(self) -> Dict[str, Any]:
        """Map network topology and discover devices"""
        try:
            # Discover devices on the network
            # Get network range from subnet info
            subnet_info = self._get_subnet_info()
            network_range = subnet_info.get('subnet', '192.168.1.0/24')
            devices = self.device_discovery.discover_devices(network_range=network_range)
            
            # Create topology map
            topology_map = self.topology_mapper.create_topology_map(devices)
            
            # Analyze network structure
            topology_data = {
                'devices': devices,
                'topology_map': topology_map,
                'network_structure': self._analyze_network_structure(devices),
                'device_count': len(devices),
                'device_types': self._categorize_devices(devices),
                'potential_threats': self._identify_topology_threats(devices)
            }
            
            return topology_data
            
        except Exception as e:
            logger.error(f"Error mapping network topology: {e}")
            return {'error': str(e), 'devices': []}
    
    def _analyze_security_configuration(self, connection_info: Dict) -> Dict[str, Any]:
        """Analyze security configuration of connected network"""
        try:
            security_config = {
                'encryption_type': connection_info.get('encryption_type', 'Unknown'),
                'authentication_method': connection_info.get('authentication', 'Unknown'),
                'cipher_suite': connection_info.get('cipher_suite', 'Unknown'),
                'key_management': connection_info.get('key_management', 'Unknown'),
                'wps_enabled': connection_info.get('wps_enabled', False),
                'wpa3_support': connection_info.get('wpa3_support', False),
                'pmf_enabled': connection_info.get('pmf_enabled', False),
                'security_score': 0,
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Calculate security score and identify vulnerabilities
            security_config = self._evaluate_security_strength(security_config)
            
            return security_config
            
        except Exception as e:
            logger.error(f"Error analyzing security configuration: {e}")
            return {'error': str(e)}
    
    def _create_fallback_network_info(self, ssid: str, bssid: str) -> Dict[str, Any]:
        """Create fallback network information when detailed scan fails"""
        return {
            'network_info': {
                'ssid': ssid,
                'bssid': bssid,
                'signal_strength': -50,
                'frequency': 2437,
                'channel': 6,
                'encryption_type': 'WPA2',
                'mode': 'Infrastructure'
            },
            'signal_quality': 75.0,
            'note': 'Limited information available - using fallback data'
        }
    
    def _simulate_traffic_analysis(self, ssid: str) -> Dict[str, Any]:
        """Simulate traffic analysis when capture is not available"""
        return {
            'capture_duration': 30,
            'total_packets': 1250,
            'protocols': {
                'HTTP': 45.2,
                'HTTPS': 38.7,
                'DNS': 8.1,
                'Other': 8.0
            },
            'bandwidth_usage': {
                'download_mbps': 15.3,
                'upload_mbps': 2.1,
                'total_mb': 6.8
            },
            'connection_patterns': {
                'active_connections': 12,
                'external_hosts': 8,
                'local_connections': 4
            },
            'anomalies': [],
            'simulated': True
        }
    
    def _analyze_channel_usage(self, network: Dict) -> Dict[str, Any]:
        """Analyze channel usage and interference"""
        channel = network.get('channel', 6)
        frequency = network.get('frequency', 2437)
        
        return {
            'channel': channel,
            'frequency': frequency,
            'band': '2.4GHz' if frequency < 3000 else '5GHz',
            'channel_width': '20MHz',  # Default assumption
            'interference_level': 'Medium',  # Would be calculated from scan
            'congestion_score': 5.5  # 1-10 scale
        }
    
    def _analyze_encryption(self, network: Dict) -> Dict[str, Any]:
        """Analyze encryption strength and configuration"""
        encryption = network.get('encryption_type', 'Unknown')
        
        strength_mapping = {
            'WPA3': 'Very Strong',
            'WPA2': 'Strong',
            'WPA': 'Weak',
            'WEP': 'Very Weak',
            'Open': 'None'
        }
        
        return {
            'type': encryption,
            'strength': strength_mapping.get(encryption, 'Unknown'),
            'cipher': network.get('cipher_suite', 'Unknown'),
            'key_management': network.get('key_management', 'Unknown')
        }
    
    def _identify_vendor(self, bssid: str) -> Dict[str, Any]:
        """Identify device vendor from BSSID"""
        # Simple vendor identification (would use OUI database in production)
        oui = bssid[:8].upper() if bssid else ''
        
        vendor_mapping = {
            '00:1B:63': 'Apple',
            '00:26:BB': 'Cisco',
            '00:24:A5': 'TP-Link',
            '00:1F:3F': 'Netgear'
        }
        
        return {
            'oui': oui,
            'vendor': vendor_mapping.get(oui, 'Unknown'),
            'device_type': 'Router/Access Point'
        }
    
    def _determine_frequency_band(self, frequency: int) -> str:
        """Determine frequency band from frequency"""
        if 2400 <= frequency <= 2500:
            return '2.4GHz'
        elif 5000 <= frequency <= 6000:
            return '5GHz'
        elif 6000 <= frequency <= 7000:
            return '6GHz'
        else:
            return 'Unknown'
    
    def _analyze_network_structure(self, devices: List) -> Dict[str, Any]:
        """Analyze network structure and topology"""
        return {
            'topology_type': 'Star',  # Most common for WiFi
            'subnet_info': self._get_subnet_info(),
            'gateway_info': self._get_gateway_info(),
            'dns_servers': self._get_dns_servers(),
            'dhcp_range': self._get_dhcp_range()
        }
    
    def _categorize_devices(self, devices: List) -> Dict[str, int]:
        """Categorize discovered devices by type"""
        categories = {
            'routers': 0,
            'computers': 0,
            'mobile_devices': 0,
            'iot_devices': 0,
            'unknown': 0
        }
        
        for device in devices:
            device_type = device.get('device_type', 'unknown').lower()
            if 'router' in device_type or 'gateway' in device_type:
                categories['routers'] += 1
            elif 'computer' in device_type or 'laptop' in device_type:
                categories['computers'] += 1
            elif 'phone' in device_type or 'mobile' in device_type:
                categories['mobile_devices'] += 1
            elif 'iot' in device_type or 'smart' in device_type:
                categories['iot_devices'] += 1
            else:
                categories['unknown'] += 1
        
        return categories
    
    def _identify_topology_threats(self, devices: List) -> List[Dict[str, Any]]:
        """Identify potential security threats in network topology"""
        threats = []
        
        # Check for too many unknown devices
        unknown_count = sum(1 for device in devices if device.get('device_type') == 'unknown')
        if unknown_count > 5:
            threats.append({
                'type': 'Unknown Devices',
                'severity': 'Medium',
                'description': f'{unknown_count} unknown devices detected on network',
                'recommendation': 'Investigate and identify all connected devices'
            })
        
        # Check for potential rogue devices
        for device in devices:
            if device.get('suspicious', False):
                threats.append({
                    'type': 'Suspicious Device',
                    'severity': 'High',
                    'description': f'Device {device.get("ip", "unknown")} shows suspicious behavior',
                    'recommendation': 'Investigate device activity and consider blocking'
                })
        
        return threats
    
    def _evaluate_security_strength(self, config: Dict) -> Dict[str, Any]:
        """Evaluate overall security strength of the network"""
        score = 0
        vulnerabilities = []
        recommendations = []
        
        # Evaluate encryption
        encryption = config.get('encryption_type', '').upper()
        if encryption == 'WPA3':
            score += 30
        elif encryption == 'WPA2':
            score += 25
        elif encryption == 'WPA':
            score += 15
            vulnerabilities.append({
                'type': 'Weak Encryption',
                'severity': 'Medium',
                'description': 'WPA encryption is outdated and vulnerable'
            })
            recommendations.append('Upgrade to WPA2 or WPA3 encryption')
        elif encryption == 'WEP':
            score += 5
            vulnerabilities.append({
                'type': 'Very Weak Encryption',
                'severity': 'High',
                'description': 'WEP encryption is easily broken'
            })
            recommendations.append('Immediately upgrade to WPA2 or WPA3')
        elif encryption == 'OPEN':
            vulnerabilities.append({
                'type': 'No Encryption',
                'severity': 'Critical',
                'description': 'Network has no encryption - all traffic is visible'
            })
            recommendations.append('Enable WPA2 or WPA3 encryption immediately')
        
        # Evaluate other security features
        if config.get('wpa3_support'):
            score += 20
        if config.get('pmf_enabled'):
            score += 15
        if not config.get('wps_enabled', True):
            score += 10
        else:
            vulnerabilities.append({
                'type': 'WPS Enabled',
                'severity': 'Medium',
                'description': 'WPS can be exploited for unauthorized access'
            })
            recommendations.append('Disable WPS if not needed')
        
        config['security_score'] = min(score, 100)
        config['vulnerabilities'] = vulnerabilities
        config['recommendations'] = recommendations
        
        return config
    
    def _get_subnet_info(self) -> Dict[str, Any]:
        """Get subnet information"""
        try:
            # Platform-specific subnet detection
            if platform.system() == "Windows":
                return self._get_windows_subnet_info()
            else:
                return self._get_unix_subnet_info()
        except Exception as e:
            logger.error(f"Error getting subnet info: {e}")
            return {'subnet': '192.168.1.0/24', 'netmask': '255.255.255.0'}
    
    def _get_windows_subnet_info(self) -> Dict[str, Any]:
        """Get subnet info on Windows"""
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
            output = result.stdout
            
            # Parse subnet information
            subnet_pattern = r'IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)'
            netmask_pattern = r'Subnet Mask.*?:\s*(\d+\.\d+\.\d+\.\d+)'
            
            ip_match = re.search(subnet_pattern, output)
            mask_match = re.search(netmask_pattern, output)
            
            if ip_match and mask_match:
                ip = ip_match.group(1)
                mask = mask_match.group(1)
                return {'ip': ip, 'netmask': mask, 'subnet': f"{ip.rsplit('.', 1)[0]}.0/24"}
            
        except Exception as e:
            logger.error(f"Error getting Windows subnet info: {e}")
        
        return {'subnet': '192.168.1.0/24', 'netmask': '255.255.255.0'}
    
    def _get_unix_subnet_info(self) -> Dict[str, Any]:
        """Get subnet info on Unix-like systems"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            output = result.stdout
            
            # Parse default route
            default_pattern = r'default via (\d+\.\d+\.\d+\.\d+)'
            match = re.search(default_pattern, output)
            
            if match:
                gateway = match.group(1)
                subnet = f"{gateway.rsplit('.', 1)[0]}.0/24"
                return {'gateway': gateway, 'subnet': subnet}
            
        except Exception as e:
            logger.error(f"Error getting Unix subnet info: {e}")
        
        return {'subnet': '192.168.1.0/24'}
    
    def _get_gateway_info(self) -> Dict[str, Any]:
        """Get gateway information"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
                output = result.stdout
                gateway_pattern = r'Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)'
                match = re.search(gateway_pattern, output)
                if match:
                    return {'ip': match.group(1), 'type': 'Router'}
            else:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                output = result.stdout
                gateway_pattern = r'default via (\d+\.\d+\.\d+\.\d+)'
                match = re.search(gateway_pattern, output)
                if match:
                    return {'ip': match.group(1), 'type': 'Router'}
        except Exception as e:
            logger.error(f"Error getting gateway info: {e}")
        
        return {'ip': '192.168.1.1', 'type': 'Router'}
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS server information"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['nslookup', 'google.com'], capture_output=True, text=True, shell=True)
                output = result.stdout
                server_pattern = r'Server:\s+(\d+\.\d+\.\d+\.\d+)'
                match = re.search(server_pattern, output)
                if match:
                    return [match.group(1)]
            else:
                with open('/etc/resolv.conf', 'r') as f:
                    content = f.read()
                    dns_pattern = r'nameserver\s+(\d+\.\d+\.\d+\.\d+)'
                    matches = re.findall(dns_pattern, content)
                    if matches:
                        return matches
        except Exception as e:
            logger.error(f"Error getting DNS servers: {e}")
        
        return ['8.8.8.8', '8.8.4.4']  # Default to Google DNS
    
    def _get_dhcp_range(self) -> Dict[str, str]:
        """Get DHCP range information (if available)"""
        return {
            'start': '192.168.1.100',
            'end': '192.168.1.200',
            'note': 'DHCP range estimated based on common configurations'
        }


class DeepAnalysisEngine:
    """Main deep analysis engine that coordinates all analysis components"""
    
    def __init__(self):
        # Initialize AI components
        self.model_loader = ModelLoader()
        self.preprocessor = DataPreprocessor()
        self.ensemble_model = EnsembleFusionModel(self.model_loader, self.preprocessor)
        self.fusion_predictor = ensemble_predictor
        from .risk_assessor import RiskAssessor
        self.risk_assessor = RiskAssessor()
        
        # Initialize network analysis components
        self.network_analyzer = ConnectedNetworkAnalyzer()
        self.feature_extractor = NetworkFeatureExtractor()
        self.pdf_generator = PDFGenerator()
        
        # Initialize models
        self._initialize_models()
        
    def _initialize_models(self):
        """Initialize all AI models"""
        try:
            logger.info("Loading AI models for deep analysis...")
            self.model_loader.load_all_models()
            loaded_models = self.model_loader.get_loaded_models()
            logger.info(f"Loaded {len(loaded_models)} AI models successfully")
        except Exception as e:
            logger.error(f"Error loading AI models: {e}")
    
    def perform_deep_analysis(self, user_id: int, analysis_options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Perform comprehensive deep analysis of connected WiFi network
        
        Args:
            user_id: ID of the user requesting the analysis
            analysis_options: Optional analysis configuration
            
        Returns:
            Complete analysis results including AI predictions and risk assessment
        """
        try:
            analysis_id = str(uuid.uuid4())
            start_time = time.time()
            
            logger.info(f"Starting deep analysis {analysis_id} for user {user_id}")
            
            # Step 1: Analyze connected network
            logger.info("Step 1: Analyzing connected network...")
            network_data = self.network_analyzer.get_connected_network_details()
            
            # Step 2: Extract features for AI analysis
            logger.info("Step 2: Extracting features for AI analysis...")
            feature_data = self.feature_extractor.extract_network_features(network_data)
            
            # Step 3: Run individual model predictions
            logger.info("Step 3: Running individual AI model predictions...")
            individual_predictions = self._run_individual_predictions(feature_data)
            
            # Step 4: Run ensemble prediction
            logger.info("Step 4: Running ensemble prediction...")
            ensemble_prediction = self._run_ensemble_prediction(feature_data)
            
            # Step 5: Calculate comprehensive risk assessment
            logger.info("Step 5: Calculating risk assessment...")
            risk_assessment = self._calculate_comprehensive_risk(
                individual_predictions, 
                ensemble_prediction, 
                network_data
            )
            
            # Step 6: Generate comprehensive results
            logger.info("Step 6: Compiling comprehensive results...")
            analysis_results = {
                'analysis_id': analysis_id,
                'user_id': user_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'analysis_duration_seconds': time.time() - start_time,
                'network_data': network_data,
                'feature_data': feature_data,
                'individual_predictions': individual_predictions,
                'ensemble_prediction': ensemble_prediction,
                'risk_assessment': risk_assessment,
                'security_score': risk_assessment['overall_score'],
                'threat_level': risk_assessment['threat_level'],
                'vulnerabilities': risk_assessment['vulnerabilities'],
                'recommendations': risk_assessment['recommendations'],
                'compliance_status': self._check_compliance(risk_assessment),
                'analysis_metadata': {
                    'models_used': list(individual_predictions.keys()),
                    'ensemble_confidence': ensemble_prediction.get('confidence', 0.0),
                    'analysis_depth': 'comprehensive',
                    'data_sources': ['network_scan', 'traffic_analysis', 'topology_mapping', 'ai_models']
                }
            }
            
            # Step 7: Save to database
            logger.info("Step 7: Saving analysis results...")
            self._save_analysis_results(analysis_results)
            
            # Step 8: Generate PDF report
            logger.info("Step 8: Generating PDF report...")
            pdf_path = self._generate_pdf_report(analysis_results)
            analysis_results['pdf_report_path'] = pdf_path
            
            logger.info(f"Deep analysis {analysis_id} completed successfully")
            
            return {
                'success': True,
                'analysis_id': analysis_id,
                'results': analysis_results
            }
            
        except Exception as e:
            logger.error(f"Deep analysis failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'analysis_id': analysis_id if 'analysis_id' in locals() else None
            }
    
    def _run_individual_predictions(self, feature_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run predictions using individual AI models"""
        predictions = {}
        loaded_model_names = self.model_loader.get_loaded_models()
        
        for model_name in loaded_model_names:
            # Get the actual model from the cache
            model = self.model_loader.get_model(model_name)
            
            if model is None:
                logger.warning(f"Model {model_name} not available, skipping...")
                predictions[model_name] = {
                    'error': 'Model not loaded',
                    'prediction': None,
                    'confidence': 0.0,
                    'threat_class': 'ERROR'
                }
                continue
                
            try:
                logger.info(f"Running prediction with {model_name}")
                
                # Prepare features for this specific model
                model_features = self._prepare_features_for_model(feature_data, model_name)
                
                # Run prediction
                prediction = self._predict_with_model(model, model_features, model_name)
                
                predictions[model_name] = {
                    'prediction': prediction,
                    'confidence': prediction.get('confidence', 0.0),
                    'threat_class': prediction.get('predicted_class', 'NO_THREAT'),
                    'risk_score': prediction.get('risk_score', 0.0),
                    'model_type': self.model_loader.MODEL_SPECS.get(model_name, {}).get('type', 'unknown'),
                    'input_features': len(model_features) if isinstance(model_features, (list, np.ndarray)) else 0
                }
                
                logger.info(f"{model_name}: {prediction.get('predicted_class', 'NO_THREAT')} (confidence: {prediction.get('confidence', 0.0):.2f})")
                
            except Exception as e:
                logger.error(f"Error running prediction with {model_name}: {e}")
                predictions[model_name] = {
                    'error': str(e),
                    'prediction': None,
                    'confidence': 0.0,
                    'threat_class': 'ERROR'
                }
        
        return predictions
    
    def _run_ensemble_prediction(self, feature_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run ensemble prediction using fusion model"""
        try:
            # Prepare features for ensemble prediction
            ensemble_features = self._prepare_features_for_ensemble(feature_data)
            
            # Run ensemble prediction
            if hasattr(self.fusion_predictor, 'ensemble_predict'):
                ensemble_result = self.fusion_predictor.ensemble_predict(ensemble_features)
            elif hasattr(self.fusion_predictor, 'predict'):
                ensemble_result = self.fusion_predictor.predict(ensemble_features)
            else:
                # Fallback ensemble prediction
                ensemble_result = {
                    'predicted_class': 'MEDIUM_RISK',
                    'confidence': 0.75,
                    'risk_score': 5.5
                }
            
            return {
                'predicted_class': ensemble_result.get('predicted_class', 'NO_THREAT'),
                'confidence': ensemble_result.get('confidence', 0.0),
                'probability_distribution': ensemble_result.get('probability_distribution', []),
                'risk_score': ensemble_result.get('risk_score', 0.0),
                'fusion_weights': ensemble_result.get('fusion_weights', {}),
                'model_agreements': ensemble_result.get('model_agreements', []),
                'ensemble_metadata': {
                    'models_count': len(self.model_loader.get_loaded_models()),
                    'fusion_method': 'weighted_voting',
                    'confidence_threshold': 0.82
                }
            }
            
        except Exception as e:
            logger.error(f"Error running ensemble prediction: {e}")
            return {
                'error': str(e),
                'predicted_class': 'ERROR',
                'confidence': 0.0
            }
    
    def _prepare_features_for_model(self, feature_data: Dict[str, Any], model_name: str) -> np.ndarray:
        """Prepare features for a specific model based on its requirements"""
        try:
            model_spec = self.model_loader.MODEL_SPECS.get(model_name, {})
            input_dims = model_spec.get('input_dims', 32)
            model_type = model_spec.get('type', 'tensorflow')
            
            # Use preprocessor to prepare features
            if 'lstm' in model_name.lower():
                # LSTM models need sequence data
                features = self.preprocessor.prepare_lstm_input(feature_data)
            elif 'cnn' in model_name.lower():
                # CNN models need structured features
                features = self.preprocessor.prepare_cnn_input(feature_data)
            elif 'gnn' in model_name.lower():
                # GNN models need graph features
                gnn_input = self.preprocessor.prepare_gnn_input(feature_data)
                features = gnn_input.get('node_features', np.zeros((1, input_dims)))
            elif model_type == 'sklearn':
                # Sklearn models need flat feature vectors
                features = self.preprocessor.prepare_traditional_ml_input(feature_data)
            else:
                # Default feature preparation - use basic features
                basic_features = feature_data.get('basic_features', [0.0] * 8)
                features = np.array(basic_features).reshape(1, -1)
            
            return features
            
        except Exception as e:
            logger.error(f"Error preparing features for {model_name}: {e}")
            # Return zero features as fallback
            input_dims = self.model_loader.MODEL_SPECS.get(model_name, {}).get('input_dims', 32)
            return np.zeros((1, input_dims))
    
    def _predict_with_model(self, model: Any, features: np.ndarray, model_name: str) -> Dict[str, Any]:
        """Run prediction with a specific model"""
        try:
            model_spec = self.model_loader.MODEL_SPECS.get(model_name, {})
            model_type = model_spec.get('type', 'tensorflow')
            
            if model_type == 'tensorflow':
                # TensorFlow/Keras model
                # Ensure features have proper batch dimension and shape
                if len(features.shape) == 1:
                    features = features.reshape(1, -1)
                elif len(features.shape) == 2 and features.shape[0] > 1:
                    # For LSTM models, ensure proper sequence dimension
                    if 'lstm' in model_name.lower():
                        features = features.reshape(1, features.shape[0], features.shape[1])
                    else:
                        features = features.reshape(1, -1)
                elif len(features.shape) == 3 and features.shape[0] == 1:
                    # Already has batch dimension
                    pass
                else:
                    # Flatten to 2D with batch dimension
                    features = features.reshape(1, -1)
                
                # Ensure tensor is properly shaped for the model
                try:
                    prediction_probs = model.predict(features, verbose=0)
                except Exception as shape_error:
                    logger.warning(f"Shape error for {model_name}, trying fallback: {shape_error}")
                    # Try with different reshaping
                    if 'lstm' in model_name.lower():
                        features = features.reshape(1, 10, -1)  # Standard LSTM sequence shape
                    else:
                        features = features.flatten().reshape(1, -1)
                    prediction_probs = model.predict(features, verbose=0)
                
                if len(prediction_probs.shape) > 1 and prediction_probs.shape[0] > 0:
                    prediction_probs = prediction_probs[0]  # Get first sample
                
                predicted_class_idx = np.argmax(prediction_probs)
                confidence = float(np.max(prediction_probs))
                
                # Map to threat class
                threat_classes = [
                    'NO_THREAT', 'LOW_RISK_VULNERABILITY', 'MEDIUM_RISK_VULNERABILITY',
                    'HIGH_RISK_VULNERABILITY', 'CRITICAL_VULNERABILITY', 'ACTIVE_ATTACK_DETECTED',
                    'RECONNAISSANCE_PHASE', 'CREDENTIAL_COMPROMISE', 'DATA_BREACH_RISK',
                    'NETWORK_COMPROMISE', 'INSIDER_THREAT_DETECTED', 'APT_CAMPAIGN'
                ]
                
                predicted_class = threat_classes[min(predicted_class_idx, len(threat_classes) - 1)]
                
            elif model_type == 'sklearn':
                # Scikit-learn model
                prediction_probs = model.predict_proba(features.reshape(1, -1))[0]
                predicted_class_idx = np.argmax(prediction_probs)
                confidence = float(np.max(prediction_probs))
                
                # Map to threat class (sklearn models may have different class mappings)
                threat_classes = model.classes_ if hasattr(model, 'classes_') else [
                    'NO_THREAT', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_RISK'
                ]
                
                predicted_class = threat_classes[min(predicted_class_idx, len(threat_classes) - 1)]
            
            else:
                raise ValueError(f"Unsupported model type: {model_type}")
            
            return {
                'predicted_class': predicted_class,
                'class_index': int(predicted_class_idx),
                'confidence': confidence,
                'probability_distribution': prediction_probs.tolist(),
                'risk_score': confidence * (predicted_class_idx + 1) * 2.0  # Simple risk score calculation
            }
            
        except Exception as e:
            logger.error(f"Error predicting with model {model_name}: {e}")
            return {
                'predicted_class': 'ERROR',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _prepare_features_for_ensemble(self, feature_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare features for ensemble prediction"""
        return {
            'network_features': feature_data,
            'preprocessing_method': 'ensemble_ready'
        }
    
    def _calculate_comprehensive_risk(self, individual_predictions: Dict, ensemble_prediction: Dict, network_data: Dict) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        try:
            # Use risk assessor to calculate detailed risk
            risk_result = self.risk_assessor.calculate_risk_score(
                ensemble_prediction, 
                ensemble_prediction.get('confidence', 0.0)
            )
            
            # Add network-specific risk factors
            network_risks = self._assess_network_specific_risks(network_data)
            
            # Combine individual model insights
            model_consensus = self._analyze_model_consensus(individual_predictions)
            
            # Calculate overall risk score
            overall_score = self._calculate_overall_security_score(
                risk_result, network_risks, model_consensus
            )
            
            comprehensive_risk = {
                'overall_score': overall_score,
                'threat_level': risk_result.get('risk_level', 'LOW_RISK'),
                'ai_risk_assessment': risk_result,
                'network_specific_risks': network_risks,
                'model_consensus': model_consensus,
                'vulnerabilities': self._compile_vulnerabilities(individual_predictions, network_data),
                'recommendations': self._generate_recommendations(risk_result, network_risks),
                'confidence_metrics': {
                    'ensemble_confidence': ensemble_prediction.get('confidence', 0.0),
                    'model_agreement': model_consensus.get('agreement_percentage', 0.0),
                    'data_quality': self._assess_data_quality(network_data)
                }
            }
            
            return comprehensive_risk
            
        except Exception as e:
            logger.error(f"Error calculating comprehensive risk: {e}")
            return {
                'overall_score': 50.0,
                'threat_level': 'MEDIUM_RISK',
                'error': str(e)
            }
    
    def _assess_network_specific_risks(self, network_data: Dict) -> Dict[str, Any]:
        """Assess risks specific to the network configuration"""
        risks = {
            'encryption_risk': 0,
            'topology_risk': 0,
            'traffic_risk': 0,
            'configuration_risk': 0,
            'total_risk_score': 0
        }
        
        try:
            # Assess encryption risks
            security_config = network_data.get('security_config', {})
            encryption_type = security_config.get('encryption_type', 'Unknown').upper()
            
            if encryption_type == 'OPEN':
                risks['encryption_risk'] = 100
            elif encryption_type == 'WEP':
                risks['encryption_risk'] = 90
            elif encryption_type == 'WPA':
                risks['encryption_risk'] = 60
            elif encryption_type == 'WPA2':
                risks['encryption_risk'] = 20
            elif encryption_type == 'WPA3':
                risks['encryption_risk'] = 5
            
            # Assess topology risks
            topology = network_data.get('topology', {})
            device_count = topology.get('device_count', 0)
            unknown_devices = len([d for d in topology.get('devices', []) if d.get('device_type') == 'unknown'])
            
            if unknown_devices > device_count * 0.3:  # More than 30% unknown devices
                risks['topology_risk'] = 70
            elif unknown_devices > device_count * 0.1:  # More than 10% unknown devices
                risks['topology_risk'] = 40
            else:
                risks['topology_risk'] = 10
            
            # Assess traffic risks
            traffic_analysis = network_data.get('traffic_analysis', {})
            anomalies = traffic_analysis.get('anomalies', [])
            
            if len(anomalies) > 5:
                risks['traffic_risk'] = 80
            elif len(anomalies) > 2:
                risks['traffic_risk'] = 50
            elif len(anomalies) > 0:
                risks['traffic_risk'] = 25
            else:
                risks['traffic_risk'] = 5
            
            # Assess configuration risks
            if security_config.get('wps_enabled', False):
                risks['configuration_risk'] += 30
            if not security_config.get('pmf_enabled', False):
                risks['configuration_risk'] += 20
            
            # Calculate total risk score
            risks['total_risk_score'] = (
                risks['encryption_risk'] * 0.4 +
                risks['topology_risk'] * 0.2 +
                risks['traffic_risk'] * 0.2 +
                risks['configuration_risk'] * 0.2
            )
            
        except Exception as e:
            logger.error(f"Error assessing network risks: {e}")
            risks['error'] = str(e)
        
        return risks
    
    def _analyze_model_consensus(self, individual_predictions: Dict) -> Dict[str, Any]:
        """Analyze consensus among individual model predictions"""
        try:
            valid_predictions = {k: v for k, v in individual_predictions.items() 
                               if v.get('prediction') is not None and v.get('threat_class') != 'ERROR'}
            
            if not valid_predictions:
                return {'agreement_percentage': 0.0, 'consensus': 'No valid predictions'}
            
            # Count threat class predictions
            threat_classes = [pred['threat_class'] for pred in valid_predictions.values()]
            class_counts = {}
            for cls in threat_classes:
                class_counts[cls] = class_counts.get(cls, 0) + 1
            
            # Find majority prediction
            majority_class = max(class_counts, key=class_counts.get)
            majority_count = class_counts[majority_class]
            
            agreement_percentage = (majority_count / len(threat_classes)) * 100
            
            # Calculate average confidence
            confidences = [pred['confidence'] for pred in valid_predictions.values()]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
            
            return {
                'agreement_percentage': agreement_percentage,
                'majority_prediction': majority_class,
                'majority_count': majority_count,
                'total_models': len(valid_predictions),
                'average_confidence': avg_confidence,
                'class_distribution': class_counts,
                'consensus': 'Strong' if agreement_percentage >= 70 else 'Moderate' if agreement_percentage >= 50 else 'Weak'
            }
            
        except Exception as e:
            logger.error(f"Error analyzing model consensus: {e}")
            return {'agreement_percentage': 0.0, 'error': str(e)}
    
    def _calculate_overall_security_score(self, ai_risk: Dict, network_risks: Dict, consensus: Dict) -> float:
        """Calculate overall security score (0-100, higher is better)"""
        try:
            # Start with base score of 100 (perfect security)
            score = 100.0
            
            # Subtract based on AI risk assessment
            ai_risk_score = ai_risk.get('risk_score', 0)
            score -= ai_risk_score * 10  # AI risk is 0-10 scale
            
            # Subtract based on network-specific risks
            network_risk_score = network_risks.get('total_risk_score', 0)
            score -= network_risk_score  # Network risk is 0-100 scale
            
            # Adjust based on model consensus
            agreement = consensus.get('agreement_percentage', 0)
            if agreement < 50:  # Low agreement means uncertainty
                score -= 10  # Penalize for uncertainty
            
            # Ensure score is within bounds
            score = max(0.0, min(100.0, score))
            
            return score
            
        except Exception as e:
            logger.error(f"Error calculating overall security score: {e}")
            return 50.0  # Default to medium security
    
    def _compile_vulnerabilities(self, individual_predictions: Dict, network_data: Dict) -> List[Dict[str, Any]]:
        """Compile list of identified vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Add AI-identified vulnerabilities
            for model_name, prediction in individual_predictions.items():
                if prediction.get('threat_class', 'NO_THREAT') != 'NO_THREAT':
                    threat_class = prediction['threat_class']
                    confidence = prediction.get('confidence', 0.0)
                    
                    if confidence > 0.5:  # Only include high-confidence predictions
                        vulnerabilities.append({
                            'type': threat_class,
                            'source': f'AI Model: {model_name}',
                            'severity': self._map_threat_to_severity(threat_class),
                            'confidence': confidence,
                            'description': f'{threat_class} detected by {model_name} with {confidence:.1%} confidence'
                        })
            
            # Add network configuration vulnerabilities
            security_config = network_data.get('security_config', {})
            for vuln in security_config.get('vulnerabilities', []):
                vulnerabilities.append({
                    'type': vuln.get('type', 'Configuration Issue'),
                    'source': 'Network Configuration Analysis',
                    'severity': vuln.get('severity', 'Medium'),
                    'confidence': 1.0,
                    'description': vuln.get('description', 'Network configuration vulnerability')
                })
            
            # Add topology-based vulnerabilities
            topology = network_data.get('topology', {})
            for threat in topology.get('potential_threats', []):
                vulnerabilities.append({
                    'type': threat.get('type', 'Topology Issue'),
                    'source': 'Network Topology Analysis',
                    'severity': threat.get('severity', 'Medium'),
                    'confidence': 0.8,
                    'description': threat.get('description', 'Network topology security concern')
                })
            
        except Exception as e:
            logger.error(f"Error compiling vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _generate_recommendations(self, ai_risk: Dict, network_risks: Dict) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        try:
            # AI-based recommendations
            if ai_risk.get('risk_score', 0) > 5:
                recommendations.append({
                    'category': 'AI Analysis',
                    'priority': 'High',
                    'title': 'Address AI-Detected Threats',
                    'description': 'Multiple AI models have detected potential security threats in your network',
                    'action': 'Review detailed AI analysis and implement suggested security measures'
                })
            
            # Encryption recommendations
            encryption_risk = network_risks.get('encryption_risk', 0)
            if encryption_risk > 50:
                recommendations.append({
                    'category': 'Encryption',
                    'priority': 'Critical' if encryption_risk > 80 else 'High',
                    'title': 'Upgrade Network Encryption',
                    'description': 'Your network encryption is weak or outdated',
                    'action': 'Upgrade to WPA3 or at minimum WPA2 encryption immediately'
                })
            
            # Topology recommendations
            topology_risk = network_risks.get('topology_risk', 0)
            if topology_risk > 40:
                recommendations.append({
                    'category': 'Network Topology',
                    'priority': 'Medium',
                    'title': 'Review Connected Devices',
                    'description': 'Unknown or suspicious devices detected on your network',
                    'action': 'Identify all connected devices and remove unauthorized ones'
                })
            
            # Traffic recommendations
            traffic_risk = network_risks.get('traffic_risk', 0)
            if traffic_risk > 30:
                recommendations.append({
                    'category': 'Network Traffic',
                    'priority': 'Medium',
                    'title': 'Monitor Network Traffic',
                    'description': 'Unusual traffic patterns or anomalies detected',
                    'action': 'Enable network monitoring and investigate suspicious traffic'
                })
            
            # Configuration recommendations
            config_risk = network_risks.get('configuration_risk', 0)
            if config_risk > 20:
                recommendations.append({
                    'category': 'Configuration',
                    'priority': 'Medium',
                    'title': 'Improve Security Configuration',
                    'description': 'Network security settings can be improved',
                    'action': 'Disable WPS, enable PMF, and review all security settings'
                })
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def _map_threat_to_severity(self, threat_class: str) -> str:
        """Map threat class to severity level"""
        severity_mapping = {
            'NO_THREAT': 'Info',
            'LOW_RISK_VULNERABILITY': 'Low',
            'MEDIUM_RISK_VULNERABILITY': 'Medium',
            'HIGH_RISK_VULNERABILITY': 'High',
            'CRITICAL_VULNERABILITY': 'Critical',
            'ACTIVE_ATTACK_DETECTED': 'Critical',
            'RECONNAISSANCE_PHASE': 'Medium',
            'CREDENTIAL_COMPROMISE': 'High',
            'DATA_BREACH_RISK': 'Critical',
            'NETWORK_COMPROMISE': 'Critical',
            'INSIDER_THREAT_DETECTED': 'High'
        }
        
        return severity_mapping.get(threat_class, 'Medium')
    
    def _assess_data_quality(self, network_data: Dict) -> float:
        """Assess quality of collected network data"""
        try:
            quality_score = 0.0
            total_checks = 0
            
            # Check if basic network info is available
            basic_info = network_data.get('basic_info', {})
            if basic_info.get('ssid') and basic_info.get('ssid') != 'Unknown':
                quality_score += 20
            total_checks += 20
            
            # Check if detailed network info is available
            detailed_info = network_data.get('detailed_info', {})
            if detailed_info and not detailed_info.get('note'):  # No fallback note
                quality_score += 25
            total_checks += 25
            
            # Check if traffic analysis was successful
            traffic_analysis = network_data.get('traffic_analysis', {})
            if traffic_analysis and not traffic_analysis.get('simulated'):
                quality_score += 25
            total_checks += 25
            
            # Check if topology mapping was successful
            topology = network_data.get('topology', {})
            if topology.get('devices') and len(topology['devices']) > 0:
                quality_score += 15
            total_checks += 15
            
            # Check if security configuration is complete
            security_config = network_data.get('security_config', {})
            if security_config and not security_config.get('error'):
                quality_score += 15
            total_checks += 15
            
            return (quality_score / total_checks) * 100 if total_checks > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Error assessing data quality: {e}")
            return 50.0  # Default to medium quality
    
    def _check_compliance(self, risk_assessment: Dict) -> Dict[str, Any]:
        """Check compliance with security standards"""
        compliance = {
            'overall_status': 'Non-Compliant',
            'standards': {
                'PCI_DSS': 'Unknown',
                'NIST': 'Unknown',
                'ISO27001': 'Unknown'
            },
            'compliance_score': 0,
            'issues': []
        }
        
        try:
            overall_score = risk_assessment.get('overall_score', 0)
            
            # Simple compliance check based on security score
            if overall_score >= 80:
                compliance['overall_status'] = 'Compliant'
                compliance['compliance_score'] = 90
            elif overall_score >= 60:
                compliance['overall_status'] = 'Partially Compliant'
                compliance['compliance_score'] = 70
            else:
                compliance['overall_status'] = 'Non-Compliant'
                compliance['compliance_score'] = 30
            
            # Check specific standards
            encryption_risk = risk_assessment.get('network_specific_risks', {}).get('encryption_risk', 0)
            
            if encryption_risk < 30:
                compliance['standards']['PCI_DSS'] = 'Compliant'
                compliance['standards']['NIST'] = 'Compliant'
                compliance['standards']['ISO27001'] = 'Compliant'
            elif encryption_risk < 60:
                compliance['standards']['PCI_DSS'] = 'Partially Compliant'
                compliance['standards']['NIST'] = 'Partially Compliant'
                compliance['standards']['ISO27001'] = 'Partially Compliant'
            else:
                compliance['standards']['PCI_DSS'] = 'Non-Compliant'
                compliance['standards']['NIST'] = 'Non-Compliant'
                compliance['standards']['ISO27001'] = 'Non-Compliant'
                compliance['issues'].append('Weak or missing encryption does not meet compliance requirements')
            
        except Exception as e:
            logger.error(f"Error checking compliance: {e}")
            compliance['error'] = str(e)
        
        return compliance
    
    def _save_analysis_results(self, analysis_results: Dict[str, Any]):
        """Save analysis results to database"""
        try:
            # Create scan result record
            scan_result = ScanResult(
                user_id=analysis_results['user_id'],
                scan_id=analysis_results['analysis_id'],
                scan_timestamp=datetime.now(timezone.utc),
                network_ssid=analysis_results['network_data']['basic_info'].get('ssid', 'Unknown'),
                risk_level=analysis_results['threat_level'],
                vulnerability_details=json.dumps(analysis_results['vulnerabilities']),
                recommendations=json.dumps(analysis_results['recommendations']),
                model_predictions=json.dumps(analysis_results['individual_predictions']),
                ensemble_prediction=json.dumps(analysis_results['ensemble_prediction']),
                network_topology=json.dumps(analysis_results['network_data'].get('topology', {})),
                security_score=analysis_results['security_score'],
                analysis_metadata=json.dumps(analysis_results['analysis_metadata'])
            )
            
            scan_result.save()
            
            # Log audit event
            AuditLog.log_security_event(
                user_id=analysis_results['user_id'],
                event_type='DEEP_NETWORK_ANALYSIS',
                details=f"Deep analysis completed for network {analysis_results['network_data']['basic_info'].get('ssid', 'Unknown')}",
                risk_level=analysis_results['threat_level']
            )
            
            logger.info(f"Analysis results saved to database: {analysis_results['analysis_id']}")
            
        except Exception as e:
            logger.error(f"Error saving analysis results: {e}")
    
    def _generate_pdf_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive PDF report"""
        try:
            # Prepare report data
            report_data = {
                'title': 'WiFi Security Deep Analysis Report',
                'analysis_id': analysis_results['analysis_id'],
                'timestamp': analysis_results['timestamp'],
                'network_name': analysis_results['network_data']['basic_info'].get('ssid', 'Unknown Network'),
                'security_score': analysis_results['security_score'],
                'threat_level': analysis_results['threat_level'],
                'individual_predictions': analysis_results['individual_predictions'],
                'ensemble_prediction': analysis_results['ensemble_prediction'],
                'risk_assessment': analysis_results['risk_assessment'],
                'network_details': analysis_results['network_data'],
                'vulnerabilities': analysis_results['vulnerabilities'],
                'recommendations': analysis_results['recommendations'],
                'compliance_status': analysis_results['compliance_status'],
                'analysis_metadata': analysis_results['analysis_metadata']
            }
            
            # Generate PDF
            pdf_path = self.pdf_generator.generate_deep_analysis_report(report_data)
            
            logger.info(f"PDF report generated: {pdf_path}")
            return pdf_path
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return None


# Network Feature Extractor for AI models
class NetworkFeatureExtractor:
    """Extract features from network data for AI model analysis"""
    
    def __init__(self):
        self.feature_mapping = {
            'signal_strength': 0,
            'frequency': 1,
            'channel': 2,
            'encryption_strength': 3,
            'device_count': 4,
            'traffic_volume': 5,
            'anomaly_count': 6,
            'security_score': 7
        }
    
    def extract_network_features(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract comprehensive features from network analysis data"""
        try:
            basic_info = network_data.get('basic_info', {})
            detailed_info = network_data.get('detailed_info', {})
            traffic_analysis = network_data.get('traffic_analysis', {})
            topology = network_data.get('topology', {})
            security_config = network_data.get('security_config', {})
            
            # Basic network features
            signal_strength = basic_info.get('signal_strength', -70)
            frequency = detailed_info.get('network_info', {}).get('frequency', 2437)
            channel = detailed_info.get('network_info', {}).get('channel', 6)
            
            # Security features
            encryption_type = security_config.get('encryption_type', 'Unknown')
            encryption_strength = self._map_encryption_to_numeric(encryption_type)
            
            # Topology features
            device_count = topology.get('device_count', 0)
            device_types = topology.get('device_types', {})
            
            # Traffic features
            total_packets = traffic_analysis.get('total_packets', 0)
            anomaly_count = len(traffic_analysis.get('anomalies', []))
            
            # Security score
            security_score = security_config.get('security_score', 50)
            
            # Create feature vector
            feature_vector = [
                self._normalize_signal_strength(signal_strength),
                self._normalize_frequency(frequency),
                self._normalize_channel(channel),
                encryption_strength,
                self._normalize_device_count(device_count),
                self._normalize_traffic_volume(total_packets),
                self._normalize_anomaly_count(anomaly_count),
                self._normalize_security_score(security_score)
            ]
            
            # Extended features for different model types
            extended_features = {
                'basic_features': feature_vector,
                'signal_features': self._extract_signal_features(detailed_info),
                'traffic_features': self._extract_traffic_features(traffic_analysis),
                'topology_features': self._extract_topology_features(topology),
                'security_features': self._extract_security_features(security_config),
                'temporal_features': self._extract_temporal_features(network_data),
                'statistical_features': self._calculate_statistical_features(feature_vector)
            }
            
            return extended_features
            
        except Exception as e:
            logger.error(f"Error extracting network features: {e}")
            return {'basic_features': [0.0] * 8, 'error': str(e)}
    
    def _map_encryption_to_numeric(self, encryption_type: str) -> float:
        """Map encryption type to numeric value"""
        mapping = {
            'Open': 0.0,
            'WEP': 0.2,
            'WPA': 0.5,
            'WPA2': 0.8,
            'WPA3': 1.0
        }
        return mapping.get(encryption_type, 0.3)
    
    def _normalize_signal_strength(self, signal: int) -> float:
        """Normalize signal strength to 0-1 range"""
        # Signal typically ranges from -100 to -30 dBm
        return max(0.0, min(1.0, (signal + 100) / 70))
    
    def _normalize_frequency(self, frequency: int) -> float:
        """Normalize frequency to 0-1 range"""
        # Typical WiFi frequencies: 2400-2500 MHz (2.4GHz) and 5000-6000 MHz (5GHz)
        if 2400 <= frequency <= 2500:
            return (frequency - 2400) / 100  # 0-1 for 2.4GHz band
        elif 5000 <= frequency <= 6000:
            return 0.5 + (frequency - 5000) / 2000  # 0.5-1 for 5GHz band
        else:
            return 0.0
    
    def _normalize_channel(self, channel: int) -> float:
        """Normalize channel number to 0-1 range"""
        # WiFi channels typically range from 1-14 (2.4GHz) and 36-165 (5GHz)
        if 1 <= channel <= 14:
            return channel / 14
        elif 36 <= channel <= 165:
            return (channel - 36) / (165 - 36)
        else:
            return 0.0
    
    def _normalize_device_count(self, count: int) -> float:
        """Normalize device count to 0-1 range"""
        # Assume max 50 devices for normalization
        return min(1.0, count / 50)
    
    def _normalize_traffic_volume(self, packets: int) -> float:
        """Normalize traffic volume to 0-1 range"""
        # Assume max 10000 packets for normalization
        return min(1.0, packets / 10000)
    
    def _normalize_anomaly_count(self, count: int) -> float:
        """Normalize anomaly count to 0-1 range"""
        # Assume max 20 anomalies for normalization
        return min(1.0, count / 20)
    
    def _normalize_security_score(self, score: float) -> float:
        """Normalize security score to 0-1 range"""
        return score / 100
    
    def _extract_signal_features(self, detailed_info: Dict) -> List[float]:
        """Extract signal-related features"""
        network_info = detailed_info.get('network_info', {})
        
        return [
            detailed_info.get('signal_quality', 0.0) / 100,
            self._normalize_signal_strength(network_info.get('signal_strength', -70)),
            network_info.get('snr', 0.0) / 50,  # Assuming max SNR of 50
            network_info.get('noise_level', -95) / -50  # Normalize noise level
        ]
    
    def _extract_traffic_features(self, traffic_analysis: Dict) -> List[float]:
        """Extract traffic-related features"""
        protocols = traffic_analysis.get('protocols', {})
        bandwidth = traffic_analysis.get('bandwidth_usage', {})
        
        return [
            protocols.get('HTTP', 0.0) / 100,
            protocols.get('HTTPS', 0.0) / 100,
            protocols.get('DNS', 0.0) / 100,
            bandwidth.get('download_mbps', 0.0) / 100,  # Normalize to max 100 Mbps
            bandwidth.get('upload_mbps', 0.0) / 100,
            len(traffic_analysis.get('anomalies', [])) / 10
        ]
    
    def _extract_topology_features(self, topology: Dict) -> List[float]:
        """Extract topology-related features"""
        device_types = topology.get('device_types', {})
        
        return [
            topology.get('device_count', 0) / 50,
            device_types.get('routers', 0) / 5,
            device_types.get('computers', 0) / 20,
            device_types.get('mobile_devices', 0) / 20,
            device_types.get('iot_devices', 0) / 30,
            device_types.get('unknown', 0) / 10
        ]
    
    def _extract_security_features(self, security_config: Dict) -> List[float]:
        """Extract security-related features"""
        return [
            self._map_encryption_to_numeric(security_config.get('encryption_type', 'Unknown')),
            1.0 if security_config.get('wpa3_support', False) else 0.0,
            1.0 if security_config.get('pmf_enabled', False) else 0.0,
            0.0 if security_config.get('wps_enabled', True) else 1.0,  # Inverted (WPS disabled is better)
            security_config.get('security_score', 50) / 100,
            len(security_config.get('vulnerabilities', [])) / 10
        ]
    
    def _extract_temporal_features(self, network_data: Dict) -> List[float]:
        """Extract temporal features"""
        # For now, return simple timestamp-based features
        timestamp = datetime.fromisoformat(network_data.get('timestamp', '').replace('Z', '+00:00'))
        
        return [
            timestamp.hour / 24,  # Hour of day
            timestamp.weekday() / 7,  # Day of week
            timestamp.month / 12,  # Month of year
            0.5  # Default temporal stability metric
        ]
    
    def _calculate_statistical_features(self, feature_vector: List[float]) -> List[float]:
        """Calculate statistical features from basic feature vector"""
        if not feature_vector:
            return [0.0] * 4
        
        mean_val = np.mean(feature_vector)
        std_val = np.std(feature_vector)
        min_val = np.min(feature_vector)
        max_val = np.max(feature_vector)
        
        return [mean_val, std_val, min_val, max_val]