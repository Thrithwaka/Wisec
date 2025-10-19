"""
Real-Time WiFi Analysis Integration
Purpose: Bridge WiFi Scanner and AI Models for Real-Time Threat Detection

This module integrates the WiFi scanner with AI models to provide real-time
threat detection using actual network data instead of synthetic data.
"""

import logging
import time
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
from datetime import datetime

from .wifi_feature_extractor import WiFiFeatureExtractor, WiFiFeatures
from .ensemble_predictor import EnsembleFusionModel
from .model_loader import model_loader
from .preprocessor import data_preprocessor

logger = logging.getLogger(__name__)

class RealTimeWiFiAnalyzer:
    """
    Real-time WiFi network analyzer that integrates scanner data with AI models
    
    This class processes real WiFi network data from the scanner system and
    feeds it to the AI ensemble models for threat detection.
    """
    
    def __init__(self):
        """Initialize the real-time analyzer"""
        self.feature_extractor = WiFiFeatureExtractor()
        self.ensemble_model = EnsembleFusionModel(model_loader, data_preprocessor)
        self.analysis_cache = {}
        self.cache_ttl = 300  # 5 minutes cache TTL
        
        logger.info("RealTimeWiFiAnalyzer initialized")
    
    def analyze_network(self, network_info, all_networks: List = None) -> Dict[str, Any]:
        """
        Analyze a single network using AI models with real data
        
        Args:
            network_info: NetworkInfo object from WiFi scanner
            all_networks: List of all discovered networks for context
            
        Returns:
            Dictionary containing comprehensive threat analysis
        """
        try:
            start_time = time.time()
            
            # Check cache first
            cache_key = f"{network_info.bssid}_{network_info.last_seen}"
            if cache_key in self.analysis_cache:
                cache_entry = self.analysis_cache[cache_key]
                if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                    logger.debug(f"Cache hit for {network_info.ssid}")
                    return cache_entry['result']
            
            logger.info(f"Analyzing network: {network_info.ssid} ({network_info.bssid})")
            
            # Extract features from real network data
            wifi_features = self.feature_extractor.extract_features(
                network_info, all_networks, time.time()
            )
            
            # Convert to format expected by AI models
            feature_array = wifi_features.to_array()
            
            # Get AI predictions using real features
            ai_predictions = self._get_ai_predictions(feature_array, wifi_features)
            
            # Analyze network security profile
            security_analysis = self._analyze_security_profile(network_info)
            
            # Detect potential threats
            threat_analysis = self._detect_threats(network_info, ai_predictions, security_analysis)
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(ai_predictions, security_analysis, threat_analysis)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(threat_analysis, risk_score)
            
            processing_time = (time.time() - start_time) * 1000
            
            # Compile comprehensive analysis result
            analysis_result = {
                'network_info': {
                    'ssid': network_info.ssid,
                    'bssid': network_info.bssid,
                    'signal_strength': network_info.signal_strength,
                    'signal_quality': network_info.quality,
                    'encryption_type': network_info.encryption_type,
                    'vendor': network_info.vendor,
                    'device_type': network_info.device_type,
                    'channel': network_info.channel,
                    'frequency': network_info.frequency,
                    'is_hidden': network_info.is_hidden
                },
                'ai_analysis': ai_predictions,
                'security_analysis': security_analysis,
                'threat_analysis': threat_analysis,
                'risk_score': risk_score,
                'recommendations': recommendations,
                'feature_vector': feature_array.tolist(),
                'processing_time_ms': processing_time,
                'timestamp': datetime.now().isoformat(),
                'analysis_version': '2.0',
                'using_real_data': True
            }
            
            # Cache the result
            self.analysis_cache[cache_key] = {
                'result': analysis_result,
                'timestamp': time.time()
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing network {network_info.ssid}: {e}")
            return self._get_fallback_analysis(network_info, str(e))
    
    def analyze_multiple_networks(self, networks: List, 
                                context_analysis: bool = True) -> List[Dict[str, Any]]:
        """
        Analyze multiple networks with optional context analysis
        
        Args:
            networks: List of NetworkInfo objects
            context_analysis: Whether to perform network context analysis
            
        Returns:
            List of analysis results
        """
        results = []
        start_time = time.time()
        
        logger.info(f"Analyzing {len(networks)} networks")
        
        for i, network in enumerate(networks):
            try:
                # Pass all networks for context if enabled
                context = networks if context_analysis else None
                result = self.analyze_network(network, context)
                results.append(result)
                
                if i % 10 == 0:  # Progress logging
                    logger.info(f"Processed {i+1}/{len(networks)} networks")
                    
            except Exception as e:
                logger.error(f"Error analyzing network {i}: {e}")
                results.append(self._get_fallback_analysis(network, str(e)))
        
        total_time = (time.time() - start_time) * 1000
        logger.info(f"Analyzed {len(networks)} networks in {total_time:.2f}ms")
        
        return results
    
    def _get_ai_predictions(self, features: np.ndarray, wifi_features: WiFiFeatures) -> Dict[str, Any]:
        """Get predictions from AI ensemble models using real features"""
        try:
            # Prepare data for AI models
            synthetic_data = self._convert_features_to_synthetic_format(features, wifi_features)
            
            # Create sequence from synthetic data for ensemble prediction  
            network_sequence = [synthetic_data] * 50  # Create 50-timestep sequence as expected
            
            # Use the ensemble predictor to get accurate predictions with real data
            ensemble_predictions = self.ensemble_model.predict_threat(
                network_data_sequence=network_sequence,
                confidence_threshold=0.7
            )
            
            # Add feature-based analysis
            feature_analysis = {
                'signal_analysis': {
                    'strength_normalized': float(features[0]),
                    'quality_score': float(features[1]),
                    'snr_score': float(features[2]),
                    'stability_score': float(features[3])
                },
                'security_analysis': {
                    'encryption_strength': float(features[8]),
                    'cipher_score': float(features[9]),
                    'auth_method_score': float(features[10]),
                    'wps_vulnerable': bool(features[11] > 0.5)
                },
                'network_analysis': {
                    'vendor_trust': float(features[16]),
                    'device_risk': float(features[17]),
                    'ssid_entropy': float(features[18]),
                    'suspicious_indicators': float(features[19])
                }
            }
            
            return {
                'ensemble_predictions': ensemble_predictions,
                'feature_analysis': feature_analysis,
                'confidence_score': ensemble_predictions.get('ensemble_confidence', 0.5),
                'predicted_class': ensemble_predictions.get('final_prediction', 'UNKNOWN'),
                'model_agreement': ensemble_predictions.get('model_agreement', 0.0)
            }
            
        except Exception as e:
            logger.error(f"Error getting AI predictions: {e}")
            return {
                'ensemble_predictions': {'error': str(e)},
                'feature_analysis': {},
                'confidence_score': 0.3,
                'predicted_class': 'ANALYSIS_ERROR',
                'model_agreement': 0.0,
                'fallback': True
            }
    
    def _convert_features_to_synthetic_format(self, features: np.ndarray, 
                                           wifi_features: WiFiFeatures) -> Dict[str, Any]:
        """Convert real WiFi features to network data format expected by ensemble model"""
        # Convert the 32-dimensional feature vector back to network data format
        # that the ensemble predictor's preprocessor can handle
        
        # Extract key network parameters from features
        signal_strength = -100 + (features[0] * 80)  # Convert normalized to dBm range
        channel = max(1, min(14, int(features[4] * 14)))  # Convert to channel 1-14
        frequency = 2400 + (channel * 5)  # Approximate frequency
        
        # Determine encryption from security features
        encryption_score = features[8]
        if encryption_score > 0.8:
            encryption = 'WPA3-PSK'
        elif encryption_score > 0.6:
            encryption = 'WPA2-PSK'
        elif encryption_score > 0.3:
            encryption = 'WPA-PSK'
        else:
            encryption = 'OPEN'
        
        # Create network data format that matches what the preprocessor expects
        network_data = {
            'timestamp': time.time(),
            'signal_strength': signal_strength,
            'channel': channel,
            'frequency': frequency,
            'encryption': encryption,
            'ssid_length': int(features[18] * 32),  # Approximate from entropy
            'vendor_oui': 'Real-Device',
            'capabilities': [encryption, 'ESS'],
            'data_rate': features[1] * 100,  # Quality as rate
            'noise_level': features[2] * -50,  # SNR converted
            'packet_count': int(features[20] * 1000),
            'beacon_interval': 100,
            'connection_attempts': int(features[21] * 10),
            'using_real_wifi_data': True,
            'feature_vector': features.tolist()
        }
        
        return network_data
    
    def _analyze_security_profile(self, network_info) -> Dict[str, Any]:
        """Analyze network security profile"""
        security_score = 100.0
        vulnerabilities = []
        security_features = []
        
        # Encryption analysis
        encryption = str(network_info.encryption_type or '').upper()
        if 'OPEN' in encryption or not encryption:
            security_score -= 40
            vulnerabilities.append('No encryption enabled')
        elif 'WEP' in encryption:
            security_score -= 35
            vulnerabilities.append('Weak WEP encryption')
        elif 'WPA3' in encryption:
            security_features.append('Strong WPA3 encryption')
            security_score += 5
        elif 'WPA2' in encryption:
            security_features.append('WPA2 encryption')
        elif 'WPA' in encryption:
            security_score -= 15
            vulnerabilities.append('Legacy WPA encryption')
        
        # Check for WPS
        capabilities = getattr(network_info, 'capabilities', None) or []
        capabilities_str = ' '.join(str(cap) for cap in capabilities).upper()
        if 'WPS' in capabilities_str:
            security_score -= 20
            vulnerabilities.append('WPS enabled (PIN attack risk)')
        
        # Check for PMF
        capabilities = getattr(network_info, 'capabilities', None) or []
        if any('PMF' in str(cap) or '11W' in str(cap) for cap in capabilities):
            security_features.append('Protected Management Frames (PMF)')
            security_score += 10
        
        # Hidden network check
        if network_info.is_hidden:
            security_score -= 5
            vulnerabilities.append('Hidden SSID (security through obscurity)')
        
        # Signal strength analysis
        if network_info.signal_strength > -30:
            vulnerabilities.append('Very strong signal - potential proximity risk')
            security_score -= 5
        
        return {
            'security_score': max(0, min(100, security_score)),
            'vulnerabilities': vulnerabilities,
            'security_features': security_features,
            'encryption_strength': self._get_encryption_strength(encryption),
            'overall_assessment': self._get_security_assessment(security_score)
        }
    
    def _detect_threats(self, network_info, ai_predictions: Dict, 
                       security_analysis: Dict) -> Dict[str, Any]:
        """Detect potential threats based on network analysis"""
        threats = []
        threat_score = 0.0
        
        # AI model threat detection
        predicted_class = ai_predictions.get('predicted_class', 'UNKNOWN')
        confidence = ai_predictions.get('confidence_score', 0.0)
        
        if confidence > 0.7:
            if predicted_class in ['BRUTE_FORCE_ATTACK', 'RECONNAISSANCE', 'BOTNET_ACTIVITY']:
                threats.append({
                    'type': predicted_class,
                    'severity': 'HIGH',
                    'confidence': confidence,
                    'source': 'AI_MODEL'
                })
                threat_score += 0.8 * confidence
            elif predicted_class in ['DATA_EXFILTRATION', 'APT_BEHAVIOR', 'COMMAND_CONTROL']:
                threats.append({
                    'type': predicted_class,
                    'severity': 'CRITICAL',
                    'confidence': confidence,
                    'source': 'AI_MODEL'
                })
                threat_score += 0.9 * confidence
        
        # Security-based threat detection
        if security_analysis['security_score'] < 40:
            threats.append({
                'type': 'WEAK_SECURITY',
                'severity': 'MEDIUM',
                'confidence': 0.9,
                'source': 'SECURITY_ANALYSIS'
            })
            threat_score += 0.3
        
        # Behavioral threat detection
        ssid = network_info.ssid.lower() if network_info.ssid else ''
        suspicious_keywords = ['free', 'guest', 'public', 'wifi', 'internet']
        if any(keyword in ssid for keyword in suspicious_keywords):
            threats.append({
                'type': 'SUSPICIOUS_SSID',
                'severity': 'MEDIUM',
                'confidence': 0.6,
                'source': 'HEURISTIC'
            })
            threat_score += 0.2
        
        # Evil twin detection (simplified)
        if network_info.vendor == 'Unknown' and network_info.signal_strength > -40:
            threats.append({
                'type': 'POTENTIAL_EVIL_TWIN',
                'severity': 'HIGH',
                'confidence': 0.7,
                'source': 'HEURISTIC'
            })
            threat_score += 0.6
        
        return {
            'threats_detected': threats,
            'threat_score': min(1.0, threat_score),
            'threat_level': self._get_threat_level(threat_score),
            'total_threats': len(threats)
        }
    
    def _calculate_risk_score(self, ai_predictions: Dict, security_analysis: Dict, 
                            threat_analysis: Dict) -> Dict[str, Any]:
        """Calculate comprehensive risk score"""
        # Weighted risk calculation
        ai_risk = ai_predictions.get('confidence_score', 0.5) * 0.4
        security_risk = (100 - security_analysis['security_score']) / 100.0 * 0.3
        threat_risk = threat_analysis['threat_score'] * 0.3
        
        overall_risk = ai_risk + security_risk + threat_risk
        overall_risk = min(1.0, max(0.0, overall_risk))
        
        return {
            'overall_risk': overall_risk,
            'risk_level': self._get_risk_level(overall_risk),
            'component_risks': {
                'ai_model_risk': ai_risk,
                'security_risk': security_risk,
                'threat_behavior_risk': threat_risk
            },
            'risk_factors': self._get_risk_factors(ai_predictions, security_analysis, threat_analysis)
        }
    
    def _generate_recommendations(self, threat_analysis: Dict, risk_score: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        risk_level = risk_score['risk_level']
        threats = threat_analysis.get('threats_detected', [])
        
        # Risk-based recommendations
        if risk_level == 'CRITICAL':
            recommendations.append('IMMEDIATE ACTION: Block network access and investigate')
            recommendations.append('Report this network to security team')
        elif risk_level == 'HIGH':
            recommendations.append('High risk detected - avoid connecting')
            recommendations.append('Monitor network activity if connection is necessary')
        elif risk_level == 'MEDIUM':
            recommendations.append('Exercise caution when connecting')
            recommendations.append('Use VPN if connection is required')
        else:
            recommendations.append('Network appears relatively safe')
            recommendations.append('Continue normal security practices')
        
        # Threat-specific recommendations
        for threat in threats:
            threat_type = threat['type']
            if threat_type == 'WEAK_SECURITY':
                recommendations.append('Enable stronger encryption (WPA3/WPA2)')
            elif threat_type == 'SUSPICIOUS_SSID':
                recommendations.append('Verify network legitimacy before connecting')
            elif threat_type == 'POTENTIAL_EVIL_TWIN':
                recommendations.append('Confirm network authenticity with administrator')
        
        return list(set(recommendations))  # Remove duplicates
    
    def _get_encryption_strength(self, encryption: str) -> str:
        """Get encryption strength classification"""
        if 'WPA3' in encryption:
            return 'STRONG'
        elif 'WPA2' in encryption:
            return 'GOOD'
        elif 'WPA' in encryption:
            return 'MODERATE'
        elif 'WEP' in encryption:
            return 'WEAK'
        else:
            return 'NONE'
    
    def _get_security_assessment(self, score: float) -> str:
        """Get overall security assessment"""
        if score >= 80:
            return 'SECURE'
        elif score >= 60:
            return 'MODERATE'
        elif score >= 40:
            return 'WEAK'
        else:
            return 'VULNERABLE'
    
    def _get_threat_level(self, threat_score: float) -> str:
        """Get threat level classification"""
        if threat_score >= 0.8:
            return 'CRITICAL'
        elif threat_score >= 0.6:
            return 'HIGH'
        elif threat_score >= 0.3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get overall risk level"""
        if risk_score >= 0.8:
            return 'CRITICAL'
        elif risk_score >= 0.6:
            return 'HIGH' 
        elif risk_score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_risk_factors(self, ai_predictions: Dict, security_analysis: Dict, 
                         threat_analysis: Dict) -> List[str]:
        """Get list of risk factors"""
        factors = []
        
        # AI-based factors
        if ai_predictions.get('confidence_score', 0) > 0.7:
            factors.append(f"AI detected: {ai_predictions.get('predicted_class', 'Unknown threat')}")
        
        # Security factors
        for vulnerability in security_analysis.get('vulnerabilities', []):
            factors.append(f"Security issue: {vulnerability}")
        
        # Threat factors
        for threat in threat_analysis.get('threats_detected', []):
            factors.append(f"{threat['severity']} threat: {threat['type']}")
        
        return factors
    
    def _get_fallback_analysis(self, network_info, error_message: str) -> Dict[str, Any]:
        """Generate fallback analysis when main analysis fails"""
        return {
            'network_info': {
                'ssid': getattr(network_info, 'ssid', 'Unknown'),
                'bssid': getattr(network_info, 'bssid', 'Unknown'),
                'signal_strength': getattr(network_info, 'signal_strength', -100),
                'encryption_type': getattr(network_info, 'encryption_type', 'Unknown')
            },
            'ai_analysis': {
                'error': error_message,
                'fallback': True
            },
            'security_analysis': {
                'security_score': 50,
                'assessment': 'ANALYSIS_FAILED'
            },
            'threat_analysis': {
                'threats_detected': [],
                'threat_level': 'UNKNOWN'
            },
            'risk_score': {
                'overall_risk': 0.5,
                'risk_level': 'UNKNOWN'
            },
            'recommendations': ['Analysis failed - manual review required'],
            'processing_time_ms': 1.0,
            'timestamp': datetime.now().isoformat(),
            'error': error_message,
            'using_real_data': False
        }
    
    def clear_cache(self):
        """Clear the analysis cache"""
        self.analysis_cache.clear()
        logger.info("Analysis cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        now = time.time()
        active_entries = sum(1 for entry in self.analysis_cache.values() 
                           if now - entry['timestamp'] < self.cache_ttl)
        
        return {
            'total_entries': len(self.analysis_cache),
            'active_entries': active_entries,
            'cache_ttl_seconds': self.cache_ttl,
            'cache_hit_potential': active_entries / max(1, len(self.analysis_cache))
        }

# Global analyzer instance
real_time_analyzer = RealTimeWiFiAnalyzer()