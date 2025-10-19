"""
WiFi AI Prediction Validator
Purpose: Verify that AI models are using real WiFi data and validate prediction accuracy

This module provides comprehensive validation of AI predictions to ensure:
1. Real WiFi data is being used (not fallback/dummy data)
2. Feature extraction is working correctly
3. Model predictions align with actual network characteristics
4. Detection of false positives/negatives
"""

import logging
import time
import json
import numpy as np
from typing import Dict, List, Any, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class WiFiPredictionValidator:
    """
    Validates AI predictions against known network characteristics
    """
    
    def __init__(self):
        """Initialize the prediction validator"""
        self.validation_history = []
        self.known_safe_networks = {
            'characteristics': {
                'strong_encryption': ['WPA3', 'WPA2', 'CCMP'],
                'legitimate_vendors': ['Apple', 'Samsung', 'Cisco', 'TP-Link', 'Netgear'],
                'normal_channels': list(range(1, 15)),
                'good_signal_range': (-80, -20)  # dBm
            }
        }
        logger.info("WiFi Prediction Validator initialized")
    
    def validate_prediction_accuracy(self, network_info, predictions: Dict, 
                                   features_used: np.ndarray) -> Dict[str, Any]:
        """
        Comprehensive validation of AI predictions
        
        Args:
            network_info: NetworkInfo object with real WiFi data
            predictions: Dictionary of model predictions
            features_used: Feature array that was fed to models
            
        Returns:
            Validation report with accuracy assessment
        """
        validation_start = time.time()
        
        logger.info(f"🔍 Starting prediction validation for network: {network_info.ssid}")
        
        # 1. Verify Real Data Usage
        real_data_verification = self._verify_real_data_usage(network_info, features_used)
        
        # 2. Check Feature Consistency
        feature_consistency = self._check_feature_consistency(network_info, features_used)
        
        # 3. Validate Against Network Profile
        profile_validation = self._validate_against_network_profile(network_info, predictions)
        
        # 4. Check for Known False Positives
        false_positive_check = self._check_false_positives(network_info, predictions)
        
        # 5. Cross-Reference with Security Standards
        security_standards_check = self._check_security_standards(network_info, predictions)
        
        # 6. Behavioral Analysis Validation
        behavioral_validation = self._validate_behavioral_predictions(network_info, predictions)
        
        validation_time = (time.time() - validation_start) * 1000
        
        # Compile comprehensive validation report
        validation_report = {
            'network_analyzed': {
                'ssid': network_info.ssid,
                'bssid': network_info.bssid,
                'encryption': network_info.encryption_type,
                'signal_strength': network_info.signal_strength,
                'channel': network_info.channel,
                'vendor': getattr(network_info, 'vendor', 'Unknown')
            },
            'real_data_verification': real_data_verification,
            'feature_consistency': feature_consistency,
            'profile_validation': profile_validation,
            'false_positive_check': false_positive_check,
            'security_standards_check': security_standards_check,
            'behavioral_validation': behavioral_validation,
            'overall_confidence': self._calculate_overall_confidence(
                real_data_verification, feature_consistency, profile_validation,
                false_positive_check, security_standards_check, behavioral_validation
            ),
            'validation_time_ms': validation_time,
            'validation_timestamp': datetime.now().isoformat(),
            'recommendations': self._generate_validation_recommendations(
                real_data_verification, profile_validation, false_positive_check
            )
        }
        
        # Store in history
        self.validation_history.append(validation_report)
        
        logger.info(f"✅ Validation completed in {validation_time:.2f}ms")
        return validation_report
    
    def _verify_real_data_usage(self, network_info, features: np.ndarray) -> Dict[str, Any]:
        """Verify that real WiFi data was used in feature extraction"""
        verification = {
            'using_real_data': True,
            'evidence': [],
            'concerns': []
        }
        
        # Check if features match network characteristics
        if len(features) >= 32:  # CNN features
            signal_feature = features[0]  # Normalized signal strength
            expected_signal_norm = max(0, min(1, (network_info.signal_strength + 100) / 80))
            
            if abs(signal_feature - expected_signal_norm) < 0.1:
                verification['evidence'].append(f"Signal strength feature matches real data: {signal_feature:.3f} vs expected {expected_signal_norm:.3f}")
            else:
                verification['concerns'].append(f"Signal strength mismatch: feature={signal_feature:.3f}, expected={expected_signal_norm:.3f}")
                verification['using_real_data'] = False
        
        # Check encryption consistency
        if network_info.encryption_type:
            encryption = network_info.encryption_type.upper()
            if len(features) >= 9:
                encryption_feature = features[8]
                expected_enc_score = self._get_expected_encryption_score(encryption)
                
                if abs(encryption_feature - expected_enc_score) < 0.2:
                    verification['evidence'].append(f"Encryption feature consistent: {encryption_feature:.3f} for {encryption}")
                else:
                    verification['concerns'].append(f"Encryption feature inconsistent: {encryption_feature:.3f} for {encryption}")
        
        # Check channel consistency
        if len(features) >= 5 and network_info.channel:
            channel_feature = features[4]
            expected_channel_norm = network_info.channel / 14.0
            
            if abs(channel_feature - expected_channel_norm) < 0.1:
                verification['evidence'].append(f"Channel feature matches: {channel_feature:.3f} for channel {network_info.channel}")
            else:
                verification['concerns'].append(f"Channel feature mismatch: {channel_feature:.3f} for channel {network_info.channel}")
        
        return verification
    
    def _check_feature_consistency(self, network_info, features: np.ndarray) -> Dict[str, Any]:
        """Check if extracted features are consistent with network properties"""
        consistency = {
            'consistent': True,
            'feature_analysis': {},
            'anomalies': []
        }
        
        if len(features) >= 32:
            # Analyze key features
            consistency['feature_analysis'] = {
                'signal_strength_normalized': float(features[0]),
                'signal_quality': float(features[1]),
                'encryption_strength': float(features[8]),
                'channel_normalized': float(features[4]),
                'legitimate_network_indicators': {
                    'strong_signal': features[0] > 0.5,
                    'good_encryption': features[8] > 0.6,
                    'standard_channel': 0 < features[4] < 1
                }
            }
            
            # Check for feature anomalies
            if features[0] < 0.1 or features[0] > 1.0:
                consistency['anomalies'].append(f"Signal strength feature out of range: {features[0]}")
                consistency['consistent'] = False
            
            if features[8] < 0 or features[8] > 1.0:
                consistency['anomalies'].append(f"Encryption strength feature out of range: {features[8]}")
                consistency['consistent'] = False
        
        return consistency
    
    def _validate_against_network_profile(self, network_info, predictions: Dict) -> Dict[str, Any]:
        """Validate predictions against known network profile characteristics"""
        profile_validation = {
            'network_profile': 'UNKNOWN',
            'expected_threats': [],
            'unexpected_predictions': [],
            'profile_match_score': 0.0
        }
        
        # Analyze network profile
        encryption = str(network_info.encryption_type or '').upper()
        signal_strength = network_info.signal_strength
        vendor = getattr(network_info, 'vendor', 'Unknown')
        
        # Determine expected profile
        if any(enc in encryption for enc in ['WPA3', 'WPA2', 'CCMP']):
            if signal_strength > -50 and vendor in self.known_safe_networks['characteristics']['legitimate_vendors']:
                profile_validation['network_profile'] = 'LEGITIMATE_HOME_NETWORK'
                profile_validation['expected_threats'] = ['NONE', 'LOW_RISK_VULNERABILITIES']
            elif signal_strength > -30:
                profile_validation['network_profile'] = 'STRONG_LEGITIMATE_NETWORK'
                profile_validation['expected_threats'] = ['NONE', 'NORMAL_BEHAVIOR']
        elif 'OPEN' in encryption:
            profile_validation['network_profile'] = 'OPEN_NETWORK'
            profile_validation['expected_threats'] = ['WEAK_SECURITY', 'POTENTIAL_RISKS']
        
        # Check predictions against profile
        individual_preds = predictions.get('individual_predictions', {})
        concerning_predictions = []
        
        for model_name, pred in individual_preds.items():
            pred_class = pred.get('predicted_class', 'UNKNOWN')
            confidence = pred.get('confidence', 0.0)
            
            # Check for unexpected high-severity predictions on legitimate networks
            if profile_validation['network_profile'] in ['LEGITIMATE_HOME_NETWORK', 'STRONG_LEGITIMATE_NETWORK']:
                high_threat_classes = [
                    'BOTNET_ACTIVITY', 'LATERAL_MOVEMENT', 'DATA_EXFILTRATION', 
                    'APT_BEHAVIOR', 'COMMAND_CONTROL', 'CRITICAL_NODE'
                ]
                
                if pred_class in high_threat_classes and confidence > 0.5:
                    concerning_predictions.append({
                        'model': model_name,
                        'prediction': pred_class,
                        'confidence': confidence,
                        'concern': f'High-threat prediction on legitimate network'
                    })
        
        profile_validation['unexpected_predictions'] = concerning_predictions
        profile_validation['profile_match_score'] = max(0, 1.0 - (len(concerning_predictions) * 0.2))
        
        return profile_validation
    
    def _check_false_positives(self, network_info, predictions: Dict) -> Dict[str, Any]:
        """Check for common false positive patterns"""
        false_positive_check = {
            'likely_false_positives': [],
            'confidence_assessment': {},
            'false_positive_probability': 0.0
        }
        
        # Check for common false positive patterns
        individual_preds = predictions.get('individual_predictions', {})
        
        for model_name, pred in individual_preds.items():
            pred_class = pred.get('predicted_class', 'UNKNOWN')
            confidence = pred.get('confidence', 0.0)
            
            # Pattern 1: High-threat prediction on well-encrypted home network
            if (pred_class in ['BOTNET_ACTIVITY', 'LATERAL_MOVEMENT'] and 
                'WPA' in str(network_info.encryption_type or '') and
                network_info.signal_strength > -40):
                
                false_positive_check['likely_false_positives'].append({
                    'model': model_name,
                    'prediction': pred_class,
                    'confidence': confidence,
                    'reason': 'High-threat prediction on secure home network',
                    'false_positive_probability': 0.8
                })
            
            # Pattern 2: Perfect confidence scores (often indicates overfitting)
            if confidence >= 0.99:
                false_positive_check['confidence_assessment'][model_name] = {
                    'confidence': confidence,
                    'concern': 'Suspiciously high confidence - possible overfitting',
                    'reliability': 'LOW'
                }
        
        # Calculate overall false positive probability
        if false_positive_check['likely_false_positives']:
            avg_fp_prob = np.mean([fp['false_positive_probability'] 
                                 for fp in false_positive_check['likely_false_positives']])
            false_positive_check['false_positive_probability'] = avg_fp_prob
        
        return false_positive_check
    
    def _check_security_standards(self, network_info, predictions: Dict) -> Dict[str, Any]:
        """Check predictions against established security standards"""
        standards_check = {
            'encryption_assessment': 'UNKNOWN',
            'security_compliance': {},
            'standard_based_risk': 'UNKNOWN'
        }
        
        encryption = str(network_info.encryption_type or '').upper()
        
        # Assess encryption according to security standards
        if 'WPA3' in encryption:
            standards_check['encryption_assessment'] = 'EXCELLENT'
            standards_check['standard_based_risk'] = 'VERY_LOW'
        elif 'WPA2' in encryption or 'CCMP' in encryption:
            standards_check['encryption_assessment'] = 'GOOD'
            standards_check['standard_based_risk'] = 'LOW'
        elif 'WPA' in encryption:
            standards_check['encryption_assessment'] = 'FAIR'
            standards_check['standard_based_risk'] = 'MEDIUM'
        elif 'WEP' in encryption:
            standards_check['encryption_assessment'] = 'POOR'
            standards_check['standard_based_risk'] = 'HIGH'
        elif 'OPEN' in encryption:
            standards_check['encryption_assessment'] = 'NONE'
            standards_check['standard_based_risk'] = 'VERY_HIGH'
        
        # Check compliance with security standards
        standards_check['security_compliance'] = {
            'modern_encryption': 'WPA2' in encryption or 'WPA3' in encryption,
            'strong_signal': network_info.signal_strength > -70,
            'standard_channel': 1 <= network_info.channel <= 11,
            'pmf_capable': 'CCMP' in encryption
        }
        
        return standards_check
    
    def _validate_behavioral_predictions(self, network_info, predictions: Dict) -> Dict[str, Any]:
        """Validate behavioral threat predictions"""
        behavioral_validation = {
            'behavioral_consistency': True,
            'traffic_analysis_required': False,
            'behavioral_concerns': []
        }
        
        individual_preds = predictions.get('individual_predictions', {})
        behavioral_models = ['lstm', 'lstm_main', 'lstm_production', 'cnn_lstm_hybrid']
        
        behavioral_predictions = {
            model: pred for model, pred in individual_preds.items() 
            if any(bm in model.lower() for bm in behavioral_models)
        }
        
        # Check if behavioral predictions make sense for a home network
        concerning_behaviors = []
        for model_name, pred in behavioral_predictions.items():
            pred_class = pred.get('predicted_class', 'UNKNOWN')
            confidence = pred.get('confidence', 0.0)
            
            if pred_class in ['BOTNET_ACTIVITY', 'LATERAL_MOVEMENT', 'DATA_EXFILTRATION']:
                if confidence > 0.5:
                    concerning_behaviors.append({
                        'model': model_name,
                        'behavior': pred_class,
                        'confidence': confidence
                    })
        
        if concerning_behaviors:
            behavioral_validation['behavioral_consistency'] = False
            behavioral_validation['traffic_analysis_required'] = True
            behavioral_validation['behavioral_concerns'] = concerning_behaviors
        
        return behavioral_validation
    
    def _get_expected_encryption_score(self, encryption: str) -> float:
        """Get expected encryption strength score"""
        if 'WPA3' in encryption:
            return 1.0
        elif 'WPA2' in encryption or 'CCMP' in encryption:
            return 0.8
        elif 'WPA' in encryption:
            return 0.4
        elif 'WEP' in encryption:
            return 0.2
        else:  # OPEN
            return 0.0
    
    def _calculate_overall_confidence(self, *validation_results) -> Dict[str, Any]:
        """Calculate overall confidence in predictions"""
        confidence_factors = []
        
        # Real data verification
        if validation_results[0]['using_real_data']:
            confidence_factors.append(0.9)
        else:
            confidence_factors.append(0.1)
        
        # Feature consistency
        if validation_results[1]['consistent']:
            confidence_factors.append(0.8)
        else:
            confidence_factors.append(0.3)
        
        # Profile validation
        profile_match = validation_results[2]['profile_match_score']
        confidence_factors.append(profile_match)
        
        # False positive check
        fp_prob = validation_results[3]['false_positive_probability']
        confidence_factors.append(max(0, 1.0 - fp_prob))
        
        overall_confidence = np.mean(confidence_factors)
        
        return {
            'overall_confidence_score': overall_confidence,
            'confidence_level': self._get_confidence_level(overall_confidence),
            'reliability_factors': {
                'real_data_usage': confidence_factors[0],
                'feature_consistency': confidence_factors[1],
                'profile_match': confidence_factors[2],
                'false_positive_resistance': confidence_factors[3]
            }
        }
    
    def _get_confidence_level(self, score: float) -> str:
        """Get confidence level description"""
        if score >= 0.9:
            return 'VERY_HIGH'
        elif score >= 0.7:
            return 'HIGH'
        elif score >= 0.5:
            return 'MEDIUM'
        elif score >= 0.3:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _generate_validation_recommendations(self, real_data_check: Dict, 
                                           profile_validation: Dict,
                                           false_positive_check: Dict) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        if not real_data_check['using_real_data']:
            recommendations.append("❌ CRITICAL: AI models may not be using real WiFi data - validate feature extraction")
        
        if false_positive_check['false_positive_probability'] > 0.7:
            recommendations.append("⚠️ WARNING: High probability of false positive predictions detected")
        
        if profile_validation['unexpected_predictions']:
            recommendations.append("🔍 INVESTIGATE: Unexpected high-threat predictions on legitimate network")
            recommendations.append("💡 SUGGESTION: Perform manual traffic analysis to verify behavioral predictions")
        
        if not recommendations:
            recommendations.append("✅ Predictions appear to be using real data and are reasonably consistent")
        
        return recommendations
    
    def generate_validation_report(self, validation_result: Dict) -> str:
        """Generate human-readable validation report"""
        report = f"""
🔍 WiFi AI Prediction Validation Report
=====================================

Network: {validation_result['network_analyzed']['ssid']} ({validation_result['network_analyzed']['bssid']})
Encryption: {validation_result['network_analyzed']['encryption']}
Signal: {validation_result['network_analyzed']['signal_strength']}dBm
Channel: {validation_result['network_analyzed']['channel']}

Real Data Verification: {'✅ PASS' if validation_result['real_data_verification']['using_real_data'] else '❌ FAIL'}
Feature Consistency: {'✅ PASS' if validation_result['feature_consistency']['consistent'] else '❌ FAIL'}
Profile Match Score: {validation_result['profile_validation']['profile_match_score']:.2f}
False Positive Risk: {validation_result['false_positive_check']['false_positive_probability']:.2f}

Overall Confidence: {validation_result['overall_confidence']['confidence_level']} ({validation_result['overall_confidence']['overall_confidence_score']:.2f})

Recommendations:
{chr(10).join('• ' + rec for rec in validation_result['recommendations'])}
"""
        return report

# Global validator instance
prediction_validator = WiFiPredictionValidator()