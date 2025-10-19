"""
Wi-Fi Security System - Risk Assessment Module (FIXED)
app/ai_engine/risk_assessor.py

Purpose: Calculate risk scores and categorize threats based on AI model predictions
Author: Wi-Fi Security System Development Team
Version: 1.1 (Fixed)
"""

import logging
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from enum import Enum
from dataclasses import dataclass
import json
from datetime import datetime, timedelta

# Configure logging
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration"""
    NORMAL = "NORMAL"
    LOW_RISK = "LOW_RISK"
    HIGH_RISK = "HIGH_RISK"

class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"

@dataclass
class RiskMetrics:
    """Risk metrics container"""
    overall_score: float
    vulnerability_score: float
    threat_score: float
    confidence_score: float
    temporal_risk: float
    network_risk: float
    crypto_risk: float
    risk_level: RiskLevel  # ADD THIS LINE
    risk_factors: List[str]  # ADD THIS LINE
    timestamp: str  # ADD THIS LINE

@dataclass
class ThreatDetails:
    """Threat details container"""
    threat_type: str
    severity: ThreatSeverity
    confidence: float
    description: str
    impact: str
    likelihood: float

class RiskCategory:
    """Risk categorization system"""
    
    def __init__(self):
        # Risk thresholds based on ensemble model outputs
        self.HIGH_RISK_THRESHOLD = 0.75
        self.LOW_RISK_THRESHOLD = 0.35
        
        # Threat category mappings from ensemble model (20 categories)
        self.threat_categories = {
            0: ("NO_THREAT", ThreatSeverity.MINIMAL),
            1: ("LOW_RISK_VULNERABILITY", ThreatSeverity.LOW),
            2: ("MEDIUM_RISK_VULNERABILITY", ThreatSeverity.MEDIUM),
            3: ("HIGH_RISK_VULNERABILITY", ThreatSeverity.HIGH),
            4: ("CRITICAL_VULNERABILITY", ThreatSeverity.CRITICAL),
            5: ("ACTIVE_ATTACK_DETECTED", ThreatSeverity.CRITICAL),
            6: ("RECONNAISSANCE_PHASE", ThreatSeverity.MEDIUM),
            7: ("CREDENTIAL_COMPROMISE", ThreatSeverity.HIGH),
            8: ("DATA_BREACH_RISK", ThreatSeverity.HIGH),
            9: ("NETWORK_COMPROMISE", ThreatSeverity.CRITICAL),
            10: ("INSIDER_THREAT_DETECTED", ThreatSeverity.HIGH),
            11: ("APT_CAMPAIGN", ThreatSeverity.CRITICAL),
            12: ("RANSOMWARE_INDICATORS", ThreatSeverity.CRITICAL),
            13: ("BOTNET_PARTICIPATION", ThreatSeverity.HIGH),
            14: ("CRYPTO_WEAKNESS", ThreatSeverity.MEDIUM),
            15: ("FIRMWARE_EXPLOIT", ThreatSeverity.HIGH),
            16: ("CONFIGURATION_ERROR", ThreatSeverity.LOW),
            17: ("COMPLIANCE_VIOLATION", ThreatSeverity.MEDIUM),
            18: ("ANOMALOUS_BEHAVIOR", ThreatSeverity.MEDIUM),
            19: ("SYSTEM_COMPROMISE", ThreatSeverity.CRITICAL)
        }
        
        # Individual model threat mappings
        self.cnn_threats = {
            0: ("SECURE_NETWORK", ThreatSeverity.MINIMAL),
            1: ("WEAK_ENCRYPTION", ThreatSeverity.MEDIUM),
            2: ("OPEN_NETWORK", ThreatSeverity.HIGH),
            3: ("WPS_VULNERABILITY", ThreatSeverity.MEDIUM),
            4: ("ROGUE_AP", ThreatSeverity.HIGH),
            5: ("EVIL_TWIN", ThreatSeverity.CRITICAL),
            6: ("DEAUTH_ATTACK", ThreatSeverity.HIGH),
            7: ("HANDSHAKE_CAPTURE", ThreatSeverity.MEDIUM),
            8: ("FIRMWARE_OUTDATED", ThreatSeverity.MEDIUM),
            9: ("DEFAULT_CREDENTIALS", ThreatSeverity.HIGH),
            10: ("SIGNAL_LEAKAGE", ThreatSeverity.LOW),
            11: ("UNKNOWN_THREAT", ThreatSeverity.MEDIUM)
        }
        
        self.lstm_threats = {
            0: ("NORMAL_BEHAVIOR", ThreatSeverity.MINIMAL),
            1: ("BRUTE_FORCE_ATTACK", ThreatSeverity.HIGH),
            2: ("RECONNAISSANCE", ThreatSeverity.MEDIUM),
            3: ("DATA_EXFILTRATION", ThreatSeverity.CRITICAL),
            4: ("BOTNET_ACTIVITY", ThreatSeverity.HIGH),
            5: ("INSIDER_THREAT", ThreatSeverity.HIGH),
            6: ("APT_BEHAVIOR", ThreatSeverity.CRITICAL),
            7: ("DDOS_PREPARATION", ThreatSeverity.HIGH),
            8: ("LATERAL_MOVEMENT", ThreatSeverity.HIGH),
            9: ("COMMAND_CONTROL", ThreatSeverity.CRITICAL)
        }
        
        self.gnn_threats = {
            0: ("ISOLATED_VULNERABILITY", ThreatSeverity.LOW),
            1: ("CASCADING_RISK", ThreatSeverity.HIGH),
            2: ("CRITICAL_NODE", ThreatSeverity.CRITICAL),
            3: ("BRIDGE_VULNERABILITY", ThreatSeverity.HIGH),
            4: ("CLUSTER_WEAKNESS", ThreatSeverity.MEDIUM),
            5: ("PERIMETER_BREACH", ThreatSeverity.CRITICAL),
            6: ("PRIVILEGE_ESCALATION", ThreatSeverity.HIGH),
            7: ("NETWORK_PARTITION", ThreatSeverity.MEDIUM)
        }

    def categorize_risk(self, risk_score: float) -> RiskLevel:
        """Categorize risk based on score"""
        try:
            risk_score = float(risk_score)
            if risk_score >= self.HIGH_RISK_THRESHOLD:
                return RiskLevel.HIGH_RISK
            elif risk_score >= self.LOW_RISK_THRESHOLD:
                return RiskLevel.LOW_RISK
            else:
                return RiskLevel.NORMAL
        except (ValueError, TypeError):
            return RiskLevel.LOW_RISK

    def get_threat_details(self, prediction_class: int, model_type: str = "ensemble") -> ThreatDetails:
        """Get threat details for a prediction class"""
        try:
            prediction_class = int(prediction_class)
            
            if model_type == "ensemble":
                threat_name, severity = self.threat_categories.get(prediction_class, ("UNKNOWN", ThreatSeverity.MEDIUM))
            elif model_type == "cnn":
                threat_name, severity = self.cnn_threats.get(prediction_class, ("UNKNOWN", ThreatSeverity.MEDIUM))
            elif model_type == "lstm":
                threat_name, severity = self.lstm_threats.get(prediction_class, ("UNKNOWN", ThreatSeverity.MEDIUM))
            elif model_type == "gnn":
                threat_name, severity = self.gnn_threats.get(prediction_class, ("UNKNOWN", ThreatSeverity.MEDIUM))
            else:
                threat_name, severity = ("UNKNOWN", ThreatSeverity.MEDIUM)
            
            return ThreatDetails(
                threat_type=threat_name,
                severity=severity,
                confidence=0.0,  # Will be updated by caller
                description=self._get_threat_description(threat_name),
                impact=self._get_threat_impact(threat_name),
                likelihood=self._calculate_likelihood(severity)
            )
        except Exception as e:
            logger.error(f"Error getting threat details: {str(e)}")
            return ThreatDetails(
                threat_type="UNKNOWN",
                severity=ThreatSeverity.MEDIUM,
                confidence=0.0,
                description="Unknown threat detected",
                impact="Potential security risk",
                likelihood=0.5
            )

    def _get_threat_description(self, threat_name: str) -> str:
        """Get threat description"""
        descriptions = {
            "NO_THREAT": "No security threats detected in the network",
            "LOW_RISK_VULNERABILITY": "Minor security vulnerability with limited impact",
            "MEDIUM_RISK_VULNERABILITY": "Moderate security vulnerability requiring attention",
            "HIGH_RISK_VULNERABILITY": "Serious security vulnerability requiring immediate action",
            "CRITICAL_VULNERABILITY": "Critical security flaw requiring urgent remediation",
            "ACTIVE_ATTACK_DETECTED": "Active malicious attack in progress",
            "RECONNAISSANCE_PHASE": "Network reconnaissance activity detected",
            "CREDENTIAL_COMPROMISE": "Compromised credentials detected",
            "DATA_BREACH_RISK": "High risk of data breach",
            "NETWORK_COMPROMISE": "Network infrastructure compromised",
            "INSIDER_THREAT_DETECTED": "Malicious insider activity detected",
            "APT_CAMPAIGN": "Advanced Persistent Threat campaign identified",
            "RANSOMWARE_INDICATORS": "Ransomware attack indicators present",
            "BOTNET_PARTICIPATION": "Device participating in botnet",
            "CRYPTO_WEAKNESS": "Cryptographic vulnerability detected",
            "FIRMWARE_EXPLOIT": "Firmware vulnerability being exploited",
            "CONFIGURATION_ERROR": "Security misconfiguration detected",
            "COMPLIANCE_VIOLATION": "Security policy violation",
            "ANOMALOUS_BEHAVIOR": "Unusual network behavior pattern",
            "SYSTEM_COMPROMISE": "Complete system compromise detected",
            "SECURE_NETWORK": "Network appears secure",
            "WEAK_ENCRYPTION": "Weak encryption protocols in use",
            "OPEN_NETWORK": "Unencrypted network access point",
            "WPS_VULNERABILITY": "WPS vulnerability detected",
            "ROGUE_AP": "Unauthorized access point detected",
            "EVIL_TWIN": "Malicious duplicate network detected",
            "DEAUTH_ATTACK": "Deauthentication attack in progress",
            "HANDSHAKE_CAPTURE": "WPA handshake capture vulnerability",
            "FIRMWARE_OUTDATED": "Outdated firmware with known vulnerabilities",
            "DEFAULT_CREDENTIALS": "Default administrative credentials in use",
            "SIGNAL_LEAKAGE": "Network signal extending beyond secure perimeter",
            "NORMAL_BEHAVIOR": "Normal network behavior patterns",
            "BRUTE_FORCE_ATTACK": "Brute force password attack detected",
            "RECONNAISSANCE": "Network scanning and reconnaissance",
            "DATA_EXFILTRATION": "Suspicious data transfer patterns",
            "BOTNET_ACTIVITY": "Automated malicious behavior",
            "INSIDER_THREAT": "Suspicious internal user activity",
            "APT_BEHAVIOR": "Advanced persistent threat behavior",
            "DDOS_PREPARATION": "DDoS attack preparation detected",
            "LATERAL_MOVEMENT": "Unauthorized network traversal",
            "COMMAND_CONTROL": "Command and control communication",
            "ISOLATED_VULNERABILITY": "Single point of failure vulnerability",
            "CASCADING_RISK": "Multi-hop vulnerability chain",
            "CRITICAL_NODE": "Critical network node compromise",
            "BRIDGE_VULNERABILITY": "Network bridge security risk",
            "CLUSTER_WEAKNESS": "Device cluster vulnerability",
            "PERIMETER_BREACH": "Network perimeter security breach",
            "PRIVILEGE_ESCALATION": "Unauthorized privilege escalation path",
            "NETWORK_PARTITION": "Network isolation bypass potential"
        }
        return descriptions.get(threat_name, "Unknown security threat")

    def _get_threat_impact(self, threat_name: str) -> str:
        """Get threat impact description"""
        impacts = {
            "CRITICAL_VULNERABILITY": "Complete system compromise possible",
            "ACTIVE_ATTACK_DETECTED": "Immediate data loss or system damage",
            "NETWORK_COMPROMISE": "Full network infrastructure at risk",
            "APT_CAMPAIGN": "Long-term persistent access and data theft",
            "RANSOMWARE_INDICATORS": "Data encryption and ransom demands",
            "SYSTEM_COMPROMISE": "Complete loss of system integrity",
            "DATA_BREACH_RISK": "Sensitive data exposure and theft",
            "CREDENTIAL_COMPROMISE": "Unauthorized system access",
            "HIGH_RISK_VULNERABILITY": "Significant security breach potential",
            "INSIDER_THREAT_DETECTED": "Internal data theft or sabotage",
            "BOTNET_PARTICIPATION": "Resource hijacking and malicious activity",
            "FIRMWARE_EXPLOIT": "Device control and persistent access",
            "EVIL_TWIN": "Credential theft and man-in-the-middle attacks",
            "OPEN_NETWORK": "Unencrypted data transmission exposure",
            "DEFAULT_CREDENTIALS": "Easy unauthorized access",
            "MEDIUM_RISK_VULNERABILITY": "Moderate security exposure",
            "WEAK_ENCRYPTION": "Data interception vulnerability",
            "CONFIGURATION_ERROR": "Security policy bypass",
            "LOW_RISK_VULNERABILITY": "Limited security exposure",
            "SIGNAL_LEAKAGE": "Information disclosure beyond premises"
        }
        return impacts.get(threat_name, "Potential security impact")

    def _calculate_likelihood(self, severity: ThreatSeverity) -> float:
        """Calculate threat likelihood based on severity"""
        likelihood_map = {
            ThreatSeverity.CRITICAL: 0.9,
            ThreatSeverity.HIGH: 0.7,
            ThreatSeverity.MEDIUM: 0.5,
            ThreatSeverity.LOW: 0.3,
            ThreatSeverity.MINIMAL: 0.1
        }
        return likelihood_map.get(severity, 0.5)

class RiskAssessor:
    """Main risk assessment engine"""
    
    def __init__(self):
        self.risk_category = RiskCategory()
        self.risk_weights = {
            'vulnerability': 0.25,
            'threat': 0.25,
            'temporal': 0.20,
            'network': 0.15,
            'crypto': 0.15
        }
        self.historical_risks = []
        self.baseline_risk = 0.1  # Baseline risk level
        
    
    def calculate_risk_score(self, prediction: Dict[str, Any], confidence: float) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment with detailed analysis - Updated to match ensemble methodology"""
        try:
            predicted_class = prediction.get('predicted_class', 'NO_THREAT')
            class_index = prediction.get('class_index', 0)
            probabilities = prediction.get('probability_distribution', [])
            
            # Get base risk level using ensemble-style mapping
            base_risk_level = self.threat_risk_mapping.get(predicted_class, 'LOW_RISK')
            base_risk_score = self.risk_levels[base_risk_level]
            
            # Confidence-adjusted risk calculation (matching ensemble methodology)
            confidence_multiplier = min(confidence * 1.5, 1.0)  # Cap at 1.0
            adjusted_risk_score = base_risk_score * confidence_multiplier
            
            # Critical threat probability analysis
            critical_threat_prob = self._calculate_critical_threat_probability(probabilities)
            
            # Final risk score (0-10 scale) - ensemble methodology
            final_risk_score = min((adjusted_risk_score * 2.0) + (critical_threat_prob * 3.0), 10.0)
            
            # Determine final risk level using ensemble thresholds
            final_risk_level = self._determine_risk_level_ensemble_style(final_risk_score)
            
            # Generate comprehensive risk assessment (ensemble format)
            risk_assessment = {
                'risk_level': final_risk_level,
                'risk_score': round(final_risk_score, 2),
                'base_risk_score': base_risk_score,
                'confidence_adjusted_score': round(adjusted_risk_score, 2),
                'critical_threat_probability': round(critical_threat_prob, 3),
                'risk_factors': self._identify_risk_factors_ensemble_style(predicted_class, confidence, probabilities),
                'threat_severity': self._assess_threat_severity_ensemble_style(predicted_class),
                'urgency_level': self._determine_urgency_ensemble_style(final_risk_level, confidence),
                'impact_assessment': self._assess_potential_impact_ensemble_style(predicted_class),
                'mitigation_priority': self._determine_mitigation_priority(final_risk_level, predicted_class),
                'business_impact': self._assess_business_impact(predicted_class, confidence),
                'compliance_impact': self._assess_compliance_impact(predicted_class),
                'assessment_timestamp': datetime.now().isoformat(),
                'assessment_version': '2.0'
            }
            
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return self._generate_error_risk_assessment(str(e))
    
    def _calculate_critical_threat_probability(self, probabilities: List[float]) -> float:
        """Calculate probability of critical threats - Ensemble methodology"""
        try:
            if not probabilities or len(probabilities) < 20:
                return 0.0
            
            # Critical threat indices (based on 20-class system from ensemble)
            critical_indices = [4, 5, 8, 9, 11, 12, 19]  # CRITICAL_VULNERABILITY, ACTIVE_ATTACK, etc.
            
            critical_prob = sum(probabilities[i] for i in critical_indices if i < len(probabilities))
            return min(critical_prob, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating critical threat probability: {str(e)}")
            return 0.0
    
    def _determine_risk_level_ensemble_style(self, risk_score: float) -> str:
        """Determine risk level from numerical score - Ensemble methodology"""
        if risk_score >= 8.5:
            return 'CRITICAL_RISK'
        elif risk_score >= 6.5:
            return 'HIGH_RISK'
        elif risk_score >= 4.0:
            return 'MEDIUM_RISK'
        elif risk_score >= 1.5:
            return 'LOW_RISK'
        else:
            return 'NO_RISK'
    
    def _identify_risk_factors_ensemble_style(self, predicted_class: str, confidence: float, 
                             probabilities: List[float]) -> List[str]:
        """Identify specific risk factors - Ensemble methodology"""
        risk_factors = []
        
        try:
            # Confidence-based factors (ensemble thresholds)
            if confidence > 0.95:
                risk_factors.append("Very high prediction confidence")
            elif confidence > 0.82:
                risk_factors.append("High prediction confidence")
            elif confidence < 0.6:
                risk_factors.append("Low prediction confidence - requires verification")
            
            # Threat-specific factors (ensemble mapping)
            threat_factors = {
                'ACTIVE_ATTACK_DETECTED': "Real-time attack activity identified",
                'CRITICAL_VULNERABILITY': "Critical system weakness found",
                'DATA_BREACH_RISK': "Potential data exposure detected",
                'NETWORK_COMPROMISE': "Network integrity compromised",
                'CREDENTIAL_COMPROMISE': "Authentication credentials at risk",
                'APT_CAMPAIGN': "Advanced persistent threat indicators",
                'RANSOMWARE_INDICATORS': "Ransomware attack patterns detected",
                'INSIDER_THREAT_DETECTED': "Malicious insider activity suspected",
                'BOTNET_PARTICIPATION': "System participating in botnet",
                'CRYPTO_WEAKNESS': "Cryptographic implementation flaws",
                'FIRMWARE_EXPLOIT': "Firmware-level security breach",
                'SYSTEM_COMPROMISE': "Complete system takeover detected"
            }
            
            if predicted_class in threat_factors:
                risk_factors.append(threat_factors[predicted_class])
            
            # Probability distribution analysis (ensemble methodology)
            if probabilities and len(probabilities) >= 20:
                max_prob = max(probabilities)
                if max_prob > 0.8:
                    risk_factors.append("Strong probability concentration")
                
                # Check for multiple high-probability threats
                high_prob_count = sum(1 for prob in probabilities if prob > 0.3)
                if high_prob_count > 1:
                    risk_factors.append("Multiple potential threats detected")
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Error identifying risk factors: {str(e)}")
            return ["Risk factor analysis failed"]
    
    def _assess_threat_severity_ensemble_style(self, predicted_class: str) -> str:
        """Assess threat severity level - Ensemble methodology"""
        critical_threats = [
            'ACTIVE_ATTACK_DETECTED', 'DATA_BREACH_RISK', 'NETWORK_COMPROMISE',
            'APT_CAMPAIGN', 'RANSOMWARE_INDICATORS', 'SYSTEM_COMPROMISE'
        ]
        
        high_threats = [
            'CRITICAL_VULNERABILITY', 'CREDENTIAL_COMPROMISE', 'INSIDER_THREAT_DETECTED',
            'BOTNET_PARTICIPATION', 'FIRMWARE_EXPLOIT'
        ]
        
        medium_threats = [
            'HIGH_RISK_VULNERABILITY', 'RECONNAISSANCE_PHASE', 'CRYPTO_WEAKNESS',
            'COMPLIANCE_VIOLATION', 'ANOMALOUS_BEHAVIOR'
        ]
        
        if predicted_class in critical_threats:
            return 'CRITICAL'
        elif predicted_class in high_threats:
            return 'HIGH'
        elif predicted_class in medium_threats:
            return 'MEDIUM'
        elif predicted_class in ['MEDIUM_RISK_VULNERABILITY', 'CONFIGURATION_ERROR']:
            return 'MEDIUM'
        elif predicted_class == 'LOW_RISK_VULNERABILITY':
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _determine_urgency_ensemble_style(self, risk_level: str, confidence: float) -> str:
        """Determine response urgency level - Ensemble methodology"""
        if risk_level == 'CRITICAL_RISK' and confidence > 0.9:
            return 'IMMEDIATE'
        elif risk_level == 'CRITICAL_RISK':
            return 'URGENT'
        elif risk_level == 'HIGH_RISK' and confidence > 0.85:
            return 'URGENT'
        elif risk_level == 'HIGH_RISK':
            return 'HIGH'
        elif risk_level == 'MEDIUM_RISK':
            return 'MEDIUM'
        elif risk_level == 'LOW_RISK':
            return 'LOW'
        else:
            return 'ROUTINE'
    
    def _assess_potential_impact_ensemble_style(self, predicted_class: str) -> Dict[str, str]:
        """Assess potential impact across CIA triad - Ensemble methodology"""
        impact = {
            'confidentiality': 'LOW',
            'integrity': 'LOW',
            'availability': 'LOW',
            'business_impact': 'LOW'
        }
        
        # High confidentiality impact
        confidentiality_threats = [
            'DATA_BREACH_RISK', 'CREDENTIAL_COMPROMISE', 'INSIDER_THREAT_DETECTED',
            'APT_CAMPAIGN', 'RECONNAISSANCE_PHASE'
        ]
        
        # High integrity impact
        integrity_threats = [
            'ACTIVE_ATTACK_DETECTED', 'SYSTEM_COMPROMISE', 'FIRMWARE_EXPLOIT',
            'NETWORK_COMPROMISE', 'RANSOMWARE_INDICATORS'
        ]
        
        # High availability impact
        availability_threats = [
            'RANSOMWARE_INDICATORS', 'BOTNET_PARTICIPATION', 'NETWORK_COMPROMISE',
            'SYSTEM_COMPROMISE'
        ]
        
        if predicted_class in confidentiality_threats:
            impact['confidentiality'] = 'HIGH'
            impact['business_impact'] = 'HIGH'
        
        if predicted_class in integrity_threats:
            impact['integrity'] = 'HIGH'
            impact['business_impact'] = 'HIGH'
        
        if predicted_class in availability_threats:
            impact['availability'] = 'HIGH'
            impact['business_impact'] = 'HIGH'
        
        # Critical vulnerabilities affect all areas
        if predicted_class in ['CRITICAL_VULNERABILITY', 'APT_CAMPAIGN']:
            impact = {
                'confidentiality': 'HIGH',
                'integrity': 'HIGH',
                'availability': 'MEDIUM',
                'business_impact': 'HIGH'
            }
        
        return impact
    
    def _determine_mitigation_priority(self, risk_level: str, predicted_class: str) -> str:
        """Determine mitigation priority - Ensemble methodology"""
        if risk_level == 'CRITICAL_RISK':
            return 'IMMEDIATE'
        elif risk_level == 'HIGH_RISK':
            return 'HIGH'
        elif risk_level == 'MEDIUM_RISK':
            return 'MEDIUM'
        elif risk_level == 'LOW_RISK':
            return 'LOW'
        else:
            return 'ROUTINE'
    
    def _assess_business_impact(self, predicted_class: str, confidence: float) -> str:
        """Assess business impact - Ensemble methodology"""
        high_impact_threats = [
            'ACTIVE_ATTACK_DETECTED', 'DATA_BREACH_RISK', 'NETWORK_COMPROMISE',
            'APT_CAMPAIGN', 'RANSOMWARE_INDICATORS', 'SYSTEM_COMPROMISE'
        ]
        
        if predicted_class in high_impact_threats and confidence > 0.8:
            return 'HIGH'
        elif predicted_class in high_impact_threats:
            return 'MEDIUM'
        elif confidence > 0.9:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_compliance_impact(self, predicted_class: str) -> str:
        """Assess compliance impact - Ensemble methodology"""
        compliance_relevant = [
            'DATA_BREACH_RISK', 'CREDENTIAL_COMPROMISE', 'COMPLIANCE_VIOLATION',
            'CRYPTO_WEAKNESS', 'CONFIGURATION_ERROR'
        ]
        
        if predicted_class in compliance_relevant:
            return 'HIGH'
        elif predicted_class != 'NO_THREAT':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_error_risk_assessment(self, error_msg: str) -> Dict[str, Any]:
        """Generate error risk assessment - Ensemble methodology"""
        return {
            'risk_level': 'LOW_RISK',
            'risk_score': 1.0,
            'base_risk_score': 0,
            'confidence_adjusted_score': 0.5,
            'critical_threat_probability': 0.0,
            'risk_factors': [f"Risk assessment error: {error_msg}"],
            'threat_severity': 'MINIMAL',
            'urgency_level': 'ROUTINE',
            'impact_assessment': {
                'confidentiality': 'LOW',
                'integrity': 'LOW',
                'availability': 'LOW',
                'business_impact': 'LOW'
            },
            'mitigation_priority': 'LOW',
            'business_impact': 'LOW',
            'compliance_impact': 'LOW',
            'assessment_timestamp': datetime.now().isoformat(),
            'assessment_version': '2.0',
            'error': True
        }
    
    # Add ensemble-style risk mapping
    @property 
    def threat_risk_mapping(self):
        """Threat class to risk level mapping - Ensemble methodology"""
        return {
            'NO_THREAT': 'NO_RISK',
            'LOW_RISK_VULNERABILITY': 'LOW_RISK',
            'MEDIUM_RISK_VULNERABILITY': 'MEDIUM_RISK',
            'HIGH_RISK_VULNERABILITY': 'HIGH_RISK',
            'CRITICAL_VULNERABILITY': 'CRITICAL_RISK',
            'ACTIVE_ATTACK_DETECTED': 'CRITICAL_RISK',
            'RECONNAISSANCE_PHASE': 'MEDIUM_RISK',
            'CREDENTIAL_COMPROMISE': 'HIGH_RISK',
            'DATA_BREACH_RISK': 'CRITICAL_RISK',
            'NETWORK_COMPROMISE': 'CRITICAL_RISK',
            'INSIDER_THREAT_DETECTED': 'HIGH_RISK',
            'APT_CAMPAIGN': 'CRITICAL_RISK',
            'RANSOMWARE_INDICATORS': 'CRITICAL_RISK',
            'BOTNET_PARTICIPATION': 'HIGH_RISK',
            'CRYPTO_WEAKNESS': 'MEDIUM_RISK',
            'FIRMWARE_EXPLOIT': 'HIGH_RISK',
            'CONFIGURATION_ERROR': 'LOW_RISK',
            'COMPLIANCE_VIOLATION': 'MEDIUM_RISK',
            'ANOMALOUS_BEHAVIOR': 'MEDIUM_RISK',
            'SYSTEM_COMPROMISE': 'CRITICAL_RISK'
        }
    
    @property
    def risk_levels(self):
        """Risk level numeric mappings - Ensemble methodology"""
        return {
            'NO_RISK': 0,
            'LOW_RISK': 1,
            'MEDIUM_RISK': 2,
            'HIGH_RISK': 3,
            'CRITICAL_RISK': 4
        }
            
    def _generate_risk_factors(self, model_predictions: Dict[str, Any], overall_score: float) -> List[str]:
        """Generate list of contributing risk factors"""
        try:
            risk_factors = []
            
            # Analyze each model's contribution
            for model_name, prediction_data in model_predictions.items():
                if not isinstance(prediction_data, dict):
                    continue
                    
                confidence = prediction_data.get('confidence', 0.0)
                class_index = prediction_data.get('class_index', prediction_data.get('predicted_class', 0))
                
                if isinstance(confidence, (int, float)) and float(confidence) > 0.7:
                    if model_name == 'cnn' and isinstance(class_index, (int, float)):
                        class_idx = int(class_index)
                        if class_idx > 0:
                            risk_factors.append(f"Network vulnerability detected (CNN model, class {class_idx})")
                    elif model_name == 'lstm' and isinstance(class_index, (int, float)):
                        class_idx = int(class_index)
                        if class_idx > 0:
                            risk_factors.append(f"Suspicious behavior pattern (LSTM model, class {class_idx})")
                    elif model_name == 'gnn' and isinstance(class_index, (int, float)):
                        class_idx = int(class_index)
                        if class_idx > 0:
                            risk_factors.append(f"Network topology risk (GNN model, class {class_idx})")
                    elif model_name == 'crypto_bert' and isinstance(class_index, (int, float)):
                        class_idx = int(class_index)
                        if class_idx > 0:
                            risk_factors.append(f"Cryptographic weakness (BERT model, class {class_idx})")
            
            # Add overall risk assessment
            if float(overall_score) > 0.75:
                risk_factors.append("High security risk detected")
            elif float(overall_score) > 0.35:
                risk_factors.append("Medium security concern identified")
            elif float(overall_score) > 0.1:
                risk_factors.append("Low-level security concerns detected")
            else:
                risk_factors.append("No significant security risks detected")
            
            return risk_factors[:5]  # Limit to top 5 factors
            
        except Exception as e:
            logger.error(f"Error generating risk factors: {str(e)}")
            return ["Risk assessment completed with limited information"]

    def _calculate_vulnerability_score(self, cnn_pred: Dict, ensemble_pred: Dict) -> float:
        """Calculate vulnerability risk score - FIXED"""
        try:
            # Get predictions with proper fallback
            cnn_class = cnn_pred.get('predicted_class', cnn_pred.get('class_index', 0))
            cnn_confidence = cnn_pred.get('confidence', 0.0)
            
            # Convert to proper types
            try:
                cnn_class = int(cnn_class)
                cnn_confidence = float(cnn_confidence)
            except (ValueError, TypeError):
                cnn_class = 0
                cnn_confidence = 0.0
            
            # Calculate base vulnerability score from class and confidence
            vuln_score = 0.0
            
            # CNN class-based risk scoring (based on your PDF documentation)
            # High risk vulnerability classes from CNN model (12 classes total)
            high_risk_classes = {
                2: 0.8,   # OPEN_NETWORK
                4: 0.9,   # ROGUE_AP  
                5: 0.9,   # EVIL_TWIN
                6: 0.7,   # DEAUTH_ATTACK
                9: 0.8    # DEFAULT_CREDENTIALS
            }
            
            medium_risk_classes = {
                1: 0.6,   # WEAK_ENCRYPTION
                3: 0.5,   # WPS_VULNERABILITY
                7: 0.6,   # HANDSHAKE_CAPTURE
                8: 0.7,   # FIRMWARE_OUTDATED
                10: 0.4,  # SIGNAL_LEAKAGE
                11: 0.6   # UNKNOWN_THREAT
            }
            
            # Calculate risk based on predicted class
            if cnn_class in high_risk_classes:
                vuln_score = high_risk_classes[cnn_class] * cnn_confidence
            elif cnn_class in medium_risk_classes:
                vuln_score = medium_risk_classes[cnn_class] * cnn_confidence
            elif cnn_class == 0:  # SECURE_NETWORK
                vuln_score = 0.1 * cnn_confidence
            else:
                vuln_score = 0.3 * cnn_confidence  # Unknown class, moderate risk
            
            return max(0.0, min(1.0, float(vuln_score)))
            
        except Exception as e:
            logger.error(f"Error calculating vulnerability score: {str(e)}")
            return self.baseline_risk

    def _calculate_threat_score(self, lstm_pred: Dict, ensemble_pred: Dict) -> float:
        """Calculate threat risk score - FIXED"""
        try:
            # Get LSTM predictions
            lstm_class = lstm_pred.get('predicted_class', lstm_pred.get('class_index', 0))
            lstm_confidence = lstm_pred.get('confidence', 0.0)
            
            # Convert to proper types
            try:
                lstm_class = int(lstm_class)
                lstm_confidence = float(lstm_confidence)
            except (ValueError, TypeError):
                lstm_class = 0
                lstm_confidence = 0.0
            
            threat_score = 0.0
            
            # LSTM class-based threat scoring (10 classes total from PDF)
            critical_threats = {
                3: 0.9,   # DATA_EXFILTRATION
                6: 0.9,   # APT_BEHAVIOR
                9: 0.8    # COMMAND_CONTROL
            }
            
            high_threats = {
                1: 0.7,   # BRUTE_FORCE_ATTACK
                4: 0.8,   # BOTNET_ACTIVITY
                5: 0.7,   # INSIDER_THREAT
                7: 0.6,   # DDOS_PREPARATION
                8: 0.7    # LATERAL_MOVEMENT
            }
            
            medium_threats = {
                2: 0.4    # RECONNAISSANCE
            }
            
            # Calculate threat score based on predicted class
            if lstm_class in critical_threats:
                threat_score = critical_threats[lstm_class] * lstm_confidence
            elif lstm_class in high_threats:
                threat_score = high_threats[lstm_class] * lstm_confidence
            elif lstm_class in medium_threats:
                threat_score = medium_threats[lstm_class] * lstm_confidence
            elif lstm_class == 0:  # NORMAL_BEHAVIOR
                threat_score = 0.1 * lstm_confidence
            else:
                threat_score = 0.4 * lstm_confidence  # Unknown class, moderate threat
            
            return max(0.0, min(1.0, float(threat_score)))
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {str(e)}")
            return self.baseline_risk

    def _calculate_temporal_risk(self, lstm_pred: Dict, historical_data: List[Dict] = None) -> float:
        """Calculate temporal risk based on behavior patterns"""
        try:
            temporal_risk = 0.0
            
            # Base temporal risk from LSTM predictions
            lstm_class = lstm_pred.get('predicted_class', lstm_pred.get('class_index', 0))
            lstm_confidence = lstm_pred.get('confidence', 0.5)
            
            # Ensure values are numeric
            try:
                lstm_class = int(lstm_class)
                lstm_confidence = float(lstm_confidence)
            except (ValueError, TypeError):
                lstm_class = 0
                lstm_confidence = 0.5
            
            # Sequential threat indicators increase temporal risk
            sequential_threats = [1, 2, 6, 7]  # BRUTE_FORCE, RECONNAISSANCE, APT_BEHAVIOR, DDOS_PREPARATION
            if lstm_class in sequential_threats:
                temporal_risk += lstm_confidence * 0.7
            
            # Analyze historical patterns if available
            if historical_data and isinstance(historical_data, list) and len(historical_data) > 1:
                try:
                    # Check for escalating threat patterns
                    recent_risks = []
                    for scan in historical_data[-5:]:
                        if isinstance(scan, dict):
                            risk_val = scan.get('risk_score', 0.1)
                            recent_risks.append(float(risk_val))
                    
                    if len(recent_risks) >= 2:
                        risk_trend = (recent_risks[-1] - recent_risks[0]) / len(recent_risks)
                        if risk_trend > 0.1:  # Increasing risk trend
                            temporal_risk += 0.3
                except Exception:
                    pass
            
            return max(0.0, min(1.0, float(temporal_risk)))
            
        except Exception as e:
            logger.error(f"Error calculating temporal risk: {str(e)}")
            return self.baseline_risk

    def _calculate_network_risk(self, gnn_pred: Dict, network_context: Dict = None) -> float:
        """Calculate network topology risk - FIXED"""
        try:
            # Get GNN predictions
            gnn_class = gnn_pred.get('predicted_class', gnn_pred.get('class_index', 0))
            gnn_confidence = gnn_pred.get('confidence', 0.0)
            
            # Convert to proper types
            try:
                gnn_class = int(gnn_class)
                gnn_confidence = float(gnn_confidence)
            except (ValueError, TypeError):
                gnn_class = 0
                gnn_confidence = 0.0
            
            network_risk = 0.0
            
            # GNN class-based network risk scoring (8 classes total from PDF)
            critical_network_classes = {
                1: 0.8,   # CASCADING_RISK
                2: 0.9,   # CRITICAL_NODE
                5: 0.9    # PERIMETER_BREACH
            }
            
            high_network_classes = {
                3: 0.6,   # BRIDGE_VULNERABILITY
                6: 0.7,   # PRIVILEGE_ESCALATION
                4: 0.6,   # CLUSTER_WEAKNESS
                7: 0.5    # NETWORK_PARTITION
            }
            
            # Calculate network risk based on predicted class
            if gnn_class in critical_network_classes:
                network_risk = critical_network_classes[gnn_class] * gnn_confidence
            elif gnn_class in high_network_classes:
                network_risk = high_network_classes[gnn_class] * gnn_confidence
            elif gnn_class == 0:  # ISOLATED_VULNERABILITY
                network_risk = 0.2 * gnn_confidence
            else:
                network_risk = 0.3 * gnn_confidence  # Unknown class
            
            # Consider network context if available
            if network_context and isinstance(network_context, dict):
                try:
                    device_count = int(network_context.get('device_count', 1))
                    if device_count > 10:
                        network_risk *= 1.1
                    
                    open_ports = int(network_context.get('open_ports', 0))
                    if open_ports > 5:
                        network_risk += 0.1
                except (ValueError, TypeError):
                    pass
            
            return max(0.0, min(1.0, float(network_risk)))
            
        except Exception as e:
            logger.error(f"Error calculating network risk: {str(e)}")
            return self.baseline_risk

    def _calculate_crypto_risk(self, crypto_pred: Dict) -> float:
        """Calculate cryptographic risk - FIXED"""
        try:
            # Get crypto predictions  
            crypto_class = crypto_pred.get('predicted_class', crypto_pred.get('class_index', 0))
            crypto_confidence = crypto_pred.get('confidence', 0.0)
            
            # Convert to proper types
            try:
                crypto_class = int(crypto_class)
                crypto_confidence = float(crypto_confidence)
            except (ValueError, TypeError):
                crypto_class = 0
                crypto_confidence = 0.0
            
            crypto_risk = 0.0
            
            # Crypto-BERT class-based risk scoring (15 classes total from PDF)
            critical_crypto = {
                1: 0.8,   # WEAK_CIPHER_SUITE
                2: 0.7,   # CERTIFICATE_INVALID
                5: 0.9,   # MAN_IN_MIDDLE
                8: 0.8,   # QUANTUM_VULNERABLE
                11: 0.7,  # PADDING_ORACLE
                12: 0.6   # LENGTH_EXTENSION
            }
            
            high_crypto = {
                3: 0.6,   # KEY_REUSE
                4: 0.7,   # DOWNGRADE_ATTACK
                6: 0.6,   # REPLAY_ATTACK
                7: 0.5,   # TIMING_ATTACK
                9: 0.6,   # ENTROPY_WEAKNESS
                10: 0.5,  # HASH_COLLISION
                13: 0.6,  # PROTOCOL_CONFUSION
                14: 0.4   # CRYPTO_AGILITY_LACK
            }
            
            # Calculate crypto risk based on predicted class
            if crypto_class in critical_crypto:
                crypto_risk = critical_crypto[crypto_class] * crypto_confidence
            elif crypto_class in high_crypto:
                crypto_risk = high_crypto[crypto_class] * crypto_confidence
            elif crypto_class == 0:  # STRONG_ENCRYPTION
                crypto_risk = 0.1 * crypto_confidence
            else:
                crypto_risk = 0.3 * crypto_confidence  # Unknown class
            
            return max(0.0, min(1.0, float(crypto_risk)))
            
        except Exception as e:
            logger.error(f"Error calculating crypto risk: {str(e)}")
            return self.baseline_risk

    def _calculate_confidence_score(self, model_predictions: Dict[str, Any]) -> float:
        """Calculate overall confidence in risk assessment - FIXED"""
        try:
            confidences = []
            
            # Handle different prediction formats
            if isinstance(model_predictions, dict):
                if 'confidence' in model_predictions:
                    # Direct prediction with confidence
                    conf_val = model_predictions['confidence']
                    try:
                        return max(0.0, min(1.0, float(conf_val)))
                    except (ValueError, TypeError):
                        return 0.5
                
                # Collect confidence scores from all models
                for model_name, pred in model_predictions.items():
                    if isinstance(pred, dict):
                        confidence = pred.get('confidence', 0.5)
                        try:
                            conf_val = float(confidence)
                            confidences.append(max(0.0, min(1.0, conf_val)))
                        except (ValueError, TypeError):
                            confidences.append(0.5)
            
            if not confidences:
                return 0.5  # Default confidence
            
            # Calculate weighted average confidence
            avg_confidence = sum(confidences) / len(confidences)
            
            # Adjust confidence based on model agreement
            if len(confidences) > 1:
                # Calculate standard deviation manually to avoid numpy issues
                mean_conf = avg_confidence
                variance = sum((c - mean_conf) ** 2 for c in confidences) / len(confidences)
                confidence_std = variance ** 0.5
                
                if confidence_std < 0.1:  # High agreement
                    avg_confidence *= 1.1
                elif confidence_std > 0.3:  # Low agreement
                    avg_confidence *= 0.9
            
            return max(0.0, min(1.0, float(avg_confidence)))
            
        except Exception as e:
            logger.error(f"Error calculating confidence score: {str(e)}")
            return 0.5
    def categorize_risk(self, risk_score: float) -> RiskLevel:
        """Categorize risk level based on score"""
        return self.risk_category.categorize_risk(risk_score)

    def generate_risk_summary(self, risk_metrics: RiskMetrics, 
                            model_predictions: Dict[str, Any],
                            network_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive risk summary
        
        Args:
            risk_metrics: Risk assessment metrics
            model_predictions: AI model predictions
            network_info: Network information
            
        Returns:
            Dict: Comprehensive risk summary
        """
        try:
            # Categorize overall risk
            risk_level = self.categorize_risk(risk_metrics.overall_score)
            
            # Get primary threats from ensemble prediction or direct prediction
            if isinstance(model_predictions, dict):
                if 'ensemble' in model_predictions:
                    ensemble_pred = model_predictions['ensemble']
                elif 'class_index' in model_predictions:
                    ensemble_pred = model_predictions
                else:
                    # Use first available prediction
                    ensemble_pred = next(iter(model_predictions.values())) if model_predictions else {}
            else:
                ensemble_pred = {}
            
            primary_threat_class = ensemble_pred.get('predicted_class', ensemble_pred.get('class_index', 0))
            try:
                primary_threat_class = int(primary_threat_class)
            except (ValueError, TypeError):
                primary_threat_class = 0
                
            primary_threat = self.risk_category.get_threat_details(
                primary_threat_class, 
                "ensemble"
            )
            primary_threat.confidence = float(ensemble_pred.get('confidence', 0.5))
            
            # Get secondary threats from individual models
            secondary_threats = []
            
            # CNN threats
            if 'cnn' in model_predictions and isinstance(model_predictions['cnn'], dict):
                cnn_pred = model_predictions['cnn']
                cnn_class = cnn_pred.get('predicted_class', cnn_pred.get('class_index', 0))
                try:
                    cnn_class = int(cnn_class)
                    if cnn_class != 0:  # Not SECURE_NETWORK
                        cnn_threat = self.risk_category.get_threat_details(cnn_class, "cnn")
                        cnn_threat.confidence = float(cnn_pred.get('confidence', 0.5))
                        secondary_threats.append(cnn_threat)
                except (ValueError, TypeError):
                    pass
            
            # LSTM threats
            if 'lstm' in model_predictions and isinstance(model_predictions['lstm'], dict):
                lstm_pred = model_predictions['lstm']
                lstm_class = lstm_pred.get('predicted_class', lstm_pred.get('class_index', 0))
                try:
                    lstm_class = int(lstm_class)
                    if lstm_class != 0:  # Not NORMAL_BEHAVIOR
                        lstm_threat = self.risk_category.get_threat_details(lstm_class, "lstm")
                        lstm_threat.confidence = float(lstm_pred.get('confidence', 0.5))
                        secondary_threats.append(lstm_threat)
                except (ValueError, TypeError):
                    pass
            
            # GNN threats
            if 'gnn' in model_predictions and isinstance(model_predictions['gnn'], dict):
                gnn_pred = model_predictions['gnn']
                gnn_class = gnn_pred.get('predicted_class', gnn_pred.get('class_index', 0))
                try:
                    gnn_class = int(gnn_class)
                    if gnn_class != 0:  # Not ISOLATED_VULNERABILITY
                        gnn_threat = self.risk_category.get_threat_details(gnn_class, "gnn")
                        gnn_threat.confidence = float(gnn_pred.get('confidence', 0.5))
                        secondary_threats.append(gnn_threat)
                except (ValueError, TypeError):
                    pass
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                risk_level, 
                primary_threat, 
                secondary_threats,
                risk_metrics
            )
            
            # Create comprehensive summary
            risk_summary = {
                'overall_assessment': {
                    'risk_level': risk_level.value,
                    'risk_score': round(float(risk_metrics.overall_score), 3),
                    'confidence': round(float(risk_metrics.confidence_score), 3),
                    'severity': primary_threat.severity.value,
                    'assessment_timestamp': datetime.now().isoformat()
                },
                'risk_breakdown': {
                    'vulnerability_risk': round(float(risk_metrics.vulnerability_score), 3),
                    'threat_risk': round(float(risk_metrics.threat_score), 3),
                    'temporal_risk': round(float(risk_metrics.temporal_risk), 3),
                    'network_risk': round(float(risk_metrics.network_risk), 3),
                    'crypto_risk': round(float(risk_metrics.crypto_risk), 3)
                },
                'primary_threat': {
                    'type': primary_threat.threat_type,
                    'severity': primary_threat.severity.value,
                    'confidence': round(float(primary_threat.confidence), 3),
                    'description': primary_threat.description,
                    'impact': primary_threat.impact,
                    'likelihood': round(float(primary_threat.likelihood), 3)
                },
                'secondary_threats': [
                    {
                        'type': threat.threat_type,
                        'severity': threat.severity.value,
                        'confidence': round(float(threat.confidence), 3),
                        'description': threat.description
                    }
                    for threat in secondary_threats[:3]  # Top 3 secondary threats
                ],
                'recommendations': recommendations,
                'network_context': network_info or {},
                'model_agreement': {
                    'ensemble_confidence': float(ensemble_pred.get('confidence', 0.5)),
                    'individual_models': {
                        'cnn_confidence': float(model_predictions.get('cnn', {}).get('confidence', 0.5)),
                        'lstm_confidence': float(model_predictions.get('lstm', {}).get('confidence', 0.5)),
                        'gnn_confidence': float(model_predictions.get('gnn', {}).get('confidence', 0.5)),
                        'crypto_confidence': float(model_predictions.get('crypto_bert', {}).get('confidence', 0.5))
                    },
                    'prediction_consensus': self._calculate_prediction_consensus(model_predictions)
                }
            }
            
            logger.info(f"Risk summary generated: {risk_level.value} risk level")
            return risk_summary
            
        except Exception as e:
            logger.error(f"Error generating risk summary: {str(e)}")
            return {
                'overall_assessment': {
                    'risk_level': RiskLevel.LOW_RISK.value,
                    'risk_score': self.baseline_risk,
                    'confidence': 0.5,
                    'severity': ThreatSeverity.LOW.value,
                    'assessment_timestamp': datetime.now().isoformat()
                },
                'error': str(e)
            }

    def _generate_recommendations(self, risk_level: RiskLevel, 
                                primary_threat: ThreatDetails,
                                secondary_threats: List[ThreatDetails],
                                risk_metrics: RiskMetrics) -> List[Dict[str, str]]:
        """Generate security recommendations based on risk assessment"""
        recommendations = []
        
        try:
            # Primary threat recommendations
            if primary_threat.threat_type != "NO_THREAT":
                primary_rec = self._get_threat_recommendation(primary_threat.threat_type)
                if primary_rec:
                    recommendations.append({
                        'priority': 'HIGH',
                        'category': 'Primary Threat',
                        'action': primary_rec,
                        'urgency': 'Immediate' if primary_threat.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] else 'Medium'
                    })
            
            # Risk-specific recommendations
            if float(risk_metrics.vulnerability_score) > 0.6:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Vulnerability Management',
                    'action': 'Perform comprehensive vulnerability assessment and patch critical security flaws',
                    'urgency': 'Immediate'
                })
            
            if float(risk_metrics.crypto_risk) > 0.5:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Cryptographic Security',
                    'action': 'Update encryption protocols and review cryptographic implementations',
                    'urgency': 'Medium'
                })
            
            if float(risk_metrics.network_risk) > 0.5:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Network Security',
                    'action': 'Review network topology and implement network segmentation',
                    'urgency': 'Medium'
                })
            
            if float(risk_metrics.temporal_risk) > 0.6:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Threat Monitoring',
                    'action': 'Implement continuous monitoring and incident response procedures',
                    'urgency': 'Immediate'
                })
            
            # General security recommendations based on risk level
            if risk_level == RiskLevel.HIGH_RISK:
                recommendations.extend([
                    {
                        'priority': 'CRITICAL',
                        'category': 'Immediate Action',
                        'action': 'Isolate affected systems and initiate incident response protocol',
                        'urgency': 'Immediate'
                    },
                    {
                        'priority': 'HIGH',
                        'category': 'Security Monitoring',
                        'action': 'Enable enhanced logging and real-time threat detection',
                        'urgency': 'Immediate'
                    }
                ])
            elif risk_level == RiskLevel.LOW_RISK:
                recommendations.append({
                    'priority': 'LOW',
                    'category': 'Preventive Measures',
                    'action': 'Maintain current security posture and schedule regular security reviews',
                    'urgency': 'Low'
                })
            
            # Secondary threat recommendations
            for threat in secondary_threats[:2]:  # Top 2 secondary threats
                secondary_rec = self._get_threat_recommendation(threat.threat_type)
                if secondary_rec:
                    recommendations.append({
                        'priority': 'MEDIUM',
                        'category': 'Secondary Threat',
                        'action': secondary_rec,
                        'urgency': 'Medium'
                    })
            
            return recommendations[:8]  # Limit to top 8 recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return [{
                'priority': 'MEDIUM',
                'category': 'General',
                'action': 'Perform comprehensive security assessment',
                'urgency': 'Medium'
            }]

    def _get_threat_recommendation(self, threat_type: str) -> str:
        """Get specific recommendation for threat type"""
        recommendations = {
            'CRITICAL_VULNERABILITY': 'Apply emergency security patches and isolate affected systems immediately',
            'ACTIVE_ATTACK_DETECTED': 'Initiate incident response protocol and isolate compromised systems',
            'NETWORK_COMPROMISE': 'Perform full network forensics and rebuild compromised infrastructure',
            'APT_CAMPAIGN': 'Engage cybersecurity experts and implement advanced threat hunting procedures',
            'RANSOMWARE_INDICATORS': 'Isolate systems, verify backups, and prepare ransomware response plan',
            'SYSTEM_COMPROMISE': 'Perform complete system rebuild and forensic analysis',
            'DATA_BREACH_RISK': 'Implement data loss prevention and review data access controls',
            'CREDENTIAL_COMPROMISE': 'Force password resets and implement multi-factor authentication',
            'INSIDER_THREAT_DETECTED': 'Review user access privileges and implement user behavior analytics',
            'BOTNET_PARTICIPATION': 'Clean infected systems and implement network traffic monitoring',
            'FIRMWARE_EXPLOIT': 'Update device firmware and implement device security policies',
            'EVIL_TWIN': 'Verify network authenticity and implement certificate pinning',
            'OPEN_NETWORK': 'Enable WPA3 encryption and configure proper network security',
            'DEFAULT_CREDENTIALS': 'Change default passwords and implement strong authentication',
            'WEAK_ENCRYPTION': 'Upgrade to stronger encryption protocols (WPA3, AES-256)',
            'WPS_VULNERABILITY': 'Disable WPS functionality and use strong pre-shared keys',
            'ROGUE_AP': 'Identify and remove unauthorized access points',
            'DEAUTH_ATTACK': 'Implement 802.11w (PMF) protection and monitor for attacks',
            'HANDSHAKE_CAPTURE': 'Use strong passwords and implement WPA3 if available',
            'FIRMWARE_OUTDATED': 'Update device firmware to latest security patches',
            'SIGNAL_LEAKAGE': 'Adjust antenna power and implement signal containment',
            'BRUTE_FORCE_ATTACK': 'Implement account lockout policies and intrusion prevention',
            'RECONNAISSANCE': 'Enable network monitoring and implement access controls',
            'DATA_EXFILTRATION': 'Implement data loss prevention and monitor network traffic',
            'LATERAL_MOVEMENT': 'Implement network segmentation and zero-trust architecture',
            'COMMAND_CONTROL': 'Block malicious domains and implement DNS filtering',
            'CASCADING_RISK': 'Implement network segmentation and isolation controls',
            'CRITICAL_NODE': 'Harden critical systems and implement redundancy',
            'PERIMETER_BREACH': 'Review firewall rules and implement intrusion detection',
            'PRIVILEGE_ESCALATION': 'Review user privileges and implement least-privilege access',
            'CONFIGURATION_ERROR': 'Review and correct security configuration settings',
            'COMPLIANCE_VIOLATION': 'Implement compliance controls and audit procedures'
        }
        return recommendations.get(threat_type, 'Review security configuration and implement best practices')

    def _calculate_prediction_consensus(self, model_predictions: Dict[str, Any]) -> float:
        """Calculate consensus between model predictions - FIXED"""
        try:
            predictions = []
            confidences = []
            
            # Collect predictions and confidences with proper type conversion
            for model_name, pred in model_predictions.items():
                if isinstance(pred, dict):
                    # Get class index and convert to int
                    class_idx = pred.get('predicted_class', pred.get('class_index', 0))
                    confidence = pred.get('confidence', 0.5)
                    
                    try:
                        predictions.append(int(class_idx))
                        confidences.append(float(confidence))
                    except (ValueError, TypeError):
                        predictions.append(0)
                        confidences.append(0.5)
            
            if len(predictions) < 2:
                return 0.5
            
            # Calculate prediction variance using only integers
            predictions_array = np.array(predictions, dtype=np.int32)
            confidences_array = np.array(confidences, dtype=np.float64)
            
            pred_variance = float(np.var(predictions_array))
            conf_avg = float(np.mean(confidences_array))
            
            # Convert variance to consensus score (0-1, higher is better)
            max_variance = float(len(predictions) ** 2)  # Theoretical maximum variance
            consensus = 1.0 - (pred_variance / max_variance) if max_variance > 0 else 0.5
            
            # Weight by average confidence
            final_consensus = (consensus * 0.7) + (conf_avg * 0.3)
            
            return max(0.0, min(1.0, float(final_consensus)))
            
        except Exception as e:
            logger.error(f"Error calculating prediction consensus: {str(e)}")
            return 0.5
    def _store_risk_assessment(self, risk_metrics: RiskMetrics):
        """Store risk assessment for historical analysis"""
        try:
            assessment_record = {
                'timestamp': datetime.now().isoformat(),
                'overall_score': float(risk_metrics.overall_score),
                'vulnerability_score': float(risk_metrics.vulnerability_score),
                'threat_score': float(risk_metrics.threat_score),
                'confidence_score': float(risk_metrics.confidence_score),
                'temporal_risk': float(risk_metrics.temporal_risk),
                'network_risk': float(risk_metrics.network_risk),
                'crypto_risk': float(risk_metrics.crypto_risk)
            }
            
            # Keep only last 100 assessments in memory
            self.historical_risks.append(assessment_record)
            if len(self.historical_risks) > 100:
                self.historical_risks.pop(0)
                
        except Exception as e:
            logger.error(f"Error storing risk assessment: {str(e)}")

    def get_risk_trend(self, days: int = 7) -> Dict[str, Any]:
        """Get risk trend analysis for specified period"""
        try:
            if not self.historical_risks:
                return {'trend': 'insufficient_data', 'change': 0.0}
            
            # Get recent assessments within specified days
            cutoff_date = datetime.now() - timedelta(days=days)
            recent_assessments = []
            
            for assessment in self.historical_risks:
                try:
                    assessment_time = datetime.fromisoformat(assessment['timestamp'])
                    if assessment_time >= cutoff_date:
                        recent_assessments.append(assessment)
                except Exception:
                    continue
            
            if len(recent_assessments) < 2:
                return {'trend': 'insufficient_data', 'change': 0.0}
            
            # Calculate trend
            scores = [float(assessment['overall_score']) for assessment in recent_assessments]
            first_score = scores[0]
            last_score = scores[-1]
            change = last_score - first_score
            
            if change > 0.1:
                trend = 'increasing'
            elif change < -0.1:
                trend = 'decreasing'
            else:
                trend = 'stable'
            
            return {
                'trend': trend,
                'change': round(float(change), 3),
                'average_score': round(float(np.mean(scores)), 3),
                'max_score': round(float(max(scores)), 3),
                'min_score': round(float(min(scores)), 3),
                'assessment_count': len(recent_assessments)
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk trend: {str(e)}")
            return {'trend': 'error', 'change': 0.0}

    def export_risk_history(self) -> List[Dict[str, Any]]:
        """Export historical risk data"""
        try:
            return self.historical_risks.copy()
        except Exception as e:
            logger.error(f"Error exporting risk history: {str(e)}")
            return []

    def clear_risk_history(self):
        """Clear historical risk data"""
        try:
            self.historical_risks.clear()
            logger.info("Risk history cleared")
        except Exception as e:
            logger.error(f"Error clearing risk history: {str(e)}")


# Example usage and testing functions
def test_risk_assessor():
    """Test function for risk assessor - FIXED"""
    assessor = RiskAssessor()
    
    # Mock model predictions with proper data types
    mock_predictions = {
        'ensemble': {
            'predicted_class': 4,  # CRITICAL_VULNERABILITY
            'class_index': 4,
            'confidence': 0.85,
            'probabilities': [0.05, 0.1, 0.15, 0.25, 0.35, 0.05, 0.03, 0.02] + [0.0] * 12
        },
        'cnn': {
            'predicted_class': 2,  # OPEN_NETWORK
            'class_index': 2,
            'confidence': 0.78,
            'probabilities': [0.1, 0.15, 0.45, 0.1, 0.05, 0.05, 0.05, 0.03, 0.02] + [0.0] * 3
        },
        'lstm': {
            'predicted_class': 1,  # BRUTE_FORCE_ATTACK
            'class_index': 1,
            'confidence': 0.72,
            'probabilities': [0.2, 0.4, 0.15, 0.1, 0.05, 0.05, 0.03, 0.02] + [0.0] * 2
        },
        'gnn': {
            'predicted_class': 2,  # CRITICAL_NODE
            'class_index': 2,
            'confidence': 0.68,
            'probabilities': [0.1, 0.2, 0.35, 0.15, 0.1, 0.05, 0.03, 0.02]
        },
        'crypto_bert': {
            'predicted_class': 1,  # WEAK_CIPHER_SUITE
            'class_index': 1,
            'confidence': 0.75,
            'probabilities': [0.15, 0.4, 0.2, 0.1, 0.05] + [0.0] * 10
        }
    }
    
    # Calculate risk
    risk_metrics = assessor.calculate_risk_score(mock_predictions)
    print(f"Risk Assessment Results:")
    print(f"Overall Score: {risk_metrics.overall_score:.3f}")
    print(f"Risk Level: {assessor.categorize_risk(risk_metrics.overall_score).value}")
    
    # Generate summary
    risk_summary = assessor.generate_risk_summary(risk_metrics, mock_predictions)
    print(f"Primary Threat: {risk_summary['primary_threat']['type']}")
    print(f"Recommendations: {len(risk_summary['recommendations'])}")
    
    return risk_metrics, risk_summary

if __name__ == "__main__":
    # Run test
    test_risk_assessor()