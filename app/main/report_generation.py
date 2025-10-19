"""
Deep Scan Report Generation Module
Professional WiFi Security Assessment Report Generator
"""

from flask import jsonify
from datetime import datetime
import logging
import io
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

logger = logging.getLogger(__name__)

def generate_professional_report(scan_results, network_info):
    """Generate professional WiFi security assessment report"""
    try:
        logger.info(f"Received scan_results keys: {list(scan_results.keys()) if scan_results else 'None'}")
        logger.info(f"Received network_info keys: {list(network_info.keys()) if network_info else 'None'}")
        
        # Extract key information with proper fallbacks
        individual_preds = scan_results.get('individual_predictions', {})
        ensemble_pred = scan_results.get('ensemble_prediction', {})
        threats = scan_results.get('threats', [])
        risk_assessment = scan_results.get('risk_assessment', {})
        network_data = scan_results.get('network_data', network_info)  # Use network_info as fallback
        
        logger.info(f"Extracted individual_preds: {len(individual_preds) if individual_preds else 0} models")
        logger.info(f"Extracted ensemble_pred keys: {list(ensemble_pred.keys()) if ensemble_pred else 'None'}")
        logger.info(f"Extracted threats: {len(threats) if threats else 0}")
        logger.info(f"Risk assessment keys: {list(risk_assessment.keys()) if risk_assessment else 'None'}")
        
        # Generate executive summary
        executive_summary = generate_executive_summary(ensemble_pred, risk_assessment, len(individual_preds))
        
        # Generate network analysis section - prioritize network_info over network_data
        network_analysis = generate_network_analysis(network_info or network_data, network_data)
        
        # Generate AI model analysis section
        model_analysis = generate_model_analysis(individual_preds, ensemble_pred)
        
        # Generate threat analysis section
        threat_analysis = generate_threat_analysis(threats, risk_assessment)
        
        # Generate recommendations section
        recommendations = generate_recommendations_section(risk_assessment, threats, network_info or network_data)
        
        # Add detailed input features section (original)
        input_features_analysis = generate_input_features_analysis(network_info, individual_preds, ensemble_pred)
        
        # Add 32 WiFi input features section
        wifi_input_features = generate_wifi_input_features_section(network_info, scan_results)
        
        # Compile full report
        report = {
            'title': 'WiFi Security Deep Scan Report',
            'generated_date': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'scan_timestamp': scan_results.get('timestamp', ''),
            'network_name': (network_info or network_data or {}).get('ssid', 'Unknown Network'),
            'executive_summary': executive_summary,
            'network_analysis': network_analysis,
            'ai_model_analysis': model_analysis,
            'input_features_analysis': input_features_analysis,
            'wifi_input_features': wifi_input_features,
            'threat_analysis': threat_analysis,
            'recommendations': recommendations,
            'technical_details': {
                'models_analyzed': len(individual_preds),
                'ensemble_confidence': ensemble_pred.get('ensemble_confidence', 0),
                'risk_score': risk_assessment.get('risk_score', 0),
                'threats_detected': len(threats)
            }
        }
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating professional report: {str(e)}")
        logger.error(f"scan_results structure: {scan_results}")
        raise

def generate_executive_summary(ensemble_pred, risk_assessment, model_count):
    """Generate executive summary section"""
    try:
        logger.info(f"Generating executive summary - ensemble_pred: {ensemble_pred}")
        logger.info(f"Risk assessment structure: {risk_assessment}")
        
        # Handle ensemble prediction - it might be directly in ensemble_pred or nested
        if 'ensemble_prediction' in ensemble_pred:
            ensemble_result = ensemble_pred.get('ensemble_prediction', {})
            predicted_class = ensemble_result.get('predicted_class', 'NO_THREAT')
        else:
            # Direct structure
            predicted_class = ensemble_pred.get('predicted_class', 'NO_THREAT')
        
        confidence = ensemble_pred.get('ensemble_confidence', 0)
        if confidence > 1:  # If it's already a percentage
            confidence = confidence
        else:
            confidence = confidence * 100
            
        # Handle risk assessment structure - it comes directly from the /api/deep-scan/risk-assessment endpoint
        # The risk assessment should have risk_level and risk_score at the top level
        risk_level = risk_assessment.get('risk_level', 'Minimal')
        risk_score = risk_assessment.get('risk_score', 0)
        
        logger.info(f"Extracted values - class: {predicted_class}, confidence: {confidence}, risk_level: {risk_level}, risk_score: {risk_score}")
        
        summary = {
            'overall_status': predicted_class.replace('_', ' ').title(),
            'confidence_level': f"{confidence:.1f}%",
            'risk_level': risk_level,
            'risk_score': risk_score,
            'models_analyzed': model_count,
            'key_findings': []
        }
        
        # Add key findings based on results
        if predicted_class == 'NO_THREAT':
            summary['key_findings'].append("Network shows no immediate security threats")
        else:
            summary['key_findings'].append(f"Potential security concern detected: {predicted_class.replace('_', ' ')}")
        
        if confidence >= 70:
            summary['key_findings'].append("High confidence in AI model predictions")
        elif confidence >= 50:
            summary['key_findings'].append("Moderate confidence in AI model predictions")
        else:
            summary['key_findings'].append("Low confidence in predictions - manual review recommended")
        
        return summary
        
    except Exception as e:
        logger.error(f"Failed to generate executive summary: {str(e)}")
        return {'error': f"Failed to generate executive summary: {str(e)}"}

def generate_network_analysis(network_info, network_data):
    """Generate network configuration analysis"""
    try:
        if not network_info:
            return {'error': 'Network information not available'}
        
        analysis = {
            'network_configuration': {
                'ssid': network_info.get('ssid', 'Unknown'),
                'encryption': network_info.get('security', 'Unknown'),
                'signal_strength': network_info.get('signal_strength', 'Unknown'),
                'channel': network_info.get('channel', 'Unknown'),
                'frequency': network_info.get('frequency', 'Unknown'),
                'mac_address': network_info.get('bssid', 'Unknown'),
                'ip_address': network_info.get('ip_address', 'Unknown'),
                'gateway': network_info.get('gateway', 'Unknown'),
                'dns_servers': network_info.get('dns_servers', 'Unknown'),
                'data_rate': network_info.get('data_rate', 'Unknown'),
                'radio_type': network_info.get('radio_type', 'Unknown')
            },
            'security_assessment': {
                'encryption_strength': assess_encryption_strength(network_info.get('security', '')),
                'signal_quality': assess_signal_quality(network_info.get('signal_strength', '')),
                'channel_congestion': assess_channel_usage(network_info.get('channel', ''))
            },
            'input_features_used': extract_input_features(network_data)
        }
        
        return analysis
        
    except Exception as e:
        return {'error': f"Failed to generate network analysis: {str(e)}"}

def generate_model_analysis(individual_preds, ensemble_pred):
    """Generate AI model analysis section"""
    try:
        analysis = {
            'individual_models': [],
            'ensemble_fusion': {},
            'model_agreement': {}
        }
        
        # Process individual model predictions
        for model_name, prediction in individual_preds.items():
            if prediction:
                model_info = {
                    'name': model_name.replace('_', ' ').title(),
                    'prediction': prediction.get('predicted_class', 'Unknown').replace('_', ' '),
                    'confidence': f"{prediction.get('confidence', 0) * 100:.1f}%",
                    'processing_time': f"{prediction.get('processing_time_ms', 0):.1f}ms",
                    'model_type': determine_model_category(model_name),
                    'class_index': prediction.get('predicted_class_index', 'Unknown')
                }
                analysis['individual_models'].append(model_info)
        
        # Process ensemble prediction
        ensemble_result = ensemble_pred.get('ensemble_prediction', {})
        analysis['ensemble_fusion'] = {
            'final_prediction': ensemble_result.get('predicted_class', 'Unknown').replace('_', ' '),
            'confidence': f"{ensemble_pred.get('ensemble_confidence', 0) * 100:.1f}%",
            'models_used': len(individual_preds),
            'agreement_score': f"{(1 - ensemble_pred.get('model_agreement', 0)) * 100:.1f}%",
            'fusion_method': 'Weighted Average with Confidence Scoring'
        }
        
        return analysis
        
    except Exception as e:
        return {'error': f"Failed to generate model analysis: {str(e)}"}

def generate_threat_analysis(threats, risk_assessment):
    """Generate threat analysis section"""
    try:
        assessment_data = risk_assessment.get('assessment', {})
        analysis = {
            'threat_summary': {
                'total_threats': len(threats),
                'risk_level': assessment_data.get('risk_level', 'Unknown'),
                'risk_score': assessment_data.get('risk_score', 0)
            },
            'detected_threats': [],
            'vulnerability_assessment': []
        }
        
        # Process detected threats
        for threat in threats:
            if threat:
                threat_info = {
                    'type': threat.get('title', 'Unknown'),
                    'severity': threat.get('severity', 'Unknown').upper(),
                    'description': threat.get('description', 'No description available'),
                    'confidence': f"{threat.get('confidence', 0) * 100:.1f}%" if threat.get('confidence') else 'N/A',
                    'source': threat.get('source', 'Unknown')
                }
                analysis['detected_threats'].append(threat_info)
        
        # Add vulnerability assessment
        if len(threats) == 0:
            analysis['vulnerability_assessment'].append({
                'category': 'Network Security',
                'status': 'SECURE',
                'details': 'No immediate threats detected - current network configuration appears secure'
            })
        else:
            # Categorize threats by severity
            threat_categories = {}
            for threat in threats:
                severity = threat.get('severity', 'low').upper()
                if severity not in threat_categories:
                    threat_categories[severity] = 0
                threat_categories[severity] += 1
            
            for severity, count in threat_categories.items():
                analysis['vulnerability_assessment'].append({
                    'category': f'{severity} Priority Threats',
                    'status': f'{count} detected',
                    'details': f'{count} threat(s) requiring {severity.lower()} priority attention'
                })
        
        return analysis
        
    except Exception as e:
        return {'error': f"Failed to generate threat analysis: {str(e)}"}

def generate_recommendations_section(risk_assessment, threats, network_info):
    """Generate recommendations section"""
    try:
        recommendations = {
            'immediate_actions': [],
            'security_improvements': [],
            'monitoring_suggestions': []
        }
        
        # Get recommendations from risk assessment - they are at the top level
        risk_recommendations = risk_assessment.get('recommendations', [])
        
        for rec in risk_recommendations:
            if rec.get('priority') == 'high':
                recommendations['immediate_actions'].append({
                    'action': rec.get('text', ''),
                    'reason': 'High priority security concern',
                    'urgency': 'IMMEDIATE'
                })
            elif rec.get('priority') == 'medium':
                recommendations['security_improvements'].append({
                    'action': rec.get('text', ''),
                    'reason': 'Security enhancement opportunity',
                    'urgency': 'WITHIN 30 DAYS'
                })
            else:
                recommendations['monitoring_suggestions'].append({
                    'action': rec.get('text', ''),
                    'reason': 'Ongoing security monitoring',
                    'urgency': 'ONGOING'
                })
        
        # Add network-specific recommendations based on current configuration
        if network_info:
            encryption = network_info.get('security', '').lower()
            if 'wpa2' in encryption and 'wpa3' not in encryption:
                recommendations['security_improvements'].append({
                    'action': 'Consider upgrading to WPA3 encryption if supported by your router',
                    'reason': 'WPA3 provides enhanced security features',
                    'urgency': 'WITHIN 90 DAYS'
                })
            
            signal_strength = network_info.get('signal_strength', '')
            if signal_strength and 'dBm' in str(signal_strength):
                try:
                    dbm_value = int(str(signal_strength).split()[0])
                    if dbm_value < -70:
                        recommendations['monitoring_suggestions'].append({
                            'action': 'Monitor WiFi signal strength and consider relocating router for better coverage',
                            'reason': 'Weak signal strength may impact security and performance',
                            'urgency': 'ONGOING'
                        })
                except:
                    pass
        
        # Add standard monitoring recommendations
        recommendations['monitoring_suggestions'].append({
            'action': 'Schedule regular automated security scans',
            'reason': 'Continuous monitoring for emerging threats',
            'urgency': 'ONGOING'
        })
        
        recommendations['monitoring_suggestions'].append({
            'action': 'Review and update network access credentials quarterly',
            'reason': 'Regular credential rotation reduces long-term exposure risk',
            'urgency': 'QUARTERLY'
        })
        
        return recommendations
        
    except Exception as e:
        return {'error': f"Failed to generate recommendations: {str(e)}"}

def assess_encryption_strength(encryption):
    """Assess encryption strength"""
    encryption_lower = encryption.lower()
    if 'wpa3' in encryption_lower:
        return 'Excellent (WPA3 - Latest Standard)'
    elif 'wpa2' in encryption_lower:
        return 'Good (WPA2 - Industry Standard)'
    elif 'wpa' in encryption_lower:
        return 'Fair (WPA - Legacy Standard)'
    elif 'wep' in encryption_lower:
        return 'Poor (WEP - Deprecated and Insecure)'
    elif 'open' in encryption_lower or 'none' in encryption_lower:
        return 'Critical (Open Network - No Encryption)'
    else:
        return 'Unknown Encryption Type'

def assess_signal_quality(signal_strength):
    """Assess signal quality"""
    try:
        if 'dBm' in str(signal_strength):
            dbm = int(str(signal_strength).split()[0])
            if dbm >= -30:
                return 'Excellent (-30 dBm or higher)'
            elif dbm >= -50:
                return 'Good (-50 to -30 dBm)'
            elif dbm >= -70:
                return 'Fair (-70 to -50 dBm)'
            else:
                return 'Poor (Below -70 dBm)'
        elif '%' in str(signal_strength):
            # Handle percentage values
            percent = int(str(signal_strength).replace('%', ''))
            if percent >= 80:
                return 'Excellent (80-100%)'
            elif percent >= 60:
                return 'Good (60-79%)'
            elif percent >= 40:
                return 'Fair (40-59%)'
            else:
                return 'Poor (Below 40%)'
    except:
        pass
    return 'Unable to assess signal quality'

def assess_channel_usage(channel):
    """Assess channel congestion and band usage"""
    try:
        ch = int(channel)
        if ch in [1, 6, 11]:
            return 'Standard 2.4GHz non-overlapping channel (Good choice)'
        elif 1 <= ch <= 14:
            return '2.4GHz band (May experience congestion)'
        elif ch >= 36:
            return '5GHz band (Less congested, better performance)'
        else:
            return 'Non-standard channel'
    except:
        return 'Unable to assess channel usage'

def generate_input_features_analysis(network_info, individual_preds, ensemble_pred):
    """Generate detailed analysis of input features and prediction values"""
    try:
        analysis = {
            'raw_input_data': {},
            'processed_features': {},
            'prediction_details': {},
            'model_inputs_summary': {}
        }
        
        # Extract and organize raw network input data
        if network_info:
            analysis['raw_input_data'] = {
                'Network Name (SSID)': network_info.get('ssid', 'Unknown'),
                'MAC Address (BSSID)': network_info.get('bssid', 'Unknown'),
                'Signal Strength': network_info.get('signal_strength', 'Unknown'),
                'WiFi Channel': network_info.get('channel', 'Unknown'),
                'Operating Frequency': network_info.get('frequency', 'Unknown'),
                'Encryption Type': network_info.get('security', 'Unknown'),
                'Authentication Method': network_info.get('authentication', 'Unknown'),
                'Connection Speed': network_info.get('data_rate', 'Unknown'),
                'Radio Type': network_info.get('radio_type', 'Unknown'),
                'Device IP Address': network_info.get('ip_address', 'Unknown'),
                'Network Gateway': network_info.get('gateway', 'Unknown'),
                'DNS Servers': network_info.get('dns_servers', 'Unknown'),
                'Link Quality': network_info.get('link_quality', 'Unknown')
            }
        
        # Process individual model predictions and their inputs
        if individual_preds:
            for model_name, prediction in individual_preds.items():
                if prediction:
                    analysis['prediction_details'][model_name] = {
                        'prediction_class': prediction.get('predicted_class', 'Unknown'),
                        'confidence_score': f"{prediction.get('confidence', 0) * 100:.1f}%",
                        'processing_time': f"{prediction.get('processing_time_ms', 0):.1f}ms",
                        'model_type': determine_model_category(model_name),
                        'input_dimensions': get_model_input_requirements(model_name)
                    }
        
        # Add ensemble prediction details
        if ensemble_pred:
            analysis['prediction_details']['ensemble_model'] = {
                'final_prediction': ensemble_pred.get('predicted_class', 'Unknown'),
                'ensemble_confidence': f"{ensemble_pred.get('ensemble_confidence', 0) * 100:.1f}%",
                'models_used': len(individual_preds) if individual_preds else 0,
                'model_agreement': f"{(1 - ensemble_pred.get('model_agreement', 0)) * 100:.1f}%",
                'fusion_method': 'Weighted Average with Confidence Scoring'
            }
        
        # Summarize model input requirements
        analysis['model_inputs_summary'] = {
            'CNN Models': 'Use 32-dimensional feature vectors from network parameters',
            'LSTM Models': 'Use time-series data with 48 features across 10 time steps',
            'GNN Models': 'Use graph representation of network topology and relationships',
            'BERT Models': 'Use tokenized protocol sequences and communication patterns',
            'Traditional ML': 'Use 64-dimensional engineered feature vectors',
            'Ensemble': 'Combines predictions from all available models using weighted fusion'
        }
        
        # Add feature engineering details
        analysis['processed_features'] = {
            'Signal Quality Features': ['Signal strength (dBm)', 'Link quality percentage', 'Signal-to-noise ratio'],
            'Security Features': ['Encryption strength score', 'Authentication method classification', 'Protocol security level'],
            'Network Topology': ['Channel utilization', 'Frequency band classification', 'Network density metrics'],
            'Performance Metrics': ['Data rate classification', 'Latency indicators', 'Throughput patterns'],
            'Behavioral Features': ['Connection patterns', 'Traffic flow analysis', 'Protocol conformance']
        }
        
        return analysis
        
    except Exception as e:
        logger.error(f"Failed to generate input features analysis: {str(e)}")
        return {'error': f"Failed to generate input features analysis: {str(e)}"}

def get_model_input_requirements(model_name):
    """Get input requirements for specific model"""
    model_name_lower = model_name.lower()
    if 'cnn' in model_name_lower and 'lstm' not in model_name_lower:
        return '32-dimensional feature vector'
    elif 'lstm' in model_name_lower and 'cnn' not in model_name_lower:
        return '(10, 48) time-series matrix'
    elif 'cnn' in model_name_lower and 'lstm' in model_name_lower:
        return '(50, 48) hybrid sequence matrix'
    elif 'gnn' in model_name_lower:
        return 'Graph adjacency matrix + node features'
    elif 'bert' in model_name_lower:
        return 'Tokenized protocol sequences'
    elif any(ml_type in model_name_lower for ml_type in ['random_forest', 'gradient_boosting']):
        return '64-dimensional feature vector'
    else:
        return 'Variable-length feature vector'

def extract_input_features(network_data):
    """Extract key input features used for AI analysis"""
    try:
        features = []
        
        # Network identification features
        if network_data.get('ssid'):
            features.append(f"Network SSID: {network_data['ssid']}")
        if network_data.get('bssid'):
            features.append(f"MAC Address (BSSID): {network_data['bssid']}")
            
        # Signal and connection features
        if network_data.get('signal_strength'):
            features.append(f"Signal Strength: {network_data['signal_strength']}")
        if network_data.get('channel'):
            features.append(f"WiFi Channel: {network_data['channel']}")
        if network_data.get('frequency'):
            features.append(f"Operating Frequency: {network_data['frequency']}")
            
        # Security features
        if network_data.get('encryption'):
            features.append(f"Encryption Type: {network_data['encryption']}")
        if network_data.get('authentication'):
            features.append(f"Authentication Method: {network_data['authentication']}")
            
        # Network topology features
        if network_data.get('ip_address'):
            features.append(f"Device IP Address: {network_data['ip_address']}")
        if network_data.get('gateway'):
            features.append(f"Network Gateway: {network_data['gateway']}")
        if network_data.get('connected_devices'):
            features.append(f"Connected Devices: {network_data['connected_devices']}")
            
        # Performance features
        if network_data.get('data_rate'):
            features.append(f"Connection Speed: {network_data['data_rate']}")
        if network_data.get('data_transfer'):
            features.append(f"Data Transfer Statistics: {network_data['data_transfer']}")
        
        return features if features else ['Basic network configuration parameters']
        
    except Exception as e:
        return [f'Error extracting input features: {str(e)}']

def determine_model_category(model_name):
    """Determine AI model category for professional display"""
    model_name_lower = model_name.lower()
    if 'cnn' in model_name_lower:
        return 'Convolutional Neural Network (CNN) - Pattern Recognition'
    elif 'lstm' in model_name_lower:
        return 'Long Short-Term Memory (LSTM) - Temporal Analysis'
    elif 'gnn' in model_name_lower:
        return 'Graph Neural Network (GNN) - Network Topology Analysis'
    elif 'bert' in model_name_lower:
        return 'BERT Language Model - Protocol and Communication Analysis'
    elif 'random_forest' in model_name_lower:
        return 'Random Forest - Ensemble Decision Trees'
    elif 'gradient_boosting' in model_name_lower:
        return 'Gradient Boosting - Advanced Ensemble Learning'
    elif 'attention' in model_name_lower:
        return 'Attention Mechanism - Feature Correlation Analysis'
    else:
        return 'Advanced Machine Learning Model'

def generate_wifi_input_features_section(network_info, scan_results):
    """Generate detailed analysis of the 32 WiFi input features used for AI prediction"""
    try:
        features_section = {
            'feature_categories': {
                'Signal Intelligence Features (0-7)': [],
                'Packet Analysis Features (8-15)': [], 
                'Network Protocol Features (16-23)': [],
                'Traffic Pattern Features (24-31)': []
            },
            'raw_inputs': {},
            'feature_extraction_summary': {}
        }
        
        # Raw network inputs that were captured
        if network_info:
            features_section['raw_inputs'] = {
                'Network SSID': network_info.get('ssid', 'Unknown'),
                'MAC Address (BSSID)': network_info.get('bssid', 'Unknown'),
                'Signal Strength (RSSI)': network_info.get('signal_strength', 'Unknown'),
                'WiFi Channel': network_info.get('channel', 'Unknown'),
                'Operating Frequency': network_info.get('frequency', 'Unknown'),
                'Encryption Type': network_info.get('security', 'Unknown'),
                'Cipher Suite': network_info.get('cipher_suite', 'Unknown'),
                'Authentication Method': network_info.get('authentication', 'Unknown'),
                'Connection Speed': network_info.get('data_rate', 'Unknown'),
                'Radio Type': network_info.get('radio_type', 'Unknown'),
                'Beacon Interval': network_info.get('beacon_interval', 'Unknown'),
                'Device IP Address': network_info.get('ip_address', 'Unknown'),
                'Network Gateway': network_info.get('gateway', 'Unknown'),
                'DNS Servers': network_info.get('dns_servers', 'Unknown'),
                'Link Quality': network_info.get('link_quality', 'Unknown'),
                'Noise Level': network_info.get('noise_level', 'Unknown'),
                'SNR': network_info.get('snr', 'Unknown'),
                'Bandwidth': network_info.get('bandwidth', 'Unknown'),
                'Network Mode': network_info.get('mode', 'Unknown')
            }
        
        # Define the 32 feature descriptions based on WiFiFeatures class
        feature_definitions = {
            'Signal Intelligence Features (0-7)': [
                'Signal Strength Normalized: RSSI normalized to 0-1 range',
                'Signal Quality: Signal quality percentage normalized',
                'SNR Normalized: Signal-to-Noise ratio normalized', 
                'Signal Stability: Signal stability score 0-1',
                'Frequency Band: 0=2.4GHz, 0.5=5GHz, 1=6GHz',
                'Channel Congestion: Channel utilization 0-1',
                'Interference Level: Interference level 0-1', 
                'Beacon Interval Normalized: Beacon interval normalized'
            ],
            'Packet Analysis Features (8-15)': [
                'Encryption Strength: 0=Open, 0.25=WEP, 0.5=WPA, 0.75=WPA2, 1=WPA3',
                'Cipher Suite Score: Cipher strength score 0-1',
                'Authentication Method: Auth method score 0-1',
                'WPS Vulnerability: 1 if WPS enabled, 0 otherwise',
                'PMF Enabled: 1 if PMF enabled, 0 otherwise',
                'Enterprise Features: Enterprise security features 0-1',
                'Protocol Version: 802.11 version normalized',
                'Max Data Rate Normalized: Maximum data rate normalized'
            ],
            'Network Protocol Features (16-23)': [
                'Vendor Trust Score: Vendor trust score 0-1',
                'Device Type Score: Device type risk score 0-1',
                'SSID Entropy: SSID randomness score 0-1',
                'SSID Suspicious Keywords: Suspicious SSID keywords 0-1',
                'BSSID OUI Known: Known OUI indicator 0-1',
                'Capabilities Count: Number of capabilities normalized',
                'Hidden Network: 1 if hidden, 0 otherwise',
                'Country Code Match: Country code consistency 0-1'
            ],
            'Traffic Pattern Features (24-31)': [
                'Network Age: How long network has been seen 0-1',
                'Signal Trend: 0=degrading, 0.5=stable, 1=improving',
                'Connection Attempts: Connection attempt patterns 0-1',
                'Bandwidth Capacity: Network capacity estimate 0-1',
                'Load Estimate: Current network load 0-1',
                'Geographic Anomaly: Geographic inconsistency 0-1',
                'Time Pattern Anomaly: Unusual time patterns 0-1',
                'Duplicate Detection: Evil twin / duplicate detection 0-1'
            ]
        }
        
        # Populate feature categories with definitions
        for category, feature_list in feature_definitions.items():
            features_section['feature_categories'][category] = feature_list
        
        # Feature extraction summary
        features_section['feature_extraction_summary'] = {
            'Total Input Features': '32 normalized features',
            'Feature Engineering': 'Real-time extraction from live WiFi data',
            'Normalization Method': 'Min-max scaling to 0-1 range',
            'Data Types': 'Float32 arrays for AI model compatibility',
            'Feature Categories': '4 categories covering signal, security, protocol, and behavior',
            'Update Frequency': 'Real-time during network scanning',
            'Missing Value Handling': 'Default values based on network type',
            'Quality Assurance': 'Automated validation and bounds checking'
        }
        
        return features_section
        
    except Exception as e:
        logger.error(f"Error generating WiFi input features section: {str(e)}")
        return {'error': f"Failed to generate input features analysis: {str(e)}"}

def generate_professional_report_pdf(scan_results, network_info):
    """Generate professional WiFi security assessment report as PDF"""
    try:
        # Generate the report data first
        report_data = generate_professional_report(scan_results, network_info)
        
        # Create PDF buffer
        buffer = io.BytesIO()
        
        # Create PDF document
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=24, spaceAfter=30, alignment=TA_CENTER)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading1'], fontSize=16, spaceAfter=12, textColor=colors.HexColor('#1e40af'))
        subheading_style = ParagraphStyle('CustomSubheading', parent=styles['Heading2'], fontSize=14, spaceAfter=10, textColor=colors.HexColor('#374151'))
        normal_style = ParagraphStyle('CustomNormal', parent=styles['Normal'], fontSize=10, spaceAfter=6, alignment=TA_JUSTIFY)
        
        # Build PDF content
        content = []
        
        # Title Page
        content.append(Paragraph("Professional WiFi Security Assessment Report", title_style))
        content.append(Spacer(1, 20))
        
        # Report metadata
        metadata_data = [
            ['Report Generated:', report_data.get('generated_date', 'Unknown')],
            ['Network Name:', report_data.get('network_name', 'Unknown')],
            ['Scan Timestamp:', report_data.get('scan_timestamp', 'Unknown')],
        ]
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
        ]))
        content.append(metadata_table)
        content.append(Spacer(1, 30))
        
        # Executive Summary
        exec_summary = report_data.get('executive_summary', {})
        if exec_summary and not exec_summary.get('error'):
            content.append(Paragraph("Executive Summary", heading_style))
            
            # Create summary table
            summary_data = [
                ['Overall Status:', exec_summary.get('overall_status', 'Unknown')],
                ['Confidence Level:', exec_summary.get('confidence_level', 'Unknown')],
                ['Risk Level:', exec_summary.get('risk_level', 'Unknown')],
                ['Risk Score:', str(exec_summary.get('risk_score', 'Unknown'))],
                ['Models Analyzed:', str(exec_summary.get('models_analyzed', 'Unknown'))]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
            ]))
            content.append(summary_table)
            
            # Key findings
            key_findings = exec_summary.get('key_findings', [])
            if key_findings:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Key Findings:", subheading_style))
                for finding in key_findings:
                    content.append(Paragraph(f"• {finding}", normal_style))
            
            content.append(PageBreak())
        
        # Network Analysis
        network_analysis = report_data.get('network_analysis', {})
        if network_analysis and not network_analysis.get('error'):
            content.append(Paragraph("Network Configuration Analysis", heading_style))
            
            network_config = network_analysis.get('network_configuration', {})
            if network_config:
                config_data = []
                for key, value in network_config.items():
                    if value != 'Unknown':
                        config_data.append([key.replace('_', ' ').title() + ':', str(value)])
                
                if config_data:
                    config_table = Table(config_data, colWidths=[2*inch, 4*inch])
                    config_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                    ]))
                    content.append(config_table)
            
            # Security Assessment
            security_assessment = network_analysis.get('security_assessment', {})
            if security_assessment:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Security Assessment:", subheading_style))
                for key, value in security_assessment.items():
                    if value and value != 'Unknown':
                        content.append(Paragraph(f"<b>{key.replace('_', ' ').title()}:</b> {value}", normal_style))
            
            content.append(PageBreak())
        
        # AI Model Analysis
        model_analysis = report_data.get('ai_model_analysis', {})
        if model_analysis and not model_analysis.get('error'):
            content.append(Paragraph("AI Model Analysis", heading_style))
            
            # Ensemble results
            ensemble_fusion = model_analysis.get('ensemble_fusion', {})
            if ensemble_fusion:
                content.append(Paragraph("Ensemble Model Results:", subheading_style))
                ensemble_data = []
                for key, value in ensemble_fusion.items():
                    if value:
                        ensemble_data.append([key.replace('_', ' ').title() + ':', str(value)])
                
                if ensemble_data:
                    ensemble_table = Table(ensemble_data, colWidths=[2*inch, 4*inch])
                    ensemble_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                    ]))
                    content.append(ensemble_table)
            
            # Individual models
            individual_models = model_analysis.get('individual_models', [])
            if individual_models:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Individual Model Results:", subheading_style))
                
                model_headers = ['Model Name', 'Prediction', 'Confidence', 'Type']
                model_data = [model_headers]
                
                for model in individual_models:
                    model_data.append([
                        model.get('name', 'Unknown'),
                        model.get('prediction', 'Unknown'),
                        model.get('confidence', 'Unknown'),
                        model.get('model_type', 'Unknown')
                    ])
                
                model_table = Table(model_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2*inch])
                model_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9fafb')),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                ]))
                content.append(model_table)
            
            content.append(PageBreak())
        
        # Threat Analysis
        threat_analysis = report_data.get('threat_analysis', {})
        if threat_analysis and not threat_analysis.get('error'):
            content.append(Paragraph("Threat Analysis", heading_style))
            
            threat_summary = threat_analysis.get('threat_summary', {})
            if threat_summary:
                summary_data = []
                for key, value in threat_summary.items():
                    if value:
                        summary_data.append([key.replace('_', ' ').title() + ':', str(value)])
                
                if summary_data:
                    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
                    summary_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                    ]))
                    content.append(summary_table)
            
            # Detected threats
            detected_threats = threat_analysis.get('detected_threats', [])
            if detected_threats:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Detected Threats:", subheading_style))
                
                for threat in detected_threats:
                    content.append(Paragraph(f"<b>{threat.get('type', 'Unknown')} ({threat.get('severity', 'Unknown')})</b>", normal_style))
                    content.append(Paragraph(f"{threat.get('description', 'No description')}", normal_style))
                    if threat.get('confidence'):
                        content.append(Paragraph(f"Confidence: {threat.get('confidence', 'N/A')}", normal_style))
                    content.append(Spacer(1, 8))
            
            content.append(PageBreak())
        
        # Recommendations
        recommendations = report_data.get('recommendations', {})
        if recommendations and not recommendations.get('error'):
            content.append(Paragraph("Security Recommendations", heading_style))
            
            # Immediate Actions
            immediate_actions = recommendations.get('immediate_actions', [])
            if immediate_actions:
                content.append(Paragraph("Immediate Actions Required:", subheading_style))
                for action in immediate_actions:
                    content.append(Paragraph(f"• <b>{action.get('urgency', 'HIGH')}:</b> {action.get('action', 'No action specified')}", normal_style))
                    content.append(Paragraph(f"  Reason: {action.get('reason', 'No reason provided')}", normal_style))
                    content.append(Spacer(1, 6))
            
            # Security Improvements
            security_improvements = recommendations.get('security_improvements', [])
            if security_improvements:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Security Improvements:", subheading_style))
                for improvement in security_improvements:
                    content.append(Paragraph(f"• <b>{improvement.get('urgency', 'MEDIUM')}:</b> {improvement.get('action', 'No action specified')}", normal_style))
                    content.append(Paragraph(f"  Reason: {improvement.get('reason', 'No reason provided')}", normal_style))
                    content.append(Spacer(1, 6))
            
            # Monitoring Suggestions
            monitoring_suggestions = recommendations.get('monitoring_suggestions', [])
            if monitoring_suggestions:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Ongoing Monitoring:", subheading_style))
                for suggestion in monitoring_suggestions:
                    content.append(Paragraph(f"• <b>{suggestion.get('urgency', 'ONGOING')}:</b> {suggestion.get('action', 'No action specified')}", normal_style))
                    content.append(Paragraph(f"  Reason: {suggestion.get('reason', 'No reason provided')}", normal_style))
                    content.append(Spacer(1, 6))
        
        # WiFi Input Features Section
        wifi_input_features = report_data.get('wifi_input_features', {})
        if wifi_input_features and not wifi_input_features.get('error'):
            content.append(PageBreak())
            content.append(Paragraph("WiFi Network Input Features (32 Features)", heading_style))
            
            # Raw inputs captured from WiFi network
            raw_inputs = wifi_input_features.get('raw_inputs', {})
            if raw_inputs:
                content.append(Paragraph("Raw Network Data Captured:", subheading_style))
                raw_data = []
                for key, value in raw_inputs.items():
                    if value and str(value) != 'Unknown':
                        raw_data.append([key + ':', str(value)])
                
                if raw_data:
                    raw_table = Table(raw_data, colWidths=[2*inch, 4*inch])
                    raw_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                    ]))
                    content.append(raw_table)
            
            # 32 Feature Categories
            feature_categories = wifi_input_features.get('feature_categories', {})
            if feature_categories:
                content.append(Spacer(1, 15))
                content.append(Paragraph("AI Model Input Features (32 Features):", subheading_style))
                
                for category, features in feature_categories.items():
                    if features:
                        content.append(Spacer(1, 10))
                        content.append(Paragraph(f"<b>{category}</b>", normal_style))
                        for i, feature in enumerate(features):
                            content.append(Paragraph(f"  {i + (8 if '8-15' in category else 16 if '16-23' in category else 24 if '24-31' in category else 0)}. {feature}", normal_style))
            
            # Feature extraction summary
            extraction_summary = wifi_input_features.get('feature_extraction_summary', {})
            if extraction_summary:
                content.append(Spacer(1, 15))
                content.append(Paragraph("Feature Extraction Summary:", subheading_style))
                summary_data = []
                for key, value in extraction_summary.items():
                    summary_data.append([key + ':', str(value)])
                
                if summary_data:
                    summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
                    summary_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                    ]))
                    content.append(summary_table)
        
        # Technical Details
        technical_details = report_data.get('technical_details', {})
        if technical_details:
            content.append(PageBreak())
            content.append(Paragraph("Technical Details", heading_style))
            
            tech_data = []
            for key, value in technical_details.items():
                if value:
                    tech_data.append([key.replace('_', ' ').title() + ':', str(value)])
            
            if tech_data:
                tech_table = Table(tech_data, colWidths=[2*inch, 4*inch])
                tech_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb'))
                ]))
                content.append(tech_table)
        
        # Build PDF
        doc.build(content)
        
        # Get PDF data
        buffer.seek(0)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        raise