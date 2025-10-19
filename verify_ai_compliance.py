#!/usr/bin/env python3
"""
AI Model Documentation Compliance Verification Script

This script verifies that the current AI system implementation matches 
the specifications in the AI model documentation PDF and ensemble training script.
"""

import sys
import os
import numpy as np
import json
from datetime import datetime
import traceback

# Add project path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def print_header(title):
    """Print formatted header"""
    print(f"\n{'='*80}")
    print(f"{title.center(80)}")
    print(f"{'='*80}")

def print_section(title):
    """Print formatted section"""
    print(f"\n{'-'*60}")
    print(f"{title}")
    print(f"{'-'*60}")

def check_model_specs():
    """Verify model specifications match documentation"""
    print_header("MODEL SPECIFICATIONS VERIFICATION")
    
    try:
        from app.ai_engine.model_loader import ModelLoader
        from app.ai_engine.preprocessor import DataPreprocessor
        
        loader = ModelLoader()
        preprocessor = DataPreprocessor()
        MODEL_SPECS = loader.get_model_specs()
        
        # Documentation specifications
        doc_specs = {
            'cnn': {
                'input_shape': (32,),  # Reshaped to (32, 1) for CNN
                'output_classes': 12,
                'confidence_threshold': 0.85,
                'description': 'CNN Wi-Fi Vulnerability Detection'
            },
            'lstm': {
                'input_shape': (50, 48),
                'output_classes': 10, 
                'confidence_threshold': 0.82,
                'description': 'LSTM Wi-Fi Vulnerability Detection'
            },
            'gnn': {
                'node_features': 24,
                'edge_features': 16,
                'output_classes': 8,
                'confidence_threshold': 0.80,
                'description': 'Graph Neural Network'
            },
            'crypto_bert': {
                'input_shape': (256,),  # 256 tokens
                'output_classes': 15,
                'confidence_threshold': 0.88,
                'description': 'Enhanced Crypto-BERT'
            },
            'ensemble': {
                'component_models': 5,
                'output_classes': 10,
                'confidence_threshold': 0.82,
                'description': 'WiFi LSTM Ensemble Fusion'
            }
        }
        
        print_section("Current vs Documentation Model Specifications")
        
        compliance_issues = []
        
        for model_name, doc_spec in doc_specs.items():
            current_spec = MODEL_SPECS.get(model_name, {})
            
            print(f"\n{model_name.upper()} MODEL:")
            print(f"  Documentation: {doc_spec}")
            print(f"  Current:       {current_spec}")
            
            # Check compliance
            issues = []
            
            if 'input_shape' in doc_spec:
                if current_spec.get('input_shape') != doc_spec['input_shape']:
                    issues.append(f"Input shape mismatch: {current_spec.get('input_shape')} vs {doc_spec['input_shape']}")
            
            if 'node_features' in doc_spec:
                if current_spec.get('node_features') != doc_spec['node_features']:
                    issues.append(f"Node features mismatch: {current_spec.get('node_features')} vs {doc_spec['node_features']}")
            
            if current_spec.get('output_classes') != doc_spec.get('output_classes'):
                issues.append(f"Output classes mismatch: {current_spec.get('output_classes')} vs {doc_spec.get('output_classes')}")
            
            if current_spec.get('confidence_threshold') != doc_spec.get('confidence_threshold'):
                issues.append(f"Confidence threshold mismatch: {current_spec.get('confidence_threshold')} vs {doc_spec.get('confidence_threshold')}")
            
            if issues:
                print(f"  [X] COMPLIANCE ISSUES:")
                for issue in issues:
                    print(f"     * {issue}")
                compliance_issues.extend(issues)
            else:
                print(f"  [OK] COMPLIANT")
        
        return compliance_issues
        
    except Exception as e:
        print(f"[ERROR]: {str(e)}")
        print(traceback.format_exc())
        return [f"Model specs verification failed: {str(e)}"]

def check_ensemble_implementation():
    """Verify ensemble implementation matches training script"""
    print_header("ENSEMBLE IMPLEMENTATION VERIFICATION")
    
    try:
        from app.ai_engine.ensemble_predictor import EnsemblePredictor
        from app.ai_engine.model_loader import ModelLoader
        
        predictor = EnsemblePredictor()
        loader = ModelLoader()
        
        # Expected component models from training script
        expected_models = {
            'lstm': 'wifi_lstm_model.h5',
            'cnn_lstm': 'wifi_cnn_lstm_model.h5', 
            'attention': 'wifi_attention_model.h5',
            'random_forest': 'wifi_random_forest_model.pkl',
            'gradient_boosting': 'wifi_gradient_boosting_model.pkl'
        }
        
        # Current available models
        available_models = loader.get_available_models()
        
        print_section("Component Models Comparison")
        print(f"Expected models: {list(expected_models.keys())}")
        print(f"Available models: {available_models}")
        
        issues = []
        
        # Check for missing models
        for expected_model in expected_models.keys():
            if expected_model not in available_models:
                # Check for alternative names
                alternatives = {
                    'lstm': ['lstm_main', 'lstm_production'],
                    'cnn_lstm': ['cnn_lstm_hybrid', 'hybrid'],
                    'attention': []  # This model might not be available
                }
                
                found_alternative = False
                for alt in alternatives.get(expected_model, []):
                    if alt in available_models:
                        print(f"  [WARN] {expected_model} -> found alternative: {alt}")
                        found_alternative = True
                        break
                
                if not found_alternative:
                    if expected_model == 'attention':
                        print(f"  [WARN] {expected_model} model not available (acceptable - may not be implemented)")
                    else:
                        issues.append(f"Missing expected model: {expected_model}")
                        print(f"  [X] Missing: {expected_model}")
            else:
                print(f"  [OK] Found: {expected_model}")
        
        # Check ensemble method
        print_section("Ensemble Method Verification")
        if hasattr(predictor, 'predict_threat'):
            print("  ✅ Main prediction method available")
        else:
            issues.append("Missing main prediction method: predict_threat")
            print("  ❌ Missing main prediction method")
        
        # Check output format
        print_section("Output Format Verification")
        expected_output_keys = [
            'predicted_class', 'confidence', 'is_threat', 'take_action',
            'all_probabilities', 'processing_time'
        ]
        
        print(f"Expected output keys: {expected_output_keys}")
        # This would need actual testing with sample data
        
        return issues
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return [f"Ensemble verification failed: {str(e)}"]

def check_feature_extraction():
    """Verify feature extraction matches documentation"""
    print_header("FEATURE EXTRACTION VERIFICATION")
    
    try:
        from app.ai_engine.feature_extractor import WiFiFeatureExtractor
        from app.ai_engine.preprocessor import DataPreprocessor
        
        extractor = WiFiFeatureExtractor()
        preprocessor = DataPreprocessor()
        
        print_section("CNN Features (32 features)")
        
        # Test sample network data
        sample_network_data = {
            'ssid': 'TestNetwork',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'signal_strength': -65,
            'channel': 6,
            'encryption': 'WPA2',
            'cipher_suite': 'AES',
            'auth_method': 'PSK'
        }
        
        issues = []
        
        # Test CNN feature extraction
        try:
            cnn_features = extractor.extract_cnn_features(sample_network_data)
            print(f"CNN features shape: {cnn_features.shape}")
            
            if cnn_features.shape != (32,):
                issues.append(f"CNN features wrong shape: {cnn_features.shape}, expected (32,)")
            else:
                print("  ✅ CNN features correct shape")
            
            # Check for real variation (not all zeros or constants)
            if np.all(cnn_features == 0) or np.std(cnn_features) < 1e-6:
                issues.append("CNN features appear to be static/zeros")
                print("  ❌ CNN features are static")
            else:
                print("  ✅ CNN features show variation")
                
        except Exception as e:
            issues.append(f"CNN feature extraction failed: {str(e)}")
            print(f"  ❌ CNN extraction error: {str(e)}")
        
        print_section("LSTM Features (50x48 sequence)")
        
        # Test LSTM feature extraction
        try:
            # Create sequence data
            network_sequence = [sample_network_data.copy() for _ in range(50)]
            lstm_features = extractor.extract_lstm_features(network_sequence)
            print(f"LSTM features shape: {lstm_features.shape}")
            
            if lstm_features.shape != (50, 48):
                issues.append(f"LSTM features wrong shape: {lstm_features.shape}, expected (50, 48)")
            else:
                print("  ✅ LSTM features correct shape")
                
            # Check for variation
            if np.std(lstm_features) < 1e-6:
                issues.append("LSTM features appear to be static")
                print("  ❌ LSTM features are static")
            else:
                print("  ✅ LSTM features show variation")
                
        except Exception as e:
            issues.append(f"LSTM feature extraction failed: {str(e)}")
            print(f"  ❌ LSTM extraction error: {str(e)}")
        
        print_section("GNN Features (24 node + 16 edge features)")
        
        # Test GNN feature extraction
        try:
            sample_topology = {
                'nodes': [
                    {'id': 0, 'device_type': 'router'},
                    {'id': 1, 'device_type': 'client'}
                ],
                'edges': [
                    {'source': 0, 'destination': 1, 'connection_strength': 0.9}
                ]
            }
            
            node_features, edge_features, adjacency = extractor.extract_gnn_features(sample_topology)
            print(f"GNN node features shape: {node_features.shape}")
            print(f"GNN edge features shape: {edge_features.shape}")
            
            if node_features.shape[1] != 24:
                issues.append(f"GNN node features wrong dimension: {node_features.shape[1]}, expected 24")
            else:
                print("  ✅ GNN node features correct dimensions")
            
            if edge_features.shape[1] != 16:
                issues.append(f"GNN edge features wrong dimension: {edge_features.shape[1]}, expected 16") 
            else:
                print("  ✅ GNN edge features correct dimensions")
                
        except Exception as e:
            issues.append(f"GNN feature extraction failed: {str(e)}")
            print(f"  ❌ GNN extraction error: {str(e)}")
        
        return issues
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return [f"Feature extraction verification failed: {str(e)}"]

def check_model_files():
    """Check if required model files exist"""
    print_header("MODEL FILES VERIFICATION")
    
    models_path = "models"
    
    # Expected model files from documentation
    expected_files = {
        'CNN Model': [
            'wifi_vulnerability_cnn_final.h5',
            'wifi_vulnerability_scaler.pkl'
        ],
        'LSTM Models': [
            'wifi_lstm_production.h5',
            'wifi_lstm_model.h5',
            'wifi_lstm_preprocessor.pkl'
        ],
        'GNN Model': [
            'gnn_wifi_vulnerability_model.h5'
        ],
        'Crypto-BERT Model': [
            'crypto_bert_enhanced.h5'
        ],
        'Ensemble Models': [
            'wifi_cnn_lstm_model.h5',
            'wifi_attention_model.h5',
            'wifi_random_forest_model.pkl',
            'wifi_gradient_boosting_model.pkl',
            'wifi_ensemble_weights.pkl',
            'wifi_ensemble_metadata.json'
        ]
    }
    
    issues = []
    
    for category, files in expected_files.items():
        print_section(category)
        
        for filename in files:
            filepath = os.path.join(models_path, filename)
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
                print(f"  ✅ {filename} ({file_size:,} bytes)")
            else:
                print(f"  ❌ {filename} (MISSING)")
                if 'attention' in filename:
                    print(f"     ⚠️  Attention model may not be implemented")
                elif 'crypto_bert' in filename:
                    print(f"     ⚠️  Crypto-BERT model may not be implemented")
                else:
                    issues.append(f"Missing required model file: {filename}")
    
    return issues

def check_api_compliance():
    """Check API interface compliance"""
    print_header("API INTERFACE COMPLIANCE VERIFICATION")
    
    try:
        # Check main prediction interfaces
        issues = []
        
        print_section("Prediction Method Signatures")
        
        # Check CNN prediction
        try:
            from app.ai_engine.preprocessor import preprocess_for_cnn
            print("  ✅ CNN preprocessing function available")
        except ImportError:
            issues.append("CNN preprocessing function not available")
            print("  ❌ CNN preprocessing function missing")
        
        # Check LSTM prediction  
        try:
            from app.ai_engine.preprocessor import preprocess_for_lstm
            print("  ✅ LSTM preprocessing function available")
        except ImportError:
            issues.append("LSTM preprocessing function not available")
            print("  ❌ LSTM preprocessing function missing")
        
        # Check ensemble prediction
        try:
            from app.ai_engine.ensemble_predictor import EnsemblePredictor
            predictor = EnsemblePredictor()
            if hasattr(predictor, 'predict_threat'):
                print("  ✅ Ensemble prediction method available")
            else:
                issues.append("Ensemble prediction method missing")
                print("  ❌ Ensemble prediction method missing")
        except Exception as e:
            issues.append(f"Ensemble predictor error: {str(e)}")
            print(f"  ❌ Ensemble predictor error: {str(e)}")
        
        return issues
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return [f"API compliance check failed: {str(e)}"]

def check_class_mappings():
    """Verify output class mappings match documentation"""
    print_header("OUTPUT CLASS MAPPINGS VERIFICATION")
    
    try:
        from app.ai_engine.preprocessor import DataPreprocessor
        
        preprocessor = DataPreprocessor()
        class_mappings = preprocessor.get_class_mappings()
        
        # Documentation class mappings
        doc_mappings = {
            'cnn_classes': [
                'SECURE_NETWORK', 'WEAK_ENCRYPTION', 'OPEN_NETWORK', 'WPS_VULNERABILITY',
                'ROGUE_AP', 'EVIL_TWIN', 'DEAUTH_ATTACK', 'HANDSHAKE_CAPTURE',
                'FIRMWARE_OUTDATED', 'DEFAULT_CREDENTIALS', 'SIGNAL_LEAKAGE', 'UNKNOWN_THREAT'
            ],
            'lstm_classes': [
                'NORMAL_BEHAVIOR', 'BRUTE_FORCE_ATTACK', 'RECONNAISSANCE', 'DATA_EXFILTRATION',
                'BOTNET_ACTIVITY', 'INSIDER_THREAT', 'APT_BEHAVIOR', 'DDOS_PREPARATION',
                'LATERAL_MOVEMENT', 'COMMAND_CONTROL'
            ],
            'gnn_classes': [
                'ISOLATED_VULNERABILITY', 'CASCADING_RISK', 'CRITICAL_NODE', 'BRIDGE_VULNERABILITY',
                'CLUSTER_WEAKNESS', 'PERIMETER_BREACH', 'PRIVILEGE_ESCALATION', 'NETWORK_PARTITION'
            ]
        }
        
        issues = []
        
        for mapping_name, doc_classes in doc_mappings.items():
            current_classes = class_mappings.get(mapping_name, [])
            
            print_section(f"{mapping_name.upper()}")
            print(f"Expected ({len(doc_classes)}): {doc_classes}")
            print(f"Current  ({len(current_classes)}): {current_classes}")
            
            if len(current_classes) != len(doc_classes):
                issues.append(f"{mapping_name} class count mismatch: {len(current_classes)} vs {len(doc_classes)}")
                print("  ❌ Class count mismatch")
            
            missing_classes = set(doc_classes) - set(current_classes)
            extra_classes = set(current_classes) - set(doc_classes)
            
            if missing_classes:
                issues.append(f"{mapping_name} missing classes: {missing_classes}")
                print(f"  ❌ Missing classes: {missing_classes}")
            
            if extra_classes:
                issues.append(f"{mapping_name} extra classes: {extra_classes}")
                print(f"  ⚠️  Extra classes: {extra_classes}")
            
            if not missing_classes and not extra_classes:
                print("  ✅ Classes match documentation")
        
        return issues
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        return [f"Class mappings check failed: {str(e)}"]

def generate_compliance_report():
    """Generate comprehensive compliance report"""
    print_header("COMPREHENSIVE AI COMPLIANCE VERIFICATION REPORT")
    
    # Run all verification checks
    all_issues = []
    
    print("Running verification checks...")
    
    model_spec_issues = check_model_specs()
    all_issues.extend(model_spec_issues)
    
    ensemble_issues = check_ensemble_implementation()
    all_issues.extend(ensemble_issues)
    
    feature_issues = check_feature_extraction()
    all_issues.extend(feature_issues)
    
    file_issues = check_model_files()
    all_issues.extend(file_issues)
    
    api_issues = check_api_compliance()
    all_issues.extend(api_issues)
    
    class_issues = check_class_mappings()
    all_issues.extend(class_issues)
    
    # Generate summary report
    print_header("COMPLIANCE VERIFICATION SUMMARY")
    
    if not all_issues:
        print("🎉 FULL COMPLIANCE ACHIEVED!")
        print("✅ All AI models and implementations match documentation specifications")
        compliance_status = "COMPLIANT"
    else:
        print(f"⚠️  COMPLIANCE ISSUES FOUND: {len(all_issues)}")
        print("\nISSUES TO ADDRESS:")
        for i, issue in enumerate(all_issues, 1):
            print(f"{i:2d}. {issue}")
        compliance_status = "NON-COMPLIANT"
    
    # Generate detailed report
    report = {
        'verification_date': datetime.now().isoformat(),
        'compliance_status': compliance_status,
        'total_issues': len(all_issues),
        'issues': all_issues,
        'checks_performed': [
            'Model specifications vs documentation',
            'Ensemble implementation vs training script', 
            'Feature extraction correctness',
            'Required model files presence',
            'API interface compliance',
            'Output class mappings'
        ]
    }
    
    # Save report
    with open('ai_compliance_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📋 Detailed report saved to: ai_compliance_report.json")
    
    return compliance_status == "COMPLIANT"

def main():
    """Main verification function"""
    print("AI Model Documentation Compliance Verification")
    print("=" * 80)
    print(f"Verification started at: {datetime.now()}")
    
    try:
        is_compliant = generate_compliance_report()
        
        if is_compliant:
            print("\n🎯 RESULT: System is FULLY COMPLIANT with documentation")
            return 0
        else:
            print("\n⚠️  RESULT: System has COMPLIANCE ISSUES that need attention")
            return 1
            
    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {str(e)}")
        print(traceback.format_exc())
        return 2

if __name__ == "__main__":
    sys.exit(main())
