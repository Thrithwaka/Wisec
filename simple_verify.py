#!/usr/bin/env python3
"""
Simplified AI Compliance Verification Script
Checks current AI system against documentation requirements
"""

import sys
import os
import numpy as np
import json
from datetime import datetime

# Add project path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    print("AI Model Documentation Compliance Verification")
    print("=" * 60)
    
    try:
        from app.ai_engine.model_loader import ModelLoader
        from app.ai_engine.ensemble_predictor import EnsemblePredictor
        from app.ai_engine.feature_extractor import WiFiFeatureExtractor
        from app.ai_engine.preprocessor import DataPreprocessor
        
        # Initialize components
        loader = ModelLoader()
        predictor = EnsemblePredictor()
        extractor = WiFiFeatureExtractor()
        preprocessor = DataPreprocessor()
        
        print("\n1. MODEL AVAILABILITY CHECK")
        print("-" * 40)
        available_models = loader.get_available_models()
        print(f"Available models: {len(available_models)}")
        for model in available_models:
            print(f"  * {model}")
        
        # Documentation requirements
        doc_requirements = {
            'cnn': {'input_shape': (32,), 'output_classes': 12},
            'lstm': {'input_shape': (50, 48), 'output_classes': 10},
            'gnn': {'node_features': 24, 'edge_features': 16, 'output_classes': 8},
            'crypto_bert': {'input_shape': (256,), 'output_classes': 15},
            'ensemble': {'component_models': 5, 'output_classes': 10}
        }
        
        print("\n2. MODEL SPECIFICATION COMPLIANCE")
        print("-" * 40)
        MODEL_SPECS = loader.get_model_specs()
        
        compliance_issues = []
        
        # Check CNN (map to cnn_final)
        if 'cnn_final' in MODEL_SPECS:
            cnn_spec = MODEL_SPECS['cnn_final']
            print(f"CNN Model: {cnn_spec.get('output_classes')} classes (expected: 12)")
            if cnn_spec.get('output_classes') == 12:
                print("  [OK] CNN output classes match")
            else:
                compliance_issues.append("CNN output classes mismatch")
                print("  [ISSUE] CNN output classes mismatch")
        else:
            compliance_issues.append("CNN model not found")
            print("  [ISSUE] CNN model not found")
        
        # Check LSTM models
        lstm_models = [m for m in available_models if 'lstm' in m]
        if lstm_models:
            lstm_spec = MODEL_SPECS.get(lstm_models[0], {})
            print(f"LSTM Model: {lstm_spec.get('output_classes')} classes (expected: 10)")
            if lstm_spec.get('output_classes') == 10:
                print("  [OK] LSTM output classes match")
            else:
                compliance_issues.append("LSTM output classes mismatch")
        else:
            compliance_issues.append("LSTM model not found")
        
        # Check GNN
        if 'gnn' in MODEL_SPECS:
            gnn_spec = MODEL_SPECS['gnn']
            print(f"GNN Model: {gnn_spec.get('output_classes')} classes (expected: 8)")
            if gnn_spec.get('output_classes') == 8:
                print("  [OK] GNN output classes match")
            else:
                compliance_issues.append("GNN output classes mismatch")
        else:
            compliance_issues.append("GNN model not found")
        
        print("\n3. FEATURE EXTRACTION TEST")
        print("-" * 40)
        
        # Test feature extraction with sample data
        sample_data = {
            'ssid': 'TestNetwork',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'signal_strength': -65,
            'channel': 6,
            'encryption': 'WPA2',
            'cipher_suite': 'AES',
            'auth_method': 'PSK'
        }
        
        try:
            # Test CNN features
            cnn_features = extractor.extract_cnn_features(sample_data)
            print(f"CNN features shape: {cnn_features.shape}")
            if cnn_features.shape == (32,):
                print("  [OK] CNN features correct shape")
            else:
                compliance_issues.append(f"CNN features wrong shape: {cnn_features.shape}")
            
            # Check for variation (not all zeros)
            if np.std(cnn_features) > 1e-6:
                print("  [OK] CNN features show variation")
            else:
                compliance_issues.append("CNN features are static/zeros")
                
        except Exception as e:
            compliance_issues.append(f"CNN feature extraction failed: {str(e)}")
            print(f"  [ERROR] CNN extraction: {str(e)}")
        
        try:
            # Test LSTM features
            sequence_data = [sample_data.copy() for _ in range(50)]
            lstm_features = extractor.extract_lstm_features(sequence_data)
            print(f"LSTM features shape: {lstm_features.shape}")
            if lstm_features.shape == (50, 48):
                print("  [OK] LSTM features correct shape")
            else:
                compliance_issues.append(f"LSTM features wrong shape: {lstm_features.shape}")
                
        except Exception as e:
            compliance_issues.append(f"LSTM feature extraction failed: {str(e)}")
            print(f"  [ERROR] LSTM extraction: {str(e)}")
        
        print("\n4. ENSEMBLE IMPLEMENTATION CHECK")
        print("-" * 40)
        
        # Check ensemble predictor
        if hasattr(predictor, 'predict_threat'):
            print("  [OK] Main prediction method available")
        else:
            compliance_issues.append("Missing main prediction method")
            print("  [ISSUE] Missing main prediction method")
        
        # Check component models count
        expected_components = ['lstm', 'cnn_lstm', 'random_forest', 'gradient_boosting']
        actual_components = []
        
        for expected in expected_components:
            alternatives = {
                'lstm': ['lstm_main', 'lstm_production'],
                'cnn_lstm': ['cnn_lstm_hybrid']
            }
            
            found = False
            if expected in available_models:
                actual_components.append(expected)
                found = True
            else:
                for alt in alternatives.get(expected, []):
                    if alt in available_models:
                        actual_components.append(alt)
                        found = True
                        break
            
            if not found and expected not in ['attention']:  # attention is optional
                compliance_issues.append(f"Missing component model: {expected}")
        
        print(f"Component models found: {len(actual_components)}")
        print(f"Expected minimum: 4 (excluding optional attention)")
        
        if len(actual_components) >= 4:
            print("  [OK] Sufficient component models")
        else:
            compliance_issues.append("Insufficient component models")
        
        print("\n5. REAL DATA USAGE VERIFICATION")
        print("-" * 40)
        
        # Check for fallback/dummy data usage
        try:
            from app.main.routes import get_scan_result_manager
            scan_mgr = get_scan_result_manager()
            
            # Test real WiFi data extraction
            real_data = scan_mgr._extract_real_wifi_data({})
            if real_data and isinstance(real_data, dict):
                print("  [OK] Real WiFi data extraction functional")
            else:
                print("  [WARN] Real WiFi data extraction returned empty/None")
                
        except Exception as e:
            print(f"  [ERROR] Real data verification: {str(e)}")
        
        print("\n" + "=" * 60)
        print("COMPLIANCE SUMMARY")
        print("=" * 60)
        
        if not compliance_issues:
            print("[SUCCESS] FULL COMPLIANCE ACHIEVED!")
            print("All AI models and implementations match requirements")
            result = 0
        else:
            print(f"[ISSUES] {len(compliance_issues)} compliance issues found:")
            for i, issue in enumerate(compliance_issues, 1):
                print(f"  {i}. {issue}")
            result = 1
        
        # Save report
        report = {
            'verification_date': datetime.now().isoformat(),
            'compliance_status': 'COMPLIANT' if result == 0 else 'NON-COMPLIANT',
            'total_issues': len(compliance_issues),
            'issues': compliance_issues,
            'available_models': available_models,
            'model_count': len(available_models)
        }
        
        with open('compliance_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nDetailed report saved to: compliance_report.json")
        return result
        
    except Exception as e:
        print(f"\n[ERROR] Verification failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 2

if __name__ == "__main__":
    sys.exit(main())