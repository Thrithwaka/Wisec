#!/usr/bin/env python3
"""
Check if CNN Final is receiving the correct 32 features
"""

import numpy as np
import sys
import os

# Add project path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def check_cnn_input_flow():
    """Check the complete data flow to CNN Final"""
    
    print("=== CHECKING CNN FINAL INPUT FLOW ===")
    print("=" * 50)
    
    from app.ai_engine.feature_extractor import WiFiFeatureExtractor
    from app.ai_engine.ensemble_predictor import ensemble_predictor
    from app.ai_engine.model_loader import model_loader
    
    # Test network data
    network_data = {
        'ssid': 'TestNetwork',
        'signal_strength': 75,
        'channel': 6,
        'encryption': 'WPA2',
        'cipher_suite': 'AES',
        'auth_method': 'PSK'
    }
    
    print("\n1. FEATURE EXTRACTION STEP")
    print("-" * 30)
    
    extractor = WiFiFeatureExtractor()
    cnn_features = extractor.extract_cnn_features(network_data)
    
    if cnn_features is not None:
        print(f"✓ CNN features extracted: shape {cnn_features.shape}")
        print(f"✓ Matches documentation: {cnn_features.shape == (32,)}")
        print(f"  First 5 features: {cnn_features[:5]}")
        print(f"  Last 5 features: {cnn_features[-5:]}")
    else:
        print("✗ CNN feature extraction failed")
        return
    
    print("\n2. ENSEMBLE PREDICTOR DATA PREPARATION")  
    print("-" * 40)
    
    # Let's trace what happens inside the ensemble predictor
    # We need to check the predict_proba method
    try:
        # Extract the same features that the predictor would
        sequence_data = [network_data.copy() for _ in range(50)]
        lstm_features = extractor.extract_lstm_features(sequence_data)
        
        print(f"✓ LSTM features shape: {lstm_features.shape}")
        print(f"  Expected: (50, 48)")
        print(f"  Match: {lstm_features.shape == (50, 48)}")
        
        # The key question: How does the ensemble predictor convert LSTM features to CNN features?
        print(f"\n3. CRITICAL ISSUE DETECTION")
        print("-" * 30)
        
        print("CHECKING ENSEMBLE PREDICTOR SOURCE CODE...")
        
        # Get the CNN model
        cnn_model = model_loader.get_model('cnn_final')
        if cnn_model:
            print("✓ CNN Final model loaded")
            
            # Test direct prediction with correct features
            test_batch = cnn_features.reshape(1, -1)  # (1, 32)
            print(f"✓ Direct CNN input shape: {test_batch.shape}")
            
            cnn_pred = cnn_model.predict(test_batch, verbose=0)
            print(f"✓ Direct CNN prediction works: {cnn_pred.shape}")
            print(f"  Prediction: {np.argmax(cnn_pred[0])}")
            
        else:
            print("✗ CNN Final model not loaded")
            
        print(f"\n4. ENSEMBLE PREDICTOR ANALYSIS")
        print("-" * 35)
        
        # Call the ensemble predictor and check what it does internally
        print("Testing ensemble predictor predict_single()...")
        
        result = ensemble_predictor.predict_single(network_data)
        
        print(f"✓ Ensemble prediction successful")
        print(f"  Predicted class: {result.get('predicted_class')}")
        print(f"  Individual confidences: {result.get('individual_confidences', {})}")
        
        # The key question: Are the CNN features being extracted correctly inside the ensemble?
        print(f"\n5. PROBLEM IDENTIFICATION")
        print("-" * 25)
        
        print("CHECKING WHAT FEATURES ARE PASSED TO CNN INSIDE ENSEMBLE...")
        
        # Let's manually trace the predict_proba method
        # First, prepare data like the ensemble does
        X_scaled = lstm_features.reshape(1, 50, 48)  # (1, 50, 48)
        
        print(f"X_scaled shape (for LSTM): {X_scaled.shape}")
        
        # For CNN, the ensemble might be using different logic
        # Let's check by looking at ensemble_predictor source
        
        print("\nISSUE: The ensemble predictor extract_features_for_cnn() method")
        print("       needs to be checked to see if it's extracting the")
        print("       correct 32 CNN features!")
        
        # Test what features are actually passed to CNN
        try:
            # Get CNN features the way ensemble does it
            cnn_features_from_ensemble = ensemble_predictor._extract_features_for_cnn(network_data)
            
            print(f"\nCNN features from ensemble: {cnn_features_from_ensemble.shape}")
            print(f"Expected: (32,)")
            print(f"Match: {cnn_features_from_ensemble.shape == (32,)}")
            
            if cnn_features_from_ensemble.shape == (32,):
                print("✓ CORRECT: Ensemble is extracting 32 CNN features")
                
                # Compare features
                diff = np.abs(cnn_features - cnn_features_from_ensemble).max()
                print(f"  Max difference from direct extraction: {diff:.6f}")
                
                if diff < 0.001:
                    print("✓ CORRECT: Features match direct extraction")
                else:
                    print("⚠  WARNING: Features differ from direct extraction")
                    
            else:
                print("✗ PROBLEM: Ensemble is NOT extracting 32 CNN features!")
                print(f"  Actual shape: {cnn_features_from_ensemble.shape}")
                
        except AttributeError:
            print("⚠  WARNING: _extract_features_for_cnn method not found")
            print("  Need to check how CNN features are prepared in ensemble")
        except Exception as e:
            print(f"✗ ERROR: {e}")
        
        print("\n" + "=" * 50)
        print("CNN INPUT FLOW CHECK COMPLETE")
        print("=" * 50)
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_cnn_input_flow()