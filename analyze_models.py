"""
Script to analyze actual model input/output shapes and requirements
"""
import os
import sys
import tensorflow as tf
import pickle
import numpy as np

def analyze_tensorflow_model(model_path):
    """Analyze TensorFlow model input/output shapes"""
    try:
        model = tf.keras.models.load_model(model_path, compile=False)
        print(f"\nModel: {os.path.basename(model_path)}")
        print(f"Input shape: {model.input_shape}")
        print(f"Output shape: {model.output_shape}")
        
        # Try to get layer info
        print("Layers:")
        for i, layer in enumerate(model.layers[:5]):  # First 5 layers
            print(f"  {i}: {layer.name} -> {layer.output_shape}")
        if len(model.layers) > 5:
            print(f"  ... and {len(model.layers)-5} more layers")
            
        return {
            'input_shape': model.input_shape,
            'output_shape': model.output_shape,
            'total_params': model.count_params(),
            'layers': len(model.layers)
        }
    except Exception as e:
        print(f"Error loading {model_path}: {str(e)}")
        return None

def analyze_sklearn_model(model_path):
    """Analyze scikit-learn model"""
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        print(f"\nModel: {os.path.basename(model_path)}")
        print(f"Model type: {type(model).__name__}")
        
        if hasattr(model, 'n_features_in_'):
            print(f"Input features: {model.n_features_in_}")
        if hasattr(model, 'classes_'):
            print(f"Output classes: {len(model.classes_)} classes")
            print(f"Class names: {model.classes_[:5]}..." if len(model.classes_) > 5 else f"Class names: {model.classes_}")
        
        return {
            'model_type': type(model).__name__,
            'input_features': getattr(model, 'n_features_in_', 'unknown'),
            'output_classes': len(model.classes_) if hasattr(model, 'classes_') else 'unknown'
        }
    except Exception as e:
        print(f"Error loading {model_path}: {str(e)}")
        return None

def main():
    models_dir = "models"
    
    print("ANALYZING CURRENT AI MODELS")
    print("="*50)
    
    results = {}
    
    # TensorFlow models
    tf_models = [
        'wifi_vulnerability_cnn_final.h5',
        'wifi_lstm_model.h5', 
        'wifi_lstm_production.h5',
        'gnn_wifi_vulnerability_model.h5',
        'crypto_bert_enhanced.h5',
        'wifi_cnn_lstm_model.h5',
        'wifi_attention_model.h5'
    ]
    
    print("\nTENSORFLOW MODELS:")
    for model_file in tf_models:
        model_path = os.path.join(models_dir, model_file)
        if os.path.exists(model_path):
            result = analyze_tensorflow_model(model_path)
            if result:
                results[model_file] = result
    
    # Scikit-learn models
    sklearn_models = [
        'wifi_random_forest_model.pkl',
        'wifi_gradient_boosting_model.pkl'
    ]
    
    print("\nSCIKIT-LEARN MODELS:")
    for model_file in sklearn_models:
        model_path = os.path.join(models_dir, model_file)
        if os.path.exists(model_path):
            result = analyze_sklearn_model(model_path)
            if result:
                results[model_file] = result
    
    # Summary
    print("\nSUMMARY:")
    print("="*50)
    working_models = len([r for r in results.values() if r is not None])
    total_models = len(tf_models + sklearn_models)
    print(f"Working models: {working_models}/{total_models}")
    
    print("\nINPUT SHAPES DETECTED:")
    for model_name, info in results.items():
        if info and 'input_shape' in info:
            print(f"  {model_name}: {info['input_shape']}")
        elif info and 'input_features' in info:
            print(f"  {model_name}: {info['input_features']} features")
    
    print("\nOUTPUT SHAPES DETECTED:")
    for model_name, info in results.items():
        if info and 'output_shape' in info:
            print(f"  {model_name}: {info['output_shape']}")
        elif info and 'output_classes' in info:
            print(f"  {model_name}: {info['output_classes']} classes")
    
    return results

if __name__ == "__main__":
    results = main()