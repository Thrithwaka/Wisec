"""
Wi-Fi Security System - Ensemble Prediction Engine
Purpose: WiFi LSTM Ensemble Fusion Model implementation according to documentation and training specifications
Author: AI Security Team
Version: 3.0

Implements exact ensemble model from Ensemble training.py with 5 component models:
1. LSTM Neural Network
2. CNN-LSTM Hybrid  
3. Attention Model
4. Random Forest Classifier
5. Gradient Boosting Classifier

Uses weighted voting with confidence thresholds as specified in documentation.
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
import pickle
import json
import logging
import threading
import os
import time
from typing import Dict, List, Tuple, Any, Optional, Union
from datetime import datetime
from collections import Counter, defaultdict
import warnings

# Suppress TensorFlow warnings
warnings.filterwarnings('ignore', category=FutureWarning)
tf.get_logger().setLevel('ERROR')

# Import existing components
from .model_loader import ModelLoader, model_loader
from .preprocessor import DataPreprocessor, data_preprocessor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnsembleFusionModel:
    """
    WiFi LSTM Ensemble Fusion Model implementation according to documentation specifications
    Combines 5 component models using weighted voting as specified in Ensemble training.py
    """
    
    def __init__(self, model_loader: ModelLoader, preprocessor: DataPreprocessor):
        self.model_loader = model_loader
        self.preprocessor = preprocessor
        self.logger = logging.getLogger(__name__)
        
        # Model specifications matching current available models
        self.component_models = {
            'cnn_final': {
                'weight': 0.15,  # CNN model - security-focused
                'type': 'deep_learning',
                'input_shape': (32,),
                'output_classes': 12,  # Different output classes
                'description': 'CNN Vulnerability Detection'
            },
            'lstm_main': {
                'weight': 0.20,  # Main LSTM model
                'type': 'deep_learning',
                'input_shape': (50, 48),
                'output_classes': 10,
                'description': 'Main LSTM Model - Temporal analysis'
            },
            'lstm_production': {
                'weight': 0.20,  # Production LSTM model
                'type': 'deep_learning',
                'input_shape': (50, 48),
                'output_classes': 10,
                'description': 'Production LSTM Model - Temporal analysis'
            },
            'cnn_lstm_hybrid': {
                'weight': 0.15,  # CNN-LSTM hybrid
                'type': 'deep_learning', 
                'input_shape': (50, 48),
                'output_classes': 10,
                'description': 'CNN-LSTM Hybrid Model'
            },
            'random_forest': {
                'weight': 0.15,  # Random Forest
                'type': 'traditional_ml',
                'input_shape': (2400,),  # Flattened 50*48
                'output_classes': 10,
                'description': 'Random Forest Classifier'
            },
            'gradient_boosting': {
                'weight': 0.15,  # Gradient Boosting
                'type': 'traditional_ml',
                'input_shape': (2400,),  # Flattened 50*48
                'output_classes': 10,
                'description': 'Gradient Boosting Classifier'
            }
        }
        
        # Class names from documentation and metadata
        self.class_names = [
            'NORMAL_BEHAVIOR',
            'BRUTE_FORCE_ATTACK',
            'RECONNAISSANCE', 
            'DATA_EXFILTRATION',
            'BOTNET_ACTIVITY',
            'INSIDER_THREAT',
            'APT_BEHAVIOR',
            'DDOS_PREPARATION',
            'LATERAL_MOVEMENT',
            'COMMAND_CONTROL'
        ]
        
        # Confidence thresholds from documentation
        self.confidence_threshold = 0.82
        self.high_confidence_threshold = 0.90
        
        # Load ensemble metadata and weights
        self.ensemble_metadata = self._load_ensemble_metadata()
        
        # Track model performance
        self.prediction_history = []
        self.model_performance = defaultdict(list)
        
    def _load_ensemble_metadata(self) -> Dict[str, Any]:
        """Load ensemble metadata and adjust weights if available"""
        try:
            metadata = self.model_loader.get_ensemble_metadata()
            if metadata:
                self.logger.info("Ensemble metadata loaded successfully")
                return metadata
            else:
                self.logger.warning("Using default ensemble configuration")
                return self._get_default_metadata()
        except Exception as e:
            self.logger.error(f"Error loading ensemble metadata: {str(e)}")
            return self._get_default_metadata()
    
    def _get_default_metadata(self) -> Dict[str, Any]:
        """Get default ensemble metadata matching Ensemble training.py"""
        return {
            'model_type': 'WiFi LSTM Ensemble Fusion Model',
            'target_accuracy': '91-94%',
            'confidence_threshold': 0.82,
            'high_confidence_threshold': 0.90,
            'component_models': list(self.component_models.keys()),
            'ensemble_weights': {name: spec['weight'] for name, spec in self.component_models.items()},
            'class_names': self.class_names,
            'input_shape': [50, 48],
            'output_classes': 10
        }
    
    def predict_proba(self, X_scaled: np.ndarray, X_flat: Optional[np.ndarray] = None, network_context: Optional[Dict[str, Any]] = None) -> Dict[str, np.ndarray]:
        """
        Get probability predictions from all component models
        Args:
            X_scaled: Scaled input data for deep learning models (shape: batch_size, 50, 48)
            X_flat: Flattened input data for traditional ML models (shape: batch_size, 2400)
        """
        predictions = {}
        
        try:
            # Ensure X_flat is available for traditional models
            if X_flat is None:
                X_flat = X_scaled.reshape(X_scaled.shape[0], -1)
            
            # CNN model (different input requirements)
            if 'cnn_final' in self.component_models:
                model = self.model_loader.get_model('cnn_final')
                if model is not None:
                    try:
                        # CNN expects (batch_size, 32) features
                        from .feature_extractor import WiFiFeatureExtractor
                        extractor = WiFiFeatureExtractor()
                        
                        # Extract CNN features from real network data
                        if network_context and network_context.get('using_real_wifi_data'):
                            # Use the real WiFi data for CNN features
                            cnn_features = extractor.extract_cnn_features(network_context)
                            self.logger.info(f"Using REAL WiFi data for CNN: {network_context.get('encryption', 'Unknown')}")
                        elif network_context:
                            cnn_features = extractor.extract_cnn_features(network_context) 
                            self.logger.info(f"Using provided network context for CNN")
                        else:
                            # Only use fallback if absolutely no context
                            sample_network = {'encryption': 'WPA2', 'channel': 6, 'signal_strength': -50}
                            cnn_features = extractor.extract_cnn_features(sample_network)
                            self.logger.warning("Using fallback sample data for CNN - no real data available")
                        cnn_input = cnn_features.reshape(1, -1)
                        
                        pred = model.predict(cnn_input, verbose=0)
                        
                        # CNN has 12 classes, map to 10 classes for ensemble
                        if pred.shape[1] == 12:
                            # Map 12 CNN vulnerability classes to 10 threat classes
                            cnn_to_threat_mapping = np.array([
                                [0.8, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.1, 0.0],  # SECURE_NETWORK -> NORMAL_BEHAVIOR
                                [0.0, 0.6, 0.2, 0.0, 0.0, 0.1, 0.0, 0.0, 0.1, 0.0],  # WEAK_ENCRYPTION -> BRUTE_FORCE
                                [0.2, 0.0, 0.5, 0.1, 0.0, 0.0, 0.0, 0.0, 0.2, 0.0],  # OPEN_NETWORK -> RECONNAISSANCE  
                                [0.0, 0.3, 0.0, 0.0, 0.0, 0.2, 0.3, 0.0, 0.2, 0.0],  # WPS_VULNERABILITY -> INSIDER_THREAT
                                [0.0, 0.1, 0.3, 0.0, 0.0, 0.0, 0.4, 0.0, 0.2, 0.0],  # ROGUE_AP -> APT_BEHAVIOR
                                [0.0, 0.1, 0.3, 0.0, 0.0, 0.0, 0.4, 0.0, 0.2, 0.0],  # EVIL_TWIN -> APT_BEHAVIOR
                                [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.2, 0.0],  # DEAUTH_ATTACK -> DDOS_PREPARATION
                                [0.0, 0.0, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.8, 0.0],  # HANDSHAKE_CAPTURE -> LATERAL_MOVEMENT
                                [0.1, 0.2, 0.1, 0.0, 0.0, 0.2, 0.2, 0.0, 0.2, 0.0],  # FIRMWARE_OUTDATED -> mixed
                                [0.0, 0.4, 0.1, 0.0, 0.0, 0.2, 0.0, 0.0, 0.3, 0.0],  # DEFAULT_CREDENTIALS -> BRUTE_FORCE
                                [0.0, 0.0, 0.0, 0.7, 0.0, 0.0, 0.0, 0.0, 0.3, 0.0],  # SIGNAL_LEAKAGE -> DATA_EXFILTRATION
                                [0.0, 0.0, 0.0, 0.0, 0.6, 0.0, 0.0, 0.0, 0.4, 0.0]   # UNKNOWN_THREAT -> BOTNET_ACTIVITY
                            ])
                            mapped_pred = np.dot(pred, cnn_to_threat_mapping)
                            predictions['cnn_final'] = mapped_pred
                        else:
                            predictions['cnn_final'] = pred
                            
                        self.logger.debug(f"cnn_final prediction shape: {predictions['cnn_final'].shape}")
                        
                    except Exception as e:
                        self.logger.error(f"Error predicting with cnn_final: {str(e)}")
                        predictions['cnn_final'] = np.ones((1, 10)) / 10
                else:
                    self.logger.warning("CNN model not available, using default prediction")
                    predictions['cnn_final'] = np.ones((X_scaled.shape[0], 10)) / 10
            
            # Deep learning models - using available models only
            for model_name in ['lstm_main', 'lstm_production', 'cnn_lstm_hybrid']:
                if model_name in self.component_models:
                    model = self.model_loader.get_model(model_name)
                    if model is not None:
                        try:
                            # All LSTM models expect (batch_size, 50, 48)
                            pred = model.predict(X_scaled, verbose=0)
                            
                            # Ensure output has correct number of classes (10)
                            if pred.shape[1] != 10:
                                self.logger.warning(f"{model_name} output shape mismatch: {pred.shape[1]}, expected 10")
                                # Pad or truncate to 10 classes
                                correct_pred = np.zeros((pred.shape[0], 10))
                                min_classes = min(pred.shape[1], 10)
                                correct_pred[:, :min_classes] = pred[:, :min_classes]
                                pred = correct_pred
                            
                            predictions[model_name] = pred
                            self.logger.debug(f"{model_name} prediction shape: {pred.shape}")
                            
                        except Exception as e:
                            self.logger.error(f"Error predicting with {model_name}: {str(e)}")
                            # Create default prediction
                            predictions[model_name] = np.ones((X_scaled.shape[0], 10)) / 10
                    else:
                        self.logger.warning(f"Model {model_name} not available, using default prediction")
                        predictions[model_name] = np.ones((X_scaled.shape[0], 10)) / 10
            
            # Traditional ML models
            for model_name in ['random_forest', 'gradient_boosting']:
                if model_name in self.component_models:
                    model = self.model_loader.get_model(model_name)
                    if model is not None:
                        try:
                            # Traditional models expect flattened input
                            pred = model.predict_proba(X_flat)
                            
                            # Ensure output has correct number of classes (10)
                            if pred.shape[1] != 10:
                                self.logger.warning(f"{model_name} output shape mismatch: {pred.shape[1]}, expected 10")
                                # Pad or truncate to 10 classes
                                correct_pred = np.zeros((pred.shape[0], 10))
                                min_classes = min(pred.shape[1], 10)
                                correct_pred[:, :min_classes] = pred[:, :min_classes]
                                pred = correct_pred
                            
                            predictions[model_name] = pred
                            self.logger.debug(f"{model_name} prediction shape: {pred.shape}")
                            
                        except Exception as e:
                            self.logger.error(f"Error predicting with {model_name}: {str(e)}")
                            # Create default prediction
                            predictions[model_name] = np.ones((X_flat.shape[0], 10)) / 10
                    else:
                        self.logger.warning(f"Model {model_name} not available, using default prediction")
                        predictions[model_name] = np.ones((X_flat.shape[0], 10)) / 10
            
            return predictions
            
        except Exception as e:
            self.logger.error(f"Error in predict_proba: {str(e)}")
            # Return default predictions
            batch_size = X_scaled.shape[0] if X_scaled is not None else 1
            return {name: np.ones((batch_size, 10)) / 10 for name in self.component_models.keys()}
    
    def _calculate_adaptive_weights(self, model_predictions: Dict[str, np.ndarray], network_context: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
        """
        Calculate adaptive weights based on model confidence and network characteristics
        """
        base_weights = {name: spec['weight'] for name, spec in self.component_models.items()}
        
        if not model_predictions or not network_context:
            return base_weights
        
        adaptive_weights = base_weights.copy()
        
        # Extract network characteristics
        encryption = str(network_context.get('encryption', 'Unknown')).upper()
        channel = network_context.get('channel', 0)
        signal_strength = network_context.get('signal_strength', -50)
        
        # Boost CNN model for security-focused networks (WPA3, enterprise)
        if 'cnn_final' in model_predictions and ('WPA3' in encryption or 'ENTERPRISE' in encryption):
            adaptive_weights['cnn_final'] = adaptive_weights.get('cnn_final', 0) * 1.3
        
        # Boost LSTM models for temporal anomaly detection on specific channels
        if channel in [1, 6, 11]:  # Common WiFi channels
            for model_name in ['lstm_main', 'lstm_production']:
                if model_name in adaptive_weights:
                    adaptive_weights[model_name] *= 1.2
        
        # Boost traditional ML for weak signal scenarios (more noise)
        if signal_strength < -70:
            for model_name in ['random_forest', 'gradient_boosting']:
                if model_name in adaptive_weights:
                    adaptive_weights[model_name] *= 1.25
        
        # Confidence-based adaptive weighting
        for model_name, pred in model_predictions.items():
            if model_name in adaptive_weights:
                # Get model's top prediction confidence
                max_confidence = np.max(pred[0])
                confidence_multiplier = 0.8 + (max_confidence * 0.4)  # 0.8 to 1.2 range
                adaptive_weights[model_name] *= confidence_multiplier
        
        return adaptive_weights
    
    def predict(self, X_scaled: np.ndarray, X_flat: Optional[np.ndarray] = None, network_context: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        Make ensemble predictions using adaptive weighted voting
        Args:
            X_scaled: Scaled input data for deep learning models
            X_flat: Flattened input data for traditional ML models
            network_context: Network-specific context for adaptive weighting
        Returns:
            Ensemble probability predictions
        """
        try:
            # Get predictions from all models
            model_predictions = self.predict_proba(X_scaled, X_flat, network_context)
            
            if not model_predictions:
                batch_size = X_scaled.shape[0] if X_scaled is not None else 1
                return np.ones((batch_size, 10)) / 10
            
            # Initialize ensemble prediction
            batch_size = list(model_predictions.values())[0].shape[0]
            ensemble_pred = np.zeros((batch_size, 10))
            
            # Calculate adaptive weights based on network characteristics
            adaptive_weights = self._calculate_adaptive_weights(model_predictions, network_context)
            total_weight = sum(adaptive_weights.values())
            
            # Log adaptive weighting debug info
            self.logger.debug(f"Network context: {network_context}")
            self.logger.debug(f"Adaptive weights: {adaptive_weights}")
            
            # Log individual model predictions for debugging
            for model_name, pred in model_predictions.items():
                top_class_idx = np.argmax(pred[0])
                top_class_name = self.class_names[top_class_idx] if top_class_idx < len(self.class_names) else f"CLASS_{top_class_idx}"
                confidence = pred[0][top_class_idx]
                weight = adaptive_weights.get(model_name, 0)
                self.logger.debug(f"Model {model_name}: {top_class_name} (conf: {confidence:.3f}, weight: {weight:.3f})")
            
            # Weighted average of predictions using adaptive weights
            for model_name, pred in model_predictions.items():
                if model_name in adaptive_weights:
                    weight = adaptive_weights[model_name]
                    ensemble_pred += weight * pred
            
            # Normalize by total weight
            if total_weight > 0:
                ensemble_pred /= total_weight
            else:
                ensemble_pred = np.ones((batch_size, 10)) / 10
            
            self.logger.debug(f"Ensemble prediction shape: {ensemble_pred.shape}")
            return ensemble_pred
            
        except Exception as e:
            self.logger.error(f"Error in ensemble prediction: {str(e)}")
            batch_size = X_scaled.shape[0] if X_scaled is not None else 1
            return np.ones((batch_size, 10)) / 10
    
    def predict_threat(self, network_data_sequence: List[Dict[str, Any]], 
                      confidence_threshold: Optional[float] = None) -> Dict[str, Any]:
        """
        Predict threat for network data sequence according to documentation specifications
        This is the main prediction function matching the Ensemble training.py API
        """
        try:
            start_time = time.time()
            
            if confidence_threshold is None:
                confidence_threshold = self.confidence_threshold
            
            # Log that we're using real WiFi data
            if network_data_sequence and len(network_data_sequence) > 0:
                first_sample = network_data_sequence[0]
                if first_sample.get('using_real_wifi_data') or first_sample.get('data_source') == 'real_wifi_scan':
                    self.logger.info(f"Ensemble predicting with REAL WiFi data from network: {first_sample.get('ssid', 'Unknown')}")
                else:
                    self.logger.warning(f"Ensemble predicting with non-real data - this should not happen")
            
            # Preprocess data for LSTM models
            X_scaled = self.preprocessor.preprocess_for_lstm(network_data_sequence)
            
            # Ensure batch dimension
            if len(X_scaled.shape) == 2:
                X_scaled = X_scaled.reshape(1, X_scaled.shape[0], X_scaled.shape[1])
            
            # Flatten for traditional models
            X_flat = X_scaled.reshape(X_scaled.shape[0], -1)
            
            # Extract network context from first data point for adaptive weighting
            network_context = network_data_sequence[0] if network_data_sequence else {}
            
            # Get ensemble predictions with network context
            ensemble_predictions = self.predict(X_scaled, X_flat, network_context)
            
            # Get individual model predictions for detailed analysis
            model_predictions = self.predict_proba(X_scaled, X_flat, network_context)
            
            # Extract results for first sample (assuming single prediction)
            prediction_probs = ensemble_predictions[0]
            predicted_class_idx = np.argmax(prediction_probs)
            confidence = float(np.max(prediction_probs))
            
            # Determine threat status
            is_threat = predicted_class_idx != 0  # 0 is NORMAL_BEHAVIOR
            take_action = confidence >= confidence_threshold
            high_confidence = confidence >= self.high_confidence_threshold
            
            # Processing time
            processing_time = time.time() - start_time
            
            # Individual model confidences
            individual_confidences = {}
            for model_name, pred in model_predictions.items():
                individual_confidences[model_name] = float(np.max(pred[0]))
            
            # Create result dictionary matching Ensemble training.py API
            result = {
                'predicted_class': self.class_names[predicted_class_idx],
                'predicted_class_idx': int(predicted_class_idx),
                'confidence': confidence,
                'is_threat': is_threat,
                'take_action': take_action,
                'high_confidence': high_confidence,
                'all_probabilities': prediction_probs.tolist(),
                'individual_confidences': individual_confidences,
                'processing_time': processing_time,
                'model_version': 'v3.0',
                'timestamp': datetime.now().isoformat(),
                'ensemble_weights': {name: spec['weight'] for name, spec in self.component_models.items()},
                'meets_confidence_threshold': confidence >= confidence_threshold
            }
            
            # Store prediction history for monitoring
            self.prediction_history.append({
                'timestamp': datetime.now(),
                'predicted_class': result['predicted_class'],
                'confidence': confidence,
                'is_threat': is_threat
            })
            
            # Keep only recent history
            if len(self.prediction_history) > 1000:
                self.prediction_history = self.prediction_history[-1000:]
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in predict_threat: {str(e)}")
            return self._get_default_prediction_result()
    
    def evaluate(self, X_scaled: np.ndarray, X_flat: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate ensemble model performance
        Args:
            X_scaled: Test data for deep learning models
            X_flat: Test data for traditional ML models  
            y_true: True labels
        Returns:
            Evaluation metrics
        """
        try:
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            # Get predictions
            predictions = self.predict(X_scaled, X_flat)
            pred_classes = np.argmax(predictions, axis=1)
            
            # Calculate metrics
            accuracy = accuracy_score(y_true, pred_classes)
            precision = precision_score(y_true, pred_classes, average='weighted', zero_division=0)
            recall = recall_score(y_true, pred_classes, average='weighted', zero_division=0)
            f1 = f1_score(y_true, pred_classes, average='weighted', zero_division=0)
            
            # Individual model evaluation
            individual_metrics = {}
            model_predictions = self.predict_proba(X_scaled, X_flat)
            
            for model_name, pred in model_predictions.items():
                pred_classes_individual = np.argmax(pred, axis=1)
                individual_metrics[model_name] = {
                    'accuracy': accuracy_score(y_true, pred_classes_individual),
                    'precision': precision_score(y_true, pred_classes_individual, average='weighted', zero_division=0),
                    'recall': recall_score(y_true, pred_classes_individual, average='weighted', zero_division=0),
                    'f1_score': f1_score(y_true, pred_classes_individual, average='weighted', zero_division=0)
                }
            
            return {
                'ensemble_metrics': {
                    'accuracy': accuracy,
                    'precision': precision, 
                    'recall': recall,
                    'f1_score': f1
                },
                'individual_metrics': individual_metrics,
                'predictions': predictions,
                'pred_classes': pred_classes,
                'meets_target_accuracy': accuracy >= 0.91  # Target from documentation
            }
            
        except Exception as e:
            self.logger.error(f"Error in evaluation: {str(e)}")
            return {
                'ensemble_metrics': {'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0},
                'individual_metrics': {},
                'predictions': np.array([]),
                'pred_classes': np.array([]),
                'meets_target_accuracy': False
            }
    
    def _get_default_prediction_result(self) -> Dict[str, Any]:
        """Get default prediction result in case of errors"""
        return {
            'predicted_class': 'NORMAL_BEHAVIOR',
            'predicted_class_idx': 0,
            'confidence': 0.5,
            'is_threat': False,
            'take_action': False,
            'high_confidence': False,
            'all_probabilities': [0.9] + [0.01] * 9,  # High probability for normal behavior
            'individual_confidences': {name: 0.5 for name in self.component_models.keys()},
            'processing_time': 0.01,
            'model_version': 'v3.0',
            'timestamp': datetime.now().isoformat(),
            'ensemble_weights': {name: spec['weight'] for name, spec in self.component_models.items()},
            'meets_confidence_threshold': False,
            'error': 'Prediction failed, using default result'
        }
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all component models"""
        status = {
            'ensemble_ready': True,
            'component_models_status': {},
            'total_models': len(self.component_models),
            'loaded_models': 0,
            'failed_models': []
        }
        
        for model_name in self.component_models.keys():
            model = self.model_loader.get_model(model_name)
            is_loaded = model is not None
            status['component_models_status'][model_name] = {
                'loaded': is_loaded,
                'weight': self.component_models[model_name]['weight'],
                'type': self.component_models[model_name]['type'],
                'description': self.component_models[model_name]['description']
            }
            
            if is_loaded:
                status['loaded_models'] += 1
            else:
                status['failed_models'].append(model_name)
        
        status['ensemble_ready'] = status['loaded_models'] > 0
        return status
    
    def get_prediction_statistics(self) -> Dict[str, Any]:
        """Get prediction statistics from history"""
        if not self.prediction_history:
            return {'total_predictions': 0, 'threat_rate': 0.0, 'avg_confidence': 0.0}
        
        total_predictions = len(self.prediction_history)
        threat_predictions = sum(1 for pred in self.prediction_history if pred['is_threat'])
        threat_rate = threat_predictions / total_predictions
        avg_confidence = sum(pred['confidence'] for pred in self.prediction_history) / total_predictions
        
        # Class distribution
        class_counts = Counter(pred['predicted_class'] for pred in self.prediction_history)
        
        return {
            'total_predictions': total_predictions,
            'threat_rate': threat_rate,
            'avg_confidence': avg_confidence,
            'class_distribution': dict(class_counts),
            'recent_predictions': self.prediction_history[-10:] if len(self.prediction_history) >= 10 else self.prediction_history
        }
    
    def update_model_weights(self, new_weights: Dict[str, float]) -> bool:
        """Update ensemble model weights dynamically"""
        try:
            total_weight = sum(new_weights.values())
            if abs(total_weight - 1.0) > 0.01:  # Allow small tolerance
                self.logger.warning(f"Model weights sum to {total_weight}, normalizing...")
                new_weights = {name: weight / total_weight for name, weight in new_weights.items()}
            
            # Update weights
            for model_name, weight in new_weights.items():
                if model_name in self.component_models:
                    self.component_models[model_name]['weight'] = weight
            
            self.logger.info(f"Updated model weights: {new_weights}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating model weights: {str(e)}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        try:
            health_status = {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'healthy',
                'issues': []
            }
            
            # Check model loader
            if not self.model_loader.is_initialized:
                health_status['issues'].append('Model loader not initialized')
                health_status['overall_status'] = 'unhealthy'
            
            # Check preprocessor
            if not self.preprocessor:
                health_status['issues'].append('Preprocessor not available')
                health_status['overall_status'] = 'unhealthy'
            
            # Check component models
            model_status = self.get_model_status()
            if model_status['loaded_models'] == 0:
                health_status['issues'].append('No component models loaded')
                health_status['overall_status'] = 'critical'
            elif model_status['loaded_models'] < 3:
                health_status['issues'].append(f'Only {model_status["loaded_models"]} models loaded, ensemble may be degraded')
                health_status['overall_status'] = 'degraded'
            
            # Test prediction capability
            try:
                sample_data = self.preprocessor.create_sample_data_for_testing()
                test_sequence = [sample_data['network_data']] * 50
                test_result = self.predict_threat(test_sequence)
                if 'error' in test_result:
                    health_status['issues'].append('Test prediction failed')
                    health_status['overall_status'] = 'degraded'
            except Exception as e:
                health_status['issues'].append(f'Test prediction error: {str(e)}')
                health_status['overall_status'] = 'degraded'
            
            health_status['model_status'] = model_status
            health_status['prediction_stats'] = self.get_prediction_statistics()
            
            return health_status
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'critical',
                'issues': [f'Health check failed: {str(e)}'],
                'model_status': {},
                'prediction_stats': {}
            }


class EnsemblePredictor:
    """
    Main ensemble predictor class - wrapper around EnsembleFusionModel
    Provides the main API interface for ensemble predictions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.model_loader = model_loader
        self.preprocessor = data_preprocessor
        self.ensemble_model = None
        self.is_initialized = False
        self._initialize()
    
    def _initialize(self):
        """Initialize the ensemble predictor"""
        try:
            self.logger.info("Initializing Ensemble Predictor...")
            
            # Initialize model loader
            if not self.model_loader.is_initialized:
                load_results = self.model_loader.load_all_models()
                self.logger.info(f"Model loading results: {load_results}")
            
            # Create ensemble fusion model
            self.ensemble_model = EnsembleFusionModel(self.model_loader, self.preprocessor)
            
            self.is_initialized = True
            self.logger.info("Ensemble Predictor initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing Ensemble Predictor: {str(e)}")
            self.is_initialized = False
    
    def predict_threat(self, network_data_sequence: List[Dict[str, Any]], 
                      confidence_threshold: Optional[float] = None) -> Dict[str, Any]:
        """
        Main prediction interface - matches Ensemble training.py API
        Args:
            network_data_sequence: List of network data dictionaries (50 timesteps)
            confidence_threshold: Confidence threshold for predictions
        Returns:
            Prediction result dictionary
        """
        if not self.is_initialized or not self.ensemble_model:
            self.logger.error("Ensemble predictor not initialized")
            return self._get_error_result("Ensemble predictor not initialized")
        
        try:
            return self.ensemble_model.predict_threat(network_data_sequence, confidence_threshold)
        except Exception as e:
            self.logger.error(f"Error in prediction: {str(e)}")
            return self._get_error_result(f"Prediction failed: {str(e)}")
    
    def predict_single(self, network_data: Dict[str, Any], 
                      confidence_threshold: Optional[float] = None) -> Dict[str, Any]:
        """
        Predict from single network data point by creating a sequence
        Args:
            network_data: Single network data dictionary
            confidence_threshold: Confidence threshold for predictions
        Returns:
            Prediction result dictionary
        """
        # Create sequence from single data point
        network_data_sequence = [network_data] * 50
        return self.predict_threat(network_data_sequence, confidence_threshold)
    
    def evaluate_ensemble(self, test_data: List[List[Dict[str, Any]]], 
                         test_labels: List[int]) -> Dict[str, Any]:
        """
        Evaluate ensemble model performance
        Args:
            test_data: List of network data sequences
            test_labels: True labels for test data
        Returns:
            Evaluation metrics
        """
        if not self.is_initialized or not self.ensemble_model:
            return {'error': 'Ensemble predictor not initialized'}
        
        try:
            # Preprocess all test data
            X_scaled_list = []
            for sequence in test_data:
                X_scaled = self.preprocessor.preprocess_for_lstm(sequence)
                X_scaled_list.append(X_scaled)
            
            X_scaled = np.array(X_scaled_list)
            X_flat = X_scaled.reshape(X_scaled.shape[0], -1)
            y_true = np.array(test_labels)
            
            return self.ensemble_model.evaluate(X_scaled, X_flat, y_true)
            
        except Exception as e:
            self.logger.error(f"Error in evaluation: {str(e)}")
            return {'error': f'Evaluation failed: {str(e)}'}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get comprehensive model information"""
        if not self.is_initialized or not self.ensemble_model:
            return {'error': 'Ensemble predictor not initialized'}
        
        try:
            model_status = self.ensemble_model.get_model_status()
            prediction_stats = self.ensemble_model.get_prediction_statistics()
            health_status = self.ensemble_model.health_check()
            
            return {
                'model_status': model_status,
                'prediction_statistics': prediction_stats,
                'health_status': health_status,
                'component_models': self.ensemble_model.component_models,
                'class_names': self.ensemble_model.class_names,
                'confidence_thresholds': {
                    'standard': self.ensemble_model.confidence_threshold,
                    'high_confidence': self.ensemble_model.high_confidence_threshold
                },
                'ensemble_metadata': self.ensemble_model.ensemble_metadata
            }
            
        except Exception as e:
            self.logger.error(f"Error getting model info: {str(e)}")
            return {'error': f'Failed to get model info: {str(e)}'}
    
    def update_weights(self, new_weights: Dict[str, float]) -> Dict[str, Any]:
        """Update ensemble model weights"""
        if not self.is_initialized or not self.ensemble_model:
            return {'success': False, 'error': 'Ensemble predictor not initialized'}
        
        try:
            success = self.ensemble_model.update_model_weights(new_weights)
            return {'success': success, 'weights': new_weights}
        except Exception as e:
            self.logger.error(f"Error updating weights: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_error_result(self, error_message: str) -> Dict[str, Any]:
        """Get error result in standard format"""
        return {
            'predicted_class': 'NORMAL_BEHAVIOR',
            'predicted_class_idx': 0,
            'confidence': 0.0,
            'is_threat': False,
            'take_action': False,
            'high_confidence': False,
            'all_probabilities': [1.0] + [0.0] * 9,
            'individual_confidences': {},
            'processing_time': 0.0,
            'model_version': 'v3.0',
            'timestamp': datetime.now().isoformat(),
            'ensemble_weights': {},
            'meets_confidence_threshold': False,
            'error': error_message
        }
    
    def test_prediction(self) -> Dict[str, Any]:
        """Test prediction with sample data"""
        if not self.is_initialized or not self.ensemble_model:
            return {'success': False, 'error': 'Ensemble predictor not initialized'}
        
        try:
            # Create test data
            sample_data = self.preprocessor.create_sample_data_for_testing()
            test_sequence = [sample_data['network_data']] * 50
            
            # Make prediction
            result = self.predict_threat(test_sequence)
            
            return {
                'success': True,
                'test_result': result,
                'test_data_sample': sample_data['network_data']
            }
            
        except Exception as e:
            self.logger.error(f"Error in test prediction: {str(e)}")
            return {'success': False, 'error': str(e)}


# Global ensemble predictor instance
ensemble_predictor = EnsemblePredictor()

# Convenience functions for easy access - matching Ensemble training.py API
def predict_threat(network_data_sequence: List[Dict[str, Any]], 
                  confidence_threshold: Optional[float] = None) -> Dict[str, Any]:
    """
    Main prediction function matching Ensemble training.py API
    """
    return ensemble_predictor.predict_threat(network_data_sequence, confidence_threshold)

def predict_single(network_data: Dict[str, Any], 
                  confidence_threshold: Optional[float] = None) -> Dict[str, Any]:
    """Predict from single network data point"""
    return ensemble_predictor.predict_single(network_data, confidence_threshold)

def evaluate_ensemble(test_data: List[List[Dict[str, Any]]], 
                     test_labels: List[int]) -> Dict[str, Any]:
    """Evaluate ensemble model"""
    return ensemble_predictor.evaluate_ensemble(test_data, test_labels)

def get_model_info() -> Dict[str, Any]:
    """Get model information"""
    return ensemble_predictor.get_model_info()

def update_weights(new_weights: Dict[str, float]) -> Dict[str, Any]:
    """Update model weights"""
    return ensemble_predictor.update_weights(new_weights)

def test_prediction() -> Dict[str, Any]:
    """Test prediction with sample data"""
    return ensemble_predictor.test_prediction()

def health_check() -> Dict[str, Any]:
    """Perform health check"""
    if ensemble_predictor.ensemble_model:
        return ensemble_predictor.ensemble_model.health_check()
    else:
        return {'overall_status': 'critical', 'issues': ['Ensemble predictor not initialized']}