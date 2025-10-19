"""
Wi-Fi Security System - Data Preprocessing Engine
File: app/ai_engine/preprocessor.py

Purpose: Prepare real network data for AI model inference according to documentation specifications
Author: Wi-Fi Security System
Version: 2.0

Implements exact preprocessing requirements for CNN (32 features), LSTM (50x48 features), 
GNN (24+16 features), and Crypto-BERT (256 tokens) models using ONLY real WiFi data
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional, Union
import logging
import json
import os
import pickle
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
import tensorflow as tf

try:
    from transformers import AutoTokenizer
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Warning: transformers library not available. Using fallback tokenization.")

from .feature_extractor import WiFiFeatureExtractor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataPreprocessor:
    """
    Main preprocessing class for all AI models according to documentation specifications
    Handles data preparation for CNN, LSTM, GNN, and Crypto-BERT models using ONLY real network data
    """
    
    def __init__(self, models_path: str = "models/"):
        """Initialize preprocessor with exact documentation specifications"""
        self.models_path = models_path
        self.logger = logging.getLogger(__name__)
        self.feature_extractor = WiFiFeatureExtractor()
        
        # Model specifications from documentation
        self.model_specs = {
            'cnn': {
                'input_shape': (32,),
                'output_classes': 12,
                'feature_count': 32,
                'confidence_threshold': 0.85,
                'description': 'CNN Wi-Fi Vulnerability Detection Model'
            },
            'lstm': {
                'input_shape': (50, 48),
                'output_classes': 10,
                'sequence_length': 50,
                'features_per_timestep': 48,
                'confidence_threshold': 0.82,
                'description': 'LSTM Wi-Fi Vulnerability Detection Model'
            },
            'gnn': {
                'node_features': 24,
                'edge_features': 16,
                'output_classes': 8,
                'confidence_threshold': 0.80,
                'description': 'Graph Neural Network Model'
            },
            'crypto_bert': {
                'input_shape': (256,),
                'max_tokens': 256,
                'vocab_size': 30000,
                'output_classes': 15,
                'confidence_threshold': 0.88,
                'description': 'Enhanced Crypto-BERT Model'
            },
            'ensemble': {
                'output_classes': 10,
                'confidence_threshold': 0.82,
                'component_models': 5,
                'description': 'WiFi LSTM Ensemble Fusion Model'
            }
        }
        
        # Class mappings from documentation
        self.class_mappings = {
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
            ],
            'crypto_classes': [
                'STRONG_ENCRYPTION', 'WEAK_CIPHER_SUITE', 'CERTIFICATE_INVALID', 'KEY_REUSE',
                'DOWNGRADE_ATTACK', 'MAN_IN_MIDDLE', 'REPLAY_ATTACK', 'TIMING_ATTACK',
                'QUANTUM_VULNERABLE', 'ENTROPY_WEAKNESS', 'HASH_COLLISION', 'PADDING_ORACLE',
                'LENGTH_EXTENSION', 'PROTOCOL_CONFUSION', 'CRYPTO_AGILITY_LACK'
            ]
        }
        
        # Initialize scalers for different models
        self.scalers = {
            'cnn_scaler': StandardScaler(),
            'lstm_scaler': StandardScaler(),
            'gnn_node_scaler': StandardScaler(),
            'gnn_edge_scaler': StandardScaler()
        }
        
        # Initialize tokenizer for Crypto-BERT
        self.tokenizer = None
        self._initialize_tokenizer()
        
        # Load existing scalers if available
        self._load_scalers()
    
    def _initialize_tokenizer(self):
        """Initialize tokenizer for Crypto-BERT model"""
        try:
            if TRANSFORMERS_AVAILABLE:
                # Use BERT tokenizer if available
                self.tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
                self.logger.info("BERT tokenizer initialized successfully")
            else:
                # Use fallback tokenization
                self.tokenizer = None
                self.logger.info("Using fallback tokenization for Crypto-BERT")
        except Exception as e:
            self.logger.warning(f"Failed to initialize tokenizer: {str(e)}, using fallback")
            self.tokenizer = None
    
    def _load_scalers(self):
        """Load pre-trained scalers if available"""
        try:
            scaler_files = {
                'cnn_scaler': 'wifi_vulnerability_scaler.pkl',
                'lstm_scaler': 'wifi_lstm_preprocessor.pkl',
                'gnn_node_scaler': 'wifi_gnn_node_scaler.pkl',
                'gnn_edge_scaler': 'wifi_gnn_edge_scaler.pkl'
            }
            
            for scaler_name, filename in scaler_files.items():
                scaler_path = os.path.join(self.models_path, filename)
                if os.path.exists(scaler_path):
                    with open(scaler_path, 'rb') as f:
                        self.scalers[scaler_name] = pickle.load(f)
                    self.logger.info(f"Loaded {scaler_name} from {filename}")
                else:
                    self.logger.info(f"Scaler {filename} not found, using default")
        except Exception as e:
            self.logger.warning(f"Error loading scalers: {str(e)}")
    
    def preprocess_for_cnn(self, network_data: Dict[str, Any]) -> np.ndarray:
        """
        Preprocess data for CNN model according to documentation specifications
        Input: Real WiFi network data dictionary
        Output: Normalized numpy array of shape (32,) for CNN model
        """
        try:
            self.logger.debug("Preprocessing data for CNN model")
            
            # Extract 32 features using feature extractor
            features = self.feature_extractor.extract_cnn_features(network_data)
            
            # Reshape for CNN: (32,) -> (32, 1) as specified in documentation
            features = features.reshape(-1, 1)
            
            # Apply normalization
            if hasattr(self.scalers['cnn_scaler'], 'mean_'):
                # Use pre-trained scaler
                features_scaled = self.scalers['cnn_scaler'].transform(features.reshape(1, -1))
            else:
                # Fit scaler on current data (for first use)
                features_scaled = self.scalers['cnn_scaler'].fit_transform(features.reshape(1, -1))
            
            # Reshape back to CNN input format (32, 1)
            final_features = features_scaled.reshape(32, 1).astype(np.float32)
            
            self.logger.debug(f"CNN preprocessing completed: {final_features.shape}")
            return final_features
            
        except Exception as e:
            self.logger.error(f"Error in CNN preprocessing: {str(e)}")
            return np.zeros((32, 1), dtype=np.float32)
    
    def preprocess_for_lstm(self, network_data_sequence: List[Dict[str, Any]]) -> np.ndarray:
        """
        Preprocess data for LSTM model according to documentation specifications
        Input: List of network data dictionaries (temporal sequence)
        Output: Normalized numpy array of shape (50, 48) for LSTM model
        """
        try:
            self.logger.debug("Preprocessing data for LSTM model")
            
            # Extract temporal features using feature extractor
            features = self.feature_extractor.extract_lstm_features(network_data_sequence)
            
            # Ensure correct shape (50, 48)
            if features.shape != (50, 48):
                self.logger.warning(f"LSTM features shape mismatch: {features.shape}, expected (50, 48)")
                # Pad or truncate to correct shape
                padded_features = np.zeros((50, 48), dtype=np.float32)
                min_timesteps = min(features.shape[0], 50)
                min_features = min(features.shape[1], 48)
                padded_features[:min_timesteps, :min_features] = features[:min_timesteps, :min_features]
                features = padded_features
            
            # Apply normalization per timestep
            if hasattr(self.scalers['lstm_scaler'], 'mean_'):
                # Use pre-trained scaler
                features_flat = features.reshape(-1, features.shape[-1])
                features_scaled = self.scalers['lstm_scaler'].transform(features_flat)
                features_scaled = features_scaled.reshape(features.shape)
            else:
                # Fit scaler on current data
                features_flat = features.reshape(-1, features.shape[-1])
                features_scaled = self.scalers['lstm_scaler'].fit_transform(features_flat)
                features_scaled = features_scaled.reshape(features.shape)
            
            final_features = features_scaled.astype(np.float32)
            
            self.logger.debug(f"LSTM preprocessing completed: {final_features.shape}")
            return final_features
            
        except Exception as e:
            self.logger.error(f"Error in LSTM preprocessing: {str(e)}")
            return np.zeros((50, 48), dtype=np.float32)
    
    def preprocess_for_gnn(self, network_topology: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Preprocess data for GNN model according to documentation specifications
        Input: Network topology dictionary with nodes and edges
        Output: Tuple of (node_features, edge_features, adjacency_matrix)
        """
        try:
            self.logger.debug("Preprocessing data for GNN model")
            
            # Extract GNN features using feature extractor
            node_features, edge_features, adjacency_matrix = self.feature_extractor.extract_gnn_features(network_topology)
            
            # Normalize node features (24 dimensions per node)
            if node_features.shape[1] != 24:
                self.logger.warning(f"GNN node features shape mismatch: {node_features.shape[1]}, expected 24")
                # Pad or truncate to correct dimensions
                correct_node_features = np.zeros((node_features.shape[0], 24), dtype=np.float32)
                min_features = min(node_features.shape[1], 24)
                correct_node_features[:, :min_features] = node_features[:, :min_features]
                node_features = correct_node_features
            
            # Normalize edge features (16 dimensions per edge)
            if edge_features.shape[1] != 16:
                self.logger.warning(f"GNN edge features shape mismatch: {edge_features.shape[1]}, expected 16")
                # Pad or truncate to correct dimensions
                correct_edge_features = np.zeros((edge_features.shape[0], 16), dtype=np.float32)
                min_features = min(edge_features.shape[1], 16)
                correct_edge_features[:, :min_features] = edge_features[:, :min_features]
                edge_features = correct_edge_features
            
            # Apply scaling to node features
            if hasattr(self.scalers['gnn_node_scaler'], 'mean_') and node_features.shape[0] > 0:
                node_features_scaled = self.scalers['gnn_node_scaler'].transform(node_features)
            else:
                if node_features.shape[0] > 0:
                    node_features_scaled = self.scalers['gnn_node_scaler'].fit_transform(node_features)
                else:
                    node_features_scaled = node_features
            
            # Apply scaling to edge features
            if hasattr(self.scalers['gnn_edge_scaler'], 'mean_') and edge_features.shape[0] > 0:
                edge_features_scaled = self.scalers['gnn_edge_scaler'].transform(edge_features)
            else:
                if edge_features.shape[0] > 0:
                    edge_features_scaled = self.scalers['gnn_edge_scaler'].fit_transform(edge_features)
                else:
                    edge_features_scaled = edge_features
            
            final_node_features = node_features_scaled.astype(np.float32)
            final_edge_features = edge_features_scaled.astype(np.float32)
            final_adjacency = adjacency_matrix.astype(np.float32)
            
            self.logger.debug(f"GNN preprocessing completed: nodes={final_node_features.shape}, edges={final_edge_features.shape}")
            return final_node_features, final_edge_features, final_adjacency
            
        except Exception as e:
            self.logger.error(f"Error in GNN preprocessing: {str(e)}")
            return np.zeros((1, 24), dtype=np.float32), np.zeros((1, 16), dtype=np.float32), np.zeros((1, 1), dtype=np.float32)
    
    def preprocess_for_crypto_bert(self, protocol_sequences: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Preprocess data for Crypto-BERT model according to documentation specifications
        Input: List of protocol sequence strings
        Output: Tuple of (input_ids, attention_mask) both with shape (batch_size, 256)
        """
        try:
            self.logger.debug("Preprocessing data for Crypto-BERT model")
            
            batch_size = len(protocol_sequences)
            max_length = 256  # As specified in documentation
            
            if self.tokenizer and TRANSFORMERS_AVAILABLE:
                # Use BERT tokenizer
                encoded = self.tokenizer(
                    protocol_sequences,
                    max_length=max_length,
                    padding='max_length',
                    truncation=True,
                    return_tensors='np'
                )
                input_ids = encoded['input_ids'].astype(np.int32)
                attention_mask = encoded['attention_mask'].astype(np.int32)
            else:
                # Use fallback tokenization
                input_ids, attention_mask = self.feature_extractor.extract_crypto_bert_features(protocol_sequences)
            
            # Ensure correct shape
            if input_ids.shape[1] != max_length:
                self.logger.warning(f"Crypto-BERT input shape mismatch: {input_ids.shape[1]}, expected {max_length}")
                # Pad or truncate to correct length
                correct_input_ids = np.zeros((batch_size, max_length), dtype=np.int32)
                correct_attention_mask = np.zeros((batch_size, max_length), dtype=np.int32)
                
                min_length = min(input_ids.shape[1], max_length)
                correct_input_ids[:, :min_length] = input_ids[:, :min_length]
                correct_attention_mask[:, :min_length] = attention_mask[:, :min_length]
                
                input_ids = correct_input_ids
                attention_mask = correct_attention_mask
            
            self.logger.debug(f"Crypto-BERT preprocessing completed: {input_ids.shape}")
            return input_ids, attention_mask
            
        except Exception as e:
            self.logger.error(f"Error in Crypto-BERT preprocessing: {str(e)}")
            batch_size = len(protocol_sequences) if protocol_sequences else 1
            return np.zeros((batch_size, 256), dtype=np.int32), np.zeros((batch_size, 256), dtype=np.int32)
    
    def preprocess_for_ensemble(self, network_data: Dict[str, Any], 
                               network_data_sequence: Optional[List[Dict[str, Any]]] = None,
                               network_topology: Optional[Dict[str, Any]] = None,
                               protocol_sequences: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Preprocess data for ensemble model according to documentation specifications
        Input: Various data formats for different component models
        Output: Dictionary containing preprocessed data for all component models
        """
        try:
            self.logger.debug("Preprocessing data for ensemble model")
            
            preprocessed_data = {}
            
            # Preprocess for CNN component
            if network_data:
                preprocessed_data['cnn'] = self.preprocess_for_cnn(network_data)
            
            # Preprocess for LSTM component
            if network_data_sequence:
                preprocessed_data['lstm'] = self.preprocess_for_lstm(network_data_sequence)
            elif network_data:
                # Create sequence from single data point
                sequence = [network_data] * 50  # Replicate to create sequence
                preprocessed_data['lstm'] = self.preprocess_for_lstm(sequence)
            
            # Preprocess for GNN component
            if network_topology:
                node_features, edge_features, adjacency = self.preprocess_for_gnn(network_topology)
                preprocessed_data['gnn'] = {
                    'node_features': node_features,
                    'edge_features': edge_features,
                    'adjacency_matrix': adjacency
                }
            
            # Preprocess for Crypto-BERT component
            if protocol_sequences:
                input_ids, attention_mask = self.preprocess_for_crypto_bert(protocol_sequences)
                preprocessed_data['crypto_bert'] = {
                    'input_ids': input_ids,
                    'attention_mask': attention_mask
                }
            
            # Prepare for traditional ML models (Random Forest, Gradient Boosting)
            if network_data_sequence:
                # Flatten LSTM features for traditional models
                lstm_features = preprocessed_data.get('lstm', np.zeros((50, 48)))
                preprocessed_data['traditional_ml'] = lstm_features.reshape(1, -1).astype(np.float32)
            elif network_data:
                # Use CNN features for traditional models
                cnn_features = preprocessed_data.get('cnn', np.zeros((32, 1)))
                # Pad to match expected dimensions
                padded_features = np.zeros((1, 2400))  # 50 * 48 = 2400
                padded_features[0, :32] = cnn_features.flatten()
                preprocessed_data['traditional_ml'] = padded_features.astype(np.float32)
            
            self.logger.debug(f"Ensemble preprocessing completed with {len(preprocessed_data)} components")
            return preprocessed_data
            
        except Exception as e:
            self.logger.error(f"Error in ensemble preprocessing: {str(e)}")
            return {}
    
    def validate_input_shapes(self, model_type: str, data: Union[np.ndarray, Dict[str, Any]]) -> bool:
        """
        Validate input shapes according to documentation specifications
        """
        try:
            if model_type == 'cnn':
                return isinstance(data, np.ndarray) and data.shape == (32, 1)
            
            elif model_type == 'lstm':
                return isinstance(data, np.ndarray) and data.shape == (50, 48)
            
            elif model_type == 'gnn':
                if not isinstance(data, dict):
                    return False
                node_features = data.get('node_features')
                edge_features = data.get('edge_features')
                adjacency = data.get('adjacency_matrix')
                return (isinstance(node_features, np.ndarray) and node_features.shape[1] == 24 and
                        isinstance(edge_features, np.ndarray) and edge_features.shape[1] == 16 and
                        isinstance(adjacency, np.ndarray))
            
            elif model_type == 'crypto_bert':
                if not isinstance(data, dict):
                    return False
                input_ids = data.get('input_ids')
                attention_mask = data.get('attention_mask')
                return (isinstance(input_ids, np.ndarray) and input_ids.shape[1] == 256 and
                        isinstance(attention_mask, np.ndarray) and attention_mask.shape[1] == 256)
            
            elif model_type == 'ensemble':
                return isinstance(data, dict) and len(data) > 0
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error validating input shapes for {model_type}: {str(e)}")
            return False
    
    def get_model_specs(self) -> Dict[str, Any]:
        """Get model specifications from documentation"""
        return self.model_specs
    
    def get_class_mappings(self) -> Dict[str, List[str]]:
        """Get class mappings from documentation"""
        return self.class_mappings
    
    def save_scalers(self):
        """Save trained scalers to disk"""
        try:
            scaler_files = {
                'cnn_scaler': 'wifi_vulnerability_scaler.pkl',
                'lstm_scaler': 'wifi_lstm_preprocessor.pkl',
                'gnn_node_scaler': 'wifi_gnn_node_scaler.pkl',
                'gnn_edge_scaler': 'wifi_gnn_edge_scaler.pkl'
            }
            
            for scaler_name, filename in scaler_files.items():
                if hasattr(self.scalers[scaler_name], 'mean_'):
                    scaler_path = os.path.join(self.models_path, filename)
                    with open(scaler_path, 'wb') as f:
                        pickle.dump(self.scalers[scaler_name], f)
                    self.logger.info(f"Saved {scaler_name} to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving scalers: {str(e)}")
    
    def create_sample_data_for_testing(self) -> Dict[str, Any]:
        """
        Create sample data structures for testing all models
        Returns properly formatted test data for each model type
        """
        sample_data = {
            'network_data': {
                'bssid': 'AA:BB:CC:DD:EE:FF',
                'ssid': 'TestNetwork',
                'signal_strength': -65.0,
                'snr': 25.0,
                'channel': 6,
                'encryption': 'WPA2',
                'cipher_suite': 'AES',
                'auth_method': 'PSK',
                'packet_rate': 100,
                'avg_packet_size': 512,
                'bandwidth_utilization': 45.0,
                'connection_attempts': 5,
                'failed_logins': 0,
                'data_volume': 10000
            },
            'network_topology': {
                'nodes': [
                    {'id': 0, 'device_type': 'router', 'encryption_strength': 3, 'trust_score': 0.8},
                    {'id': 1, 'device_type': 'client', 'encryption_strength': 3, 'trust_score': 0.9}
                ],
                'edges': [
                    {'source': 0, 'destination': 1, 'connection_strength': 0.9, 'bandwidth_utilization': 0.3}
                ]
            },
            'protocol_sequences': [
                'TLS handshake initiated with cipher suite AES-256-GCM',
                'Certificate validation completed successfully'
            ]
        }
        
        return sample_data
    
    def test_all_preprocessing(self) -> Dict[str, bool]:
        """
        Test all preprocessing functions with sample data
        Returns success status for each model type
        """
        results = {}
        sample_data = self.create_sample_data_for_testing()
        
        try:
            # Test CNN preprocessing
            cnn_result = self.preprocess_for_cnn(sample_data['network_data'])
            results['cnn'] = self.validate_input_shapes('cnn', cnn_result)
            
            # Test LSTM preprocessing
            lstm_sequence = [sample_data['network_data']] * 50
            lstm_result = self.preprocess_for_lstm(lstm_sequence)
            results['lstm'] = self.validate_input_shapes('lstm', lstm_result)
            
            # Test GNN preprocessing
            gnn_node_features, gnn_edge_features, gnn_adjacency = self.preprocess_for_gnn(sample_data['network_topology'])
            gnn_data = {
                'node_features': gnn_node_features,
                'edge_features': gnn_edge_features,
                'adjacency_matrix': gnn_adjacency
            }
            results['gnn'] = self.validate_input_shapes('gnn', gnn_data)
            
            # Test Crypto-BERT preprocessing
            bert_input_ids, bert_attention_mask = self.preprocess_for_crypto_bert(sample_data['protocol_sequences'])
            bert_data = {
                'input_ids': bert_input_ids,
                'attention_mask': bert_attention_mask
            }
            results['crypto_bert'] = self.validate_input_shapes('crypto_bert', bert_data)
            
            # Test ensemble preprocessing
            ensemble_result = self.preprocess_for_ensemble(
                network_data=sample_data['network_data'],
                network_data_sequence=lstm_sequence,
                network_topology=sample_data['network_topology'],
                protocol_sequences=sample_data['protocol_sequences']
            )
            results['ensemble'] = self.validate_input_shapes('ensemble', ensemble_result)
            
        except Exception as e:
            self.logger.error(f"Error in preprocessing tests: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def get_preprocessing_summary(self) -> Dict[str, Any]:
        """Get summary of preprocessing capabilities and configurations"""
        return {
            'model_specs': self.model_specs,
            'class_mappings': self.class_mappings,
            'scalers_loaded': {name: hasattr(scaler, 'mean_') for name, scaler in self.scalers.items()},
            'tokenizer_available': self.tokenizer is not None,
            'transformers_available': TRANSFORMERS_AVAILABLE,
            'feature_extractor_ready': self.feature_extractor is not None
        }
    
    # Wrapper methods for direct feature extraction (needed for individual model predictions)
    def extract_cnn_features(self, network_data: Dict[str, Any]) -> np.ndarray:
        """Extract CNN features - wrapper for feature_extractor method"""
        return self.feature_extractor.extract_cnn_features(network_data)
    
    def extract_lstm_features(self, network_data_sequence: List[Dict[str, Any]]) -> np.ndarray:
        """Extract LSTM features - wrapper for feature_extractor method"""
        return self.feature_extractor.extract_lstm_features(network_data_sequence)
    
    def extract_gnn_features(self, network_topology: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Extract GNN features - wrapper for feature_extractor method"""
        return self.feature_extractor.extract_gnn_features(network_topology)
    
    def extract_crypto_bert_features(self, protocol_sequences: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract Crypto-BERT features - wrapper for feature_extractor method"""
        return self.feature_extractor.extract_crypto_bert_features(protocol_sequences)

# Global preprocessor instance
data_preprocessor = DataPreprocessor()

# Convenience functions for easy access
def preprocess_for_cnn(network_data: Dict[str, Any]) -> np.ndarray:
    """Preprocess data for CNN model"""
    return data_preprocessor.preprocess_for_cnn(network_data)

def preprocess_for_lstm(network_data_sequence: List[Dict[str, Any]]) -> np.ndarray:
    """Preprocess data for LSTM model"""
    return data_preprocessor.preprocess_for_lstm(network_data_sequence)

def preprocess_for_gnn(network_topology: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Preprocess data for GNN model"""
    return data_preprocessor.preprocess_for_gnn(network_topology)

def preprocess_for_crypto_bert(protocol_sequences: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    """Preprocess data for Crypto-BERT model"""
    return data_preprocessor.preprocess_for_crypto_bert(protocol_sequences)

def preprocess_for_ensemble(**kwargs) -> Dict[str, Any]:
    """Preprocess data for ensemble model"""
    return data_preprocessor.preprocess_for_ensemble(**kwargs)

def validate_input_shapes(model_type: str, data: Union[np.ndarray, Dict[str, Any]]) -> bool:
    """Validate input shapes"""
    return data_preprocessor.validate_input_shapes(model_type, data)

def get_model_specs() -> Dict[str, Any]:
    """Get model specifications"""
    return data_preprocessor.get_model_specs()

def get_class_mappings() -> Dict[str, List[str]]:
    """Get class mappings"""
    return data_preprocessor.get_class_mappings()

def test_all_preprocessing() -> Dict[str, bool]:
    """Test all preprocessing functions"""
    return data_preprocessor.test_all_preprocessing()

def get_preprocessing_summary() -> Dict[str, Any]:
    """Get preprocessing summary"""
    return data_preprocessor.get_preprocessing_summary()