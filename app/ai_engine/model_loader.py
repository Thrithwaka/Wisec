"""
Wi-Fi Security System - AI Model Loader
app/ai_engine/model_loader.py

Purpose: Load and manage AI models efficiently with caching system - Updated to match actual models
Key Classes: ModelLoader (Singleton), ModelCache
Key Functions: load_all_models(), get_model(), reload_model()
"""

import os
import json
import pickle
import logging
import threading
from typing import Dict, Any, Optional, Union
from datetime import datetime
import tensorflow as tf
from tensorflow import keras
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModelCache:
    """Model caching system for efficient model management"""
    
    def __init__(self):
        self.cache: Dict[str, Any] = {}
        self.load_times: Dict[str, datetime] = {}
        self.model_sizes: Dict[str, int] = {}
        self.access_counts: Dict[str, int] = {}
    
    def store_model(self, model_name: str, model: Any, size: int) -> None:
        """Store model in cache with metadata"""
        self.cache[model_name] = model
        self.load_times[model_name] = datetime.now()
        self.model_sizes[model_name] = size
        self.access_counts[model_name] = 0
        logger.info(f"Model {model_name} cached successfully (Size: {size/1024/1024:.1f}MB)")
    
    def get_model(self, model_name: str) -> Optional[Any]:
        """Retrieve model from cache"""
        if model_name in self.cache:
            self.access_counts[model_name] += 1
            return self.cache[model_name]
        return None
    
    def is_cached(self, model_name: str) -> bool:
        """Check if model is in cache"""
        return model_name in self.cache
    
    def remove_model(self, model_name: str) -> None:
        """Remove model from cache"""
        if model_name in self.cache:
            del self.cache[model_name]
            del self.load_times[model_name]
            del self.model_sizes[model_name]
            del self.access_counts[model_name]
            logger.info(f"Model {model_name} removed from cache")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_size = sum(self.model_sizes.values())
        return {
            'total_models': len(self.cache),
            'total_size_mb': total_size / 1024 / 1024,
            'models': {
                name: {
                    'size_mb': size / 1024 / 1024,
                    'load_time': self.load_times[name].isoformat(),
                    'access_count': self.access_counts[name]
                }
                for name, size in self.model_sizes.items()
            }
        }


class ModelLoader:
    """Singleton model loader for AI models management - Updated for current models"""
    
    _instance = None
    _lock = threading.Lock()
    
    # Model specifications based on ACTUAL models in your system
    MODEL_SPECS = {
        'cnn': {
            'path': 'wifi_vulnerability_cnn_final.h5',
            'type': 'tensorflow',
            'size_mb': 20.1,
            'input_shape': (32,),
            'output_shape': (None, 12),
            'output_classes': 12,
            'confidence_threshold': 0.85,
            'class_type': 'vulnerability',
            'description': 'CNN Wi-Fi Vulnerability Detection'
        },
        'cnn_final': {
            'path': 'wifi_vulnerability_cnn_final.h5',
            'type': 'tensorflow',
            'size_mb': 20.1,
            'input_shape': (32,),
            'output_shape': (None, 12),
            'output_classes': 12,
            'confidence_threshold': 0.85,
            'class_type': 'vulnerability',
            'description': 'CNN Wi-Fi Vulnerability Detection - 12 vulnerability classes'
        },
        'lstm': {
            'path': 'wifi_lstm_model.h5',
            'type': 'tensorflow',
            'size_mb': 17.6,
            'input_shape': (50, 48),
            'output_shape': (None, 10),
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'LSTM Wi-Fi Vulnerability Detection'
        },
        'lstm_main': {
            'path': 'wifi_lstm_model.h5',
            'type': 'tensorflow',
            'size_mb': 17.6,
            'input_shape': (50, 48),
            'output_shape': (None, 10),
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'Main LSTM - 10 threat behavior classes'
        },
        'lstm_production': {
            'path': 'wifi_lstm_production.h5',
            'type': 'tensorflow',
            'size_mb': 17.6,
            'input_shape': (50, 48),
            'output_shape': (None, 10),
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'Production LSTM - 10 threat behavior classes'
        },
        'gnn': {
            'path': 'gnn_wifi_vulnerability_model.h5',
            'type': 'tensorflow',
            'size_mb': 0.4,
            'node_features': 24,
            'edge_features': 16,
            'output_classes': 8,
            'confidence_threshold': 0.80,
            'class_type': 'network_vulnerability',
            'description': 'Graph Neural Network'
        },
        'cnn_lstm_hybrid': {
            'path': 'wifi_cnn_lstm_model.h5',
            'type': 'tensorflow',
            'size_mb': 2.7,
            'input_shape': (50, 48),
            'output_shape': (None, 10),
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'CNN-LSTM Hybrid - 10 threat behavior classes'
        },
        'random_forest': {
            'path': 'wifi_random_forest_model.pkl',
            'type': 'sklearn',
            'size_mb': 122.7,
            'input_features': 2400,
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'Random Forest - 10 threat classes (2400 features)'
        },
        'gradient_boosting': {
            'path': 'wifi_gradient_boosting_model.pkl',
            'type': 'sklearn',
            'size_mb': 0.6,
            'input_features': 2400,
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'Gradient Boosting - 10 threat classes (2400 features)'
        },
        'crypto_bert': {
            'path': 'crypto_bert_enhanced.h5',
            'type': 'tensorflow',
            'size_mb': 0.1,
            'input_shape': (256,),
            'output_classes': 15,
            'confidence_threshold': 0.88,
            'class_type': 'crypto_vulnerability',
            'description': 'Enhanced Crypto-BERT'
        },
        'ensemble': {
            'component_models': 5,
            'output_classes': 10,
            'confidence_threshold': 0.82,
            'class_type': 'threat',
            'description': 'WiFi LSTM Ensemble Fusion'
        }
    }
    
    # Class mappings for actual models
    CLASS_MAPPINGS = {
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
        'cnn_vulnerability_classes': [
            'SECURE_NETWORK', 'WEAK_ENCRYPTION', 'OPEN_NETWORK', 'WPS_VULNERABILITY',
            'ROGUE_AP', 'EVIL_TWIN', 'DEAUTH_ATTACK', 'HANDSHAKE_CAPTURE',
            'FIRMWARE_OUTDATED', 'DEFAULT_CREDENTIALS', 'SIGNAL_LEAKAGE', 'UNKNOWN_THREAT'
        ],
        'lstm_threat_classes': [
            'NORMAL_BEHAVIOR', 'BRUTE_FORCE_ATTACK', 'RECONNAISSANCE', 'DATA_EXFILTRATION',
            'BOTNET_ACTIVITY', 'INSIDER_THREAT', 'APT_BEHAVIOR', 'DDOS_PREPARATION',
            'LATERAL_MOVEMENT', 'COMMAND_CONTROL'
        ],
        'gnn_network_classes': [
            'ISOLATED_VULNERABILITY', 'CASCADING_RISK', 'CRITICAL_NODE', 'BRIDGE_VULNERABILITY',
            'CLUSTER_WEAKNESS', 'PERIMETER_BREACH', 'PRIVILEGE_ESCALATION', 'NETWORK_PARTITION'
        ]
    }
    
    def __new__(cls, *args, **kwargs):
        """Fixed singleton pattern implementation that accepts any arguments"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ModelLoader, cls).__new__(cls)
        return cls._instance
    
    def __init__(self, *args, **kwargs):
        """Initialize ModelLoader - only runs once due to singleton pattern"""
        if not hasattr(self, 'initialized'):
            self.models_path = os.path.join(os.getcwd(), 'models')
            self.cache = ModelCache()
            self.ensemble_metadata = None
            self.is_initialized = False
            self.load_lock = threading.Lock()
            self.initialized = True
            logger.info("ModelLoader initialized")
    
    def _resolve_model_name(self, model_name: str) -> Optional[str]:
        """Resolve model name to MODEL_SPECS key"""
        # Direct name mappings for common aliases
        name_aliases = {
            'wifi_vulnerability_cnn_final': 'cnn_final',
            'wifi_lstm_model': 'lstm_main',
            'wifi_lstm_production': 'lstm_production',
            'gnn_wifi_vulnerability_model': 'gnn',
            'wifi_cnn_lstm_model': 'cnn_lstm_hybrid',
            'wifi_random_forest_model': 'random_forest',
            'wifi_gradient_boosting_model': 'gradient_boosting'
        }
        
        # Try alias lookup first
        if model_name in name_aliases:
            return name_aliases[model_name]
        
        # Create mapping from full filenames to short names
        filename_to_key = {}
        for key, spec in self.MODEL_SPECS.items():
            # Skip ensemble model as it doesn't have a path
            if 'path' not in spec:
                continue
            filename_to_key[spec['path']] = key
            # Also handle names without extensions
            filename_base = spec['path'].replace('.h5', '').replace('.pkl', '')
            filename_to_key[filename_base] = key
        
        # Try direct lookup first
        if model_name in self.MODEL_SPECS:
            return model_name
        # Try filename lookup
        elif model_name in filename_to_key:
            return filename_to_key[model_name]
        # Try with extensions
        elif f"{model_name}.h5" in filename_to_key:
            return filename_to_key[f"{model_name}.h5"]
        elif f"{model_name}.pkl" in filename_to_key:
            return filename_to_key[f"{model_name}.pkl"]
        else:
            return None
    
    def _get_model_path(self, model_name: str) -> str:
        """Get full path to model file"""
        model_key = self._resolve_model_name(model_name)
        if model_key is None:
            raise ValueError(f"Unknown model: {model_name}")
        
        # Ensemble model is a virtual model, doesn't have a file path
        if model_key == 'ensemble':
            raise ValueError(f"Ensemble model is virtual and has no file path")
        
        if 'path' not in self.MODEL_SPECS[model_key]:
            raise ValueError(f"Model {model_key} has no path specified")
        
        model_path = os.path.join(self.models_path, self.MODEL_SPECS[model_key]['path'])
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        return model_path
    
    def _load_tensorflow_model(self, model_path: str) -> tf.keras.Model:
        """Load TensorFlow/Keras model with error handling"""
        try:
            # Configure TensorFlow for optimal loading
            tf.config.threading.set_inter_op_parallelism_threads(2)
            tf.config.threading.set_intra_op_parallelism_threads(2)
            
            # Load model with custom objects if needed
            try:
                model = keras.models.load_model(model_path, compile=False)
            except Exception as e:
                # Try loading with safe_mode for corrupted models
                error_str = str(e)
                if ("quantization_mode" in error_str or 
                    "No model config found" in error_str or
                    "'str' object has no attribute" in error_str):
                    logger.warning(f"Model {model_path} appears corrupted, skipping...")
                    raise ValueError(f"Corrupted model file: {model_path}")
                else:
                    raise e
            
            logger.info(f"TensorFlow model loaded from {model_path}")
            return model
        except Exception as e:
            logger.error(f"Error loading TensorFlow model from {model_path}: {str(e)}")
            raise
    
    def _load_sklearn_model(self, model_path: str) -> Any:
        """Load scikit-learn model"""
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info(f"Scikit-learn model loaded from {model_path}")
            return model
        except Exception as e:
            logger.error(f"Error loading scikit-learn model from {model_path}: {str(e)}")
            raise
    
    def _load_ensemble_metadata(self) -> Dict[str, Any]:
        """Load ensemble configuration metadata"""
        metadata_path = os.path.join(self.models_path, 'wifi_ensemble_metadata.json')
        
        try:
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            logger.info("Ensemble metadata loaded successfully")
            return metadata
        except FileNotFoundError:
            logger.warning("Ensemble metadata file not found, using defaults")
            return self._get_default_ensemble_metadata()
        except Exception as e:
            logger.error(f"Error loading ensemble metadata: {str(e)}")
            return self._get_default_ensemble_metadata()
    
    def _get_default_ensemble_metadata(self) -> Dict[str, Any]:
        """Get default ensemble metadata based on current models"""
        return {
            'model_weights': {
                'lstm_main': 0.25,          # Main LSTM
                'lstm_production': 0.20,    # Production LSTM  
                'cnn_lstm_hybrid': 0.20,    # CNN-LSTM hybrid
                'random_forest': 0.20,      # Random Forest
                'gradient_boosting': 0.15   # Gradient Boosting
            },
            'confidence_threshold': 0.82,
            'high_confidence_threshold': 0.90,
            'ensemble_classes': 10,  # LSTM threat classes
            'primary_model_type': 'lstm_threat',
            'available_models': list(self.MODEL_SPECS.keys()),
            'class_mappings': self.CLASS_MAPPINGS
        }
    
    def load_all_models(self) -> Dict[str, bool]:
        """Load all available AI models"""
        with self.load_lock:
            if self.is_initialized:
                logger.info("Models already loaded")
                return self._get_load_status()
            
            logger.info("Starting to load all AI models...")
            load_results = {}
            
            # Load ensemble metadata first
            self.ensemble_metadata = self._load_ensemble_metadata()
            
            # Load all models according to specifications
            for model_name, spec in self.MODEL_SPECS.items():
                try:
                    # Skip ensemble model as it's virtual
                    if model_name == 'ensemble':
                        logger.info(f"Skipping {model_name} (virtual ensemble model)")
                        load_results[model_name] = True  # Mark as success since it's not a file
                        continue
                        
                    logger.info(f"Loading {model_name} ({spec['description']})...")
                    
                    model_path = self._get_model_path(model_name)
                    
                    # Check if file exists
                    if not os.path.exists(model_path):
                        logger.warning(f"Model file not found: {model_path}")
                        load_results[model_name] = False
                        continue
                    
                    file_size = os.path.getsize(model_path)
                    
                    # Load model based on type
                    if spec['type'] == 'tensorflow':
                        model = self._load_tensorflow_model(model_path)
                    elif spec['type'] == 'sklearn':
                        model = self._load_sklearn_model(model_path)
                    else:
                        raise ValueError(f"Unknown model type: {spec['type']}")
                    
                    # Store in cache
                    self.cache.store_model(model_name, model, file_size)
                    load_results[model_name] = True
                    
                    logger.info(f"✓ {model_name} loaded successfully")
                    
                except Exception as e:
                    logger.error(f"✗ Failed to load {model_name}: {str(e)}")
                    load_results[model_name] = False
            
            # Check if any models are loaded (reduced requirements)
            loaded_models = sum(1 for result in load_results.values() if result)
            
            if loaded_models > 0:
                self.is_initialized = True
                logger.info(f"AI system initialized with {loaded_models} models")
            else:
                logger.error("No models loaded successfully")
                self.is_initialized = False
            
            # Log cache statistics
            stats = self.cache.get_cache_stats()
            logger.info(f"Total models loaded: {stats['total_models']}")
            logger.info(f"Total memory usage: {stats['total_size_mb']:.1f}MB")
            
            return load_results
    
    def get_model(self, model_name: str) -> Optional[Any]:
        """Retrieve specific model from cache"""
        if not self.is_initialized:
            logger.warning("Models not initialized. Call load_all_models() first.")
            return None
        
        # Resolve model name using the same logic as _get_model_path
        model_key = self._resolve_model_name(model_name)
        if model_key is None:
            logger.error(f"Unknown model: {model_name}")
            return None
        
        model = self.cache.get_model(model_key)
        if model is None:
            logger.warning(f"Model {model_key} not found in cache")
        
        return model
    
    def reload_model(self, model_name: str) -> bool:
        """Hot reload specific model"""
        model_key = self._resolve_model_name(model_name)
        if model_key is None:
            logger.error(f"Unknown model: {model_name}")
            return False
        
        try:
            logger.info(f"Reloading model: {model_key}")
            
            # Remove from cache
            self.cache.remove_model(model_key)
            
            # Reload model
            spec = self.MODEL_SPECS[model_key]
            model_path = self._get_model_path(model_key)
            file_size = os.path.getsize(model_path)
            
            if spec['type'] == 'tensorflow':
                model = self._load_tensorflow_model(model_path)
            elif spec['type'] == 'sklearn':
                model = self._load_sklearn_model(model_path)
            else:
                raise ValueError(f"Unknown model type: {spec['type']}")
            
            # Store in cache
            self.cache.store_model(model_key, model, file_size)
            
            logger.info(f"Model {model_key} reloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload model {model_name}: {str(e)}")
            return False
    
    def get_ensemble_metadata(self) -> Optional[Dict[str, Any]]:
        """Get ensemble configuration metadata"""
        return self.ensemble_metadata
    
    def get_model_specs(self) -> Dict[str, Any]:
        """Get model specifications"""
        return self.MODEL_SPECS
    
    def get_class_mappings(self) -> Dict[str, Any]:
        """Get class mappings for all model types"""
        return self.CLASS_MAPPINGS
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_cache_stats()
    
    def _get_load_status(self) -> Dict[str, bool]:
        """Get current load status of all models"""
        status = {}
        for model_name in self.MODEL_SPECS.keys():
            if model_name == 'ensemble':
                status[model_name] = True  # Virtual model is always "loaded"
            else:
                status[model_name] = self.cache.is_cached(model_name)
        return status
    
    def is_model_loaded(self, model_name: str) -> bool:
        """Check if specific model is loaded"""
        model_key = self._resolve_model_name(model_name)
        if model_key is None:
            return False
        # Ensemble model is always "loaded" as it's virtual
        if model_key == 'ensemble':
            return True
        return self.cache.is_cached(model_key)
    
    def get_available_models(self) -> list:
        """Get list of available models"""
        return list(self.MODEL_SPECS.keys())
    
    def get_loaded_models(self) -> list:
        """Get list of successfully loaded models"""
        loaded = []
        for name in self.MODEL_SPECS.keys():
            if name == 'ensemble' or self.cache.is_cached(name):
                loaded.append(name)
        return loaded
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on all loaded models"""
        health_status = {
            'system_initialized': self.is_initialized,
            'models_status': {},
            'cache_stats': self.cache.get_cache_stats(),
            'ensemble_metadata_loaded': self.ensemble_metadata is not None
        }
        
        for model_name in self.MODEL_SPECS.keys():
            model = self.cache.get_model(model_name)
            health_status['models_status'][model_name] = {
                'loaded': model is not None,
                'type': self.MODEL_SPECS[model_name]['type'],
                'size_mb': self.MODEL_SPECS[model_name]['size_mb'],
                'description': self.MODEL_SPECS[model_name]['description']
            }
        
        return health_status


# Global model loader instance
model_loader = ModelLoader()

# Convenience functions for easy access
def load_all_models() -> Dict[str, bool]:
    """Load all AI models"""
    return model_loader.load_all_models()

def get_model(model_name: str) -> Optional[Any]:
    """Get specific model"""
    return model_loader.get_model(model_name)

def reload_model(model_name: str) -> bool:
    """Reload specific model"""
    return model_loader.reload_model(model_name)

def get_ensemble_metadata() -> Optional[Dict[str, Any]]:
    """Get ensemble metadata"""
    return model_loader.get_ensemble_metadata()

def get_model_specs() -> Dict[str, Any]:
    """Get model specifications"""
    return model_loader.get_model_specs()

def get_class_mappings() -> Dict[str, Any]:
    """Get class mappings"""
    return model_loader.get_class_mappings()

def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics"""
    return model_loader.get_cache_stats()

def health_check() -> Dict[str, Any]:
    """Perform health check"""
    return model_loader.health_check()