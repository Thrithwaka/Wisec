"""
Wi-Fi Security System - AI Model Performance Monitoring
Purpose: Monitor AI model performance and health for all 9 models in the ensemble
"""

import logging
import time
import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from collections import deque, defaultdict
import threading
from statistics import mean, stdev
import psutil
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceMetrics:
    """Performance metrics collection and calculation"""
    
    def __init__(self):
        self.accuracy_history = deque(maxlen=1000)
        self.precision_history = deque(maxlen=1000)
        self.recall_history = deque(maxlen=1000)
        self.f1_history = deque(maxlen=1000)
        self.latency_history = deque(maxlen=1000)
        self.prediction_timestamps = deque(maxlen=1000)
        self.prediction_confidence = deque(maxlen=1000)
        self.memory_usage = deque(maxlen=100)
        self.cpu_usage = deque(maxlen=100)
        
    def add_prediction_metrics(self, accuracy: float, precision: float, 
                             recall: float, f1_score: float, latency: float, 
                             confidence: float):
        """Add new prediction metrics"""
        timestamp = datetime.now()
        
        self.accuracy_history.append(accuracy)
        self.precision_history.append(precision)
        self.recall_history.append(recall)
        self.f1_history.append(f1_score)
        self.latency_history.append(latency)
        self.prediction_timestamps.append(timestamp)
        self.prediction_confidence.append(confidence)
        
    def add_system_metrics(self, memory_usage: float, cpu_usage: float):
        """Add system resource metrics"""
        self.memory_usage.append(memory_usage)
        self.cpu_usage.append(cpu_usage)
        
    def get_average_metrics(self, window_size: int = 100) -> Dict[str, float]:
        """Calculate average metrics over specified window"""
        recent_accuracy = list(self.accuracy_history)[-window_size:]
        recent_precision = list(self.precision_history)[-window_size:]
        recent_recall = list(self.recall_history)[-window_size:]
        recent_f1 = list(self.f1_history)[-window_size:]
        recent_latency = list(self.latency_history)[-window_size:]
        recent_confidence = list(self.prediction_confidence)[-window_size:]
        
        if not recent_accuracy:
            return {}
            
        return {
            'avg_accuracy': mean(recent_accuracy),
            'avg_precision': mean(recent_precision),
            'avg_recall': mean(recent_recall),
            'avg_f1_score': mean(recent_f1),
            'avg_latency': mean(recent_latency),
            'avg_confidence': mean(recent_confidence),
            'accuracy_std': stdev(recent_accuracy) if len(recent_accuracy) > 1 else 0,
            'latency_std': stdev(recent_latency) if len(recent_latency) > 1 else 0
        }

class ModelMonitor:
    """Main model performance monitoring system"""
    
    def __init__(self, model_names: List[str] = None):
        """Initialize model monitor with all 9 models"""
        self.model_names = model_names or [
            'wifi_vulnerability_cnn_final',
            'wifi_lstm_model', 
            'wifi_lstm_production',
            'gnn_wifi_vulnerability_model',
            'crypto_bert_enhanced',
            'wifi_cnn_lstm_model',
            'wifi_attention_model',
            'wifi_random_forest_model',
            'wifi_gradient_boosting_model'
        ]
        
        # Individual model metrics
        self.model_metrics = {name: PerformanceMetrics() for name in self.model_names}
        
        # Ensemble metrics
        self.ensemble_metrics = PerformanceMetrics()
        
        # Performance thresholds
        self.performance_thresholds = {
            'wifi_vulnerability_cnn_final': {'min_accuracy': 0.94, 'max_latency': 50},
            'wifi_lstm_model': {'min_accuracy': 0.91, 'max_latency': 60},
            'wifi_lstm_production': {'min_accuracy': 0.91, 'max_latency': 60},
            'gnn_wifi_vulnerability_model': {'min_accuracy': 0.88, 'max_latency': 40},
            'crypto_bert_enhanced': {'min_accuracy': 0.95, 'max_latency': 80},
            'wifi_cnn_lstm_model': {'min_accuracy': 0.92, 'max_latency': 70},
            'wifi_attention_model': {'min_accuracy': 0.90, 'max_latency': 30},
            'wifi_random_forest_model': {'min_accuracy': 0.85, 'max_latency': 20},
            'wifi_gradient_boosting_model': {'min_accuracy': 0.87, 'max_latency': 25}
        }
        
        # Ensemble thresholds
        self.ensemble_threshold = {'min_accuracy': 0.96, 'max_latency': 100}
        
        # Drift detection parameters
        self.drift_detection_window = 200
        self.drift_threshold = 0.05  # 5% drop in performance
        
        # Alert configuration
        self.alert_callbacks = []
        self.alert_history = deque(maxlen=100)
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        self.model_weights = {}  # Dynamic weights for ensemble
        
        # Performance logs
        self.log_file = "logs/model_performance.log"
        self._ensure_log_directory()
        
    def _ensure_log_directory(self):
        """Ensure log directory exists"""
        log_dir = Path(self.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
    def monitor_prediction_accuracy(self, model_name: str, predicted: np.ndarray, 
                                  actual: np.ndarray, inference_time: float, 
                                  confidence: float = None) -> Dict[str, float]:
        """Track accuracy for individual models"""
        try:
            # Calculate metrics
            if len(predicted.shape) > 1:
                predicted_labels = np.argmax(predicted, axis=1)
            else:
                predicted_labels = predicted
                
            if len(actual.shape) > 1:
                actual_labels = np.argmax(actual, axis=1)
            else:
                actual_labels = actual
                
            # Calculate performance metrics
            accuracy = np.mean(predicted_labels == actual_labels)
            
            # Calculate precision, recall, F1 for multiclass
            unique_labels = np.unique(np.concatenate([predicted_labels, actual_labels]))
            precision_scores = []
            recall_scores = []
            f1_scores = []
            
            for label in unique_labels:
                tp = np.sum((predicted_labels == label) & (actual_labels == label))
                fp = np.sum((predicted_labels == label) & (actual_labels != label))
                fn = np.sum((predicted_labels != label) & (actual_labels == label))
                
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                
                precision_scores.append(precision)
                recall_scores.append(recall)
                f1_scores.append(f1)
            
            avg_precision = np.mean(precision_scores)
            avg_recall = np.mean(recall_scores)
            avg_f1 = np.mean(f1_scores)
            
            # Use prediction confidence or calculate from softmax
            if confidence is None:
                if len(predicted.shape) > 1:
                    confidence = np.mean(np.max(predicted, axis=1))
                else:
                    confidence = 1.0  # Binary classification
            
            # Store metrics
            if model_name in self.model_metrics:
                self.model_metrics[model_name].add_prediction_metrics(
                    accuracy, avg_precision, avg_recall, avg_f1, 
                    inference_time, confidence
                )
            
            # Check for performance degradation
            self._check_performance_degradation(model_name, accuracy, inference_time)
            
            # Log metrics
            self._log_performance_metrics(model_name, accuracy, avg_precision, 
                                        avg_recall, avg_f1, inference_time, confidence)
            
            return {
                'accuracy': accuracy,
                'precision': avg_precision,
                'recall': avg_recall,
                'f1_score': avg_f1,
                'inference_time': inference_time,
                'confidence': confidence
            }
            
        except Exception as e:
            logger.error(f"Error monitoring accuracy for {model_name}: {str(e)}")
            return {}
    
    def detect_model_drift(self, model_name: str) -> Dict[str, Any]:
        """Concept drift detection for individual models"""
        try:
            if model_name not in self.model_metrics:
                return {'drift_detected': False, 'reason': 'No metrics available'}
            
            metrics = self.model_metrics[model_name]
            
            if len(metrics.accuracy_history) < self.drift_detection_window:
                return {'drift_detected': False, 'reason': 'Insufficient data'}
            
            # Split data into two windows
            recent_data = list(metrics.accuracy_history)[-self.drift_detection_window//2:]
            historical_data = list(metrics.accuracy_history)[-self.drift_detection_window:-self.drift_detection_window//2]
            
            # Calculate statistical difference
            recent_mean = mean(recent_data)
            historical_mean = mean(historical_data)
            
            # Check for significant drop in performance
            performance_drop = historical_mean - recent_mean
            drift_detected = performance_drop > self.drift_threshold
            
            # Additional checks
            recent_std = stdev(recent_data) if len(recent_data) > 1 else 0
            historical_std = stdev(historical_data) if len(historical_data) > 1 else 0
            
            # Variance change detection
            variance_change = abs(recent_std - historical_std) > 0.02
            
            drift_info = {
                'drift_detected': drift_detected,
                'performance_drop': performance_drop,
                'recent_accuracy': recent_mean,
                'historical_accuracy': historical_mean,
                'variance_change': variance_change,
                'recent_std': recent_std,
                'historical_std': historical_std,
                'timestamp': datetime.now().isoformat()
            }
            
            if drift_detected:
                self._alert_degradation(model_name, f"Drift detected: {performance_drop:.3f} drop in accuracy")
                
            return drift_info
            
        except Exception as e:
            logger.error(f"Error detecting drift for {model_name}: {str(e)}")
            return {'drift_detected': False, 'error': str(e)}
    
    def log_performance_metrics(self, model_name: str, metrics: Dict[str, float]):
        """Log individual and ensemble performance metrics"""
        try:
            timestamp = datetime.now().isoformat()
            
            # System resource usage
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            cpu_usage = psutil.cpu_percent()
            
            # Add system metrics
            if model_name in self.model_metrics:
                self.model_metrics[model_name].add_system_metrics(memory_usage, cpu_usage)
            
            log_entry = {
                'timestamp': timestamp,
                'model_name': model_name,
                'metrics': metrics,
                'memory_usage_mb': memory_usage,
                'cpu_usage_percent': cpu_usage
            }
            
            # Write to log file
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Error logging metrics for {model_name}: {str(e)}")
    
    def alert_degradation(self, model_name: str, issue: str):
        """Performance degradation alerts"""
        try:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'model_name': model_name,
                'alert_type': 'PERFORMANCE_DEGRADATION',
                'issue': issue,
                'severity': 'WARNING'
            }
            
            # Add to alert history
            self.alert_history.append(alert)
            
            # Log alert
            logger.warning(f"Performance alert for {model_name}: {issue}")
            
            # Call registered callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {str(e)}")
                    
            # Write to separate alert log
            alert_log_file = "logs/security.log"
            with open(alert_log_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
                
        except Exception as e:
            logger.error(f"Error sending alert for {model_name}: {str(e)}")
    
    def ensemble_health_check(self) -> Dict[str, Any]:
        """Overall ensemble system health check"""
        try:
            health_status = {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'HEALTHY',
                'individual_models': {},
                'ensemble_metrics': {},
                'system_resources': {},
                'alerts': []
            }
            
            # Check individual models
            unhealthy_models = []
            for model_name in self.model_names:
                model_health = self._check_individual_model_health(model_name)
                health_status['individual_models'][model_name] = model_health
                
                if not model_health['healthy']:
                    unhealthy_models.append(model_name)
            
            # Check ensemble metrics
            ensemble_metrics = self.ensemble_metrics.get_average_metrics()
            health_status['ensemble_metrics'] = ensemble_metrics
            
            # System resource check
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024 / 1024  # GB
            cpu_usage = psutil.cpu_percent()
            disk_usage = psutil.disk_usage('/').percent
            
            health_status['system_resources'] = {
                'memory_usage_gb': memory_usage,
                'cpu_usage_percent': cpu_usage,
                'disk_usage_percent': disk_usage,
                'memory_healthy': memory_usage < 3.0,  # Less than 3GB as per requirements
                'cpu_healthy': cpu_usage < 80,
                'disk_healthy': disk_usage < 90
            }
            
            # Overall health determination
            resource_healthy = (memory_usage < 3.0 and cpu_usage < 80 and disk_usage < 90)
            ensemble_healthy = (len(ensemble_metrics) == 0 or 
                              ensemble_metrics.get('avg_accuracy', 0) >= 0.96)
            
            if unhealthy_models or not resource_healthy or not ensemble_healthy:
                health_status['overall_status'] = 'DEGRADED'
                
            if len(unhealthy_models) >= 3:  # More than 1/3 of models unhealthy
                health_status['overall_status'] = 'CRITICAL'
            
            # Recent alerts
            recent_alerts = [alert for alert in self.alert_history 
                           if datetime.fromisoformat(alert['timestamp']) > 
                           datetime.now() - timedelta(hours=1)]
            health_status['alerts'] = recent_alerts
            
            return health_status
            
        except Exception as e:
            logger.error(f"Error in ensemble health check: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'ERROR',
                'error': str(e)
            }
    
    def model_agreement_analysis(self, predictions: Dict[str, np.ndarray]) -> Dict[str, float]:
        """Analyze prediction agreement between models"""
        try:
            if len(predictions) < 2:
                return {'agreement_score': 1.0, 'consensus_reached': True}
            
            model_names = list(predictions.keys())
            agreement_scores = []
            
            # Pairwise agreement calculation
            for i in range(len(model_names)):
                for j in range(i + 1, len(model_names)):
                    model1_pred = predictions[model_names[i]]
                    model2_pred = predictions[model_names[j]]
                    
                    # Convert to class predictions if needed
                    if len(model1_pred.shape) > 1:
                        model1_pred = np.argmax(model1_pred, axis=1)
                    if len(model2_pred.shape) > 1:
                        model2_pred = np.argmax(model2_pred, axis=1)
                    
                    # Calculate agreement
                    agreement = np.mean(model1_pred == model2_pred)
                    agreement_scores.append(agreement)
            
            overall_agreement = np.mean(agreement_scores)
            
            # Confidence correlation
            confidence_scores = []
            for model_name in model_names:
                pred = predictions[model_name]
                if len(pred.shape) > 1:
                    confidence = np.mean(np.max(pred, axis=1))
                else:
                    confidence = 1.0
                confidence_scores.append(confidence)
            
            confidence_std = np.std(confidence_scores)
            
            return {
                'agreement_score': overall_agreement,
                'confidence_correlation': 1.0 - confidence_std,  # Higher std = lower correlation
                'consensus_reached': overall_agreement > 0.8,
                'model_count': len(predictions),
                'pairwise_agreements': agreement_scores,
                'individual_confidences': dict(zip(model_names, confidence_scores))
            }
            
        except Exception as e:
            logger.error(f"Error in agreement analysis: {str(e)}")
            return {'agreement_score': 0.0, 'error': str(e)}
    
    def calibrate_ensemble_weights(self, performance_data: Dict[str, Dict[str, float]]) -> Dict[str, float]:
        """Dynamic weight adjustment based on performance"""
        try:
            total_weight = 0
            model_weights = {}
            
            for model_name in self.model_names:
                if model_name not in performance_data:
                    # Default weight for models without recent performance data
                    weight = 0.1
                else:
                    metrics = performance_data[model_name]
                    accuracy = metrics.get('avg_accuracy', 0.5)
                    confidence = metrics.get('avg_confidence', 0.5)
                    latency = metrics.get('avg_latency', 100)
                    
                    # Weight calculation based on performance
                    # Higher accuracy and confidence, lower latency = higher weight
                    accuracy_weight = accuracy
                    confidence_weight = confidence
                    latency_weight = max(0.1, 1.0 - (latency / 200))  # Normalize latency
                    
                    weight = (accuracy_weight * 0.5 + confidence_weight * 0.3 + latency_weight * 0.2)
                
                model_weights[model_name] = weight
                total_weight += weight
            
            # Normalize weights
            if total_weight > 0:
                model_weights = {name: weight / total_weight 
                               for name, weight in model_weights.items()}
            else:
                # Equal weights as fallback
                equal_weight = 1.0 / len(self.model_names)
                model_weights = {name: equal_weight for name in self.model_names}
            
            # Store weights
            self.model_weights = model_weights
            
            # Log weight updates
            logger.info(f"Updated ensemble weights: {model_weights}")
            
            return model_weights
            
        except Exception as e:
            logger.error(f"Error calibrating ensemble weights: {str(e)}")
            return {name: 1.0/len(self.model_names) for name in self.model_names}
    
    def start_monitoring(self, interval: int = 60):
        """Start continuous monitoring"""
        if self.monitoring_active:
            logger.warning("Monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info(f"Started model monitoring with {interval}s interval")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped model monitoring")
    
    def register_alert_callback(self, callback):
        """Register callback for alerts"""
        self.alert_callbacks.append(callback)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        try:
            summary = {
                'timestamp': datetime.now().isoformat(),
                'individual_models': {},
                'ensemble_performance': {},
                'system_health': {},
                'recent_alerts': list(self.alert_history)[-10:]  # Last 10 alerts
            }
            
            # Individual model summaries
            for model_name in self.model_names:
                if model_name in self.model_metrics:
                    metrics = self.model_metrics[model_name].get_average_metrics()
                    drift_info = self.detect_model_drift(model_name)
                    
                    summary['individual_models'][model_name] = {
                        'performance_metrics': metrics,
                        'drift_detection': drift_info,
                        'health_status': self._check_individual_model_health(model_name)
                    }
            
            # Ensemble performance
            ensemble_metrics = self.ensemble_metrics.get_average_metrics()
            summary['ensemble_performance'] = {
                'metrics': ensemble_metrics,
                'model_weights': self.model_weights,
                'target_accuracy': 0.96,
                'target_latency': 100
            }
            
            # System health
            summary['system_health'] = self.ensemble_health_check()
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating performance summary: {str(e)}")
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}
    
    # Private helper methods
    def _check_individual_model_health(self, model_name: str) -> Dict[str, Any]:
        """Check health of individual model"""
        if model_name not in self.model_metrics:
            return {'healthy': False, 'reason': 'No metrics available'}
        
        metrics = self.model_metrics[model_name].get_average_metrics()
        if not metrics:
            return {'healthy': False, 'reason': 'No performance data'}
        
        thresholds = self.performance_thresholds.get(model_name, {})
        min_accuracy = thresholds.get('min_accuracy', 0.8)
        max_latency = thresholds.get('max_latency', 100)
        
        accuracy_ok = metrics.get('avg_accuracy', 0) >= min_accuracy
        latency_ok = metrics.get('avg_latency', float('inf')) <= max_latency
        
        healthy = accuracy_ok and latency_ok
        
        return {
            'healthy': healthy,
            'accuracy_ok': accuracy_ok,
            'latency_ok': latency_ok,
            'current_accuracy': metrics.get('avg_accuracy', 0),
            'current_latency': metrics.get('avg_latency', 0),
            'min_accuracy_threshold': min_accuracy,
            'max_latency_threshold': max_latency
        }
    
    def _check_performance_degradation(self, model_name: str, accuracy: float, latency: float):
        """Check for performance degradation"""
        thresholds = self.performance_thresholds.get(model_name, {})
        min_accuracy = thresholds.get('min_accuracy', 0.8)
        max_latency = thresholds.get('max_latency', 100)
        
        if accuracy < min_accuracy:
            self._alert_degradation(model_name, f"Accuracy below threshold: {accuracy:.3f} < {min_accuracy}")
        
        if latency > max_latency:
            self._alert_degradation(model_name, f"Latency above threshold: {latency:.1f}ms > {max_latency}ms")
    
    def _alert_degradation(self, model_name: str, issue: str):
        """Internal method to send degradation alerts"""
        self.alert_degradation(model_name, issue)
    
    def _log_performance_metrics(self, model_name: str, accuracy: float, precision: float, 
                                recall: float, f1_score: float, latency: float, confidence: float):
        """Internal method to log performance metrics"""
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'latency_ms': latency,
            'confidence': confidence
        }
        self.log_performance_metrics(model_name, metrics)
    
    def _monitoring_loop(self, interval: int):
        """Continuous monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform health checks
                health_status = self.ensemble_health_check()
                
                # Check for drift in all models
                for model_name in self.model_names:
                    self.detect_model_drift(model_name)
                
                # Recalibrate ensemble weights
                performance_data = {}
                for model_name in self.model_names:
                    if model_name in self.model_metrics:
                        performance_data[model_name] = self.model_metrics[model_name].get_average_metrics()
                
                self.calibrate_ensemble_weights(performance_data)
                
                # Log monitoring cycle
                logger.info(f"Monitoring cycle completed. Status: {health_status['overall_status']}")
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
            
            time.sleep(interval)