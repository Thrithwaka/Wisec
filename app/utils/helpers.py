"""
Wi-Fi Security System - Helper Functions
Purpose: General utility and helper functions for the Flask application
"""

import os
import uuid
import hashlib
import secrets
import shutil
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re
import json
import logging

# Configure logging
logger = logging.getLogger(__name__)

class UtilityHelper:
    """General utility functions"""
    
    @staticmethod
    def generate_unique_id(prefix: str = "") -> str:
        """
        Generate a unique identifier with optional prefix
        
        Args:
            prefix: Optional prefix for the ID
            
        Returns:
            Unique identifier string
        """
        unique_id = str(uuid.uuid4())
        if prefix:
            return f"{prefix}_{unique_id}"
        return unique_id
    
    @staticmethod
    def create_backup(source_path: str, backup_dir: str = "backups") -> str:
        """
        Create backup of a file or directory
        
        Args:
            source_path: Path to source file/directory
            backup_dir: Backup directory path
            
        Returns:
            Path to created backup
        """
        try:
            # Ensure backup directory exists
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate backup filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            source_name = os.path.basename(source_path)
            backup_name = f"{source_name}_{timestamp}"
            backup_path = os.path.join(backup_dir, backup_name)
            
            # Create backup
            if os.path.isfile(source_path):
                shutil.copy2(source_path, backup_path)
            elif os.path.isdir(source_path):
                shutil.copytree(source_path, backup_path)
            else:
                raise ValueError(f"Source path does not exist: {source_path}")
            
            logger.info(f"Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise
    
    @staticmethod
    def safe_remove_file(file_path: str) -> bool:
        """
        Safely remove a file with error handling
        
        Args:
            file_path: Path to file to remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"File removed: {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove file {file_path}: {e}")
            return False

class FormatHelper:
    """Data formatting utilities"""
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """
        Format file size in human-readable format
        
        Args:
            size_bytes: Size in bytes
            
        Returns:
            Formatted size string (e.g., "1.5 MB")
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    @staticmethod
    def format_signal_strength(rssi: int) -> Dict[str, Any]:
        """
        Format Wi-Fi signal strength with quality rating
        
        Args:
            rssi: RSSI value in dBm
            
        Returns:
            Dictionary with signal info and quality rating
        """
        if rssi >= -50:
            quality = "Excellent"
            bars = 5
        elif rssi >= -60:
            quality = "Good"
            bars = 4
        elif rssi >= -70:
            quality = "Fair"
            bars = 3
        elif rssi >= -80:
            quality = "Weak"
            bars = 2
        else:
            quality = "Very Weak"
            bars = 1
        
        return {
            "rssi": rssi,
            "quality": quality,
            "bars": bars,
            "percentage": max(0, min(100, 2 * (rssi + 100)))
        }
    
    @staticmethod
    def format_network_info(network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format network information for display
        
        Args:
            network_data: Raw network data
            
        Returns:
            Formatted network information
        """
        formatted = {
            "ssid": network_data.get("ssid", "Unknown"),
            "bssid": network_data.get("bssid", "").upper(),
            "channel": network_data.get("channel", "Unknown"),
            "frequency": f"{network_data.get('frequency', 0)} MHz",
            "security": network_data.get("security", "Unknown"),
            "signal": FormatHelper.format_signal_strength(
                network_data.get("signal", -100)
            ),
            "vendor": network_data.get("vendor", "Unknown"),
            "encryption": network_data.get("encryption", "Unknown")
        }
        
        return formatted
    
    @staticmethod
    def format_risk_score(risk_score: float) -> Dict[str, Any]:
        """
        Format risk score with visual indicators
        
        Args:
            risk_score: Risk score (0.0 to 1.0)
            
        Returns:
            Formatted risk information
        """
        risk_percentage = risk_score * 100
        
        if risk_score >= 0.8:
            level = "HIGH RISK"
            color = "#dc3545"  # Red
            icon = "⚠️"
        elif risk_score >= 0.4:
            level = "LOW RISK"
            color = "#ffc107"  # Yellow
            icon = "⚡"
        else:
            level = "NORMAL"
            color = "#28a745"  # Green
            icon = "✅"
        
        return {
            "score": risk_score,
            "percentage": round(risk_percentage, 1),
            "level": level,
            "color": color,
            "icon": icon,
            "description": f"{level} ({risk_percentage:.1f}%)"
        }

class DateTimeHelper:
    """Date and time utility functions"""
    
    @staticmethod
    def format_timestamp(timestamp: datetime, format_type: str = "default") -> str:
        """
        Format timestamp for display
        
        Args:
            timestamp: Datetime object
            format_type: Format type ('default', 'short', 'long', 'iso')
            
        Returns:
            Formatted timestamp string
        """
        if not timestamp:
            return "Unknown"
        
        formats = {
            "default": "%Y-%m-%d %H:%M:%S",
            "short": "%m/%d/%Y %H:%M",
            "long": "%A, %B %d, %Y at %I:%M %p",
            "iso": "%Y-%m-%dT%H:%M:%S",
            "date_only": "%Y-%m-%d",
            "time_only": "%H:%M:%S"
        }
        
        return timestamp.strftime(formats.get(format_type, formats["default"]))
    
    @staticmethod
    def calculate_time_difference(start_time: datetime, end_time: datetime = None) -> Dict[str, Any]:
        """
        Calculate time difference between two timestamps
        
        Args:
            start_time: Start timestamp
            end_time: End timestamp (defaults to now)
            
        Returns:
            Time difference information
        """
        if end_time is None:
            end_time = datetime.now()
        
        diff = end_time - start_time
        
        days = diff.days
        hours, remainder = divmod(diff.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        # Create human-readable format
        if days > 0:
            readable = f"{days} day{'s' if days != 1 else ''}"
            if hours > 0:
                readable += f", {hours} hour{'s' if hours != 1 else ''}"
        elif hours > 0:
            readable = f"{hours} hour{'s' if hours != 1 else ''}"
            if minutes > 0:
                readable += f", {minutes} minute{'s' if minutes != 1 else ''}"
        elif minutes > 0:
            readable = f"{minutes} minute{'s' if minutes != 1 else ''}"
        else:
            readable = f"{seconds} second{'s' if seconds != 1 else ''}"
        
        return {
            "total_seconds": diff.total_seconds(),
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "seconds": seconds,
            "readable": readable
        }
    
    @staticmethod
    def is_recent(timestamp: datetime, threshold_minutes: int = 30) -> bool:
        """
        Check if timestamp is recent (within threshold)
        
        Args:
            timestamp: Timestamp to check
            threshold_minutes: Threshold in minutes
            
        Returns:
            True if recent, False otherwise
        """
        if not timestamp:
            return False
        
        threshold = datetime.now() - timedelta(minutes=threshold_minutes)
        return timestamp >= threshold

class SecurityHelper:
    """Security utility functions"""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        """
        Initialize security helper
        
        Args:
            encryption_key: Optional encryption key (generates one if None)
        """
        self.encryption_key = encryption_key or self._generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def _generate_key(self) -> bytes:
        """Generate encryption key from environment or create new one"""
        key_env = os.environ.get('ENCRYPTION_KEY')
        if key_env:
            return base64.urlsafe_b64decode(key_env.encode())
        
        # Generate new key for development
        password = b"wifi_security_system_default_key"
        salt = b"salt_1234567890123456"  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """
        Encrypt sensitive data
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data as base64 string
        """
        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data
        
        Args:
            encrypted_data: Encrypted data as base64 string
            
        Returns:
            Decrypted data
        """
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    @staticmethod
    def generate_secure_filename(filename: str) -> str:
        """
        Generate secure filename by sanitizing input
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized secure filename
        """
        # Remove path separators and dangerous characters
        filename = re.sub(r'[^\w\-_\.]', '_', filename)
        
        # Limit length
        name, ext = os.path.splitext(filename)
        if len(name) > 100:
            name = name[:100]
        
        # Add timestamp to ensure uniqueness
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        secure_name = f"{name}_{timestamp}{ext}"
        
        return secure_name
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate cryptographically secure random token
        
        Args:
            length: Token length in bytes
            
        Returns:
            Secure token as hex string
        """
        return secrets.token_hex(length)
    
    @staticmethod
    def hash_data(data: str, salt: Optional[str] = None) -> str:
        """
        Hash data with optional salt
        
        Args:
            data: Data to hash
            salt: Optional salt
            
        Returns:
            Hash as hex string
        """
        if salt:
            data = f"{data}{salt}"
        
        return hashlib.sha256(data.encode()).hexdigest()

class ValidationHelper:
    """Validation utility functions"""
    
    @staticmethod
    def is_valid_ssid(ssid: str) -> bool:
        """
        Validate Wi-Fi SSID format
        
        Args:
            ssid: SSID to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not ssid or len(ssid) > 32:
            return False
        
        # Check for valid characters (printable ASCII)
        return all(32 <= ord(char) <= 126 for char in ssid)
    
    @staticmethod
    def is_valid_mac_address(mac: str) -> bool:
        """
        Validate MAC address format
        
        Args:
            mac: MAC address to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not mac:
            return False
        
        # Support different formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, mac))
    
    @staticmethod
    def sanitize_json_input(data: Any) -> Any:
        """
        Sanitize JSON input data
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data
        """
        if isinstance(data, dict):
            return {k: ValidationHelper.sanitize_json_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [ValidationHelper.sanitize_json_input(item) for item in data]
        elif isinstance(data, str):
            # Remove potentially dangerous characters
            return re.sub(r'[<>"\']', '', data)
        else:
            return data

class ConfigHelper:
    """Configuration utility functions"""
    
    @staticmethod
    def load_model_config(config_path: str) -> Dict[str, Any]:
        """
        Load AI model configuration
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Validate required fields
            required_fields = ['models', 'ensemble_weights', 'performance_thresholds']
            for field in required_fields:
                if field not in config:
                    raise ValueError(f"Missing required field: {field}")
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to load model config: {e}")
            raise
    
    @staticmethod
    def get_model_paths() -> Dict[str, str]:
        """
        Get paths to all AI model files
        
        Returns:
            Dictionary mapping model names to file paths
        """
        model_dir = "models"
        return {
            "cnn_final": os.path.join(model_dir, "wifi_vulnerability_cnn_final.h5"),
            "lstm_main": os.path.join(model_dir, "wifi_lstm_model.h5"),
            "lstm_production": os.path.join(model_dir, "wifi_lstm_production.h5"),
            "gnn": os.path.join(model_dir, "gnn_wifi_vulnerability_model.h5"),
            "crypto_bert": os.path.join(model_dir, "crypto_bert_enhanced.h5"),
            "cnn_lstm": os.path.join(model_dir, "wifi_cnn_lstm_model.h5"),
            "attention": os.path.join(model_dir, "wifi_attention_model.h5"),
            "random_forest": os.path.join(model_dir, "wifi_random_forest_model.pkl"),
            "gradient_boosting": os.path.join(model_dir, "wifi_gradient_boosting_model.pkl"),
            "ensemble_metadata": os.path.join(model_dir, "wifi_ensemble_metadata.json")
        }

# Initialize global security helper instance
_security_helper = None

def get_security_helper() -> SecurityHelper:
    """Get global security helper instance"""
    global _security_helper
    if _security_helper is None:
        _security_helper = SecurityHelper()
    return _security_helper

# Convenience functions for common operations
def format_timestamp(timestamp: datetime, format_type: str = "default") -> str:
    """Convenience function for timestamp formatting"""
    return DateTimeHelper.format_timestamp(timestamp, format_type)

def format_file_size(size_bytes: int) -> str:
    """Convenience function for file size formatting"""
    return FormatHelper.format_file_size(size_bytes)

def generate_unique_id(prefix: str = "") -> str:
    """Convenience function for unique ID generation"""
    return UtilityHelper.generate_unique_id(prefix)

def encrypt_data(data: str) -> str:
    """Convenience function for data encryption"""
    return get_security_helper().encrypt_sensitive_data(data)

def decrypt_data(encrypted_data: str) -> str:
    """Convenience function for data decryption"""
    return get_security_helper().decrypt_sensitive_data(encrypted_data)

def calculate_time_ago(timestamp: datetime) -> str:
    """Calculate and format time ago from timestamp"""
    time_diff = DateTimeHelper.calculate_time_difference(timestamp)
    return f"{time_diff['readable']} ago"

def is_valid_network_data(data: Dict[str, Any]) -> bool:
    """Validate network data structure"""
    required_fields = ['ssid', 'bssid', 'signal']
    return all(field in data for field in required_fields)

# Additional convenience functions for module-level imports
def calculate_time_difference(start_time: datetime, end_time: datetime = None) -> Dict[str, Any]:
    """Convenience function for time difference calculation"""
    return DateTimeHelper.calculate_time_difference(start_time, end_time)

def format_signal_strength(rssi: int) -> Dict[str, Any]:
    """Convenience function for signal strength formatting"""
    return FormatHelper.format_signal_strength(rssi)

def format_network_info(network_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for network info formatting"""
    return FormatHelper.format_network_info(network_data)

def format_risk_score(risk_score: float) -> Dict[str, Any]:
    """Convenience function for risk score formatting"""
    return FormatHelper.format_risk_score(risk_score)

def is_recent(timestamp: datetime, threshold_minutes: int = 30) -> bool:
    """Convenience function for recency check"""
    return DateTimeHelper.is_recent(timestamp, threshold_minutes)

def is_valid_ssid(ssid: str) -> bool:
    """Convenience function for SSID validation"""
    return ValidationHelper.is_valid_ssid(ssid)

def is_valid_mac_address(mac: str) -> bool:
    """Convenience function for MAC address validation"""
    return ValidationHelper.is_valid_mac_address(mac)

def sanitize_json_input(data: Any) -> Any:
    """Convenience function for JSON input sanitization"""
    return ValidationHelper.sanitize_json_input(data)

def generate_secure_filename(filename: str) -> str:
    """Convenience function for secure filename generation"""
    return SecurityHelper.generate_secure_filename(filename)

def generate_secure_token(length: int = 32) -> str:
    """Convenience function for secure token generation"""
    return SecurityHelper.generate_secure_token(length)

def hash_data(data: str, salt: Optional[str] = None) -> str:
    """Convenience function for data hashing"""
    return SecurityHelper.hash_data(data, salt)

def create_backup(source_path: str, backup_dir: str = "backups") -> str:
    """Convenience function for backup creation"""
    return UtilityHelper.create_backup(source_path, backup_dir)

def safe_remove_file(file_path: str) -> bool:
    """Convenience function for safe file removal"""
    return UtilityHelper.safe_remove_file(file_path)

def get_model_paths() -> Dict[str, str]:
    """Convenience function for model paths"""
    return ConfigHelper.get_model_paths()

def load_model_config(config_path: str) -> Dict[str, Any]:
    """Convenience function for model config loading"""
    return ConfigHelper.load_model_config(config_path)

# Export all helper classes and functions
__all__ = [
    'UtilityHelper',
    'FormatHelper', 
    'DateTimeHelper',
    'SecurityHelper',
    'ValidationHelper',
    'ConfigHelper',
    'get_security_helper',
    'format_timestamp',
    'format_file_size',
    'generate_unique_id',
    'encrypt_data',
    'decrypt_data',
    'calculate_time_ago',
    'is_valid_network_data',
    'calculate_time_difference',
    'format_signal_strength',
    'format_network_info',
    'format_risk_score',
    'is_recent',
    'is_valid_ssid',
    'is_valid_mac_address',
    'sanitize_json_input',
    'generate_secure_filename',
    'generate_secure_token',
    'hash_data',
    'create_backup',
    'safe_remove_file',
    'get_model_paths',
    'load_model_config'
]