"""
Wi-Fi Security System - Data Validation Utilities
Purpose: Comprehensive data validation utilities for all system inputs
"""

import re
import os
import hashlib
import mimetypes
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse
import ipaddress
import base64
import json


class InputValidator:
    """General input validation utilities"""
    
    # Common regex patterns
    PATTERNS = {
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        'username': r'^[a-zA-Z0-9_]{3,20}$',
        'password': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
        'phone': r'^\+?1?-?\.?\s?\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})$',
        'alphanumeric': r'^[a-zA-Z0-9]+$',
        'hex': r'^[0-9A-Fa-f]+$',
        'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    }
    
    # Dangerous characters and patterns
    DANGEROUS_CHARS = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`', '$']
    SQL_INJECTION_PATTERNS = [
        r'(\bunion\b.*\bselect\b)',
        r'(\bselect\b.*\bfrom\b)',
        r'(\binsert\b.*\binto\b)',
        r'(\bupdate\b.*\bset\b)',
        r'(\bdelete\b.*\bfrom\b)',
        r'(\bdrop\b.*\btable\b)',
        r'(\balter\b.*\btable\b)',
        r'(--|\#|\/\*)',
        r'(\bor\b.*=.*\bor\b)',
        r'(\band\b.*=.*\band\b)'
    ]
    
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>'
    ]
    
    @classmethod
    def validate_input(cls, value: Any, input_type: str, **kwargs) -> Tuple[bool, str]:
        """
        General input validation
        
        Args:
            value: Input value to validate
            input_type: Type of validation to perform
            **kwargs: Additional validation parameters
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if value is None:
            return False, "Input cannot be None"
        
        # Convert to string for validation
        str_value = str(value).strip()
        
        if not str_value:
            return False, f"Empty {input_type} not allowed"
        
        # Length validation
        min_length = kwargs.get('min_length', 0)
        max_length = kwargs.get('max_length', 1000)
        
        if len(str_value) < min_length:
            return False, f"{input_type} must be at least {min_length} characters"
        
        if len(str_value) > max_length:
            return False, f"{input_type} must not exceed {max_length} characters"
        
        # Pattern validation
        if input_type in cls.PATTERNS:
            if not re.match(cls.PATTERNS[input_type], str_value, re.IGNORECASE):
                return False, f"Invalid {input_type} format"
        
        # Security validation
        if not cls._check_security(str_value):
            return False, f"Potentially malicious content detected in {input_type}"
        
        return True, "Valid"
    
    @classmethod
    def validate_email_format(cls, email: str) -> Tuple[bool, str]:
        """
        Email format validation
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email cannot be empty"
        
        email = email.strip().lower()
        
        # Basic format check
        if not re.match(cls.PATTERNS['email'], email):
            return False, "Invalid email format"
        
        # Domain validation
        try:
            domain = email.split('@')[1]
            if '.' not in domain:
                return False, "Invalid domain format"
            
            # Check for consecutive dots
            if '..' in domain:
                return False, "Invalid domain format"
            
            # Length checks
            if len(email) > 254:
                return False, "Email address too long"
            
            local_part = email.split('@')[0]
            if len(local_part) > 64:
                return False, "Email local part too long"
            
            return True, "Valid email"
            
        except (IndexError, AttributeError):
            return False, "Invalid email format"
    
    @classmethod
    def validate_password_strength(cls, password: str) -> Tuple[bool, str, Dict[str, bool]]:
        """
        Password strength validation
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message, strength_details)
        """
        if not password:
            return False, "Password cannot be empty", {}
        
        strength = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digit': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[@$!%*?&]', password)),
            'no_common': password.lower() not in cls._get_common_passwords()
        }
        
        # Calculate strength score
        score = sum(strength.values())
        
        if score < 4:
            return False, "Password too weak", strength
        elif score < 6:
            return True, "Password acceptable but could be stronger", strength
        else:
            return True, "Strong password", strength
    
    @classmethod
    def sanitize_input(cls, value: str, preserve_spaces: bool = True) -> str:
        """
        Input sanitization
        
        Args:
            value: Input to sanitize
            preserve_spaces: Whether to preserve spaces
            
        Returns:
            Sanitized input string
        """
        if not value:
            return ""
        
        # Remove dangerous characters
        sanitized = value
        for char in cls.DANGEROUS_CHARS:
            sanitized = sanitized.replace(char, "")
        
        # Remove control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        # Normalize whitespace
        if not preserve_spaces:
            sanitized = re.sub(r'\s+', ' ', sanitized)
        
        return sanitized.strip()
    
    @classmethod
    def check_malicious_content(cls, content: str) -> Tuple[bool, List[str]]:
        """
        Check for malicious content patterns
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (is_safe, threats_found)
        """
        threats = []
        content_lower = content.lower()
        
        # Check for SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, content_lower):
                threats.append("SQL Injection")
                break
        
        # Check for XSS patterns
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                threats.append("Cross-Site Scripting (XSS)")
                break
        
        # Check for command injection
        cmd_patterns = [r'[;&|`]', r'\$\(', r'`.*`']
        for pattern in cmd_patterns:
            if re.search(pattern, content):
                threats.append("Command Injection")
                break
        
        return len(threats) == 0, threats
    
    @classmethod
    def _check_security(cls, value: str) -> bool:
        """Internal security check"""
        is_safe, _ = cls.check_malicious_content(value)
        return is_safe
    
    @classmethod
    def _get_common_passwords(cls) -> List[str]:
        """Get list of common passwords"""
        return [
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', '12345678',
            'monkey', '1234567890', 'dragon', 'iloveyou', '654321'
        ]


class NetworkValidator:
    """Network-specific validation utilities"""
    
    # Common network patterns
    SSID_FORBIDDEN_CHARS = ['<', '>', '"', '&', '\x00']
    MAC_ADDRESS_PATTERN = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    
    @classmethod
    def validate_network_ssid(cls, ssid: str) -> Tuple[bool, str]:
        """
        SSID validation
        
        Args:
            ssid: Network SSID to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not ssid:
            return False, "SSID cannot be empty"
        
        # Length validation (IEEE 802.11 standard)
        if len(ssid) > 32:
            return False, "SSID cannot exceed 32 characters"
        
        # Check for forbidden characters
        for char in cls.SSID_FORBIDDEN_CHARS:
            if char in ssid:
                return False, f"SSID contains forbidden character: {char}"
        
        # Check for control characters
        if any(ord(char) < 32 for char in ssid if char not in '\t\n\r'):
            return False, "SSID contains invalid control characters"
        
        # Check for potentially malicious patterns
        is_safe, threats = InputValidator.check_malicious_content(ssid)
        if not is_safe:
            return False, f"SSID contains potentially malicious content: {', '.join(threats)}"
        
        return True, "Valid SSID"
    
    @classmethod
    def validate_network_credentials(cls, ssid: str, password: str = None, 
                                   security_type: str = "WPA2") -> Tuple[bool, str]:
        """
        Network credential validation
        
        Args:
            ssid: Network SSID
            password: Network password (optional for open networks)
            security_type: Security type (WPA2, WPA3, WEP, OPEN)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Validate SSID
        ssid_valid, ssid_error = cls.validate_network_ssid(ssid)
        if not ssid_valid:
            return False, ssid_error
        
        # Validate security type
        valid_security_types = ['WPA2', 'WPA3', 'WEP', 'OPEN', 'WPA']
        if security_type.upper() not in valid_security_types:
            return False, f"Invalid security type. Must be one of: {', '.join(valid_security_types)}"
        
        # Password validation based on security type
        if security_type.upper() == 'OPEN':
            if password:
                return False, "Open networks should not have passwords"
            return True, "Valid open network credentials"
        
        if not password:
            return False, f"{security_type} networks require a password"
        
        # Password length validation by security type
        if security_type.upper() == 'WEP':
            valid_lengths = [5, 10, 13, 26]  # WEP key lengths
            if len(password) not in valid_lengths:
                return False, f"WEP password must be {' or '.join(map(str, valid_lengths))} characters"
        
        elif security_type.upper() in ['WPA', 'WPA2', 'WPA3']:
            if len(password) < 8 or len(password) > 63:
                return False, f"{security_type} password must be 8-63 characters"
        
        # Check password security
        is_safe, threats = InputValidator.check_malicious_content(password)
        if not is_safe:
            return False, f"Password contains potentially malicious content: {', '.join(threats)}"
        
        return True, "Valid network credentials"
    
    @classmethod
    def validate_ip_address(cls, ip: str, version: int = None) -> Tuple[bool, str]:
        """
        IP address validation
        
        Args:
            ip: IP address to validate
            version: IP version (4 or 6, None for auto-detect)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not ip:
            return False, "IP address cannot be empty"
        
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            
            if version and ip_obj.version != version:
                return False, f"Expected IPv{version} address"
            
            # Check for reserved addresses
            if ip_obj.is_loopback:
                return True, f"Valid loopback address (IPv{ip_obj.version})"
            elif ip_obj.is_private:
                return True, f"Valid private address (IPv{ip_obj.version})"
            elif ip_obj.is_reserved:
                return False, "Reserved IP address not allowed"
            else:
                return True, f"Valid public address (IPv{ip_obj.version})"
                
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"
    
    @classmethod
    def validate_mac_address(cls, mac: str) -> Tuple[bool, str]:
        """
        MAC address validation
        
        Args:
            mac: MAC address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not mac:
            return False, "MAC address cannot be empty"
        
        mac = mac.strip().upper()
        
        if not re.match(cls.MAC_ADDRESS_PATTERN, mac):
            return False, "Invalid MAC address format (expected: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)"
        
        # Check for broadcast address
        if mac.replace(':', '').replace('-', '') == 'FFFFFFFFFFFF':
            return False, "Broadcast MAC address not allowed"
        
        # Check for all zeros
        if mac.replace(':', '').replace('-', '') == '000000000000':
            return False, "Null MAC address not allowed"
        
        return True, "Valid MAC address"
    
    @classmethod
    def validate_network_data(cls, network_data: dict) -> bool:
        """
        Validate network data structure for AI model input
        
        Args:
            network_data: Dictionary containing network information
            
        Returns:
            bool: True if valid network data structure
        """
        if not isinstance(network_data, dict):
            return False
        
        # Check for required basic structure
        if not network_data:
            return False
        
        # Check for at least some network-related keys
        expected_keys = ['ssid', 'signal_strength', 'encryption_type', 'channel', 'frequency', 'bssid']
        has_network_keys = any(key in network_data for key in expected_keys)
        
        if not has_network_keys:
            # Check if it's preprocessed features
            feature_keys = ['cnn_features', 'lstm_features', 'gnn_features', 'bert_features']
            has_feature_keys = any(key in network_data for key in feature_keys)
            return has_feature_keys
        
        return True
    
    @classmethod
    def validate_port_number(cls, port: Union[str, int]) -> Tuple[bool, str]:
        """
        Port number validation
        
        Args:
            port: Port number to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            port_num = int(port)
            
            if port_num < 1 or port_num > 65535:
                return False, "Port number must be between 1 and 65535"
            
            if port_num < 1024:
                return True, f"Valid well-known port: {port_num}"
            elif port_num < 49152:
                return True, f"Valid registered port: {port_num}"
            else:
                return True, f"Valid dynamic/private port: {port_num}"
                
        except (ValueError, TypeError):
            return False, "Port must be a valid integer"


class SecurityValidator:
    """Security-specific validation utilities"""
    
    # Security patterns
    TOKEN_PATTERN = r'^[A-Za-z0-9+/=]{20,}$'
    API_KEY_PATTERN = r'^[A-Za-z0-9]{32,}$'
    
    @classmethod
    def validate_security_token(cls, token: str, token_type: str = "generic") -> Tuple[bool, str]:
        """
        Security token validation
        
        Args:
            token: Security token to validate
            token_type: Type of token (jwt, api_key, session, etc.)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not token:
            return False, "Token cannot be empty"
        
        token = token.strip()
        
        # Basic format validation
        if token_type.lower() == 'jwt':
            # JWT tokens have 3 parts separated by dots
            parts = token.split('.')
            if len(parts) != 3:
                return False, "Invalid JWT format (must have 3 parts)"
            
            # Validate each part is base64
            for i, part in enumerate(parts):
                try:
                    # Add padding if needed
                    padded = part + '=' * (4 - len(part) % 4)
                    base64.b64decode(padded)
                except Exception:
                    return False, f"Invalid base64 encoding in JWT part {i+1}"
        
        elif token_type.lower() == 'api_key':
            if not re.match(cls.API_KEY_PATTERN, token):
                return False, "Invalid API key format"
        
        elif token_type.lower() == 'session':
            if len(token) < 32:
                return False, "Session token too short (minimum 32 characters)"
        
        # General token validation
        if not re.match(cls.TOKEN_PATTERN, token):
            return False, f"Invalid {token_type} token format"
        
        # Check for malicious content
        is_safe, threats = InputValidator.check_malicious_content(token)
        if not is_safe:
            return False, f"Token contains potentially malicious content: {', '.join(threats)}"
        
        return True, f"Valid {token_type} token"
    
    @classmethod
    def validate_encryption_key(cls, key: str, algorithm: str = "AES") -> Tuple[bool, str]:
        """
        Encryption key validation
        
        Args:
            key: Encryption key to validate
            algorithm: Encryption algorithm (AES, RSA, etc.)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not key:
            return False, "Encryption key cannot be empty"
        
        key = key.strip()
        
        if algorithm.upper() == 'AES':
            # AES key lengths: 128, 192, or 256 bits
            valid_lengths = [16, 24, 32]  # bytes
            key_bytes = len(key.encode('utf-8'))
            
            if key_bytes not in valid_lengths:
                return False, f"AES key must be {', '.join(map(str, valid_lengths))} bytes long"
        
        elif algorithm.upper() == 'RSA':
            # RSA keys are typically much longer and in specific formats
            if len(key) < 256:
                return False, "RSA key appears too short"
        
        # Check for weak patterns
        if len(set(key)) < len(key) // 4:
            return False, "Key has insufficient entropy (too many repeated characters)"
        
        return True, f"Valid {algorithm} encryption key"
    
    @classmethod
    def validate_hash(cls, hash_value: str, hash_type: str = "SHA256") -> Tuple[bool, str]:
        """
        Hash value validation
        
        Args:
            hash_value: Hash to validate
            hash_type: Hash algorithm (MD5, SHA1, SHA256, etc.)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not hash_value:
            return False, "Hash cannot be empty"
        
        hash_value = hash_value.strip().lower()
        
        # Expected lengths for different hash types
        expected_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha512': 128
        }
        
        hash_type_lower = hash_type.lower()
        if hash_type_lower in expected_lengths:
            expected_length = expected_lengths[hash_type_lower]
            if len(hash_value) != expected_length:
                return False, f"{hash_type} hash must be exactly {expected_length} characters"
        
        # Validate hex format
        if not re.match(r'^[0-9a-f]+$', hash_value):
            return False, "Hash must contain only hexadecimal characters"
        
        return True, f"Valid {hash_type} hash"


class FileValidator:
    """File validation utilities"""
    
    # Allowed file types and their MIME types
    ALLOWED_EXTENSIONS = {
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
        'document': ['.pdf', '.doc', '.docx', '.txt', '.rtf'],
        'archive': ['.zip', '.tar', '.gz', '.rar', '.7z'],
        'certificate': ['.pem', '.crt', '.cer', '.p12', '.pfx'],
        'config': ['.json', '.xml', '.yaml', '.yml', '.ini', '.conf']
    }
    
    ALLOWED_MIME_TYPES = {
        'image': ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp'],
        'document': ['application/pdf', 'application/msword', 'text/plain', 'application/rtf'],
        'archive': ['application/zip', 'application/x-tar', 'application/gzip'],
        'certificate': ['application/x-pem-file', 'application/x-x509-ca-cert'],
        'config': ['application/json', 'application/xml', 'text/yaml', 'text/plain']
    }
    
    # Maximum file sizes (in bytes)
    MAX_FILE_SIZES = {
        'image': 10 * 1024 * 1024,      # 10MB
        'document': 50 * 1024 * 1024,   # 50MB
        'archive': 100 * 1024 * 1024,   # 100MB
        'certificate': 1 * 1024 * 1024, # 1MB
        'config': 5 * 1024 * 1024       # 5MB
    }
    
    # Dangerous file signatures (magic bytes)
    DANGEROUS_SIGNATURES = {
        b'\x4d\x5a': 'Executable (PE)',
        b'\x7f\x45\x4c\x46': 'Executable (ELF)',
        b'\xcf\xfa\xed\xfe': 'Executable (Mach-O)',
        b'\x50\x4b\x03\x04': 'ZIP Archive (check contents)',
        b'\x25\x50\x44\x46': 'PDF (check for malicious content)'
    }
    
    @classmethod
    def validate_file_upload(cls, filename: str, file_content: bytes = None, 
                           allowed_types: List[str] = None, max_size: int = None) -> Tuple[bool, str]:
        """
        File upload validation
        
        Args:
            filename: Name of the uploaded file
            file_content: File content bytes (optional)
            allowed_types: List of allowed file type categories
            max_size: Maximum file size in bytes
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not filename:
            return False, "Filename cannot be empty"
        
        # Sanitize filename
        safe_filename = cls.generate_secure_filename(filename)
        if not safe_filename:
            return False, "Invalid filename after sanitization"
        
        # Get file extension
        _, ext = os.path.splitext(filename.lower())
        if not ext:
            return False, "File must have an extension"
        
        # Check allowed types
        if allowed_types:
            type_found = False
            for file_type in allowed_types:
                if file_type in cls.ALLOWED_EXTENSIONS:
                    if ext in cls.ALLOWED_EXTENSIONS[file_type]:
                        type_found = True
                        break
            
            if not type_found:
                return False, f"File type not allowed. Allowed types: {', '.join(allowed_types)}"
        
        # File content validation
        if file_content:
            # Size validation
            file_size = len(file_content)
            
            if max_size and file_size > max_size:
                return False, f"File too large (max: {max_size} bytes)"
            
            # Check against type-specific limits
            for file_type in cls.MAX_FILE_SIZES:
                if ext in cls.ALLOWED_EXTENSIONS.get(file_type, []):
                    if file_size > cls.MAX_FILE_SIZES[file_type]:
                        return False, f"File too large for {file_type} type (max: {cls.MAX_FILE_SIZES[file_type]} bytes)"
            
            # Magic byte validation
            is_safe = cls._check_file_signature(file_content[:16])
            if not is_safe:
                return False, "Potentially dangerous file type detected"
            
            # MIME type validation
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                mime_valid = cls._validate_mime_type(mime_type, allowed_types or [])
                if not mime_valid:
                    return False, f"MIME type {mime_type} not allowed"
        
        return True, "Valid file upload"
    
    @classmethod
    def generate_secure_filename(cls, filename: str) -> str:
        """
        Generate secure filename
        
        Args:
            filename: Original filename
            
        Returns:
            Secure filename
        """
        if not filename:
            return ""
        
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '/', '\\', ';', '&']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Remove control characters
        filename = ''.join(char for char in filename if ord(char) >= 32)
        
        # Limit length
        name, ext = os.path.splitext(filename)
        if len(name) > 100:
            name = name[:100]
        
        filename = name + ext
        
        # Ensure not empty
        if not filename or filename == '.':
            return "safe_file.txt"
        
        return filename
    
    @classmethod
    def validate_file_content(cls, content: bytes, expected_type: str = None) -> Tuple[bool, str]:
        """
        Validate file content for malicious patterns
        
        Args:
            content: File content bytes
            expected_type: Expected file type
            
        Returns:
            Tuple of (is_safe, details)
        """
        if not content:
            return False, "Empty file content"
        
        # Check file signature
        if not cls._check_file_signature(content[:16]):
            return False, "Dangerous file signature detected"
        
        # Check for embedded executables
        if b'\x4d\x5a' in content[100:]:  # PE header not at start
            return False, "Embedded executable detected"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            b'<script',
            b'javascript:',
            b'vbscript:',
            b'<?php',
            b'<%',
            b'exec(',
            b'system(',
            b'shell_exec('
        ]
        
        content_lower = content.lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                return False, f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}"
        
        return True, "File content appears safe"
    
    @classmethod
    def _check_file_signature(cls, signature: bytes) -> bool:
        """Check file signature against dangerous patterns"""
        for dangerous_sig in cls.DANGEROUS_SIGNATURES:
            if signature.startswith(dangerous_sig):
                return False
        return True
    
    @classmethod
    def _validate_mime_type(cls, mime_type: str, allowed_types: List[str]) -> bool:
        """Validate MIME type against allowed types"""
        if not allowed_types:
            return True
        
        for file_type in allowed_types:
            if file_type in cls.ALLOWED_MIME_TYPES:
                if mime_type in cls.ALLOWED_MIME_TYPES[file_type]:
                    return True
        
        return False


# Utility functions for easy access
def validate_email(email: str) -> Tuple[bool, str]:
    """Quick email validation"""
    return InputValidator.validate_email_format(email)


def validate_password(password: str) -> Tuple[bool, str, Dict[str, bool]]:
    """Quick password validation"""
    return InputValidator.validate_password_strength(password)


def validate_network_ssid(ssid: str) -> Tuple[bool, str]:
    """Quick SSID validation"""
    return NetworkValidator.validate_network_ssid(ssid)


def sanitize_input(value: str) -> str:
    """Quick input sanitization"""
    return InputValidator.sanitize_input(value)


def check_malicious_content(content: str) -> Tuple[bool, List[str]]:
    """Quick malicious content check"""
    return InputValidator.check_malicious_content(content)


# Example usage and testing
if __name__ == "__main__":
    # Test input validation
    print("Testing Input Validation:")
    print(validate_email("test@example.com"))
    print(validate_password("StrongPass123!"))
    print(validate_network_ssid("MyWiFiNetwork"))
    print(sanitize_input("<script>alert('xss')</script>"))
    print(check_malicious_content("SELECT * FROM users WHERE id=1"))