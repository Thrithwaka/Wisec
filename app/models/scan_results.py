"""
Wi-Fi Security System - Scan Results Models
==========================================

Database models for storing vulnerability scan results, network information,
vulnerability reports, and threat assessments.

Compatible with the database initialization system in __init__.py
"""

from datetime import datetime, timedelta
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSON, ARRAY
from enum import Enum
import json
import logging

# Import db from the models package
from app.models import db

# Configure logging
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration for scan results"""
    NORMAL = "NORMAL"
    LOW_RISK = "LOW_RISK" 
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"

class ThreatCategory(Enum):
    """Threat category enumeration based on AI model outputs"""
    # From ensemble model - 20 comprehensive categories
    NO_THREAT = "NO_THREAT"
    LOW_RISK_VULNERABILITY = "LOW_RISK_VULNERABILITY"
    MEDIUM_RISK_VULNERABILITY = "MEDIUM_RISK_VULNERABILITY"
    HIGH_RISK_VULNERABILITY = "HIGH_RISK_VULNERABILITY"
    CRITICAL_VULNERABILITY = "CRITICAL_VULNERABILITY"
    ACTIVE_ATTACK_DETECTED = "ACTIVE_ATTACK_DETECTED"
    RECONNAISSANCE_PHASE = "RECONNAISSANCE_PHASE"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    DATA_BREACH_RISK = "DATA_BREACH_RISK"
    NETWORK_COMPROMISE = "NETWORK_COMPROMISE"
    INSIDER_THREAT_DETECTED = "INSIDER_THREAT_DETECTED"
    APT_CAMPAIGN = "APT_CAMPAIGN"
    RANSOMWARE_INDICATORS = "RANSOMWARE_INDICATORS"
    BOTNET_PARTICIPATION = "BOTNET_PARTICIPATION"
    CRYPTO_WEAKNESS = "CRYPTO_WEAKNESS"
    FIRMWARE_EXPLOIT = "FIRMWARE_EXPLOIT"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"
    ANOMALOUS_BEHAVIOR = "ANOMALOUS_BEHAVIOR"
    SYSTEM_COMPROMISE = "SYSTEM_COMPROMISE"

class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanResult(db.Model):
    """
    Main scan result storage model
    Stores vulnerability scan results with AI model predictions
    """
    __tablename__ = 'scan_results'
    
    # Primary key and relationships
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Basic scan information
    network_ssid = db.Column(db.String(255), nullable=False, index=True)
    scan_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    scan_timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    scan_duration = db.Column(db.Float)  # Duration in seconds
    
    # Risk assessment
    risk_level = db.Column(db.Enum(RiskLevel), default=RiskLevel.NORMAL, nullable=False, index=True)
    overall_risk_score = db.Column(db.Float, default=0.0, nullable=False)
    confidence_score = db.Column(db.Float, default=0.0, nullable=False)
    
    # Scan configuration and status
    scan_type = db.Column(db.String(50), default='standard')  # standard, deep, passive
    scan_status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    
    # AI Model predictions (JSON storage for all 9 models)
    model_predictions = db.Column(JSON)
    ensemble_result = db.Column(JSON)
    
    # Network and scan data
    scan_data = db.Column(db.Text)  # Raw scan data
    network_topology = db.Column(JSON)  # Network topology data
    device_inventory = db.Column(JSON)  # Discovered devices
    
    # Additional metadata
    ip_address = db.Column(db.String(45))  # IPv4/IPv6
    location_data = db.Column(JSON)  # GPS/location if available
    scan_parameters = db.Column(JSON)  # Scan configuration parameters
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('scan_results', lazy='dynamic'))
    vulnerability_reports = db.relationship('VulnerabilityReport', backref='scan_result', lazy='dynamic', cascade='all, delete-orphan')
    network_info = db.relationship('NetworkInfo', backref='scan_result', uselist=False, cascade='all, delete-orphan')
    threat_assessments = db.relationship('ThreatAssessment', backref='scan_result', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<ScanResult {self.scan_id}: {self.network_ssid} - {self.risk_level.value}>'
    
    def to_dict(self):
        """Convert scan result to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'network_ssid': self.network_ssid,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'scan_duration': self.scan_duration,
            'risk_level': self.risk_level.value,
            'overall_risk_score': self.overall_risk_score,
            'confidence_score': self.confidence_score,
            'scan_type': self.scan_type,
            'scan_status': self.scan_status.value,
            'model_predictions': self.model_predictions,
            'ensemble_result': self.ensemble_result,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def create_scan_result(cls, user_id, network_ssid, scan_type='standard', **kwargs):
        """
        Create a new scan result entry
        
        Args:
            user_id (int): User ID
            network_ssid (str): Network SSID
            scan_type (str): Type of scan
            **kwargs: Additional parameters
            
        Returns:
            ScanResult: Created scan result instance
        """
        import uuid
        
        scan_result = cls(
            user_id=user_id,
            network_ssid=network_ssid,
            scan_id=f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}",
            scan_type=scan_type,
            scan_status=ScanStatus.PENDING,
            **kwargs
        )
        
        try:
            db.session.add(scan_result)
            db.session.commit()
            logger.info(f"Created scan result: {scan_result.scan_id}")
            return scan_result
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating scan result: {e}")
            raise
    
    def update_scan_status(self, status, **kwargs):
        """Update scan status and related fields"""
        try:
            self.scan_status = status
            self.updated_at = datetime.utcnow()
            
            # Update additional fields if provided
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            
            db.session.commit()
            logger.info(f"Updated scan {self.scan_id} status to {status.value}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating scan status: {e}")
            raise
    
    def save_ai_predictions(self, predictions):
        """
        Save AI model predictions
        
        Args:
            predictions (dict): Predictions from all AI models
        """
        try:
            self.model_predictions = predictions.get('individual_models', {})
            self.ensemble_result = predictions.get('ensemble_result', {})
            
            # Extract overall scores
            if 'overall_risk_score' in predictions:
                self.overall_risk_score = predictions['overall_risk_score']
            if 'confidence_score' in predictions:
                self.confidence_score = predictions['confidence_score']
            
            # Determine risk level from ensemble result
            if self.ensemble_result and 'predicted_class' in self.ensemble_result:
                self.risk_level = self._determine_risk_level(self.ensemble_result['predicted_class'])
            
            self.updated_at = datetime.utcnow()
            db.session.commit()
            logger.info(f"Saved AI predictions for scan {self.scan_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving AI predictions: {e}")
            raise
    
    def _determine_risk_level(self, predicted_class):
        """Determine risk level from AI prediction"""
        high_risk_threats = [
            'CRITICAL_VULNERABILITY', 'ACTIVE_ATTACK_DETECTED', 'SYSTEM_COMPROMISE',
            'DATA_BREACH_RISK', 'NETWORK_COMPROMISE', 'APT_CAMPAIGN'
        ]
        
        low_risk_threats = [
            'LOW_RISK_VULNERABILITY', 'CONFIGURATION_ERROR', 'COMPLIANCE_VIOLATION',
            'MEDIUM_RISK_VULNERABILITY'
        ]
        
        if predicted_class in high_risk_threats:
            return RiskLevel.HIGH_RISK
        elif predicted_class in low_risk_threats:
            return RiskLevel.LOW_RISK
        else:
            return RiskLevel.NORMAL
    
    @classmethod
    def get_user_scan_history(cls, user_id, limit=50):
        """Get scan history for a user"""
        try:
            return cls.query.filter_by(user_id=user_id)\
                          .order_by(cls.scan_timestamp.desc())\
                          .limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting scan history: {e}")
            return []
    
    @classmethod
    def get_scan_statistics(cls, user_id=None, days=30):
        """Get scan statistics"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            query = cls.query.filter(cls.scan_timestamp >= cutoff_date)
            
            if user_id:
                query = query.filter_by(user_id=user_id)
            
            total_scans = query.count()
            high_risk_scans = query.filter_by(risk_level=RiskLevel.HIGH_RISK).count()
            low_risk_scans = query.filter_by(risk_level=RiskLevel.LOW_RISK).count()
            normal_scans = query.filter_by(risk_level=RiskLevel.NORMAL).count()
            
            return {
                'total_scans': total_scans,
                'high_risk_scans': high_risk_scans,
                'low_risk_scans': low_risk_scans,
                'normal_scans': normal_scans,
                'risk_distribution': {
                    'high_risk_percentage': (high_risk_scans / total_scans * 100) if total_scans > 0 else 0,
                    'low_risk_percentage': (low_risk_scans / total_scans * 100) if total_scans > 0 else 0,
                    'normal_percentage': (normal_scans / total_scans * 100) if total_scans > 0 else 0
                }
            }
        except Exception as e:
            logger.error(f"Error getting scan statistics: {e}")
            return {}
    @classmethod
    def get_by_user(cls, user_id, limit=50):
        """Get scan results by user ID"""
        try:
            return cls.query.filter_by(user_id=user_id)\
                          .order_by(cls.scan_timestamp.desc())\
                          .limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting scans by user: {e}")
            return []
    
    @classmethod
    def get_recent_by_user(cls, user_id, limit=10):
        """Get recent scan results by user ID"""
        try:
            cutoff_date = datetime.now() - timedelta(days=7)  # Last 7 days
            return cls.query.filter_by(user_id=user_id)\
                          .filter(cls.scan_timestamp >= cutoff_date)\
                          .order_by(cls.scan_timestamp.desc())\
                          .limit(limit).all()
        except Exception as e:
            logger.error(f"Error getting recent scans by user: {e}")
            return []
    
    @classmethod
    def get_user_recent_scans(cls, user_id, limit=10):
        """Get user's recent scans (alias method)"""
        return cls.get_recent_by_user(user_id, limit)
    
    @classmethod
    def get_by_id_and_user(cls, scan_id, user_id):
        """Get scan result by ID and user ID"""
        try:
            return cls.query.filter_by(id=scan_id, user_id=user_id).first()
        except Exception as e:
            logger.error(f"Error getting scan by ID and user: {e}")
            return None
        
    def save(self):
        """Save the scan result to database"""
        try:
            db.session.add(self)
            db.session.commit()
            logger.info(f"Saved scan result: {self.scan_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving scan result: {e}")
            raise

class VulnerabilityReport(db.Model):
    """
    Detailed vulnerability report storage
    Stores specific vulnerability findings from AI analysis
    """
    __tablename__ = 'vulnerability_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False, index=True)
    
    # Vulnerability details
    vulnerability_type = db.Column(db.String(100), nullable=False, index=True)
    threat_category = db.Column(db.Enum(ThreatCategory), nullable=False, index=True)
    severity_level = db.Column(db.String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Description and details
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    technical_details = db.Column(db.Text)
    
    # Risk assessment
    cvss_score = db.Column(db.Float)  # Common Vulnerability Scoring System
    risk_score = db.Column(db.Float, nullable=False)
    confidence_level = db.Column(db.Float, nullable=False)
    
    # AI model information
    detected_by_model = db.Column(db.String(50))  # Which AI model detected this
    model_confidence = db.Column(db.Float)
    
    # Remediation
    recommendations = db.Column(JSON)  # List of recommendations
    remediation_steps = db.Column(JSON)  # Step-by-step remediation
    remediation_priority = db.Column(db.String(20))  # IMMEDIATE, HIGH, MEDIUM, LOW
    
    # Additional data
    affected_components = db.Column(JSON)  # Affected network components
    evidence_data = db.Column(JSON)  # Supporting evidence
    
    # Timestamps
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<VulnerabilityReport {self.vulnerability_type}: {self.severity_level}>'
    
    def to_dict(self):
        """Convert vulnerability report to dictionary"""
        return {
            'id': self.id,
            'vulnerability_type': self.vulnerability_type,
            'threat_category': self.threat_category.value,
            'severity_level': self.severity_level,
            'title': self.title,
            'description': self.description,
            'cvss_score': self.cvss_score,
            'risk_score': self.risk_score,
            'confidence_level': self.confidence_level,
            'detected_by_model': self.detected_by_model,
            'recommendations': self.recommendations,
            'remediation_priority': self.remediation_priority,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None
        }
    
    @classmethod
    def create_vulnerability_report(cls, scan_result_id, vulnerability_data):
        """Create a new vulnerability report"""
        try:
            report = cls(
                scan_result_id=scan_result_id,
                **vulnerability_data
            )
            db.session.add(report)
            db.session.commit()
            logger.info(f"Created vulnerability report: {report.vulnerability_type}")
            return report
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating vulnerability report: {e}")
            raise

class NetworkInfo(db.Model):
    """
    Network information storage
    Stores detailed network configuration and device information
    """
    __tablename__ = 'network_info'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False, index=True)
    
    # Basic network information
    ssid = db.Column(db.String(255), nullable=False)
    bssid = db.Column(db.String(17))  # MAC address format
    channel = db.Column(db.Integer)
    frequency = db.Column(db.Float)  # GHz
    
    # Signal information
    signal_strength = db.Column(db.Integer)  # RSSI in dBm
    signal_quality = db.Column(db.Float)  # Percentage
    noise_level = db.Column(db.Integer)  # dBm
    snr = db.Column(db.Float)  # Signal-to-Noise Ratio
    
    # Security configuration
    encryption_type = db.Column(db.String(50))  # WPA2, WPA3, WEP, Open
    authentication_method = db.Column(db.String(50))
    cipher_suite = db.Column(db.String(100))
    key_management = db.Column(db.String(50))
    
    # Access point information
    vendor = db.Column(db.String(100))
    device_model = db.Column(db.String(100))
    firmware_version = db.Column(db.String(50))
    
    # Network configuration
    ip_range = db.Column(db.String(50))  # CIDR notation
    gateway_ip = db.Column(db.String(45))
    dns_servers = db.Column(JSON)  # List of DNS servers
    dhcp_enabled = db.Column(db.Boolean)
    
    # Topology and devices
    connected_devices = db.Column(JSON)  # List of connected devices
    network_topology = db.Column(JSON)  # Network structure
    
    # Performance metrics
    bandwidth_usage = db.Column(JSON)  # Current bandwidth usage
    connection_count = db.Column(db.Integer)
    uptime = db.Column(db.Integer)  # Seconds
    
    # Additional metadata
    geographic_location = db.Column(JSON)  # GPS coordinates if available
    regulatory_domain = db.Column(db.String(10))  # Country code
    
    # Timestamps
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<NetworkInfo {self.ssid}: {self.encryption_type}>'
    
    def to_dict(self):
        """Convert network info to dictionary"""
        return {
            'id': self.id,
            'ssid': self.ssid,
            'bssid': self.bssid,
            'channel': self.channel,
            'frequency': self.frequency,
            'signal_strength': self.signal_strength,
            'signal_quality': self.signal_quality,
            'encryption_type': self.encryption_type,
            'vendor': self.vendor,
            'device_model': self.device_model,
            'ip_range': self.ip_range,
            'connected_devices': self.connected_devices,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None
        }
    
    @classmethod
    def create_network_info(cls, scan_result_id, network_data):
        """Create network information entry"""
        try:
            network_info = cls(
                scan_result_id=scan_result_id,
                **network_data
            )
            db.session.add(network_info)
            db.session.commit()
            logger.info(f"Created network info for SSID: {network_info.ssid}")
            return network_info
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating network info: {e}")
            raise

class ThreatAssessment(db.Model):
    """
    Threat assessment storage
    Stores detailed threat analysis and risk calculations
    """
    __tablename__ = 'threat_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'), nullable=False, index=True)
    
    # Threat identification
    threat_name = db.Column(db.String(100), nullable=False)
    threat_category = db.Column(db.Enum(ThreatCategory), nullable=False, index=True)
    threat_type = db.Column(db.String(50))  # ACTIVE, PASSIVE, POTENTIAL
    
    # Risk assessment
    likelihood = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    impact = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    risk_score = db.Column(db.Float, nullable=False)  # Calculated risk
    
    # AI model analysis
    model_predictions = db.Column(JSON)  # Predictions from specific models
    confidence_scores = db.Column(JSON)  # Confidence for each prediction
    detection_method = db.Column(db.String(100))  # How was it detected
    
    # Threat details
    description = db.Column(db.Text)
    indicators = db.Column(JSON)  # Threat indicators
    attack_vectors = db.Column(JSON)  # Possible attack vectors
    potential_damage = db.Column(db.Text)
    
    # Timeline and behavior
    first_detected = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime)
    activity_pattern = db.Column(JSON)  # Temporal patterns
    
    # Mitigation
    mitigation_status = db.Column(db.String(20), default='OPEN')  # OPEN, IN_PROGRESS, RESOLVED
    mitigation_steps = db.Column(JSON)
    remediation_time_estimate = db.Column(db.Integer)  # Minutes
    
    # Additional metadata
    affected_assets = db.Column(JSON)  # Assets at risk
    business_impact = db.Column(db.Text)
    compliance_impact = db.Column(JSON)  # Regulatory compliance issues
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<ThreatAssessment {self.threat_name}: Risk {self.risk_score:.2f}>'
    
    def to_dict(self):
        """Convert threat assessment to dictionary"""
        return {
            'id': self.id,
            'threat_name': self.threat_name,
            'threat_category': self.threat_category.value,
            'threat_type': self.threat_type,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'risk_score': self.risk_score,
            'description': self.description,
            'detection_method': self.detection_method,
            'mitigation_status': self.mitigation_status,
            'first_detected': self.first_detected.isoformat() if self.first_detected else None,
            'affected_assets': self.affected_assets
        }
    
    @classmethod
    def create_threat_assessment(cls, scan_result_id, threat_data):
        """Create a new threat assessment"""
        try:
            assessment = cls(
                scan_result_id=scan_result_id,
                **threat_data
            )
            db.session.add(assessment)
            db.session.commit()
            logger.info(f"Created threat assessment: {assessment.threat_name}")
            return assessment
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating threat assessment: {e}")
            raise
    
    def calculate_risk_score(self):
        """Calculate risk score based on likelihood and impact"""
        self.risk_score = self.likelihood * self.impact
        return self.risk_score

# Utility functions for scan results management

def save_scan_result(user_id, network_ssid, scan_type='standard', **kwargs):
    """
    Create and save a complete scan result with related data
    
    Args:
        user_id (int): User ID
        network_ssid (str): Network SSID
        scan_type (str): Type of scan
        **kwargs: Additional scan data
        
    Returns:
        ScanResult: Created scan result
    """
    try:
        # Create main scan result
        scan_result = ScanResult.create_scan_result(
            user_id=user_id,
            network_ssid=network_ssid,
            scan_type=scan_type,
            **kwargs
        )
        
        logger.info(f"Successfully created scan result: {scan_result.scan_id}")
        return scan_result
        
    except Exception as e:
        logger.error(f"Error saving scan result: {e}")
        raise

def get_scan_history(user_id, limit=50):
    """Get scan history for a user with related data"""
    try:
        return ScanResult.query.filter_by(user_id=user_id)\
                              .order_by(ScanResult.scan_timestamp.desc())\
                              .limit(limit).all()
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        return []

def generate_scan_report(scan_id):
    """Generate comprehensive scan report"""
    try:
        scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
        if not scan_result:
            return None
        
        report = {
            'scan_result': scan_result.to_dict(),
            'vulnerability_reports': [vr.to_dict() for vr in scan_result.vulnerability_reports],
            'network_info': scan_result.network_info.to_dict() if scan_result.network_info else None,
            'threat_assessments': [ta.to_dict() for ta in scan_result.threat_assessments],
            'generated_at': datetime.utcnow().isoformat()
        }
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating scan report: {e}")
        return None

def cleanup_old_scan_results(days_old=30):
    """Clean up old scan results based on retention policy"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        # Count records to be deleted
        old_scans = ScanResult.query.filter(
            ScanResult.scan_timestamp < cutoff_date
        ).count()
        
        # Delete old scan results (cascade will handle related records)
        ScanResult.query.filter(
            ScanResult.scan_timestamp < cutoff_date
        ).delete()
        
        db.session.commit()
        
        logger.info(f"Cleaned up {old_scans} old scan results")
        return old_scans
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cleaning up old scan results: {e}")
        return 0

def update_threat_status(scan_id, threat_id, status):
    """Update threat mitigation status"""
    try:
        threat = ThreatAssessment.query.join(ScanResult)\
                                     .filter(ScanResult.scan_id == scan_id,
                                            ThreatAssessment.id == threat_id)\
                                     .first()
        
        if threat:
            threat.mitigation_status = status
            threat.updated_at = datetime.utcnow()
            db.session.commit()
            logger.info(f"Updated threat {threat_id} status to {status}")
            return True
        
        return False
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating threat status: {e}")
        return False

def get_statistics():
    """Get comprehensive scan result statistics"""
    try:
        total_scans = ScanResult.query.count()
        total_vulnerabilities = VulnerabilityReport.query.count()
        total_threats = ThreatAssessment.query.count()
        
        # Risk level distribution
        risk_distribution = db.session.query(
            ScanResult.risk_level,
            db.func.count(ScanResult.id)
        ).group_by(ScanResult.risk_level).all()
        
        # Recent activity (last 24 hours)
        recent_cutoff = datetime.now() - timedelta(hours=24)
        recent_scans = ScanResult.query.filter(
            ScanResult.scan_timestamp >= recent_cutoff
        ).count()
        
        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'total_threats': total_threats,
            'recent_scans_24h': recent_scans,
            'risk_distribution': {level.value: count for level, count in risk_distribution},
            'last_updated': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {}

# Export the models and functions
__all__ = [
    'ScanResult',
    'VulnerabilityReport', 
    'NetworkInfo',
    'ThreatAssessment',
    'RiskLevel',
    'ThreatCategory',
    'ScanStatus',
    'save_scan_result',
    'get_scan_history',
    'generate_scan_report',
    'cleanup_old_scan_results',
    'update_threat_status',
    'get_statistics'
]