"""
Advanced Rogue AP Detection Engine
Purpose: Detect rogue access points, evil twins, and suspicious WiFi networks in real-time
Security: Uses advanced heuristics and machine learning for accurate threat detection
"""

import time
import logging
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple, Any
import re
import difflib

class RogueAPDetector:
    """
    Advanced Rogue AP detection using real-time network analysis
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.known_legitimate_networks = {}  # Whitelist of known good networks
        self.detected_rogues = {}  # Detected rogue APs
        self.evil_twins = {}  # Detected evil twin APs  
        self.suspicious_networks = {}  # Networks flagged for suspicious behavior
        self.network_history = defaultdict(list)  # Historical data for each BSSID
        self.ssid_patterns = {}  # Legitimate SSID patterns
        self.vendor_reputation = {}  # Vendor reputation scores
        
        # Detection thresholds and parameters
        self.evil_twin_similarity_threshold = 0.85  # SSID similarity for evil twin detection
        self.signal_anomaly_threshold = 20  # dBm difference that indicates anomaly
        self.channel_hop_threshold = 3  # Number of channel changes that's suspicious
        self.beacon_interval_threshold = 5  # Suspicious beacon interval changes
        self.min_observation_time = 60  # Minimum time to observe before flagging (seconds)
        
        # Initialize detection algorithms
        self._initialize_legitimate_patterns()
        self._initialize_vendor_reputation()
        
        self.logger.info("Rogue AP Detector initialized with advanced heuristics")
    
    def _initialize_legitimate_patterns(self):
        """Initialize patterns for legitimate network SSIDs"""
        self.legitimate_patterns = [
            # Common legitimate patterns
            r'^[A-Za-z0-9_-]+$',  # Basic alphanumeric
            r'^[A-Za-z0-9_-]+(?: [A-Za-z0-9_-]+)*$',  # With spaces
            r'^[A-Za-z]+ ?\d+\.?\d*[GHz]*$',  # ISP format (e.g., "Home 5G", "Office2.4")
            r'^[A-Za-z0-9]+-[A-Za-z0-9]+$',  # Hyphenated format
        ]
        
        # Common legitimate prefixes/suffixes
        self.legitimate_prefixes = [
            'Home', 'Office', 'Guest', 'WiFi', 'Network', 'Internet', 'Broadband',
            'Router', 'Modem', 'Connection', 'Wireless', 'Net'
        ]
        
        self.legitimate_suffixes = [
            '5G', '2.4G', '_5G', '_2.4G', '-5G', '-2.4G', 'Guest', 'Public'
        ]
    
    def _initialize_vendor_reputation(self):
        """Initialize vendor reputation scores (higher = more trustworthy)"""
        self.vendor_reputation = {
            # High reputation vendors
            'Apple': 9,
            'Cisco': 9,
            'Netgear': 8,
            'TP-Link': 8,
            'ASUS': 8,
            'Linksys': 8,
            'D-Link': 7,
            'Intel': 9,
            'Samsung': 8,
            'Broadcom': 8,
            
            # Medium reputation
            'Huawei': 6,  # Due to security concerns in some regions
            'ZTE': 6,
            'Xiaomi': 7,
            
            # Low reputation / Unknown
            'Unknown': 3,
            'Generic': 2,
        }
    
    def analyze_networks(self, networks: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze networks for rogue APs, evil twins, and suspicious behavior
        """
        analysis_results = {
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'total_networks_analyzed': len(networks),
            'rogue_aps_detected': [],
            'evil_twins_detected': [],
            'suspicious_networks': [],
            'security_recommendations': [],
            'threat_level': 'LOW',
            'analysis_summary': {}
        }
        
        try:
            self.logger.info(f"Analyzing {len(networks)} networks for rogue APs...")
            
            # Update network history
            self._update_network_history(networks)
            
            # Detect evil twin attacks
            evil_twins = self._detect_evil_twins(networks)
            analysis_results['evil_twins_detected'] = evil_twins
            
            # Detect rogue APs using multiple techniques
            rogue_aps = self._detect_rogue_aps(networks)
            analysis_results['rogue_aps_detected'] = rogue_aps
            
            # Detect suspicious behavior patterns
            suspicious = self._detect_suspicious_networks(networks)
            analysis_results['suspicious_networks'] = suspicious
            
            # Calculate overall threat level
            threat_level = self._calculate_threat_level(len(evil_twins), len(rogue_aps), len(suspicious))
            analysis_results['threat_level'] = threat_level
            
            # Generate security recommendations
            recommendations = self._generate_security_recommendations(evil_twins, rogue_aps, suspicious)
            analysis_results['security_recommendations'] = recommendations
            
            # Create analysis summary
            analysis_results['analysis_summary'] = {
                'evil_twins_count': len(evil_twins),
                'rogue_aps_count': len(rogue_aps),
                'suspicious_count': len(suspicious),
                'threat_level': threat_level,
                'high_risk_networks': len([n for n in evil_twins + rogue_aps if n.get('risk_score', 0) > 7]),
                'networks_with_weak_security': len([n for n in networks.values() if self._is_weak_security(n)]),
            }
            
            self.logger.info(f"Rogue AP analysis complete: {len(evil_twins)} evil twins, {len(rogue_aps)} rogues, {len(suspicious)} suspicious")
            
        except Exception as e:
            self.logger.error(f"Error in rogue AP analysis: {e}")
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    def _update_network_history(self, networks: Dict[str, Any]):
        """Update historical data for network behavior analysis"""
        current_time = time.time()
        
        for bssid, network in networks.items():
            history_entry = {
                'timestamp': current_time,
                'ssid': network.get('ssid'),
                'channel': network.get('channel'),
                'signal_strength': network.get('signal_strength'),
                'encryption': network.get('encryption'),
                'beacon_interval': network.get('beacon_interval'),
                'vendor': network.get('vendor')
            }
            
            self.network_history[bssid].append(history_entry)
            
            # Keep only recent history (last 24 hours)
            cutoff_time = current_time - (24 * 3600)
            self.network_history[bssid] = [
                entry for entry in self.network_history[bssid] 
                if entry['timestamp'] > cutoff_time
            ]
    
    def _detect_evil_twins(self, networks: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect evil twin attacks (same SSID, different BSSID)"""
        evil_twins = []
        ssid_to_networks = defaultdict(list)
        
        # Group networks by SSID
        for bssid, network in networks.items():
            ssid = network.get('ssid')
            if ssid and ssid.strip():  # Ignore hidden/empty SSIDs
                ssid_to_networks[ssid].append((bssid, network))
        
        # Look for SSIDs with multiple BSSIDs (potential evil twins)
        for ssid, network_list in ssid_to_networks.items():
            if len(network_list) > 1:
                # Analyze each pair for evil twin characteristics
                for i, (bssid1, net1) in enumerate(network_list):
                    for bssid2, net2 in network_list[i+1:]:
                        
                        # Check if this could be an evil twin
                        twin_analysis = self._analyze_potential_evil_twin(
                            bssid1, net1, bssid2, net2, ssid
                        )
                        
                        if twin_analysis['is_evil_twin']:
                            evil_twins.append(twin_analysis)
        
        return evil_twins
    
    def _analyze_potential_evil_twin(self, bssid1: str, net1: Dict, bssid2: str, net2: Dict, ssid: str) -> Dict[str, Any]:
        """Analyze two networks with same SSID for evil twin characteristics"""
        
        # Get vendor information
        vendor1 = self._get_vendor_from_bssid(bssid1)
        vendor2 = self._get_vendor_from_bssid(bssid2)
        
        # Calculate suspicion score
        suspicion_score = 0
        risk_factors = []
        
        # Factor 1: Different vendors (high suspicion)
        if vendor1 != vendor2 and vendor1 != 'Unknown' and vendor2 != 'Unknown':
            suspicion_score += 3
            risk_factors.append(f"Different vendors: {vendor1} vs {vendor2}")
        
        # Factor 2: Signal strength analysis
        signal1 = net1.get('signal_strength', -100)
        signal2 = net2.get('signal_strength', -100)
        signal_diff = abs(signal1 - signal2)
        
        if signal_diff > self.signal_anomaly_threshold:
            suspicion_score += 2
            risk_factors.append(f"Large signal difference: {signal_diff}dBm")
        
        # Factor 3: Channel analysis
        channel1 = net1.get('channel', 0)
        channel2 = net2.get('channel', 0)
        
        if abs(channel1 - channel2) <= 1 and channel1 != channel2:
            suspicion_score += 2
            risk_factors.append(f"Adjacent channels: {channel1} vs {channel2}")
        
        # Factor 4: Security type mismatch
        sec1 = net1.get('encryption', '').upper()
        sec2 = net2.get('encryption', '').upper()
        
        if sec1 != sec2:
            if ('OPEN' in sec1 or 'OPEN' in sec2) and ('WPA' in sec1 or 'WPA' in sec2):
                suspicion_score += 4  # Open network mimicking secure one
                risk_factors.append(f"Security mismatch: {sec1} vs {sec2}")
            else:
                suspicion_score += 1
                risk_factors.append(f"Different security: {sec1} vs {sec2}")
        
        # Factor 5: Vendor reputation
        rep1 = self.vendor_reputation.get(vendor1, 5)
        rep2 = self.vendor_reputation.get(vendor2, 5)
        
        if min(rep1, rep2) < 5:  # Low reputation vendor present
            suspicion_score += 1
            risk_factors.append(f"Low reputation vendor present")
        
        # Factor 6: Historical behavior (if available)
        history1 = self.network_history.get(bssid1, [])
        history2 = self.network_history.get(bssid2, [])
        
        if len(history1) < 3 and len(history2) >= 10:  # New network vs established
            suspicion_score += 2
            risk_factors.append("Newly appeared network mimicking established one")
        
        # Determine if this is an evil twin
        is_evil_twin = suspicion_score >= 5
        
        # Determine which one is likely the rogue
        if is_evil_twin:
            # The one with lower vendor reputation or newer appearance is likely rogue
            if rep1 < rep2 or len(history1) < len(history2):
                rogue_bssid, legitimate_bssid = bssid1, bssid2
                rogue_network, legitimate_network = net1, net2
            else:
                rogue_bssid, legitimate_bssid = bssid2, bssid1
                rogue_network, legitimate_network = net2, net1
        else:
            rogue_bssid = legitimate_bssid = None
            rogue_network = legitimate_network = None
        
        return {
            'is_evil_twin': is_evil_twin,
            'ssid': ssid,
            'suspicion_score': suspicion_score,
            'risk_score': min(suspicion_score * 1.5, 10),  # Scale to 10
            'risk_factors': risk_factors,
            'networks': {
                'network_1': {
                    'bssid': bssid1,
                    'vendor': vendor1,
                    'signal': signal1,
                    'channel': channel1,
                    'security': sec1,
                    'reputation': rep1
                },
                'network_2': {
                    'bssid': bssid2,
                    'vendor': vendor2,
                    'signal': signal2,
                    'channel': channel2,
                    'security': sec2,
                    'reputation': rep2
                }
            },
            'likely_rogue': rogue_bssid,
            'likely_legitimate': legitimate_bssid,
            'detection_timestamp': datetime.utcnow().isoformat(),
            'threat_type': 'evil_twin'
        }
    
    def _detect_rogue_aps(self, networks: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect rogue access points using various heuristics"""
        rogue_aps = []
        
        for bssid, network in networks.items():
            rogue_analysis = self._analyze_network_for_rogue_indicators(bssid, network)
            
            if rogue_analysis['is_rogue']:
                rogue_aps.append(rogue_analysis)
        
        return rogue_aps
    
    def _analyze_network_for_rogue_indicators(self, bssid: str, network: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single network for rogue AP indicators"""
        
        ssid = network.get('ssid', '')
        vendor = self._get_vendor_from_bssid(bssid)
        signal = network.get('signal_strength', -100)
        channel = network.get('channel', 0)
        encryption = network.get('encryption', '').upper()
        
        suspicion_score = 0
        risk_factors = []
        
        # Factor 1: Suspicious SSID patterns
        ssid_score, ssid_factors = self._analyze_ssid_suspicion(ssid)
        suspicion_score += ssid_score
        risk_factors.extend(ssid_factors)
        
        # Factor 2: Vendor reputation
        vendor_rep = self.vendor_reputation.get(vendor, 5)
        if vendor_rep < 4:
            suspicion_score += 2
            risk_factors.append(f"Low reputation vendor: {vendor}")
        
        # Factor 3: Security analysis
        security_score, security_factors = self._analyze_security_suspicion(encryption, ssid)
        suspicion_score += security_score
        risk_factors.extend(security_factors)
        
        # Factor 4: Channel analysis
        if self._is_suspicious_channel(channel):
            suspicion_score += 1
            risk_factors.append(f"Uncommon channel: {channel}")
        
        # Factor 5: Signal strength analysis
        if signal > -30:  # Extremely strong signal (too close or amplified)
            suspicion_score += 1
            risk_factors.append(f"Unusually strong signal: {signal}dBm")
        
        # Factor 6: Historical behavior analysis
        history_score, history_factors = self._analyze_historical_behavior(bssid)
        suspicion_score += history_score
        risk_factors.extend(history_factors)
        
        # Factor 7: MAC address analysis
        mac_score, mac_factors = self._analyze_mac_address_suspicion(bssid)
        suspicion_score += mac_score
        risk_factors.extend(mac_factors)
        
        # Determine if this is a rogue AP
        is_rogue = suspicion_score >= 4
        
        return {
            'is_rogue': is_rogue,
            'bssid': bssid,
            'ssid': ssid,
            'vendor': vendor,
            'suspicion_score': suspicion_score,
            'risk_score': min(suspicion_score * 1.2, 10),
            'risk_factors': risk_factors,
            'network_details': {
                'signal_strength': signal,
                'channel': channel,
                'encryption': encryption,
                'vendor_reputation': vendor_rep
            },
            'detection_timestamp': datetime.utcnow().isoformat(),
            'threat_type': 'rogue_ap'
        }
    
    def _analyze_ssid_suspicion(self, ssid: str) -> Tuple[int, List[str]]:
        """Analyze SSID for suspicious patterns"""
        score = 0
        factors = []
        
        if not ssid or not ssid.strip():
            return 0, []  # Hidden networks handled separately
        
        # Check for common attack SSIDs
        suspicious_ssids = [
            'Free WiFi', 'Public WiFi', 'Free Internet', 'Guest Network',
            'Hotel WiFi', 'Airport WiFi', 'Coffee Shop', 'Restaurant WiFi',
            'Public', 'Open', 'Internet', 'WiFi', 'Hotspot'
        ]
        
        if ssid in suspicious_ssids:
            score += 3
            factors.append(f"Generic/suspicious SSID: {ssid}")
        
        # Check for typosquatting of popular brands
        popular_brands = [
            'Starbucks', 'McDonalds', 'Google', 'Apple', 'Microsoft',
            'Amazon', 'Facebook', 'Twitter', 'Instagram', 'Netflix'
        ]
        
        for brand in popular_brands:
            if difflib.SequenceMatcher(None, ssid.lower(), brand.lower()).ratio() > 0.8:
                if ssid.lower() != brand.lower():
                    score += 4
                    factors.append(f"Possible typosquatting of {brand}")
        
        # Check for unusual characters
        if re.search(r'[^\w\s\-_\.]', ssid):
            score += 1
            factors.append("Contains unusual characters")
        
        # Check for misleading technical terms
        tech_terms = ['5G', 'LTE', 'Fiber', 'Broadband', 'High-Speed']
        if any(term in ssid for term in tech_terms) and len(ssid) < 15:
            score += 1
            factors.append("Misleading technical terms in short SSID")
        
        return score, factors
    
    def _analyze_security_suspicion(self, encryption: str, ssid: str) -> Tuple[int, List[str]]:
        """Analyze security configuration for suspicious patterns"""
        score = 0
        factors = []
        
        # Open networks are always suspicious unless explicitly expected
        if 'OPEN' in encryption or not encryption:
            score += 2
            factors.append("Open network (no encryption)")
        
        # WEP is outdated and suspicious
        if 'WEP' in encryption:
            score += 3
            factors.append("Uses outdated WEP encryption")
        
        # Check for security downgrade tricks
        if 'WPA' in encryption and 'WPA2' not in encryption and 'WPA3' not in encryption:
            score += 1
            factors.append("Uses older WPA (not WPA2/WPA3)")
        
        return score, factors
    
    def _is_suspicious_channel(self, channel: int) -> bool:
        """Check if channel is suspicious"""
        # Most legitimate networks use common channels
        common_channels_2_4 = [1, 6, 11]  # Non-overlapping 2.4GHz
        common_channels_5 = [36, 40, 44, 48, 149, 153, 157, 161]  # Common 5GHz
        
        if channel in common_channels_2_4 or channel in common_channels_5:
            return False
        
        # Channels outside normal ranges
        if channel > 165 or channel < 1:
            return True
        
        # Less common channels might be suspicious in some contexts
        return False
    
    def _analyze_historical_behavior(self, bssid: str) -> Tuple[int, List[str]]:
        """Analyze historical behavior for suspicious patterns"""
        score = 0
        factors = []
        
        history = self.network_history.get(bssid, [])
        
        if len(history) < 2:
            return 0, []  # Not enough data
        
        # Check for frequent channel hopping
        channels = [entry.get('channel') for entry in history if entry.get('channel')]
        unique_channels = len(set(channels))
        
        if unique_channels > self.channel_hop_threshold and len(history) < 20:
            score += 2
            factors.append(f"Frequent channel hopping ({unique_channels} channels)")
        
        # Check for SSID changes (very suspicious)
        ssids = [entry.get('ssid') for entry in history if entry.get('ssid')]
        unique_ssids = len(set(ssids))
        
        if unique_ssids > 1:
            score += 4
            factors.append(f"SSID changed {unique_ssids} times")
        
        # Check for security type changes
        encryptions = [entry.get('encryption') for entry in history if entry.get('encryption')]
        unique_encryptions = len(set(encryptions))
        
        if unique_encryptions > 1:
            score += 2
            factors.append(f"Encryption type changed")
        
        return score, factors
    
    def _analyze_mac_address_suspicion(self, bssid: str) -> Tuple[int, List[str]]:
        """Analyze MAC address for suspicious patterns"""
        score = 0
        factors = []
        
        # Check for locally administered MAC (2nd bit of first octet set)
        try:
            first_octet = int(bssid.split(':')[0], 16)
            if first_octet & 0x02:  # Locally administered bit
                score += 1
                factors.append("Uses locally administered MAC address")
        except:
            pass
        
        # Check for sequential MAC addresses (indication of virtual APs)
        if hasattr(self, '_last_analyzed_mac'):
            try:
                current_mac_int = int(bssid.replace(':', ''), 16)
                last_mac_int = int(self._last_analyzed_mac.replace(':', ''), 16)
                if abs(current_mac_int - last_mac_int) < 16:  # Very close MAC addresses
                    score += 1
                    factors.append("MAC address very close to recently seen AP")
            except:
                pass
        
        self._last_analyzed_mac = bssid
        
        return score, factors
    
    def _detect_suspicious_networks(self, networks: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect networks with suspicious behavior patterns"""
        suspicious = []
        
        for bssid, network in networks.items():
            suspicion_analysis = self._analyze_network_suspicion(bssid, network)
            
            if suspicion_analysis['is_suspicious']:
                suspicious.append(suspicion_analysis)
        
        return suspicious
    
    def _analyze_network_suspicion(self, bssid: str, network: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network for general suspicious behavior"""
        
        ssid = network.get('ssid', '')
        signal = network.get('signal_strength', -100)
        encryption = network.get('encryption', '')
        
        suspicion_factors = []
        
        # Hidden networks can be suspicious in some contexts
        if not ssid or not ssid.strip():
            suspicion_factors.append("Hidden SSID")
        
        # Very strong signal might indicate close proximity attack
        if signal > -25:
            suspicion_factors.append(f"Extremely strong signal: {signal}dBm")
        
        # Check for weak security
        if self._is_weak_security(network):
            suspicion_factors.append("Weak or no security")
        
        # Check for unusual beacon intervals if available
        beacon_interval = network.get('beacon_interval')
        if beacon_interval and (beacon_interval < 50 or beacon_interval > 300):
            suspicion_factors.append(f"Unusual beacon interval: {beacon_interval}ms")
        
        is_suspicious = len(suspicion_factors) >= 2
        
        return {
            'is_suspicious': is_suspicious,
            'bssid': bssid,
            'ssid': ssid or '(Hidden)',
            'suspicion_factors': suspicion_factors,
            'risk_score': len(suspicion_factors) * 2,
            'network_details': network,
            'detection_timestamp': datetime.utcnow().isoformat(),
            'threat_type': 'suspicious_behavior'
        }
    
    def _is_weak_security(self, network: Dict[str, Any]) -> bool:
        """Check if network has weak security"""
        encryption = network.get('encryption', '').upper()
        return 'OPEN' in encryption or 'WEP' in encryption or not encryption
    
    def _calculate_threat_level(self, evil_twins_count: int, rogue_aps_count: int, suspicious_count: int) -> str:
        """Calculate overall threat level"""
        
        if evil_twins_count > 0 or rogue_aps_count > 2:
            return 'CRITICAL'
        elif rogue_aps_count > 0 or suspicious_count > 3:
            return 'HIGH'
        elif suspicious_count > 1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_security_recommendations(self, evil_twins: List, rogue_aps: List, suspicious: List) -> List[str]:
        """Generate security recommendations based on detected threats"""
        recommendations = []
        
        if evil_twins:
            recommendations.append("🚨 CRITICAL: Evil twin networks detected. Verify network authenticity before connecting.")
            recommendations.append("📱 Use WPA3 networks only and verify network certificates when possible.")
        
        if rogue_aps:
            recommendations.append("⚠️ Rogue access points detected. Avoid connecting to unknown networks.")
            recommendations.append("🔒 Use VPN when connecting to public or untrusted networks.")
        
        if suspicious:
            recommendations.append("🔍 Suspicious network activity detected. Monitor your environment regularly.")
        
        if len(evil_twins) + len(rogue_aps) + len(suspicious) == 0:
            recommendations.append("✅ No immediate threats detected. Continue monitoring.")
        
        # General recommendations
        recommendations.append("🛡️ Keep your devices updated and use strong, unique passwords.")
        recommendations.append("📡 Disable auto-connect for WiFi networks to prevent automatic connections to rogues.")
        recommendations.append("🔐 Use enterprise-grade security (WPA3-Enterprise) in business environments.")
        
        return recommendations
    
    def _get_vendor_from_bssid(self, bssid: str) -> str:
        """Get vendor from BSSID (would integrate with OUI database)"""
        # This would integrate with the vendor lookup function from routes.py
        try:
            from app.passive_monitor.routes import _get_vendor_from_mac
            return _get_vendor_from_mac(bssid)
        except ImportError:
            return 'Unknown'
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection statistics and system status"""
        return {
            'total_rogues_detected': len(self.detected_rogues),
            'total_evil_twins_detected': len(self.evil_twins),
            'total_suspicious_networks': len(self.suspicious_networks),
            'known_legitimate_networks': len(self.known_legitimate_networks),
            'detection_algorithms_active': [
                'evil_twin_detection',
                'rogue_ap_heuristics',
                'suspicious_behavior_analysis',
                'vendor_reputation_analysis',
                'historical_behavior_tracking'
            ],
            'last_analysis': datetime.utcnow().isoformat()
        }

# Export main class
__all__ = ['RogueAPDetector']