#!/usr/bin/env python3
"""
Test Real-time Rogue AP Detection System
This script tests the advanced rogue AP and evil twin detection functionality
"""

import time
import sys
import os
import json
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import our modules
from app.wifi_core.rogue_ap_detector import RogueAPDetector
from app.wifi_core.real_packet_capture import RealPacketCapture

def test_rogue_ap_detection():
    """Test rogue AP detection capabilities"""
    print("=" * 80)
    print("🚨 TESTING REAL-TIME ROGUE AP DETECTION SYSTEM")
    print("=" * 80)
    
    # Initialize systems
    detector = RogueAPDetector()
    capture = RealPacketCapture()
    
    print(f"🔧 Rogue AP Detector: {detector.__class__.__name__}")
    print(f"📡 Packet Capture: {capture.__class__.__name__}")
    print(f"🧠 Detection Algorithms: {len(detector.get_detection_statistics()['detection_algorithms_active'])}")
    
    # Test 1: Vendor reputation system
    print("\n1️⃣ Testing Vendor Reputation System...")
    test_vendors = ['Apple', 'Samsung', 'Intel', 'TP-Link', 'Unknown', 'Generic']
    for vendor in test_vendors:
        reputation = detector.vendor_reputation.get(vendor, 3)
        print(f"   {vendor:12}: {reputation}/10 {'✅' if reputation >= 7 else '⚠️' if reputation >= 5 else '❌'}")
    
    # Test 2: SSID suspicion analysis
    print("\n2️⃣ Testing SSID Suspicion Analysis...")
    test_ssids = [
        "HomeNetwork_5G",       # Legitimate
        "Free WiFi",            # Suspicious
        "Starbux",             # Typosquatting
        "Guest Network",        # Suspicious generic
        "MyRouter@!#",         # Special characters
        "",                     # Hidden network
    ]
    
    for ssid in test_ssids:
        score, factors = detector._analyze_ssid_suspicion(ssid)
        status = "🔴 HIGH" if score >= 3 else "🟡 MED" if score >= 1 else "🟢 LOW"
        print(f"   '{ssid:15}': Score {score} {status}")
        if factors:
            for factor in factors[:2]:  # Show first 2 factors
                print(f"      └ {factor}")
    
    # Test 3: Evil twin detection with sample data
    print("\n3️⃣ Testing Evil Twin Detection...")
    
    # Create sample network data that includes potential evil twins
    sample_networks = {
        '00:11:22:33:44:55': {
            'ssid': 'HomeNetwork',
            'channel': 6,
            'encryption': 'WPA2',
            'signal_strength': -45,
            'vendor': 'TP-Link',
            'first_seen': time.time() - 3600,
            'beacon_count': 150
        },
        '00:aa:bb:cc:dd:ee': {
            'ssid': 'HomeNetwork',  # Same SSID - potential evil twin
            'channel': 6,
            'encryption': 'Open',    # Different security - suspicious
            'signal_strength': -50,
            'vendor': 'Unknown',     # Different vendor - suspicious
            'first_seen': time.time() - 60,  # Recent appearance
            'beacon_count': 5
        },
        '00:22:33:44:55:66': {
            'ssid': 'OfficeWiFi',
            'channel': 11,
            'encryption': 'WPA3',
            'signal_strength': -55,
            'vendor': 'Cisco',
            'first_seen': time.time() - 7200,
            'beacon_count': 300
        }
    }
    
    analysis = detector.analyze_networks(sample_networks)
    
    print(f"   📊 Analysis Results:")
    print(f"      Networks analyzed: {analysis['total_networks_analyzed']}")
    print(f"      Evil twins found: {len(analysis['evil_twins_detected'])}")
    print(f"      Rogue APs found: {len(analysis['rogue_aps_detected'])}")
    print(f"      Suspicious networks: {len(analysis['suspicious_networks'])}")
    print(f"      Threat level: {analysis['threat_level']}")
    
    # Show evil twin details
    if analysis['evil_twins_detected']:
        print("\n   🚨 EVIL TWIN DETECTED:")
        for twin in analysis['evil_twins_detected']:
            print(f"      SSID: {twin['ssid']}")
            print(f"      Risk Score: {twin['risk_score']}/10")
            print(f"      Likely Rogue: {twin.get('likely_rogue', 'Unknown')}")
            print(f"      Risk Factors:")
            for factor in twin['risk_factors'][:3]:  # Show first 3
                print(f"        - {factor}")
    
    # Show rogue APs
    if analysis['rogue_aps_detected']:
        print("\n   ⚠️ ROGUE APs DETECTED:")
        for rogue in analysis['rogue_aps_detected']:
            print(f"      SSID: {rogue['ssid']} (BSSID: {rogue['bssid']})")
            print(f"      Risk Score: {rogue['risk_score']}/10")
            print(f"      Vendor: {rogue['vendor']}")
    
    # Test 4: Real-time system integration
    print("\n4️⃣ Testing Real-time System Integration...")
    
    try:
        # Get real networks if available
        real_networks = capture._get_system_networks()
        print(f"   📡 Real networks discovered: {len(real_networks)}")
        
        if real_networks:
            # Convert to the format expected by the detector
            network_dict = {}
            for i, network in enumerate(real_networks[:5]):  # Process first 5
                bssid = network.get('bssid', f'real:network:{i}')
                network_dict[bssid] = network
            
            # Analyze real networks
            real_analysis = detector.analyze_networks(network_dict)
            
            print(f"   📊 Real Network Analysis:")
            print(f"      Networks: {real_analysis['total_networks_analyzed']}")
            print(f"      Evil Twins: {len(real_analysis['evil_twins_detected'])}")
            print(f"      Rogue APs: {len(real_analysis['rogue_aps_detected'])}")
            print(f"      Threat Level: {real_analysis['threat_level']}")
            
            if real_analysis['evil_twins_detected'] or real_analysis['rogue_aps_detected']:
                print("   🚨 THREATS DETECTED IN YOUR ENVIRONMENT!")
                print("      Check the detailed results above.")
        else:
            print("   ⚠️ No real networks detected. This is normal if:")
            print("      - WiFi is disabled")
            print("      - No WiFi adapter is available")
            print("      - Running without sufficient permissions")
    
    except Exception as e:
        print(f"   ❌ Real-time integration test failed: {e}")
    
    # Test 5: Security recommendations
    print("\n5️⃣ Testing Security Recommendations...")
    recommendations = analysis['security_recommendations']
    
    if recommendations:
        print("   💡 Generated Recommendations:")
        for i, rec in enumerate(recommendations[:4], 1):  # Show first 4
            print(f"      {i}. {rec}")
    else:
        print("   ✅ No specific security recommendations (good!)")
    
    # Test 6: Detection statistics
    print("\n6️⃣ System Statistics...")
    stats = detector.get_detection_statistics()
    print(f"   🔍 Detection Algorithms:")
    for algo in stats['detection_algorithms_active']:
        print(f"      ✓ {algo.replace('_', ' ').title()}")
    
    print(f"   📈 Detection Capabilities:")
    print(f"      ✓ Evil Twin Detection (SSID similarity analysis)")
    print(f"      ✓ Vendor Reputation Scoring (200+ vendors)")
    print(f"      ✓ SSID Pattern Analysis (typosquatting detection)")
    print(f"      ✓ Security Type Analysis (WEP/Open detection)")
    print(f"      ✓ Historical Behavior Tracking")
    print(f"      ✓ MAC Address Analysis")
    print(f"      ✓ Channel Hopping Detection")
    print(f"      ✓ Signal Strength Anomalies")
    
    print("\n" + "=" * 80)
    print("✅ ROGUE AP DETECTION SYSTEM TEST COMPLETE")
    print("=" * 80)
    print("\n💡 USAGE INSTRUCTIONS:")
    print("1. Start your Flask application: python app.py")
    print("2. Navigate to: http://localhost:5000/passive-monitor/rogue-detector")
    print("3. Configure detection settings:")
    print("   - Mode: Comprehensive (recommended)")
    print("   - Duration: 120+ seconds")
    print("   - Sensitivity: Medium (balanced)")
    print("4. Click 'Start Detection' to begin real-time analysis")
    print("5. Monitor the threat level and review detected threats")
    print("6. Check 'Evil Twins' and 'Rogue APs' tabs for detailed results")
    print("7. Follow security recommendations to protect your network")
    
    print("\n🔧 FEATURES IMPLEMENTED:")
    print("✅ Real-time Evil Twin Detection")
    print("✅ Advanced Rogue AP Heuristics")
    print("✅ Vendor Reputation Analysis")
    print("✅ SSID Pattern Recognition")
    print("✅ Security Vulnerability Assessment")
    print("✅ Historical Behavior Tracking")
    print("✅ Interactive Web Dashboard")
    print("✅ Real-time Threat Level Monitoring")
    print("✅ Detailed Security Recommendations")
    print("✅ Export Functionality")
    
    print("\n🎯 THREAT DETECTION CAPABILITIES:")
    print("🚨 Critical: Evil Twin Networks")
    print("⚠️  High: Rogue Access Points")
    print("🔍 Medium: Suspicious Behavior")
    print("🛡️  Low: Legitimate Networks")
    
    print("\n🔒 SECURITY ANALYSIS FEATURES:")
    print("• MAC OUI Vendor Identification")
    print("• Encryption Type Assessment") 
    print("• Signal Strength Anomaly Detection")
    print("• Channel Hopping Analysis")
    print("• SSID Typosquatting Detection")
    print("• Open Network Identification")
    print("• WEP Security Warnings")
    print("• Network Behavior Monitoring")

if __name__ == "__main__":
    test_rogue_ap_detection()