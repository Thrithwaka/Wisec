#!/usr/bin/env python3
"""
Test Real-time Beacon Frame Analysis
This script tests the real WiFi network scanning functionality
"""

import time
import sys
import os
import json
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Import our modules
from app.wifi_core.real_packet_capture import RealPacketCapture
from app.passive_monitor.routes import _get_vendor_from_mac, _get_vendor_description

def test_real_network_scanning():
    """Test real network scanning capabilities"""
    print("=" * 60)
    print("🔍 TESTING REAL-TIME BEACON FRAME ANALYSIS")
    print("=" * 60)
    
    # Initialize the packet capture system
    capture = RealPacketCapture()
    
    print(f"📡 System: {capture.logger.name}")
    print(f"🔧 Lab mode enabled: {capture.lab_mode_enabled}")
    print(f"🌐 Scapy available: {capture.logger}")
    
    print("\n1️⃣ Testing available network interfaces...")
    interfaces = capture.get_available_interfaces()
    print(f"   Found {len(interfaces)} interfaces:")
    for iface in interfaces:
        print(f"   - {iface['name']} ({iface['type']}) - {iface['status']}")
    
    print("\n2️⃣ Testing system network discovery...")
    networks = capture._get_system_networks()
    print(f"   Discovered {len(networks)} networks:")
    
    if networks:
        for i, network in enumerate(networks[:5], 1):  # Show first 5 networks
            ssid = network.get('ssid', 'Hidden')
            bssid = network.get('bssid', 'Unknown')
            encryption = network.get('encryption', 'Unknown')
            signal = network.get('signal_strength', 'Unknown')
            vendor = _get_vendor_from_mac(bssid) if bssid != 'Unknown' else 'Unknown'
            
            print(f"   {i}. SSID: {ssid}")
            print(f"      BSSID: {bssid}")
            print(f"      Security: {encryption}")
            print(f"      Signal: {signal} dBm")
            print(f"      Vendor: {vendor}")
            print()
    else:
        print("   ❌ No networks found - this might be normal if:")
        print("      - No WiFi adapter is available")
        print("      - System permissions are insufficient")
        print("      - No WiFi networks are in range")
    
    print("\n3️⃣ Testing vendor identification...")
    test_macs = [
        "00:25:9c:12:34:56",  # Apple
        "00:16:32:ab:cd:ef",  # Samsung
        "00:02:b3:11:22:33",  # Intel
        "00:11:22:44:55:66",  # TP-Link
        "ff:ff:ff:00:00:00"   # Unknown
    ]
    
    for mac in test_macs:
        vendor = _get_vendor_from_mac(mac)
        description = _get_vendor_description(vendor)
        print(f"   MAC: {mac} -> {vendor} ({description})")
    
    print("\n4️⃣ Testing simulated capture session...")
    print("   Starting 15-second capture test...")
    
    try:
        # Start a short capture session
        result = capture.start_capture(
            interface='auto',
            duration=15,
            user_id='test_user'
        )
        
        print(f"   Capture started: {result.get('success', False)}")
        print(f"   Interface: {result.get('interface', 'Unknown')}")
        
        # Wait a few seconds and check status
        time.sleep(3)
        status = capture.get_capture_status()
        print(f"   Networks detected: {status.get('networks_detected', 0)}")
        print(f"   Packets captured: {status.get('packets_captured', 0)}")
        print(f"   Threats detected: {status.get('threats_detected', 0)}")
        
        # Wait for completion
        print("   Waiting for capture to complete...")
        time.sleep(12)
        
        # Check final results
        final_status = capture.get_capture_status()
        print(f"   Final networks: {final_status.get('networks_detected', 0)}")
        print(f"   Final packets: {final_status.get('packets_captured', 0)}")
        
        # Stop capture if still running
        if final_status.get('is_capturing', False):
            stop_result = capture.stop_capture()
            print(f"   Stopped: {stop_result.get('success', False)}")
        
        # Show discovered networks
        if capture.networks:
            print(f"\n   📊 DISCOVERED NETWORKS ({len(capture.networks)}):")
            for bssid, network in list(capture.networks.items())[:3]:  # Show first 3
                print(f"   - SSID: {network.get('ssid', 'Hidden')}")
                print(f"     BSSID: {bssid}")
                print(f"     Security: {network.get('encryption', 'Unknown')}")
                print(f"     Signal: {network.get('signal_strength', 'Unknown')}")
                print(f"     Vendor: {_get_vendor_from_mac(bssid)}")
                print(f"     First seen: {datetime.fromtimestamp(network.get('first_seen', 0)).strftime('%H:%M:%S')}")
                print()
        
    except Exception as e:
        print(f"   ❌ Capture test failed: {e}")
    
    print("\n" + "=" * 60)
    print("✅ REAL-TIME BEACON ANALYSIS TEST COMPLETE")
    print("=" * 60)
    print("\n💡 INSTRUCTIONS FOR USERS:")
    print("1. Start your Flask application: python app.py")
    print("2. Go to: http://localhost:5000/passive-monitor/beacon-analysis")
    print("3. Click 'Start Analysis' to begin real-time scanning")
    print("4. The system will now show REAL WiFi networks instead of dummy data!")
    print("\n🔧 If you see 'No networks found':")
    print("- Ensure WiFi is enabled on your system")
    print("- Try running as administrator (Windows) or with sudo (Linux)")
    print("- Check that your system has WiFi scanning capabilities")

if __name__ == "__main__":
    test_real_network_scanning()