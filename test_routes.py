#!/usr/bin/env python3
"""
Simple route testing script to verify our endpoints are working
"""

import requests
import json
from datetime import datetime

# Test URLs
BASE_URL = "http://127.0.0.1:5000"
ENDPOINTS = [
    "/admin/test",  # Simple test route without auth
    "/admin/routes-test",  # Test route from main routes file
    "/admin/users/count",
    "/admin/system-health", 
    "/api/model/health",
    "/api/scans/stats"
]

def test_endpoint(url):
    """Test a single endpoint"""
    try:
        print(f"\n[TEST] Testing: {url}")
        response = requests.get(f"{BASE_URL}{url}", timeout=5)
        
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"   Response: {json.dumps(data, indent=2)[:200]}...")
            except:
                print(f"   Response: {response.text[:200]}...")
        else:
            print(f"   Error: {response.text[:200]}")
            
    except requests.exceptions.RequestException as e:
        print(f"   Connection Error: {e}")
    except Exception as e:
        print(f"   Error: {e}")

def main():
    print(f"[INFO] Testing Flask endpoints at {BASE_URL}")
    print(f"[INFO] Test time: {datetime.now()}")
    
    # Test health check first
    print(f"\n[TEST] Testing health check: /health")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   [OK] Server is running")
        else:
            print("   [ERROR] Server health check failed")
    except Exception as e:
        print(f"   [ERROR] Cannot connect to server: {e}")
        print("   Make sure the Flask server is running on port 5000")
        return
    
    # Test our specific endpoints
    for endpoint in ENDPOINTS:
        test_endpoint(endpoint)
    
    print("\n[SUMMARY] Test Summary:")
    print("   If endpoints return 404, they may not be properly registered")
    print("   If endpoints return 500, there may be code errors")
    print("   If endpoints return 403, authentication may be required")

if __name__ == "__main__":
    main()