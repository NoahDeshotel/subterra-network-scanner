#!/usr/bin/env python3
"""Test backend API endpoints"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_api_endpoints():
    """Test all API endpoints"""
    
    print("Testing Backend API Endpoints")
    print("=" * 50)
    
    # Test status endpoint
    print("\n1. Testing /api/status")
    try:
        response = requests.get(f"{BASE_URL}/api/status")
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)[:200]}...")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Test scanner capabilities
    print("\n2. Testing /api/scanners/available")
    try:
        response = requests.get(f"{BASE_URL}/api/scanners/available")
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Available Scanners: {list(data.get('available_scanners', {}).keys())}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Test scan start
    print("\n3. Testing /api/scan/start")
    try:
        scan_config = {
            "subnet": "192.168.1.0/30",  # Small subnet for testing
            "scanner_type": "simple",
            "deep_scan": False,
            "topology_discovery": False
        }
        response = requests.post(
            f"{BASE_URL}/api/scan/start",
            json=scan_config,
            headers={"Content-Type": "application/json"}
        )
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Response: {json.dumps(data, indent=2)}")
            scan_id = data.get('scan_id')
            
            if scan_id:
                # Wait a moment for scan to start
                time.sleep(2)
                
                # Test scan status endpoint
                print(f"\n4. Testing /api/scan/{scan_id}/status")
                status_response = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
                print(f"   Status Code: {status_response.status_code}")
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    progress = status_data.get('progress', {})
                    print(f"   Scan Stage: {progress.get('stage')}")
                    print(f"   Progress: {progress.get('percentage', 0):.1f}%")
                    print(f"   Current Step: {progress.get('current_step')}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Test devices endpoint
    print("\n5. Testing /api/devices")
    try:
        response = requests.get(f"{BASE_URL}/api/devices")
        print(f"   Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   Total Devices: {len(data.get('devices', []))}")
        else:
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"   Failed: {e}")
    
    print("\n" + "=" * 50)
    print("API Testing Complete")

if __name__ == "__main__":
    test_api_endpoints()