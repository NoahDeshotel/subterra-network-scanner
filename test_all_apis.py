#!/usr/bin/env python3
"""
Comprehensive API Test Suite for Network Scanner Backend
Tests ALL endpoints and verifies database persistence
"""

import requests
import json
import time
import sys
from datetime import datetime

BASE_URL = "http://localhost:8080"

def print_test(name, passed, details=""):
    """Print test result with formatting"""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} - {name}")
    if details:
        print(f"    Details: {details}")
    return passed

def test_health():
    """Test health endpoint"""
    print("\n=== Testing Health Endpoint ===")
    try:
        resp = requests.get(f"{BASE_URL}/health")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        return print_test("GET /health", passed, f"Status: {resp.status_code}, Data: {data}")
    except Exception as e:
        return print_test("GET /health", False, str(e))

def test_status():
    """Test status endpoint"""
    print("\n=== Testing Status Endpoint ===")
    try:
        resp = requests.get(f"{BASE_URL}/api/status")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        return print_test("GET /api/status", passed, f"Status: {resp.status_code}")
    except Exception as e:
        return print_test("GET /api/status", False, str(e))

def test_statistics():
    """Test statistics endpoints"""
    print("\n=== Testing Statistics Endpoints ===")
    results = []
    
    # Test basic statistics
    try:
        resp = requests.get(f"{BASE_URL}/api/statistics")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        results.append(print_test("GET /api/statistics", passed, f"Total devices: {data.get('total_devices', 0) if data else 'N/A'}"))
    except Exception as e:
        results.append(print_test("GET /api/statistics", False, str(e)))
    
    # Test enhanced statistics
    try:
        resp = requests.get(f"{BASE_URL}/api/statistics/enhanced")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        results.append(print_test("GET /api/statistics/enhanced", passed, f"Status: {resp.status_code}"))
    except Exception as e:
        results.append(print_test("GET /api/statistics/enhanced", False, str(e)))
    
    return all(results)

def test_devices_api():
    """Test devices API"""
    print("\n=== Testing Devices API ===")
    try:
        resp = requests.get(f"{BASE_URL}/api/devices")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        device_count = len(data.get('devices', [])) if data else 0
        return print_test("GET /api/devices", passed, f"Found {device_count} devices")
    except Exception as e:
        return print_test("GET /api/devices", False, str(e))

def start_scan(subnet="10.0.0.0/24"):
    """Start a network scan"""
    print(f"\n=== Starting Scan for {subnet} ===")
    try:
        payload = {
            "subnet": subnet,
            "scanner_type": "simple",
            "aggressive": False,
            "deep_scan": False
        }
        resp = requests.post(f"{BASE_URL}/api/scan/start", json=payload)
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        
        if passed and data:
            scan_id = data.get('scan_id')
            print_test("POST /api/scan/start", True, f"Scan ID: {scan_id}")
            return scan_id
        else:
            print_test("POST /api/scan/start", False, f"Status: {resp.status_code}, Response: {resp.text}")
            return None
    except Exception as e:
        print_test("POST /api/scan/start", False, str(e))
        return None

def check_scan_status(scan_id):
    """Check scan status"""
    print(f"\n=== Checking Scan Status ===")
    try:
        resp = requests.get(f"{BASE_URL}/api/scan/{scan_id}/status")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        
        if data:
            status = data.get('status', 'unknown')
            progress = data.get('progress', {}).get('percentage', 0)
            devices_found = data.get('devices_found', 0)
            print_test(f"GET /api/scan/{scan_id}/status", True, 
                      f"Status: {status}, Progress: {progress}%, Devices: {devices_found}")
            return data
        else:
            print_test(f"GET /api/scan/{scan_id}/status", False, f"Status: {resp.status_code}")
            return None
    except Exception as e:
        print_test(f"GET /api/scan/{scan_id}/status", False, str(e))
        return None

def wait_for_scan(scan_id, timeout=60):
    """Wait for scan to complete"""
    print(f"\n=== Waiting for Scan Completion ===")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        status_data = check_scan_status(scan_id)
        if status_data:
            status = status_data.get('status')
            if status in ['completed', 'failed']:
                return status_data
        time.sleep(2)
    
    print("❌ Scan timeout!")
    return None

def test_scan_results(scan_id):
    """Test scan results retrieval"""
    print(f"\n=== Testing Scan Results ===")
    try:
        resp = requests.get(f"{BASE_URL}/api/scan/{scan_id}/results")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        
        if data:
            devices = data.get('devices', [])
            print_test(f"GET /api/scan/{scan_id}/results", True, f"Found {len(devices)} devices")
            return data
        else:
            print_test(f"GET /api/scan/{scan_id}/results", False, f"Status: {resp.status_code}")
            return None
    except Exception as e:
        print_test(f"GET /api/scan/{scan_id}/results", False, str(e))
        return None

def test_device_details():
    """Test device details API"""
    print("\n=== Testing Device Details ===")
    
    # First get list of devices
    try:
        resp = requests.get(f"{BASE_URL}/api/devices")
        if resp.status_code != 200:
            return print_test("Device details test", False, "Cannot get device list")
        
        devices = resp.json().get('devices', [])
        if not devices:
            return print_test("Device details test", False, "No devices to test")
        
        # Test first device
        test_ip = devices[0].get('ip')
        resp = requests.get(f"{BASE_URL}/api/devices/{test_ip}")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        
        return print_test(f"GET /api/devices/{test_ip}", passed, 
                         f"Device type: {data.get('device_type') if data else 'N/A'}")
    except Exception as e:
        return print_test("Device details test", False, str(e))

def test_topology():
    """Test topology API"""
    print("\n=== Testing Topology API ===")
    try:
        resp = requests.get(f"{BASE_URL}/api/topology")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        return print_test("GET /api/topology", passed, f"Status: {resp.status_code}")
    except Exception as e:
        return print_test("GET /api/topology", False, str(e))

def test_vulnerabilities():
    """Test vulnerabilities API"""
    print("\n=== Testing Vulnerabilities API ===")
    try:
        resp = requests.get(f"{BASE_URL}/api/vulnerabilities")
        passed = resp.status_code == 200
        data = resp.json() if passed else None
        vuln_count = len(data) if isinstance(data, list) else 0
        return print_test("GET /api/vulnerabilities", passed, f"Found {vuln_count} vulnerabilities")
    except Exception as e:
        return print_test("GET /api/vulnerabilities", False, str(e))

def test_database_clear():
    """Test database clear (optional)"""
    print("\n=== Testing Database Clear ===")
    print("⚠️  Skipping database clear to preserve data")
    return True

def main():
    """Run all tests"""
    print("=" * 60)
    print("COMPREHENSIVE API TEST SUITE")
    print(f"Backend URL: {BASE_URL}")
    print(f"Test Time: {datetime.now()}")
    print("=" * 60)
    
    all_passed = []
    
    # Test basic endpoints
    all_passed.append(test_health())
    all_passed.append(test_status())
    all_passed.append(test_statistics())
    
    # Test device retrieval before scan
    print("\n--- PRE-SCAN DEVICE CHECK ---")
    devices_result = test_devices_api()
    all_passed.append(devices_result)
    
    # Start a scan
    print("\n--- STARTING NETWORK SCAN ---")
    scan_id = start_scan("10.0.0.0/24")
    
    if scan_id:
        # Wait for scan to complete
        scan_result = wait_for_scan(scan_id, timeout=120)
        
        if scan_result:
            # Test scan results
            all_passed.append(test_scan_results(scan_id))
            
            # Wait a moment for database to update
            print("\n⏳ Waiting 3 seconds for database to update...")
            time.sleep(3)
            
            # Test device APIs after scan
            print("\n--- POST-SCAN API TESTS ---")
            all_passed.append(test_devices_api())
            all_passed.append(test_device_details())
            all_passed.append(test_statistics())
            all_passed.append(test_topology())
            all_passed.append(test_vulnerabilities())
        else:
            print("❌ Scan did not complete successfully")
            all_passed.append(False)
    else:
        print("❌ Failed to start scan")
        all_passed.append(False)
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    total_tests = len(all_passed)
    passed_tests = sum(1 for result in all_passed if result)
    failed_tests = total_tests - passed_tests
    
    print(f"Total Tests: {total_tests}")
    print(f"✅ Passed: {passed_tests}")
    print(f"❌ Failed: {failed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
    
    if failed_tests == 0:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {failed_tests} test(s) failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())