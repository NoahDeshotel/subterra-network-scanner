#!/usr/bin/env python3
"""
Test script to verify API subnet scanning functionality
Tests that the API correctly handles large subnet scans
"""

import requests
import json
import time
import sys

def test_api_scan(subnet, scan_mode=None, full_scan=False):
    """Test the API scan endpoint with different configurations"""
    
    api_url = "http://localhost:5002/api/scan/start"
    
    # Prepare request data
    data = {
        "subnet": subnet,
        "scanner_type": "simple"
    }
    
    if scan_mode:
        data["scan_mode"] = scan_mode
    
    if full_scan:
        data["full_scan"] = True
    
    print(f"\n{'='*60}")
    print(f"Testing scan of {subnet}")
    print(f"Request data: {json.dumps(data, indent=2)}")
    print(f"{'='*60}")
    
    try:
        # Start the scan
        response = requests.post(api_url, json=data)
        response.raise_for_status()
        
        result = response.json()
        scan_id = result.get('scan_id')
        config = result.get('config', {})
        
        print(f"✅ Scan initiated successfully")
        print(f"Scan ID: {scan_id}")
        print(f"Actual scan mode: {config.get('scan_mode', 'not set')}")
        print(f"Scanner type: {config.get('scanner_type', 'not set')}")
        
        # Monitor scan progress
        print("\nMonitoring scan progress...")
        status_url = f"http://localhost:5002/api/scan/{scan_id}/status"
        
        for i in range(10):  # Check for 10 seconds
            time.sleep(1)
            status_response = requests.get(status_url)
            if status_response.ok:
                status_data = status_response.json()
                if status_data.get('active'):
                    print(f"  [{i+1}s] Status: {status_data.get('status', 'unknown')}")
                else:
                    print(f"  Scan completed!")
                    break
        
        # Get final results
        results_url = f"http://localhost:5002/api/scan/{scan_id}/results"
        results_response = requests.get(results_url)
        if results_response.ok:
            results_data = results_response.json()
            summary = results_data.get('summary', {})
            print(f"\nScan Summary:")
            print(f"  - Total hosts scanned: {summary.get('total_hosts', 'N/A')}")
            print(f"  - Active hosts found: {summary.get('active_hosts', 'N/A')}")
            print(f"  - Scan successful: {summary.get('scan_successful', False)}")
            
            if 'scan_mode' in summary:
                print(f"  - Scan mode used: {summary['scan_mode']}")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API request failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def main():
    print("API Subnet Scanning Test Suite")
    print("="*60)
    
    # Check if API is running
    try:
        health_response = requests.get("http://localhost:5002/health")
        health_response.raise_for_status()
        print("✅ API is running and healthy")
    except:
        print("❌ API is not running. Please start the backend first:")
        print("   cd backend && python app.py")
        sys.exit(1)
    
    # Test cases
    test_cases = [
        # Test 1: /24 network (should auto-select 'full' mode)
        {"subnet": "10.0.0.0/24", "scan_mode": None, "full_scan": False},
        
        # Test 2: /16 network without mode (should auto-select 'thorough' mode)
        {"subnet": "10.0.0.0/16", "scan_mode": None, "full_scan": False},
        
        # Test 3: /16 network with explicit full_scan flag
        {"subnet": "10.0.0.0/16", "scan_mode": None, "full_scan": True},
        
        # Test 4: /16 network with explicit 'full' mode
        {"subnet": "10.0.0.0/16", "scan_mode": "full", "full_scan": False},
        
        # Test 5: /16 network with 'smart' mode (minimal scanning)
        {"subnet": "10.0.0.0/16", "scan_mode": "smart", "full_scan": False},
    ]
    
    print(f"\nRunning {len(test_cases)} test cases...")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest Case {i}/{len(test_cases)}")
        success = test_api_scan(**test_case)
        if not success:
            print(f"Test case {i} failed!")
        
        # Small delay between tests
        if i < len(test_cases):
            time.sleep(2)
    
    print("\n" + "="*60)
    print("Test suite completed!")

if __name__ == "__main__":
    main()