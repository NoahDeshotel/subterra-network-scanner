#!/usr/bin/env python3
"""Test the scan functionality directly"""

import requests
import json
import time

print("Testing scan API...")

# Test simple endpoint first
print("\n1. Testing API status...")
response = requests.get("http://localhost/api/status", timeout=2)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)[:200]}...")

# Test scan with minimal data
print("\n2. Starting scan...")
scan_data = {
    "subnet": "192.168.1.0/30",
    "scanner_type": "simple"
}

try:
    response = requests.post(
        "http://localhost/api/scan/start",
        json=scan_data,
        timeout=2
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except requests.exceptions.Timeout:
    print("ERROR: Request timed out after 2 seconds")
except Exception as e:
    print(f"ERROR: {e}")

print("\nDone!")