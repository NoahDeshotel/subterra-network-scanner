#!/usr/bin/env python3
"""
Debug script to test the enhanced discovery methods directly
"""

import asyncio
import sys
import os
import logging

# Add the backend path
sys.path.insert(0, '/app')

from scanner.enhanced_discovery import EnhancedNetworkDiscovery

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def test_discovery():
    print("🔍 Testing Enhanced Network Discovery")
    
    # Test with a small subnet
    subnet = "10.0.0.0/28"  # 16 hosts
    print(f"📡 Testing subnet: {subnet}")
    
    discovery = EnhancedNetworkDiscovery()
    
    try:
        print("🚀 Starting discovery...")
        devices = await discovery.discover_network(subnet, deep_scan=False, scan_id="test_scan")
        
        print(f"✅ Discovery completed!")
        print(f"📊 Found {len(devices)} devices:")
        
        for ip, device in devices.items():
            print(f"  - {ip}: {device.hostname or 'Unknown'} ({device.device_type or 'Unknown type'})")
        
        # Test individual discovery methods
        print("\n🔬 Testing individual discovery methods:")
        
        print("1. Testing ARP scan...")
        arp_hosts = await discovery._scan_arp_table(subnet)
        print(f"   ARP found: {len(arp_hosts)} hosts - {arp_hosts[:5]}")
        
        print("2. Testing ping sweep...")
        ping_hosts = await discovery._ping_sweep(subnet)
        print(f"   Ping found: {len(ping_hosts)} hosts - {ping_hosts[:5]}")
        
        print("3. Testing nmap discovery...")
        nmap_hosts = await discovery._nmap_discovery(subnet)
        print(f"   Nmap found: {len(nmap_hosts)} hosts - {nmap_hosts[:5]}")
        
    except Exception as e:
        print(f"❌ Discovery failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_discovery())
