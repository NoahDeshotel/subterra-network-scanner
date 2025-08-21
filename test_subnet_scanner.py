#!/usr/bin/env python3
"""
Test script for the subnet scanner with /16 network
"""

import sys
import os
import asyncio
import logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from scanner.subnet_scanner import SubnetScanner, scan_large_network_smart

async def test_subnet_scanner():
    print("Testing Subnet Scanner with /16 Network")
    print("=" * 50)
    
    # Test with a /16 network
    test_subnet = "10.0.0.0/16"  # This is a /16 network with 65,536 addresses
    
    print(f"Testing subnet: {test_subnet}")
    print()
    
    # Test different scan modes
    scan_modes = ['smart', 'thorough']  # 'full' would take too long for testing
    
    for mode in scan_modes:
        print(f"\n{'='*50}")
        print(f"Testing {mode.upper()} scan mode")
        print(f"{'='*50}")
        
        # Create a mock scan tracker
        class MockScanTracker:
            def update_progress(self, scan_id, percentage, message, stage='scanning'):
                print(f"[{percentage:3d}%] {message}")
        
        scan_tracker = MockScanTracker()
        scan_id = f"test-{mode}"
        
        # Progress callback
        def progress_callback(scan_id, percentage, message, tracker):
            if tracker:
                tracker.update_progress(scan_id, percentage, message)
        
        scanner = SubnetScanner()
        
        try:
            # Import advanced scanner if available
            from scanner.advanced_scanner import AdvancedNetworkScanner
            scanner.advanced_scanner = AdvancedNetworkScanner()
            print("Using advanced scanner capabilities")
        except:
            print("Using basic scanner capabilities")
        
        # Parse the network to show what will be scanned
        subnets = scanner.parse_network_intelligently(test_subnet)
        print(f"Network will be divided into {len(subnets)} subnets")
        print(f"Priority subnets to scan:")
        for i, subnet in enumerate(subnets[:10]):  # Show first 10
            print(f"  {i+1}. {subnet}")
        if len(subnets) > 10:
            print(f"  ... and {len(subnets) - 10} more")
        print()
        
        # Run the scan
        start_time = asyncio.get_event_loop().time()
        devices, summary = await scanner.scan_large_network(
            test_subnet,
            scan_id,
            scan_tracker,
            progress_callback,
            scan_mode=mode
        )
        scan_time = asyncio.get_event_loop().time() - start_time
        
        print(f"\n{mode.upper()} Scan Results:")
        print(f"  Duration: {scan_time:.2f} seconds")
        print(f"  Total Subnets: {summary.get('total_subnets', 0)}")
        print(f"  Scanned Subnets: {summary.get('scanned_subnets', 0)}")
        print(f"  Active Subnets: {summary.get('active_subnets', 0)}")
        print(f"  Devices Found: {len(devices)}")
        
        if devices:
            print(f"\n  Sample devices found:")
            for i, (ip, info) in enumerate(list(devices.items())[:5]):
                print(f"    - {ip}: {info.get('hostname', 'Unknown')}")
            if len(devices) > 5:
                print(f"    ... and {len(devices) - 5} more devices")
        
        # Show device distribution across subnets
        if devices:
            subnet_distribution = {}
            for ip in devices.keys():
                subnet_prefix = '.'.join(ip.split('.')[:3])
                subnet_distribution[subnet_prefix] = subnet_distribution.get(subnet_prefix, 0) + 1
            
            print(f"\n  Device distribution by /24 subnet:")
            for subnet, count in sorted(subnet_distribution.items())[:10]:
                print(f"    {subnet}.x: {count} devices")
            if len(subnet_distribution) > 10:
                print(f"    ... and {len(subnet_distribution) - 10} more subnets")

def test_direct_scan():
    """Test the main scanner directly with scan_mode"""
    print("\n" + "="*50)
    print("Testing Direct Scanner with scan_mode")
    print("="*50)
    
    from scanner.main_scanner import scan_with_robust_progress
    
    test_subnet = "10.0.0.0/16"
    scan_id = "test-direct"
    
    print(f"Scanning {test_subnet} with smart mode...")
    devices, summary = scan_with_robust_progress(
        test_subnet,
        scan_id,
        scan_tracker=None,
        use_advanced=True,
        scan_mode='smart'
    )
    
    print(f"Direct scan found {len(devices)} devices")
    print(f"Summary: {summary}")

if __name__ == "__main__":
    print("Network Scanner Test Suite")
    print("="*50)
    
    # Run async subnet scanner tests
    asyncio.run(test_subnet_scanner())
    
    # Run direct scanner test
    test_direct_scan()
    
    print("\n" + "="*50)
    print("All tests completed!")
    print("If you found devices across multiple subnets (10.0.x.x),")
    print("then the subnet scanner is working correctly!")
    print("="*50)