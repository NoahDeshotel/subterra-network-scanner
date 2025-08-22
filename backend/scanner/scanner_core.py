#!/usr/bin/env python3
"""
Core Scanner Module
Orchestrates network scanning using modular components
"""

import logging
import time
import asyncio
import ipaddress
from typing import Dict, Tuple, Optional, Callable
from datetime import datetime

from .host_discovery import HostDiscovery
from .port_scanner import PortScanner
from .device_identifier import DeviceIdentifier

logger = logging.getLogger(__name__)

class NetworkScanner:
    """
    Core network scanner that orchestrates discovery, port scanning, and identification
    """
    
    def __init__(self):
        self.discovery = HostDiscovery()
        self.port_scanner = PortScanner()
        self.identifier = DeviceIdentifier()
        
    def scan_network(self, 
                    subnet: str,
                    scan_mode: str = 'balanced',
                    progress_callback: Optional[Callable] = None) -> Tuple[Dict, Dict]:
        """
        Perform complete network scan
        
        Args:
            subnet: Network to scan (e.g., "10.0.0.0/24")
            scan_mode: 'quick', 'balanced', 'deep', 'full'
            progress_callback: Function(scan_id, percentage, message) for progress updates
            
        Returns:
            Tuple of (devices_dict, summary_dict)
        """
        start_time = time.time()
        scan_id = f"scan_{int(time.time())}"
        
        logger.info(f"Starting network scan - Subnet: {subnet}, Mode: {scan_mode}")
        
        # Initialize summary
        summary = {
            'scan_id': scan_id,
            'subnet': subnet,
            'scan_mode': scan_mode,
            'start_time': datetime.now().isoformat(),
            'scan_successful': False,
            'error': None
        }
        
        try:
            # Parse network to validate
            network = ipaddress.ip_network(subnet, strict=False)
            total_hosts = network.num_addresses - 2  # Exclude network and broadcast
            summary['total_hosts'] = total_hosts
            
            # Progress wrapper
            def progress(percentage, message):
                if progress_callback:
                    progress_callback(scan_id, percentage, message)
            
            # Step 1: Host Discovery (0-40% progress)
            progress(0, f"Starting discovery of {subnet}")
            
            def discovery_progress(pct, msg):
                # Scale discovery progress to 0-40% of total
                progress(int(pct * 0.4), msg)
            
            discovered_hosts = self.discovery.discover_network(subnet, discovery_progress)
            
            summary['discovered_hosts'] = len(discovered_hosts)
            logger.info(f"Discovery complete: {len(discovered_hosts)}/{total_hosts} hosts found")
            
            if not discovered_hosts:
                progress(100, "No hosts discovered")
                summary['scan_successful'] = True
                summary['scan_duration'] = time.time() - start_time
                return {}, summary
            
            # Step 2: Port Scanning (40-80% progress)
            progress(40, f"Scanning ports on {len(discovered_hosts)} hosts")
            
            # Determine port scan type based on scan mode
            port_scan_type = self._get_port_scan_type(scan_mode)
            
            def port_progress(pct, msg):
                # Scale port scan progress to 40-80% of total
                progress(40 + int(pct * 0.4), msg)
            
            enhanced_hosts = self.port_scanner.scan_network_ports(
                discovered_hosts, 
                scan_type=port_scan_type,
                callback=port_progress
            )
            
            # Step 3: Device Identification (80-95% progress)
            progress(80, "Identifying devices")
            
            devices = {}
            for idx, (ip, host_info) in enumerate(enhanced_hosts.items()):
                # Identify device
                identified = self.identifier.identify_device(host_info)
                
                # Add timestamps
                identified['first_seen'] = datetime.now().isoformat()
                identified['last_seen'] = identified['first_seen']
                
                devices[ip] = identified
                
                # Update progress
                pct = 80 + int((idx / len(enhanced_hosts)) * 15)
                progress(pct, f"Identified {idx + 1}/{len(enhanced_hosts)} devices")
            
            # Calculate summary statistics
            summary['devices_found'] = len(devices)
            summary['scan_successful'] = True
            summary['scan_duration'] = round(time.time() - start_time, 2)
            
            # Device type breakdown
            device_types = {}
            for device in devices.values():
                dtype = device.get('device_type', 'unknown')
                device_types[dtype] = device_types.get(dtype, 0) + 1
            summary['device_types'] = device_types
            
            # Port statistics
            total_open_ports = sum(
                len(d.get('open_ports', [])) for d in devices.values()
            )
            summary['total_open_ports'] = total_open_ports
            
            # Risk assessment
            risk_levels = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            for device in devices.values():
                risk = device.get('risk_level', 'low')
                risk_levels[risk] = risk_levels.get(risk, 0) + 1
            summary['risk_levels'] = risk_levels
            
            progress(100, f"Scan complete: {len(devices)} devices found")
            
            logger.info(f"Scan complete - Found {len(devices)} devices in {summary['scan_duration']}s")
            
            return devices, summary
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            summary['scan_successful'] = False
            summary['error'] = str(e)
            summary['scan_duration'] = round(time.time() - start_time, 2)
            
            if progress_callback:
                progress_callback(scan_id, 100, f"Scan failed: {e}")
            
            return {}, summary
    
    async def scan_network_async(self, 
                                 subnet: str,
                                 scan_mode: str = 'balanced',
                                 progress_callback: Optional[Callable] = None) -> Tuple[Dict, Dict]:
        """
        Async wrapper for network scanning
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.scan_network,
            subnet,
            scan_mode,
            progress_callback
        )
    
    def scan_large_network(self,
                          subnet: str,
                          scan_mode: str = 'smart',
                          progress_callback: Optional[Callable] = None) -> Tuple[Dict, Dict]:
        """
        Optimized scanning for large networks (/16 and larger)
        
        Uses intelligent subnet division and parallel scanning
        """
        start_time = time.time()
        scan_id = f"scan_large_{int(time.time())}"
        
        logger.info(f"Starting large network scan - Subnet: {subnet}, Mode: {scan_mode}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            
            # For very large networks, divide into /24 subnets
            if network.prefixlen < 24:
                subnets = list(network.subnets(new_prefix=24))
                
                # Determine which subnets to scan based on mode
                if scan_mode == 'smart':
                    # Scan only priority subnets for large networks
                    priority_subnets = self._get_priority_subnets(subnets)
                    subnets_to_scan = priority_subnets[:20]  # Limit to 20 subnets
                elif scan_mode == 'balanced':
                    # Scan first 50 subnets
                    subnets_to_scan = subnets[:50]
                else:  # full
                    # Scan all subnets (warning: can be slow)
                    subnets_to_scan = subnets
                
                logger.info(f"Scanning {len(subnets_to_scan)}/{len(subnets)} subnets")
                
                all_devices = {}
                for idx, subnet in enumerate(subnets_to_scan):
                    if progress_callback:
                        pct = int((idx / len(subnets_to_scan)) * 100)
                        progress_callback(scan_id, pct, f"Scanning subnet {idx + 1}/{len(subnets_to_scan)}")
                    
                    # Scan individual subnet
                    devices, _ = self.scan_network(str(subnet), scan_mode='quick')
                    all_devices.update(devices)
                
                summary = {
                    'scan_successful': True,
                    'total_subnets': len(subnets),
                    'scanned_subnets': len(subnets_to_scan),
                    'devices_found': len(all_devices),
                    'scan_duration': round(time.time() - start_time, 2)
                }
                
                return all_devices, summary
            else:
                # For /24 or smaller, use regular scan
                return self.scan_network(subnet, scan_mode, progress_callback)
                
        except Exception as e:
            logger.error(f"Large network scan failed: {e}")
            return {}, {'scan_successful': False, 'error': str(e)}
    
    def _get_port_scan_type(self, scan_mode: str) -> str:
        """Map scan mode to port scan type"""
        mapping = {
            'quick': 'minimal',
            'balanced': 'common',
            'deep': 'full',
            'full': 'full'
        }
        return mapping.get(scan_mode, 'common')
    
    def _get_priority_subnets(self, subnets: list) -> list:
        """
        Get priority subnets for smart scanning
        
        Prioritizes common subnet ranges like:
        - x.x.0.0/24 (network infrastructure)
        - x.x.1.0/24 (common DHCP range)
        - x.x.10.0/24, x.x.100.0/24 (common user ranges)
        """
        priority = []
        
        for subnet in subnets:
            subnet_str = str(subnet)
            # Extract the third octet
            parts = subnet_str.split('.')
            if len(parts) >= 3:
                third_octet = int(parts[2])
                
                # Priority order
                if third_octet in [0, 1, 2, 10, 20, 30, 50, 100, 192, 254]:
                    priority.append(subnet)
        
        # Add remaining subnets
        for subnet in subnets:
            if subnet not in priority:
                priority.append(subnet)
        
        return priority

# Convenience function for simple scanning
def quick_scan(subnet: str, callback=None) -> Dict:
    """
    Quick network scan that returns just active devices
    
    Args:
        subnet: Network to scan
        callback: Optional progress callback
        
    Returns:
        Dictionary of devices {ip: device_info}
    """
    scanner = NetworkScanner()
    devices, _ = scanner.scan_network(subnet, scan_mode='quick', progress_callback=callback)
    return devices

def deep_scan(subnet: str, callback=None) -> Tuple[Dict, Dict]:
    """
    Deep network scan with full port scanning and identification
    
    Args:
        subnet: Network to scan
        callback: Optional progress callback
        
    Returns:
        Tuple of (devices, summary)
    """
    scanner = NetworkScanner()
    return scanner.scan_network(subnet, scan_mode='deep', progress_callback=callback)

if __name__ == "__main__":
    # Test the scanner
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def progress_callback(scan_id, percentage, message):
        print(f"[{percentage:3d}%] {message}")
    
    scanner = NetworkScanner()
    
    # Test quick scan
    print("Testing quick scan on small network...")
    devices, summary = scanner.scan_network("10.0.0.0/28", "quick", progress_callback)
    
    print(f"\nScan Results:")
    print(f"  Devices found: {len(devices)}")
    print(f"  Scan duration: {summary.get('scan_duration', 0)}s")
    print(f"  Device types: {summary.get('device_types', {})}")
    
    for ip, device in devices.items():
        print(f"\n  {ip}:")
        print(f"    Type: {device.get('device_type', 'unknown')}")
        print(f"    OS: {device.get('os', 'unknown')}")
        print(f"    Open Ports: {device.get('open_ports', [])[: 5]}")  # Show first 5 ports