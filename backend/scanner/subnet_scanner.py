#!/usr/bin/env python3
"""
Subnet-Aware Network Scanner
Intelligently scans large networks by breaking them into manageable subnets
"""

import ipaddress
import logging
import time
import asyncio
from typing import Dict, List, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import subprocess
import platform

logger = logging.getLogger(__name__)

class SubnetScanner:
    """
    Intelligent subnet scanner for large networks
    """
    
    def __init__(self, advanced_scanner=None):
        self.advanced_scanner = advanced_scanner
        self.max_hosts_per_batch = 256  # Scan 256 hosts at a time
        self.priority_subnets = []  # Subnets to scan first
        
    def parse_network_intelligently(self, subnet: str, scan_mode: str = 'smart') -> List[ipaddress.IPv4Network]:
        """
        Break down large networks into manageable chunks
        Prioritize commonly used subnets based on scan mode
        
        Modes:
        - 'smart': Only scan priority subnets
        - 'thorough': Scan more subnets systematically
        - 'full': Scan ALL subnets in the network
        """
        network = ipaddress.ip_network(subnet, strict=False)
        subnets_to_scan = []
        
        # Get the network size
        network_size = network.num_addresses
        prefix_len = network.prefixlen
        
        logger.info(f"[SUBNET-SCAN] Analyzing network {network} with {network_size} addresses (/{prefix_len}) in {scan_mode} mode")
        
        if prefix_len >= 24:
            # Small network, scan as-is
            subnets_to_scan.append(network)
            
        elif prefix_len >= 20:  # /20 to /23 - up to 4096 hosts
            # Break into /24 subnets
            subnets_to_scan.extend(network.subnets(new_prefix=24))
            logger.info(f"[SUBNET-SCAN] Split /{prefix_len} into {len(subnets_to_scan)} /24 subnets")
            
        elif prefix_len >= 16:  # /16 to /19 - up to 65536 hosts
            # For /16, intelligently select subnets based on scan mode
            if prefix_len == 16:
                if scan_mode == 'full':
                    # FULL MODE: Scan ALL 256 /24 subnets
                    subnets_to_scan = list(network.subnets(new_prefix=24))
                    logger.info(f"[SUBNET-SCAN] FULL MODE: Generated ALL {len(subnets_to_scan)} /24 subnets for complete /16 scan")
                    
                elif scan_mode == 'thorough':
                    # THOROUGH MODE: Scan first 100 /24 subnets plus priority ones
                    all_subnets = list(network.subnets(new_prefix=24))
                    subnets_to_scan = all_subnets[:100]  # First 100 subnets
                    logger.info(f"[SUBNET-SCAN] THOROUGH MODE: Selected {len(subnets_to_scan)} /24 subnets for /16 network")
                    
                else:  # smart mode (default)
                    # SMART MODE: Only scan priority subnets
                    base_octets = str(network).split('.')[:2]
                    base = '.'.join(base_octets)
                    
                    # Priority subnets (commonly used ranges)
                    priority_ranges = [
                        f"{base}.0.0/24",    # .0.x
                        f"{base}.1.0/24",    # .1.x
                        f"{base}.2.0/24",    # .2.x
                        f"{base}.3.0/24",    # .3.x
                        f"{base}.4.0/24",    # .4.x
                        f"{base}.5.0/24",    # .5.x
                        f"{base}.10.0/24",   # .10.x
                        f"{base}.11.0/24",   # .11.x
                        f"{base}.20.0/24",   # .20.x
                        f"{base}.30.0/24",   # .30.x
                        f"{base}.40.0/24",   # .40.x
                        f"{base}.50.0/24",   # .50.x
                        f"{base}.100.0/24",  # .100.x
                        f"{base}.101.0/24",  # .101.x
                        f"{base}.110.0/24",  # .110.x
                        f"{base}.120.0/24",  # .120.x
                        f"{base}.150.0/24",  # .150.x
                        f"{base}.200.0/24",  # .200.x
                        f"{base}.254.0/24",  # .254.x (often used for management)
                        f"{base}.255.0/24",  # .255.x (sometimes used)
                    ]
                    
                    # Add priority subnets
                    for subnet_str in priority_ranges:
                        try:
                            subnet_net = ipaddress.ip_network(subnet_str)
                            if subnet_net.subnet_of(network):
                                subnets_to_scan.append(subnet_net)
                        except:
                            pass
                    
                    logger.info(f"[SUBNET-SCAN] SMART MODE: Added {len(subnets_to_scan)} priority /24 subnets for /16 network")
                
            else:
                # For /17-/19, handle based on scan mode
                all_subnets = list(network.subnets(new_prefix=24))
                
                if scan_mode == 'full':
                    # Full mode: scan all subnets
                    subnets_to_scan = all_subnets
                    logger.info(f"[SUBNET-SCAN] FULL MODE: Using all {len(subnets_to_scan)} /24 subnets")
                    
                elif scan_mode == 'thorough':
                    # Thorough mode: scan more subnets
                    if len(all_subnets) <= 100:
                        subnets_to_scan = all_subnets
                    else:
                        subnets_to_scan = all_subnets[:100]
                    logger.info(f"[SUBNET-SCAN] THOROUGH MODE: Using {len(subnets_to_scan)} /24 subnets")
                    
                else:  # smart mode
                    # Smart mode: limited scanning
                    if len(all_subnets) <= 64:
                        subnets_to_scan = all_subnets
                    else:
                        # Take first 10, last 5, and sample from middle
                        subnets_to_scan = all_subnets[:10]  # First 10
                        subnets_to_scan.extend(all_subnets[-5:])  # Last 5
                        
                        # Sample from middle
                        step = len(all_subnets) // 20
                        for i in range(10, len(all_subnets) - 5, step):
                            subnets_to_scan.append(all_subnets[i])
                    
                    logger.info(f"[SUBNET-SCAN] SMART MODE: Selected {len(subnets_to_scan)} /24 subnets from {len(all_subnets)} total")
                
        else:  # Smaller than /16 (larger network)
            # For huge networks, limit based on scan mode
            all_subnets = list(network.subnets(new_prefix=24))
            
            if scan_mode == 'full':
                # Even in full mode, limit very large networks to prevent hanging
                subnets_to_scan = all_subnets[:500]  # Max 500 /24 subnets
                logger.warning(f"[SUBNET-SCAN] Very large network (/{prefix_len}). Limiting to {len(subnets_to_scan)} subnets even in full mode.")
            elif scan_mode == 'thorough':
                subnets_to_scan = all_subnets[:50]
                logger.warning(f"[SUBNET-SCAN] Very large network (/{prefix_len}). Scanning {len(subnets_to_scan)} subnets in thorough mode.")
            else:
                subnets_to_scan = all_subnets[:10]
                logger.warning(f"[SUBNET-SCAN] Very large network (/{prefix_len}). Scanning {len(subnets_to_scan)} subnets in smart mode.")
            
        return subnets_to_scan
    
    def quick_subnet_probe(self, subnet: ipaddress.IPv4Network) -> bool:
        """
        Quickly check if a subnet has any active devices
        by pinging a few key addresses
        """
        # Check gateway addresses (.1, .254)
        test_ips = [
            subnet.network_address + 1,      # .1
            subnet.broadcast_address - 1,    # .254
            subnet.network_address + 10,     # .10
            subnet.network_address + 100,    # .100
        ]
        
        for ip in test_ips:
            if ip in subnet and self.ping_host(str(ip), timeout=0.5):
                logger.debug(f"[SUBNET-SCAN] Found active host {ip} in {subnet}")
                return True
        
        return False
    
    def ping_host(self, ip: str, timeout: float = 1.0) -> bool:
        """Quick ping check"""
        try:
            if platform.system().lower() == 'windows':
                command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), str(ip)]
            else:
                # macOS/Linux: -W expects seconds (as float), not milliseconds
                command = ['ping', '-c', '1', '-W', str(timeout), str(ip)]
            
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 0.5
            )
            
            return result.returncode == 0
        except:
            return False
    
    async def scan_large_network(self, subnet: str, scan_id: str, scan_tracker=None, 
                                 progress_callback=None, scan_mode='smart') -> Tuple[Dict, Dict]:
        """
        Scan large networks intelligently
        
        Modes:
        - 'smart': Scan priority subnets and active ranges
        - 'thorough': Scan more subnets systematically  
        - 'full': Scan entire network (warning: slow for large networks)
        """
        logger.info(f"[SUBNET-SCAN] Starting intelligent scan of {subnet} in {scan_mode} mode")
        
        all_devices = {}
        summary = {
            'scan_successful': False,
            'total_subnets': 0,
            'scanned_subnets': 0,
            'active_subnets': 0,
            'total_devices': 0,
            'scan_duration': 0,
            'scan_mode': scan_mode
        }
        
        start_time = time.time()
        
        try:
            # Parse network into subnets based on scan mode
            subnets = self.parse_network_intelligently(subnet, scan_mode)
            summary['total_subnets'] = len(subnets)
            
            logger.info(f"[SUBNET-SCAN] Will scan {len(subnets)} subnets")
            
            if progress_callback:
                progress_callback(scan_id, 5, f"Scanning {len(subnets)} subnets in {scan_mode} mode", scan_tracker)
            
            # First pass: Quick probe to find active subnets (skip for full mode)
            active_subnets = []
            
            if scan_mode == 'full':
                # FULL MODE: Don't probe, scan everything
                active_subnets = subnets
                logger.info(f"[SUBNET-SCAN] FULL MODE: Will scan ALL {len(active_subnets)} subnets without probing")
                
            elif scan_mode == 'smart':
                logger.info("[SUBNET-SCAN] SMART MODE: Performing quick probe to find active subnets...")
                
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = {executor.submit(self.quick_subnet_probe, subnet): subnet 
                              for subnet in subnets}
                    
                    for future in as_completed(futures):
                        subnet = futures[future]
                        try:
                            if future.result(timeout=5):
                                active_subnets.append(subnet)
                                logger.info(f"[SUBNET-SCAN] Active subnet found: {subnet}")
                        except:
                            pass
                
                logger.info(f"[SUBNET-SCAN] Found {len(active_subnets)} active subnets")
                
                # If no active subnets found, scan first few anyway
                if not active_subnets and subnets:
                    active_subnets = subnets[:5]
                    logger.info(f"[SUBNET-SCAN] No active subnets found, scanning first 5")
                    
            else:  # thorough mode
                # THOROUGH MODE: Scan more subnets but still do some filtering
                logger.info("[SUBNET-SCAN] THOROUGH MODE: Using expanded subnet list")
                active_subnets = subnets[:len(subnets)//2] if len(subnets) > 20 else subnets
            
            summary['active_subnets'] = len(active_subnets)
            
            # Scan active subnets - batch processing for efficiency
            if scan_mode == 'full' and len(active_subnets) > 50:
                # For full scans with many subnets, process in parallel batches
                logger.info(f"[SUBNET-SCAN] Using parallel batch processing for {len(active_subnets)} subnets")
                
                batch_size = 20  # Process 20 subnets concurrently for faster scanning
                for batch_start in range(0, len(active_subnets), batch_size):
                    batch_end = min(batch_start + batch_size, len(active_subnets))
                    batch = active_subnets[batch_start:batch_end]
                    
                    progress = 10 + int((batch_start / len(active_subnets)) * 80)
                    if progress_callback:
                        msg = f"Scanning subnets {batch_start+1}-{batch_end}/{len(active_subnets)}"
                        progress_callback(scan_id, progress, msg, scan_tracker)
                    
                    # Scan batch in parallel
                    tasks = [self.scan_subnet(subnet, scan_id) for subnet in batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for subnet, result in zip(batch, batch_results):
                        if isinstance(result, dict) and result:
                            all_devices.update(result)
                            logger.info(f"[SUBNET-SCAN] Found {len(result)} devices in {subnet}")
                        elif isinstance(result, Exception):
                            logger.error(f"[SUBNET-SCAN] Error scanning {subnet}: {result}")
                        
                        summary['scanned_subnets'] += 1
            else:
                # Original sequential scanning for smaller scans
                for idx, subnet in enumerate(active_subnets):
                    progress = 10 + int((idx / len(active_subnets)) * 80)
                    
                    if progress_callback:
                        msg = f"Scanning subnet {idx+1}/{len(active_subnets)}: {subnet}"
                        progress_callback(scan_id, progress, msg, scan_tracker)
                    
                    logger.info(f"[SUBNET-SCAN] Scanning subnet {subnet}")
                    
                    # Scan this subnet
                    subnet_devices = await self.scan_subnet(subnet, scan_id)
                    
                    if subnet_devices:
                        all_devices.update(subnet_devices)
                        logger.info(f"[SUBNET-SCAN] Found {len(subnet_devices)} devices in {subnet}")
                    
                    summary['scanned_subnets'] += 1
            
            # Final summary
            summary['scan_successful'] = True
            summary['total_devices'] = len(all_devices)
            summary['scan_duration'] = time.time() - start_time
            
            logger.info(f"[SUBNET-SCAN] Scan complete: {len(all_devices)} devices in {summary['scan_duration']:.1f}s")
            
            if progress_callback:
                progress_callback(scan_id, 95, f"Found {len(all_devices)} devices across {summary['active_subnets']} subnets", scan_tracker)
            
        except Exception as e:
            logger.error(f"[SUBNET-SCAN] Error: {e}", exc_info=True)
            summary['scan_successful'] = False
            summary['error'] = str(e)
            summary['scan_duration'] = time.time() - start_time
        
        return all_devices, summary
    
    async def scan_subnet(self, subnet: ipaddress.IPv4Network, scan_id: str) -> Dict:
        """
        Scan a single subnet - optimized for speed in large network scans
        """
        devices = {}
        
        # For full mode scans, use fast basic scanning to handle volume
        # Advanced scanner is too slow for 256 subnets
        hosts = list(subnet.hosts())  # Get all hosts in the subnet
        
        # Use fast parallel scanning with higher concurrency
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self.fast_host_check, str(ip)): ip for ip in hosts}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result(timeout=1)  # Short timeout for speed
                    if result:
                        devices[str(ip)] = result
                except:
                    pass
        
        if devices:
            logger.info(f"[SUBNET-SCAN] Found {len(devices)} devices in {subnet}")
        
        return devices
    
    def fast_host_check(self, ip: str) -> Dict:
        """Ultra-fast host checking for large network scans"""
        # Try TCP connect on common ports for speed
        common_ports = [22, 80, 443, 445, 3389, 8080]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)  # Very short timeout for speed
            try:
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    # Host is up, return basic info
                    device = {
                        'ip': ip,
                        'is_active': True,
                        'status': 'active',
                        'open_ports': [port],
                        'discovery_method': 'tcp_scan',
                        'discovery_time': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    # Try quick hostname lookup
                    try:
                        hostname, _, _ = socket.gethostbyaddr(ip)
                        device['hostname'] = hostname
                    except:
                        device['hostname'] = ip
                    
                    return device
            except:
                sock.close()
                continue
        
        # If no TCP ports responded, try ping as fallback
        if self.ping_host(ip, timeout=0.2):
            return {
                'ip': ip,
                'is_active': True,
                'status': 'active',
                'discovery_method': 'ping',
                'discovery_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        
        return None
    
    def scan_host(self, ip: str) -> Dict:
        """Basic host scanning"""
        if self.ping_host(ip, timeout=0.5):
            device = {
                'ip': ip,
                'is_active': True,
                'status': 'active',
                'discovery_time': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Try to get hostname
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                device['hostname'] = hostname
            except:
                pass
            
            return device
        return None


# Integration function for main scanner
async def scan_large_network_smart(subnet: str, scan_id: str, scan_tracker=None, scan_mode='smart'):
    """
    Wrapper function to scan large networks intelligently
    """
    scanner = SubnetScanner()
    
    # Try to use advanced scanner if available
    try:
        from .advanced_scanner import AdvancedNetworkScanner
        scanner.advanced_scanner = AdvancedNetworkScanner()
    except:
        logger.warning("Advanced scanner not available, using basic scanning")
    
    # Import progress callback
    from .main_scanner import emit_progress
    
    return await scanner.scan_large_network(
        subnet, 
        scan_id, 
        scan_tracker,
        emit_progress,
        scan_mode
    )