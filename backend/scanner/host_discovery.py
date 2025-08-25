#!/usr/bin/env python3
"""
Host Discovery Module
Fast and reliable host discovery using multiple methods
"""

import socket
import subprocess
import platform
import logging
import asyncio
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

logger = logging.getLogger(__name__)

class HostDiscovery:
    """Fast host discovery using multiple detection methods"""
    
    def __init__(self):
        self.max_workers = 50  # Optimal thread count for discovery
        self.timeout = 0.5  # Default timeout for checks
        
    def ping_host(self, ip: str, timeout: float = 0.5) -> bool:
        """Check if host responds to ping"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-W' if platform.system().lower() != 'windows' else '-w'
            
            command = ['ping', param, '1', timeout_param, str(int(timeout * 1000)), str(ip)]
            
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 0.5
            )
            
            return result.returncode == 0
        except:
            return False
    
    def arp_check(self, ip: str) -> bool:
        """Check if host exists in ARP table (more reliable for local networks)"""
        if platform.system().lower() == 'windows':
            return False
            
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True,
                text=True,
                timeout=1.0
            )
            
            # Check if IP is in ARP table and not marked as incomplete
            if ip in result.stdout and 'incomplete' not in result.stdout.lower():
                return True
                
        except:
            pass
            
        return False
    
    def tcp_scan_check(self, ip: str, ports: List[int] = None) -> tuple:
        """Quick TCP scan on common ports"""
        if ports is None:
            # Common ports ordered by likelihood
            ports = [80, 443, 22, 445, 3389, 8080, 139, 135, 21, 23, 53, 8443, 3000, 5000]
        
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    sock.close()
                    # Found at least one open port, host is up
                    return (True, open_ports)
            except:
                pass
            finally:
                sock.close()
        
        return (False, open_ports)
    
    def discover_host(self, ip: str) -> Dict:
        """
        Comprehensive host discovery using multiple methods
        Returns device info if host is up, None otherwise
        """
        ip_str = str(ip)
        
        # Try multiple discovery methods
        discovery_method = None
        host_is_up = False
        open_ports = []
        
        # Method 1: ICMP Ping
        if self.ping_host(ip_str, self.timeout):
            host_is_up = True
            discovery_method = 'ping'
            logger.debug(f"Host {ip_str} discovered via PING")
        
        # Method 2: ARP (for local networks)
        if not host_is_up and self.arp_check(ip_str):
            host_is_up = True
            discovery_method = 'arp'
            logger.debug(f"Host {ip_str} discovered via ARP")
        
        # Method 3: TCP Port Scan
        if not host_is_up:
            tcp_up, tcp_ports = self.tcp_scan_check(ip_str)
            if tcp_up:
                host_is_up = True
                open_ports = tcp_ports
                discovery_method = f'tcp_scan'
                logger.debug(f"Host {ip_str} discovered via TCP (ports: {tcp_ports})")
        
        # If host is not up, return None
        if not host_is_up:
            return None
        
        # Host is up, return basic info
        return {
            'ip': ip_str,
            'is_active': True,
            'status': 'active',
            'discovery_method': discovery_method,
            'initial_ports': open_ports,  # Ports found during discovery
        }
    
    def discover_network(self, subnet: str, callback=None) -> Dict[str, Dict]:
        """
        Discover all active hosts in a network
        
        Args:
            subnet: Network to scan (e.g., "10.0.0.0/24")
            callback: Progress callback function(percentage, message)
            
        Returns:
            Dictionary of discovered hosts {ip: host_info}
        """
        logger.info(f"Starting network discovery for {subnet}")
        
        # Parse network
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
            total_hosts = len(hosts)
        except Exception as e:
            logger.error(f"Invalid subnet {subnet}: {e}")
            return {}
        
        logger.info(f"Scanning {total_hosts} hosts in {subnet}")
        
        discovered_hosts = {}
        completed = 0
        
        # Use ThreadPoolExecutor for concurrent discovery
        with ThreadPoolExecutor(max_workers=min(self.max_workers, total_hosts)) as executor:
            # Submit all discovery tasks
            future_to_ip = {
                executor.submit(self.discover_host, ip): ip 
                for ip in hosts
            }
            
            # Process results as they complete
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                # Update progress
                if callback and completed % max(1, total_hosts // 20) == 0:
                    percentage = int((completed / total_hosts) * 100)
                    callback(percentage, f"Discovered {len(discovered_hosts)}/{completed} hosts")
                
                try:
                    result = future.result(timeout=2)
                    if result:
                        discovered_hosts[str(ip)] = result
                        logger.debug(f"Discovered host: {ip}")
                except Exception as e:
                    logger.debug(f"Error discovering {ip}: {e}")
        
        logger.info(f"Discovery complete: found {len(discovered_hosts)}/{total_hosts} hosts")
        
        if callback:
            callback(100, f"Discovery complete: {len(discovered_hosts)} hosts found")
        
        return discovered_hosts
    
    async def discover_network_async(self, subnet: str, callback=None) -> Dict[str, Dict]:
        """Async wrapper for network discovery"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.discover_network,
            subnet,
            callback
        )

# Convenience function for simple discovery
def quick_discover(subnet: str) -> List[str]:
    """Quick discovery that returns just a list of active IPs"""
    discovery = HostDiscovery()
    hosts = discovery.discover_network(subnet)
    return list(hosts.keys())

if __name__ == "__main__":
    # Test discovery
    logging.basicConfig(level=logging.INFO)
    
    discovery = HostDiscovery()
    
    # Test single host
    print("Testing single host discovery...")
    result = discovery.discover_host("10.0.0.1")
    print(f"Result: {result}")
    
    # Test network discovery
    print("\nTesting network discovery...")
    hosts = discovery.discover_network("10.0.0.0/28")  # Small test network
    print(f"Found {len(hosts)} hosts:")
    for ip, info in hosts.items():
        print(f"  - {ip}: {info['discovery_method']}")