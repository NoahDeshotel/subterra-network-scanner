#!/usr/bin/env python3
"""
Port Scanner Module
Efficient port scanning for discovered hosts
"""

import socket
import logging
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

logger = logging.getLogger(__name__)

class PortScanner:
    """Efficient port scanner for network hosts"""
    
    # Common ports grouped by service type
    COMMON_PORTS = {
        'web': [80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000, 9000],
        'remote': [22, 23, 3389, 5900, 5901],
        'file': [21, 445, 139, 2049, 873],
        'database': [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984],
        'mail': [25, 110, 143, 465, 587, 993, 995],
        'network': [53, 67, 68, 161, 162, 514],
        'other': [135, 137, 138, 389, 636, 1723, 3268, 3269]
    }
    
    # Well-known port to service mapping
    PORT_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        137: 'NetBIOS',
        138: 'NetBIOS',
        139: 'SMB',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        514: 'Syslog',
        587: 'SMTP',
        636: 'LDAPS',
        873: 'Rsync',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        1723: 'PPTP',
        2049: 'NFS',
        3000: 'Node.js',
        3268: 'LDAP',
        3269: 'LDAPS',
        3306: 'MySQL',
        3389: 'RDP',
        5000: 'Flask',
        5432: 'PostgreSQL',
        5900: 'VNC',
        5901: 'VNC',
        5984: 'CouchDB',
        6379: 'Redis',
        8000: 'HTTP-Alt',
        8001: 'HTTP-Alt',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt',
        9000: 'PHP-FPM',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }
    
    def __init__(self):
        self.timeout = 0.5  # Socket timeout in seconds
        self.max_workers = 20  # Threads per host
        
    def scan_port(self, host: str, port: int) -> Dict:
        """
        Scan a single port on a host
        
        Returns:
            Dict with port info if open, None if closed/filtered
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                # Port is open
                service = self.PORT_SERVICES.get(port, f'Unknown-{port}')
                
                # Try to grab banner if possible
                banner = None
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'protocol': 'tcp',
                    'banner': banner
                }
        except socket.timeout:
            return None  # Port filtered/closed
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port} - {e}")
            return None
        finally:
            sock.close()
            
        return None
    
    def scan_host_ports(self, host: str, ports: List[int] = None, 
                       scan_type: str = 'common') -> Dict:
        """
        Scan multiple ports on a single host
        
        Args:
            host: Target host IP
            ports: List of ports to scan (if None, uses scan_type)
            scan_type: 'common', 'full', 'web', 'minimal'
            
        Returns:
            Dict with host scan results
        """
        if ports is None:
            ports = self._get_ports_for_scan_type(scan_type)
        
        logger.debug(f"Scanning {len(ports)} ports on {host}")
        
        open_ports = []
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent port scanning
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ports))) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, host, port): port 
                for port in ports
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result(timeout=self.timeout + 1)
                    if result:
                        open_ports.append(result)
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {e}")
        
        scan_time = time.time() - start_time
        
        return {
            'host': host,
            'open_ports': open_ports,
            'ports_scanned': len(ports),
            'scan_time': round(scan_time, 2),
            'scan_type': scan_type
        }
    
    def scan_network_ports(self, hosts: Dict[str, Dict], 
                          scan_type: str = 'common',
                          callback=None) -> Dict[str, Dict]:
        """
        Scan ports on multiple hosts
        
        Args:
            hosts: Dictionary of hosts from discovery {ip: host_info}
            scan_type: Type of scan to perform
            callback: Progress callback function(percentage, message)
            
        Returns:
            Enhanced host dictionary with port information
        """
        logger.info(f"Starting port scan for {len(hosts)} hosts")
        
        enhanced_hosts = {}
        completed = 0
        total = len(hosts)
        
        for ip, host_info in hosts.items():
            # Check if host already has some ports from discovery
            initial_ports = host_info.get('initial_ports', [])
            
            # Scan ports
            if scan_type == 'minimal' and initial_ports:
                # If minimal scan and we already found ports, skip full scan
                port_results = {
                    'host': ip,
                    'open_ports': [
                        {'port': p, 'state': 'open', 
                         'service': self.PORT_SERVICES.get(p, f'Unknown-{p}'),
                         'protocol': 'tcp'}
                        for p in initial_ports
                    ],
                    'ports_scanned': len(initial_ports),
                    'scan_type': 'discovery'
                }
            else:
                # Perform full port scan
                port_results = self.scan_host_ports(ip, scan_type=scan_type)
            
            # Merge results
            enhanced_info = {**host_info}
            enhanced_info['ports'] = port_results['open_ports']
            enhanced_info['open_ports'] = [p['port'] for p in port_results['open_ports']]
            enhanced_info['open_ports_count'] = len(port_results['open_ports'])
            enhanced_info['services'] = [p['service'] for p in port_results['open_ports']]
            
            enhanced_hosts[ip] = enhanced_info
            
            completed += 1
            
            # Update progress
            if callback:
                percentage = int((completed / total) * 100)
                callback(percentage, f"Scanned ports on {completed}/{total} hosts")
        
        logger.info(f"Port scan complete for {len(enhanced_hosts)} hosts")
        
        return enhanced_hosts
    
    def _get_ports_for_scan_type(self, scan_type: str) -> List[int]:
        """Get port list based on scan type"""
        if scan_type == 'minimal':
            # Just the most common ports
            return [80, 443, 22, 445, 3389, 8080]
        elif scan_type == 'web':
            return self.COMMON_PORTS['web']
        elif scan_type == 'common':
            # Combine most important ports from each category
            ports = []
            for category in self.COMMON_PORTS.values():
                ports.extend(category[:3])  # Top 3 from each category
            return list(set(ports))
        elif scan_type == 'full':
            # All defined common ports
            ports = []
            for category in self.COMMON_PORTS.values():
                ports.extend(category)
            return list(set(ports))
        else:
            # Default to common scan
            return self._get_ports_for_scan_type('common')

# Convenience functions
def quick_port_scan(host: str, ports: List[int] = None) -> List[int]:
    """Quick scan that returns just open port numbers"""
    scanner = PortScanner()
    result = scanner.scan_host_ports(host, ports, scan_type='minimal')
    return [p['port'] for p in result.get('open_ports', [])]

if __name__ == "__main__":
    # Test port scanner
    logging.basicConfig(level=logging.INFO)
    
    scanner = PortScanner()
    
    # Test single host
    print("Testing port scan on localhost...")
    result = scanner.scan_host_ports("127.0.0.1", scan_type='minimal')
    print(f"Open ports: {result['open_ports']}")
    print(f"Scan time: {result['scan_time']}s")