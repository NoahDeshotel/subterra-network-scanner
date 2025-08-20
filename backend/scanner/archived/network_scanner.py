"""
Network Scanner Module
Handles network discovery and host scanning using Nmap
"""

import subprocess
import json
import socket
import ipaddress
import logging
import re
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nmap_path = self._find_nmap()
        if not self.nmap_path:
            raise RuntimeError("Nmap not found. Please install Nmap.")
        
        # Verify Nmap NSE scripts are available
        self._verify_nse_scripts()
    
    def _find_nmap(self) -> Optional[str]:
        """Find Nmap executable path"""
        try:
            result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def _verify_nse_scripts(self):
        """Verify required NSE scripts are available"""
        required_scripts = ['vulners', 'vulscan', 'http-vuln-*']
        try:
            subprocess.run([self.nmap_path, '--script-updatedb'], 
                         capture_output=True, check=False)
        except Exception as e:
            logger.warning(f"Could not update NSE database: {e}")
    
    def get_local_ip(self) -> str:
        """Get the local machine's IP address"""
        try:
            # Create a socket and connect to a public DNS server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.error(f"Failed to get local IP: {e}")
            return "127.0.0.1"
    
    def detect_local_subnet(self) -> str:
        """Auto-detect the local subnet in CIDR notation"""
        try:
            local_ip = self.get_local_ip()
            
            # Get network interface info
            result = subprocess.run(['ip', 'route', 'show'], 
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if local_ip in line and '/' in line:
                    # Extract CIDR notation
                    parts = line.split()
                    for part in parts:
                        if '/' in part:
                            try:
                                network = ipaddress.ip_network(part, strict=False)
                                return str(network)
                            except:
                                continue
            
            # Fallback to /24 subnet
            ip_obj = ipaddress.ip_address(local_ip)
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
            
        except Exception as e:
            logger.error(f"Failed to detect subnet: {e}")
            return "192.168.1.0/24"
    
    def discover_hosts(self, subnet: str) -> List[str]:
        """Discover live hosts on the subnet using Nmap ping scan"""
        logger.info(f"Discovering hosts on subnet: {subnet}")
        
        try:
            # Run Nmap ping scan
            cmd = [
                'sudo', self.nmap_path,
                '-sn',  # Ping scan
                '-T4',  # Aggressive timing
                '--min-parallelism', '100',
                '--max-retries', '1',
                '-oX', '-',  # XML output to stdout
                subnet
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.error(f"Nmap error: {result.stderr}")
                return []
            
            # Parse XML output
            hosts = []
            try:
                root = ET.fromstring(result.stdout)
                for host in root.findall('.//host'):
                    status = host.find('status')
                    if status is not None and status.get('state') == 'up':
                        address = host.find('.//address[@addrtype="ipv4"]')
                        if address is not None:
                            ip = address.get('addr')
                            if ip and ip != self.get_local_ip():
                                hosts.append(ip)
            except ET.ParseError as e:
                logger.error(f"Failed to parse Nmap XML: {e}")
                # Fallback to text parsing
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                        if ip_match:
                            ip = ip_match.group()
                            if ip != self.get_local_ip():
                                hosts.append(ip)
            
            logger.info(f"Discovered {len(hosts)} live hosts")
            return hosts
            
        except subprocess.TimeoutExpired:
            logger.error("Host discovery timed out")
            return []
        except Exception as e:
            logger.error(f"Host discovery failed: {e}")
            return []
    
    def scan_host(self, ip: str, aggressive: bool = False) -> Dict:
        """Perform detailed scan of a single host"""
        logger.info(f"Scanning host: {ip}")
        
        scan_result = {
            'ip': ip,
            'hostname': None,
            'state': 'up',
            'os': None,
            'ports': [],
            'services': [],
            'cves': [],
            'mac_address': None,
            'scan_time': None
        }
        
        try:
            # Build Nmap command
            cmd = [
                'sudo', self.nmap_path,
                '-A',  # Aggressive scan (OS detection, version detection, script scanning)
                '-T4',  # Aggressive timing
                '--version-intensity', '9' if aggressive else '7',
                '--script', 'vulners,vulscan,http-vuln-*,smb-vuln-*,ssl-*',
                '-oX', '-',  # XML output
                ip
            ]
            
            if aggressive:
                cmd.extend(['-p-'])  # Scan all ports
            else:
                cmd.extend(['-p', '1-10000'])  # Common ports only
            
            # Run scan with timeout
            timeout = 300 if aggressive else 120
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode != 0 and result.returncode != 1:
                logger.warning(f"Nmap returned code {result.returncode} for {ip}")
            
            # Parse XML output
            scan_result = self._parse_nmap_xml(result.stdout, scan_result)
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                scan_result['hostname'] = hostname
            except:
                pass
            
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout for {ip}")
            scan_result['state'] = 'timeout'
        except Exception as e:
            logger.error(f"Scan failed for {ip}: {e}")
            scan_result['state'] = 'error'
        
        return scan_result
    
    def _parse_nmap_xml(self, xml_data: str, result: Dict) -> Dict:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_data)
            
            # Get host element
            host = root.find('.//host')
            if not host:
                return result
            
            # Get MAC address
            mac_addr = host.find('.//address[@addrtype="mac"]')
            if mac_addr is not None:
                result['mac_address'] = mac_addr.get('addr')
                vendor = mac_addr.get('vendor')
                if vendor:
                    result['vendor'] = vendor
            
            # Get OS detection
            osmatch = host.find('.//osmatch')
            if osmatch is not None:
                result['os'] = osmatch.get('name')
                result['os_accuracy'] = osmatch.get('accuracy')
            
            # Get ports and services
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_info = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': 'open'
                    }
                    
                    # Get service info
                    service = port.find('service')
                    if service is not None:
                        port_info['service'] = service.get('name')
                        port_info['product'] = service.get('product')
                        port_info['version'] = service.get('version')
                        port_info['extrainfo'] = service.get('extrainfo')
                    
                    result['ports'].append(port_info)
                    
                    # Get script output (vulnerabilities)
                    for script in port.findall('.//script'):
                        script_id = script.get('id')
                        output = script.get('output', '')
                        
                        # Parse CVEs from vulners script
                        if 'vulners' in script_id or 'CVE' in output:
                            cves = self._extract_cves(output)
                            result['cves'].extend(cves)
            
            # Get host-level scripts
            for script in host.findall('.//script'):
                output = script.get('output', '')
                if 'CVE' in output or 'vulnerability' in output.lower():
                    cves = self._extract_cves(output)
                    result['cves'].extend(cves)
            
            # Remove duplicate CVEs
            seen = set()
            unique_cves = []
            for cve in result['cves']:
                cve_id = cve.get('id')
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    unique_cves.append(cve)
            result['cves'] = unique_cves
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")
        
        return result
    
    def _extract_cves(self, text: str) -> List[Dict]:
        """Extract CVE information from text"""
        cves = []
        
        # Pattern for CVE IDs
        cve_pattern = re.compile(r'(CVE-\d{4}-\d+)')
        
        # Pattern for CVSS scores
        cvss_pattern = re.compile(r'CVSS[:\s]+(\d+\.?\d*)')
        
        # Find all CVE IDs
        cve_ids = cve_pattern.findall(text)
        
        for cve_id in cve_ids:
            cve_info = {
                'id': cve_id,
                'cvss': None,
                'description': None
            }
            
            # Try to find CVSS score near this CVE
            cve_pos = text.find(cve_id)
            nearby_text = text[max(0, cve_pos-50):min(len(text), cve_pos+200)]
            
            cvss_match = cvss_pattern.search(nearby_text)
            if cvss_match:
                try:
                    cve_info['cvss'] = float(cvss_match.group(1))
                except:
                    pass
            
            # Extract description (simplified)
            lines = nearby_text.split('\n')
            for line in lines:
                if cve_id in line:
                    cve_info['description'] = line.strip()[:200]
                    break
            
            cves.append(cve_info)
        
        return cves
    
    def parallel_scan(self, hosts: List[str], max_workers: int = 10) -> List[Dict]:
        """Scan multiple hosts in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(self.scan_host, host): host 
                for host in hosts
            }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result(timeout=300)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to scan {host}: {e}")
                    results.append({
                        'ip': host,
                        'state': 'error',
                        'error': str(e)
                    })
        
        return results

