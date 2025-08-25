#!/usr/bin/env python3
"""
Comprehensive Network Scanner
More aggressive and thorough scanning for maximum data collection
"""

import subprocess
import json
import logging
import socket
import re
import ipaddress
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class ComprehensiveScanner:
    def __init__(self):
        self.max_workers = 10
        
    def scan_network(self, subnet: str, scan_mode: str = 'comprehensive', progress_callback=None) -> Tuple[Dict, Dict]:
        """
        Perform comprehensive network scan with multiple techniques
        """
        logger.info(f"Starting comprehensive scan of {subnet} in {scan_mode} mode")
        start_time = datetime.now()
        
        network = ipaddress.ip_network(subnet, strict=False)
        total_hosts = network.num_addresses - 2
        
        # Step 1: ARP scan for local network (gets MAC addresses)
        logger.info("Step 1: ARP discovery")
        if progress_callback:
            progress_callback(None, 5, f"Performing ARP discovery on {subnet}")
        arp_results = self._arp_scan(subnet)
        
        # Step 2: Comprehensive nmap scan with OS detection and service version
        logger.info("Step 2: Comprehensive nmap scan")
        if progress_callback:
            progress_callback(None, 20, f"Running comprehensive scan on {len(arp_results)} hosts")
        nmap_results = self._comprehensive_nmap_scan(subnet, scan_mode)
        
        # Step 3: Merge results and enhance
        logger.info("Step 3: Merging and enhancing results")
        if progress_callback:
            progress_callback(None, 80, "Processing and enhancing results")
        devices = self._merge_and_enhance_results(arp_results, nmap_results, progress_callback)
        
        # Step 4: Additional enrichment
        logger.info("Step 4: Additional enrichment")
        if progress_callback:
            progress_callback(None, 90, "Performing additional enrichment")
        devices = self._enrich_devices(devices)
        
        if progress_callback:
            progress_callback(None, 100, f"Scan complete: {len(devices)} devices found")
        
        summary = {
            'scan_successful': True,
            'devices_found': len(devices),
            'scan_duration': (datetime.now() - start_time).total_seconds(),
            'scan_mode': scan_mode,
            'subnet': subnet
        }
        
        return devices, summary
    
    def _arp_scan(self, subnet: str) -> Dict:
        """
        Perform ARP scan to get MAC addresses and ensure all hosts are found
        """
        devices = {}
        try:
            # Try without sudo first
            cmd = ['arp-scan', '--local', '--retry=2', '--timeout=500', subnet]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode != 0:
                # Try with sudo
                cmd = ['sudo', 'arp-scan', '--local', '--retry=3', '--timeout=2000', subnet]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Parse arp-scan output: IP MAC Vendor
                    match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)', line)
                    if match:
                        ip, mac, vendor = match.groups()
                        devices[ip] = {
                            'ip': ip,
                            'mac_address': mac.upper(),
                            'vendor': vendor.strip() if vendor else self._lookup_vendor(mac),
                            'discovery_method': 'arp'
                        }
            else:
                # Fallback to nmap ARP scan
                devices = self._nmap_arp_scan(subnet)
                
        except FileNotFoundError:
            # arp-scan not installed, use nmap
            devices = self._nmap_arp_scan(subnet)
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
            
        return devices
    
    def _nmap_arp_scan(self, subnet: str) -> Dict:
        """
        Use nmap for ARP scanning
        """
        devices = {}
        try:
            # Try without sudo first
            cmd = ['nmap', '-sn', '-PR', subnet, '-oX', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                # Try with sudo
                cmd = ['sudo', 'nmap', '-sn', '-PR', subnet, '-oX', '-']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                root = ET.fromstring(result.stdout)
                for host in root.findall('.//host'):
                    if host.find('.//status[@state="up"]') is not None:
                        ip_elem = host.find('.//address[@addrtype="ipv4"]')
                        mac_elem = host.find('.//address[@addrtype="mac"]')
                        
                        if ip_elem is not None:
                            ip = ip_elem.get('addr')
                            device = {'ip': ip, 'discovery_method': 'nmap-arp'}
                            
                            if mac_elem is not None:
                                mac = mac_elem.get('addr', '').upper()
                                vendor = mac_elem.get('vendor', '')
                                device['mac_address'] = mac
                                device['vendor'] = vendor or self._lookup_vendor(mac)
                            
                            devices[ip] = device
                            
        except Exception as e:
            logger.error(f"Nmap ARP scan failed: {e}")
            
        return devices
    
    def _comprehensive_nmap_scan(self, subnet: str, scan_mode: str) -> Dict:
        """
        Perform comprehensive nmap scan with OS detection and service version
        """
        devices = {}
        
        try:
            # Build nmap command based on scan mode
            # Try without sudo first, then with sudo if needed
            use_sudo = False
            cmd = ['nmap']
            
            if scan_mode == 'comprehensive':
                # Comprehensive scan - optimized for network environment
                cmd.extend([
                    '-sS',          # SYN scan
                    '-sV',          # Service version detection
                    '--version-intensity', '5',  # Moderate version detection
                    '-p', '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',  # Key ports
                    '--open',       # Only show open ports
                    '-T4',          # Aggressive timing
                    '--max-retries', '1',
                    '--host-timeout', '60s'
                ])
            elif scan_mode == 'balanced':
                # Balanced scan
                cmd.extend([
                    '-sS',          # SYN scan
                    '-O',           # OS detection  
                    '-sV',          # Service version detection
                    '-p', '1-10000',  # Common ports
                    '--open',
                    '-T4'
                ])
            else:  # quick
                # Quick scan
                cmd.extend([
                    '-sS',
                    '-sV',
                    '-F',           # Fast scan (top 100 ports)
                    '--open',
                    '-T4'
                ])
            
            # Add subnet and output format
            cmd.extend([subnet, '-oX', '-'])
            
            logger.info(f"Running nmap command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # If failed and permission denied, retry with sudo
            if result.returncode != 0 and ('Permission denied' in result.stderr or 'Operation not permitted' in result.stderr):
                logger.info("Retrying with sudo due to permission issues")
                cmd = ['sudo'] + cmd
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                devices = self._parse_nmap_xml(result.stdout)
            else:
                logger.error(f"Nmap scan failed: {result.stderr}")
                # Fallback to basic scan without OS detection
                logger.info("Falling back to basic nmap scan")
                cmd = ['nmap', '-sS', '-sV', '-F', '--open', subnet, '-oX', '-']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    devices = self._parse_nmap_xml(result.stdout)
                
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
        except Exception as e:
            logger.error(f"Comprehensive nmap scan failed: {e}")
            
        return devices
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """
        Parse nmap XML output for comprehensive data
        """
        devices = {}
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('.//host'):
                if host.find('.//status[@state="up"]') is None:
                    continue
                    
                device = {}
                
                # Get IP address
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is None:
                    continue
                ip = ip_elem.get('addr')
                device['ip'] = ip
                
                # Get MAC address
                mac_elem = host.find('.//address[@addrtype="mac"]')
                if mac_elem is not None:
                    device['mac_address'] = mac_elem.get('addr', '').upper()
                    device['vendor'] = mac_elem.get('vendor', '')
                
                # Get hostnames
                hostnames = []
                for hostname in host.findall('.//hostname'):
                    name = hostname.get('name')
                    if name:
                        hostnames.append(name)
                if hostnames:
                    device['hostname'] = hostnames[0]
                    device['all_hostnames'] = hostnames
                
                # Get OS information
                os_matches = []
                for osmatch in host.findall('.//osmatch'):
                    os_info = {
                        'name': osmatch.get('name', ''),
                        'accuracy': int(osmatch.get('accuracy', 0))
                    }
                    os_matches.append(os_info)
                    
                if os_matches:
                    best_os = max(os_matches, key=lambda x: x['accuracy'])
                    device['os'] = best_os['name']
                    device['os_accuracy'] = best_os['accuracy']
                    device['all_os_matches'] = os_matches
                
                # Get open ports and services
                ports = []
                for port in host.findall('.//port'):
                    state = port.find('.//state')
                    if state is None or state.get('state') != 'open':
                        continue
                        
                    port_info = {
                        'port': int(port.get('portid')),
                        'protocol': port.get('protocol', 'tcp'),
                        'state': 'open'
                    }
                    
                    # Get service information
                    service = port.find('.//service')
                    if service is not None:
                        port_info['service'] = service.get('name', '')
                        port_info['product'] = service.get('product', '')
                        port_info['version'] = service.get('version', '')
                        port_info['extrainfo'] = service.get('extrainfo', '')
                        
                        # Get service fingerprint
                        if service.get('servicefp'):
                            port_info['fingerprint'] = service.get('servicefp')
                    
                    # Get scripts output
                    scripts = {}
                    for script in port.findall('.//script'):
                        scripts[script.get('id')] = script.get('output', '')
                    if scripts:
                        port_info['scripts'] = scripts
                    
                    ports.append(port_info)
                
                device['open_ports'] = [p['port'] for p in ports]
                device['ports'] = ports
                
                # Get script results (host level)
                host_scripts = {}
                for script in host.findall('.//hostscript/script'):
                    host_scripts[script.get('id')] = script.get('output', '')
                if host_scripts:
                    device['host_scripts'] = host_scripts
                
                devices[ip] = device
                
        except Exception as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            
        return devices
    
    def _merge_and_enhance_results(self, arp_results: Dict, nmap_results: Dict, progress_callback=None) -> Dict:
        """
        Merge ARP and nmap results, preferring more complete data
        """
        devices = {}
        
        # Start with ARP results (has MAC addresses)
        for ip, arp_device in arp_results.items():
            devices[ip] = arp_device.copy()
        
        # Enhance with nmap results
        for ip, nmap_device in nmap_results.items():
            if ip in devices:
                # Merge, preferring nmap data but keeping ARP MAC if not in nmap
                for key, value in nmap_device.items():
                    if key == 'mac_address' and not value and 'mac_address' in devices[ip]:
                        continue  # Keep ARP MAC
                    devices[ip][key] = value
            else:
                devices[ip] = nmap_device
        
        # Add any devices only found by nmap
        for ip in nmap_results:
            if ip not in devices:
                devices[ip] = nmap_results[ip]
        
        return devices
    
    def _enrich_devices(self, devices: Dict) -> Dict:
        """
        Perform additional enrichment on discovered devices
        """
        for ip, device in devices.items():
            # Try to resolve hostname if not present
            if 'hostname' not in device or not device.get('hostname'):
                hostname = self._resolve_hostname(ip)
                if hostname:
                    device['hostname'] = hostname
            
            # Identify device type based on comprehensive data
            device['device_type'] = self._identify_device_type(device)
            
            # Clean up OS name
            if 'os' in device:
                device['os'] = self._clean_os_name(device['os'])
            
            # Add risk assessment
            device['risk_level'] = self._assess_risk(device)
            
            # Add discovery timestamp
            device['discovered_at'] = datetime.now().isoformat()
            
        return devices
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """
        Try to resolve hostname for IP
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None
    
    def _identify_device_type(self, device: Dict) -> str:
        """
        Identify device type based on comprehensive data
        """
        hostname = device.get('hostname', '').lower()
        os_name = device.get('os', '').lower()
        ports = device.get('open_ports', [])
        services = [p.get('service', '') for p in device.get('ports', [])]
        vendor = device.get('vendor', '').lower()
        
        # Router detection
        if any(x in hostname for x in ['router', 'gateway', 'gw.', '.1']):
            return 'router'
        if 'router' in vendor or 'cisco' in vendor or 'juniper' in vendor:
            return 'router'
        if device.get('ip', '').endswith('.1'):
            if any(p in ports for p in [80, 443, 22, 23]):
                return 'router'
        
        # Printer detection
        if any(x in hostname for x in ['printer', 'prn', 'hp', 'canon', 'epson']):
            return 'printer'
        if 9100 in ports or 631 in ports:
            return 'printer'
        if any(x in vendor for x in ['hewlett', 'canon', 'epson', 'brother', 'xerox']):
            return 'printer'
        
        # Server detection
        if 'server' in hostname or 'srv' in hostname:
            if 'web' in hostname or 80 in ports or 443 in ports:
                return 'web_server'
            elif 'mail' in hostname or any(p in ports for p in [25, 110, 143]):
                return 'mail_server'
            elif 'db' in hostname or any(p in ports for p in [3306, 5432, 1433]):
                return 'database_server'
            return 'server'
        
        # Database server
        if any(p in ports for p in [3306, 5432, 1433, 1521, 27017]):
            return 'database_server'
        
        # Web server
        if any(p in ports for p in [80, 443, 8080, 8443]):
            if 'nginx' in ' '.join(services) or 'apache' in ' '.join(services):
                return 'web_server'
            if len(ports) > 3:  # Multiple services
                return 'web_server'
        
        # NAS/Storage
        if any(x in hostname for x in ['nas', 'storage', 'synology', 'qnap']):
            return 'nas'
        if 'synology' in vendor or 'qnap' in vendor:
            return 'nas'
        if all(p in ports for p in [139, 445]):  # SMB
            return 'nas'
        
        # Mobile device
        if 'android' in os_name or 'ios' in os_name:
            return 'mobile_device'
        if any(x in hostname for x in ['iphone', 'ipad', 'android', 'phone']):
            return 'mobile_device'
        
        # IoT device
        if 'embedded' in os_name or 'linux 2.' in os_name:
            if len(ports) <= 2:
                return 'iot_device'
        
        # Workstation detection based on OS
        if 'windows' in os_name:
            if 3389 in ports:  # RDP
                return 'workstation'
            if 'windows 10' in os_name or 'windows 11' in os_name:
                return 'workstation'
        elif 'mac' in os_name or 'darwin' in os_name:
            return 'workstation'
        elif 'ubuntu' in os_name or 'debian' in os_name:
            if 22 in ports and len(ports) < 5:
                return 'workstation'
        
        # Default based on services
        if ports:
            if any(p in ports for p in [80, 443, 8080]):
                return 'web_server'
            elif 22 in ports:
                return 'server'
        
        return 'unknown'
    
    def _clean_os_name(self, os_name: str) -> str:
        """
        Clean up OS name for display
        """
        # Extract main OS from detailed string
        if 'Microsoft Windows' in os_name:
            if 'Windows 10' in os_name:
                return 'Windows 10'
            elif 'Windows 11' in os_name:
                return 'Windows 11'
            elif 'Server 2019' in os_name:
                return 'Windows Server 2019'
            elif 'Server 2016' in os_name:
                return 'Windows Server 2016'
            else:
                return 'Windows'
        elif 'Linux' in os_name:
            if 'Ubuntu' in os_name:
                return 'Ubuntu Linux'
            elif 'Debian' in os_name:
                return 'Debian Linux'
            elif 'CentOS' in os_name:
                return 'CentOS Linux'
            elif 'Red Hat' in os_name or 'RHEL' in os_name:
                return 'Red Hat Linux'
            else:
                return 'Linux'
        elif 'Mac OS X' in os_name or 'Darwin' in os_name:
            return 'macOS'
        elif 'FreeBSD' in os_name:
            return 'FreeBSD'
        elif 'Cisco' in os_name:
            return 'Cisco IOS'
        
        # Return first 30 chars if nothing matches
        return os_name[:30] if len(os_name) > 30 else os_name
    
    def _assess_risk(self, device: Dict) -> str:
        """
        Assess security risk level of device
        """
        ports = device.get('open_ports', [])
        
        # Critical risk ports
        critical_ports = {23, 21, 139, 445, 3389, 5900}  # Telnet, FTP, SMB, RDP, VNC
        if any(p in ports for p in critical_ports):
            return 'high'
        
        # Many open ports
        if len(ports) > 20:
            return 'high'
        elif len(ports) > 10:
            return 'medium'
        elif len(ports) > 5:
            return 'low'
        
        return 'low'
    
    def _lookup_vendor(self, mac: str) -> str:
        """
        Lookup vendor from MAC address OUI database
        """
        # This would normally query an OUI database
        # For now, return based on common prefixes
        if not mac:
            return 'Unknown'
            
        mac_prefix = mac[:8].upper().replace(':', '')
        
        vendors = {
            '00059A': 'Cisco',
            '0011BB': 'Cisco', 
            '00E0FC': 'Cisco',
            '001B11': 'D-Link',
            '001CF0': 'D-Link',
            '0015E9': 'D-Link',
            '00C0CA': 'Netgear',
            '20E52A': 'Netgear',
            '000FB5': 'Netgear',
            '001E8C': 'Asus',
            '000EA6': 'Asus',
            'BCEE7B': 'Asus',
            '18A6F7': 'TP-Link',
            'F4EC38': 'TP-Link',
            '50C7BF': 'TP-Link'
        }
        
        for prefix, vendor in vendors.items():
            if mac_prefix.startswith(prefix):
                return vendor
                
        return 'Unknown'


def test_comprehensive_scan():
    """Test the comprehensive scanner"""
    scanner = ComprehensiveScanner()
    
    def progress(scan_id, pct, msg):
        print(f"[{pct}%] {msg}")
    
    devices, summary = scanner.scan_network('10.0.0.0/24', 'balanced', progress)
    
    print(f"\nFound {len(devices)} devices:")
    for ip, device in sorted(devices.items()):
        print(f"\n{ip}:")
        print(f"  Hostname: {device.get('hostname', 'Unknown')}")
        print(f"  MAC: {device.get('mac_address', 'Unknown')}")
        print(f"  Vendor: {device.get('vendor', 'Unknown')}")
        print(f"  OS: {device.get('os', 'Unknown')}")
        print(f"  Type: {device.get('device_type', 'Unknown')}")
        print(f"  Open Ports: {device.get('open_ports', [])}")
        if device.get('ports'):
            for port in device['ports'][:5]:  # Show first 5 ports
                print(f"    Port {port['port']}/{port['protocol']}: {port.get('service', 'unknown')}")


if __name__ == '__main__':
    test_comprehensive_scan()