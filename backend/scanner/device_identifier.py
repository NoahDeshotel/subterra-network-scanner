#!/usr/bin/env python3
"""
Device Identification Module
Identifies device type, OS, vendor based on discovered information
"""

import socket
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class DeviceIdentifier:
    """Device identification based on network characteristics"""
    
    def __init__(self):
        pass
    
    def identify_device_type(self, open_ports: List[int], hostname: str = None) -> str:
        """
        Identify device type based on open ports and hostname
        
        Returns device type string
        """
        if not open_ports and not hostname:
            return 'unknown'
        
        # Convert ports to set for faster lookup
        port_set = set(open_ports) if open_ports else set()
        
        # Check hostname patterns first (most reliable)
        if hostname:
            hostname_lower = hostname.lower()
            
            # Router/Gateway patterns
            if any(x in hostname_lower for x in ['router', 'gateway', 'gw', 'rtr', 'firewall', 'fw']):
                return 'router'
            
            # Printer patterns
            if any(x in hostname_lower for x in ['printer', 'print', 'hp', 'canon', 'epson', 'brother']):
                return 'printer'
            
            # Server patterns
            if any(x in hostname_lower for x in ['server', 'srv', 'dc', 'domain']):
                if 'web' in hostname_lower:
                    return 'web_server'
                elif 'mail' in hostname_lower:
                    return 'mail_server'
                elif 'db' in hostname_lower or 'database' in hostname_lower:
                    return 'database_server'
                return 'server'
            
            # NAS patterns
            if any(x in hostname_lower for x in ['nas', 'storage', 'synology', 'qnap', 'backup']):
                return 'nas'
            
            # IoT patterns
            if any(x in hostname_lower for x in ['cam', 'camera', 'iot', 'sensor', 'thermostat']):
                return 'iot_device'
            
            # Phone patterns
            if any(x in hostname_lower for x in ['iphone', 'android', 'phone', 'mobile']):
                return 'mobile_device'
        
        # Port-based identification (when hostname doesn't give clear indication)
        
        # Database server
        if port_set & {3306, 5432, 1433, 1521, 27017}:
            return 'database_server'
        
        # Mail server
        if port_set & {25, 110, 143, 465, 587, 993, 995}:
            return 'mail_server'
        
        # Web server
        if port_set & {80, 443} and (port_set & {22, 21, 3306, 5432}):
            return 'web_server'
        elif port_set & {80, 443, 8080, 8443}:
            return 'web_server'
        
        # Domain controller
        if port_set & {88, 389, 636, 3268, 3269} and (port_set & {135, 139, 445}):
            return 'domain_controller'
        
        # Router/Firewall
        if (23 in port_set or 161 in port_set) and not (3389 in port_set or 22 in port_set):
            return 'router'
        
        # Printer
        if 9100 in port_set or 631 in port_set or 515 in port_set:
            return 'printer'
        
        # NAS/Storage
        if (port_set & {445, 139, 2049}) and (port_set & {80, 443, 5000, 5001}):
            return 'nas'
        
        # Windows workstation
        if 3389 in port_set and (port_set & {135, 139, 445}):
            return 'windows_workstation'
        
        # Linux/Unix server
        if 22 in port_set and not (3389 in port_set):
            if port_set & {80, 443, 3306, 5432}:
                return 'server'
            return 'linux_workstation'
        
        # macOS
        if port_set & {548, 5900} or (port_set & {22, 445} and 3389 not in port_set):
            return 'mac_workstation'
        
        # IoT/Embedded device
        if port_set & {8080, 8443, 81, 8081} and len(port_set) <= 3:
            return 'iot_device'
        
        # Generic server
        if len(port_set) > 5:
            return 'server'
        
        # Generic workstation
        if port_set & {445, 139, 135}:
            return 'workstation'
        
        return 'unknown'
    
    def identify_os(self, open_ports: List[int], hostname: str = None) -> str:
        """
        Identify operating system based on ports and hostname
        
        Returns OS string
        """
        if not open_ports:
            return 'Unknown'
        
        port_set = set(open_ports)
        
        # Windows signatures
        if port_set & {135, 139, 445}:
            if 3389 in port_set:
                # RDP present, likely Windows Server
                if port_set & {88, 389, 636}:
                    return 'Windows Server (DC)'
                return 'Windows Server'
            return 'Windows'
        
        # Just RDP without SMB (could be Windows with firewall)
        if 3389 in port_set:
            return 'Windows'
        
        # macOS signatures
        if port_set & {548, 5900}:  # AFP or VNC
            return 'macOS'
        
        # Linux/Unix signatures
        if 22 in port_set:
            # Check for specific Linux distributions
            if hostname:
                hostname_lower = hostname.lower()
                if 'ubuntu' in hostname_lower:
                    return 'Ubuntu Linux'
                elif 'centos' in hostname_lower:
                    return 'CentOS Linux'
                elif 'debian' in hostname_lower:
                    return 'Debian Linux'
                elif 'rhel' in hostname_lower or 'redhat' in hostname_lower:
                    return 'Red Hat Linux'
            
            # Check for NFS (common on Unix/Linux)
            if port_set & {111, 2049}:
                return 'Linux/Unix'
            
            return 'Linux'
        
        # Network device OS
        if 23 in port_set and 161 in port_set:
            return 'Network OS'
        
        # Embedded/IoT
        if (port_set & {80, 443, 8080, 8443}) and len(port_set) <= 3:
            return 'Embedded/IoT'
        
        # Printer OS
        if 9100 in port_set or 631 in port_set:
            return 'Printer Firmware'
        
        return 'Unknown'
    
    def identify_vendor(self, hostname: str = None, open_ports: List[int] = None, 
                       mac_address: str = None) -> str:
        """
        Identify device vendor based on hostname, ports, and MAC address
        
        Returns vendor string
        """
        # Check hostname patterns
        if hostname:
            hostname_lower = hostname.lower()
            
            # Network vendors
            if 'cisco' in hostname_lower or 'csco' in hostname_lower:
                return 'Cisco'
            if 'juniper' in hostname_lower or 'jnpr' in hostname_lower:
                return 'Juniper'
            if 'aruba' in hostname_lower:
                return 'Aruba'
            if 'fortinet' in hostname_lower or 'fortigate' in hostname_lower:
                return 'Fortinet'
            if 'paloalto' in hostname_lower:
                return 'Palo Alto'
            
            # Computer vendors
            if 'dell' in hostname_lower:
                return 'Dell'
            if 'hp' in hostname_lower or 'hewlett' in hostname_lower:
                return 'HP'
            if 'lenovo' in hostname_lower or 'thinkpad' in hostname_lower:
                return 'Lenovo'
            if 'apple' in hostname_lower or 'macbook' in hostname_lower or 'imac' in hostname_lower:
                return 'Apple'
            
            # Printer vendors
            if 'canon' in hostname_lower:
                return 'Canon'
            if 'epson' in hostname_lower:
                return 'Epson'
            if 'brother' in hostname_lower:
                return 'Brother'
            if 'xerox' in hostname_lower:
                return 'Xerox'
            
            # NAS vendors
            if 'synology' in hostname_lower:
                return 'Synology'
            if 'qnap' in hostname_lower:
                return 'QNAP'
            if 'netgear' in hostname_lower:
                return 'Netgear'
            
            # IoT vendors
            if 'nest' in hostname_lower:
                return 'Google/Nest'
            if 'ring' in hostname_lower or 'amazon' in hostname_lower:
                return 'Amazon'
            if 'sonos' in hostname_lower:
                return 'Sonos'
            if 'roku' in hostname_lower:
                return 'Roku'
            
            # Software vendors (for virtual machines)
            if 'vmware' in hostname_lower:
                return 'VMware'
            if 'hyperv' in hostname_lower or 'azure' in hostname_lower:
                return 'Microsoft'
        
        # MAC address OUI lookup (simplified - you'd want a full OUI database)
        if mac_address and len(mac_address) >= 8:
            mac_prefix = mac_address[:8].upper().replace(':', '').replace('-', '')
            
            # Common MAC prefixes (OUI)
            mac_vendors = {
                '00037F': 'Atheros',
                '00040B': 'Siemens',
                '000D93': 'Apple',
                '001B63': 'Apple',
                '0023DF': 'Apple',
                '00A0C9': '3Com',
                '00E018': 'Cisco',
                '0019E3': 'Cisco',
                '001122': 'Cisco',
                '0050BA': 'HP',
                '3C5282': 'Microsoft',
                '00155D': 'Microsoft (Hyper-V)',
                '00059A': 'Cisco',
                '005056': 'VMware',
                '000C29': 'VMware',
            }
            
            for prefix, vendor in mac_vendors.items():
                if mac_prefix.startswith(prefix):
                    return vendor
        
        # Port-based vendor detection
        if open_ports:
            port_set = set(open_ports)
            
            # Microsoft signatures
            if port_set & {135, 139, 445, 3389}:
                return 'Microsoft'
            
            # Apple signatures
            if port_set & {548, 5900} or (22 in port_set and 548 in port_set):
                return 'Apple'
            
            # VMware signatures
            if 902 in port_set or 903 in port_set:
                return 'VMware'
        
        return 'Unknown'
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """
        Try to resolve hostname for an IP address
        
        Returns hostname or None
        """
        try:
            socket.setdefaulttimeout(1.0)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return None
    
    def identify_device(self, host_info: Dict) -> Dict:
        """
        Complete device identification
        
        Args:
            host_info: Dictionary with host information (ip, ports, etc.)
            
        Returns:
            Enhanced dictionary with device identification
        """
        ip = host_info.get('ip')
        open_ports = host_info.get('open_ports', [])
        hostname = host_info.get('hostname')
        mac_address = host_info.get('mac_address')
        
        # Try to get hostname if not provided
        if not hostname and ip:
            hostname = self.get_hostname(ip)
            if hostname:
                host_info['hostname'] = hostname
        
        # Identify device characteristics
        device_type = self.identify_device_type(open_ports, hostname)
        os = self.identify_os(open_ports, hostname)
        vendor = self.identify_vendor(hostname, open_ports, mac_address)
        
        # Update host info
        host_info['device_type'] = device_type
        host_info['os'] = os
        host_info['vendor'] = vendor
        
        # Add risk assessment
        risk_level = self._assess_risk(open_ports, device_type)
        host_info['risk_level'] = risk_level
        
        return host_info
    
    def _assess_risk(self, open_ports: List[int], device_type: str) -> str:
        """
        Assess security risk level based on open ports and device type
        
        Returns: 'low', 'medium', 'high', 'critical'
        """
        if not open_ports:
            return 'low'
        
        port_set = set(open_ports)
        
        # Critical risk ports
        critical_ports = {23, 21, 139, 445, 3389, 5900, 1433}  # Telnet, FTP, SMB, RDP, VNC, SQL
        if port_set & critical_ports:
            if device_type in ['router', 'server', 'database_server']:
                return 'critical'
            return 'high'
        
        # High risk ports
        high_risk_ports = {22, 3306, 5432, 27017}  # SSH, MySQL, PostgreSQL, MongoDB
        if port_set & high_risk_ports:
            if len(port_set & high_risk_ports) > 1:
                return 'high'
            return 'medium'
        
        # Many open ports
        if len(open_ports) > 10:
            return 'high'
        elif len(open_ports) > 5:
            return 'medium'
        
        return 'low'

# Convenience function
def identify_network_devices(hosts: Dict[str, Dict]) -> Dict[str, Dict]:
    """Identify all devices in a network scan result"""
    identifier = DeviceIdentifier()
    
    for ip, host_info in hosts.items():
        identifier.identify_device(host_info)
    
    return hosts

if __name__ == "__main__":
    # Test device identification
    logging.basicConfig(level=logging.INFO)
    
    identifier = DeviceIdentifier()
    
    # Test cases
    test_devices = [
        {'ip': '10.0.0.1', 'open_ports': [80, 443, 22], 'hostname': 'router.local'},
        {'ip': '10.0.0.2', 'open_ports': [445, 139, 3389], 'hostname': 'WIN-SERVER'},
        {'ip': '10.0.0.3', 'open_ports': [22, 80, 3306], 'hostname': 'web-server'},
        {'ip': '10.0.0.4', 'open_ports': [9100], 'hostname': 'HP-Printer'},
    ]
    
    for device in test_devices:
        result = identifier.identify_device(device)
        print(f"\n{result['ip']}:")
        print(f"  Hostname: {result.get('hostname', 'Unknown')}")
        print(f"  Type: {result['device_type']}")
        print(f"  OS: {result['os']}")
        print(f"  Vendor: {result['vendor']}")
        print(f"  Risk: {result['risk_level']}")