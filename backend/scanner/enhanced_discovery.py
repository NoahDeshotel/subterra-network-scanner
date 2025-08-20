"""
Enhanced Network Discovery Engine
Inspired by Netdisco's multi-protocol discovery approach
Combines SNMP, Nmap, and device APIs for comprehensive network mapping
"""

import asyncio
import logging
import socket
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import json
import time
from .scan_progress_tracker import get_scan_tracker, ScanStage, ScanPriority

try:
    from pysnmp.hlapi import *
    from pysnmp.error import PySnmpError
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("SNMP libraries not available. Install with: pip install pysnmp")

logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Enhanced device information structure"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None  # router, switch, server, workstation, etc.
    ports: List[Dict] = None
    interfaces: List[Dict] = None
    neighbors: List[Dict] = None  # CDP/LLDP neighbors
    uptime: Optional[int] = None
    location: Optional[str] = None
    contact: Optional[str] = None
    description: Optional[str] = None
    vlan_info: List[Dict] = None
    routing_table: List[Dict] = None
    arp_table: List[Dict] = None
    bridge_table: List[Dict] = None
    discovered_by: List[str] = None  # Methods used to discover
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if self.interfaces is None:
            self.interfaces = []
        if self.neighbors is None:
            self.neighbors = []
        if self.vlan_info is None:
            self.vlan_info = []
        if self.routing_table is None:
            self.routing_table = []
        if self.arp_table is None:
            self.arp_table = []
        if self.bridge_table is None:
            self.bridge_table = []
        if self.discovered_by is None:
            self.discovered_by = []

class EnhancedNetworkDiscovery:
    """
    Enhanced network discovery engine that combines multiple discovery methods
    like Netdisco for comprehensive network mapping
    """
    
    def __init__(self):
        self.discovered_devices: Dict[str, DeviceInfo] = {}
        self.discovery_methods = []
        
        # Initialize available discovery methods
        if SNMP_AVAILABLE:
            self.discovery_methods.append('snmp')
        self.discovery_methods.extend(['nmap', 'arp', 'ping'])
        
        # OID mappings for SNMP discovery
        self.snmp_oids = {
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysObjectID': '1.3.6.1.2.1.1.2.0',
            'ifTable': '1.3.6.1.2.1.2.2.1',  # Interface table
            'ipAddrTable': '1.3.6.1.2.1.4.20.1',  # IP address table
            'ipNetToMediaTable': '1.3.6.1.2.1.4.22.1',  # ARP table
            'dot1dBridge': '1.3.6.1.2.1.17',  # Bridge MIB
            'lldpRemTable': '1.0.8802.1.1.2.1.4.1.1',  # LLDP neighbors
            'cdpCacheTable': '1.3.6.1.4.1.9.9.23.1.2.1.1'  # CDP neighbors (Cisco)
        }
        
        # Device type classification patterns
        self.device_patterns = {
            'router': [
                r'cisco.*router', r'juniper.*router', r'mikrotik.*router',
                r'router', r'gateway', r'edge'
            ],
            'switch': [
                r'cisco.*switch', r'hp.*switch', r'dell.*switch',
                r'switch', r'catalyst', r'procurve'
            ],
            'firewall': [
                r'firewall', r'fortigate', r'palo.*alto', r'checkpoint',
                r'sonicwall', r'asa', r'pix'
            ],
            'access_point': [
                r'access.*point', r'wireless', r'wifi', r'ap\d+',
                r'unifi', r'aruba.*ap'
            ],
            'server': [
                r'server', r'linux', r'windows.*server', r'ubuntu.*server',
                r'centos', r'redhat', r'esxi', r'vmware'
            ],
            'workstation': [
                r'windows.*\d+', r'macos', r'desktop', r'laptop',
                r'workstation', r'pc'
            ],
            'printer': [
                r'printer', r'hp.*laserjet', r'canon', r'epson',
                r'lexmark', r'xerox'
            ],
            'iot': [
                r'camera', r'sensor', r'thermostat', r'lighting',
                r'smart', r'iot'
            ]
        }
        
        logger.info(f"Enhanced discovery initialized with methods: {self.discovery_methods}")
    
    async def discover_network(self, subnet: str, deep_scan: bool = False, scan_id: str = None) -> Dict[str, DeviceInfo]:
        """
        Comprehensive network discovery using multiple methods with detailed progress tracking
        """
        tracker = get_scan_tracker()
        
        if not scan_id:
            scan_id = f"scan_{int(time.time())}"
        
        # Calculate total estimated hosts
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_hosts = min(254, network.num_addresses - 2)  # Exclude network and broadcast
        except:
            total_hosts = 254
        
        # Start progress tracking
        tracker.start_scan(scan_id, total_hosts, {
            "subnet": subnet,
            "deep_scan": deep_scan,
            "discovery_methods": self.discovery_methods
        })
        
        try:
            # Phase 1: Network Discovery - Quick host discovery
            tracker.update_stage(scan_id, ScanStage.NETWORK_DISCOVERY, "Discovering network structure...")
            tracker.log_info(scan_id, f"Starting enhanced network discovery for subnet: {subnet}")
            
            live_hosts = await self._discover_live_hosts(subnet, scan_id)
            tracker.log_info(scan_id, f"Phase 1: Discovered {len(live_hosts)} live hosts")
            
            # Phase 2: Host Discovery - Detailed scanning
            tracker.update_stage(scan_id, ScanStage.HOST_DISCOVERY, "Scanning discovered hosts...")
            
            discovery_tasks = []
            for i, host in enumerate(live_hosts):
                tracker.update_step(scan_id, f"Preparing scan for {host}", i, len(live_hosts), host)
                discovery_tasks.append(self._discover_device_details(host, deep_scan, scan_id))
            
            if discovery_tasks:
                # Process hosts in batches to avoid overwhelming the network
                batch_size = 10
                for i in range(0, len(discovery_tasks), batch_size):
                    batch = discovery_tasks[i:i+batch_size]
                    batch_hosts = live_hosts[i:i+batch_size]
                    
                    tracker.update_step(
                        scan_id, 
                        f"Scanning batch {i//batch_size + 1}/{(len(discovery_tasks) + batch_size - 1)//batch_size}",
                        i,
                        len(discovery_tasks)
                    )
                    
                    try:
                        await asyncio.gather(*batch, return_exceptions=True)
                    except Exception as e:
                        tracker.log_error(scan_id, f"Error in batch processing: {str(e)}")
                    
                    tracker.update_target_progress(scan_id, min(i + batch_size, len(live_hosts)))
            
            # Phase 3: Topology discovery (if SNMP devices found and deep scan requested)
            if deep_scan:
                tracker.update_stage(scan_id, ScanStage.TOPOLOGY_MAPPING, "Mapping network topology...")
                await self._discover_topology(scan_id)
            
            # Phase 4: Data processing
            tracker.update_stage(scan_id, ScanStage.DATA_PROCESSING, "Processing discovery results...")
            await asyncio.sleep(0.1)  # Brief pause for final processing
            
            # Complete the scan
            tracker.complete_scan(scan_id, True, f"Discovery complete. Found {len(self.discovered_devices)} devices")
            
        except Exception as e:
            tracker.log_error(scan_id, f"Discovery failed: {str(e)}")
            tracker.complete_scan(scan_id, False, f"Discovery failed: {str(e)}")
            raise
        
        return self.discovered_devices
    
    async def _discover_live_hosts(self, subnet: str, scan_id: str = None) -> List[str]:
        """
        Discover live hosts using multiple methods with progress tracking
        """
        tracker = get_scan_tracker()
        live_hosts = set()
        
        # Calculate expected host count for progress tracking
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_possible_hosts = len(list(network.hosts()))
            if scan_id:
                tracker.log_info(scan_id, f"Scanning subnet {subnet} ({total_possible_hosts} possible hosts)")
        except:
            total_possible_hosts = 254
        
        discovery_methods = [
            ("ARP table scanning", self._scan_arp_table),
            ("Ping sweep", self._ping_sweep),
            ("Nmap discovery", self._nmap_discovery)
        ]
        
        for i, (method_name, method_func) in enumerate(discovery_methods):
            if scan_id:
                tracker.update_step(scan_id, f"Running {method_name}...", i, len(discovery_methods))
                tracker.log_info(scan_id, f"Starting {method_name} for {subnet}")
            
            try:
                logger.info(f"Starting {method_name} for {subnet}")
                hosts = await method_func(subnet)
                live_hosts.update(hosts)
                
                if scan_id:
                    tracker.log_info(scan_id, f"{method_name} completed: found {len(hosts)} hosts (total unique: {len(live_hosts)})")
                logger.info(f"{method_name} completed: found {len(hosts)} hosts")
                    
            except Exception as e:
                if scan_id:
                    tracker.log_warning(scan_id, f"{method_name} failed: {str(e)}")
                logger.error(f"{method_name} failed: {e}")
        
        if scan_id:
            tracker.update_step(scan_id, f"Host discovery complete", len(discovery_methods), len(discovery_methods))
            tracker.log_info(scan_id, f"Host discovery completed: {len(live_hosts)} unique hosts found out of {total_possible_hosts} possible")
        
        logger.info(f"Host discovery completed for {subnet}: {len(live_hosts)} unique hosts found")
        return list(live_hosts)
    
    async def _scan_arp_table(self, subnet: str) -> List[str]:
        """
        Scan local ARP table for known hosts
        """
        hosts = []
        try:
            # Get local ARP table
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                network = ipaddress.ip_network(subnet, strict=False)
                for line in result.stdout.split('\n'):
                    # Parse ARP entries: hostname (ip) at mac [ether] on interface
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ipaddress.ip_address(ip) in network:
                            hosts.append(ip)
            
            logger.debug(f"ARP scan found {len(hosts)} hosts")
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
        
        return hosts
    
    async def _ping_sweep(self, subnet: str) -> List[str]:
        """
        Perform ping sweep to find live hosts with proper handling of large subnets
        """
        hosts = []
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            all_hosts = list(network.hosts())
            total_hosts = len(all_hosts)
            
            logger.info(f"Starting ping sweep for {total_hosts} hosts in {subnet}")
            
            # For very large networks, limit the scan or use different strategy
            if total_hosts > 16384:  # More than /18
                logger.warning(f"Large network detected ({total_hosts} hosts). Using sampled ping sweep.")
                # Sample every 64th host for very large networks
                all_hosts = all_hosts[::64]
                total_hosts = len(all_hosts)
            elif total_hosts > 1024:  # More than /22
                logger.info(f"Medium-large network detected ({total_hosts} hosts). Using efficient batch processing.")
            
            # Process in batches to avoid overwhelming the system
            batch_size = 100  # Process 100 hosts at a time
            semaphore = asyncio.Semaphore(50)  # Limit concurrent pings
            
            async def bounded_ping(ip_str):
                async with semaphore:
                    try:
                        result = await self._ping_host(ip_str)
                        return ip_str if result else None
                    except Exception as e:
                        logger.debug(f"Ping failed for {ip_str}: {e}")
                        return None
            
            # Process hosts in batches
            for i in range(0, total_hosts, batch_size):
                batch = all_hosts[i:i + batch_size]
                batch_ips = [str(ip) for ip in batch]
                
                logger.debug(f"Ping sweep batch {i//batch_size + 1}/{(total_hosts + batch_size - 1)//batch_size}: {len(batch)} hosts")
                
                # Process batch
                results = await asyncio.gather(*[bounded_ping(ip_str) for ip_str in batch_ips], 
                                             return_exceptions=True)
                
                # Collect successful pings
                batch_hosts = [ip for ip in results if ip and not isinstance(ip, Exception)]
                hosts.extend(batch_hosts)
                
                if batch_hosts:
                    logger.debug(f"Batch found {len(batch_hosts)} live hosts: {batch_hosts[:5]}{'...' if len(batch_hosts) > 5 else ''}")
                
                # Small delay between batches to be network-friendly
                await asyncio.sleep(0.1)
            
            logger.info(f"Ping sweep completed: found {len(hosts)} live hosts out of {total_hosts} scanned")
            
        except Exception as e:
            logger.error(f"Ping sweep failed: {e}")
        
        return hosts
    
    async def _ping_host(self, ip: str) -> bool:
        """
        Ping a single host to check if it's alive
        """
        try:
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            returncode = await process.wait()
            return returncode == 0
        except:
            return False
    
    async def _nmap_discovery(self, subnet: str) -> List[str]:
        """
        Use Nmap for host discovery with timeout
        """
        hosts = []
        logger.info(f"[NMAP] Starting Nmap discovery for {subnet}")
        try:
            # Add timeout and faster options for large networks
            cmd = ['nmap', '-sn', '-T4', '--min-parallelism', '100', '--max-retries', '1', subnet]
            logger.info(f"[NMAP] Running command: {' '.join(cmd)}")
            
            # Create subprocess with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion with timeout (30 seconds for /24 network)
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=30.0  # 30 second timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"[NMAP] Nmap discovery timed out after 30 seconds for {subnet}")
                process.kill()
                await process.wait()
                return hosts
            
            if process.returncode == 0:
                output = stdout.decode()
                for line in output.split('\n'):
                    if 'Nmap scan report for' in line:
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                        if ip_match:
                            hosts.append(ip_match.group())
                logger.info(f"[NMAP] Discovery found {len(hosts)} hosts")
            else:
                logger.warning(f"[NMAP] Nmap returned non-zero exit code: {process.returncode}")
                if stderr:
                    logger.warning(f"[NMAP] Stderr: {stderr.decode()}")
            
        except FileNotFoundError:
            logger.error(f"[NMAP] Nmap not found - make sure it's installed")
        except Exception as e:
            logger.error(f"[NMAP] Discovery failed: {e}")
        
        return hosts
    
    async def _discover_device_details(self, ip: str, deep_scan: bool = False, scan_id: str = None):
        """
        Discover detailed information about a device with progress tracking
        """
        tracker = get_scan_tracker()
        
        if scan_id:
            tracker.log_info(scan_id, f"Starting detailed scan of {ip}")
        
        device = DeviceInfo(ip=ip, first_seen=datetime.now(), last_seen=datetime.now())
        
        try:
            # Phase 1: Basic discovery
            if scan_id:
                tracker.update_step(scan_id, f"Basic discovery for {ip}", target=ip)
            
            # Try multiple discovery methods
            discovery_tasks = [
                self._snmp_discovery(device),
                self._nmap_scan(device, deep_scan),
                self._reverse_dns_lookup(device)
            ]
            
            await asyncio.gather(*discovery_tasks, return_exceptions=True)
            
            # Phase 2: Device classification
            if scan_id:
                tracker.update_step(scan_id, f"Classifying device {ip}", target=ip)
            
            device.device_type = self._classify_device(device)
            
            # Store device
            self.discovered_devices[ip] = device
            
            if scan_id:
                tracker.log_info(scan_id, f"Completed detailed scan of {ip}: {device.hostname or 'Unknown'} ({device.device_type})")
            
            logger.debug(f"Discovered device {ip}: {device.hostname or 'Unknown'} ({device.device_type})")
            
        except Exception as e:
            if scan_id:
                tracker.log_error(scan_id, f"Failed to scan {ip}: {str(e)}", target=ip)
            logger.error(f"Failed to discover details for {ip}: {e}")
    
    async def _snmp_discovery(self, device: DeviceInfo):
        """
        Discover device information using SNMP
        """
        if not SNMP_AVAILABLE:
            return
        
        try:
            # Try common SNMP communities
            communities = ['public', 'private', 'community']
            
            for community in communities:
                if await self._snmp_get_device_info(device, community):
                    device.discovered_by.append('snmp')
                    break
        except Exception as e:
            logger.debug(f"SNMP discovery failed for {device.ip}: {e}")
    
    async def _snmp_get_device_info(self, device: DeviceInfo, community: str) -> bool:
        """
        Get device information via SNMP
        """
        try:
            # Basic system information
            for errorIndication, errorStatus, errorIndex, varBinds in getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((device.ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(self.snmp_oids['sysName'])),
                ObjectType(ObjectIdentity(self.snmp_oids['sysDescr'])),
                ObjectType(ObjectIdentity(self.snmp_oids['sysContact'])),
                ObjectType(ObjectIdentity(self.snmp_oids['sysLocation'])),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    return False
                
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = str(oid)
                    
                    if oid_str.endswith('.5.0'):  # sysName
                        device.hostname = str(value)
                    elif oid_str.endswith('.1.0'):  # sysDescr
                        device.description = str(value)
                        # Extract OS and vendor info from description
                        device.os, device.vendor = self._parse_sys_descr(str(value))
                    elif oid_str.endswith('.4.0'):  # sysContact
                        device.contact = str(value)
                    elif oid_str.endswith('.6.0'):  # sysLocation
                        device.location = str(value)
                
                return True
        except Exception as e:
            logger.debug(f"SNMP query failed for {device.ip}: {e}")
            return False
    
    def _parse_sys_descr(self, sys_descr: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Parse system description to extract OS and vendor information
        """
        sys_descr_lower = sys_descr.lower()
        
        # Common vendor patterns
        vendors = {
            'cisco': ['cisco', 'catalyst', 'nexus'],
            'hp': ['hp', 'hewlett', 'procurve'],
            'dell': ['dell', 'powerconnect'],
            'juniper': ['juniper', 'junos'],
            'aruba': ['aruba'],
            'mikrotik': ['mikrotik', 'routeros'],
            'ubiquiti': ['ubiquiti', 'unifi'],
            'netgear': ['netgear'],
            'dlink': ['d-link']
        }
        
        vendor = None
        for v, patterns in vendors.items():
            if any(pattern in sys_descr_lower for pattern in patterns):
                vendor = v
                break
        
        # Extract OS information
        os_info = None
        if 'ios' in sys_descr_lower:
            os_info = 'Cisco IOS'
        elif 'junos' in sys_descr_lower:
            os_info = 'Juniper JUNOS'
        elif 'linux' in sys_descr_lower:
            os_info = 'Linux'
        elif 'windows' in sys_descr_lower:
            os_info = 'Windows'
        
        return os_info, vendor
    
    async def _nmap_scan(self, device: DeviceInfo, deep_scan: bool = False):
        """
        Perform Nmap scan on device
        """
        try:
            cmd = ['nmap', '-A', '-T4']
            if deep_scan:
                cmd.extend(['-p-', '--script=vuln'])
            else:
                cmd.extend(['-F'])  # Fast scan
            cmd.append(device.ip)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self._parse_nmap_output(device, stdout.decode())
                device.discovered_by.append('nmap')
        except Exception as e:
            logger.debug(f"Nmap scan failed for {device.ip}: {e}")
    
    def _parse_nmap_output(self, device: DeviceInfo, output: str):
        """
        Parse Nmap output to extract device information
        """
        lines = output.split('\n')
        current_port = None
        
        for line in lines:
            line = line.strip()
            
            # Parse hostname
            if 'Nmap scan report for' in line:
                hostname_match = re.search(r'for ([^\s(]+)', line)
                if hostname_match and not re.match(r'\d+\.\d+\.\d+\.\d+', hostname_match.group(1)):
                    device.hostname = hostname_match.group(1)
            
            # Parse OS detection
            elif line.startswith('OS:'):
                device.os = line[3:].strip()
            elif 'OS details:' in line:
                device.os = line.split(':', 1)[1].strip()
            
            # Parse MAC address
            elif 'MAC Address:' in line:
                mac_match = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', line)
                if mac_match:
                    device.mac_address = mac_match.group(1)
                
                # Extract vendor from MAC line
                vendor_match = re.search(r'\((.+)\)$', line)
                if vendor_match:
                    device.vendor = vendor_match.group(1)
            
            # Parse open ports
            elif re.match(r'\d+/(tcp|udp)', line):
                port_info = self._parse_port_line(line)
                if port_info:
                    device.ports.append(port_info)
    
    def _parse_port_line(self, line: str) -> Optional[Dict]:
        """
        Parse a port line from Nmap output
        """
        parts = line.split()
        if len(parts) < 2:
            return None
        
        port_proto = parts[0]
        state = parts[1]
        
        port_match = re.match(r'(\d+)/(tcp|udp)', port_proto)
        if not port_match:
            return None
        
        port_info = {
            'port': int(port_match.group(1)),
            'protocol': port_match.group(2),
            'state': state
        }
        
        # Extract service information if available
        if len(parts) > 2:
            port_info['service'] = parts[2]
        
        # Extract version information
        if len(parts) > 3:
            version_info = ' '.join(parts[3:])
            port_info['version'] = version_info
        
        return port_info
    
    async def _reverse_dns_lookup(self, device: DeviceInfo):
        """
        Perform reverse DNS lookup
        """
        try:
            hostname = socket.gethostbyaddr(device.ip)[0]
            if not device.hostname:  # Only set if not already discovered
                device.hostname = hostname
            device.discovered_by.append('dns')
        except:
            pass  # Reverse DNS lookup failed
    
    def _classify_device(self, device: DeviceInfo) -> str:
        """
        Classify device type based on gathered information
        """
        # Combine all available text for classification
        text_to_check = ' '.join(filter(None, [
            device.hostname or '',
            device.description or '',
            device.os or '',
            device.vendor or ''
        ])).lower()
        
        # Check against device patterns
        for device_type, patterns in self.device_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check):
                    return device_type
        
        # Classify based on open ports
        if device.ports:
            port_numbers = [p['port'] for p in device.ports]
            
            # Server-like services
            if any(p in port_numbers for p in [80, 443, 8080, 8443, 3389, 5985]):
                return 'server'
            
            # Network infrastructure
            elif any(p in port_numbers for p in [22, 23, 161, 162, 514]):
                return 'infrastructure'
            
            # Workstation-like
            elif any(p in port_numbers for p in [135, 139, 445, 5357]):
                return 'workstation'
        
        return 'unknown'
    
    async def _discover_topology(self):
        """
        Discover network topology using SNMP (CDP/LLDP)
        """
        if not SNMP_AVAILABLE:
            return
        
        logger.info("Discovering network topology...")
        
        # Find SNMP-capable devices
        snmp_devices = [
            device for device in self.discovered_devices.values()
            if 'snmp' in device.discovered_by
        ]
        
        for device in snmp_devices:
            await self._get_neighbor_info(device)
            await self._get_interface_info(device)
    
    async def _get_neighbor_info(self, device: DeviceInfo):
        """
        Get neighbor information via CDP/LLDP
        """
        # This would implement SNMP walks for CDP and LLDP tables
        # Simplified for brevity
        pass
    
    async def _get_interface_info(self, device: DeviceInfo):
        """
        Get interface information via SNMP
        """
        # This would implement SNMP walks for interface tables
        # Simplified for brevity
        pass
    
    async def _discover_topology(self, scan_id: str = None):
        """
        Discover network topology using SNMP (CDP/LLDP) and other methods
        """
        tracker = get_scan_tracker()
        
        if scan_id:
            tracker.log_info(scan_id, "Starting topology discovery")
        
        if not SNMP_AVAILABLE:
            if scan_id:
                tracker.log_warning(scan_id, "SNMP not available - skipping topology discovery")
            return
        
        # Find SNMP-enabled devices
        snmp_devices = [device for device in self.discovered_devices.values() 
                       if 'snmp' in (device.discovered_by or [])]
        
        if scan_id:
            tracker.log_info(scan_id, f"Found {len(snmp_devices)} SNMP-enabled devices for topology mapping")
        
        try:
            for i, device in enumerate(snmp_devices):
                if scan_id:
                    tracker.update_step(scan_id, f"Mapping neighbors for {device.ip}", i, len(snmp_devices), device.ip)
                
                # Try to get neighbor information via CDP/LLDP
                neighbors = await self._get_device_neighbors(device.ip)
                if neighbors:
                    device.neighbors = neighbors
                    if scan_id:
                        tracker.log_info(scan_id, f"Found {len(neighbors)} neighbors for {device.ip}")
            
            if scan_id:
                tracker.log_info(scan_id, "Topology discovery completed")
                
        except Exception as e:
            if scan_id:
                tracker.log_error(scan_id, f"Topology discovery failed: {str(e)}")
            logger.error(f"Topology discovery failed: {e}")
    
    async def _get_device_neighbors(self, device_ip: str) -> List[Dict]:
        """
        Get device neighbors via SNMP (CDP/LLDP)
        """
        neighbors = []
        
        if not SNMP_AVAILABLE:
            return neighbors
        
        try:
            # Try CDP first (Cisco Discovery Protocol)
            cdp_neighbors = await self._get_cdp_neighbors(device_ip)
            neighbors.extend(cdp_neighbors)
            
            # Try LLDP (Link Layer Discovery Protocol)
            lldp_neighbors = await self._get_lldp_neighbors(device_ip)
            neighbors.extend(lldp_neighbors)
            
        except Exception as e:
            logger.debug(f"Failed to get neighbors for {device_ip}: {e}")
        
        return neighbors
    
    async def _get_cdp_neighbors(self, device_ip: str) -> List[Dict]:
        """
        Get CDP neighbors via SNMP
        """
        neighbors = []
        # CDP implementation would go here
        # This is a placeholder for now
        return neighbors
    
    async def _get_lldp_neighbors(self, device_ip: str) -> List[Dict]:
        """
        Get LLDP neighbors via SNMP
        """
        neighbors = []
        # LLDP implementation would go here
        # This is a placeholder for now
        return neighbors

    def get_discovery_summary(self) -> Dict:
        """
        Get summary of discovery results
        """
        device_types = {}
        vendors = {}
        os_types = {}
        
        for device in self.discovered_devices.values():
            # Count device types
            device_type = device.device_type or 'unknown'
            device_types[device_type] = device_types.get(device_type, 0) + 1
            
            # Count vendors
            vendor = device.vendor or 'unknown'
            vendors[vendor] = vendors.get(vendor, 0) + 1
            
            # Count OS types
            os_type = device.os or 'unknown'
            os_types[os_type] = os_types.get(os_type, 0) + 1
        
        return {
            'total_devices': len(self.discovered_devices),
            'device_types': device_types,
            'vendors': vendors,
            'operating_systems': os_types,
            'discovery_methods': self.discovery_methods
        }
    
    def export_devices(self) -> List[Dict]:
        """
        Export discovered devices as a list of dictionaries
        """
        return [asdict(device) for device in self.discovered_devices.values()]

# Main discovery function for easy import
async def discover_network_enhanced(subnet: str, deep_scan: bool = False, scan_id: str = None) -> Tuple[Dict[str, DeviceInfo], Dict]:
    """
    Main function to perform enhanced network discovery with progress tracking
    
    Args:
        subnet: Network subnet to scan (e.g., '192.168.1.0/24')
        deep_scan: Whether to perform deep scanning with topology discovery
        scan_id: Optional scan ID for progress tracking
    
    Returns:
        Tuple of (discovered_devices, summary)
    """
    logger.info(f"[ENHANCED] Starting enhanced discovery for {subnet}")
    discovery = EnhancedNetworkDiscovery()
    
    try:
        # Set a reasonable timeout based on network size
        network = ipaddress.ip_network(subnet, strict=False)
        num_hosts = network.num_addresses - 2  # Exclude network and broadcast
        
        # Calculate timeout: 1 second per host for quick scan, 5 seconds for deep scan
        # Maximum 5 minutes for any scan
        timeout_seconds = min(300, num_hosts * (5 if deep_scan else 1))
        logger.info(f"[ENHANCED] Scanning {num_hosts} hosts with {timeout_seconds}s timeout")
        
        # Run discovery with timeout
        devices = await asyncio.wait_for(
            discovery.discover_network(subnet, deep_scan, scan_id),
            timeout=timeout_seconds
        )
        
        logger.info(f"[ENHANCED] Discovery completed successfully: {len(devices)} devices found")
        
    except asyncio.TimeoutError:
        logger.warning(f"[ENHANCED] Discovery timed out after {timeout_seconds} seconds")
        # Return what we have so far
        devices = discovery.discovered_devices
        
    except Exception as e:
        logger.error(f"[ENHANCED] Discovery failed: {e}")
        devices = {}
    
    summary = discovery.get_discovery_summary()
    summary['scan_successful'] = len(devices) > 0 or not isinstance(devices, dict)
    
    return devices, summary

if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        devices, summary = await discover_network_enhanced("192.168.1.0/24", deep_scan=True)
        
        print(f"Discovery Summary:")
        print(f"Total devices: {summary['total_devices']}")
        print(f"Device types: {summary['device_types']}")
        print(f"Vendors: {summary['vendors']}")
        
        for ip, device in devices.items():
            print(f"\nDevice: {ip}")
            print(f"  Hostname: {device.hostname}")
            print(f"  Type: {device.device_type}")
            print(f"  Vendor: {device.vendor}")
            print(f"  OS: {device.os}")
            print(f"  Ports: {len(device.ports)} open")
            print(f"  Discovered by: {', '.join(device.discovered_by)}")
    
    asyncio.run(main())
