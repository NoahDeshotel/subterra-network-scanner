#!/usr/bin/env python3
"""
Advanced Network Scanner Module
Ultra-powerful scanning with comprehensive device discovery and information gathering
"""

import socket
import subprocess
import ipaddress
import threading
import time
import logging
import json
import struct
import re
import os
import asyncio
from typing import Dict, Tuple, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import nmap
import netifaces
from collections import defaultdict

logger = logging.getLogger(__name__)

class AdvancedNetworkScanner:
    """
    Cutting-edge network scanner with multiple discovery methods
    """
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.mac_vendor_db = self._load_mac_vendor_db()
        self.service_signatures = self._load_service_signatures()
        self.os_fingerprints = self._load_os_fingerprints()
        
    def _load_mac_vendor_db(self) -> Dict:
        """Load MAC vendor database for manufacturer identification"""
        return {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:05:69": "VMware",
            "00:1C:42": "Parallels",
            "08:00:27": "Oracle VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:1B:21": "Intel",
            "00:1E:C9": "Apple",
            "00:26:AB": "Cisco",
            "00:0D:B9": "Cisco",
            "00:1A:A1": "Cisco",
            "00:1B:54": "Cisco",
            "00:1C:58": "Cisco",
            "00:22:90": "Cisco",
            "00:23:04": "Cisco",
            "00:24:14": "Cisco",
            "00:26:0A": "Cisco",
            "00:1F:6C": "Cisco",
            "00:21:D8": "Cisco",
            "00:23:5D": "Cisco",
            "00:24:F7": "Cisco",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "E4:5F:01": "Raspberry Pi",
            "28:CD:C1": "Raspberry Pi",
            "00:09:0F": "Fortinet",
            "00:15:5D": "Microsoft Hyper-V",
            "00:03:FF": "Microsoft",
            "00:0D:3A": "Microsoft",
            "00:12:5A": "Microsoft",
            "00:17:FA": "Microsoft",
            "00:50:F2": "Microsoft",
            "00:1D:D8": "Microsoft",
            "60:45:CB": "Microsoft",
            "7C:ED:8D": "Microsoft",
            "00:21:9B": "Dell",
            "00:14:22": "Dell",
            "00:19:B9": "Dell",
            "00:1A:A0": "Dell",
            "00:1C:23": "Dell",
            "00:1E:4F": "Dell",
            "00:21:70": "Dell",
            "00:22:19": "Dell",
            "00:24:E8": "Dell",
            "00:25:64": "Dell",
            "00:26:B9": "Dell",
            "F4:8E:38": "Dell",
            "B0:83:FE": "Dell",
            "14:18:77": "Dell",
            "34:17:EB": "Dell",
            "D4:AE:52": "Dell",
            "00:1B:11": "D-Link",
            "00:05:5D": "D-Link",
            "00:0D:88": "D-Link",
            "00:0F:3D": "D-Link",
            "00:11:95": "D-Link",
            "00:13:46": "D-Link",
            "00:15:E9": "D-Link",
            "00:17:9A": "D-Link",
            "00:19:5B": "D-Link",
            "00:1C:F0": "D-Link",
            "00:1E:58": "D-Link",
            "00:21:91": "D-Link",
            "00:22:B0": "D-Link",
            "00:24:01": "D-Link",
            "00:26:5A": "D-Link",
            "14:D6:4D": "D-Link",
            "1C:7E:E5": "D-Link",
            "28:10:7B": "D-Link",
            "00:04:5A": "Linksys",
            "00:06:25": "Linksys",
            "00:0C:41": "Linksys",
            "00:0F:66": "Linksys",
            "00:12:17": "Linksys",
            "00:13:10": "Linksys",
            "00:14:BF": "Linksys",
            "00:16:B6": "Linksys",
            "00:18:39": "Linksys",
            "00:18:F8": "Linksys",
            "00:1A:70": "Linksys",
            "00:1C:10": "Linksys",
            "00:1D:7E": "Linksys",
            "00:1E:E5": "Linksys",
            "00:21:29": "Linksys",
            "00:22:6B": "Linksys",
            "00:23:69": "Linksys",
            "00:25:9C": "Linksys",
            "20:AA:4B": "Linksys",
            "58:6D:8F": "Linksys",
            "68:7F:74": "Linksys",
            "C0:C1:C0": "Linksys",
            "C0:56:27": "Linksys",
            "00:0A:95": "Apple",
            "00:10:83": "Apple",
            "00:11:24": "Apple",
            "00:14:51": "Apple",
            "00:16:CB": "Apple",
            "00:17:F2": "Apple",
            "00:19:E3": "Apple",
            "00:1B:63": "Apple",
            "00:1C:B3": "Apple",
            "00:1D:4F": "Apple",
            "00:1E:52": "Apple",
            "00:1F:5B": "Apple",
            "00:1F:F3": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:24:36": "Apple",
            "00:25:00": "Apple",
            "00:25:4B": "Apple",
            "00:25:BC": "Apple",
            "00:26:08": "Apple",
            "00:26:4A": "Apple",
            "00:26:B0": "Apple",
            "00:26:BB": "Apple",
            "00:30:65": "Apple",
            "00:3E:E1": "Apple",
            "00:50:E4": "Apple",
            "00:56:CD": "Apple",
            "00:61:71": "Apple",
            "00:6D:52": "Apple",
            "00:88:65": "Apple",
            "00:A0:40": "Apple",
            "00:B3:62": "Apple",
            "00:C6:10": "Apple",
            "00:CD:FE": "Apple",
            "00:D8:3B": "Apple",
            "00:DB:70": "Apple",
            "00:F4:B9": "Apple",
            "00:F7:6F": "Apple",
            "04:0C:CE": "Apple",
            "04:15:52": "Apple",
            "04:1E:64": "Apple",
            "04:26:65": "Apple",
            "04:48:9A": "Apple",
            "04:52:F3": "Apple",
            "04:54:53": "Apple",
            "04:69:F8": "Apple",
            "04:D3:CF": "Apple",
            "04:DB:56": "Apple",
            "04:E5:36": "Apple",
            "04:F1:3E": "Apple",
            "04:F7:E4": "Apple",
            "08:00:07": "Apple",
            "08:66:98": "Apple",
            "08:6D:41": "Apple",
            "08:70:45": "Apple",
            "08:74:02": "Apple",
            "00:11:75": "Intel",
            "00:12:F0": "Intel",
            "00:13:02": "Intel",
            "00:13:20": "Intel",
            "00:13:CE": "Intel",
            "00:13:E8": "Intel",
            "00:15:00": "Intel",
            "00:15:17": "Intel",
            "00:16:6F": "Intel",
            "00:16:76": "Intel",
            "00:16:EA": "Intel",
            "00:16:EB": "Intel",
            "00:18:DE": "Intel",
            "00:19:D1": "Intel",
            "00:19:D2": "Intel",
            "00:1A:92": "Intel",
            "00:1B:21": "Intel",
            "00:1B:77": "Intel",
            "00:1C:BF": "Intel",
            "00:1C:C0": "Intel",
            "00:1D:E0": "Intel",
            "00:1D:E1": "Intel",
            "00:1E:64": "Intel",
            "00:1E:65": "Intel",
            "00:1E:67": "Intel",
            "00:1F:3A": "Intel",
            "00:1F:3B": "Intel",
            "00:1F:3C": "Intel",
            "00:21:5C": "Intel",
            "00:21:5D": "Intel",
            "00:21:6A": "Intel",
            "00:21:6B": "Intel",
            "00:22:FA": "Intel",
            "00:22:FB": "Intel",
            "00:23:14": "Intel",
            "00:23:15": "Intel",
            "00:24:D6": "Intel",
            "00:24:D7": "Intel",
            "00:26:C6": "Intel",
            "00:26:C7": "Intel",
            "00:27:0E": "Intel",
            "00:27:10": "Intel",
            "00:50:F1": "Intel",
            "00:90:27": "Intel",
            "00:A0:C9": "Intel",
            "00:AA:00": "Intel",
            "00:AA:01": "Intel",
            "00:AA:02": "Intel",
            "00:D0:B7": "Intel",
            "08:11:96": "Intel",
            "08:D4:0C": "Intel",
            "0C:8B:FD": "Intel",
            "0C:D2:92": "Intel",
            "10:0B:A9": "Intel",
            "10:4A:7D": "Intel",
            "18:3D:A2": "Intel",
            "18:5E:0F": "Intel",
            "00:01:42": "Cisco",
            "00:01:43": "Cisco",
            "00:01:63": "Cisco",
            "00:01:64": "Cisco",
            "00:01:96": "Cisco",
            "00:01:97": "Cisco",
            "00:01:C7": "Cisco",
            "00:01:C9": "Cisco",
            "00:02:16": "Cisco",
            "00:02:17": "Cisco",
            "00:02:3D": "Cisco",
            "00:02:4A": "Cisco",
            "00:02:4B": "Cisco",
            "00:02:7D": "Cisco",
            "00:02:7E": "Cisco",
            "00:02:B9": "Cisco",
            "00:02:BA": "Cisco",
            "00:02:FC": "Cisco",
            "00:02:FD": "Cisco",
            "00:03:31": "Cisco",
            "00:03:32": "Cisco",
            "00:03:6B": "Cisco",
            "00:03:6C": "Cisco",
            "00:03:9F": "Cisco",
            "00:03:A0": "Cisco",
            "00:03:E3": "Cisco",
            "00:03:E4": "Cisco",
            "00:03:FD": "Cisco",
            "00:03:FE": "Cisco",
            "00:04:27": "Cisco",
            "00:04:28": "Cisco",
            "00:04:4D": "Cisco",
            "00:04:4E": "Cisco",
            "00:04:6D": "Cisco",
            "00:04:6E": "Cisco",
            "00:04:9A": "Cisco",
            "00:04:9B": "Cisco",
            "00:04:C0": "Cisco",
            "00:04:C1": "Cisco",
            "00:04:DD": "Cisco",
            "00:04:DE": "Cisco",
            "00:05:00": "Cisco",
            "00:05:01": "Cisco",
            "00:05:31": "Cisco",
            "00:05:32": "Cisco",
            "00:05:5E": "Cisco",
            "00:05:5F": "Cisco",
            "00:05:73": "Cisco",
            "00:05:74": "Cisco",
            "00:05:9B": "Cisco",
            "00:05:DC": "Cisco",
            "00:05:DD": "Cisco",
            "00:06:28": "Cisco",
            "00:06:2A": "Cisco",
            "00:06:52": "Cisco",
            "00:06:53": "Cisco",
            "00:06:7C": "Cisco",
            "00:06:C1": "Cisco",
            "00:06:D6": "Cisco",
            "00:06:D7": "Cisco",
            "00:06:F6": "Cisco",
            "00:07:01": "Cisco",
            "00:07:0D": "Cisco",
            "00:07:0E": "Cisco",
            "00:07:4F": "Cisco",
            "00:07:50": "Cisco",
            "00:07:7D": "Cisco",
            "00:07:84": "Cisco",
            "00:07:85": "Cisco",
            "00:07:B3": "Cisco",
            "00:07:B4": "Cisco",
            "00:07:EB": "Cisco",
            "00:07:EC": "Cisco",
            "00:08:20": "Cisco",
            "00:08:21": "Cisco",
            "00:08:2F": "Cisco",
            "00:08:30": "Cisco",
            "00:08:31": "Cisco",
            "00:08:7C": "Cisco",
            "00:08:7D": "Cisco",
            "00:08:A3": "Cisco",
            "00:08:A4": "Cisco",
            "00:08:C2": "Cisco",
            "00:08:E2": "Cisco",
            "00:08:E3": "Cisco",
            "00:09:11": "Cisco",
            "00:09:12": "Cisco",
            "00:09:43": "Cisco",
            "00:09:44": "Cisco",
            "00:09:7B": "Cisco",
            "00:09:7C": "Cisco",
            "00:09:B6": "Cisco",
            "00:09:B7": "Cisco",
            "00:09:E8": "Cisco",
            "00:09:E9": "Cisco",
            "00:0A:41": "Cisco",
            "00:0A:42": "Cisco",
            "00:0A:8A": "Cisco",
            "00:0A:8B": "Cisco",
            "00:0A:B7": "Cisco",
            "00:0A:B8": "Cisco",
            "00:0A:F3": "Cisco",
            "00:0A:F4": "Cisco",
            "00:0B:45": "Cisco",
            "00:0B:46": "Cisco",
            "00:0B:5F": "Cisco",
            "00:0B:60": "Cisco",
            "00:0B:85": "Cisco",
            "00:0B:BE": "Cisco",
            "00:0B:BF": "Cisco",
            "00:0B:FC": "Cisco",
            "00:0B:FD": "Cisco",
            "00:0C:30": "Cisco",
            "00:0C:31": "Cisco",
            "00:0C:85": "Cisco",
            "00:0C:86": "Cisco",
            "00:0C:CE": "Cisco",
            "00:0C:CF": "Cisco",
            "00:0D:28": "Cisco",
            "00:0D:29": "Cisco",
            "00:0D:65": "Cisco",
            "00:0D:66": "Cisco",
            "00:0D:BC": "Cisco",
            "00:0D:BD": "Cisco"
        }
    
    def _load_service_signatures(self) -> Dict:
        """Load service signatures for better service detection"""
        return {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            123: "NTP",
            135: "RPC/DCOM",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-Trap",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            464: "Kerberos",
            465: "SMTPS",
            514: "Syslog",
            515: "LPD",
            548: "AFP",
            554: "RTSP",
            587: "SMTP-Submission",
            631: "IPP/CUPS",
            636: "LDAPS",
            873: "Rsync",
            902: "VMware",
            993: "IMAPS",
            995: "POP3S",
            1080: "SOCKS",
            1194: "OpenVPN",
            1433: "MSSQL",
            1434: "MSSQL-Browser",
            1521: "Oracle",
            1701: "L2TP",
            1723: "PPTP",
            1883: "MQTT",
            2049: "NFS",
            2082: "cPanel",
            2083: "cPanel-SSL",
            2086: "WHM",
            2087: "WHM-SSL",
            2181: "ZooKeeper",
            2222: "SSH-Alt",
            3000: "Dev-Server",
            3128: "Squid-Proxy",
            3306: "MySQL/MariaDB",
            3389: "RDP",
            3690: "SVN",
            4369: "Erlang",
            4443: "HTTPS-Alt",
            4444: "Metasploit",
            5000: "UPnP/Flask",
            5001: "Synology-DSM",
            5060: "SIP",
            5222: "XMPP",
            5269: "XMPP-Server",
            5353: "mDNS",
            5432: "PostgreSQL",
            5555: "ADB",
            5601: "Kibana",
            5672: "AMQP/RabbitMQ",
            5900: "VNC",
            5901: "VNC",
            5902: "VNC",
            5984: "CouchDB",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
            6000: "X11",
            6379: "Redis",
            6443: "Kubernetes-API",
            6666: "IRC",
            6667: "IRC",
            7000: "Cassandra",
            7001: "Cassandra",
            7070: "Realserver",
            7077: "DockerUI",
            8000: "HTTP-Alt",
            8008: "HTTP-Alt",
            8009: "AJP13",
            8020: "HTTP-Alt",
            8080: "HTTP-Proxy",
            8081: "HTTP-Alt",
            8086: "InfluxDB",
            8087: "InfluxDB",
            8088: "HTTP-Alt",
            8089: "Splunk",
            8123: "Home-Assistant",
            8140: "Puppet",
            8181: "HTTP-Alt",
            8200: "Vault",
            8300: "Consul",
            8301: "Consul",
            8302: "Consul",
            8333: "Bitcoin",
            8443: "HTTPS-Alt",
            8444: "HTTPS-Alt",
            8500: "Consul-UI",
            8545: "Ethereum-RPC",
            8600: "Consul-DNS",
            8686: "JMX",
            8787: "Ruby-DRb",
            8834: "Nessus",
            8883: "MQTT-SSL",
            8888: "HTTP-Alt",
            9000: "SonarQube/PHP-FPM",
            9001: "Tor",
            9042: "Cassandra",
            9090: "Prometheus/Cockpit",
            9091: "Transmission",
            9092: "OpenVAS",
            9093: "OpenVAS",
            9100: "JetDirect",
            9160: "Cassandra",
            9200: "Elasticsearch",
            9300: "Elasticsearch",
            9418: "Git",
            9999: "HTTP-Alt",
            10000: "Webmin",
            10050: "Zabbix",
            10051: "Zabbix",
            11211: "Memcached",
            11371: "PGBouncer",
            15672: "RabbitMQ-Management",
            19999: "DNP3",
            25565: "Minecraft",
            27017: "MongoDB",
            27018: "MongoDB",
            27019: "MongoDB",
            32400: "Plex",
            50000: "Jenkins",
            50070: "HDFS",
            54321: "uTorrent",
            55553: "Metasploit",
            61616: "ActiveMQ"
        }
    
    def _load_os_fingerprints(self) -> Dict:
        """Load OS fingerprinting patterns"""
        return {
            "ttl_patterns": {
                64: ["Linux", "macOS", "Android", "iOS"],
                128: ["Windows"],
                255: ["Cisco IOS", "Solaris"],
                254: ["Cisco", "Foundry"],
                60: ["Juniper"]
            },
            "port_patterns": {
                "Windows": [135, 139, 445, 3389, 5985],
                "Linux": [22, 111, 2049],
                "macOS": [22, 548, 631],
                "ESXi": [443, 902, 5989],
                "Cisco": [22, 23, 161],
                "Printer": [9100, 631, 515],
                "NAS": [139, 445, 548, 2049]
            }
        }
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address using ARP"""
        try:
            if platform.system().lower() == 'darwin':
                cmd = ['arp', '-n', ip]
            elif platform.system().lower() == 'linux':
                cmd = ['arp', '-n', ip]
            else:  # Windows
                cmd = ['arp', '-a', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            output = result.stdout
            
            # Extract MAC address from output
            mac_pattern = r'([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}'
            match = re.search(mac_pattern, output)
            if match:
                return match.group().upper().replace('-', ':')
        except Exception as e:
            logger.debug(f"Failed to get MAC for {ip}: {e}")
        return None
    
    def get_mac_vendor(self, mac_address: str) -> str:
        """Identify device manufacturer from MAC address"""
        if not mac_address:
            return "Unknown"
        
        # Get first 3 octets (OUI)
        oui = mac_address[:8].upper()
        
        # Check our database
        for prefix, vendor in self.mac_vendor_db.items():
            if oui.startswith(prefix.upper()):
                return vendor
        
        return "Unknown"
    
    def detect_os_from_ttl(self, ip: str) -> Optional[str]:
        """Detect OS based on TTL value"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', ip]
            else:
                cmd = ['ping', '-c', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            output = result.stdout
            
            # Extract TTL
            ttl_match = re.search(r'ttl[=:]?\s*(\d+)', output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # Map TTL to OS
                for ttl_value, os_list in self.os_fingerprints["ttl_patterns"].items():
                    if ttl <= ttl_value + 5 and ttl >= ttl_value - 5:
                        return os_list[0]
        except Exception as e:
            logger.debug(f"TTL detection failed for {ip}: {e}")
        return None
    
    def detect_os_from_ports(self, open_ports: List[int]) -> Optional[str]:
        """Detect OS based on open port patterns"""
        if not open_ports:
            return None
        
        scores = defaultdict(int)
        for os_name, characteristic_ports in self.os_fingerprints["port_patterns"].items():
            for port in characteristic_ports:
                if port in open_ports:
                    scores[os_name] += 1
        
        if scores:
            return max(scores, key=scores.get)
        return None
    
    def perform_snmp_scan(self, ip: str, community: str = "public") -> Dict:
        """Try to get device info via SNMP"""
        info = {}
        try:
            from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
            
            # System description OID
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=1, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if not errorIndication and not errorStatus:
                for varBind in varBinds:
                    info['snmp_description'] = str(varBind[1])
                    info['snmp_capable'] = True
                    
                    # Try to extract OS info from description
                    desc = str(varBind[1]).lower()
                    if 'windows' in desc:
                        info['os_hint'] = 'Windows'
                    elif 'linux' in desc:
                        info['os_hint'] = 'Linux'
                    elif 'cisco' in desc:
                        info['os_hint'] = 'Cisco IOS'
                        info['device_type_hint'] = 'network_device'
                    elif 'hp' in desc and 'jetdirect' in desc:
                        info['device_type_hint'] = 'printer'
        except Exception:
            pass
        
        return info
    
    def detect_mdns_services(self, ip: str) -> Dict:
        """Detect services advertised via mDNS/Bonjour"""
        services = {}
        try:
            # Quick mDNS probe
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            
            # Check common mDNS services
            mdns_ports = {
                5353: "mDNS",
                5354: "mDNS-Responder",
                9: "WOL",
                1900: "UPnP/SSDP"
            }
            
            for port, service in mdns_ports.items():
                try:
                    sock.sendto(b'', (ip, port))
                    services[port] = service
                except:
                    pass
            
            sock.close()
        except Exception:
            pass
        
        return services
    
    def detect_netbios_info(self, ip: str) -> Dict:
        """Get NetBIOS name and workgroup"""
        info = {}
        try:
            # NetBIOS name query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            # NetBIOS name query packet
            packet = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
                    b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
            
            sock.sendto(packet, (ip, 137))
            
            try:
                data, _ = sock.recvfrom(1024)
                # Parse NetBIOS response (simplified)
                if len(data) > 56:
                    names_data = data[56:]
                    names = []
                    for i in range(0, len(names_data), 18):
                        if i + 15 < len(names_data):
                            name = names_data[i:i+15].decode('ascii', errors='ignore').strip()
                            if name and not name.startswith('\x00'):
                                names.append(name)
                    
                    if names:
                        info['netbios_names'] = names[:3]  # First 3 names
                        info['hostname_hint'] = names[0]
            except socket.timeout:
                pass
            
            sock.close()
        except Exception:
            pass
        
        return info
    
    def advanced_port_scan(self, ip: str, ports: List[int] = None) -> Dict:
        """Comprehensive port scanning with service detection"""
        if ports is None:
            # Extended port list for better coverage
            ports = [
                21, 22, 23, 25, 53, 67, 69, 80, 110, 111, 123, 135, 137, 138, 139,
                143, 161, 389, 443, 445, 464, 514, 515, 548, 554, 587, 631, 636,
                873, 902, 993, 995, 1080, 1194, 1433, 1521, 1701, 1723, 1883,
                2049, 2082, 2083, 2086, 2087, 2181, 2222, 3000, 3128, 3306, 3389,
                3690, 4369, 4443, 4444, 5000, 5001, 5060, 5222, 5353, 5432, 5555,
                5601, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443, 6666,
                7000, 7001, 7070, 8000, 8008, 8080, 8081, 8086, 8087, 8088, 8089,
                8123, 8140, 8181, 8200, 8300, 8443, 8444, 8500, 8834, 8883, 8888,
                9000, 9001, 9042, 9090, 9091, 9092, 9100, 9200, 9300, 9418, 9999,
                10000, 10050, 11211, 15672, 19999, 25565, 27017, 32400, 50000
            ]
        
        open_ports = []
        services = {}
        
        # Use nmap for comprehensive scanning if available
        try:
            nm_result = self.nm.scan(ip, ','.join(map(str, ports)), arguments='-sV -sS -T4 --version-intensity 5')
            
            if ip in nm_result['scan']:
                host_info = nm_result['scan'][ip]
                
                # Get open ports and services
                if 'tcp' in host_info:
                    for port, port_info in host_info['tcp'].items():
                        if port_info['state'] == 'open':
                            open_ports.append(port)
                            service_name = port_info.get('name', 'unknown')
                            service_product = port_info.get('product', '')
                            service_version = port_info.get('version', '')
                            
                            services[port] = {
                                'name': service_name,
                                'product': service_product,
                                'version': service_version,
                                'full': f"{service_product} {service_version}".strip() or service_name
                            }
                
                # Get OS detection if available
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_match = host_info['osmatch'][0]
                    return {
                        'open_ports': open_ports,
                        'services': services,
                        'os_detected': os_match.get('name', 'Unknown'),
                        'os_accuracy': os_match.get('accuracy', 0)
                    }
        except Exception as e:
            logger.debug(f"Nmap scan failed for {ip}, falling back to socket scan: {e}")
            
            # Fallback to socket scanning
            for port in ports[:50]:  # Limit for performance
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.3)
                    result = sock.connect_ex((str(ip), port))
                    
                    if result == 0:
                        open_ports.append(port)
                        # Try to grab banner
                        try:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = sock.recv(1024).decode('utf-8', errors='ignore')
                            if banner:
                                services[port] = {'banner': banner[:100]}
                        except:
                            pass
                    
                    sock.close()
                except Exception:
                    pass
        
        return {
            'open_ports': open_ports,
            'services': services
        }
    
    def classify_device_advanced(self, device_info: Dict) -> str:
        """Advanced device classification based on multiple factors"""
        open_ports = device_info.get('open_ports', [])
        services = device_info.get('services', {})
        hostname = device_info.get('hostname', '').lower()
        mac_vendor = device_info.get('mac_vendor', '').lower()
        os_hint = device_info.get('os_detected', '').lower()
        
        # Router/Network device detection
        if any(p in open_ports for p in [23, 161, 22]) and any(p in open_ports for p in [80, 443]):
            if 'cisco' in mac_vendor or 'cisco' in os_hint:
                return 'cisco_router'
            elif 'juniper' in mac_vendor:
                return 'juniper_router'
            elif 'mikrotik' in hostname or 'routeros' in os_hint:
                return 'mikrotik_router'
            elif 'ubiquiti' in mac_vendor:
                return 'ubiquiti_ap'
            else:
                return 'router'
        
        # Server detection
        if 22 in open_ports or 3389 in open_ports:
            if 3389 in open_ports and 445 in open_ports:
                return 'windows_server'
            elif 22 in open_ports and any(p in open_ports for p in [80, 443, 3306, 5432]):
                return 'linux_server'
            elif 902 in open_ports:
                return 'vmware_esxi'
        
        # Workstation detection
        if 445 in open_ports and 135 in open_ports:
            return 'windows_workstation'
        elif 548 in open_ports or 631 in open_ports:
            return 'mac_workstation'
        elif 22 in open_ports and not any(p in open_ports for p in [80, 443]):
            return 'linux_workstation'
        
        # IoT/Special devices
        if 'raspberry' in mac_vendor:
            return 'raspberry_pi'
        elif 9100 in open_ports or (631 in open_ports and 'printer' in str(services.get(631, '')).lower()):
            return 'printer'
        elif 554 in open_ports or 8000 in open_ports:
            return 'ip_camera'
        elif 1883 in open_ports or 8883 in open_ports:
            return 'iot_device'
        elif any(p in open_ports for p in [32400, 8096, 8989, 8081]):
            return 'media_server'
        elif 'synology' in hostname or 'qnap' in hostname or 'nas' in hostname:
            return 'nas_device'
        
        # Database servers
        if 3306 in open_ports:
            return 'mysql_server'
        elif 5432 in open_ports:
            return 'postgresql_server'
        elif 1433 in open_ports:
            return 'mssql_server'
        elif 27017 in open_ports:
            return 'mongodb_server'
        elif 6379 in open_ports:
            return 'redis_server'
        
        # Web servers
        if 80 in open_ports or 443 in open_ports:
            return 'web_server'
        
        # Mobile devices
        if 62078 in open_ports:
            return 'ios_device'
        elif 5555 in open_ports:
            return 'android_device'
        
        # Virtual machines
        if 'vmware' in mac_vendor:
            return 'virtual_machine'
        elif 'virtualbox' in mac_vendor:
            return 'virtual_machine'
        elif 'kvm' in mac_vendor or 'qemu' in mac_vendor:
            return 'virtual_machine'
        
        # Smart home devices
        if 8123 in open_ports:
            return 'home_assistant'
        elif 'philips' in mac_vendor and 80 in open_ports:
            return 'smart_light'
        elif 'amazon' in mac_vendor:
            return 'alexa_device'
        elif 'google' in mac_vendor and 8008 in open_ports:
            return 'chromecast'
        
        return 'unknown'
    
    def comprehensive_host_scan(self, ip: str) -> Dict:
        """Perform comprehensive scanning of a single host"""
        device_info = {
            'ip': str(ip),
            'is_active': True,
            'status': 'active',
            'discovery_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Get MAC address
        mac = self.get_mac_address(str(ip))
        if mac:
            device_info['mac_address'] = mac
            device_info['mac_vendor'] = self.get_mac_vendor(mac)
        
        # Advanced port scanning with service detection
        port_scan_result = self.advanced_port_scan(str(ip))
        device_info.update(port_scan_result)
        
        # Get hostname via DNS
        try:
            hostname, _, _ = socket.gethostbyaddr(str(ip))
            device_info['hostname'] = hostname
        except:
            pass
        
        # OS Detection
        os_from_ttl = self.detect_os_from_ttl(str(ip))
        os_from_ports = self.detect_os_from_ports(port_scan_result.get('open_ports', []))
        
        if 'os_detected' not in device_info:
            device_info['os_detected'] = os_from_ttl or os_from_ports or 'Unknown'
        
        # SNMP scanning
        snmp_info = self.perform_snmp_scan(str(ip))
        if snmp_info:
            device_info.update(snmp_info)
        
        # NetBIOS scanning
        netbios_info = self.detect_netbios_info(str(ip))
        if netbios_info:
            device_info.update(netbios_info)
            if 'hostname' not in device_info and 'hostname_hint' in netbios_info:
                device_info['hostname'] = netbios_info['hostname_hint']
        
        # mDNS detection
        mdns_services = self.detect_mdns_services(str(ip))
        if mdns_services:
            device_info['mdns_services'] = mdns_services
        
        # Advanced device classification
        device_info['device_type'] = self.classify_device_advanced(device_info)
        
        # Service summary
        if 'services' in device_info and device_info['services']:
            service_names = []
            for port, service_info in device_info['services'].items():
                if isinstance(service_info, dict):
                    name = service_info.get('full') or service_info.get('name') or self.service_signatures.get(port, f'port-{port}')
                else:
                    name = self.service_signatures.get(port, f'port-{port}')
                service_names.append(f"{name}:{port}")
            device_info['service_summary'] = ', '.join(service_names[:10])  # Top 10 services
        
        # Calculate device score (for importance/interest)
        score = 0
        if device_info.get('open_ports'):
            score += len(device_info['open_ports']) * 2
        if device_info.get('hostname'):
            score += 5
        if device_info.get('mac_address'):
            score += 3
        if device_info.get('os_detected') != 'Unknown':
            score += 10
        if device_info.get('snmp_capable'):
            score += 8
        device_info['discovery_score'] = score
        
        return device_info


def emit_progress(scan_id: str, percentage: int, message: str, scan_tracker=None):
    """Emit progress update via WebSocket"""
    logger.info(f"[PROGRESS] {scan_id}: {percentage}% - {message}")
    
    try:
        if scan_tracker:
            scan_tracker.update_progress(
                scan_id,
                percentage,
                message,
                stage='scanning'
            )
        
        # Also emit via socketio if available
        try:
            from flask_socketio import emit as socketio_emit
            emit_data = {
                'scan_id': scan_id,
                'progress': percentage,
                'percentage': percentage,
                'message': message,
                'stage': 'scanning'
            }
            socketio_emit('scan_progress', emit_data, broadcast=True, namespace='/')
            logger.info(f"[PROGRESS] ✅ WebSocket progress emitted: {percentage}% - {message}")
        except Exception as e:
            logger.debug(f"[PROGRESS] Could not emit via socketio: {e}")
            
    except Exception as e:
        logger.error(f"[PROGRESS] ❌ Error emitting progress: {e}", exc_info=True)


def advanced_network_scan(subnet: str, scan_id: str, scan_tracker=None) -> Tuple[Dict, Dict]:
    """
    Perform advanced network scan with multiple discovery methods
    """
    logger.info(f"[ADV-SCAN] ========== Starting Advanced Network Scan ==========")
    logger.info(f"[ADV-SCAN] Scan ID: {scan_id}")
    logger.info(f"[ADV-SCAN] Target subnet: {subnet}")
    
    scanner = AdvancedNetworkScanner()
    devices = {}
    summary = {
        'scan_successful': False,
        'total_hosts': 0,
        'active_hosts': 0,
        'scan_duration': 0,
        'discovery_methods': [],
        'errors': []
    }
    
    start_time = time.time()
    
    try:
        # Parse network
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        summary['total_hosts'] = total_hosts
        
        logger.info(f"[ADV-SCAN] Network: {network}")
        logger.info(f"[ADV-SCAN] Total hosts to scan: {total_hosts}")
        
        emit_progress(scan_id, 5, f"Starting advanced scan of {subnet} ({total_hosts} hosts)", scan_tracker)
        
        # Stage 1: ARP Discovery (for local network)
        emit_progress(scan_id, 10, "Stage 1: Performing ARP discovery", scan_tracker)
        try:
            # Use nmap for ARP scan on local network
            local_network = ipaddress.ip_network(subnet, strict=False)
            local_interface = None
            
            # Find local interface in same network
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        try:
                            if ipaddress.ip_address(addr['addr']) in local_network:
                                local_interface = iface
                                break
                        except:
                            pass
            
            if local_interface:
                logger.info(f"[ADV-SCAN] Performing ARP scan on local network via {local_interface}")
                nm = nmap.PortScanner()
                nm.scan(hosts=str(network), arguments='-sn -PR')
                
                for host in nm.all_hosts():
                    if nm[host].state() == 'up':
                        if host not in devices:
                            devices[host] = {'ip': host, 'discovery_method': 'arp'}
                            logger.info(f"[ADV-SCAN] ARP discovered: {host}")
                
                summary['discovery_methods'].append('ARP')
        except Exception as e:
            logger.debug(f"[ADV-SCAN] ARP scan failed: {e}")
        
        # Stage 2: Fast TCP SYN scan on common ports
        emit_progress(scan_id, 20, "Stage 2: TCP SYN scanning for active hosts", scan_tracker)
        
        # Limit hosts for large networks
        if total_hosts > 512:
            logger.warning(f"Large network detected ({total_hosts} hosts), limiting to first 512")
            hosts = hosts[:512]
            total_hosts = 512
        
        # Quick discovery scan
        discovered_hosts = set()
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = []
            
            for ip in hosts:
                future = executor.submit(scanner.comprehensive_host_scan, ip)
                futures.append((future, ip))
            
            completed = 0
            for future, ip in futures:
                completed += 1
                
                # Update progress
                progress = 20 + int((completed / total_hosts) * 60)
                if completed % max(1, total_hosts // 10) == 0:
                    emit_progress(
                        scan_id,
                        progress,
                        f"Scanning: {completed}/{total_hosts} hosts, found {len(devices)} devices",
                        scan_tracker
                    )
                
                try:
                    result = future.result(timeout=10)
                    if result and result.get('open_ports'):
                        devices[str(ip)] = result
                        discovered_hosts.add(str(ip))
                        
                        logger.info(f"[ADV-SCAN] ✅ Device discovered: {ip}")
                        logger.info(f"[ADV-SCAN]   Hostname: {result.get('hostname', 'Unknown')}")
                        logger.info(f"[ADV-SCAN]   MAC: {result.get('mac_address', 'Unknown')}")
                        logger.info(f"[ADV-SCAN]   Type: {result.get('device_type', 'unknown')}")
                        logger.info(f"[ADV-SCAN]   OS: {result.get('os_detected', 'Unknown')}")
                        logger.info(f"[ADV-SCAN]   Ports: {len(result.get('open_ports', []))} open")
                        
                        # Emit device discovered event
                        try:
                            from flask_socketio import emit as socketio_emit
                            socketio_emit('device_discovered', result, broadcast=True, namespace='/')
                        except:
                            pass
                            
                except Exception as e:
                    logger.debug(f"[ADV-SCAN] Error scanning {ip}: {e}")
        
        # Stage 3: Enhanced scanning for discovered devices
        emit_progress(scan_id, 85, f"Stage 3: Gathering detailed information for {len(devices)} devices", scan_tracker)
        
        # Final summary
        scan_duration = time.time() - start_time
        summary['scan_duration'] = scan_duration
        summary['scan_successful'] = True
        summary['devices_found'] = len(devices)
        summary['active_hosts'] = len(devices)
        
        # Device statistics
        device_types = defaultdict(int)
        os_types = defaultdict(int)
        total_ports = 0
        
        for device in devices.values():
            device_types[device.get('device_type', 'unknown')] += 1
            os_types[device.get('os_detected', 'Unknown')] += 1
            total_ports += len(device.get('open_ports', []))
        
        summary['device_types'] = dict(device_types)
        summary['os_distribution'] = dict(os_types)
        summary['total_open_ports'] = total_ports
        summary['avg_ports_per_device'] = total_ports / len(devices) if devices else 0
        
        logger.info(f"[ADV-SCAN] ========== Advanced Scan Complete ==========")
        logger.info(f"[ADV-SCAN] Duration: {scan_duration:.1f} seconds")
        logger.info(f"[ADV-SCAN] Devices found: {len(devices)}")
        logger.info(f"[ADV-SCAN] Device types: {dict(device_types)}")
        logger.info(f"[ADV-SCAN] OS distribution: {dict(os_types)}")
        
        emit_progress(scan_id, 100, f"Advanced scan complete: {len(devices)} devices discovered", scan_tracker)
        
    except Exception as e:
        logger.error(f"[ADV-SCAN] ❌ SCAN FAILED: {e}", exc_info=True)
        summary['scan_successful'] = False
        summary['error'] = str(e)
        summary['scan_duration'] = time.time() - start_time
        emit_progress(scan_id, 100, f"Scan failed: {str(e)}", scan_tracker)
    
    return devices, summary