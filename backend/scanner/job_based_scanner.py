#!/usr/bin/env python3
"""
Modern Job-Based Network Scanner
Inspired by Netdisco's proven architecture with modern enhancements

This implements a complete job-based scanning system with:
- Event-driven job queue with priority scheduling
- Breadth-first topology discovery
- Historical data continuity
- Intelligent deferral/backoff system
- Multi-protocol device discovery (SNMP, CDP, LLDP, ICMP, Nmap)
- Real-time progress tracking
- Modular job types for different discovery methods
"""

import asyncio
import logging
import time
import json
import sqlite3
import ipaddress
import subprocess
import socket
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict
import re

# Try to import SNMP libraries
try:
    from pysnmp.hlapi import *
    from pysnmp.error import PySnmpError
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("SNMP libraries not available. Install with: pip install pysnmp")

logger = logging.getLogger(__name__)

# Enhanced OID mappings from Netdisco
ENHANCED_OIDS = {
    # System Information (ISO 1.3.6.1.2.1.1)
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysObjectID': '1.3.6.1.2.1.1.2.0', 
    'sysUpTime': '1.3.6.1.2.1.1.3.0',
    'sysContact': '1.3.6.1.2.1.1.4.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'sysLocation': '1.3.6.1.2.1.1.6.0',
    'sysServices': '1.3.6.1.2.1.1.7.0',
    
    # Interface Table (ISO 1.3.6.1.2.1.2.2.1)
    'ifIndex': '1.3.6.1.2.1.2.2.1.1',
    'ifDescr': '1.3.6.1.2.1.2.2.1.2',
    'ifType': '1.3.6.1.2.1.2.2.1.3',
    'ifMtu': '1.3.6.1.2.1.2.2.1.4',
    'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
    'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
    'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
    'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
    'ifLastChange': '1.3.6.1.2.1.2.2.1.9',
    'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
    'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',
    'ifName': '1.3.6.1.2.1.31.1.1.1.1',
    'ifAlias': '1.3.6.1.2.1.31.1.1.1.18',
    
    # IP Address Table (ISO 1.3.6.1.2.1.4.20.1)
    'ipAdEntAddr': '1.3.6.1.2.1.4.20.1.1',
    'ipAdEntIfIndex': '1.3.6.1.2.1.4.20.1.2',
    'ipAdEntNetMask': '1.3.6.1.2.1.4.20.1.3',
    
    # ARP Table (ISO 1.3.6.1.2.1.4.22.1)
    'ipNetToMediaIfIndex': '1.3.6.1.2.1.4.22.1.1',
    'ipNetToMediaPhysAddress': '1.3.6.1.2.1.4.22.1.2',
    'ipNetToMediaNetAddress': '1.3.6.1.2.1.4.22.1.3',
    'ipNetToMediaType': '1.3.6.1.2.1.4.22.1.4',
    
    # Bridge MIB - Forwarding Database (ISO 1.3.6.1.2.1.17)
    'dot1dBaseBridgeAddress': '1.3.6.1.2.1.17.1.1.0',
    'dot1dBaseNumPorts': '1.3.6.1.2.1.17.1.2.0',
    'dot1dTpFdbAddress': '1.3.6.1.2.1.17.4.3.1.1',
    'dot1dTpFdbPort': '1.3.6.1.2.1.17.4.3.1.2',
    'dot1dTpFdbStatus': '1.3.6.1.2.1.17.4.3.1.3',
    'dot1dBasePortIfIndex': '1.3.6.1.2.1.17.1.4.1.2',
    
    # Q-BRIDGE MIB for VLAN-aware switches
    'dot1qVlanStaticName': '1.3.6.1.2.1.17.7.1.4.3.1.1',
    'dot1qVlanCurrentEgressPorts': '1.3.6.1.2.1.17.7.1.4.2.1.4',
    'dot1qVlanCurrentUntaggedPorts': '1.3.6.1.2.1.17.7.1.4.2.1.5',
    
    # CDP (Cisco Discovery Protocol)
    'cdpCacheDeviceId': '1.3.6.1.4.1.9.9.23.1.2.1.1.6',
    'cdpCacheDevicePort': '1.3.6.1.4.1.9.9.23.1.2.1.1.7',
    'cdpCachePlatform': '1.3.6.1.4.1.9.9.23.1.2.1.1.8',
    'cdpCacheCapabilities': '1.3.6.1.4.1.9.9.23.1.2.1.1.9',
    'cdpCacheVersion': '1.3.6.1.4.1.9.9.23.1.2.1.1.5',
    'cdpCacheAddress': '1.3.6.1.4.1.9.9.23.1.2.1.1.4',
    
    # LLDP (Link Layer Discovery Protocol)
    'lldpRemChassisIdSubtype': '1.0.8802.1.1.2.1.4.1.1.4',
    'lldpRemChassisId': '1.0.8802.1.1.2.1.4.1.1.5',
    'lldpRemPortIdSubtype': '1.0.8802.1.1.2.1.4.1.1.6',
    'lldpRemPortId': '1.0.8802.1.1.2.1.4.1.1.7',
    'lldpRemPortDesc': '1.0.8802.1.1.2.1.4.1.1.8',
    'lldpRemSysName': '1.0.8802.1.1.2.1.4.1.1.9',
    'lldpRemSysDesc': '1.0.8802.1.1.2.1.4.1.1.10',
    'lldpRemSysCapSupported': '1.0.8802.1.1.2.1.4.1.1.11',
    'lldpRemSysCapEnabled': '1.0.8802.1.1.2.1.4.1.1.12',
    
    # Entity MIB for physical inventory
    'entPhysicalDescr': '1.3.6.1.2.1.47.1.1.1.1.2',
    'entPhysicalVendorType': '1.3.6.1.2.1.47.1.1.1.1.3',
    'entPhysicalContainedIn': '1.3.6.1.2.1.47.1.1.1.1.4',
    'entPhysicalClass': '1.3.6.1.2.1.47.1.1.1.1.5',
    'entPhysicalParentRelPos': '1.3.6.1.2.1.47.1.1.1.1.6',
    'entPhysicalName': '1.3.6.1.2.1.47.1.1.1.1.7',
    'entPhysicalHardwareRev': '1.3.6.1.2.1.47.1.1.1.1.8',
    'entPhysicalFirmwareRev': '1.3.6.1.2.1.47.1.1.1.1.9',
    'entPhysicalSoftwareRev': '1.3.6.1.2.1.47.1.1.1.1.10',
    'entPhysicalSerialNum': '1.3.6.1.2.1.47.1.1.1.1.11',
    'entPhysicalMfgName': '1.3.6.1.2.1.47.1.1.1.1.12',
    'entPhysicalModelName': '1.3.6.1.2.1.47.1.1.1.1.13'
}

# Enhanced vendor OID mappings
VENDOR_OIDS = {
    '1.3.6.1.4.1.9': 'Cisco Systems',
    '1.3.6.1.4.1.2636': 'Juniper Networks', 
    '1.3.6.1.4.1.11': 'Hewlett-Packard',
    '1.3.6.1.4.1.674': 'Dell Inc.',
    '1.3.6.1.4.1.1588': 'Brocade Communications',
    '1.3.6.1.4.1.6486': 'Alcatel-Lucent',
    '1.3.6.1.4.1.1991': 'Foundry Networks',
    '1.3.6.1.4.1.25506': 'H3C Technologies',
    '1.3.6.1.4.1.41112': 'Ubiquiti Networks',
    '1.3.6.1.4.1.14988': 'MikroTik',
    '1.3.6.1.4.1.4526': 'Netgear',
    '1.3.6.1.4.1.171': 'D-Link',
    '1.3.6.1.4.1.207': 'Allied Telesis',
    '1.3.6.1.4.1.259': 'EtherWAN Systems',
    '1.3.6.1.4.1.2021': 'Net-SNMP'
}

# Enhanced device classification patterns
ENHANCED_DEVICE_PATTERNS = {
    'router': [
        r'router', r'gateway', r'gw[-_]', r'rt[-_]', r'rtr[-_]',
        r'cisco.*router', r'juniper.*router', r'mikrotik',
        r'edgerouter', r'pfsense', r'opnsense', r'vyos',
        r'fortinet', r'sonicwall', r'watchguard'
    ],
    'switch': [
        r'switch', r'sw[-_]', r'swt[-_]', r'catalyst', r'nexus',
        r'procurve', r'ex\d+', r'sg\d+', r'ws[-_]c', r'dell.*switch',
        r'hp.*switch', r'aruba.*switch', r'powerconnect'
    ],
    'firewall': [
        r'firewall', r'fw[-_]', r'asa', r'fortigate', r'palo.*alto',
        r'checkpoint', r'sonicwall', r'watchguard', r'pfsense',
        r'vyos', r'untangle', r'smoothwall'
    ],
    'wireless_controller': [
        r'wlc', r'wireless.*controller', r'wifi.*controller',
        r'unifi.*controller', r'aruba.*controller'
    ],
    'access_point': [
        r'ap[-_]', r'wap[-_]', r'access.*point', r'aironet',
        r'unifi', r'meraki', r'aruba.*ap', r'cisco.*ap',
        r'wifi', r'wireless'
    ],
    'server': [
        r'server', r'srv[-_]', r'host[-_]', r'vm[-_]', r'esx',
        r'vcenter', r'dc[-_]', r'mail', r'web', r'db', r'sql',
        r'exchange', r'sharepoint', r'domain.*controller',
        r'file.*server', r'print.*server'
    ],
    'workstation': [
        r'pc[-_]', r'desktop', r'laptop', r'workstation',
        r'ws[-_]', r'computer', r'client'
    ],
    'printer': [
        r'printer', r'print', r'hp.*jet', r'canon', r'xerox',
        r'brother', r'lexmark', r'ricoh', r'konica', r'epson'
    ],
    'phone': [
        r'phone', r'voip', r'sip', r'cisco.*phone', r'polycom',
        r'yealink', r'grandstream', r'aastra', r'avaya'
    ],
    'camera': [
        r'camera', r'cam[-_]', r'ipcam', r'axis', r'hikvision',
        r'dahua', r'surveillance', r'security.*cam'
    ],
    'storage': [
        r'storage', r'nas', r'san', r'netapp', r'emc',
        r'dell.*storage', r'synology', r'qnap', r'drobo',
        r'freenas', r'truenas'
    ],
    'ups': [
        r'ups', r'power', r'battery', r'backup', r'apc'
    ],
    'environmental': [
        r'sensor', r'hvac', r'thermostat', r'temperature',
        r'humidity', r'environmental'
    ],
    'iot': [
        r'iot', r'smart.*', r'sensor', r'meter', r'controller',
        r'automation', r'building.*management'
    ]
}

class JobType(Enum):
    """Types of discovery jobs"""
    DISCOVER = "discover"           # Device discovery and basic profiling
    MACSUCK = "macsuck"            # MAC address table collection
    ARPNIP = "arpnip"              # ARP/NDP table collection  
    PINGSWEEP = "pingsweep"        # Ping sweep subnet scanning
    TOPOLOGY = "topology"          # Topology discovery via CDP/LLDP
    NBTSTAT = "nbtstat"           # NetBIOS name resolution
    PORTMAP = "portmap"           # Port mapping and service detection
    VULNSCAN = "vulnscan"         # Vulnerability scanning

class JobPriority(Enum):
    """Job priority levels"""
    HIGH = 1      # Critical infrastructure, gateways
    NORMAL = 2    # Regular devices
    LOW = 3       # Background scans, deferrals
    BULK = 4      # Mass operations

class JobStatus(Enum):
    """Job execution status"""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    DEFERRED = "deferred"
    SKIPPED = "skipped"

@dataclass
class JobRequest:
    """Represents a scan job request"""
    job_id: str
    job_type: JobType
    target: str  # IP address or subnet
    priority: JobPriority
    parameters: Dict[str, Any]
    created_at: datetime
    scheduled_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    defer_until: Optional[datetime] = None
    parent_job_id: Optional[str] = None

@dataclass  
class JobResult:
    """Represents job execution results"""
    job_id: str
    status: JobStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    data: Dict[str, Any] = None
    error: Optional[str] = None
    spawned_jobs: List[str] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.spawned_jobs is None:
            self.spawned_jobs = []

@dataclass
class DeviceRecord:
    """Enhanced device record with historical continuity"""
    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    system_description: Optional[str] = None
    system_object_id: Optional[str] = None
    contact: Optional[str] = None
    location: Optional[str] = None
    uptime: Optional[int] = None
    
    # Status and timestamps
    active: bool = True
    first_seen: datetime = None
    last_seen: datetime = None
    last_discover: Optional[datetime] = None
    last_macsuck: Optional[datetime] = None  
    last_arpnip: Optional[datetime] = None
    
    # Skip/deferral tracking
    skip_count: int = 0
    defer_until: Optional[datetime] = None
    
    # Capabilities
    snmp_capable: bool = False
    snmp_community: Optional[str] = None
    has_bridge_mib: bool = False
    has_cdp: bool = False  
    has_lldp: bool = False
    
    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = datetime.now()
        if self.last_seen is None:
            self.last_seen = datetime.now()

class JobBasedScanner:
    """
    Modern job-based network scanner with Netdisco-inspired architecture
    """
    
    def __init__(self, db_path: str = "data/netdisco_scanner.db", max_workers: int = 50):
        self.db_path = db_path
        self.max_workers = max_workers
        self.job_queue: asyncio.PriorityQueue = None
        self.active_jobs: Dict[str, JobRequest] = {}
        self.devices: Dict[str, DeviceRecord] = {}
        self.job_results: Dict[str, JobResult] = {}
        
        # Thread pool for blocking operations
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Statistics
        self.stats = {
            'jobs_completed': 0,
            'jobs_failed': 0,
            'jobs_deferred': 0,
            'devices_discovered': 0,
            'discovery_start_time': None
        }
        
        # Initialize database
        self._init_database()
        
        # Load existing devices from database
        self._load_devices_from_db()
        
        logger.info(f"Job-based scanner initialized with {len(self.devices)} known devices")

    def _init_database(self):
        """Initialize enhanced database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Jobs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    job_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    parameters TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    retry_count INTEGER DEFAULT 0,
                    defer_until TEXT,
                    parent_job_id TEXT,
                    result_data TEXT,
                    error_message TEXT,
                    FOREIGN KEY (parent_job_id) REFERENCES jobs (job_id)
                )
            ''')
            
            # Enhanced devices table with historical continuity
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    mac_address TEXT,
                    vendor TEXT,
                    model TEXT,
                    os_name TEXT,
                    os_version TEXT,
                    device_type TEXT,
                    system_description TEXT,
                    system_object_id TEXT,
                    contact TEXT,
                    location TEXT,
                    uptime INTEGER,
                    active BOOLEAN DEFAULT TRUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_discover TEXT,
                    last_macsuck TEXT,
                    last_arpnip TEXT,
                    skip_count INTEGER DEFAULT 0,
                    defer_until TEXT,
                    snmp_capable BOOLEAN DEFAULT FALSE,
                    snmp_community TEXT,
                    has_bridge_mib BOOLEAN DEFAULT FALSE,
                    has_cdp BOOLEAN DEFAULT FALSE,
                    has_lldp BOOLEAN DEFAULT FALSE,
                    extra_data TEXT
                )
            ''')
            
            # Device interfaces table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_interfaces (
                    device_ip TEXT,
                    if_index INTEGER,
                    if_name TEXT,
                    if_descr TEXT,
                    if_type INTEGER,
                    if_speed INTEGER,
                    if_mac TEXT,
                    if_admin_status INTEGER,
                    if_oper_status INTEGER,
                    if_alias TEXT,
                    active BOOLEAN DEFAULT TRUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    FOREIGN KEY (device_ip) REFERENCES devices (ip),
                    PRIMARY KEY (device_ip, if_index)
                )
            ''')
            
            # MAC address entries (bridge table data)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mac_entries (
                    mac_address TEXT,
                    device_ip TEXT,
                    port_name TEXT,
                    vlan_id INTEGER,
                    active BOOLEAN DEFAULT TRUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    FOREIGN KEY (device_ip) REFERENCES devices (ip),
                    PRIMARY KEY (mac_address, device_ip, port_name, vlan_id)
                )
            ''')
            
            # ARP/NDP entries (IP to MAC mappings)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS arp_entries (
                    ip_address TEXT,
                    mac_address TEXT,
                    device_ip TEXT,
                    active BOOLEAN DEFAULT TRUE,
                    dns_name TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    router_history TEXT,
                    FOREIGN KEY (device_ip) REFERENCES devices (ip),
                    PRIMARY KEY (ip_address, mac_address, device_ip)
                )
            ''')
            
            # Topology links (neighbor relationships)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS topology_links (
                    local_device TEXT,
                    local_port TEXT,
                    remote_device TEXT,
                    remote_port TEXT,
                    protocol TEXT,
                    active BOOLEAN DEFAULT TRUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    FOREIGN KEY (local_device) REFERENCES devices (ip),
                    PRIMARY KEY (local_device, local_port, remote_device)
                )
            ''')
            
            # VLAN information
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vlans (
                    device_ip TEXT,
                    vlan_id INTEGER,
                    vlan_name TEXT,
                    tagged_ports TEXT,
                    untagged_ports TEXT,
                    active BOOLEAN DEFAULT TRUE,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    FOREIGN KEY (device_ip) REFERENCES devices (ip),
                    PRIMARY KEY (device_ip, vlan_id)
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs (created_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_active ON devices (active)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices (last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_mac_entries_active ON mac_entries (active)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_arp_entries_active ON arp_entries (active)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_topology_links_active ON topology_links (active)')
            
            conn.commit()
            
        logger.info("Enhanced database schema initialized")

    def _load_devices_from_db(self):
        """Load existing devices from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM devices WHERE active = 1')
            
            for row in cursor.fetchall():
                device = DeviceRecord(
                    ip=row[0], hostname=row[1], mac_address=row[2],
                    vendor=row[3], model=row[4], os_name=row[5],
                    os_version=row[6], device_type=row[7],
                    system_description=row[8], system_object_id=row[9],
                    contact=row[10], location=row[11], uptime=row[12],
                    active=bool(row[13]),
                    first_seen=datetime.fromisoformat(row[14]),
                    last_seen=datetime.fromisoformat(row[15]),
                    skip_count=row[19] or 0,
                    snmp_capable=bool(row[21]), snmp_community=row[22],
                    has_bridge_mib=bool(row[23]), has_cdp=bool(row[24]),
                    has_lldp=bool(row[25])
                )
                
                # Parse timestamps
                if row[16]: device.last_discover = datetime.fromisoformat(row[16])
                if row[17]: device.last_macsuck = datetime.fromisoformat(row[17])  
                if row[18]: device.last_arpnip = datetime.fromisoformat(row[18])
                if row[20]: device.defer_until = datetime.fromisoformat(row[20])
                
                self.devices[device.ip] = device

    async def start_discovery(self, initial_targets: List[str], scan_id: str = None):
        """
        Start network discovery using job-based approach
        
        Args:
            initial_targets: List of IP addresses or subnets to start discovery
            scan_id: Optional scan ID for progress tracking
        """
        self.stats['discovery_start_time'] = datetime.now()
        self.job_queue = asyncio.PriorityQueue()
        
        logger.info(f"Starting job-based discovery with {len(initial_targets)} initial targets")
        
        # Queue initial discovery jobs
        job_count = 0
        for target in initial_targets:
            if '/' in target:  # Subnet
                job_id = f"pingsweep_{target.replace('/', '_')}_{job_count}"
                job = JobRequest(
                    job_id=job_id,
                    job_type=JobType.PINGSWEEP,
                    target=target,
                    priority=JobPriority.HIGH,
                    parameters={'scan_id': scan_id},
                    created_at=datetime.now()
                )
            else:  # Single IP
                job_id = f"discover_{target}_{job_count}"
                job = JobRequest(
                    job_id=job_id,
                    job_type=JobType.DISCOVER,
                    target=target,
                    priority=JobPriority.HIGH,
                    parameters={'scan_id': scan_id},
                    created_at=datetime.now()
                )
            
            await self.job_queue.put((job.priority.value, job))
            job_count += 1
        
        # Start job processing
        await self._process_job_queue()
        
        # Final statistics
        logger.info(f"Discovery completed: {self.stats}")
        return self.devices, self.stats

    async def _process_job_queue(self):
        """Process jobs from the queue with proper concurrency control"""
        workers = []
        
        # Start worker tasks
        for i in range(min(self.max_workers, 20)):  # Limit concurrent jobs
            worker = asyncio.create_task(self._job_worker(f"worker_{i}"))
            workers.append(worker)
        
        # Wait for all jobs to complete
        try:
            await asyncio.gather(*workers, return_exceptions=True)
        except Exception as e:
            logger.error(f"Error in job processing: {e}")

    async def _job_worker(self, worker_name: str):
        """Individual job worker"""
        while True:
            try:
                # Get next job (with timeout to allow shutdown)
                try:
                    priority, job = await asyncio.wait_for(
                        self.job_queue.get(), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    # Check if we should continue (jobs still running or queued)
                    if len(self.active_jobs) == 0 and self.job_queue.empty():
                        break
                    continue
                
                # Check if job should be deferred
                if job.defer_until and datetime.now() < job.defer_until:
                    # Re-queue for later
                    await self.job_queue.put((priority, job))
                    await asyncio.sleep(1)
                    continue
                
                # Execute job
                self.active_jobs[job.job_id] = job
                result = await self._execute_job(job)
                
                # Store result
                self.job_results[job.job_id] = result
                
                # Remove from active jobs
                if job.job_id in self.active_jobs:
                    del self.active_jobs[job.job_id]
                
                # Queue any spawned jobs
                for spawned_job_id in result.spawned_jobs:
                    if spawned_job_id in self.job_results:
                        spawned_job = self.job_results[spawned_job_id]
                        if hasattr(spawned_job, 'job_request'):
                            await self.job_queue.put((
                                spawned_job.job_request.priority.value,
                                spawned_job.job_request
                            ))
                
                # Update statistics
                if result.status == JobStatus.COMPLETED:
                    self.stats['jobs_completed'] += 1
                elif result.status == JobStatus.FAILED:
                    self.stats['jobs_failed'] += 1
                elif result.status == JobStatus.DEFERRED:
                    self.stats['jobs_deferred'] += 1
                
                # Mark task as done
                self.job_queue.task_done()
                
            except Exception as e:
                logger.error(f"Worker {worker_name} error: {e}")
                if job.job_id in self.active_jobs:
                    del self.active_jobs[job.job_id]
                continue
        
        logger.debug(f"Worker {worker_name} shutting down")

    async def _execute_job(self, job: JobRequest) -> JobResult:
        """Execute a single job based on its type"""
        logger.debug(f"Executing job {job.job_id}: {job.job_type.value} on {job.target}")
        
        result = JobResult(
            job_id=job.job_id,
            status=JobStatus.RUNNING,
            started_at=datetime.now()
        )
        
        try:
            # Execute job based on type
            if job.job_type == JobType.DISCOVER:
                await self._execute_discover_job(job, result)
            elif job.job_type == JobType.PINGSWEEP:
                await self._execute_pingsweep_job(job, result) 
            elif job.job_type == JobType.MACSUCK:
                await self._execute_macsuck_job(job, result)
            elif job.job_type == JobType.ARPNIP:
                await self._execute_arpnip_job(job, result)
            elif job.job_type == JobType.TOPOLOGY:
                await self._execute_topology_job(job, result)
            else:
                result.status = JobStatus.FAILED
                result.error = f"Unknown job type: {job.job_type}"
            
            result.completed_at = datetime.now()
            
        except Exception as e:
            logger.error(f"Job {job.job_id} failed: {e}")
            result.status = JobStatus.FAILED
            result.error = str(e)
            result.completed_at = datetime.now()
            
            # Handle retry logic
            if job.retry_count < job.max_retries:
                result.status = JobStatus.DEFERRED
                job.retry_count += 1
                job.defer_until = datetime.now() + timedelta(
                    seconds=min(300, 30 * (2 ** job.retry_count))  # Exponential backoff
                )
        
        # Store job result in database
        await self._store_job_result(job, result)
        
        return result

    async def _execute_discover_job(self, job: JobRequest, result: JobResult):
        """Execute device discovery job (Netdisco's discover algorithm)"""
        target_ip = job.target
        
        # Check if device should be skipped due to previous failures
        if target_ip in self.devices:
            device = self.devices[target_ip]
            if device.defer_until and datetime.now() < device.defer_until:
                result.status = JobStatus.DEFERRED
                return
        
        logger.info(f"Discovering device {target_ip}")
        
        # Create or update device record
        if target_ip not in self.devices:
            device = DeviceRecord(ip=target_ip)
            self.devices[target_ip] = device
            self.stats['devices_discovered'] += 1
        else:
            device = self.devices[target_ip]
        
        device.last_seen = datetime.now()
        device.active = True
        
        discovery_data = {}
        spawned_jobs = []
        
        # Phase 1: Basic connectivity check
        if not await self._ping_host(target_ip):
            device.skip_count += 1
            device.defer_until = datetime.now() + timedelta(
                seconds=min(3600, 60 * (2 ** device.skip_count))
            )
            result.status = JobStatus.DEFERRED
            result.data = {'reason': 'host_unreachable', 'skip_count': device.skip_count}
            return
        
        # Reset skip count on successful ping
        device.skip_count = 0
        device.defer_until = None
        
        # Phase 2: SNMP Discovery (if available)
        if SNMP_AVAILABLE:
            snmp_data = await self._discover_snmp_device(target_ip)
            if snmp_data:
                discovery_data.update(snmp_data)
                device.snmp_capable = True
                device.snmp_community = snmp_data.get('community', 'public')
                
                # Update device attributes from SNMP
                device.hostname = snmp_data.get('sysName') or device.hostname
                device.system_description = snmp_data.get('sysDescr')
                device.system_object_id = snmp_data.get('sysObjectID')
                device.contact = snmp_data.get('sysContact')
                device.location = snmp_data.get('sysLocation')
                device.uptime = snmp_data.get('sysUpTime')
                device.vendor = snmp_data.get('vendor') or device.vendor
                device.has_bridge_mib = snmp_data.get('has_bridge_mib', False)
                device.has_cdp = snmp_data.get('has_cdp', False)
                device.has_lldp = snmp_data.get('has_lldp', False)
                
                # Schedule follow-up jobs based on capabilities
                if device.has_bridge_mib:
                    macsuck_job_id = f"macsuck_{target_ip}_{int(time.time())}"
                    spawned_jobs.append(macsuck_job_id)
                    
                if device.snmp_capable:
                    arpnip_job_id = f"arpnip_{target_ip}_{int(time.time())}"
                    spawned_jobs.append(arpnip_job_id)
                
                if device.has_cdp or device.has_lldp:
                    topo_job_id = f"topology_{target_ip}_{int(time.time())}"
                    spawned_jobs.append(topo_job_id)
        
        # Phase 3: Nmap scanning for additional details
        nmap_data = await self._discover_nmap_device(target_ip)
        if nmap_data:
            discovery_data.update(nmap_data)
            device.hostname = nmap_data.get('hostname') or device.hostname
            device.os_name = nmap_data.get('os_name') or device.os_name  
            device.os_version = nmap_data.get('os_version') or device.os_version
            device.mac_address = nmap_data.get('mac_address') or device.mac_address
            device.vendor = nmap_data.get('vendor') or device.vendor
        
        # Phase 4: Device classification
        device.device_type = self._classify_device(device)
        
        # Phase 5: Update timestamps
        device.last_discover = datetime.now()
        device.last_seen = datetime.now()
        
        # Store device in database
        await self._store_device(device)
        
        result.status = JobStatus.COMPLETED
        result.data = discovery_data
        result.spawned_jobs = spawned_jobs
        
        logger.info(f"Device discovery completed for {target_ip}: {device.hostname or 'Unknown'} ({device.device_type})")

    async def _execute_pingsweep_job(self, job: JobRequest, result: JobResult):
        """Execute ping sweep job to find live hosts"""
        subnet = job.target
        logger.info(f"Ping sweep for subnet {subnet}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
            
            # Limit scan size for performance
            if len(hosts) > 4096:
                logger.warning(f"Large subnet {subnet} ({len(hosts)} hosts), sampling every 16th host")
                hosts = hosts[::16]
            
            # Ping hosts in batches
            batch_size = 100
            live_hosts = []
            spawned_jobs = []
            
            for i in range(0, len(hosts), batch_size):
                batch = hosts[i:i+batch_size]
                batch_results = await asyncio.gather(*[
                    self._ping_host(str(host)) for host in batch
                ], return_exceptions=True)
                
                # Collect live hosts and spawn discovery jobs
                for j, is_alive in enumerate(batch_results):
                    if is_alive and not isinstance(is_alive, Exception):
                        host_ip = str(batch[j])
                        live_hosts.append(host_ip)
                        
                        # Spawn discovery job for live host
                        discover_job_id = f"discover_{host_ip}_{int(time.time())}"
                        spawned_jobs.append(discover_job_id)
                        
                        # Create and queue the discovery job
                        discover_job = JobRequest(
                            job_id=discover_job_id,
                            job_type=JobType.DISCOVER,
                            target=host_ip,
                            priority=JobPriority.NORMAL,
                            parameters=job.parameters,
                            created_at=datetime.now(),
                            parent_job_id=job.job_id
                        )
                        
                        # Store job for spawning
                        self.job_results[discover_job_id] = JobResult(
                            job_id=discover_job_id,
                            status=JobStatus.PENDING,
                            started_at=datetime.now()
                        )
                        setattr(self.job_results[discover_job_id], 'job_request', discover_job)
            
            result.status = JobStatus.COMPLETED
            result.data = {
                'subnet': subnet,
                'hosts_scanned': len(hosts),
                'live_hosts': live_hosts,
                'live_count': len(live_hosts)
            }
            result.spawned_jobs = spawned_jobs
            
            logger.info(f"Ping sweep completed for {subnet}: {len(live_hosts)} live hosts found")
            
        except Exception as e:
            logger.error(f"Ping sweep failed for {subnet}: {e}")
            result.status = JobStatus.FAILED
            result.error = str(e)

    async def _execute_macsuck_job(self, job: JobRequest, result: JobResult):
        """Execute MAC address table collection (Netdisco's macsuck algorithm)"""
        target_ip = job.target
        
        if target_ip not in self.devices:
            result.status = JobStatus.FAILED
            result.error = "Device not found"
            return
        
        device = self.devices[target_ip]
        
        if not device.snmp_capable or not device.has_bridge_mib:
            result.status = JobStatus.SKIPPED
            result.data = {'reason': 'device_not_capable'}
            return
        
        logger.info(f"MAC table collection for {target_ip}")
        
        try:
            mac_entries = await self._collect_mac_table(target_ip, device.snmp_community)
            
            # Store MAC entries in database with historical continuity
            await self._store_mac_entries(target_ip, mac_entries)
            
            device.last_macsuck = datetime.now()
            await self._store_device(device)
            
            result.status = JobStatus.COMPLETED
            result.data = {
                'mac_entries_collected': len(mac_entries),
                'mac_entries': mac_entries
            }
            
            logger.info(f"MAC collection completed for {target_ip}: {len(mac_entries)} entries")
            
        except Exception as e:
            logger.error(f"MAC collection failed for {target_ip}: {e}")
            result.status = JobStatus.FAILED
            result.error = str(e)

    async def _execute_arpnip_job(self, job: JobRequest, result: JobResult):
        """Execute ARP/NDP table collection (Netdisco's arpnip algorithm)"""
        target_ip = job.target
        
        if target_ip not in self.devices:
            result.status = JobStatus.FAILED
            result.error = "Device not found"
            return
        
        device = self.devices[target_ip]
        
        if not device.snmp_capable:
            result.status = JobStatus.SKIPPED
            result.data = {'reason': 'device_not_snmp_capable'}
            return
        
        logger.info(f"ARP table collection for {target_ip}")
        
        try:
            arp_entries = await self._collect_arp_table(target_ip, device.snmp_community)
            
            # Store ARP entries with historical continuity
            await self._store_arp_entries(target_ip, arp_entries)
            
            device.last_arpnip = datetime.now()
            await self._store_device(device)
            
            result.status = JobStatus.COMPLETED
            result.data = {
                'arp_entries_collected': len(arp_entries),
                'arp_entries': arp_entries
            }
            
            logger.info(f"ARP collection completed for {target_ip}: {len(arp_entries)} entries")
            
        except Exception as e:
            logger.error(f"ARP collection failed for {target_ip}: {e}")
            result.status = JobStatus.FAILED
            result.error = str(e)

    async def _execute_topology_job(self, job: JobRequest, result: JobResult):
        """Execute topology discovery via CDP/LLDP"""
        target_ip = job.target
        
        if target_ip not in self.devices:
            result.status = JobStatus.FAILED
            result.error = "Device not found"
            return
        
        device = self.devices[target_ip]
        
        if not (device.has_cdp or device.has_lldp):
            result.status = JobStatus.SKIPPED
            result.data = {'reason': 'no_topology_protocol'}
            return
        
        logger.info(f"Topology discovery for {target_ip}")
        
        try:
            neighbors = []
            spawned_jobs = []
            
            # Try CDP first
            if device.has_cdp:
                cdp_neighbors = await self._discover_cdp_neighbors(target_ip, device.snmp_community)
                neighbors.extend(cdp_neighbors)
            
            # Try LLDP
            if device.has_lldp:
                lldp_neighbors = await self._discover_lldp_neighbors(target_ip, device.snmp_community)
                neighbors.extend(lldp_neighbors)
            
            # Store topology links
            await self._store_topology_links(target_ip, neighbors)
            
            # Spawn discovery jobs for unknown neighbors (breadth-first discovery)
            for neighbor in neighbors:
                neighbor_ip = neighbor.get('remote_ip')
                if neighbor_ip and neighbor_ip not in self.devices:
                    discover_job_id = f"discover_{neighbor_ip}_{int(time.time())}"
                    spawned_jobs.append(discover_job_id)
                    
                    # Create discovery job for neighbor
                    discover_job = JobRequest(
                        job_id=discover_job_id,
                        job_type=JobType.DISCOVER,
                        target=neighbor_ip,
                        priority=JobPriority.NORMAL,
                        parameters=job.parameters,
                        created_at=datetime.now(),
                        parent_job_id=job.job_id
                    )
                    
                    self.job_results[discover_job_id] = JobResult(
                        job_id=discover_job_id,
                        status=JobStatus.PENDING,
                        started_at=datetime.now()
                    )
                    setattr(self.job_results[discover_job_id], 'job_request', discover_job)
            
            result.status = JobStatus.COMPLETED
            result.data = {
                'neighbors_discovered': len(neighbors),
                'neighbors': neighbors
            }
            result.spawned_jobs = spawned_jobs
            
            logger.info(f"Topology discovery completed for {target_ip}: {len(neighbors)} neighbors, {len(spawned_jobs)} new discoveries spawned")
            
        except Exception as e:
            logger.error(f"Topology discovery failed for {target_ip}: {e}")
            result.status = JobStatus.FAILED
            result.error = str(e)

    # Helper methods for device discovery and data collection
    
    async def _ping_host(self, ip: str) -> bool:
        """Ping a host to check if it's alive"""
        try:
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '2', ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            returncode = await process.wait()
            return returncode == 0
        except:
            return False

    async def _discover_snmp_device(self, ip: str) -> Optional[Dict]:
        """Discover device via SNMP"""
        if not SNMP_AVAILABLE:
            return None
        
        communities = ['public', 'private', 'community']
        
        for community in communities:
            try:
                device_data = await self._snmp_get_system_info(ip, community)
                if device_data:
                    device_data['community'] = community
                    return device_data
            except:
                continue
        
        return None

    async def _snmp_get_system_info(self, ip: str, community: str) -> Optional[Dict]:
        """Get system information via SNMP"""
        try:
            device_data = {}
            
            # Get basic system info
            for errorIndication, errorStatus, errorIndex, varBinds in getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=5),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['sysName'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['sysDescr'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['sysObjectID'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['sysContact'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['sysLocation'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['sysUpTime']))
            ):
                if errorIndication or errorStatus:
                    return None
                
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = str(oid)
                    
                    if oid_str.endswith('.5.0'):  # sysName
                        device_data['sysName'] = str(value)
                    elif oid_str.endswith('.1.0'):  # sysDescr
                        device_data['sysDescr'] = str(value)
                        device_data['vendor'] = self._extract_vendor_from_descr(str(value))
                    elif oid_str.endswith('.2.0'):  # sysObjectID
                        device_data['sysObjectID'] = str(value)
                        device_data['vendor'] = device_data.get('vendor') or VENDOR_OIDS.get(str(value).rsplit('.', 1)[0])
                    elif oid_str.endswith('.4.0'):  # sysContact
                        device_data['sysContact'] = str(value)
                    elif oid_str.endswith('.6.0'):  # sysLocation
                        device_data['sysLocation'] = str(value)
                    elif oid_str.endswith('.3.0'):  # sysUpTime
                        device_data['sysUpTime'] = int(value)
            
            # Check for additional capabilities
            device_data['has_bridge_mib'] = await self._check_bridge_mib(ip, community)
            device_data['has_cdp'] = await self._check_cdp_support(ip, community)
            device_data['has_lldp'] = await self._check_lldp_support(ip, community)
            
            return device_data
            
        except Exception as e:
            logger.debug(f"SNMP query failed for {ip}: {e}")
            return None

    def _extract_vendor_from_descr(self, descr: str) -> Optional[str]:
        """Extract vendor from system description"""
        descr_lower = descr.lower()
        
        vendor_patterns = {
            'Cisco': ['cisco', 'catalyst', 'nexus', 'ios'],
            'Juniper': ['juniper', 'junos'],
            'HP': ['hewlett', 'hp', 'procurve'],
            'Dell': ['dell', 'powerconnect'],
            'Aruba': ['aruba'],
            'Ubiquiti': ['ubiquiti', 'unifi'],
            'MikroTik': ['mikrotik', 'routeros'],
            'Netgear': ['netgear']
        }
        
        for vendor, patterns in vendor_patterns.items():
            if any(pattern in descr_lower for pattern in patterns):
                return vendor
        
        return None

    async def _check_bridge_mib(self, ip: str, community: str) -> bool:
        """Check if device supports Bridge MIB"""
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=3),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['dot1dBaseBridgeAddress']))
            ):
                return not (errorIndication or errorStatus)
        except:
            return False

    async def _check_cdp_support(self, ip: str, community: str) -> bool:
        """Check if device supports CDP"""
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=3),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['cdpCacheDeviceId'])),
                lexicographicMode=False, maxRows=1
            ):
                return not (errorIndication or errorStatus)
        except:
            return False

    async def _check_lldp_support(self, ip: str, community: str) -> bool:
        """Check if device supports LLDP"""
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=3),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['lldpRemSysName'])),
                lexicographicMode=False, maxRows=1
            ):
                return not (errorIndication or errorStatus)
        except:
            return False

    async def _discover_nmap_device(self, ip: str) -> Optional[Dict]:
        """Discover device using Nmap"""
        try:
            cmd = [
                'nmap', '-sS', '-O', '-sV', '-T4', '--host-timeout', '30s',
                '--script=banner', '-p', '22,23,80,443,161,162', ip
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return self._parse_nmap_output(stdout.decode())
        except Exception as e:
            logger.debug(f"Nmap scan failed for {ip}: {e}")
        
        return None

    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse Nmap output for device information"""
        data = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Nmap scan report for' in line:
                hostname_match = re.search(r'for ([^\s(]+)', line)
                if hostname_match and not re.match(r'\d+\.\d+\.\d+\.\d+', hostname_match.group(1)):
                    data['hostname'] = hostname_match.group(1)
            
            elif line.startswith('OS:') or 'OS details:' in line:
                data['os_name'] = line.split(':', 1)[1].strip()
            
            elif 'MAC Address:' in line:
                mac_match = re.search(r'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})', line, re.I)
                if mac_match:
                    data['mac_address'] = mac_match.group(1)
                
                vendor_match = re.search(r'\((.+)\)$', line)
                if vendor_match:
                    data['vendor'] = vendor_match.group(1)
        
        return data

    def _classify_device(self, device: DeviceRecord) -> str:
        """Enhanced device classification using comprehensive patterns"""
        # Combine all available text for classification
        text_fields = [
            device.hostname or '',
            device.system_description or '',
            device.os_name or '',
            device.vendor or ''
        ]
        
        text_to_check = ' '.join(text_fields).lower()
        
        # Check against enhanced device patterns
        for device_type, patterns in ENHANCED_DEVICE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_to_check):
                    return device_type
        
        # Fallback classification based on IP patterns
        try:
            octets = device.ip.split('.')
            if octets[-1] in ['1', '254']:
                return 'router'
        except:
            pass
        
        # Default classification
        if device.hostname:
            return 'workstation'
        else:
            return 'unknown'

    async def _collect_mac_table(self, ip: str, community: str) -> List[Dict]:
        """Collect MAC address table from switch"""
        mac_entries = []
        
        try:
            # Walk the bridge forwarding database
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['dot1dTpFdbAddress'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['dot1dTpFdbPort'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['dot1dTpFdbStatus'])),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                
                mac_addr = None
                port = None
                status = None
                
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = str(oid)
                    
                    if ENHANCED_OIDS['dot1dTpFdbAddress'] in oid_str:
                        # Convert MAC address from SNMP format
                        mac_bytes = bytes.fromhex(str(value).replace(' ', ''))
                        if len(mac_bytes) == 6:
                            mac_addr = ':'.join(f'{b:02x}' for b in mac_bytes)
                    elif ENHANCED_OIDS['dot1dTpFdbPort'] in oid_str:
                        port = int(value)
                    elif ENHANCED_OIDS['dot1dTpFdbStatus'] in oid_str:
                        status = int(value)
                
                if mac_addr and port and status == 3:  # Status 3 = learned
                    mac_entries.append({
                        'mac_address': mac_addr,
                        'port': port,
                        'status': 'learned',
                        'vlan_id': 1  # Default VLAN, would be enhanced with Q-BRIDGE
                    })
                    
        except Exception as e:
            logger.debug(f"MAC table collection failed for {ip}: {e}")
        
        return mac_entries

    async def _collect_arp_table(self, ip: str, community: str) -> List[Dict]:
        """Collect ARP table from router"""
        arp_entries = []
        
        try:
            # Walk the IP-to-Media table
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['ipNetToMediaNetAddress'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['ipNetToMediaPhysAddress'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['ipNetToMediaType'])),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                
                ip_addr = None
                mac_addr = None
                entry_type = None
                
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = str(oid)
                    
                    if ENHANCED_OIDS['ipNetToMediaNetAddress'] in oid_str:
                        ip_addr = str(value)
                    elif ENHANCED_OIDS['ipNetToMediaPhysAddress'] in oid_str:
                        # Convert MAC address from SNMP format
                        mac_bytes = bytes.fromhex(str(value).replace(' ', ''))
                        if len(mac_bytes) == 6:
                            mac_addr = ':'.join(f'{b:02x}' for b in mac_bytes)
                    elif ENHANCED_OIDS['ipNetToMediaType'] in oid_str:
                        entry_type = int(value)
                
                if ip_addr and mac_addr and entry_type in [3, 4]:  # 3=dynamic, 4=static
                    # Try DNS resolution
                    dns_name = None
                    try:
                        dns_name = socket.gethostbyaddr(ip_addr)[0]
                    except:
                        pass
                    
                    arp_entries.append({
                        'ip_address': ip_addr,
                        'mac_address': mac_addr,
                        'type': 'dynamic' if entry_type == 3 else 'static',
                        'dns_name': dns_name
                    })
                    
        except Exception as e:
            logger.debug(f"ARP table collection failed for {ip}: {e}")
        
        return arp_entries

    async def _discover_cdp_neighbors(self, ip: str, community: str) -> List[Dict]:
        """Discover CDP neighbors"""
        neighbors = []
        
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['cdpCacheDeviceId'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['cdpCacheDevicePort'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['cdpCachePlatform'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['cdpCacheAddress'])),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                
                neighbor = {'protocol': 'CDP'}
                
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = str(oid)
                    
                    if ENHANCED_OIDS['cdpCacheDeviceId'] in oid_str:
                        neighbor['remote_device'] = str(value)
                    elif ENHANCED_OIDS['cdpCacheDevicePort'] in oid_str:
                        neighbor['remote_port'] = str(value)
                    elif ENHANCED_OIDS['cdpCachePlatform'] in oid_str:
                        neighbor['platform'] = str(value)
                    elif ENHANCED_OIDS['cdpCacheAddress'] in oid_str:
                        neighbor['remote_ip'] = str(value)
                
                if neighbor.get('remote_device'):
                    neighbors.append(neighbor)
                    
        except Exception as e:
            logger.debug(f"CDP discovery failed for {ip}: {e}")
        
        return neighbors

    async def _discover_lldp_neighbors(self, ip: str, community: str) -> List[Dict]:
        """Discover LLDP neighbors"""
        neighbors = []
        
        try:
            for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['lldpRemSysName'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['lldpRemPortId'])),
                ObjectType(ObjectIdentity(ENHANCED_OIDS['lldpRemSysDesc'])),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                
                neighbor = {'protocol': 'LLDP'}
                
                for varBind in varBinds:
                    oid, value = varBind
                    oid_str = str(oid)
                    
                    if ENHANCED_OIDS['lldpRemSysName'] in oid_str:
                        neighbor['remote_device'] = str(value)
                    elif ENHANCED_OIDS['lldpRemPortId'] in oid_str:
                        neighbor['remote_port'] = str(value)
                    elif ENHANCED_OIDS['lldpRemSysDesc'] in oid_str:
                        neighbor['description'] = str(value)
                
                if neighbor.get('remote_device'):
                    neighbors.append(neighbor)
                    
        except Exception as e:
            logger.debug(f"LLDP discovery failed for {ip}: {e}")
        
        return neighbors

    # Database storage methods
    
    async def _store_device(self, device: DeviceRecord):
        """Store device record in database with historical continuity"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO devices (
                    ip, hostname, mac_address, vendor, model, os_name, os_version,
                    device_type, system_description, system_object_id, contact,
                    location, uptime, active, first_seen, last_seen, last_discover,
                    last_macsuck, last_arpnip, skip_count, defer_until,
                    snmp_capable, snmp_community, has_bridge_mib, has_cdp, has_lldp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device.ip, device.hostname, device.mac_address, device.vendor,
                device.model, device.os_name, device.os_version, device.device_type,
                device.system_description, device.system_object_id, device.contact,
                device.location, device.uptime, device.active,
                device.first_seen.isoformat(), device.last_seen.isoformat(),
                device.last_discover.isoformat() if device.last_discover else None,
                device.last_macsuck.isoformat() if device.last_macsuck else None,
                device.last_arpnip.isoformat() if device.last_arpnip else None,
                device.skip_count,
                device.defer_until.isoformat() if device.defer_until else None,
                device.snmp_capable, device.snmp_community, device.has_bridge_mib,
                device.has_cdp, device.has_lldp
            ))

    async def _store_mac_entries(self, device_ip: str, mac_entries: List[Dict]):
        """Store MAC entries with historical continuity"""
        now = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Mark old entries as inactive
            cursor.execute(
                'UPDATE mac_entries SET active = FALSE WHERE device_ip = ?',
                (device_ip,)
            )
            
            # Insert new entries
            for entry in mac_entries:
                cursor.execute('''
                    INSERT OR REPLACE INTO mac_entries (
                        mac_address, device_ip, port_name, vlan_id, active,
                        first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, TRUE, ?, ?)
                ''', (
                    entry['mac_address'], device_ip, str(entry.get('port', '')),
                    entry.get('vlan_id', 1), now, now
                ))

    async def _store_arp_entries(self, device_ip: str, arp_entries: List[Dict]):
        """Store ARP entries with historical continuity"""
        now = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Mark old entries as inactive
            cursor.execute(
                'UPDATE arp_entries SET active = FALSE WHERE device_ip = ?',
                (device_ip,)
            )
            
            # Insert new entries
            for entry in arp_entries:
                # Update router history
                router_history = json.dumps({
                    f"seen_on_router_first": now,
                    f"seen_on_router_last": now
                })
                
                cursor.execute('''
                    INSERT OR REPLACE INTO arp_entries (
                        ip_address, mac_address, device_ip, active, dns_name,
                        first_seen, last_seen, router_history
                    ) VALUES (?, ?, ?, TRUE, ?, ?, ?, ?)
                ''', (
                    entry['ip_address'], entry['mac_address'], device_ip,
                    entry.get('dns_name'), now, now, router_history
                ))

    async def _store_topology_links(self, device_ip: str, neighbors: List[Dict]):
        """Store topology links with historical continuity"""
        now = datetime.now().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Mark old links as inactive
            cursor.execute(
                'UPDATE topology_links SET active = FALSE WHERE local_device = ?',
                (device_ip,)
            )
            
            # Insert new links
            for neighbor in neighbors:
                cursor.execute('''
                    INSERT OR REPLACE INTO topology_links (
                        local_device, local_port, remote_device, remote_port,
                        protocol, active, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, TRUE, ?, ?)
                ''', (
                    device_ip, neighbor.get('local_port', ''),
                    neighbor.get('remote_device', ''), neighbor.get('remote_port', ''),
                    neighbor.get('protocol', ''), now, now
                ))

    async def _store_job_result(self, job: JobRequest, result: JobResult):
        """Store job result in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO jobs (
                    job_id, job_type, target, priority, parameters, status,
                    created_at, started_at, completed_at, retry_count, defer_until,
                    parent_job_id, result_data, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                job.job_id, job.job_type.value, job.target, job.priority.value,
                json.dumps(job.parameters), result.status.value,
                job.created_at.isoformat(), result.started_at.isoformat(),
                result.completed_at.isoformat() if result.completed_at else None,
                job.retry_count,
                job.defer_until.isoformat() if job.defer_until else None,
                job.parent_job_id, json.dumps(result.data) if result.data else None,
                result.error
            ))

    def get_discovery_summary(self) -> Dict:
        """Get summary of discovery results"""
        device_types = defaultdict(int)
        vendors = defaultdict(int)
        os_types = defaultdict(int)
        active_devices = 0
        snmp_devices = 0
        
        for device in self.devices.values():
            if device.active:
                active_devices += 1
                device_types[device.device_type or 'unknown'] += 1
                vendors[device.vendor or 'unknown'] += 1
                os_types[device.os_name or 'unknown'] += 1
                
                if device.snmp_capable:
                    snmp_devices += 1
        
        return {
            'total_devices': len(self.devices),
            'active_devices': active_devices,
            'snmp_devices': snmp_devices,
            'device_types': dict(device_types),
            'vendors': dict(vendors),
            'operating_systems': dict(os_types),
            'jobs_completed': self.stats['jobs_completed'],
            'jobs_failed': self.stats['jobs_failed'],
            'jobs_deferred': self.stats['jobs_deferred'],
            'discovery_duration': (
                (datetime.now() - self.stats['discovery_start_time']).total_seconds()
                if self.stats['discovery_start_time'] else 0
            )
        }

    def export_devices(self) -> List[Dict]:
        """Export discovered devices as dictionaries"""
        return [asdict(device) for device in self.devices.values() if device.active]

    async def cleanup(self):
        """Cleanup resources"""
        if self.executor:
            self.executor.shutdown(wait=True)
        logger.info("Scanner cleanup completed")

# Main function for easy integration
async def run_job_based_discovery(initial_targets: List[str], scan_id: str = None) -> Tuple[Dict, Dict]:
    """
    Run job-based network discovery
    
    Args:
        initial_targets: List of IP addresses or subnets to discover
        scan_id: Optional scan ID for progress tracking
    
    Returns:
        Tuple of (devices_dict, summary_dict)
    """
    scanner = JobBasedScanner()
    
    try:
        devices, stats = await scanner.start_discovery(initial_targets, scan_id)
        summary = scanner.get_discovery_summary()
        
        # Convert devices to dict format
        devices_dict = {ip: asdict(device) for ip, device in devices.items() if device.active}
        
        return devices_dict, summary
        
    finally:
        await scanner.cleanup()

if __name__ == "__main__":
    # Example usage
    async def main():
        initial_targets = ['192.168.1.0/24']
        devices, summary = await run_job_based_discovery(initial_targets)
        
        print(f"Discovery Summary:")
        print(f"Total devices: {summary['total_devices']}")
        print(f"Active devices: {summary['active_devices']}")
        print(f"SNMP devices: {summary['snmp_devices']}")
        print(f"Device types: {summary['device_types']}")
        print(f"Jobs completed: {summary['jobs_completed']}")
        print(f"Jobs failed: {summary['jobs_failed']}")
        
        for ip, device in devices.items():
            print(f"\nDevice: {ip}")
            print(f"  Hostname: {device.get('hostname', 'Unknown')}")
            print(f"  Type: {device.get('device_type', 'unknown')}")
            print(f"  Vendor: {device.get('vendor', 'Unknown')}")
            print(f"  SNMP: {'Yes' if device.get('snmp_capable') else 'No'}")
    
    asyncio.run(main())