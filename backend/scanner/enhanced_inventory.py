"""
Enhanced Inventory Management System
Inspired by Netdisco's PostgreSQL-based device tracking
Provides comprehensive device lifecycle management and change tracking
"""

import asyncio
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from pathlib import Path

# Optional pandas import for Docker compatibility
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logging.warning("Pandas not available. Some export features will be limited.")

logger = logging.getLogger(__name__)

class ChangeType(Enum):
    """Types of changes tracked in the inventory"""
    NEW_DEVICE = "new_device"
    DEVICE_DISAPPEARED = "device_disappeared"
    DEVICE_RETURNED = "device_returned"
    HOSTNAME_CHANGED = "hostname_changed"
    OS_CHANGED = "os_changed"
    VENDOR_CHANGED = "vendor_changed"
    NEW_PORT = "new_port"
    PORT_CLOSED = "port_closed"
    SERVICE_CHANGED = "service_changed"
    LOCATION_MOVED = "location_moved"  # For topology changes
    NEIGHBOR_CHANGED = "neighbor_changed"
    VLAN_CHANGED = "vlan_changed"

@dataclass
class DeviceChange:
    """Represents a change in device state"""
    change_id: str
    device_ip: str
    change_type: ChangeType
    old_value: Optional[str]
    new_value: Optional[str]
    timestamp: datetime
    scan_id: str
    details: Optional[Dict] = None
    
    def __post_init__(self):
        if isinstance(self.change_type, str):
            self.change_type = ChangeType(self.change_type)

@dataclass
class DeviceFingerprint:
    """Device fingerprint for change detection"""
    ip: str
    hostname_hash: str
    os_hash: str
    vendor_hash: str
    ports_hash: str
    services_hash: str
    mac_hash: str
    
    @classmethod
    def from_device(cls, device_data: Dict) -> 'DeviceFingerprint':
        """Create fingerprint from device data"""
        def safe_hash(value):
            if value is None:
                return ""
            return hashlib.md5(str(value).encode()).hexdigest()[:8]
        
        # Create hash of ports and services
        ports = device_data.get('ports', [])
        ports_str = ','.join(sorted([f"{p.get('port', 0)}:{p.get('protocol', 'tcp')}" for p in ports]))
        services_str = ','.join(sorted([p.get('service', '') for p in ports if p.get('service')]))
        
        return cls(
            ip=device_data.get('ip', ''),
            hostname_hash=safe_hash(device_data.get('hostname')),
            os_hash=safe_hash(device_data.get('os')),
            vendor_hash=safe_hash(device_data.get('vendor')),
            ports_hash=safe_hash(ports_str),
            services_hash=safe_hash(services_str),
            mac_hash=safe_hash(device_data.get('mac_address'))
        )

class EnhancedInventoryManager:
    """
    Enhanced inventory management system with comprehensive device tracking,
    change detection, and lifecycle management inspired by Netdisco
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Use environment variable or default to local data directory
            import os
            db_path = os.getenv('DATABASE_PATH', '../data/enhanced_inventory.db')
            # Ensure the directory exists
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
        self.db_path = db_path
        self.initialize_enhanced_db()
        self._device_cache = {}
        self._fingerprint_cache = {}
    
    def initialize_enhanced_db(self):
        """Initialize enhanced database schema with comprehensive tracking"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Enhanced devices table with more fields
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT NOT NULL UNIQUE,
                        hostname TEXT,
                        mac_address TEXT,
                        vendor TEXT,
                        model TEXT,
                        os TEXT,
                        os_version TEXT,
                        device_type TEXT,
                        location TEXT,
                        contact TEXT,
                        description TEXT,
                        uptime INTEGER,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        confidence_score REAL DEFAULT 1.0,
                        discovery_methods TEXT,
                        fingerprint_hash TEXT,
                        custom_name TEXT,
                        notes TEXT,
                        tags TEXT,
                        criticality_level TEXT DEFAULT 'normal',
                        compliance_status TEXT,
                        asset_tag TEXT,
                        purchase_date DATE,
                        warranty_expiry DATE,
                        department TEXT,
                        owner TEXT
                    )
                ''')
                
                # Enhanced ports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        port_number INTEGER,
                        protocol TEXT,
                        state TEXT,
                        service_name TEXT,
                        service_product TEXT,
                        service_version TEXT,
                        service_info TEXT,
                        banner TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        risk_level TEXT DEFAULT 'low',
                        FOREIGN KEY (device_id) REFERENCES devices(id)
                    )
                ''')
                
                # Device interfaces table (for SNMP data)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_interfaces (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        interface_index INTEGER,
                        interface_name TEXT,
                        interface_type TEXT,
                        interface_speed BIGINT,
                        admin_status TEXT,
                        oper_status TEXT,
                        mac_address TEXT,
                        ip_address TEXT,
                        subnet_mask TEXT,
                        vlan_id INTEGER,
                        description TEXT,
                        last_change TIMESTAMP,
                        in_octets BIGINT,
                        out_octets BIGINT,
                        in_errors INTEGER,
                        out_errors INTEGER,
                        FOREIGN KEY (device_id) REFERENCES devices(id)
                    )
                ''')
                
                # Device vulnerabilities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        cve_id TEXT,
                        cvss_score REAL,
                        description TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(device_id, cve_id),
                        FOREIGN KEY (device_id) REFERENCES devices(id)
                    )
                ''')

                # Network topology table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS topology (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        neighbor_device_id INTEGER,
                        local_interface TEXT,
                        remote_interface TEXT,
                        connection_type TEXT,  -- cdp, lldp, manual
                        discovered_via TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        FOREIGN KEY (device_id) REFERENCES devices(id),
                        FOREIGN KEY (neighbor_device_id) REFERENCES devices(id)
                    )
                ''')
                
                # Enhanced changes table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_changes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        change_id TEXT UNIQUE,
                        device_id INTEGER,
                        device_ip TEXT,
                        change_type TEXT,
                        old_value TEXT,
                        new_value TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        scan_id TEXT,
                        details TEXT,
                        severity TEXT DEFAULT 'info',
                        acknowledged BOOLEAN DEFAULT 0,
                        acknowledged_by TEXT,
                        acknowledged_at TIMESTAMP,
                        FOREIGN KEY (device_id) REFERENCES devices(id)
                    )
                ''')
                
                # VLAN tracking table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vlans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vlan_id INTEGER,
                        vlan_name TEXT,
                        description TEXT,
                        status TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Device VLAN membership
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_vlans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id INTEGER,
                        vlan_id INTEGER,
                        interface_name TEXT,
                        access_type TEXT,  -- access, trunk
                        native_vlan BOOLEAN DEFAULT 0,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (device_id) REFERENCES devices(id),
                        FOREIGN KEY (vlan_id) REFERENCES vlans(id)
                    )
                ''')
                
                # Scan metadata table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_metadata (
                        scan_id TEXT PRIMARY KEY,
                        scan_type TEXT,
                        subnet TEXT,
                        start_time TIMESTAMP,
                        end_time TIMESTAMP,
                        duration_seconds INTEGER,
                        devices_discovered INTEGER,
                        changes_detected INTEGER,
                        deep_scan BOOLEAN DEFAULT 0,
                        scan_parameters TEXT,
                        status TEXT DEFAULT 'completed'
                    )
                ''')
                
                # Device groups for organization
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_groups (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        group_name TEXT UNIQUE,
                        group_type TEXT,  -- department, location, function
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Device group membership
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS device_group_members (
                        device_id INTEGER,
                        group_id INTEGER,
                        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (device_id) REFERENCES devices(id),
                        FOREIGN KEY (group_id) REFERENCES device_groups(id),
                        PRIMARY KEY (device_id, group_id)
                    )
                ''')
                
                # Create comprehensive indexes
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)',
                    'CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)',
                    'CREATE INDEX IF NOT EXISTS idx_devices_device_type ON devices(device_type)',
                    'CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor)',
                    'CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)',
                    'CREATE INDEX IF NOT EXISTS idx_ports_device ON device_ports(device_id)',
                    'CREATE INDEX IF NOT EXISTS idx_ports_number ON device_ports(port_number)',
                    'CREATE INDEX IF NOT EXISTS idx_ports_service ON device_ports(service_name)',
                    'CREATE INDEX IF NOT EXISTS idx_interfaces_device ON device_interfaces(device_id)',
                    'CREATE INDEX IF NOT EXISTS idx_vulns_device ON device_vulnerabilities(device_id)',
                    'CREATE INDEX IF NOT EXISTS idx_vulns_cve ON device_vulnerabilities(cve_id)',
                    'CREATE INDEX IF NOT EXISTS idx_topology_device ON topology(device_id)',
                    'CREATE INDEX IF NOT EXISTS idx_topology_neighbor ON topology(neighbor_device_id)',
                    'CREATE INDEX IF NOT EXISTS idx_changes_device ON device_changes(device_id)',
                    'CREATE INDEX IF NOT EXISTS idx_changes_timestamp ON device_changes(timestamp)',
                    'CREATE INDEX IF NOT EXISTS idx_changes_type ON device_changes(change_type)',
                    'CREATE INDEX IF NOT EXISTS idx_vlans_id ON vlans(vlan_id)',
                    'CREATE INDEX IF NOT EXISTS idx_device_vlans_device ON device_vlans(device_id)'
                ]
                
                for index_sql in indexes:
                    cursor.execute(index_sql)
                
                conn.commit()
                logger.info("Enhanced inventory database initialized successfully")
                
        except Exception as e:
            logger.error(f"Enhanced database initialization failed: {e}")
            raise
    
    async def process_scan_results(self, devices: Dict, scan_id: str, scan_metadata: Dict = None) -> Dict:
        """
        Process scan results and detect changes
        """
        logger.info(f"Processing scan results for scan {scan_id}")
        
        changes_detected = []
        devices_processed = 0
        new_devices = 0
        
        # Store scan metadata
        if scan_metadata:
            self._store_scan_metadata(scan_id, scan_metadata)
        
        for ip, device_data in devices.items():
            try:
                # Convert device data if it's a dataclass
                if hasattr(device_data, '__dict__'):
                    device_dict = asdict(device_data)
                else:
                    device_dict = device_data
                
                device_dict['ip'] = ip  # Ensure IP is set
                
                # Process device and detect changes
                device_changes = await self._process_device(device_dict, scan_id)
                changes_detected.extend(device_changes)
                
                devices_processed += 1
                
                # Check if this is a new device
                if any(change.change_type == ChangeType.NEW_DEVICE for change in device_changes):
                    new_devices += 1
                
            except Exception as e:
                logger.error(f"Error processing device {ip}: {e}")
        
        # Mark devices that weren't seen in this scan
        await self._mark_missing_devices(scan_id, list(devices.keys()))
        
        # Update scan metadata with results
        self._update_scan_results(scan_id, devices_processed, len(changes_detected))
        
        logger.info(f"Scan processing complete: {devices_processed} devices, {len(changes_detected)} changes, {new_devices} new devices")
        
        return {
            'devices_processed': devices_processed,
            'changes_detected': len(changes_detected),
            'new_devices': new_devices,
            'changes': [asdict(change) for change in changes_detected]
        }
    
    async def _process_device(self, device_data: Dict, scan_id: str) -> List[DeviceChange]:
        """
        Process a single device and detect changes
        """
        ip = device_data['ip']
        changes = []
        
        # Get or create device record
        device_id = self._get_or_create_device(device_data, scan_id)
        
        # Generate current fingerprint
        current_fingerprint = DeviceFingerprint.from_device(device_data)
        
        # Get previous fingerprint
        previous_fingerprint = self._fingerprint_cache.get(ip)
        
        if previous_fingerprint is None:
            # First time seeing this device
            changes.append(DeviceChange(
                change_id=self._generate_change_id(ip, ChangeType.NEW_DEVICE, scan_id),
                device_ip=ip,
                change_type=ChangeType.NEW_DEVICE,
                old_value=None,
                new_value=device_data.get('hostname', 'Unknown'),
                timestamp=datetime.now(),
                scan_id=scan_id,
                details=device_data
            ))
        else:
            # Compare fingerprints to detect changes
            changes.extend(self._detect_changes(ip, previous_fingerprint, current_fingerprint, device_data, scan_id))
        
        # Update fingerprint cache
        self._fingerprint_cache[ip] = current_fingerprint
        
        # Update device ports
        await self._update_device_ports(device_id, device_data.get('ports', []), scan_id)
        
        # Update device interfaces if available
        if 'interfaces' in device_data:
            await self._update_device_interfaces(device_id, device_data['interfaces'])
        
        # Store all changes
        for change in changes:
            self._store_change(change, device_id)
        
        # Store vulnerabilities if present
        if device_data.get('cves'):
            self._update_device_vulnerabilities(device_id, device_data['cves'])

        return changes
    
    def _get_or_create_device(self, device_data: Dict, scan_id: str) -> int:
        """
        Get existing device or create new one
        """
        ip = device_data['ip']
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if device exists
                cursor.execute('SELECT id FROM devices WHERE ip = ?', (ip,))
                result = cursor.fetchone()
                
                if result:
                    device_id = result[0]
                    # Update existing device
                    self._update_device_record(cursor, device_id, device_data)
                else:
                    # Create new device
                    device_id = self._create_device_record(cursor, device_data, scan_id)
                
                conn.commit()
                return device_id
                
        except Exception as e:
            logger.error(f"Error managing device record for {ip}: {e}")
            raise
    
    def _create_device_record(self, cursor, device_data: Dict, scan_id: str) -> int:
        """
        Create new device record
        """
        discovery_methods = json.dumps(device_data.get('discovered_by', []))
        fingerprint = DeviceFingerprint.from_device(device_data)
        fingerprint_hash = hashlib.md5(json.dumps(asdict(fingerprint)).encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO devices (
                ip, hostname, mac_address, vendor, model, os, os_version,
                device_type, location, contact, description, uptime,
                discovery_methods, fingerprint_hash, first_seen, last_seen,
                open_ports, vulnerabilities
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_data['ip'],
            device_data.get('hostname'),
            device_data.get('mac_address'),
            device_data.get('vendor'),
            device_data.get('model'),
            device_data.get('os'),
            device_data.get('os_version'),
            device_data.get('device_type'),
            device_data.get('location'),
            device_data.get('contact'),
            device_data.get('description'),
            device_data.get('uptime'),
            discovery_methods,
            fingerprint_hash,
            datetime.now(),
            datetime.now(),
            device_data.get('open_ports', 0),
            len(device_data.get('cves', []))
        ))
        
        return cursor.lastrowid
    
    def _update_device_record(self, cursor, device_id: int, device_data: Dict):
        """
        Update existing device record
        """
        discovery_methods = json.dumps(device_data.get('discovered_by', []))
        fingerprint = DeviceFingerprint.from_device(device_data)
        fingerprint_hash = hashlib.md5(json.dumps(asdict(fingerprint)).encode()).hexdigest()
        
        cursor.execute('''
            UPDATE devices SET
                hostname = ?, mac_address = ?, vendor = ?, model = ?,
                os = ?, os_version = ?, device_type = ?, location = ?,
                contact = ?, description = ?, uptime = ?, discovery_methods = ?,
                fingerprint_hash = ?, last_seen = ?, last_changed = ?
            WHERE id = ?
        ''', (
            device_data.get('hostname'),
            device_data.get('mac_address'),
            device_data.get('vendor'),
            device_data.get('model'),
            device_data.get('os'),
            device_data.get('os_version'),
            device_data.get('device_type'),
            device_data.get('location'),
            device_data.get('contact'),
            device_data.get('description'),
            device_data.get('uptime'),
            discovery_methods,
            fingerprint_hash,
            datetime.now(),
            datetime.now(),
            device_id
        ))
    
    def _detect_changes(self, ip: str, old_fp: DeviceFingerprint, new_fp: DeviceFingerprint, 
                       device_data: Dict, scan_id: str) -> List[DeviceChange]:
        """
        Detect changes between fingerprints
        """
        changes = []
        
        # Hostname change
        if old_fp.hostname_hash != new_fp.hostname_hash:
            changes.append(DeviceChange(
                change_id=self._generate_change_id(ip, ChangeType.HOSTNAME_CHANGED, scan_id),
                device_ip=ip,
                change_type=ChangeType.HOSTNAME_CHANGED,
                old_value="Previous hostname",
                new_value=device_data.get('hostname', 'Unknown'),
                timestamp=datetime.now(),
                scan_id=scan_id
            ))
        
        # OS change
        if old_fp.os_hash != new_fp.os_hash:
            changes.append(DeviceChange(
                change_id=self._generate_change_id(ip, ChangeType.OS_CHANGED, scan_id),
                device_ip=ip,
                change_type=ChangeType.OS_CHANGED,
                old_value="Previous OS",
                new_value=device_data.get('os', 'Unknown'),
                timestamp=datetime.now(),
                scan_id=scan_id
            ))
        
        # Vendor change
        if old_fp.vendor_hash != new_fp.vendor_hash:
            changes.append(DeviceChange(
                change_id=self._generate_change_id(ip, ChangeType.VENDOR_CHANGED, scan_id),
                device_ip=ip,
                change_type=ChangeType.VENDOR_CHANGED,
                old_value="Previous vendor",
                new_value=device_data.get('vendor', 'Unknown'),
                timestamp=datetime.now(),
                scan_id=scan_id
            ))
        
        # Ports change
        if old_fp.ports_hash != new_fp.ports_hash:
            changes.append(DeviceChange(
                change_id=self._generate_change_id(ip, ChangeType.NEW_PORT, scan_id),
                device_ip=ip,
                change_type=ChangeType.NEW_PORT,
                old_value="Previous port configuration",
                new_value="New port configuration",
                timestamp=datetime.now(),
                scan_id=scan_id,
                details={'ports': device_data.get('ports', [])}
            ))
        
        # Services change
        if old_fp.services_hash != new_fp.services_hash:
            changes.append(DeviceChange(
                change_id=self._generate_change_id(ip, ChangeType.SERVICE_CHANGED, scan_id),
                device_ip=ip,
                change_type=ChangeType.SERVICE_CHANGED,
                old_value="Previous services",
                new_value="New services",
                timestamp=datetime.now(),
                scan_id=scan_id
            ))
        
        return changes
    
    async def _update_device_ports(self, device_id: int, ports: List[Dict], scan_id: str):
        """
        Update device ports information
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get existing ports
                cursor.execute('''
                    SELECT port_number, protocol, service_name 
                    FROM device_ports 
                    WHERE device_id = ?
                ''', (device_id,))
                
                existing_ports = {
                    (row[0], row[1]): row[2] for row in cursor.fetchall()
                }
                
                # Update or insert ports
                for port_data in ports:
                    port_key = (port_data.get('port'), port_data.get('protocol', 'tcp'))
                    
                    if port_key in existing_ports:
                        # Update existing port
                        cursor.execute('''
                            UPDATE device_ports SET
                                state = ?, service_name = ?, service_product = ?,
                                service_version = ?, service_info = ?, last_seen = ?
                            WHERE device_id = ? AND port_number = ? AND protocol = ?
                        ''', (
                            port_data.get('state', 'open'),
                            port_data.get('service'),
                            port_data.get('product'),
                            port_data.get('version'),
                            port_data.get('extrainfo'),
                            datetime.now(),
                            device_id,
                            port_data.get('port'),
                            port_data.get('protocol', 'tcp')
                        ))
                    else:
                        # Insert new port
                        cursor.execute('''
                            INSERT INTO device_ports (
                                device_id, port_number, protocol, state,
                                service_name, service_product, service_version,
                                service_info, risk_level
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            device_id,
                            port_data.get('port'),
                            port_data.get('protocol', 'tcp'),
                            port_data.get('state', 'open'),
                            port_data.get('service'),
                            port_data.get('product'),
                            port_data.get('version'),
                            port_data.get('extrainfo'),
                            self._calculate_port_risk(port_data)
                        ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating device ports: {e}")
    
    def _calculate_port_risk(self, port_data: Dict) -> str:
        """
        Calculate risk level for a port based on service and port number
        """
        port = port_data.get('port', 0)
        service = port_data.get('service', '').lower()
        
        # High-risk ports/services
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900]
        high_risk_services = ['ftp', 'telnet', 'rlogin', 'rsh', 'vnc', 'rdp']
        
        if port in high_risk_ports or any(srv in service for srv in high_risk_services):
            return 'high'
        
        # Medium-risk ports
        medium_risk_ports = [22, 80, 443, 993, 995]
        if port in medium_risk_ports:
            return 'medium'
        
        return 'low'

    def _update_device_vulnerabilities(self, device_id: int, cves: List[Dict]):
        """
        Upsert device vulnerabilities
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for v in cves:
                    cursor.execute('''
                        INSERT INTO device_vulnerabilities (
                            device_id, cve_id, cvss_score, description
                        ) VALUES (?, ?, ?, ?)
                        ON CONFLICT(device_id, cve_id) DO UPDATE SET
                            cvss_score = excluded.cvss_score,
                            description = excluded.description,
                            last_seen = CURRENT_TIMESTAMP
                    ''', (
                        device_id,
                        v.get('id'),
                        v.get('cvss', 0.0),
                        v.get('description')
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"Error updating device vulnerabilities: {e}")

    # === Public getters used by API ===
    def get_vulnerabilities(self, severity: str = 'all', host: Optional[str] = None) -> List[Dict]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                params = []
                where = []
                if host:
                    where.append('d.ip = ?')
                    params.append(host)
                if severity and severity != 'all':
                    # Map severity to CVSS ranges
                    if severity == 'critical':
                        where.append('v.cvss_score >= 9.0')
                    elif severity == 'high':
                        where.append('v.cvss_score >= 7.0 AND v.cvss_score < 9.0')
                    elif severity == 'medium':
                        where.append('v.cvss_score >= 4.0 AND v.cvss_score < 7.0')
                    elif severity == 'low':
                        where.append('v.cvss_score > 0 AND v.cvss_score < 4.0')
                where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''
                cursor.execute(f'''
                    SELECT d.ip, d.hostname, v.cve_id, v.cvss_score, v.description, v.last_seen
                    FROM device_vulnerabilities v
                    JOIN devices d ON v.device_id = d.id
                    {where_sql}
                    ORDER BY v.cvss_score DESC, v.last_seen DESC
                ''', params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities: {e}")
            return []

    def get_total_open_ports(self) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM device_ports WHERE state = 'open'")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error counting open ports: {e}")
            return 0

    def get_last_scan_time(self) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(start_time) FROM scan_metadata")
                res = cursor.fetchone()[0]
                return res
        except Exception as e:
            logger.error(f"Error getting last scan time: {e}")
            return None

    def get_vulnerability_count(self) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM device_vulnerabilities")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error counting vulnerabilities: {e}")
            return 0
    
    async def _update_device_interfaces(self, device_id: int, interfaces: List[Dict]):
        """
        Update device interfaces (from SNMP data)
        """
        # Implementation for SNMP interface data
        # Simplified for brevity
        pass
    
    async def _mark_missing_devices(self, scan_id: str, seen_ips: List[str]):
        """
        Mark devices that weren't seen in this scan as potentially disappeared
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get devices that were active but not seen
                placeholders = ','.join(['?' for _ in seen_ips])
                cursor.execute(f'''
                    SELECT ip FROM devices 
                    WHERE status = 'active' 
                    AND ip NOT IN ({placeholders})
                    AND last_seen < datetime('now', '-1 hour')
                ''', seen_ips)
                
                missing_devices = [row[0] for row in cursor.fetchall()]
                
                for ip in missing_devices:
                    # Create disappearance change record
                    change = DeviceChange(
                        change_id=self._generate_change_id(ip, ChangeType.DEVICE_DISAPPEARED, scan_id),
                        device_ip=ip,
                        change_type=ChangeType.DEVICE_DISAPPEARED,
                        old_value="active",
                        new_value="missing",
                        timestamp=datetime.now(),
                        scan_id=scan_id
                    )
                    
                    # Get device ID for storing change
                    cursor.execute('SELECT id FROM devices WHERE ip = ?', (ip,))
                    result = cursor.fetchone()
                    if result:
                        self._store_change(change, result[0])
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error marking missing devices: {e}")
    
    def _store_change(self, change: DeviceChange, device_id: int):
        """
        Store a change record in the database
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                details_json = json.dumps(change.details) if change.details else None
                
                cursor.execute('''
                    INSERT OR REPLACE INTO device_changes (
                        change_id, device_id, device_ip, change_type,
                        old_value, new_value, timestamp, scan_id, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    change.change_id,
                    device_id,
                    change.device_ip,
                    change.change_type.value,
                    change.old_value,
                    change.new_value,
                    change.timestamp,
                    change.scan_id,
                    details_json
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error storing change: {e}")
    
    def _generate_change_id(self, ip: str, change_type: ChangeType, scan_id: str) -> str:
        """
        Generate unique change ID
        """
        content = f"{ip}:{change_type.value}:{scan_id}:{datetime.now().isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _store_scan_metadata(self, scan_id: str, metadata: Dict):
        """
        Store scan metadata
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO scan_metadata (
                        scan_id, scan_type, subnet, start_time, deep_scan, scan_parameters
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    metadata.get('scan_type', 'network'),
                    metadata.get('subnet'),
                    metadata.get('start_time', datetime.now()),
                    metadata.get('deep_scan', False),
                    json.dumps(metadata.get('parameters', {}))
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error storing scan metadata: {e}")
    
    def _update_scan_results(self, scan_id: str, devices_count: int, changes_count: int):
        """
        Update scan results
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE scan_metadata SET
                        end_time = ?, devices_discovered = ?, changes_detected = ?
                    WHERE scan_id = ?
                ''', (datetime.now(), devices_count, changes_count, scan_id))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating scan results: {e}")
    
    def get_device_history(self, ip: str, days: int = 30) -> Dict:
        """
        Get device change history
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days)
                
                cursor.execute('''
                    SELECT change_type, old_value, new_value, timestamp, scan_id, details
                    FROM device_changes
                    WHERE device_ip = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                ''', (ip, cutoff_date))
                
                changes = []
                for row in cursor.fetchall():
                    changes.append({
                        'change_type': row[0],
                        'old_value': row[1],
                        'new_value': row[2],
                        'timestamp': row[3],
                        'scan_id': row[4],
                        'details': json.loads(row[5]) if row[5] else None
                    })
                
                return {'device_ip': ip, 'changes': changes}
                
        except Exception as e:
            logger.error(f"Error getting device history: {e}")
            return {'device_ip': ip, 'changes': []}
    
    def get_topology_map(self) -> Dict:
        """
        Get network topology information
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get all devices with their connections
                cursor.execute('''
                    SELECT d1.ip, d1.hostname, d1.device_type,
                           d2.ip, d2.hostname, d2.device_type,
                           t.local_interface, t.remote_interface, t.connection_type
                    FROM topology t
                    JOIN devices d1 ON t.device_id = d1.id
                    JOIN devices d2 ON t.neighbor_device_id = d2.id
                    WHERE t.status = 'active'
                ''')
                
                connections = []
                nodes = set()
                
                for row in cursor.fetchall():
                    connection = {
                        'source': {'ip': row[0], 'hostname': row[1], 'type': row[2]},
                        'target': {'ip': row[3], 'hostname': row[4], 'type': row[5]},
                        'local_interface': row[6],
                        'remote_interface': row[7],
                        'connection_type': row[8]
                    }
                    connections.append(connection)
                    nodes.add(row[0])
                    nodes.add(row[3])
                
                return {
                    'nodes': list(nodes),
                    'connections': connections,
                    'total_devices': len(nodes)
                }
                
        except Exception as e:
            logger.error(f"Error getting topology: {e}")
            return {'nodes': [], 'connections': [], 'total_devices': 0}
    
    def get_enhanced_summary(self) -> Dict:
        """
        Get comprehensive inventory summary
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Device statistics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_devices,
                        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_devices,
                        COUNT(CASE WHEN device_type = 'server' THEN 1 END) as servers,
                        COUNT(CASE WHEN device_type = 'workstation' THEN 1 END) as workstations,
                        COUNT(CASE WHEN device_type = 'router' THEN 1 END) as routers,
                        COUNT(CASE WHEN device_type = 'switch' THEN 1 END) as switches
                    FROM devices
                ''')
                
                stats = cursor.fetchone()
                
                # Recent changes
                cursor.execute('''
                    SELECT COUNT(*) 
                    FROM device_changes 
                    WHERE timestamp >= datetime('now', '-24 hours')
                ''')
                
                recent_changes = cursor.fetchone()[0]
                
                # Port statistics
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_ports,
                        COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high_risk_ports,
                        COUNT(CASE WHEN service_name LIKE '%http%' THEN 1 END) as web_services
                    FROM device_ports
                    WHERE state = 'open'
                ''')
                
                port_stats = cursor.fetchone()
                
                return {
                    'total_devices': stats[0],
                    'active_devices': stats[1],
                    'device_breakdown': {
                        'servers': stats[2],
                        'workstations': stats[3],
                        'routers': stats[4],
                        'switches': stats[5]
                    },
                    'recent_changes_24h': recent_changes,
                    'port_statistics': {
                        'total_open_ports': port_stats[0],
                        'high_risk_ports': port_stats[1],
                        'web_services': port_stats[2]
                    }
                }
                
        except Exception as e:
            logger.error(f"Error getting enhanced summary: {e}")
            return {}
    
    def get_all_hosts(self, search: str = None, page: int = 1, per_page: int = 50) -> List[Dict]:
        """Get all hosts with optional search and pagination"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Base query using correct table names
                query = '''
                    SELECT d.*, 
                           COUNT(DISTINCT dp.port_number) as open_ports
                    FROM devices d
                    LEFT JOIN device_ports dp ON d.id = dp.device_id
                '''
                
                params = []
                if search:
                    query += ' WHERE d.ip LIKE ? OR d.hostname LIKE ? OR d.os LIKE ?'
                    search_param = f'%{search}%'
                    params.extend([search_param, search_param, search_param])
                
                query += '''
                    GROUP BY d.id
                    ORDER BY d.last_seen DESC
                    LIMIT ? OFFSET ?
                '''
                
                offset = (page - 1) * per_page
                params.extend([per_page, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                hosts = []
                for row in rows:
                    host = dict(row)
                    host['device_type'] = host.get('device_type', 'unknown')
                    host['discovery_methods'] = ['nmap']  # Default
                    host['confidence_score'] = host.get('confidence_score', 1.0)
                    host['last_changed'] = host.get('last_seen')
                    host['topology_connections'] = 0
                    host['vulnerabilities'] = 0  # No vulnerabilities table yet
                    host['max_cvss'] = None
                    hosts.append(host)
                
                return hosts
                
        except Exception as e:
            logger.error(f"Failed to get all hosts: {e}")
            return []

    def get_host_count(self) -> int:
        """Get total count of devices in inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM devices')
                count = cursor.fetchone()[0]
                return count
        except Exception as e:
            logger.error(f"Failed to get host count: {e}")
            return 0

    async def process_scan_results(self, devices: Dict, scan_id: str) -> Dict:
        """
        Process and store scan results in the enhanced inventory
        """
        try:
            results = {
                'devices_processed': 0,
                'devices_new': 0,
                'devices_updated': 0,
                'errors': []
            }
            
            logger.info(f"Processing scan results for {len(devices)} devices")
            
            for ip, device_info in devices.items():
                try:
                    # Convert DeviceInfo object to dict if needed
                    if hasattr(device_info, '__dict__'):
                        device_data = asdict(device_info)
                    else:
                        device_data = device_info
                    
                    # Add or update device
                    existing_device = self.get_device_by_ip(ip)
                    
                    if existing_device:
                        # Update existing device
                        await self.update_device(ip, device_data, scan_id)
                        results['devices_updated'] += 1
                        logger.debug(f"Updated device {ip}")
                    else:
                        # Add new device
                        await self.add_device(device_data, scan_id)
                        results['devices_new'] += 1
                        logger.debug(f"Added new device {ip}")
                    
                    results['devices_processed'] += 1
                    
                except Exception as e:
                    error_msg = f"Failed to process device {ip}: {str(e)}"
                    results['errors'].append(error_msg)
                    logger.error(error_msg)
            
            # Record scan metadata
            self.record_scan_metadata(scan_id, results)
            
            logger.info(f"Scan processing complete: {results['devices_new']} new, {results['devices_updated']} updated, {len(results['errors'])} errors")
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to process scan results: {e}")
            return {'error': str(e)}

    def get_device_by_ip(self, ip: str) -> Optional[Dict]:
        """Get device by IP address"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM devices WHERE ip = ?', (ip,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get device by IP {ip}: {e}")
            return None

    async def add_device(self, device_data: Dict, scan_id: str = None):
        """Add a new device to the inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Prepare device data
                now = datetime.now().isoformat()
                
                cursor.execute('''
                    INSERT INTO devices (
                        ip, hostname, mac_address, vendor, model, os, os_version,
                        device_type, location, contact, description, uptime,
                        first_seen, last_seen, last_changed, status, confidence_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_data.get('ip'),
                    device_data.get('hostname'),
                    device_data.get('mac_address'),
                    device_data.get('vendor'),
                    device_data.get('model'),
                    device_data.get('os'),
                    device_data.get('os_version'),
                    device_data.get('device_type'),
                    device_data.get('location'),
                    device_data.get('contact'),
                    device_data.get('description'),
                    device_data.get('uptime'),
                    device_data.get('first_seen', now),
                    device_data.get('last_seen', now),
                    now,  # last_changed
                    'active',
                    device_data.get('confidence_score', 1.0)
                ))
                
                device_id = cursor.lastrowid
                
                # Add ports if available
                if device_data.get('ports'):
                    for port_info in device_data['ports']:
                        cursor.execute('''
                            INSERT INTO device_ports (device_id, port, protocol, state, service, version)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            device_id,
                            port_info.get('port'),
                            port_info.get('protocol', 'tcp'),
                            port_info.get('state', 'open'),
                            port_info.get('service'),
                            port_info.get('version')
                        ))
                
                conn.commit()
                logger.info(f"Added device {device_data.get('ip')} to inventory")
                
        except Exception as e:
            logger.error(f"Failed to add device {device_data.get('ip')}: {e}")

    async def update_device(self, ip: str, device_data: Dict, scan_id: str = None):
        """Update an existing device in the inventory"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                now = datetime.now().isoformat()
                
                cursor.execute('''
                    UPDATE devices SET
                        hostname = ?, mac_address = ?, vendor = ?, model = ?,
                        os = ?, os_version = ?, device_type = ?, location = ?,
                        contact = ?, description = ?, uptime = ?, last_seen = ?,
                        last_changed = ?, status = 'active'
                    WHERE ip = ?
                ''', (
                    device_data.get('hostname'),
                    device_data.get('mac_address'),
                    device_data.get('vendor'),
                    device_data.get('model'),
                    device_data.get('os'),
                    device_data.get('os_version'),
                    device_data.get('device_type'),
                    device_data.get('location'),
                    device_data.get('contact'),
                    device_data.get('description'),
                    device_data.get('uptime'),
                    now,
                    now,
                    ip
                ))
                
                conn.commit()
                logger.debug(f"Updated device {ip} in inventory")
                
        except Exception as e:
            logger.error(f"Failed to update device {ip}: {e}")

    def record_scan_metadata(self, scan_id: str, results: Dict):
        """Record scan metadata"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO scan_metadata (
                        scan_id, timestamp, devices_found, devices_new, 
                        devices_updated, errors_count
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    datetime.now().isoformat(),
                    results.get('devices_processed', 0),
                    results.get('devices_new', 0),
                    results.get('devices_updated', 0),
                    len(results.get('errors', []))
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to record scan metadata: {e}")

# Helper function for easy integration
async def process_enhanced_scan(devices: Dict, scan_id: str, db_path: str = None) -> Dict:
    """
    Process scan results with enhanced inventory management
    """
    manager = EnhancedInventoryManager(db_path) if db_path else EnhancedInventoryManager()
    return await manager.process_scan_results(devices, scan_id)
