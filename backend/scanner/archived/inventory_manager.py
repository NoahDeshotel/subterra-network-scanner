"""
Inventory Manager Module
Handles persistent storage and tracking of network scan results
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)

class InventoryManager:
    def __init__(self, db_path: str = '/app/data/inventory.db'):
        self.db_path = db_path
        self.initialize_db()
    
    def initialize_db(self):
        """Initialize SQLite database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Scans table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        subnet TEXT,
                        host_count INTEGER,
                        vulnerability_count INTEGER,
                        metadata TEXT
                    )
                ''')
                
                # Hosts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        ip TEXT NOT NULL,
                        hostname TEXT,
                        mac_address TEXT,
                        vendor TEXT,
                        os TEXT,
                        os_accuracy TEXT,
                        state TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        tags TEXT,
                        custom_name TEXT,
                        notes TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    )
                ''')
                
                # Ports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host_id INTEGER,
                        scan_id TEXT,
                        port INTEGER,
                        protocol TEXT,
                        state TEXT,
                        service TEXT,
                        product TEXT,
                        version TEXT,
                        extrainfo TEXT,
                        FOREIGN KEY (host_id) REFERENCES hosts(id),
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    )
                ''')
                
                # Vulnerabilities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host_id INTEGER,
                        scan_id TEXT,
                        cve_id TEXT,
                        cvss_score REAL,
                        severity TEXT,
                        description TEXT,
                        exploit_available BOOLEAN,
                        patch_available BOOLEAN,
                        discovered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        resolved_date TIMESTAMP,
                        FOREIGN KEY (host_id) REFERENCES hosts(id),
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    )
                ''')
                
                # Changes table for tracking inventory changes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS changes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        scan_id TEXT,
                        change_type TEXT,
                        entity_type TEXT,
                        entity_id TEXT,
                        old_value TEXT,
                        new_value TEXT,
                        details TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                    )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_host ON vulnerabilities(host_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_changes_scan ON changes(scan_id)')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def add_scan_result(self, host_data: Dict, scan_id: Optional[str] = None) -> int:
        """Add a host scan result to the inventory"""
        if not scan_id:
            scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if host exists
                cursor.execute('''
                    SELECT id FROM hosts 
                    WHERE ip = ? 
                    ORDER BY last_seen DESC 
                    LIMIT 1
                ''', (host_data['ip'],))
                
                existing_host = cursor.fetchone()
                
                # Insert or update host
                if existing_host:
                    host_id = existing_host[0]
                    cursor.execute('''
                        UPDATE hosts 
                        SET last_seen = CURRENT_TIMESTAMP,
                            hostname = ?,
                            mac_address = ?,
                            vendor = ?,
                            os = ?,
                            os_accuracy = ?,
                            state = ?
                        WHERE id = ?
                    ''', (
                        host_data.get('hostname'),
                        host_data.get('mac_address'),
                        host_data.get('vendor'),
                        host_data.get('os'),
                        host_data.get('os_accuracy'),
                        host_data.get('state', 'up'),
                        host_id
                    ))
                    
                    # Log change if significant
                    self._log_host_changes(cursor, scan_id, host_id, existing_host, host_data)
                else:
                    cursor.execute('''
                        INSERT INTO hosts (
                            scan_id, ip, hostname, mac_address, vendor,
                            os, os_accuracy, state
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        host_data['ip'],
                        host_data.get('hostname'),
                        host_data.get('mac_address'),
                        host_data.get('vendor'),
                        host_data.get('os'),
                        host_data.get('os_accuracy'),
                        host_data.get('state', 'up')
                    ))
                    host_id = cursor.lastrowid
                    
                    # Log new host discovery
                    self._log_change(cursor, scan_id, 'NEW_HOST', 'host', 
                                   host_data['ip'], None, host_data['ip'])
                
                # Add ports
                for port in host_data.get('ports', []):
                    cursor.execute('''
                        INSERT INTO ports (
                            host_id, scan_id, port, protocol, state,
                            service, product, version, extrainfo
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        host_id,
                        scan_id,
                        port['port'],
                        port.get('protocol', 'tcp'),
                        port.get('state', 'open'),
                        port.get('service'),
                        port.get('product'),
                        port.get('version'),
                        port.get('extrainfo')
                    ))
                
                # Add vulnerabilities
                for cve in host_data.get('cves', []):
                    severity = self._calculate_severity(cve.get('cvss'))
                    
                    cursor.execute('''
                        INSERT INTO vulnerabilities (
                            host_id, scan_id, cve_id, cvss_score,
                            severity, description
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        host_id,
                        scan_id,
                        cve['id'],
                        cve.get('cvss'),
                        severity,
                        cve.get('description')
                    ))
                
                conn.commit()
                return host_id
                
        except Exception as e:
            logger.error(f"Failed to add scan result: {e}")
            raise
    
    def _calculate_severity(self, cvss_score: Optional[float]) -> str:
        """Calculate severity level from CVSS score"""
        if not cvss_score:
            return 'unknown'
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _log_change(self, cursor, scan_id: str, change_type: str, 
                   entity_type: str, entity_id: str, 
                   old_value: Any, new_value: Any, details: str = None):
        """Log an inventory change"""
        cursor.execute('''
            INSERT INTO changes (
                scan_id, change_type, entity_type, entity_id,
                old_value, new_value, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, change_type, entity_type, entity_id,
            json.dumps(old_value) if old_value else None,
            json.dumps(new_value) if new_value else None,
            details
        ))
    
    def _log_host_changes(self, cursor, scan_id: str, host_id: int, 
                         old_data: tuple, new_data: Dict):
        """Log changes in host configuration"""
        # This would compare old and new data and log significant changes
        # Implementation simplified for brevity
        pass
    
    def get_history(self, days: int = 30) -> Dict:
        """Get scan history for the specified number of days"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days)
                
                # Get scan summary
                cursor.execute('''
                    SELECT scan_id, timestamp, subnet, host_count, vulnerability_count
                    FROM scans
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                ''', (cutoff_date,))
                
                scans = []
                for row in cursor.fetchall():
                    scans.append({
                        'scan_id': row[0],
                        'timestamp': row[1],
                        'subnet': row[2],
                        'host_count': row[3],
                        'vulnerability_count': row[4]
                    })
                
                # Get host statistics
                cursor.execute('''
                    SELECT COUNT(DISTINCT ip) as unique_hosts,
                           COUNT(DISTINCT mac_address) as unique_devices
                    FROM hosts
                    WHERE last_seen >= ?
                ''', (cutoff_date,))
                
                stats = cursor.fetchone()
                
                # Get vulnerability trends
                cursor.execute('''
                    SELECT DATE(discovered_date) as date,
                           severity,
                           COUNT(*) as count
                    FROM vulnerabilities
                    WHERE discovered_date >= ?
                    GROUP BY DATE(discovered_date), severity
                    ORDER BY date
                ''', (cutoff_date,))
                
                vuln_trends = []
                for row in cursor.fetchall():
                    vuln_trends.append({
                        'date': row[0],
                        'severity': row[1],
                        'count': row[2]
                    })
                
                return {
                    'scans': scans,
                    'statistics': {
                        'unique_hosts': stats[0] if stats else 0,
                        'unique_devices': stats[1] if stats else 0
                    },
                    'vulnerability_trends': vuln_trends
                }
                
        except Exception as e:
            logger.error(f"Failed to get history: {e}")
            return {'scans': [], 'statistics': {}, 'vulnerability_trends': []}
    
    def compare_scans(self, scan1_id: str, scan2_id: str) -> Dict:
        """Compare two scans to identify changes"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get hosts from both scans
                cursor.execute('''
                    SELECT ip, hostname, mac_address, os
                    FROM hosts
                    WHERE scan_id = ?
                ''', (scan1_id,))
                
                scan1_hosts = {row[0]: row for row in cursor.fetchall()}
                
                cursor.execute('''
                    SELECT ip, hostname, mac_address, os
                    FROM hosts
                    WHERE scan_id = ?
                ''', (scan2_id,))
                
                scan2_hosts = {row[0]: row for row in cursor.fetchall()}
                
                # Identify changes
                new_hosts = [ip for ip in scan2_hosts if ip not in scan1_hosts]
                removed_hosts = [ip for ip in scan1_hosts if ip not in scan2_hosts]
                
                modified_hosts = []
                for ip in set(scan1_hosts.keys()) & set(scan2_hosts.keys()):
                    if scan1_hosts[ip] != scan2_hosts[ip]:
                        modified_hosts.append({
                            'ip': ip,
                            'changes': self._compare_host_details(
                                scan1_hosts[ip], scan2_hosts[ip]
                            )
                        })
                
                # Get vulnerability changes
                cursor.execute('''
                    SELECT h.ip, COUNT(v.id) as vuln_count
                    FROM hosts h
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                    WHERE h.scan_id = ?
                    GROUP BY h.ip
                ''', (scan1_id,))
                
                scan1_vulns = {row[0]: row[1] for row in cursor.fetchall()}
                
                cursor.execute('''
                    SELECT h.ip, COUNT(v.id) as vuln_count
                    FROM hosts h
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                    WHERE h.scan_id = ?
                    GROUP BY h.ip
                ''', (scan2_id,))
                
                scan2_vulns = {row[0]: row[1] for row in cursor.fetchall()}
                
                vuln_changes = []
                for ip in set(scan1_vulns.keys()) | set(scan2_vulns.keys()):
                    old_count = scan1_vulns.get(ip, 0)
                    new_count = scan2_vulns.get(ip, 0)
                    if old_count != new_count:
                        vuln_changes.append({
                            'ip': ip,
                            'old_count': old_count,
                            'new_count': new_count,
                            'change': new_count - old_count
                        })
                
                return {
                    'new_hosts': new_hosts,
                    'removed_hosts': removed_hosts,
                    'modified_hosts': modified_hosts,
                    'vulnerability_changes': vuln_changes
                }
                
        except Exception as e:
            logger.error(f"Failed to compare scans: {e}")
            return {
                'new_hosts': [],
                'removed_hosts': [],
                'modified_hosts': [],
                'vulnerability_changes': []
            }
    
    def _compare_host_details(self, old_host: tuple, new_host: tuple) -> List[Dict]:
        """Compare details of two host records"""
        changes = []
        fields = ['ip', 'hostname', 'mac_address', 'os']
        
        for i, field in enumerate(fields):
            if old_host[i] != new_host[i]:
                changes.append({
                    'field': field,
                    'old_value': old_host[i],
                    'new_value': new_host[i]
                })
        
        return changes
    
    def export_to_csv(self, scan_id: Optional[str] = None) -> str:
        """Export inventory data to CSV"""
        try:
            # Prepare query
            if scan_id:
                query = '''
                    SELECT h.ip, h.hostname, h.mac_address, h.vendor, h.os,
                           COUNT(DISTINCT p.port) as open_ports,
                           COUNT(DISTINCT v.cve_id) as vulnerabilities,
                           MAX(v.cvss_score) as max_cvss
                    FROM hosts h
                    LEFT JOIN ports p ON h.id = p.host_id
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                    WHERE h.scan_id = ?
                    GROUP BY h.id
                '''
                params = (scan_id,)
            else:
                query = '''
                    SELECT h.ip, h.hostname, h.mac_address, h.vendor, h.os,
                           COUNT(DISTINCT p.port) as open_ports,
                           COUNT(DISTINCT v.cve_id) as vulnerabilities,
                           MAX(v.cvss_score) as max_cvss,
                           h.last_seen
                    FROM hosts h
                    LEFT JOIN ports p ON h.id = p.host_id
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                    GROUP BY h.id
                    ORDER BY h.last_seen DESC
                '''
                params = ()
            
            # Read data into DataFrame
            df = pd.read_sql_query(query, sqlite3.connect(self.db_path), params=params)
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'/app/data/exports/inventory_{timestamp}.csv'
            
            # Ensure directory exists
            Path('/app/data/exports').mkdir(parents=True, exist_ok=True)
            
            # Export to CSV
            df.to_csv(filename, index=False)
            
            logger.info(f"Exported inventory to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to export to CSV: {e}")
            raise
    
    def get_host_details(self, ip: str) -> Dict:
        """Get detailed information about a specific host"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get host info
                cursor.execute('''
                    SELECT * FROM hosts
                    WHERE ip = ?
                    ORDER BY last_seen DESC
                    LIMIT 1
                ''', (ip,))
                
                host = cursor.fetchone()
                if not host:
                    return None
                
                host_id = host[0]
                
                # Get ports
                cursor.execute('''
                    SELECT port, protocol, service, product, version
                    FROM ports
                    WHERE host_id = ?
                    ORDER BY port
                ''', (host_id,))
                
                ports = []
                for row in cursor.fetchall():
                    ports.append({
                        'port': row[0],
                        'protocol': row[1],
                        'service': row[2],
                        'product': row[3],
                        'version': row[4]
                    })
                
                # Get vulnerabilities
                cursor.execute('''
                    SELECT cve_id, cvss_score, severity, description
                    FROM vulnerabilities
                    WHERE host_id = ?
                    ORDER BY cvss_score DESC
                ''', (host_id,))
                
                vulnerabilities = []
                for row in cursor.fetchall():
                    vulnerabilities.append({
                        'cve_id': row[0],
                        'cvss_score': row[1],
                        'severity': row[2],
                        'description': row[3]
                    })
                
                return {
                    'ip': host[2],
                    'hostname': host[3],
                    'mac_address': host[4],
                    'vendor': host[5],
                    'os': host[6],
                    'first_seen': host[9],
                    'last_seen': host[10],
                    'ports': ports,
                    'vulnerabilities': vulnerabilities
                }
                
        except Exception as e:
            logger.error(f"Failed to get host details: {e}")
            return None

    def get_all_hosts(self, search='', page=1, per_page=50):
        """Get all hosts with pagination and search"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Build query with search
                base_query = '''
                    SELECT h.ip, h.hostname, h.mac_address, h.vendor, h.os,
                           COUNT(DISTINCT p.port) as open_ports,
                           COUNT(DISTINCT v.cve_id) as vulnerabilities,
                           MAX(v.cvss_score) as max_cvss,
                           h.last_seen
                    FROM hosts h
                    LEFT JOIN ports p ON h.id = p.host_id
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                '''
                
                where_clause = ''
                params = []
                
                if search:
                    where_clause = ''' WHERE (h.ip LIKE ? OR h.hostname LIKE ? OR h.os LIKE ?)'''
                    search_param = f'%{search}%'
                    params = [search_param, search_param, search_param]
                
                query = base_query + where_clause + '''
                    GROUP BY h.id
                    ORDER BY h.last_seen DESC
                    LIMIT ? OFFSET ?
                '''
                
                params.extend([per_page, (page - 1) * per_page])
                
                cursor.execute(query, params)
                
                hosts = []
                for row in cursor.fetchall():
                    risk_level = 'low'
                    if row[7]:  # max_cvss
                        if row[7] >= 9.0:
                            risk_level = 'critical'
                        elif row[7] >= 7.0:
                            risk_level = 'high'
                        elif row[7] >= 4.0:
                            risk_level = 'medium'
                    
                    hosts.append({
                        'ip': row[0],
                        'hostname': row[1],
                        'mac_address': row[2],
                        'vendor': row[3],
                        'os': row[4],
                        'open_ports': row[5],
                        'vulnerabilities': row[6],
                        'max_cvss': row[7],
                        'risk_level': risk_level,
                        'last_seen': row[8]
                    })
                
                return hosts
                
        except Exception as e:
            logger.error(f"Failed to get hosts: {e}")
            return []

    def get_host_count(self):
        """Get total host count"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(DISTINCT ip) FROM hosts')
                return cursor.fetchone()[0]
        except:
            return 0

    def get_vulnerability_count(self, severity=None):
        """Get vulnerability count by severity"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if severity:
                    cursor.execute(
                        'SELECT COUNT(*) FROM vulnerabilities WHERE severity = ?',
                        (severity,)
                    )
                else:
                    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
                
                return cursor.fetchone()[0]
        except:
            return 0

    def get_total_open_ports(self):
        """Get total open ports count"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM ports WHERE state = "open"')
                return cursor.fetchone()[0]
        except:
            return 0

    def get_last_scan_time(self):
        """Get last scan timestamp"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT MAX(timestamp) FROM scans')
                result = cursor.fetchone()[0]
                return result
        except:
            return None

    def get_vulnerabilities(self, severity='all', host=None):
        """Get vulnerabilities with filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT v.cve_id, v.cvss_score, v.severity, v.description,
                           h.ip, h.hostname
                    FROM vulnerabilities v
                    JOIN hosts h ON v.host_id = h.id
                '''
                
                conditions = []
                params = []
                
                if severity != 'all':
                    conditions.append('v.severity = ?')
                    params.append(severity)
                
                if host:
                    conditions.append('h.ip = ?')
                    params.append(host)
                
                if conditions:
                    query += ' WHERE ' + ' AND '.join(conditions)
                
                query += ' ORDER BY v.cvss_score DESC'
                
                cursor.execute(query, params)
                
                vulnerabilities = []
                for row in cursor.fetchall():
                    vulnerabilities.append({
                        'cve_id': row[0],
                        'cvss_score': row[1],
                        'severity': row[2],
                        'description': row[3],
                        'host_ip': row[4],
                        'hostname': row[5]
                    })
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return []

    def get_hosts_with_vulnerabilities(self):
        """Get hosts that have vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT DISTINCT h.ip, h.hostname, h.os, h.mac_address,
                           GROUP_CONCAT(v.cve_id) as cve_list,
                           GROUP_CONCAT(v.cvss_score) as cvss_list,
                           GROUP_CONCAT(p.port) as port_list,
                           GROUP_CONCAT(p.service) as service_list
                    FROM hosts h
                    JOIN vulnerabilities v ON h.id = v.host_id
                    LEFT JOIN ports p ON h.id = p.host_id
                    GROUP BY h.id
                ''')
                
                hosts = []
                for row in cursor.fetchall():
                    cve_ids = row[4].split(',') if row[4] else []
                    cvss_scores = [float(x) for x in row[5].split(',') if x] if row[5] else []
                    ports = [{'port': int(x)} for x in row[6].split(',') if x] if row[6] else []
                    
                    cves = []
                    for i, cve_id in enumerate(cve_ids):
                        cves.append({
                            'id': cve_id,
                            'cvss': cvss_scores[i] if i < len(cvss_scores) else 0
                        })
                    
                    hosts.append({
                        'ip': row[0],
                        'hostname': row[1],
                        'os': row[2],
                        'mac_address': row[3],
                        'cves': cves,
                        'ports': ports
                    })
                
                return hosts
                
        except Exception as e:
            logger.error(f"Failed to get hosts with vulnerabilities: {e}")
            return []

    def get_scan_history(self, days=30):
        """Get scan history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days)
                
                cursor.execute('''
                    SELECT scan_id, timestamp, subnet, host_count, vulnerability_count
                    FROM scans
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                ''', (cutoff_date,))
                
                scans = []
                for row in cursor.fetchall():
                    scans.append({
                        'scan_id': row[0],
                        'timestamp': row[1],
                        'subnet': row[2],
                        'host_count': row[3],
                        'vulnerability_count': row[4]
                    })
                
                return {'scans': scans}
                
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return {'scans': []}

    def get_latest_scan(self):
        """Get latest scan data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT scan_id FROM scans
                    ORDER BY timestamp DESC
                    LIMIT 1
                ''')
                
                result = cursor.fetchone()
                if not result:
                    return None
                
                scan_id = result[0]
                
                # Get hosts from this scan
                cursor.execute('''
                    SELECT h.ip, h.hostname, h.os, h.mac_address,
                           GROUP_CONCAT(v.cve_id) as cve_list,
                           GROUP_CONCAT(v.cvss_score) as cvss_list,
                           GROUP_CONCAT(p.port) as port_list
                    FROM hosts h
                    LEFT JOIN vulnerabilities v ON h.id = v.host_id
                    LEFT JOIN ports p ON h.id = p.host_id
                    WHERE h.scan_id = ?
                    GROUP BY h.id
                ''', (scan_id,))
                
                hosts = []
                for row in cursor.fetchall():
                    cve_ids = row[4].split(',') if row[4] else []
                    cvss_scores = [float(x) for x in row[5].split(',') if x] if row[5] else []
                    ports = [{'port': int(x)} for x in row[6].split(',') if x] if row[6] else []
                    
                    cves = []
                    for i, cve_id in enumerate(cve_ids):
                        if cve_id:
                            cves.append({
                                'id': cve_id,
                                'cvss': cvss_scores[i] if i < len(cvss_scores) else 0
                            })
                    
                    hosts.append({
                        'ip': row[0],
                        'hostname': row[1],
                        'os': row[2],
                        'mac_address': row[3],
                        'cves': cves,
                        'ports': ports
                    })
                
                return {'hosts': hosts, 'scan_id': scan_id}
                
        except Exception as e:
            logger.error(f"Failed to get latest scan: {e}")
            return None

    def get_hosts_since(self, hours=24):
        """Get hosts discovered in the last N hours"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_time = datetime.now() - timedelta(hours=hours)
                
                cursor.execute('''
                    SELECT ip, hostname, first_seen
                    FROM hosts
                    WHERE first_seen >= ?
                    ORDER BY first_seen DESC
                ''', (cutoff_time,))
                
                hosts = []
                for row in cursor.fetchall():
                    hosts.append({
                        'ip': row[0],
                        'hostname': row[1],
                        'first_seen': row[2]
                    })
                
                return hosts
                
        except Exception as e:
            logger.error(f"Failed to get recent hosts: {e}")
            return []

    def get_hosts_with_many_ports(self, threshold=20):
        """Get hosts with many open ports"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT h.ip, h.hostname, COUNT(p.port) as port_count
                    FROM hosts h
                    JOIN ports p ON h.id = p.host_id
                    WHERE p.state = 'open'
                    GROUP BY h.id
                    HAVING port_count > ?
                    ORDER BY port_count DESC
                ''', (threshold,))
                
                hosts = []
                for row in cursor.fetchall():
                    hosts.append({
                        'ip': row[0],
                        'hostname': row[1],
                        'port_count': row[2]
                    })
                
                return hosts
                
        except Exception as e:
            logger.error(f"Failed to get hosts with many ports: {e}")
            return []

    def get_summary(self):
        """Get inventory summary"""
        try:
            return {
                'total_hosts': self.get_host_count(),
                'total_vulnerabilities': self.get_vulnerability_count(),
                'critical_vulnerabilities': self.get_vulnerability_count('critical'),
                'high_vulnerabilities': self.get_vulnerability_count('high'),
                'open_ports': self.get_total_open_ports(),
                'last_scan': self.get_last_scan_time()
            }
        except Exception as e:
            logger.error(f"Failed to get summary: {e}")
            return {}
