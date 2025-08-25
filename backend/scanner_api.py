#!/usr/bin/env python3
"""
Scanner API Handler
Clean API interface for the modular scanner system
"""

import logging
import asyncio
import uuid
import json
from typing import Dict, Optional
from datetime import datetime
from threading import Thread

from scanner.scanner_core import NetworkScanner
from scanner.comprehensive_scanner import ComprehensiveScanner
from scanner.scan_progress_tracker import ScanProgressTracker
from scanner.enhanced_inventory import EnhancedInventoryManager

logger = logging.getLogger(__name__)

class ScannerAPI:
    """API handler for network scanning operations"""
    
    def __init__(self, socketio=None):
        self.scanner = NetworkScanner()
        self.comprehensive_scanner = ComprehensiveScanner()
        self.scan_tracker = ScanProgressTracker()
        self.inventory = EnhancedInventoryManager()
        self.socketio = socketio
        self.active_scans = {}
        
    def start_scan(self, config: Dict) -> Dict:
        """
        Start a network scan
        
        Args:
            config: Scan configuration dictionary
                - subnet: Network to scan (required)
                - scan_mode: 'quick', 'balanced', 'deep', 'full' (default: 'balanced')
                - scan_type: Legacy compatibility field
                
        Returns:
            Response dictionary with scan_id and status
        """
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Extract configuration
        subnet = config.get('subnet', 'auto')
        scan_mode = config.get('scan_mode')
        scan_type = config.get('scan_type', 'balanced')
        
        # Auto-detect subnet if needed
        if subnet == 'auto':
            subnet = self._detect_subnet()
            if not subnet:
                return {
                    'success': False,
                    'error': 'Could not auto-detect subnet'
                }
        
        # Determine scan mode
        if not scan_mode:
            # Map scan_type to scan_mode for compatibility
            type_to_mode = {
                'quick': 'quick',
                'comprehensive': 'deep',
                'emergency': 'full',
                'vulnerability': 'deep'
            }
            scan_mode = type_to_mode.get(scan_type, 'balanced')
        
        # Store scan info
        self.active_scans[scan_id] = {
            'config': config,
            'status': 'starting',
            'start_time': datetime.now().isoformat()
        }
        
        # Start scan in background thread
        thread = Thread(
            target=self._run_scan,
            args=(scan_id, subnet, scan_mode),
            daemon=True
        )
        thread.start()
        
        logger.info(f"Started scan {scan_id} for {subnet} in {scan_mode} mode")
        
        return {
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan initiated',
            'config': {
                'subnet': subnet,
                'scan_mode': scan_mode,
                'scanner_type': 'modular'  # New modular scanner
            }
        }
    
    def _run_scan(self, scan_id: str, subnet: str, scan_mode: str):
        """Run scan in background thread with progressive saving"""
        try:
            # Update status
            self.active_scans[scan_id]['status'] = 'running'
            self.active_scans[scan_id]['devices_saved'] = 0
            self.active_scans[scan_id]['devices_scanned'] = 0
            self.active_scans[scan_id]['total_addresses'] = 0
            
            # Calculate total addresses to scan
            import ipaddress
            network = ipaddress.ip_network(subnet, strict=False)
            total_addresses = network.num_addresses - 2  # Exclude network and broadcast
            self.active_scans[scan_id]['total_addresses'] = total_addresses
            
            # Initialize scan in tracker
            self.scan_tracker.start_scan(scan_id, scan_config={
                'subnet': subnet,
                'scan_mode': scan_mode,
                'total_addresses': total_addresses
            })
            
            # Batch of devices to save periodically
            device_batch = {}
            batch_size = 10  # Save every 10 devices
            
            # Enhanced progress callback with batch saving
            def progress_callback(sid, percentage, message):
                # Extract device count from message if available
                devices_scanned = 0
                if 'Scanned' in message or 'Identified' in message:
                    # Try to extract numbers from message like "Scanned 15/254 hosts"
                    import re
                    match = re.search(r'(\d+)/(\d+)', message)
                    if match:
                        devices_scanned = int(match.group(1))
                        total = int(match.group(2))
                        self.active_scans[scan_id]['devices_scanned'] = devices_scanned
                        
                        # Create enhanced message with more detail
                        message = f"{message} ({percentage}% complete)"
                
                self.scan_tracker.update_progress(scan_id, percentage, message)
                
                # Emit detailed progress via WebSocket
                if self.socketio:
                    try:
                        self.socketio.emit('scan_progress', {
                            'scan_id': scan_id,
                            'percentage': percentage,
                            'message': message,
                            'progress': percentage,
                            'devices_scanned': self.active_scans[scan_id].get('devices_scanned', 0),
                            'devices_saved': self.active_scans[scan_id].get('devices_saved', 0),
                            'total_addresses': total_addresses
                        })
                    except:
                        pass
            
            # Run the scan with progressive saving
            logger.info(f"Executing scan {scan_id} for {total_addresses} addresses")
            
            # Use comprehensive scanner for better results if requested
            use_comprehensive = self.active_scans[scan_id]['config'].get('comprehensive', False) or scan_mode in ['deep', 'comprehensive']
            
            if use_comprehensive:
                logger.info(f"Using comprehensive scanner for scan {scan_id}")
                # Use comprehensive scanner
                devices, scan_summary = self.comprehensive_scanner.scan_network(
                    subnet, scan_mode, progress_callback
                )
                # Save all devices at once for comprehensive scan
                if devices:
                    logger.info(f"Saving {len(devices)} devices from comprehensive scan")
                    asyncio.run(
                        self.inventory.process_scan_results(devices, scan_id)
                    )
                    self.active_scans[scan_id]['devices_saved'] = len(devices)
            else:
                # Use progressive scan
                devices = self._scan_with_progressive_save(
                    scan_id, subnet, scan_mode, progress_callback, use_comprehensive=False
                )
            
            # Create summary
            summary = {
                'scan_successful': True,
                'devices_found': len(devices),
                'total_addresses': total_addresses,
                'scan_mode': scan_mode
            }
            
            # Update scan status
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['devices_found'] = len(devices)
            self.active_scans[scan_id]['summary'] = summary
            
            # Mark scan as complete
            self.scan_tracker.complete_scan(
                scan_id,
                success=True,
                final_message=f"Scan completed: {len(devices)} devices found"
            )
            
            # Emit completion event
            if self.socketio:
                self.socketio.emit('scan_completed', {
                    'scan_id': scan_id,
                    'success': True,
                    'devices_found': len(devices),
                    'summary': summary
                })
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)
            
            self.scan_tracker.complete_scan(
                scan_id,
                success=False,
                final_message=f"Scan failed: {e}"
            )
            
            if self.socketio:
                self.socketio.emit('scan_completed', {
                    'scan_id': scan_id,
                    'success': False,
                    'error': str(e)
                })
    
    def _scan_with_progressive_save(self, scan_id: str, subnet: str, scan_mode: str, progress_callback, use_comprehensive: bool = False) -> Dict:
        """
        Enhanced scanning with progressive device saving
        """
        import ipaddress
        from datetime import datetime
        
        devices_found = {}
        batch_to_save = {}
        batch_size = 5  # Save every 5 devices
        
        # Custom scanner that processes devices one by one
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        
        logger.info(f"Progressive scan starting for {total_hosts} hosts")
        
        # Discovery phase with batched results
        discovered_count = 0
        for idx, host in enumerate(hosts):
            host_ip = str(host)
            
            # Update progress for discovery
            percentage = int((idx / total_hosts) * 100)
            progress_callback(
                scan_id, 
                percentage, 
                f"Scanning {idx + 1}/{total_hosts} addresses ({host_ip})"
            )
            
            # Quick discovery check
            discovered_hosts = self.scanner.discovery.discover_network(
                f"{host_ip}/32", 
                callback=None
            )
            
            if discovered_hosts:
                discovered_count += 1
                
                # Port scan for discovered host
                enhanced_hosts = self.scanner.port_scanner.scan_network_ports(
                    discovered_hosts,
                    scan_type='common' if scan_mode == 'balanced' else 'minimal',
                    callback=None
                )
                
                # Identify device
                for ip, host_info in enhanced_hosts.items():
                    identified = self.scanner.identifier.identify_device(host_info)
                    identified['first_seen'] = datetime.now().isoformat()
                    identified['last_seen'] = identified['first_seen']
                    
                    # Convert 'open_ports' to 'ports' for inventory compatibility
                    if 'open_ports' in identified:
                        # Convert port numbers to port details format
                        port_details = []
                        for port in identified.get('open_ports', []):
                            port_details.append({
                                'port': port,
                                'protocol': 'tcp',
                                'state': 'open',
                                'service': self._get_service_name(port)
                            })
                        identified['ports'] = port_details
                    
                    devices_found[ip] = identified
                    batch_to_save[ip] = identified
                    
                    # Save batch when it reaches the size limit
                    if len(batch_to_save) >= batch_size:
                        logger.info(f"Saving batch of {len(batch_to_save)} devices")
                        try:
                            asyncio.run(
                                self.inventory.process_scan_results(batch_to_save, scan_id)
                            )
                            self.active_scans[scan_id]['devices_saved'] += len(batch_to_save)
                            batch_to_save = {}
                            
                            # Emit update about saved devices
                            if self.socketio:
                                self.socketio.emit('devices_saved', {
                                    'scan_id': scan_id,
                                    'devices_saved': self.active_scans[scan_id]['devices_saved'],
                                    'total_found': len(devices_found)
                                })
                        except Exception as e:
                            logger.error(f"Failed to save batch: {e}")
        
        # Save any remaining devices
        if batch_to_save:
            logger.info(f"Saving final batch of {len(batch_to_save)} devices")
            try:
                asyncio.run(
                    self.inventory.process_scan_results(batch_to_save, scan_id)
                )
                self.active_scans[scan_id]['devices_saved'] += len(batch_to_save)
            except Exception as e:
                logger.error(f"Failed to save final batch: {e}")
        
        return devices_found
    
    def _get_service_name(self, port: int) -> str:
        """
        Get common service name for a port number
        """
        common_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            69: 'TFTP', 80: 'HTTP', 110: 'POP3', 119: 'NNTP',
            123: 'NTP', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            161: 'SNMP', 162: 'SNMP-TRAP', 389: 'LDAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 514: 'SYSLOG', 515: 'LPD',
            548: 'AFP', 554: 'RTSP', 587: 'SMTP', 631: 'IPP',
            636: 'LDAPS', 873: 'RSYNC', 902: 'VMware', 993: 'IMAPS',
            995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL',
            1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 3000: 'Node.js',
            3306: 'MySQL', 3389: 'RDP', 3690: 'SVN', 5000: 'UPnP',
            5432: 'PostgreSQL', 5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis',
            6667: 'IRC', 7000: 'Cassandra', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
            8081: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'PHP-FPM',
            9090: 'Prometheus', 9100: 'JetDirect', 9200: 'Elasticsearch', 10000: 'Webmin',
            11211: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB'
        }
        return common_services.get(port, f'Port-{port}')
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get status of a scan"""
        if scan_id not in self.active_scans:
            # Check tracker
            progress = self.scan_tracker.get_progress(scan_id)
            if progress:
                return {
                    'scan_id': scan_id,
                    'active': progress.stage != 'completed',
                    'status': progress.stage.value if hasattr(progress.stage, 'value') else str(progress.stage),
                    'devices_found': progress.targets_completed,
                    'progress': progress.percentage
                }
            
            return {
                'scan_id': scan_id,
                'error': 'Scan not found'
            }
        
        scan_info = self.active_scans[scan_id]
        progress = self.scan_tracker.get_progress(scan_id)
        
        return {
            'scan_id': scan_id,
            'status': scan_info['status'],
            'active': scan_info['status'] == 'running',
            'config': scan_info['config'],
            'start_time': scan_info['start_time'],
            'devices_found': scan_info.get('devices_found', 0),
            'progress': progress.percentage if progress else 0,
            'summary': scan_info.get('summary', {})
        }
    
    def get_scan_results(self, scan_id: str) -> Dict:
        """Get results of a completed scan"""
        if scan_id not in self.active_scans:
            return {
                'scan_id': scan_id,
                'error': 'Scan not found'
            }
        
        scan_info = self.active_scans[scan_id]
        
        if scan_info['status'] != 'completed':
            return {
                'scan_id': scan_id,
                'status': scan_info['status'],
                'message': 'Scan not yet completed'
            }
        
        return {
            'scan_id': scan_id,
            'success': True,
            'devices_found': scan_info.get('devices_found', 0),
            'summary': scan_info.get('summary', {}),
            'devices': []  # Devices are in the database, fetch separately
        }
    
    def stop_scan(self, scan_id: str) -> Dict:
        """Stop a running scan"""
        if scan_id not in self.active_scans:
            return {
                'success': False,
                'error': 'Scan not found'
            }
        
        # Mark as cancelled
        self.active_scans[scan_id]['status'] = 'cancelled'
        
        # Update tracker
        self.scan_tracker.complete_scan(
            scan_id,
            success=False,
            final_message='Scan cancelled by user'
        )
        
        return {
            'success': True,
            'message': 'Scan cancelled'
        }
    
    def _detect_subnet(self) -> Optional[str]:
        """Auto-detect local subnet"""
        try:
            import socket
            import ipaddress
            
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Assume /24 subnet
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
            
        except Exception as e:
            logger.error(f"Failed to auto-detect subnet: {e}")
            return None

# Global scanner API instance
scanner_api = None

def initialize_scanner_api(socketio=None):
    """Initialize the global scanner API"""
    global scanner_api
    scanner_api = ScannerAPI(socketio)
    return scanner_api

def get_scanner_api():
    """Get the global scanner API instance"""
    global scanner_api
    if scanner_api is None:
        scanner_api = ScannerAPI()
    return scanner_api