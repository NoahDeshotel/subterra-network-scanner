#!/usr/bin/env python3
"""
Simple Network Scanner - A working implementation for your 10.0.0.0/16 network
This version focuses on reliability and completing scans successfully
"""

import subprocess
import ipaddress
import socket
import logging
import time
from typing import List, Dict, Optional
from datetime import datetime
import concurrent.futures
import threading

logger = logging.getLogger(__name__)

class SimpleNetworkScanner:
    """
    Simple, reliable network scanner that actually completes scans
    """
    
    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback
        self.discovered_devices = {}
        self.scan_id = None
        self.progress_tracker = None
        self.socketio = None
        
    def scan_network(self, subnet: str, scan_id: str = None) -> Dict[str, Dict]:
        """
        Scan network using simple but reliable methods
        """
        logger.info(f"Starting simple network scan for {subnet}")
        
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            all_hosts = list(network.hosts())
            total_hosts = len(all_hosts)
            
            if scan_id and self.progress_callback:
                self.progress_callback(scan_id, f"Scanning {total_hosts} hosts in {subnet}")
            
            logger.info(f"Scanning {total_hosts} hosts in {subnet}")
            
            # For very large networks, limit the scan
            if total_hosts > 4096:  # Limit to /20 or smaller for reasonable scan times
                logger.warning(f"Large network detected ({total_hosts} hosts). Sampling every 16th host for performance.")
                all_hosts = all_hosts[::16]
                total_hosts = len(all_hosts)
            
            # Step 1: Quick ping sweep to find live hosts
            if scan_id and self.progress_callback:
                self.progress_callback(scan_id, f"Phase 1: Ping sweep ({total_hosts} hosts)")
            
            live_hosts = self._ping_sweep_simple(all_hosts, scan_id)
            
            logger.info(f"Ping sweep found {len(live_hosts)} live hosts")
            
            # Step 2: Gather details for live hosts
            if scan_id and self.progress_callback:
                self.progress_callback(scan_id, f"Phase 2: Gathering details for {len(live_hosts)} live hosts")
            
            for i, host_ip in enumerate(live_hosts):
                if scan_id and self.progress_callback and i % 10 == 0:
                    self.progress_callback(scan_id, f"Processing host {i+1}/{len(live_hosts)}: {host_ip}")
                
                device_info = self._get_host_details(host_ip)
                self.discovered_devices[host_ip] = device_info
                
                # Send device discovered notification via WebSocket
                if self.socketio:
                    try:
                        self.socketio.emit('device_discovered', {
                            'ip': host_ip,
                            'hostname': device_info.get('hostname', 'Unknown'),
                            'mac': device_info.get('mac_address'),
                            'device_type': device_info.get('device_type', 'unknown'),
                            'scan_id': self.scan_id
                        })
                    except Exception as e:
                        logger.debug(f"Could not emit device discovery: {e}")
                
                logger.debug(f"Processed {host_ip}: {device_info.get('hostname', 'Unknown')}")
            
            if scan_id and self.progress_callback:
                self.progress_callback(scan_id, f"Scan completed: {len(self.discovered_devices)} devices found")
            
            logger.info(f"Network scan completed: {len(self.discovered_devices)} devices found")
            
            return self.discovered_devices
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            if scan_id and self.progress_callback:
                self.progress_callback(scan_id, f"Scan failed: {str(e)}")
            raise
    
    def _ping_sweep_simple(self, hosts: List, scan_id: str = None) -> List[str]:
        """
        Simple ping sweep using threading for efficiency
        """
        live_hosts = []
        
        def ping_host(host_ip: str) -> Optional[str]:
            """Ping a single host"""
            try:
                # Use subprocess ping - more reliable than async
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', str(host_ip)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3
                )
                return str(host_ip) if result.returncode == 0 else None
            except:
                return None
        
        # Use ThreadPoolExecutor for controlled concurrency
        max_workers = min(50, len(hosts))  # Limit concurrent pings
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all ping tasks
            future_to_host = {executor.submit(ping_host, str(host)): str(host) for host in hosts}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_host):
                completed += 1
                host_ip = future_to_host[future]
                
                try:
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                        logger.debug(f"Host {result} is alive")
                except Exception as e:
                    logger.debug(f"Ping failed for {host_ip}: {e}")
                
                # Progress update every 50 hosts
                if scan_id and self.progress_callback and completed % 50 == 0:
                    self.progress_callback(scan_id, f"Ping sweep: {completed}/{len(hosts)} tested, {len(live_hosts)} alive")
        
        return live_hosts
    
    def _get_host_details(self, host_ip: str) -> Dict[str, str]:
        """
        Get basic details about a host
        """
        device_info = {
            'ip': host_ip,
            'hostname': None,
            'mac_address': None,
            'os': None,
            'device_type': 'unknown',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'status': 'active'
        }
        
        # Try to get hostname
        try:
            hostname = socket.gethostbyaddr(host_ip)[0]
            device_info['hostname'] = hostname
            logger.debug(f"Resolved hostname for {host_ip}: {hostname}")
        except:
            pass
        
        # Simple device type classification
        device_info['device_type'] = self._classify_device(device_info)
        
        return device_info
    
    def _classify_device(self, device_info: Dict) -> str:
        """
        Simple device classification based on hostname and IP
        """
        hostname = (device_info.get('hostname') or '').lower()
        ip = device_info.get('ip', '')
        
        if any(term in hostname for term in ['router', 'gateway', 'gw']):
            return 'router'
        elif any(term in hostname for term in ['switch', 'sw']):
            return 'switch'
        elif any(term in hostname for term in ['server', 'srv']):
            return 'server'
        elif any(term in hostname for term in ['printer', 'print']):
            return 'printer'
        elif any(term in hostname for term in ['phone', 'voip']):
            return 'phone'
        elif hostname:
            return 'workstation'
        else:
            # Check if it's likely a gateway/router by IP
            try:
                octets = ip.split('.')
                if octets[-1] in ['1', '254']:
                    return 'router'
            except:
                pass
            
            return 'unknown'

def scan_with_progress(subnet: str, scan_id: str, progress_tracker):
    """
    Run a simple scan with progress tracking
    """
    from scanner.scan_progress_tracker import ScanStage, ScanPriority
    import socketio
    
    # Try to get socketio instance for device notifications
    sio = None
    try:
        from app import socketio as app_socketio
        sio = app_socketio
    except:
        pass
    
    def progress_callback(scan_id: str, message: str, percentage: float = None):
        if progress_tracker:
            # Update stage based on message content
            if "Ping sweep" in message:
                progress_tracker.update_stage(scan_id, ScanStage.HOST_DISCOVERY, message)
            elif "Gathering details" in message:
                progress_tracker.update_stage(scan_id, ScanStage.SERVICE_DETECTION, message)
            elif "Processing host" in message:
                progress_tracker.update_step(scan_id, message)
                # Extract progress from message like "Processing host 10/50"
                import re
                match = re.search(r'(\d+)/(\d+)', message)
                if match:
                    current = int(match.group(1))
                    total = int(match.group(2))
                    progress_tracker.update_target_progress(scan_id, current)
            else:
                progress_tracker.log_message(scan_id, ScanStage.HOST_DISCOVERY, 
                                            ScanPriority.INFO, message)
        logger.info(f"[{scan_id}] {message}")
    
    scanner = SimpleNetworkScanner()
    scanner.progress_callback = progress_callback
    scanner.scan_id = scan_id
    scanner.progress_tracker = progress_tracker
    scanner.socketio = sio
    
    try:
        # Initialize scan tracking
        network = ipaddress.ip_network(subnet, strict=False)
        total_hosts = len(list(network.hosts()))
        
        if progress_tracker:
            progress_tracker.start_scan(scan_id, total_hosts, {'subnet': subnet})
            progress_tracker.update_stage(scan_id, ScanStage.INITIALIZING, 
                                        f"Initializing scan for {subnet}")
        
        progress_callback(scan_id, f"Starting network scan for {subnet}")
        devices = scanner.scan_network(subnet, scan_id)
        
        if progress_tracker:
            progress_tracker.update_stage(scan_id, ScanStage.FINALIZING, 
                                        "Processing scan results")
        
        progress_callback(scan_id, f"Scan completed successfully: {len(devices)} devices found")
        
        if progress_tracker:
            progress_tracker.complete_scan(scan_id, True, 
                                         f"Scan completed: {len(devices)} devices found")
        
        return devices, {'total_devices': len(devices), 'scan_successful': True}
    except Exception as e:
        progress_callback(scan_id, f"Scan failed: {str(e)}")
        if progress_tracker:
            progress_tracker.complete_scan(scan_id, False, f"Scan failed: {str(e)}")
        return {}, {'error': str(e), 'scan_successful': False}
