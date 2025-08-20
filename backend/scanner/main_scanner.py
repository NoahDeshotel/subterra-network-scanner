#!/usr/bin/env python3
"""
Main Network Scanner Module
Core scanning functionality with concurrent host discovery and progress tracking
"""

import socket
import subprocess
import ipaddress
import threading
import time
import logging
from typing import Dict, Tuple, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform

logger = logging.getLogger(__name__)

def emit_progress(scan_id: str, percentage: int, message: str, scan_tracker=None):
    """Emit progress update via WebSocket"""
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
            socketio_emit('scan_progress', {
                'scan_id': scan_id,
                'progress': percentage,
                'percentage': percentage,
                'message': message,
                'stage': 'scanning'
            }, broadcast=True, namespace='/')
            logger.info(f"Emitted progress: {percentage}% - {message}")
        except Exception as e:
            logger.debug(f"Could not emit via socketio: {e}")
            
    except Exception as e:
        logger.error(f"Error emitting progress: {e}")

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Check if host responds to ping"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(int(timeout * 1000)), str(ip)]
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5
        )
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {e}")
        return False

def tcp_scan_host(ip: str, ports: List[int] = None, timeout: float = 0.5) -> Dict:
    """Quick TCP scan of common ports"""
    if ports is None:
        ports = [22, 80, 443, 445, 3389, 8080, 8443]
    
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    
    return {'open_ports': open_ports}

def get_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Get hostname for IP address"""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(str(ip))
        return hostname
    except Exception:
        return None

def classify_device(open_ports: List[int], hostname: str = None) -> str:
    """Simple device classification based on open ports"""
    if 22 in open_ports or 3389 in open_ports:
        return 'server'
    elif 80 in open_ports or 443 in open_ports:
        return 'web_server'
    elif 445 in open_ports:
        return 'workstation'
    elif hostname and ('router' in hostname.lower() or 'gateway' in hostname.lower()):
        return 'router'
    else:
        return 'unknown'

def scan_single_host(ip: str, scan_id: str = None, scan_tracker=None) -> Optional[Dict]:
    """Scan a single host"""
    try:
        ip_str = str(ip)
        
        # First check if host is up
        if not ping_host(ip_str, timeout=1.0):
            # Try TCP scan on port 80 as fallback
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_str, 80))
            sock.close()
            if result != 0:
                return None
        
        # Host is up, gather information
        device_info = {
            'ip': ip_str,
            'is_active': True,
            'status': 'active',
            'discovery_method': 'ping'
        }
        
        # Get hostname
        hostname = get_hostname(ip_str)
        if hostname:
            device_info['hostname'] = hostname
        
        # Quick port scan
        port_info = tcp_scan_host(ip_str)
        device_info['open_ports'] = port_info['open_ports']
        device_info['open_ports_count'] = len(port_info['open_ports'])
        
        # Classify device
        device_info['device_type'] = classify_device(
            port_info['open_ports'],
            hostname
        )
        
        # Add timestamps
        device_info['first_seen'] = time.strftime('%Y-%m-%d %H:%M:%S')
        device_info['last_seen'] = device_info['first_seen']
        
        logger.info(f"Discovered device: {ip_str} ({hostname or 'Unknown'})")
        
        # Emit device discovered event
        try:
            from flask_socketio import emit as socketio_emit
            socketio_emit('device_discovered', device_info, broadcast=True, namespace='/')
        except Exception:
            pass
        
        return device_info
        
    except Exception as e:
        logger.error(f"Error scanning host {ip}: {e}")
        return None

def robust_network_scan(subnet: str, scan_id: str, scan_tracker=None) -> Tuple[Dict, Dict]:
    """
    Perform network scan with concurrent host discovery
    
    Scans the specified subnet using multiple discovery methods:
    - ICMP ping
    - TCP port scanning
    - Hostname resolution
    """
    devices = {}
    summary = {
        'scan_successful': False,
        'total_hosts': 0,
        'active_hosts': 0,
        'scan_duration': 0,
        'errors': []
    }
    
    start_time = time.time()
    
    try:
        # Parse network
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        summary['total_hosts'] = total_hosts
        
        logger.info(f"Starting robust scan of {subnet} ({total_hosts} hosts)")
        emit_progress(scan_id, 5, f"Starting scan of {subnet} ({total_hosts} hosts)", scan_tracker)
        
        # Limit scan size for performance
        if total_hosts > 1024:
            logger.warning(f"Large network detected ({total_hosts} hosts), limiting to first 256")
            hosts = hosts[:256]
            total_hosts = 256
            emit_progress(scan_id, 10, f"Scanning first 256 hosts of network", scan_tracker)
        else:
            emit_progress(scan_id, 10, f"Preparing to scan {total_hosts} hosts", scan_tracker)
        
        # Use ThreadPoolExecutor for concurrent scanning
        max_workers = min(50, total_hosts)  # Limit concurrent threads
        discovered_count = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            future_to_ip = {
                executor.submit(scan_single_host, ip, scan_id, scan_tracker): ip 
                for ip in hosts
            }
            
            # Process results as they complete
            completed = 0
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                # Update progress
                progress = 10 + int((completed / total_hosts) * 80)
                if completed % max(1, total_hosts // 20) == 0:  # Update every 5%
                    emit_progress(
                        scan_id, 
                        progress, 
                        f"Scanned {completed}/{total_hosts} hosts, found {discovered_count} devices",
                        scan_tracker
                    )
                
                try:
                    result = future.result(timeout=5)
                    if result:
                        devices[str(ip)] = result
                        discovered_count += 1
                        summary['active_hosts'] += 1
                        
                        # Log discovery
                        logger.info(f"Device discovered: {ip} ({result.get('hostname', 'Unknown')})")
                        
                except Exception as e:
                    logger.debug(f"Error scanning {ip}: {e}")
                    summary['errors'].append(f"Error scanning {ip}: {str(e)}")
        
        # Final summary
        scan_duration = time.time() - start_time
        summary['scan_duration'] = scan_duration
        summary['scan_successful'] = True
        summary['devices_found'] = len(devices)
        
        # Emit completion
        emit_progress(
            scan_id,
            95,
            f"Scan complete: {len(devices)} devices found in {scan_duration:.1f} seconds",
            scan_tracker
        )
        
        logger.info(f"Scan completed: {len(devices)} devices found in {scan_duration:.1f} seconds")
        
        # Final progress
        emit_progress(scan_id, 100, "Scan completed successfully", scan_tracker)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        summary['scan_successful'] = False
        summary['error'] = str(e)
        emit_progress(scan_id, 100, f"Scan failed: {str(e)}", scan_tracker)
    
    return devices, summary

def scan_with_robust_progress(subnet: str, scan_id: str, scan_tracker=None) -> Tuple[Dict, Dict]:
    """
    Main entry point for network scanning with progress tracking
    """
    logger.info(f"Initiating network scan {scan_id} for subnet {subnet}")
    
    # Emit initial progress
    emit_progress(scan_id, 0, "Initializing network scan", scan_tracker)
    
    try:
        # Perform the scan
        devices, summary = robust_network_scan(subnet, scan_id, scan_tracker)
        
        # Ensure we always return valid data
        if devices is None:
            devices = {}
        if summary is None:
            summary = {'scan_successful': False, 'error': 'Unknown error'}
        
        return devices, summary
        
    except Exception as e:
        logger.error(f"Fatal error in robust scan: {e}")
        return {}, {
            'scan_successful': False,
            'error': str(e),
            'devices_found': 0
        }