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

# Import advanced scanner for enhanced capabilities
try:
    from .advanced_scanner import AdvancedNetworkScanner, advanced_network_scan
    ADVANCED_SCANNER_AVAILABLE = True
except ImportError:
    ADVANCED_SCANNER_AVAILABLE = False
    logger.warning("Advanced scanner not available, using basic scanning")

logger = logging.getLogger(__name__)

def emit_progress(scan_id: str, percentage: int, message: str, scan_tracker=None):
    """Emit progress update via WebSocket"""
    logger.info(f"[PROGRESS] {scan_id}: {percentage}% - {message}")
    
    try:
        if scan_tracker:
            logger.debug(f"[PROGRESS] Updating scan tracker for {scan_id}")
            scan_tracker.update_progress(
                scan_id,
                percentage,
                message,
                stage='scanning'
            )
            logger.debug(f"[PROGRESS] Scan tracker updated successfully")
        else:
            logger.debug(f"[PROGRESS] No scan tracker available")
        
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
            logger.debug(f"[PROGRESS] Emitting WebSocket event: {emit_data}")
            socketio_emit('scan_progress', emit_data, broadcast=True, namespace='/')
            logger.info(f"[PROGRESS] ✅ WebSocket progress emitted: {percentage}% - {message}")
        except Exception as e:
            logger.debug(f"[PROGRESS] Could not emit via socketio: {e}")
            
    except Exception as e:
        logger.error(f"[PROGRESS] ❌ Error emitting progress: {e}", exc_info=True)

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Check if host responds to ping"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(int(timeout * 1000)), str(ip)]
        logger.debug(f"[PING] Running command: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 0.5
        )
        
        success = result.returncode == 0
        if success:
            logger.debug(f"[PING] ✅ Host {ip} is reachable via ping")
        else:
            logger.debug(f"[PING] Host {ip} did not respond to ping")
        return success
    except subprocess.TimeoutExpired:
        logger.debug(f"[PING] Timeout for {ip}")
        return False
    except Exception as e:
        logger.debug(f"[PING] Error pinging {ip}: {e}")
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
        logger.debug(f"[HOST-SCAN] Starting scan of {ip_str}")
        
        # First check if host is up
        logger.debug(f"[HOST-SCAN] Checking if {ip_str} is up via ping")
        if not ping_host(ip_str, timeout=1.0):
            logger.debug(f"[HOST-SCAN] Ping failed for {ip_str}, trying TCP fallback on port 80")
            # Try TCP scan on port 80 as fallback
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_str, 80))
            sock.close()
            if result != 0:
                logger.debug(f"[HOST-SCAN] Host {ip_str} appears to be down (no ping, no TCP 80)")
                return None
            else:
                logger.debug(f"[HOST-SCAN] Host {ip_str} responsive on TCP port 80")
        
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
        
        logger.info(f"[HOST-SCAN] ✅ Discovered device: {ip_str} ({hostname or 'Unknown'})")
        logger.info(f"[HOST-SCAN] Device type: {device_info['device_type']}, Open ports: {device_info['open_ports']}")
        
        # Emit device discovered event
        try:
            from flask_socketio import emit as socketio_emit
            logger.debug(f"[HOST-SCAN] Emitting device_discovered event for {ip_str}")
            socketio_emit('device_discovered', device_info, broadcast=True, namespace='/')
            logger.debug(f"[HOST-SCAN] Device discovery event emitted")
        except Exception as e:
            logger.debug(f"[HOST-SCAN] Could not emit device discovery: {e}")
        
        return device_info
        
    except Exception as e:
        logger.error(f"[HOST-SCAN] ❌ Error scanning host {ip}: {e}", exc_info=True)
        return None

def robust_network_scan(subnet: str, scan_id: str, scan_tracker=None) -> Tuple[Dict, Dict]:
    """
    Perform network scan with concurrent host discovery
    
    Scans the specified subnet using multiple discovery methods:
    - ICMP ping
    - TCP port scanning
    - Hostname resolution
    """
    logger.info(f"[NETWORK-SCAN] ========== Starting Network Scan ==========")
    logger.info(f"[NETWORK-SCAN] Scan ID: {scan_id}")
    logger.info(f"[NETWORK-SCAN] Target subnet: {subnet}")
    logger.info(f"[NETWORK-SCAN] Scan tracker available: {scan_tracker is not None}")
    
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
        logger.info(f"[NETWORK-SCAN] Parsing network address: {subnet}")
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())
        total_hosts = len(hosts)
        summary['total_hosts'] = total_hosts
        
        logger.info(f"[NETWORK-SCAN] ✅ Network parsed successfully")
        logger.info(f"[NETWORK-SCAN] Network: {network}")
        logger.info(f"[NETWORK-SCAN] Total hosts to scan: {total_hosts}")
        logger.info(f"[NETWORK-SCAN] IP range: {hosts[0] if hosts else 'empty'} - {hosts[-1] if hosts else 'empty'}")
        
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
        
        logger.info(f"[NETWORK-SCAN] Starting concurrent scan with {max_workers} worker threads")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all scan tasks
            logger.info(f"[NETWORK-SCAN] Submitting {len(hosts)} scan tasks to thread pool")
            future_to_ip = {
                executor.submit(scan_single_host, ip, scan_id, scan_tracker): ip 
                for ip in hosts
            }
            logger.info(f"[NETWORK-SCAN] All tasks submitted, waiting for results...")
            
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
                        logger.info(f"[NETWORK-SCAN] ✅ Device #{discovered_count} discovered: {ip} ({result.get('hostname', 'Unknown')})")
                        logger.debug(f"[NETWORK-SCAN] Device details: {result}")
                    else:
                        logger.debug(f"[NETWORK-SCAN] No response from {ip}")
                        
                except Exception as e:
                    logger.debug(f"[NETWORK-SCAN] Error scanning {ip}: {e}")
                    summary['errors'].append(f"Error scanning {ip}: {str(e)}")
        
        # Final summary
        scan_duration = time.time() - start_time
        summary['scan_duration'] = scan_duration
        summary['scan_successful'] = True
        summary['devices_found'] = len(devices)
        
        logger.info(f"[NETWORK-SCAN] ========== Scan Complete ==========")
        logger.info(f"[NETWORK-SCAN] Duration: {scan_duration:.1f} seconds")
        logger.info(f"[NETWORK-SCAN] Total hosts scanned: {total_hosts}")
        logger.info(f"[NETWORK-SCAN] Active devices found: {len(devices)}")
        logger.info(f"[NETWORK-SCAN] Success rate: {(len(devices)/total_hosts*100):.1f}%" if total_hosts > 0 else "N/A")
        logger.info(f"[NETWORK-SCAN] Errors encountered: {len(summary['errors'])}")
        
        # Emit completion
        emit_progress(
            scan_id,
            95,
            f"Scan complete: {len(devices)} devices found in {scan_duration:.1f} seconds",
            scan_tracker
        )
        
        # Log discovered devices summary
        if devices:
            logger.info(f"[NETWORK-SCAN] Discovered devices:")
            for ip, dev_info in devices.items():
                logger.info(f"[NETWORK-SCAN]   - {ip}: {dev_info.get('hostname', 'Unknown')} ({dev_info.get('device_type', 'unknown')})")
        
        # Final progress
        emit_progress(scan_id, 100, "Scan completed successfully", scan_tracker)
        
    except Exception as e:
        logger.error(f"[NETWORK-SCAN] ❌ SCAN FAILED: {e}", exc_info=True)
        logger.error(f"[NETWORK-SCAN] Exception type: {type(e).__name__}")
        summary['scan_successful'] = False
        summary['error'] = str(e)
        summary['scan_duration'] = time.time() - start_time
        emit_progress(scan_id, 100, f"Scan failed: {str(e)}", scan_tracker)
    
    return devices, summary

def scan_with_robust_progress(subnet: str, scan_id: str, scan_tracker=None, use_advanced: bool = True, scan_mode: str = 'smart') -> Tuple[Dict, Dict]:
    """
    Main entry point for network scanning with progress tracking
    
    Args:
        subnet: Target subnet to scan
        scan_id: Unique scan identifier
        scan_tracker: Scan tracker object for progress updates
        use_advanced: Whether to use advanced scanning capabilities (default: True)
        scan_mode: Scanning mode for large networks ('smart', 'thorough', 'full')
    """
    logger.info(f"[MAIN-SCANNER] ============================================")
    logger.info(f"[MAIN-SCANNER] NETWORK SCAN INITIATED")
    logger.info(f"[MAIN-SCANNER] Scan ID: {scan_id}")
    logger.info(f"[MAIN-SCANNER] Target Subnet: {subnet}")
    logger.info(f"[MAIN-SCANNER] Tracker Available: {scan_tracker is not None}")
    logger.info(f"[MAIN-SCANNER] Advanced Scanner: {ADVANCED_SCANNER_AVAILABLE and use_advanced}")
    logger.info(f"[MAIN-SCANNER] Scan Mode: {scan_mode}")
    logger.info(f"[MAIN-SCANNER] ============================================")
    
    # Emit initial progress
    emit_progress(scan_id, 0, "Initializing network scan", scan_tracker)
    
    try:
        # Check network size
        network = ipaddress.ip_network(subnet, strict=False)
        total_hosts = network.num_addresses - 2  # Subtract network and broadcast
        
        # For large networks (more than 1024 hosts), use subnet scanner
        if total_hosts > 1024:
            logger.info(f"[MAIN-SCANNER] Large network detected ({total_hosts} hosts), using intelligent subnet scanning")
            emit_progress(scan_id, 5, f"Large network detected: {total_hosts} hosts. Using {scan_mode} scanning mode", scan_tracker)
            
            # Use the subnet scanner for large networks
            try:
                from .subnet_scanner import scan_large_network_smart
                import asyncio
                
                # Run the async subnet scanner
                devices, summary = asyncio.run(
                    scan_large_network_smart(subnet, scan_id, scan_tracker, scan_mode)
                )
                
                logger.info(f"[MAIN-SCANNER] Subnet scan completed: {len(devices)} devices found")
                return devices, summary
                
            except ImportError as e:
                logger.warning(f"[MAIN-SCANNER] Subnet scanner not available: {e}")
                # Fall back to limited scanning
                logger.warning(f"[MAIN-SCANNER] Falling back to limited scanning (first 512 hosts)")
                emit_progress(scan_id, 5, "Using limited scanning for large network", scan_tracker)
        
        # For smaller networks or if subnet scanner not available, use regular scanning
        if ADVANCED_SCANNER_AVAILABLE and use_advanced:
            logger.info(f"[MAIN-SCANNER] Using ADVANCED scanning capabilities")
            devices, summary = advanced_network_scan(subnet, scan_id, scan_tracker)
        else:
            logger.info(f"[MAIN-SCANNER] Using basic scanning capabilities")
            devices, summary = robust_network_scan(subnet, scan_id, scan_tracker)
        
        logger.info(f"[MAIN-SCANNER] Scan function returned successfully")
        logger.info(f"[MAIN-SCANNER] Devices returned: {len(devices) if devices else 0}")
        logger.info(f"[MAIN-SCANNER] Summary: {summary}")
        
        # Ensure we always return valid data
        if devices is None:
            logger.warning(f"[MAIN-SCANNER] Devices was None, returning empty dict")
            devices = {}
        if summary is None:
            logger.warning(f"[MAIN-SCANNER] Summary was None, creating error summary")
            summary = {'scan_successful': False, 'error': 'Unknown error'}
        
        logger.info(f"[MAIN-SCANNER] ✅ Scan completed, returning results")
        return devices, summary
        
    except Exception as e:
        logger.error(f"[MAIN-SCANNER] ❌ FATAL ERROR in scan: {e}", exc_info=True)
        logger.error(f"[MAIN-SCANNER] Exception type: {type(e).__name__}")
        return {}, {
            'scan_successful': False,
            'error': str(e),
            'devices_found': 0
        }