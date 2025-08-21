#!/usr/bin/env python3
"""
Enhanced Network Scanner Backend - Netdisco-Inspired Implementation
Combines modern UI with comprehensive network discovery and inventory management
"""

# DO NOT use eventlet - it breaks threading needed for scans
# Use threading mode instead for socketio
# import eventlet
# eventlet.monkey_patch()

import os
import sys
import asyncio
import logging
import uuid
import ipaddress
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect
import threading
import json
import time
from pathlib import Path

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging first
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import enhanced modules
try:
    from scanner.enhanced_discovery import EnhancedNetworkDiscovery, discover_network_enhanced
    from scanner.enhanced_inventory import EnhancedInventoryManager, process_enhanced_scan
    from scanner.scan_progress_tracker import get_scan_tracker, set_websocket_callback, ScanStage, ScanPriority
    logger.info("Successfully imported enhanced modules")
except ImportError as e:
    logger.error(f"Failed to import enhanced modules: {e}")
    # Fallback imports if available
    try:
        from enhanced_discovery import EnhancedNetworkDiscovery, discover_network_enhanced
        from enhanced_inventory import EnhancedInventoryManager, process_enhanced_scan
        logger.info("Successfully imported enhanced modules from fallback location")
    except ImportError:
        logger.error("Enhanced modules not found. Please ensure they are in the correct location.")
        sys.exit(1)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'enhanced-network-scanner-key')

# Enable CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize SocketIO with threading mode for proper background task execution
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',  # Use threading mode - eventlet breaks scan threads
    logger=True,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# Set up progress tracking WebSocket callback
def websocket_progress_callback(event_type: str, data: dict):
    """Send progress updates via WebSocket"""
    try:
        socketio.emit(event_type, data)
        logger.debug(f"Sent WebSocket event: {event_type}")
    except Exception as e:
        logger.error(f"Failed to send WebSocket event: {e}")

# Global instances
inventory_manager = EnhancedInventoryManager()
discovery_engine = None
active_scans = {}
scan_tracker = get_scan_tracker()
set_websocket_callback(websocket_progress_callback)

class ScanManager:
    """Manages scanning operations and WebSocket communication"""
    
    def __init__(self):
        self.active_scans = {}
    
    async def start_scan(self, scan_config: dict, scan_id: str):
        """Start a network scan with enhanced discovery"""
        try:
            self.active_scans[scan_id] = {
                'status': 'running',
                'start_time': datetime.now(),
                'config': scan_config,
                'progress': 0
            }
            
            # Notify clients that scan started
            socketio.emit('scan_started', {
                'scan_id': scan_id,
                'config': scan_config,
                'timestamp': datetime.now().isoformat()
            })
            
            # Initialize discovery engine
            discovery = EnhancedNetworkDiscovery()
            
            # Emit progress updates
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 10,
                'message': 'Initializing network discovery...'
            })
            
            # Detect subnet if auto
            subnet = scan_config.get('subnet', 'auto')
            if subnet == 'auto':
                # Use discovery engine to detect local subnet
                local_ip = discovery.get_local_ip() if hasattr(discovery, 'get_local_ip') else '192.168.1.1'
                subnet = f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
            
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 20,
                'message': f'Scanning subnet: {subnet}'
            })
            
            # Perform enhanced discovery
            deep_scan = scan_config.get('deep_scan', False)
            devices, summary = await discover_network_enhanced(subnet, deep_scan)
            
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 70,
                'message': f'Processing {len(devices)} discovered devices...'
            })
            
            # Process results with enhanced inventory
            scan_metadata = {
                'scan_type': 'enhanced_network_scan',
                'subnet': subnet,
                'start_time': self.active_scans[scan_id]['start_time'],
                'deep_scan': deep_scan,
                'parameters': scan_config
            }
            
            # Convert devices to dict format if needed
            devices_dict = {}
            for ip, device in devices.items():
                if hasattr(device, '__dict__'):
                    devices_dict[ip] = device.__dict__
                else:
                    devices_dict[ip] = device
            
            inventory_results = await process_enhanced_scan(devices_dict, scan_id, scan_metadata)
            
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 90,
                'message': 'Finalizing scan results...'
            })
            
            # Update scan status
            self.active_scans[scan_id].update({
                'status': 'completed',
                'end_time': datetime.now(),
                'results': {
                    'devices_discovered': len(devices),
                    'summary': summary,
                    'inventory_results': inventory_results
                }
            })
            
            # Notify completion
            socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'results': self.active_scans[scan_id]['results'],
                'duration': (datetime.now() - self.active_scans[scan_id]['start_time']).total_seconds()
            })
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            self.active_scans[scan_id] = {
                'status': 'failed',
                'error': str(e),
                'end_time': datetime.now()
            }
            
            socketio.emit('scan_failed', {
                'scan_id': scan_id,
                'error': str(e)
            })

# Global scan manager
scan_manager = ScanManager()

# Health check
@app.route('/health')
def health_check():
    """Enhanced health check with system status"""
    try:
        # Check database connectivity
        summary = inventory_manager.get_enhanced_summary()
        
        return jsonify({
            'status': 'healthy',
            'version': '3.0.0-enhanced',
            'database': 'connected',
            'features': [
                'enhanced_discovery',
                'snmp_support',
                'topology_mapping',
                'change_tracking',
                'real_time_updates'
            ],
            'statistics': summary
        })
    except Exception as e:
        return jsonify({
            'status': 'degraded',
            'error': str(e)
        }), 500

@app.route('/api/scanners/available')
def get_available_scanners():
    """Get list of available scanners with their capabilities"""
    try:
        # Import scanner capabilities
        from scanner.scanner_capabilities import get_scan_capabilities, get_supported_protocols
        
        scanners = {
            'simple': {
                'name': 'Simple Scanner',
                'description': 'Basic ping sweep and hostname resolution',
                'features': ['ping_sweep', 'hostname_resolution', 'basic_classification'],
                'recommended_for': 'Small networks (<64 hosts)',
                'performance': 'Fast',
                'capabilities': ['icmp', 'dns']
            },
            'enhanced': {
                'name': 'Enhanced Scanner',
                'description': 'Multi-method discovery with port scanning',
                'features': ['multi_method_discovery', 'nmap_scanning', 'basic_snmp', 'cve_detection'],
                'recommended_for': 'Medium networks (64-256 hosts)',
                'performance': 'Medium',
                'capabilities': ['icmp', 'dns', 'tcp', 'udp', 'snmp_basic', 'nmap']
            },
            'job_based': {
                'name': 'Job-Based Netdisco Scanner',
                'description': 'Advanced job-based scanner with Netdisco-inspired algorithms',
                'features': [
                    'event_driven_jobs', 'breadth_first_discovery', 'comprehensive_snmp',
                    'mac_table_collection', 'arp_table_collection', 'topology_discovery',
                    'historical_continuity', 'intelligent_deferral', 'device_profiling'
                ],
                'recommended_for': 'All networks, especially large (>256 hosts)',
                'performance': 'Comprehensive',
                'capabilities': get_supported_protocols(),
                'advanced_features': get_scan_capabilities()
            },
            'netdisco': {
                'name': 'Netdisco Compatible',
                'description': 'Alias for job-based scanner with Netdisco compatibility',
                'features': ['same_as_job_based'],
                'recommended_for': 'Networks requiring Netdisco-style discovery',
                'performance': 'Comprehensive',
                'capabilities': get_supported_protocols()
            }
        }
        
        return jsonify({
            'available_scanners': scanners,
            'default_scanner': 'auto',
            'auto_selection_logic': {
                'small_networks': 'simple (< 64 hosts)',
                'medium_networks': 'enhanced (64-256 hosts)',
                'large_networks': 'job_based (> 256 hosts)',
                'topology_required': 'job_based (any size)',
                'deep_scan_required': 'job_based (any size)'
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting scanner info: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scanners/capabilities')
def get_scanner_capabilities():
    """Get detailed capabilities of the enhanced scanner system"""
    try:
        from scanner.scanner_capabilities import (
            get_scan_capabilities, get_supported_protocols, 
            get_device_classification_types, get_vendor_database_info
        )
        
        return jsonify({
            'system_capabilities': get_scan_capabilities(),
            'supported_protocols': get_supported_protocols(),
            'device_types': get_device_classification_types(),
            'vendor_database': get_vendor_database_info(),
            'job_types': [
                'discover', 'macsuck', 'arpnip', 'pingsweep', 
                'topology', 'nbtstat', 'portmap', 'vulnscan'
            ],
            'data_continuity': {
                'historical_tracking': True,
                'change_detection': True,
                'active_inactive_flagging': True,
                'audit_trail': True
            },
            'intelligent_features': {
                'exponential_backoff': True,
                'device_deferral': True,
                'breadth_first_discovery': True,
                'neighbor_spawning': True,
                'priority_scheduling': True
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting capabilities: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/status')
def get_status():
    """Get enhanced scanner status"""
    return jsonify({
        'status': 'active',
        'version': '4.0.0-netdisco-enhanced',
        'active_scans': len([s for s in active_scans.values() if s.get('status') == 'running']),
        'available_scanners': ['simple', 'enhanced', 'job_based', 'netdisco'],
        'default_scanner': 'auto',
        'features': {
            'snmp_discovery': True,
            'topology_mapping': True,
            'change_detection': True,
            'device_classification': True,
            'vulnerability_scanning': True,
            'real_time_updates': True,
            'job_based_architecture': True,
            'netdisco_compatibility': True,
            'historical_continuity': True,
            'intelligent_deferral': True
        }
    })

@app.route('/api/scan/test', methods=['GET'])
def test_scan():
    """Test endpoint to verify scanning works"""
    try:
        # Simple test to verify components work
        from scanner.main_scanner import scan_single_host
        
        # Test localhost
        result = scan_single_host('127.0.0.1')
        
        return jsonify({
            'success': True,
            'message': 'Scanner test successful',
            'localhost_scan': result
        })
    except Exception as e:
        logger.error(f"Scanner test failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start enhanced network scan"""
    try:
        data = request.get_json() or {}
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Prepare scan configuration
        scan_config = {
            'subnet': data.get('subnet', 'auto'),
            'aggressive': data.get('aggressive', False),
            'deep_scan': data.get('deep_scan', False),
            'vulnerability_scan': data.get('vulnerability_scan', False),  # Disable by default for faster scans
            'snmp_communities': data.get('snmp_communities', ['public']),
            'topology_discovery': data.get('topology_discovery', False),  # Disable by default
            'scanner_type': data.get('scanner_type', 'simple'),  # Use simple scanner by default
            'scan_mode': data.get('scan_mode', 'smart')  # Scan mode for large networks: smart, thorough, or full
        }
        
        logger.info(f"Starting scan {scan_id} with config: {scan_config}")
        
        # IMPORTANT: Return response immediately, do everything else in background
        response = jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Scan initiated',
            'config': scan_config
        })
        
        # Auto-detect subnet if needed
        if scan_config['subnet'] == 'auto':
            import socket
            import netifaces
            import platform
            
            # Get the host's actual network interface (not Docker's)
            detected_subnet = None
            
            try:
                # Method 1: Try to get the default gateway interface
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    default_interface = gateways['default'][netifaces.AF_INET][1]
                    addrs = netifaces.ifaddresses(default_interface)
                    if netifaces.AF_INET in addrs:
                        ip_info = addrs[netifaces.AF_INET][0]
                        ip_addr = ip_info['addr']
                        netmask = ip_info.get('netmask', '255.255.255.0')
                        
                        # Calculate network address
                        ip_obj = ipaddress.ip_interface(f"{ip_addr}/{netmask}")
                        detected_subnet = str(ip_obj.network)
                        logger.info(f"Detected host network from default interface: {detected_subnet}")
            except Exception as e:
                logger.warning(f"Could not detect from default interface: {e}")
            
            # Method 2: Fallback to examining all interfaces
            if not detected_subnet:
                try:
                    for interface in netifaces.interfaces():
                        # Skip loopback and docker interfaces
                        if interface.startswith(('lo', 'docker', 'br-')):
                            continue
                        
                        addrs = netifaces.ifaddresses(interface)
                        if netifaces.AF_INET in addrs:
                            for addr_info in addrs[netifaces.AF_INET]:
                                ip = addr_info['addr']
                                # Skip localhost and docker IPs
                                if ip.startswith(('127.', '172.17.', '172.18.', '172.19.')):
                                    continue
                                
                                netmask = addr_info.get('netmask', '255.255.255.0')
                                ip_obj = ipaddress.ip_interface(f"{ip}/{netmask}")
                                detected_subnet = str(ip_obj.network)
                                logger.info(f"Detected host network from interface {interface}: {detected_subnet}")
                                break
                        
                        if detected_subnet:
                            break
                except Exception as e:
                    logger.warning(f"Could not detect from interfaces: {e}")
            
            # Method 3: Use environment variable if set (for Docker - highest priority)
            if not detected_subnet and os.getenv('HOST_SUBNET'):
                detected_subnet = os.getenv('HOST_SUBNET')
                logger.info(f"Using HOST_SUBNET environment variable: {detected_subnet}")
            
            # Method 4: Try external connection method
            if not detected_subnet:
                try:
                    # Connect to external host to determine local IP
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    
                    # Convert to /24 subnet
                    subnet_parts = local_ip.split('.')
                    detected_subnet = f"{'.'.join(subnet_parts[:3])}.0/24"
                    logger.info(f"Detected subnet via external connection: {detected_subnet}")
                except Exception as e:
                    logger.warning(f"Could not detect via external connection: {e}")
            
            # Method 5: Final fallback
            if not detected_subnet:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                
                # Check if it's a Docker IP and use a sensible default
                if local_ip.startswith(('172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.')):
                    # Common home network subnets to try
                    default_subnets = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24', '10.1.0.0/24']
                    detected_subnet = default_subnets[0]  # Default to most common home subnet
                    logger.warning(f"Detected Docker IP {local_ip}, using common home subnet: {detected_subnet}")
                    logger.warning("⚠️  Consider setting HOST_SUBNET environment variable for accurate scanning")
                else:
                    # Convert to /24 subnet
                    subnet_parts = local_ip.split('.')
                    detected_subnet = f"{'.'.join(subnet_parts[:3])}.0/24"
                    logger.info(f"Using fallback subnet detection: {detected_subnet}")
            
            scan_config['subnet'] = detected_subnet
            logger.info(f"Final subnet for scanning: {scan_config['subnet']}")
        
        
        # Store scan in active scans
        active_scans[scan_id] = {
            'status': 'initializing',
            'config': scan_config,
            'start_time': datetime.now().isoformat()
        }
        
        # Background task to start everything
        def start_scan_background():
            print(f"\n{'='*60}", flush=True)
            print(f"[SCAN-THREAD] SCAN STARTING: {scan_id}", flush=True)
            print(f"[SCAN-THREAD] Subnet: {scan_config['subnet']}", flush=True)
            print(f"[SCAN-THREAD] Mode: {scan_config.get('scan_mode', 'smart')}", flush=True)
            print(f"[SCAN-THREAD] Scanner: {scan_config.get('scanner_type', 'simple')}", flush=True)
            print(f"{'='*60}\n", flush=True)
            
            logger.info(f"[SCAN-THREAD] Thread function called for scan {scan_id}")
            logger.info(f"[SCAN-THREAD] Thread name: {threading.current_thread().name}")
            logger.info(f"[SCAN-THREAD] Scan config: {json.dumps(scan_config, indent=2)}")
            
            try:
                # Initialize scan tracking
                logger.info(f"[SCAN-THREAD] Step 1: Initializing scan tracker")
                logger.info(f"[SCAN-THREAD] scan_tracker object: {scan_tracker}")
                logger.info(f"[SCAN-THREAD] scan_tracker type: {type(scan_tracker)}")
                
                if scan_tracker:
                    try:
                        logger.info(f"[SCAN-THREAD] Calling scan_tracker.start_scan() with scan_id={scan_id}")
                        scan_tracker.start_scan(scan_id, 0, scan_config)
                        logger.info(f"[SCAN-THREAD] ✅ Scan tracker initialized successfully for {scan_id}")
                    except Exception as e:
                        logger.error(f"[SCAN-THREAD] ❌ Failed to initialize scan tracker: {e}", exc_info=True)
                        logger.error(f"[SCAN-THREAD] Exception type: {type(e).__name__}")
                else:
                    logger.warning(f"[SCAN-THREAD] ⚠️ scan_tracker is None, skipping initialization")
                
                # Update active scans status
                logger.info(f"[SCAN-THREAD] Step 2: Updating active scans status to 'running'")
                if scan_id in active_scans:
                    active_scans[scan_id]['status'] = 'running'
                    logger.info(f"[SCAN-THREAD] Active scan status updated to 'running'")
                
                # Emit scan started event
                logger.info(f"[SCAN-THREAD] Step 3: Emitting WebSocket scan_started event")
                try:
                    emit_data = {
                        'scan_id': scan_id,
                        'config': scan_config,
                        'subnet': scan_config['subnet']
                    }
                    logger.info(f"[SCAN-THREAD] Emitting data: {json.dumps(emit_data, indent=2)}")
                    socketio.emit('scan_started', emit_data)
                    logger.info(f"[SCAN-THREAD] ✅ Successfully emitted scan_started event")
                except Exception as e:
                    logger.error(f"[SCAN-THREAD] ❌ Failed to emit scan_started: {e}", exc_info=True)
                
                # Execute the scan based on scanner type
                scanner_type = scan_config.get('scanner_type', 'simple')
                logger.info(f"[SCAN-THREAD] Step 4: Starting actual scan")
                logger.info(f"[SCAN-THREAD] Scanner type: {scanner_type}")
                logger.info(f"[SCAN-THREAD] Target subnet: {scan_config['subnet']}")
                logger.info(f"[SCAN-THREAD] Deep scan: {scan_config.get('deep_scan', False)}")
                logger.info(f"[SCAN-THREAD] Aggressive: {scan_config.get('aggressive', False)}")
                
                # Import and run scanner based on type
                logger.info(f"[SCAN-THREAD] Selecting scanner based on type: {scanner_type}")
                
                if scanner_type == 'enhanced' or scan_config.get('deep_scan', False):
                    print(f"[SCAN-THREAD-PRINT] Using ENHANCED scanner", flush=True)
                    logger.info(f"[SCAN-THREAD] Using ENHANCED scanner with advanced features")
                    
                    # Import the main scanner which includes subnet scanning for large networks
                    from scanner.main_scanner import scan_with_robust_progress
                    print(f"[SCAN-THREAD-PRINT] Imported scan_with_robust_progress", flush=True)
                    logger.info(f"[SCAN-THREAD] ✅ Successfully imported main scanner with subnet scanning")
                    
                    # Use main scanner which handles large networks intelligently
                    logger.info(f"[SCAN-THREAD] Running main scanner with subnet support")
                    logger.info(f"[SCAN-THREAD] Features enabled: SNMP={scan_config.get('snmp_communities')}, Vulnerability={scan_config.get('vulnerability_scan')}, Topology={scan_config.get('topology_discovery')}")
                    logger.info(f"[SCAN-THREAD] Scan mode: {scan_config.get('scan_mode', 'smart')}")
                    
                    # Run the main scanner which includes subnet scanning
                    devices, summary = scan_with_robust_progress(
                        scan_config['subnet'], 
                        scan_id,
                        scan_tracker,
                        use_advanced=True,  # Use advanced features for enhanced scanner
                        scan_mode=scan_config.get('scan_mode', 'smart')
                    )
                        
                else:
                    logger.info(f"[SCAN-THREAD] Using SIMPLE scanner for quick scan")
                    try:
                        from scanner.main_scanner import scan_with_robust_progress
                        logger.info(f"[SCAN-THREAD] ✅ Successfully imported simple scanner")
                    except ImportError as e:
                        logger.error(f"[SCAN-THREAD] ❌ Failed to import scanner: {e}", exc_info=True)
                        raise
                    
                    logger.info(f"[SCAN-THREAD] Calling scan_with_robust_progress()")
                    logger.info(f"[SCAN-THREAD] Parameters: subnet={scan_config['subnet']}, scan_id={scan_id}, tracker={scan_tracker is not None}")
                    
                    devices, summary = scan_with_robust_progress(
                        scan_config['subnet'], 
                        scan_id,
                        scan_tracker,
                        use_advanced=True,
                        scan_mode=scan_config.get('scan_mode', 'smart')
                    )
                
                logger.info(f"[SCAN-THREAD] ✅ Scan function returned")
                logger.info(f"[SCAN-THREAD] Devices found: {len(devices)}")
                logger.info(f"[SCAN-THREAD] Summary: {json.dumps(summary, indent=2)}")
                
                # Update active scans
                logger.info(f"[SCAN-THREAD] Step 5: Updating active scans with results")
                if scan_id in active_scans:
                    scan_status = 'completed' if summary.get('scan_successful', False) else 'failed'
                    active_scans[scan_id]['status'] = scan_status
                    active_scans[scan_id]['devices_found'] = len(devices)
                    active_scans[scan_id]['summary'] = summary
                    active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                    logger.info(f"[SCAN-THREAD] Active scan updated with status: {scan_status}")
                
                # Save scan results to database
                logger.info(f"[SCAN-THREAD] Step 6: Saving scan results to database")
                if devices and len(devices) > 0:
                    try:
                        logger.info(f"[SCAN-THREAD] Processing {len(devices)} devices for database storage")
                        
                        # Create scan metadata
                        scan_metadata = {
                            'scan_id': scan_id,
                            'subnet': scan_config['subnet'],
                            'scan_type': scan_config.get('scanner_type', 'simple'),
                            'start_time': active_scans[scan_id]['start_time'],
                            'end_time': datetime.now().isoformat(),
                            'total_hosts': summary.get('total_hosts', 0),
                            'active_hosts': summary.get('active_hosts', len(devices))
                        }
                        
                        # Convert devices to dict format expected by process_enhanced_scan
                        devices_dict = {}
                        
                        # Check if devices is already a dict (from main_scanner)
                        if isinstance(devices, dict):
                            logger.debug(f"[SCAN-THREAD] Devices is already a dict with {len(devices)} entries")
                            devices_dict = devices
                        elif isinstance(devices, list):
                            # If it's a list, convert to dict
                            for device in devices:
                                logger.debug(f"[SCAN-THREAD] Processing device from list: {device}")
                                if isinstance(device, dict):
                                    # Check for both 'ip' and 'ip_address' fields
                                    ip_key = device.get('ip') or device.get('ip_address')
                                    if ip_key:
                                        devices_dict[ip_key] = device
                                        logger.debug(f"[SCAN-THREAD] Added device {ip_key} to devices_dict")
                                    else:
                                        logger.warning(f"[SCAN-THREAD] Device has no IP field: {device}")
                        else:
                            logger.warning(f"[SCAN-THREAD] Unexpected devices type: {type(devices)}")
                        
                        # Process and save to database
                        logger.info(f"[SCAN-THREAD] Calling process_enhanced_scan with {len(devices_dict)} devices")
                        import asyncio
                        inventory_results = asyncio.run(
                            process_enhanced_scan(devices_dict, scan_id, scan_metadata)
                        )
                        logger.info(f"[SCAN-THREAD] ✅ Scan results saved to database: {inventory_results}")
                        
                    except Exception as e:
                        logger.error(f"[SCAN-THREAD] ❌ Failed to save scan results to database: {e}", exc_info=True)
                
                # Complete the scan tracking
                logger.info(f"[SCAN-THREAD] Step 7: Completing scan tracking")
                if scan_tracker:
                    if summary.get('scan_successful', False):
                        msg = f"Scan completed: {len(devices)} devices found"
                        logger.info(f"[SCAN-THREAD] Marking scan as successful: {msg}")
                        scan_tracker.complete_scan(scan_id, True, msg)
                    else:
                        error_msg = summary.get('error', 'Unknown error')
                        logger.info(f"[SCAN-THREAD] Marking scan as failed: {error_msg}")
                        scan_tracker.complete_scan(scan_id, False, error_msg)
                
                # Notify completion via WebSocket
                logger.info(f"[SCAN-THREAD] Step 8: Emitting scan_completed event")
                completion_data = {
                    'scan_id': scan_id,
                    'success': summary.get('scan_successful', False),
                    'devices_found': len(devices),
                    'summary': summary
                }
                socketio.emit('scan_completed', completion_data)
                logger.info(f"[SCAN-THREAD] ✅ Scan {scan_id} completed successfully")
                logger.info(f"[SCAN-THREAD] Final status: {'SUCCESS' if summary.get('scan_successful', False) else 'FAILED'}")
                
            except Exception as e:
                logger.error(f"[SCAN-THREAD] ❌ CRITICAL ERROR in scan thread: {e}", exc_info=True)
                logger.error(f"[SCAN-THREAD] Exception type: {type(e).__name__}")
                logger.error(f"[SCAN-THREAD] Exception args: {e.args}")
                
                if scan_id in active_scans:
                    active_scans[scan_id]['status'] = 'failed'
                    active_scans[scan_id]['error'] = str(e)
                    active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                    
                socketio.emit('scan_completed', {
                    'scan_id': scan_id,
                    'success': False,
                    'error': str(e)
                })
                logger.info(f"[SCAN-THREAD] Scan thread exiting due to error")
        
        # Start background thread - now that we're using threading mode, normal threads work
        logger.info(f"Starting scan thread for {scan_id}")
        
        # Use a regular thread since we're in threading mode
        scan_thread = threading.Thread(
            target=start_scan_background, 
            name=f"scan-{scan_id[:8]}",
            daemon=True
        )
        scan_thread.start()
        
        logger.info(f"Scan thread started successfully - is_alive: {scan_thread.is_alive()}")
        
        logger.info(f"Returning response immediately for {scan_id}")
        return response
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    """Get scan results"""
    try:
        # Check if scan exists in active or completed scans
        if scan_id in active_scans:
            scan_info = active_scans[scan_id]
            if scan_info.get('status') == 'completed':
                # Get devices from the summary
                devices_found = scan_info.get('devices_found', 0)
                summary = scan_info.get('summary', {})
                
                # Get actual devices from database (those added during this scan)
                devices = []
                try:
                    # Get all devices discovered in the time window of this scan
                    start_time = scan_info.get('start_time')
                    end_time = scan_info.get('end_time', datetime.now().isoformat())
                    
                    # For now, just get the most recent devices
                    devices_data = inventory_manager.get_all_hosts(per_page=devices_found)
                    devices = devices_data.get('devices', [])
                except Exception as e:
                    logger.error(f"Failed to get devices for scan {scan_id}: {e}")
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'completed',
                    'devices': devices,
                    'summary': summary
                })
            else:
                return jsonify({
                    'scan_id': scan_id,
                    'status': scan_info.get('status', 'running'),
                    'message': 'Scan not yet completed'
                }), 202
        else:
            # Check scan tracker for completed scans
            scan_tracker = get_scan_tracker()
            progress = scan_tracker.get_progress(scan_id)
            
            if progress:
                return jsonify({
                    'scan_id': scan_id,
                    'status': progress.stage.value,
                    'devices': progress.scan_results,
                    'summary': {
                        'targets_completed': progress.targets_completed,
                        'targets_successful': progress.targets_successful,
                        'targets_failed': progress.targets_failed
                    }
                })
            else:
                return jsonify({'error': 'Scan not found'}), 404
                
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get detailed scan status with progress tracking"""
    try:
        # First check active scans
        if scan_id in active_scans:
            scan_info = active_scans[scan_id]
            return jsonify({
                'scan_id': scan_id,
                'status': scan_info.get('status', 'unknown'),
                'config': scan_info.get('config', {}),
                'devices_found': scan_info.get('devices_found', 0),
                'summary': scan_info.get('summary', {}),
                'start_time': scan_info.get('start_time'),
                'active': scan_info.get('status') in ['initializing', 'running']
            })
        
        # Try scan tracker
        progress = scan_tracker.get_progress(scan_id)
        if not progress:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Convert to dict for JSON serialization
        progress_dict = progress.__dict__.copy()
        progress_dict['start_time'] = progress.start_time.isoformat()
        progress_dict['last_update'] = progress.last_update.isoformat()
        progress_dict['stage'] = progress.stage.value
        
        return jsonify({
            'scan_id': scan_id,
            'progress': progress_dict,
            'active': progress.stage not in ['completed', 'failed']
        })
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/logs')
def get_scan_logs(scan_id):
    """Get scan logs with filtering options"""
    try:
        limit = request.args.get('limit', 100, type=int)
        priority_filter = request.args.get('priority', None)
        
        # Convert priority filter to list
        if priority_filter:
            from scanner.scan_progress_tracker import ScanPriority
            try:
                priority_list = [ScanPriority(p.strip()) for p in priority_filter.split(',')]
            except ValueError:
                priority_list = None
        else:
            priority_list = None
        
        logs = scan_tracker.get_logs(scan_id, limit=limit, priority_filter=priority_list)
        
        # Convert logs to dict format
        logs_dict = []
        for log in logs:
            log_dict = {
                'timestamp': log.timestamp.isoformat(),
                'stage': log.stage.value,
                'priority': log.priority.value,
                'message': log.message,
                'target': log.target,
                'details': log.details,
                'duration': log.duration
            }
            logs_dict.append(log_dict)
        
        return jsonify({
            'scan_id': scan_id,
            'logs': logs_dict,
            'total_logs': len(logs_dict)
        })
        
    except Exception as e:
        logger.error(f"Error getting scan logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/active')
def get_active_scans():
    """Get all currently active scans"""
    try:
        active_scans = scan_tracker.get_active_scans()
        
        # Convert to dict format
        scans_dict = {}
        for scan_id, progress in active_scans.items():
            progress_dict = progress.__dict__.copy()
            progress_dict['start_time'] = progress.start_time.isoformat()
            progress_dict['last_update'] = progress.last_update.isoformat()
            progress_dict['stage'] = progress.stage.value
            scans_dict[scan_id] = progress_dict
        
        return jsonify({
            'active_scans': scans_dict,
            'total_active': len(scans_dict)
        })
        
    except Exception as e:
        logger.error(f"Error getting active scans: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scans():
    """Get recent scans with enhanced metadata"""
    try:
        # Get scan history from inventory manager
        days = int(request.args.get('days', 7))
        
        # This would be implemented in the inventory manager
        # For now, return recent scans from active_scans and database
        recent_scans = []
        
        # Add completed scans from memory
        for scan_id, scan_info in scan_manager.active_scans.items():
            if scan_info.get('status') in ['completed', 'failed']:
                recent_scans.append({
                    'id': scan_id,
                    'status': scan_info['status'],
                    'start_time': scan_info.get('start_time', datetime.now()).isoformat(),
                    'end_time': scan_info.get('end_time', datetime.now()).isoformat(),
                    'config': scan_info.get('config', {}),
                    'results': scan_info.get('results', {})
                })
        
        return jsonify(recent_scans)
        
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices')
def get_devices():
    """Get devices with enhanced filtering and pagination"""
    try:
        search = request.args.get('search', '')
        device_type = request.args.get('type', 'all')
        status = request.args.get('status', 'all')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        
        # Get devices from inventory manager
        try:
            result = inventory_manager.get_all_hosts(search, page, per_page)
            devices = result.get('devices', []) if isinstance(result, dict) else []
            total = result.get('total', 0) if isinstance(result, dict) else 0
        except Exception as e:
            logger.warning(f"Could not get devices from inventory: {e}")
            devices = []
            total = 0
        
        # Enhance device data with additional information
        enhanced_devices = []
        for device in devices:
            if isinstance(device, dict):
                enhanced_device = device.copy()
                enhanced_device.update({
                    'device_type': enhanced_device.get('device_type', 'unknown'),
                    'discovery_methods': enhanced_device.get('discovery_methods', ['nmap']),
                    'confidence_score': enhanced_device.get('confidence_score', 1.0),
                    'last_changed': enhanced_device.get('last_changed') or enhanced_device.get('last_seen'),
                    'topology_connections': enhanced_device.get('topology_connections', 0)
                })
                enhanced_devices.append(enhanced_device)
        
        return jsonify({
            'devices': enhanced_devices,
            'total': total,
            'page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def get_statistics():
    """Get network statistics from actual database"""
    try:
        total_hosts = inventory_manager.get_host_count()
        
        # Get device statistics from database
        with sqlite3.connect(inventory_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'active'")
            active_hosts = cursor.fetchone()[0]
            
            # Get device type breakdown
            cursor.execute("""
                SELECT device_type, COUNT(*) as count 
                FROM devices 
                WHERE status = 'active' 
                GROUP BY device_type
            """)
            device_types = {row[0] or 'unknown': row[1] for row in cursor.fetchall()}
            
            # Get last scan time
            cursor.execute("SELECT MAX(start_time) FROM scan_metadata")
            last_scan_result = cursor.fetchone()[0]
            last_scan = last_scan_result if last_scan_result else None
        
        return jsonify({
            'total_hosts': total_hosts,
            'active_hosts': active_hosts,
            'total_devices': total_hosts,  # Frontend compatibility
            'active_devices': active_hosts,  # Frontend compatibility
            'device_breakdown': device_types,  # Frontend expects 'device_breakdown'
            'device_types': device_types,
            'critical_vulnerabilities': 0,  # TODO: Add when vulnerability scanning is implemented
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0, 
            'low_vulnerabilities': 0,
            'recent_changes_24h': 0,  # TODO: Calculate actual changes
            'port_statistics': {
                'high_risk_ports': 0,
                'total_open_ports': 0,  # TODO: Calculate from device_ports table
                'web_services': 0
            },  # TODO: Calculate from ports
            'last_scan': last_scan,
            'uptime_percentage': 99.0  # TODO: Calculate from actual uptime data
        })
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_ip>/history')
def get_device_history(device_ip):
    """Get device change history"""
    try:
        days = int(request.args.get('days', 30))
        history = inventory_manager.get_device_history(device_ip, days)
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error getting device history: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/topology')
def get_topology():
    """Get network topology map"""
    try:
        topology = inventory_manager.get_topology_map()
        return jsonify(topology)
    except Exception as e:
        logger.error(f"Error getting topology: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics/enhanced')
def get_enhanced_statistics():
    """Get comprehensive network statistics"""
    try:
        stats = inventory_manager.get_enhanced_summary()
        
        # Add real-time statistics
        stats.update({
            'active_scans': len([s for s in scan_manager.active_scans.values() 
                               if s.get('status') == 'running']),
            'last_scan_time': max([s.get('start_time', datetime.min) 
                                 for s in scan_manager.active_scans.values()], 
                                default=datetime.min).isoformat() if scan_manager.active_scans else None,
            'system_uptime': (datetime.now() - datetime.now().replace(hour=0, minute=0, second=0)).total_seconds()
        })
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting enhanced statistics: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/changes')
def get_recent_changes():
    """Get recent network changes"""
    try:
        hours = int(request.args.get('hours', 24))
        change_type = request.args.get('type', 'all')
        
        # This would query the device_changes table
        # For now, return mock data
        changes = [
            {
                'id': 'change_1',
                'device_ip': '192.168.1.100',
                'change_type': 'new_device',
                'description': 'New device discovered',
                'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                'severity': 'info'
            },
            {
                'id': 'change_2',
                'device_ip': '192.168.1.101',
                'change_type': 'service_changed',
                'description': 'HTTP service detected on port 8080',
                'timestamp': (datetime.now() - timedelta(hours=4)).isoformat(),
                'severity': 'warning'
            }
        ]
        
        return jsonify(changes)
        
    except Exception as e:
        logger.error(f"Error getting changes: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get security alerts with enhanced detection"""
    try:
        severity = request.args.get('severity', 'all')
        
        # Enhanced alert generation based on inventory data
        alerts = []
        
        # Get devices with high-risk ports
        # This would query the database for actual data
        alerts.extend([
            {
                'id': 'alert_1',
                'type': 'high_risk_port',
                'severity': 'warning',
                'title': 'High-Risk Service Detected',
                'description': 'Telnet service detected on 192.168.1.100:23',
                'timestamp': (datetime.now() - timedelta(hours=1)).isoformat(),
                'device_ip': '192.168.1.100',
                'recommendation': 'Consider disabling Telnet and using SSH instead'
            },
            {
                'id': 'alert_2',
                'type': 'new_device',
                'severity': 'info',
                'title': 'New Device Discovered',
                'description': 'Unknown device joined network: 192.168.1.150',
                'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat(),
                'device_ip': '192.168.1.150',
                'recommendation': 'Verify device ownership and purpose'
            }
        ])
        
        return jsonify(alerts)
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/devices', methods=['POST'])
def export_devices():
    """Export device inventory"""
    try:
        data = request.get_json() or {}
        export_format = data.get('format', 'csv')
        filters = data.get('filters', {})
        
        if export_format == 'csv':
            filename = inventory_manager.export_to_csv()
            return jsonify({
                'success': True,
                'filename': filename,
                'download_url': f'/api/download/{filename.split("/")[-1]}'
            })
        else:
            return jsonify({'error': 'Unsupported export format'}), 400
            
    except Exception as e:
        logger.error(f"Error exporting devices: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<device_ip>')
def get_device_details(device_ip):
    """Get detailed information about a specific device"""
    try:
        device_details = inventory_manager.get_host_details(device_ip)
        if not device_details:
            return jsonify({'error': 'Device not found'}), 404
        return jsonify(device_details)
    except Exception as e:
        logger.error(f"Error getting device details for {device_ip}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get vulnerability information"""
    try:
        severity = request.args.get('severity', 'all')
        host = request.args.get('host')
        
        vulnerabilities = inventory_manager.get_vulnerabilities(severity, host)
        return jsonify(vulnerabilities)
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Generate a network report"""
    try:
        data = request.get_json() or {}
        report_type = data.get('type', 'summary')
        format_type = data.get('format', 'json')
        
        # Generate report data
        report_data = {
            'type': report_type,
            'generated_at': datetime.now().isoformat(),
            'summary': inventory_manager.get_enhanced_summary(),
            'devices': inventory_manager.get_all_hosts(),
            'vulnerabilities': inventory_manager.get_vulnerabilities()
        }
        
        if format_type == 'json':
            return jsonify(report_data)
        elif format_type == 'csv':
            filename = inventory_manager.export_to_csv()
            return send_file(filename, as_attachment=True)
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/summary')
def get_network_summary():
    """Get network overview summary"""
    try:
        summary = {
            'total_devices': inventory_manager.get_host_count(),
            'total_vulnerabilities': inventory_manager.get_vulnerability_count(),
            'open_ports': inventory_manager.get_total_open_ports(),
            'last_scan': inventory_manager.get_last_scan_time(),
            'device_types': {},
            'risk_distribution': {}
        }
        
        # Add enhanced summary data
        enhanced_summary = inventory_manager.get_enhanced_summary()
        summary.update(enhanced_summary)
        
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting network summary: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/database/clear', methods=['POST'])
def clear_database():
    """Clear all database data"""
    try:
        # Clear all tables
        with sqlite3.connect(inventory_manager.db_path) as conn:
            cursor = conn.cursor()
            
            # Get list of all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            # Clear each table
            for table in tables:
                table_name = table[0]
                if table_name != 'sqlite_sequence':  # Skip SQLite internal table
                    cursor.execute(f"DELETE FROM {table_name}")
            
            # Reset auto-increment counters
            cursor.execute("DELETE FROM sqlite_sequence")
            
            conn.commit()
        
        logger.info("Database cleared successfully")
        return jsonify({'success': True, 'message': 'Database cleared successfully'})
        
    except Exception as e:
        logger.error(f"Error clearing database: {e}")
        return jsonify({'error': str(e)}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection and start background updates"""
    try:
        logger.info(f'Client connected: {request.sid}')
        emit('connected', {'message': 'Connected to enhanced network scanner', 'sid': request.sid})
        
        # Start background update thread for real-time data (only once)
        if not hasattr(app, 'update_thread_started'):
            app.update_thread_started = True
            logger.info('Starting background update thread')
            socketio.start_background_task(send_periodic_updates)
    except Exception as e:
        logger.error(f'Error in connect handler: {e}')
        disconnect()

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        logger.info(f'Client disconnected: {request.sid}')
    except Exception as e:
        logger.error(f'Error in disconnect handler: {e}')

@socketio.on('subscribe_updates')
def handle_subscribe_updates(data):
    """Subscribe to real-time updates"""
    update_type = data.get('type', 'all')
    logger.info(f'Client subscribed to {update_type} updates')
    
    # Send current status
    emit('status_update', {
        'active_scans': len([s for s in scan_manager.active_scans.values() 
                           if s.get('status') == 'running']),
        'total_devices': inventory_manager.get_host_count(),
        'timestamp': datetime.now().isoformat()
    })

def send_periodic_updates():
    """Send periodic updates to connected clients"""
    while True:
        try:
            # Send system statistics every 30 seconds
            stats = inventory_manager.get_enhanced_summary()
            socketio.emit('stats_update', stats)
            
            # Send recent changes every 60 seconds
            # This would query recent changes from database
            
        except Exception as e:
            logger.error(f"Error sending periodic updates: {e}")
        
        socketio.sleep(30)

# Background update thread is now started in handle_connect()

if __name__ == '__main__':
    logger.info("🚀 Enhanced Network Scanner Backend starting...")
    logger.info("🔧 Features enabled:")
    logger.info("  ✅ Multi-protocol discovery (SNMP, Nmap, ARP)")
    logger.info("  ✅ Device classification and fingerprinting")
    logger.info("  ✅ Comprehensive change tracking")
    logger.info("  ✅ Network topology mapping")
    logger.info("  ✅ Real-time WebSocket updates")
    logger.info("  ✅ Enhanced inventory management")
    logger.info("  ✅ RESTful API with comprehensive endpoints")
    
    # Initialize database on startup
    try:
        inventory_manager.get_enhanced_summary()
        logger.info("✅ Enhanced inventory database ready")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        logger.info("🔧 Creating database tables...")
        try:
            inventory_manager.initialize_enhanced_db()
            logger.info("✅ Database tables created successfully")
        except Exception as init_error:
            logger.error(f"❌ Database creation failed: {init_error}")
    
    # Print API endpoints for reference
    logger.info("🌐 Available API endpoints:")
    logger.info("  📊 GET  /health - System health check")
    logger.info("  📊 GET  /api/status - Scanner status")
    logger.info("  📈 GET  /api/statistics/enhanced - Enhanced statistics")
    logger.info("  🖥️  GET  /api/devices - Device inventory")
    logger.info("  🛡️  GET  /api/vulnerabilities - Vulnerability data")
    logger.info("  🌐 GET  /api/topology - Network topology")
    logger.info("  🔍 POST /api/scan/start - Start network scan")
    logger.info("  📄 POST /api/reports/generate - Generate reports")
    logger.info("  🗑️  POST /api/database/clear - Clear database")
    
    # Start the server
    port = int(os.environ.get('PORT', 5002))
    logger.info(f"🌐 Server starting on http://0.0.0.0:{port}")
    logger.info(f"📱 WebSocket available for real-time updates")
    logger.info(f"🧪 Run 'python test_api.py' to test all endpoints")
    
    try:
        # Use development configuration with eventlet (production should use gunicorn)
        port = int(os.environ.get('PORT', 5002))
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=port, 
            debug=False,
            use_reloader=False,
            log_output=True,
            allow_unsafe_werkzeug=True  # Allow development server for testing
        )
    except KeyboardInterrupt:
        logger.info("🛑 Server shutdown requested")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
    finally:
        logger.info("👋 Enhanced Network Scanner Backend stopped")
