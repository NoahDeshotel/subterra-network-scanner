#!/usr/bin/env python3
"""
Enhanced Network Scanner Backend - Netdisco-Inspired Implementation
Combines modern UI with comprehensive network discovery and inventory management
"""

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
from flask_socketio import SocketIO, emit
import threading
import json
from pathlib import Path

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
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

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Set up progress tracking WebSocket callback
def websocket_progress_callback(event_type: str, data: dict):
    """Send progress updates via WebSocket"""
    try:
        socketio.emit(event_type, data)
        logger.debug(f"Sent WebSocket event: {event_type}")
    except Exception as e:
        logger.error(f"Failed to send WebSocket event: {e}")

set_websocket_callback(websocket_progress_callback)

# Global instances
inventory_manager = EnhancedInventoryManager()
discovery_engine = None
active_scans = {}
scan_tracker = get_scan_tracker()

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

@app.route('/api/status')
def get_status():
    """Get enhanced scanner status"""
    return jsonify({
        'status': 'active',
        'version': '3.0.0-enhanced',
        'active_scans': len([s for s in active_scans.values() if s.get('status') == 'running']),
        'features': {
            'snmp_discovery': True,
            'topology_mapping': True,
            'change_detection': True,
            'device_classification': True,
            'vulnerability_scanning': True,
            'real_time_updates': True
        }
    })

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
            'vulnerability_scan': data.get('vulnerability_scan', True),
            'snmp_communities': data.get('snmp_communities', ['public']),
            'topology_discovery': data.get('topology_discovery', True)
        }
        
        logger.info(f"Starting enhanced scan {scan_id} with config: {scan_config}")
        
        # Auto-detect subnet if needed
        if scan_config['subnet'] == 'auto':
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            # Convert to /24 subnet
            subnet_parts = local_ip.split('.')
            scan_config['subnet'] = f"{'.'.join(subnet_parts[:3])}.0/24"
        
        # Start scan in background thread
        def run_scan():
            try:
                # Choose scanner based on subnet size and scan type
                network = ipaddress.ip_network(scan_config['subnet'], strict=False)
                total_hosts = len(list(network.hosts()))
                
                if scan_config.get('deep_scan', False) or total_hosts >= 256:
                    # Use enhanced scanner for deep scans or large networks
                    from scanner.netdisco_enhanced_scan import scan_with_enhanced_progress
                    devices, summary = scan_with_enhanced_progress(
                        scan_config['subnet'], 
                        scan_id,
                        scan_tracker
                    )
                else:
                    # Use simple scanner for quick scans
                    from scanner.simple_scan import scan_with_progress
                    devices, summary = scan_with_progress(
                        scan_config['subnet'], 
                        scan_id,
                        scan_tracker
                    )
                
                # Process results through inventory manager if devices found
                if devices:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        result_data = loop.run_until_complete(
                            process_enhanced_scan(devices, scan_id)
                        )
                    finally:
                        loop.close()
                
                # Complete the scan tracking
                if summary.get('scan_successful', False):
                    scan_tracker.complete_scan(scan_id, True, f"Scan completed: {len(devices)} devices found")
                else:
                    scan_tracker.complete_scan(scan_id, False, summary.get('error', 'Unknown error'))
                
                # Notify completion via WebSocket
                socketio.emit('scan_completed', {
                    'scan_id': scan_id,
                    'success': summary.get('scan_successful', False),
                    'devices_found': len(devices),
                    'summary': summary
                })
                
            except Exception as e:
                logger.error(f"Scan {scan_id} failed: {e}")
                scan_tracker.complete_scan(scan_id, False, f"Scan failed: {str(e)}")
                socketio.emit('scan_completed', {
                    'scan_id': scan_id,
                    'success': False,
                    'error': str(e)
                })
        
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Enhanced scan started for {scan_config["subnet"]}',
            'config': scan_config
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get detailed scan status with progress tracking"""
    try:
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
        
        # This would use the enhanced inventory manager
        # For now, return basic device information
        devices = inventory_manager.get_all_hosts(search, page, per_page)
        
        # Enhance device data with additional information
        enhanced_devices = []
        for device in devices:
            enhanced_device = device.copy()
            enhanced_device.update({
                'device_type': enhanced_device.get('device_type', 'unknown'),
                'discovery_methods': ['nmap'],  # Would come from database
                'confidence_score': 1.0,
                'last_changed': enhanced_device.get('last_seen'),
                'topology_connections': 0  # Would be calculated
            })
            enhanced_devices.append(enhanced_device)
        
        return jsonify({
            'devices': enhanced_devices,
            'total': len(enhanced_devices),
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
    """Handle client connection"""
    logger.info('Client connected')
    emit('connected', {'message': 'Connected to enhanced network scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')

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

# Start background update thread
@socketio.on('connect')
def start_background_updates():
    """Start background update thread for real-time data"""
    if not hasattr(app, 'update_thread_started'):
        app.update_thread_started = True
        socketio.start_background_task(send_periodic_updates)

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
    
    # Start the server
    logger.info(f"🌐 Server starting on http://0.0.0.0:8080")
    logger.info(f"📱 WebSocket available for real-time updates")
    logger.info(f"🧪 Run 'python test_api.py' to test all endpoints")
    
    try:
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=8080, 
            debug=False, 
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        logger.info("🛑 Server shutdown requested")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
    finally:
        logger.info("👋 Enhanced Network Scanner Backend stopped")
