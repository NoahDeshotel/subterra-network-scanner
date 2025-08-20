#!/usr/bin/env python3
"""
Advanced Network Scanner Backend
Comprehensive L3 network scanning with inventory management and real-time visualization
"""

import os
import sys
import json
import asyncio
import logging
import threading
import time
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import schedule
from dotenv import load_dotenv

# Import custom modules
from scanner.network_scanner import NetworkScanner
from scanner.inventory_manager import InventoryManager
from scanner.vulnerability_analyzer import VulnerabilityAnalyzer
from api.routes import create_api_routes
from api.websocket_handler import WebSocketHandler

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Enable CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize components
scanner = NetworkScanner()
inventory = InventoryManager(db_path='/app/data/inventory.db')
vuln_analyzer = VulnerabilityAnalyzer()
ws_handler = WebSocketHandler(socketio)

# Global scan state
scan_state = {
    'is_scanning': False,
    'progress': 0,
    'current_host': None,
    'discovered_hosts': [],
    'start_time': None,
    'estimated_completion': None
}

@app.route('/health')
def health_check():
    """Health check endpoint for Docker"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Initiate a network scan"""
    global scan_state
    
    if scan_state['is_scanning']:
        return jsonify({'error': 'Scan already in progress'}), 409
    
    # Get scan parameters
    data = request.json or {}
    subnet = data.get('subnet', 'auto')
    aggressive = data.get('aggressive', False)
    
    # Start scan in background thread
    thread = threading.Thread(
        target=run_scan,
        args=(subnet, aggressive),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        'message': 'Scan started',
        'scan_id': datetime.now().isoformat()
    })

def run_scan(subnet='auto', aggressive=False):
    """Execute network scan with real-time updates"""
    global scan_state
    
    try:
        scan_state['is_scanning'] = True
        scan_state['start_time'] = datetime.now()
        scan_state['progress'] = 0
        scan_state['discovered_hosts'] = []
        
        logger.info(f"Starting network scan - Subnet: {subnet}, Aggressive: {aggressive}")
        
        # Emit scan started event
        socketio.emit('scan_started', {
            'timestamp': scan_state['start_time'].isoformat(),
            'subnet': subnet
        })
        
        # Detect subnet if auto
        if subnet == 'auto':
            subnet = scanner.detect_local_subnet()
            logger.info(f"Auto-detected subnet: {subnet}")
        
        # Phase 1: Host discovery
        update_scan_progress(10, "Discovering hosts...")
        hosts = scanner.discover_hosts(subnet)
        scan_state['discovered_hosts'] = hosts
        
        socketio.emit('hosts_discovered', {
            'count': len(hosts),
            'hosts': hosts
        })
        
        # Phase 2: Detailed scanning
        total_hosts = len(hosts)
        results = []
        
        for idx, host in enumerate(hosts):
            progress = 10 + (idx / total_hosts) * 80
            update_scan_progress(progress, f"Scanning {host}")
            
            # Scan individual host
            host_data = scanner.scan_host(host, aggressive=aggressive)
            
            # Analyze vulnerabilities
            if host_data.get('cves'):
                host_data['vulnerability_score'] = vuln_analyzer.calculate_risk_score(
                    host_data['cves']
                )
            
            results.append(host_data)
            
            # Store in inventory
            inventory.add_scan_result(host_data)
            
            # Emit progress update
            socketio.emit('host_scanned', {
                'host': host,
                'data': host_data,
                'progress': progress
            })
        
        # Phase 3: Generate visualization data
        update_scan_progress(90, "Generating visualization...")
        graph_data = generate_graph_data(results)
        
        # Save results
        scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_path = f'/app/data/scans/scan_{scan_id}.json'
        
        with open(save_path, 'w') as f:
            json.dump({
                'metadata': {
                    'scan_id': scan_id,
                    'timestamp': datetime.now().isoformat(),
                    'subnet': subnet,
                    'host_count': len(results)
                },
                'results': results,
                'graph': graph_data
            }, f, indent=2)
        
        # Complete scan
        update_scan_progress(100, "Scan complete")
        
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'duration': (datetime.now() - scan_state['start_time']).total_seconds(),
            'host_count': len(results),
            'vulnerability_count': sum(len(h.get('cves', [])) for h in results)
        })
        
        logger.info(f"Scan completed successfully - {len(results)} hosts scanned")
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        socketio.emit('scan_error', {'error': str(e)})
    finally:
        scan_state['is_scanning'] = False
        scan_state['progress'] = 0

def update_scan_progress(progress: float, message: str):
    """Update scan progress and emit to clients"""
    global scan_state
    scan_state['progress'] = progress
    
    socketio.emit('scan_progress', {
        'progress': progress,
        'message': message,
        'timestamp': datetime.now().isoformat()
    })

def generate_graph_data(scan_results: List[Dict]) -> Dict:
    """Generate Three.js compatible graph data"""
    nodes = []
    edges = []
    
    # Get local IP
    local_ip = scanner.get_local_ip()
    
    # Add local machine as central node
    nodes.append({
        'id': local_ip,
        'label': 'You',
        'group': 'self',
        'x': 0,
        'y': 0,
        'z': 0,
        'data': {
            'type': 'local',
            'os': 'Local System'
        }
    })
    
    # Add discovered hosts
    num_hosts = len(scan_results)
    
    for idx, host in enumerate(scan_results):
        angle = (2 * math.pi * idx) / num_hosts
        radius = 100
        
        # Calculate risk level for coloring
        risk_level = 'low'
        if host.get('cves'):
            max_cvss = max((cve.get('cvss', 0) for cve in host['cves']), default=0)
            if max_cvss >= 7:
                risk_level = 'high'
            elif max_cvss >= 4:
                risk_level = 'medium'
        
        nodes.append({
            'id': host['ip'],
            'label': host.get('hostname', host['ip']),
            'group': risk_level,
            'x': radius * math.cos(angle),
            'y': radius * math.sin(angle),
            'z': 0,
            'data': host
        })
        
        # Add edge from local to host
        edges.append({
            'source': local_ip,
            'target': host['ip'],
            'label': f"{len(host.get('ports', []))} ports",
            'value': len(host.get('ports', []))
        })
    
    return {'nodes': nodes, 'edges': edges}

@app.route('/api/inventory/history')
def get_inventory_history():
    """Get historical scan data"""
    days = request.args.get('days', 30, type=int)
    history = inventory.get_history(days=days)
    return jsonify(history)

@app.route('/api/inventory/changes')
def get_inventory_changes():
    """Get inventory changes between scans"""
    scan1_id = request.args.get('scan1')
    scan2_id = request.args.get('scan2')
    
    if not scan1_id or not scan2_id:
        return jsonify({'error': 'Both scan IDs required'}), 400
    
    changes = inventory.compare_scans(scan1_id, scan2_id)
    return jsonify(changes)

@app.route('/api/export/<format>')
def export_data(format):
    """Export scan data in various formats"""
    scan_id = request.args.get('scan_id')
    
    if format == 'csv':
        file_path = inventory.export_to_csv(scan_id)
    elif format == 'pdf':
        file_path = generate_pdf_report(scan_id)
    elif format == 'json':
        file_path = f'/app/data/scans/scan_{scan_id}.json'
    else:
        return jsonify({'error': 'Invalid format'}), 400
    
    return send_file(file_path, as_attachment=True)

def generate_pdf_report(scan_id: str) -> str:
    """Generate PDF report for scan"""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    
    # Implementation would go here
    # Return path to generated PDF
    return f'/app/data/reports/report_{scan_id}.pdf'

def scheduled_scan():
    """Run scheduled network scan"""
    logger.info("Running scheduled scan")
    run_scan(subnet='auto', aggressive=False)

# Schedule periodic scans
scan_interval = int(os.environ.get('SCAN_INTERVAL', 3600))
schedule.every(scan_interval).seconds.do(scheduled_scan)

def run_scheduler():
    """Run the scheduler in a separate thread"""
    while True:
        schedule.run_pending()
        time.sleep(60)

# Register API routes
create_api_routes(app, scanner, inventory, vuln_analyzer)

if __name__ == '__main__':
    # Ensure data directories exist
    Path('/app/data/scans').mkdir(parents=True, exist_ok=True)
    Path('/app/data/reports').mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    inventory.initialize_db()
    
    # Start scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    # Display startup message
    logger.info("""
    ╔══════════════════════════════════════════════╗
    ║   Network Scanner & Visualization System     ║
    ║   Version 2.0 - Enterprise Edition           ║
    ╚══════════════════════════════════════════════╝
    
    🚀 Starting services...
    📡 Scanner: Ready
    💾 Database: Connected
    🌐 Web UI: http://localhost:80
    📊 API: http://localhost:8080
    
    ⚠️  Legal Notice: Only scan networks you own or have permission to test.
    """)
    
    # Run Flask with SocketIO using eventlet for production
    try:
        import eventlet
        eventlet.monkey_patch()
        logger.info("Starting with eventlet server on port 8080")
        socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
    except ImportError:
        logger.warning("Eventlet not available, falling back to Werkzeug with unsafe flag")
        socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)
