#!/usr/bin/env python3
"""
Network Scanner Backend - Working Minimal API
"""

import os
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'

# Enable CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

@app.route('/api/status')
def get_status():
    """Get scanner status"""
    return jsonify({'status': 'active', 'version': '2.0.0'})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a network scan"""
    try:
        data = request.get_json() or {}
        subnet = data.get('subnet', '192.168.1.0/24')
        aggressive = data.get('aggressive', False)
        vulnerability_scan = data.get('vulnerability_scan', False)
        
        logger.info(f"Starting scan for subnet: {subnet}, aggressive: {aggressive}, vuln_scan: {vulnerability_scan}")
        
        # Simulate scan start
        return jsonify({
            'success': True,
            'scan_id': 'scan_123',
            'message': f'Scan started for {subnet}',
            'subnet': subnet,
            'aggressive': aggressive,
            'vulnerability_scan': vulnerability_scan
        })
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans')
def get_scans():
    """Get recent scans"""
    days = request.args.get('days', 7)
    return jsonify([
        {
            'id': 'scan_123',
            'subnet': '192.168.1.0/24',
            'timestamp': '2025-08-19T14:00:00Z',
            'status': 'completed',
            'hosts_found': 12,
            'vulnerabilities': 3
        },
        {
            'id': 'scan_122',
            'subnet': '10.0.0.0/24',
            'timestamp': '2025-08-18T10:30:00Z',
            'status': 'completed',
            'hosts_found': 8,
            'vulnerabilities': 1
        }
    ])

@app.route('/api/statistics')
def get_statistics():
    """Get network statistics"""
    return jsonify({
        'total_hosts': 25,
        'active_hosts': 20,
        'critical_vulnerabilities': 2,
        'high_vulnerabilities': 5,
        'medium_vulnerabilities': 8,
        'low_vulnerabilities': 12,
        'last_scan': '2025-08-19T14:00:00Z',
        'uptime_percentage': 98.5
    })

@app.route('/api/alerts')
def get_alerts():
    """Get security alerts"""
    return jsonify([
        {
            'id': 'alert_1',
            'type': 'critical',
            'title': 'Critical Vulnerability Detected',
            'description': 'CVE-2024-1234 found on host 192.168.1.100',
            'timestamp': '2025-08-19T13:45:00Z',
            'host': '192.168.1.100'
        },
        {
            'id': 'alert_2',
            'type': 'warning',
            'title': 'New Host Discovered',
            'description': 'Unknown device joined network: 192.168.1.150',
            'timestamp': '2025-08-19T12:30:00Z',
            'host': '192.168.1.150'
        }
    ])

if __name__ == '__main__':
    logger.info("Network Scanner Backend starting on port 8080")
    socketio.run(app, host='0.0.0.0', port=8080, debug=False, allow_unsafe_werkzeug=True)

