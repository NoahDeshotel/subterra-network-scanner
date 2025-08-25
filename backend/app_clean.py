#!/usr/bin/env python3
"""
Clean Network Scanner API
Simplified API using modular scanner architecture
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import logging
import os
from datetime import datetime

# Import scanner API
from scanner_api import initialize_scanner_api, get_scanner_api
from scanner.enhanced_inventory import EnhancedInventoryManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
CORS(app, resources={r"/*": {"origins": "*"}})

# Create SocketIO instance
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25,
    logger=True,
    engineio_logger=True
)

# Initialize scanner API with socketio
scanner_api = initialize_scanner_api(socketio)

# Initialize inventory manager
inventory = EnhancedInventoryManager()

# =====================
# Health & Status Routes
# =====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Get statistics using correct method
        stats = inventory.get_enhanced_summary()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'statistics': stats,
            'features': [
                'modular_scanning',
                'host_discovery',
                'port_scanning',
                'device_identification',
                'real_time_updates'
            ]
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# =====================
# Scan Management Routes
# =====================

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a network scan"""
    try:
        data = request.get_json() or {}
        
        # Start scan via API
        result = scanner_api.start_scan(data)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"Failed to start scan: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    try:
        status = scanner_api.get_scan_status(scan_id)
        return jsonify(status)
    except Exception as e:
        logger.error(f"Failed to get scan status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    try:
        result = scanner_api.stop_scan(scan_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Failed to stop scan: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    try:
        results = scanner_api.get_scan_results(scan_id)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Failed to get scan results: {e}")
        return jsonify({'error': str(e)}), 500

# =====================
# Device Management Routes
# =====================

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get all devices from inventory"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        search = request.args.get('search', '')
        
        # Use correct method name
        devices = inventory.get_all_hosts(
            search=search,
            page=page,
            per_page=per_page
        )
        
        return jsonify(devices)
        
    except Exception as e:
        logger.error(f"Failed to get devices: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<ip>', methods=['GET'])
def get_device(ip):
    """Get specific device details"""
    try:
        device = inventory.get_device_by_ip(ip)
        
        if device:
            return jsonify(device)
        else:
            return jsonify({'error': 'Device not found'}), 404
            
    except Exception as e:
        logger.error(f"Failed to get device: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<ip>', methods=['PUT'])
def update_device(ip):
    """Update device information"""
    try:
        data = request.get_json()
        
        # Update device in inventory
        import asyncio
        result = asyncio.run(
            inventory.update_device(ip, data)
        )
        
        return jsonify({'success': True, 'message': 'Device updated'})
        
    except Exception as e:
        logger.error(f"Failed to update device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/devices/<ip>', methods=['DELETE'])
def delete_device(ip):
    """Delete a device from inventory"""
    try:
        success = inventory.delete_device(ip)
        
        if success:
            return jsonify({'success': True, 'message': 'Device deleted'})
        else:
            return jsonify({'success': False, 'error': 'Device not found'}), 404
            
    except Exception as e:
        logger.error(f"Failed to delete device: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================
# Database Management Routes
# =====================

@app.route('/api/database/clear', methods=['POST'])
def clear_database():
    """Clear all devices from database"""
    try:
        # Direct database clearing
        import sqlite3
        db_path = '/app/data/enhanced_inventory.db'
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices")
            cursor.execute("DELETE FROM device_ports")
            cursor.execute("DELETE FROM device_vulnerabilities")
            cursor.execute("DELETE FROM device_changes")
            cursor.execute("DELETE FROM scan_metadata")
            conn.commit()
        
        return jsonify({'success': True, 'message': 'Database cleared successfully'})
    except Exception as e:
        logger.error(f"Failed to clear database: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/database/export', methods=['GET'])
def export_database():
    """Export devices to JSON"""
    try:
        devices = inventory.get_all_hosts(per_page=10000)
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'total_devices': devices.get('total', 0),
            'devices': devices.get('devices', [])
        })
        
    except Exception as e:
        logger.error(f"Failed to export database: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================
# Statistics Routes
# =====================

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get network statistics"""
    try:
        stats = inventory.get_enhanced_summary()
        
        return jsonify({
            'success': True,
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# =====================
# WebSocket Events
# =====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected")
    socketio.emit('connected', {'message': 'Connected to scanner API'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected")

@socketio.on('request_scan')
def handle_scan_request(data):
    """Handle scan request via WebSocket"""
    try:
        result = scanner_api.start_scan(data)
        socketio.emit('scan_started', result)
    except Exception as e:
        logger.error(f"WebSocket scan failed: {e}")
        socketio.emit('scan_error', {'error': str(e)})

# =====================
# Error Handlers
# =====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# =====================
# Main Entry Point
# =====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    
    logger.info("=" * 60)
    logger.info("NETWORK SCANNER API - CLEAN VERSION")
    logger.info("=" * 60)
    logger.info(f"Starting server on port {port}")
    logger.info("Features: Modular scanning, Real-time updates, Device identification")
    logger.info("=" * 60)
    
    # Run with SocketIO
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=False,
        use_reloader=False,
        log_output=True,
        allow_unsafe_werkzeug=True  # Allow for development
    )