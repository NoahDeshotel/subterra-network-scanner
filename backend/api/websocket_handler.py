"""
WebSocket Handler Module
Real-time communication for scan progress and live updates
"""

import logging
from datetime import datetime
from flask import request
from flask_socketio import emit, disconnect, join_room, leave_room
from typing import Dict, Any

logger = logging.getLogger(__name__)

class WebSocketHandler:
    def __init__(self, socketio):
        self.socketio = socketio
        self.connected_clients = set()
        self._register_events()
    
    def _register_events(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            logger.info(f"Client connected")
            self.connected_clients.add(request.sid)
            emit('connected', {'status': 'connected'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            logger.info(f"Client disconnected")
            self.connected_clients.discard(request.sid)
        
        @self.socketio.on('join_room')
        def handle_join_room(data):
            """Handle client joining a room"""
            room = data.get('room')
            if room:
                join_room(room)
                emit('joined_room', {'room': room})
        
        @self.socketio.on('leave_room')
        def handle_leave_room(data):
            """Handle client leaving a room"""
            room = data.get('room')
            if room:
                leave_room(room)
                emit('left_room', {'room': room})
    
    def broadcast_scan_progress(self, progress: float, message: str):
        """Broadcast scan progress to all clients"""
        self.socketio.emit('scan_progress', {
            'progress': progress,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    
    def broadcast_host_discovered(self, host_data: Dict):
        """Broadcast when a new host is discovered"""
        self.socketio.emit('host_discovered', {
            'host': host_data,
            'timestamp': datetime.now().isoformat()
        })
    
    def broadcast_vulnerability_found(self, host_ip: str, vulnerability: Dict):
        """Broadcast when a vulnerability is found"""
        self.socketio.emit('vulnerability_found', {
            'host': host_ip,
            'vulnerability': vulnerability,
            'timestamp': datetime.now().isoformat()
        })
    
    def broadcast_scan_complete(self, scan_summary: Dict):
        """Broadcast when scan is complete"""
        self.socketio.emit('scan_complete', {
            'summary': scan_summary,
            'timestamp': datetime.now().isoformat()
        })
    
    def broadcast_alert(self, alert: Dict):
        """Broadcast security alert"""
        self.socketio.emit('security_alert', {
            'alert': alert,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_connected_clients_count(self) -> int:
        """Get number of connected clients"""
        return len(self.connected_clients)
