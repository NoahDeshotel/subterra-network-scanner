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
from scanner.scan_progress_tracker import ScanProgressTracker
from scanner.enhanced_inventory import EnhancedInventoryManager

logger = logging.getLogger(__name__)

class ScannerAPI:
    """API handler for network scanning operations"""
    
    def __init__(self, socketio=None):
        self.scanner = NetworkScanner()
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
        """Run scan in background thread"""
        try:
            # Update status
            self.active_scans[scan_id]['status'] = 'running'
            
            # Initialize scan in tracker
            self.scan_tracker.start_scan(scan_id, scan_config={
                'subnet': subnet,
                'scan_mode': scan_mode
            })
            
            # Progress callback
            def progress_callback(sid, percentage, message):
                self.scan_tracker.update_progress(scan_id, percentage, message)
                
                # Emit via WebSocket if available
                if self.socketio:
                    try:
                        self.socketio.emit('scan_progress', {
                            'scan_id': scan_id,
                            'percentage': percentage,
                            'message': message,
                            'progress': percentage
                        })
                    except:
                        pass
            
            # Run the scan
            logger.info(f"Executing scan {scan_id}")
            devices, summary = self.scanner.scan_network(
                subnet,
                scan_mode=scan_mode,
                progress_callback=progress_callback
            )
            
            # Save results to database
            if devices:
                logger.info(f"Saving {len(devices)} devices to inventory")
                asyncio.run(
                    self.inventory.process_scan_results(devices, scan_id)
                )
            
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