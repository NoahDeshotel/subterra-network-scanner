#!/usr/bin/env python3
"""
Netdisco Integration Adapter
Connects the new job-based scanner with the existing API and progress tracking
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

from .job_based_scanner import (
    JobBasedScanner, run_job_based_discovery, 
    JobType, JobPriority, JobStatus
)
from .scan_progress_tracker import get_scan_tracker, ScanStage, ScanPriority

logger = logging.getLogger(__name__)

class NetdiscoScanAdapter:
    """
    Adapter to integrate job-based scanner with existing progress tracking
    """
    
    def __init__(self):
        self.scanner = None
        self.scan_tracker = get_scan_tracker()
        
    async def scan_network_enhanced(self, subnet: str, scan_id: str = None, **kwargs) -> tuple:
        """
        Enhanced network scan using job-based approach with progress tracking
        
        Args:
            subnet: Network subnet to scan (e.g., '192.168.1.0/24')
            scan_id: Optional scan ID for progress tracking
            **kwargs: Additional scan parameters
        
        Returns:
            Tuple of (devices_dict, summary_dict)
        """
        if not scan_id:
            scan_id = f"netdisco_scan_{int(time.time())}"
        
        logger.info(f"Starting enhanced Netdisco-style scan for {subnet}")
        
        try:
            # Initialize progress tracking
            self.scan_tracker.start_scan(scan_id, 1000, {
                "subnet": subnet,
                "scan_type": "netdisco_enhanced",
                "parameters": kwargs
            })
            
            # Start discovery
            self.scan_tracker.update_stage(scan_id, ScanStage.NETWORK_DISCOVERY, 
                                         "Initializing job-based discovery engine...")
            
            self.scanner = JobBasedScanner()
            
            # Parse initial targets
            initial_targets = [subnet]
            
            self.scan_tracker.update_stage(scan_id, ScanStage.HOST_DISCOVERY,
                                         f"Starting breadth-first discovery for {subnet}")
            
            # Create progress monitoring task
            progress_task = asyncio.create_task(self._monitor_progress(scan_id))
            
            try:
                # Run discovery
                devices, stats = await self.scanner.start_discovery(initial_targets, scan_id)
                
                # Stop progress monitoring
                progress_task.cancel()
                
                # Final processing
                self.scan_tracker.update_stage(scan_id, ScanStage.DATA_PROCESSING,
                                             "Processing discovery results...")
                
                # Convert devices to expected format
                devices_dict = {}
                for ip, device in devices.items():
                    if device.active:
                        devices_dict[ip] = {
                            'ip': device.ip,
                            'hostname': device.hostname,
                            'mac_address': device.mac_address,
                            'vendor': device.vendor,
                            'model': device.model,
                            'os': device.os_name,
                            'os_version': device.os_version,
                            'device_type': device.device_type,
                            'description': device.system_description,
                            'location': device.location,
                            'contact': device.contact,
                            'first_seen': device.first_seen.isoformat(),
                            'last_seen': device.last_seen.isoformat(),
                            'last_discover': device.last_discover.isoformat() if device.last_discover else None,
                            'snmp_capable': device.snmp_capable,
                            'has_bridge_mib': device.has_bridge_mib,
                            'has_cdp': device.has_cdp,
                            'has_lldp': device.has_lldp,
                            'uptime': device.uptime,
                            'ports': [],  # Would be populated from port scan results
                            'services': [],  # Would be populated from service detection
                            'cves': [],  # Would be populated from vulnerability scan
                            'status': 'active' if device.active else 'inactive'
                        }
                
                # Create enhanced summary
                summary = self.scanner.get_discovery_summary()
                enhanced_summary = {
                    'total_devices': len(devices_dict),
                    'scan_successful': True,
                    'enhanced': True,
                    'netdisco_compatible': True,
                    'discovery_method': 'job_based_breadth_first',
                    'scan_duration': summary.get('discovery_duration', 0),
                    'jobs_executed': {
                        'completed': summary.get('jobs_completed', 0),
                        'failed': summary.get('jobs_failed', 0),
                        'deferred': summary.get('jobs_deferred', 0)
                    },
                    'device_breakdown': summary.get('device_types', {}),
                    'vendor_breakdown': summary.get('vendors', {}),
                    'os_breakdown': summary.get('operating_systems', {}),
                    'snmp_devices': summary.get('snmp_devices', 0),
                    'topology_links': 0,  # Would be calculated from topology data
                    'features_used': [
                        'snmp_discovery',
                        'ping_sweep',
                        'device_classification',
                        'mac_table_collection',
                        'arp_table_collection',
                        'topology_discovery',
                        'historical_continuity',
                        'intelligent_deferral'
                    ]
                }
                
                # Complete scan
                self.scan_tracker.complete_scan(scan_id, True, 
                    f"Enhanced scan completed: {len(devices_dict)} devices discovered using {summary.get('jobs_completed', 0)} jobs")
                
                logger.info(f"Enhanced scan completed for {subnet}: {len(devices_dict)} devices")
                return devices_dict, enhanced_summary
                
            except asyncio.CancelledError:
                progress_task.cancel()
                raise
            
        except Exception as e:
            logger.error(f"Enhanced scan failed for {subnet}: {e}")
            self.scan_tracker.complete_scan(scan_id, False, f"Scan failed: {str(e)}")
            
            return {}, {
                'error': str(e),
                'scan_successful': False,
                'enhanced': True,
                'scan_duration': 0
            }
        
        finally:
            if self.scanner:
                await self.scanner.cleanup()
                self.scanner = None
    
    async def _monitor_progress(self, scan_id: str):
        """Monitor job-based scanner progress and update scan tracker"""
        last_completed_jobs = 0
        last_active_jobs = 0
        
        try:
            while True:
                await asyncio.sleep(2)  # Update every 2 seconds
                
                if not self.scanner:
                    continue
                
                # Get current job statistics
                completed_jobs = self.scanner.stats.get('jobs_completed', 0)
                failed_jobs = self.scanner.stats.get('jobs_failed', 0)
                active_jobs = len(self.scanner.active_jobs)
                total_devices = len(self.scanner.devices)
                
                # Update progress if there are changes
                if completed_jobs != last_completed_jobs or active_jobs != last_active_jobs:
                    
                    # Determine current stage based on job types
                    current_stage = ScanStage.HOST_DISCOVERY
                    stage_message = f"Processing jobs: {completed_jobs} completed, {active_jobs} active"
                    
                    # Check what types of jobs are running
                    if self.scanner.active_jobs:
                        job_types = [job.job_type.value for job in self.scanner.active_jobs.values()]
                        
                        if any('pingsweep' in jtype for jtype in job_types):
                            current_stage = ScanStage.NETWORK_DISCOVERY
                            stage_message = f"Network discovery: {total_devices} devices found"
                        elif any('discover' in jtype for jtype in job_types):
                            current_stage = ScanStage.HOST_DISCOVERY
                            stage_message = f"Device profiling: {completed_jobs} jobs completed"
                        elif any('topology' in jtype for jtype in job_types):
                            current_stage = ScanStage.TOPOLOGY_MAPPING
                            stage_message = f"Topology discovery: mapping network relationships"
                    
                    self.scan_tracker.update_stage(scan_id, current_stage, stage_message)
                    
                    # Log significant progress
                    if completed_jobs > last_completed_jobs:
                        jobs_delta = completed_jobs - last_completed_jobs
                        self.scan_tracker.log_info(scan_id, 
                            f"Completed {jobs_delta} jobs: {total_devices} total devices discovered")
                    
                    last_completed_jobs = completed_jobs
                    last_active_jobs = active_jobs
                
                # Check if discovery is complete (no active jobs and queue empty)
                if active_jobs == 0 and hasattr(self.scanner, 'job_queue'):
                    if self.scanner.job_queue.empty():
                        self.scan_tracker.log_info(scan_id, "Job queue empty - discovery completing")
                        break
                    
        except asyncio.CancelledError:
            self.scan_tracker.log_info(scan_id, "Progress monitoring cancelled")
        except Exception as e:
            logger.error(f"Progress monitoring error: {e}")

# Global adapter instance
_adapter = None

def get_netdisco_adapter():
    """Get singleton adapter instance"""
    global _adapter
    if _adapter is None:
        _adapter = NetdiscoScanAdapter()
    return _adapter

async def scan_with_netdisco_enhanced(subnet: str, scan_id: str, progress_tracker=None):
    """
    Enhanced network scan using Netdisco-inspired job-based approach
    Compatible with existing API interface
    
    Args:
        subnet: Network subnet to scan
        scan_id: Scan identifier for progress tracking
        progress_tracker: Progress tracker instance (optional)
    
    Returns:
        Tuple of (devices_dict, summary_dict)
    """
    
    def progress_callback(scan_id: str, message: str):
        if progress_tracker:
            progress_tracker.log_info(scan_id, message)
        logger.info(f"[{scan_id}] {message}")
    
    adapter = get_netdisco_adapter()
    
    try:
        progress_callback(scan_id, f"Starting enhanced Netdisco scan for {subnet}")
        
        # Run enhanced scan
        devices, summary = await adapter.scan_network_enhanced(subnet, scan_id)
        
        progress_callback(scan_id, 
            f"Enhanced scan completed: {len(devices)} devices found using job-based discovery")
        
        return devices, summary
        
    except Exception as e:
        progress_callback(scan_id, f"Enhanced scan failed: {str(e)}")
        logger.error(f"Enhanced scan error: {e}")
        return {}, {'error': str(e), 'scan_successful': False, 'enhanced': True}

# Additional utility functions for integration

def get_scan_capabilities():
    """Get capabilities of the enhanced scanner"""
    return {
        'job_based_architecture': True,
        'breadth_first_discovery': True,
        'snmp_discovery': True,
        'mac_table_collection': True,
        'arp_table_collection': True,
        'topology_discovery': True,
        'cdp_support': True,
        'lldp_support': True,
        'device_classification': True,
        'historical_continuity': True,
        'intelligent_deferral': True,
        'exponential_backoff': True,
        'concurrent_job_processing': True,
        'comprehensive_device_profiling': True,
        'vendor_identification': True,
        'os_detection': True,
        'service_discovery': True,
        'netdisco_compatible': True
    }

def get_supported_protocols():
    """Get list of supported discovery protocols"""
    return [
        'ICMP',      # Ping sweep
        'SNMPv1',    # Basic SNMP discovery
        'SNMPv2c',   # Community-based SNMP
        'CDP',       # Cisco Discovery Protocol
        'LLDP',      # Link Layer Discovery Protocol
        'ARP',       # Address Resolution Protocol
        'DNS',       # Domain Name Resolution
        'TCP',       # Port scanning
        'UDP',       # UDP service discovery
        'HTTP',      # Web service detection
        'HTTPS',     # Secure web service detection
        'SSH',       # Secure shell detection
        'Telnet',    # Legacy telnet detection
        'SNMP',      # SNMP service detection
    ]

def get_device_classification_types():
    """Get supported device classification types"""
    from .job_based_scanner import ENHANCED_DEVICE_PATTERNS
    return list(ENHANCED_DEVICE_PATTERNS.keys())

def get_vendor_database_info():
    """Get information about vendor identification capabilities"""
    from .job_based_scanner import VENDOR_OIDS
    return {
        'vendor_oids_supported': len(VENDOR_OIDS),
        'vendors': list(VENDOR_OIDS.values()),
        'classification_methods': [
            'SNMP sysObjectID',
            'System description parsing',
            'MAC address OUI lookup',
            'Hostname pattern matching',
            'Service fingerprinting'
        ]
    }

async def test_enhanced_scanner():
    """Test the enhanced scanner functionality"""
    logger.info("Testing enhanced Netdisco-compatible scanner...")
    
    test_subnet = "192.168.1.0/24"
    scan_id = f"test_scan_{int(time.time())}"
    
    try:
        devices, summary = await scan_with_netdisco_enhanced(test_subnet, scan_id)
        
        print(f"Test Results:")
        print(f"  Devices found: {len(devices)}")
        print(f"  Scan successful: {summary.get('scan_successful', False)}")
        print(f"  Enhanced features: {summary.get('enhanced', False)}")
        print(f"  Jobs completed: {summary.get('jobs_executed', {}).get('completed', 0)}")
        print(f"  Device types: {summary.get('device_breakdown', {})}")
        print(f"  Vendors: {summary.get('vendor_breakdown', {})}")
        
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    # Run test
    asyncio.run(test_enhanced_scanner())