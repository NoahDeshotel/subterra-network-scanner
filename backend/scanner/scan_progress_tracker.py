"""
Scan Progress Tracking System
Provides detailed logging and real-time progress updates for network scans
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import json

logger = logging.getLogger(__name__)

class ScanStage(Enum):
    """Network scan stages"""
    INITIALIZING = "initializing"
    NETWORK_DISCOVERY = "network_discovery"
    HOST_DISCOVERY = "host_discovery"
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    OS_DETECTION = "os_detection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    SNMP_DISCOVERY = "snmp_discovery"
    TOPOLOGY_MAPPING = "topology_mapping"
    DATA_PROCESSING = "data_processing"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"

class ScanPriority(Enum):
    """Scan message priority levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ScanProgress:
    """Scan progress information"""
    scan_id: str
    stage: ScanStage
    current_step: str
    total_steps: int = 0
    completed_steps: int = 0
    percentage: float = 0.0
    estimated_time_remaining: Optional[int] = None
    current_target: Optional[str] = None
    targets_total: int = 0
    targets_completed: int = 0
    start_time: datetime = None
    last_update: datetime = None
    errors: List[str] = None
    warnings: List[str] = None
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()
        if self.last_update is None:
            self.last_update = datetime.now()
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.details is None:
            self.details = {}

@dataclass
class ScanLogEntry:
    """Individual scan log entry"""
    timestamp: datetime
    scan_id: str
    stage: ScanStage
    priority: ScanPriority
    message: str
    target: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    duration: Optional[float] = None

class ScanProgressTracker:
    """
    Comprehensive scan progress tracking and logging system
    """
    
    def __init__(self, websocket_callback: Optional[Callable] = None):
        self.active_scans: Dict[str, ScanProgress] = {}
        self.scan_logs: Dict[str, List[ScanLogEntry]] = {}
        self.websocket_callback = websocket_callback
        self._lock = threading.Lock()
        
        # Stage timing estimates (in seconds)
        self.stage_estimates = {
            ScanStage.INITIALIZING: 2,
            ScanStage.NETWORK_DISCOVERY: 30,
            ScanStage.HOST_DISCOVERY: 60,
            ScanStage.PORT_SCANNING: 120,
            ScanStage.SERVICE_DETECTION: 90,
            ScanStage.OS_DETECTION: 45,
            ScanStage.VULNERABILITY_SCAN: 180,
            ScanStage.SNMP_DISCOVERY: 60,
            ScanStage.TOPOLOGY_MAPPING: 30,
            ScanStage.DATA_PROCESSING: 15,
            ScanStage.FINALIZING: 5
        }
    
    def start_scan(self, scan_id: str, total_targets: int = 0, scan_config: Dict = None) -> ScanProgress:
        """Start tracking a new scan"""
        logger.info(f"[TRACKER] start_scan called for {scan_id}")
        with self._lock:
            logger.info(f"[TRACKER] Creating ScanProgress object for {scan_id}")
            progress = ScanProgress(
                scan_id=scan_id,
                stage=ScanStage.INITIALIZING,
                current_step="Initializing scan...",
                targets_total=total_targets,
                details=scan_config or {}
            )
            
            logger.info(f"[TRACKER] Adding scan to active_scans: {scan_id}")
            self.active_scans[scan_id] = progress
            self.scan_logs[scan_id] = []
            
            logger.info(f"[TRACKER] Calling _notify_progress_update for {scan_id}")
            self._notify_progress_update(scan_id)
            logger.info(f"[TRACKER] start_scan completed for {scan_id}, now logging message")
        
        # Call log_message outside the lock to avoid deadlock
        logger.info(f"[TRACKER] Logging initial message for {scan_id}")
        self.log_message(
            scan_id, 
            ScanStage.INITIALIZING,
            ScanPriority.INFO,
            f"Scan started with {total_targets} targets",
            details={"config": scan_config}
        )
        
        return progress
    
    def update_stage(self, scan_id: str, stage: ScanStage, message: str = None):
        """Update the current scan stage"""
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            progress = self.active_scans[scan_id]
            old_stage = progress.stage
            progress.stage = stage
            progress.current_step = message or f"Starting {stage.value.replace('_', ' ').title()}"
            progress.last_update = datetime.now()
            
            # Reset step counters for new stage
            progress.completed_steps = 0
            progress.total_steps = 0
            
            # Update percentage based on stage completion
            self._update_overall_percentage(scan_id)
            
            self.log_message(
                scan_id,
                stage,
                ScanPriority.INFO,
                f"Stage changed: {old_stage.value} → {stage.value}",
                details={"previous_stage": old_stage.value, "new_stage": stage.value}
            )
            
            self._notify_progress_update(scan_id)
    
    def update_step(self, scan_id: str, message: str, completed_steps: int = None, 
                   total_steps: int = None, target: str = None):
        """Update the current step within a stage"""
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            progress = self.active_scans[scan_id]
            progress.current_step = message
            progress.current_target = target
            progress.last_update = datetime.now()
            
            if completed_steps is not None:
                progress.completed_steps = completed_steps
            if total_steps is not None:
                progress.total_steps = total_steps
            
            # Calculate stage percentage
            if progress.total_steps > 0:
                stage_percentage = (progress.completed_steps / progress.total_steps) * 100
                progress.details['stage_percentage'] = stage_percentage
            
            # Update overall percentage
            self._update_overall_percentage(scan_id)
            
            # Update time estimates
            self._update_time_estimates(scan_id)
            
            self.log_message(
                scan_id,
                progress.stage,
                ScanPriority.DEBUG,
                message,
                target=target,
                details={
                    "completed_steps": completed_steps,
                    "total_steps": total_steps,
                    "stage_percentage": progress.details.get('stage_percentage', 0)
                }
            )
            
            self._notify_progress_update(scan_id)
    
    def update_target_progress(self, scan_id: str, completed_targets: int):
        """Update the number of completed targets"""
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            progress = self.active_scans[scan_id]
            progress.targets_completed = completed_targets
            progress.last_update = datetime.now()
            
            # Update overall percentage
            self._update_overall_percentage(scan_id)
            self._update_time_estimates(scan_id)
            
            self.log_message(
                scan_id,
                progress.stage,
                ScanPriority.INFO,
                f"Target progress: {completed_targets}/{progress.targets_total}",
                details={"targets_completed": completed_targets, "targets_total": progress.targets_total}
            )
            
            self._notify_progress_update(scan_id)
    
    def log_message(self, scan_id: str, stage: ScanStage, priority: ScanPriority, 
                   message: str, target: str = None, details: Dict = None, duration: float = None):
        """Log a message for the scan"""
        entry = ScanLogEntry(
            timestamp=datetime.now(),
            scan_id=scan_id,
            stage=stage,
            priority=priority,
            message=message,
            target=target,
            details=details,
            duration=duration
        )
        
        with self._lock:
            if scan_id not in self.scan_logs:
                self.scan_logs[scan_id] = []
            
            self.scan_logs[scan_id].append(entry)
            
            # Add to errors/warnings list if applicable
            if scan_id in self.active_scans:
                progress = self.active_scans[scan_id]
                if priority == ScanPriority.ERROR or priority == ScanPriority.CRITICAL:
                    progress.errors.append(f"{target or ''}: {message}")
                elif priority == ScanPriority.WARNING:
                    progress.warnings.append(f"{target or ''}: {message}")
        
        # Log to standard logging system
        log_level = {
            ScanPriority.DEBUG: logging.DEBUG,
            ScanPriority.INFO: logging.INFO,
            ScanPriority.WARNING: logging.WARNING,
            ScanPriority.ERROR: logging.ERROR,
            ScanPriority.CRITICAL: logging.CRITICAL
        }[priority]
        
        logger.log(log_level, f"[{scan_id}] {stage.value}: {message}", extra={
            "scan_id": scan_id,
            "stage": stage.value,
            "target": target,
            "details": details
        })
    
    def update_progress(self, scan_id: str, percentage: int, message: str, stage: str = None):
        """Update scan progress (compatibility method)"""
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            progress = self.active_scans[scan_id]
            progress.percentage = float(percentage)
            progress.current_step = message
            progress.last_update = datetime.now()
            
            # Update stage if provided
            if stage:
                try:
                    new_stage = ScanStage(stage)
                    if progress.stage != new_stage:
                        progress.stage = new_stage
                except ValueError:
                    pass  # Invalid stage value, ignore
            
            self._notify_progress_update(scan_id)
    
    def log_error(self, scan_id: str, message: str, target: str = None, details: Dict = None):
        """Log an error message"""
        stage = self.active_scans.get(scan_id, ScanProgress(scan_id, ScanStage.INITIALIZING, "")).stage
        self.log_message(scan_id, stage, ScanPriority.ERROR, message, target, details)
    
    def log_warning(self, scan_id: str, message: str, target: str = None, details: Dict = None):
        """Log a warning message"""
        stage = self.active_scans.get(scan_id, ScanProgress(scan_id, ScanStage.INITIALIZING, "")).stage
        self.log_message(scan_id, stage, ScanPriority.WARNING, message, target, details)
    
    def log_info(self, scan_id: str, message: str, target: str = None, details: Dict = None):
        """Log an info message"""
        stage = self.active_scans.get(scan_id, ScanProgress(scan_id, ScanStage.INITIALIZING, "")).stage
        self.log_message(scan_id, stage, ScanPriority.INFO, message, target, details)
    
    def complete_scan(self, scan_id: str, success: bool = True, final_message: str = None):
        """Mark a scan as completed"""
        with self._lock:
            if scan_id not in self.active_scans:
                return
            
            progress = self.active_scans[scan_id]
            progress.stage = ScanStage.COMPLETED if success else ScanStage.FAILED
            progress.percentage = 100.0 if success else 0.0
            progress.current_step = final_message or ("Scan completed successfully" if success else "Scan failed")
            progress.last_update = datetime.now()
            progress.estimated_time_remaining = 0
            
            duration = (progress.last_update - progress.start_time).total_seconds()
            
            self.log_message(
                scan_id,
                progress.stage,
                ScanPriority.INFO if success else ScanPriority.ERROR,
                progress.current_step,
                details={
                    "success": success,
                    "total_duration": duration,
                    "total_errors": len(progress.errors),
                    "total_warnings": len(progress.warnings)
                }
            )
            
            self._notify_progress_update(scan_id)
    
    def get_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get current progress for a scan"""
        with self._lock:
            return self.active_scans.get(scan_id)
    
    def get_logs(self, scan_id: str, limit: int = None, priority_filter: List[ScanPriority] = None) -> List[ScanLogEntry]:
        """Get logs for a scan"""
        with self._lock:
            logs = self.scan_logs.get(scan_id, [])
            
            if priority_filter:
                logs = [log for log in logs if log.priority in priority_filter]
            
            if limit:
                logs = logs[-limit:]
            
            return logs
    
    def get_active_scans(self) -> Dict[str, ScanProgress]:
        """Get all active scans"""
        with self._lock:
            return {k: v for k, v in self.active_scans.items() 
                   if v.stage not in [ScanStage.COMPLETED, ScanStage.FAILED]}
    
    def cleanup_completed_scans(self, max_age_hours: int = 24):
        """Clean up old completed scans"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        with self._lock:
            to_remove = []
            for scan_id, progress in self.active_scans.items():
                if (progress.stage in [ScanStage.COMPLETED, ScanStage.FAILED] and 
                    progress.last_update < cutoff_time):
                    to_remove.append(scan_id)
            
            for scan_id in to_remove:
                del self.active_scans[scan_id]
                if scan_id in self.scan_logs:
                    del self.scan_logs[scan_id]
    
    def _update_overall_percentage(self, scan_id: str):
        """Update the overall scan percentage"""
        progress = self.active_scans[scan_id]
        
        # Stage weights for overall progress calculation
        stage_weights = {
            ScanStage.INITIALIZING: 2,
            ScanStage.NETWORK_DISCOVERY: 15,
            ScanStage.HOST_DISCOVERY: 20,
            ScanStage.PORT_SCANNING: 25,
            ScanStage.SERVICE_DETECTION: 15,
            ScanStage.OS_DETECTION: 10,
            ScanStage.VULNERABILITY_SCAN: 8,
            ScanStage.SNMP_DISCOVERY: 3,
            ScanStage.TOPOLOGY_MAPPING: 1,
            ScanStage.DATA_PROCESSING: 1,
            ScanStage.FINALIZING: 0
        }
        
        total_weight = sum(stage_weights.values())
        completed_weight = 0
        
        # Calculate completed stages
        stage_order = list(ScanStage)
        current_stage_index = stage_order.index(progress.stage)
        
        for i, stage in enumerate(stage_order):
            if i < current_stage_index:
                completed_weight += stage_weights.get(stage, 0)
            elif i == current_stage_index:
                # Add partial completion of current stage
                stage_progress = 0
                if progress.total_steps > 0:
                    stage_progress = progress.completed_steps / progress.total_steps
                elif progress.targets_total > 0:
                    stage_progress = progress.targets_completed / progress.targets_total
                
                completed_weight += stage_weights.get(stage, 0) * stage_progress
                break
        
        progress.percentage = min(100.0, (completed_weight / total_weight) * 100)
    
    def _update_time_estimates(self, scan_id: str):
        """Update estimated time remaining"""
        progress = self.active_scans[scan_id]
        
        if progress.percentage > 0:
            elapsed = (progress.last_update - progress.start_time).total_seconds()
            total_estimated = elapsed / (progress.percentage / 100)
            remaining = max(0, total_estimated - elapsed)
            progress.estimated_time_remaining = int(remaining)
    
    def _notify_progress_update(self, scan_id: str):
        """Notify frontend of progress update via WebSocket"""
        logger.debug(f"[TRACKER] _notify_progress_update called for {scan_id}, callback={self.websocket_callback is not None}")
        if self.websocket_callback:
            progress = self.active_scans.get(scan_id)
            if progress:
                try:
                    logger.debug(f"[TRACKER] Converting progress to dict for {scan_id}")
                    # Convert to dict for JSON serialization
                    progress_dict = asdict(progress)
                    progress_dict['start_time'] = progress.start_time.isoformat()
                    progress_dict['last_update'] = progress.last_update.isoformat()
                    progress_dict['stage'] = progress.stage.value
                    
                    logger.debug(f"[TRACKER] Calling websocket_callback for {scan_id}")
                    self.websocket_callback('scan_progress', {
                        'scan_id': scan_id,
                        'progress': progress_dict
                    })
                    logger.debug(f"[TRACKER] websocket_callback completed for {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to send progress update: {e}")

# Global tracker instance
scan_tracker = None

def get_scan_tracker() -> ScanProgressTracker:
    """Get the global scan tracker instance"""
    global scan_tracker
    if scan_tracker is None:
        scan_tracker = ScanProgressTracker()
    return scan_tracker

def set_websocket_callback(callback: Callable):
    """Set the WebSocket callback for progress updates"""
    tracker = get_scan_tracker()
    tracker.websocket_callback = callback
