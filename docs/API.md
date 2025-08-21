# API Documentation

## Base URL
```
Development: http://localhost:5002
Production: http://your-domain:5002
```

## Authentication
Currently, the API does not require authentication. Future versions will implement JWT-based authentication.

## Response Format
All API responses follow this general structure:

### Success Response
```json
{
    "success": true,
    "data": { ... },
    "message": "Operation successful"
}
```

### Error Response
```json
{
    "success": false,
    "error": "Error description",
    "code": "ERROR_CODE"
}
```

## Endpoints

### Health & Status

#### GET /health
Check system health and capabilities.

**Response:**
```json
{
    "status": "healthy",
    "version": "3.0.0-enhanced",
    "database": "connected",
    "features": [
        "enhanced_discovery",
        "snmp_support",
        "topology_mapping",
        "change_tracking",
        "real_time_updates"
    ],
    "statistics": {
        "total_devices": 150,
        "active_devices": 145,
        "total_scans": 25
    }
}
```

#### GET /api/status
Get scanner system status.

**Response:**
```json
{
    "status": "active",
    "version": "4.0.0-netdisco-enhanced",
    "active_scans": 0,
    "available_scanners": ["simple", "enhanced", "job_based", "netdisco"],
    "default_scanner": "auto",
    "features": {
        "snmp_discovery": true,
        "topology_mapping": true,
        "change_detection": true,
        "device_classification": true,
        "vulnerability_scanning": true,
        "real_time_updates": true
    }
}
```

### Scanning Operations

#### POST /api/scan/start
Initiate a network scan.

**Request Body:**
```json
{
    "subnet": "192.168.1.0/24",  // or "auto" for automatic detection
    "aggressive": false,
    "deep_scan": false,
    "vulnerability_scan": false,
    "snmp_communities": ["public"],
    "topology_discovery": false,
    "scanner_type": "simple",  // "simple", "enhanced", "job_based", or "auto"
    "scan_mode": "smart"  // "smart", "thorough", or "full"
}
```

**Response:**
```json
{
    "success": true,
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "message": "Scan initiated",
    "config": {
        "subnet": "192.168.1.0/24",
        "scanner_type": "simple",
        "scan_mode": "smart"
    }
}
```

#### GET /api/scan/{scan_id}/status
Get current scan status.

**Response:**
```json
{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "running",
    "config": { ... },
    "devices_found": 25,
    "summary": {
        "total_hosts": 254,
        "scanned_hosts": 100,
        "active_hosts": 25
    },
    "start_time": "2025-01-21T10:30:00Z",
    "active": true
}
```

#### GET /api/scan/{scan_id}/results
Get scan results.

**Response:**
```json
{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "devices": [
        {
            "ip": "192.168.1.1",
            "hostname": "router.local",
            "device_type": "router",
            "vendor": "Cisco",
            "ports": [22, 80, 443]
        }
    ],
    "summary": {
        "total_hosts": 254,
        "active_hosts": 45,
        "scan_duration": 120.5
    }
}
```

#### GET /api/scan/{scan_id}/logs
Get detailed scan logs.

**Query Parameters:**
- `limit` (int): Maximum number of logs to return (default: 100)
- `priority` (string): Filter by priority (info, warning, error)

**Response:**
```json
{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "logs": [
        {
            "timestamp": "2025-01-21T10:30:00Z",
            "stage": "scanning",
            "priority": "info",
            "message": "Scanning host 192.168.1.1",
            "target": "192.168.1.1",
            "duration": 0.5
        }
    ],
    "total_logs": 150
}
```

#### GET /api/scans/active
Get all active scans.

**Response:**
```json
{
    "active_scans": {
        "550e8400-e29b-41d4-a716-446655440000": {
            "status": "running",
            "progress": 45,
            "subnet": "192.168.1.0/24",
            "start_time": "2025-01-21T10:30:00Z"
        }
    },
    "total_active": 1
}
```

### Device Inventory

#### GET /api/devices
Get device inventory with pagination and filtering.

**Query Parameters:**
- `search` (string): Search term for filtering
- `type` (string): Filter by device type
- `status` (string): Filter by status (active, inactive, all)
- `page` (int): Page number (default: 1)
- `per_page` (int): Items per page (default: 50)

**Response:**
```json
{
    "devices": [
        {
            "id": 1,
            "ip": "192.168.1.1",
            "hostname": "router.local",
            "mac_address": "00:11:22:33:44:55",
            "vendor": "Cisco",
            "device_type": "router",
            "status": "active",
            "first_seen": "2025-01-15T08:00:00Z",
            "last_seen": "2025-01-21T10:30:00Z",
            "ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "state": "open"
                }
            ]
        }
    ],
    "total": 150,
    "page": 1,
    "per_page": 50
}
```

#### GET /api/devices/{device_ip}
Get detailed information about a specific device.

**Response:**
```json
{
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "mac_address": "00:11:22:33:44:55",
    "vendor": "Cisco",
    "model": "ASA 5505",
    "os": "Cisco IOS",
    "os_version": "15.2(4)M10",
    "device_type": "router",
    "status": "active",
    "location": "Server Room A",
    "department": "IT Infrastructure",
    "owner": "Network Team",
    "first_seen": "2025-01-15T08:00:00Z",
    "last_seen": "2025-01-21T10:30:00Z",
    "uptime": 864000,
    "ports": [ ... ],
    "interfaces": [ ... ],
    "neighbors": [ ... ],
    "changes": [ ... ],
    "vulnerabilities": [ ... ]
}
```

#### GET /api/devices/{device_ip}/history
Get device change history.

**Query Parameters:**
- `days` (int): Number of days of history (default: 30)

**Response:**
```json
[
    {
        "change_id": "ch_001",
        "change_type": "new_port",
        "old_value": null,
        "new_value": "8080",
        "timestamp": "2025-01-20T14:30:00Z",
        "scan_id": "550e8400-e29b-41d4-a716-446655440000"
    }
]
```

### Statistics & Analytics

#### GET /api/statistics
Get network statistics.

**Response:**
```json
{
    "total_hosts": 150,
    "active_hosts": 145,
    "total_devices": 150,
    "active_devices": 145,
    "device_breakdown": {
        "router": 5,
        "switch": 10,
        "server": 30,
        "workstation": 100,
        "unknown": 5
    },
    "critical_vulnerabilities": 2,
    "high_vulnerabilities": 8,
    "medium_vulnerabilities": 15,
    "low_vulnerabilities": 30,
    "recent_changes_24h": 12,
    "port_statistics": {
        "high_risk_ports": 3,
        "total_open_ports": 450,
        "web_services": 25
    },
    "last_scan": "2025-01-21T10:30:00Z",
    "uptime_percentage": 99.5
}
```

#### GET /api/statistics/enhanced
Get comprehensive network statistics.

**Response:**
```json
{
    "total_devices": 150,
    "active_devices": 145,
    "inactive_devices": 5,
    "new_devices_24h": 3,
    "disappeared_devices_24h": 1,
    "total_ports": 450,
    "high_risk_ports": 3,
    "total_vulnerabilities": 55,
    "vulnerability_breakdown": {
        "critical": 2,
        "high": 8,
        "medium": 15,
        "low": 30
    },
    "topology_nodes": 150,
    "topology_links": 280,
    "compliance_rate": 92.5,
    "security_score": 85.0,
    "active_scans": 0,
    "last_scan_time": "2025-01-21T10:30:00Z",
    "system_uptime": 864000
}
```

### Security & Vulnerabilities

#### GET /api/vulnerabilities
Get vulnerability information.

**Query Parameters:**
- `severity` (string): Filter by severity (critical, high, medium, low, all)
- `host` (string): Filter by specific host IP

**Response:**
```json
[
    {
        "id": "vuln_001",
        "device_ip": "192.168.1.50",
        "cve_id": "CVE-2021-44228",
        "severity": "critical",
        "description": "Log4j Remote Code Execution",
        "affected_service": "Apache Log4j",
        "port": 8080,
        "discovered_at": "2025-01-20T10:00:00Z",
        "remediation": "Update Log4j to version 2.17.0 or later"
    }
]
```

#### GET /api/alerts
Get security alerts.

**Query Parameters:**
- `severity` (string): Filter by severity

**Response:**
```json
[
    {
        "id": "alert_001",
        "type": "high_risk_port",
        "severity": "warning",
        "title": "High-Risk Service Detected",
        "description": "Telnet service detected on 192.168.1.100:23",
        "timestamp": "2025-01-21T09:00:00Z",
        "device_ip": "192.168.1.100",
        "recommendation": "Consider disabling Telnet and using SSH instead"
    }
]
```

### Network Topology

#### GET /api/topology
Get network topology data.

**Response:**
```json
{
    "nodes": [
        {
            "id": "192.168.1.1",
            "label": "router.local",
            "type": "router",
            "x": 0,
            "y": 0,
            "connections": 45
        }
    ],
    "edges": [
        {
            "source": "192.168.1.1",
            "target": "192.168.1.10",
            "type": "ethernet",
            "bandwidth": 1000
        }
    ]
}
```

### Changes & Events

#### GET /api/changes
Get recent network changes.

**Query Parameters:**
- `hours` (int): Number of hours to look back (default: 24)
- `type` (string): Filter by change type

**Response:**
```json
[
    {
        "id": "change_001",
        "device_ip": "192.168.1.100",
        "change_type": "new_device",
        "description": "New device discovered",
        "timestamp": "2025-01-21T08:00:00Z",
        "severity": "info"
    }
]
```

### Scanner Information

#### GET /api/scanners/available
Get available scanner types and capabilities.

**Response:**
```json
{
    "available_scanners": {
        "simple": {
            "name": "Simple Scanner",
            "description": "Basic ping sweep and hostname resolution",
            "features": ["ping_sweep", "hostname_resolution"],
            "recommended_for": "Small networks (<64 hosts)",
            "performance": "Fast"
        },
        "enhanced": {
            "name": "Enhanced Scanner",
            "description": "Multi-method discovery with port scanning",
            "features": ["multi_method_discovery", "nmap_scanning", "basic_snmp"],
            "recommended_for": "Medium networks (64-256 hosts)",
            "performance": "Medium"
        }
    },
    "default_scanner": "auto"
}
```

#### GET /api/scanners/capabilities
Get detailed scanner capabilities.

**Response:**
```json
{
    "system_capabilities": {
        "discovery_methods": ["icmp", "tcp", "udp", "snmp", "arp"],
        "service_detection": true,
        "os_fingerprinting": true,
        "vulnerability_scanning": true,
        "topology_mapping": true
    },
    "supported_protocols": ["icmp", "tcp", "udp", "snmp_v1", "snmp_v2c"],
    "device_types": ["router", "switch", "server", "workstation", "printer"],
    "job_types": ["discover", "macsuck", "arpnip", "topology"],
    "data_continuity": {
        "historical_tracking": true,
        "change_detection": true,
        "audit_trail": true
    }
}
```

### Reports & Export

#### POST /api/reports/generate
Generate a network report.

**Request Body:**
```json
{
    "type": "summary",  // "summary", "detailed", "vulnerability", "compliance"
    "format": "json",   // "json", "csv", "pdf"
    "scan_id": "optional_scan_id"
}
```

**Response:**
```json
{
    "type": "summary",
    "generated_at": "2025-01-21T10:30:00Z",
    "summary": { ... },
    "devices": [ ... ],
    "vulnerabilities": [ ... ]
}
```

#### POST /api/export/devices
Export device inventory.

**Request Body:**
```json
{
    "format": "csv",  // "csv", "json", "xml"
    "filters": {
        "status": "active",
        "device_type": "server"
    }
}
```

**Response:**
```json
{
    "success": true,
    "filename": "devices_export_20250121.csv",
    "download_url": "/api/download/devices_export_20250121.csv"
}
```

### Database Management

#### POST /api/database/clear
Clear all database data (use with caution).

**Response:**
```json
{
    "success": true,
    "message": "Database cleared successfully"
}
```

### Network Summary

#### GET /api/network/summary
Get network overview summary.

**Response:**
```json
{
    "total_devices": 150,
    "total_vulnerabilities": 55,
    "open_ports": 450,
    "last_scan": "2025-01-21T10:30:00Z",
    "device_types": {
        "router": 5,
        "switch": 10,
        "server": 30,
        "workstation": 100
    },
    "risk_distribution": {
        "high": 10,
        "medium": 30,
        "low": 110
    }
}
```

## WebSocket Events

### Connection
```javascript
const socket = io('http://localhost:5002');

socket.on('connect', () => {
    console.log('Connected to server');
});
```

### Subscribe to Updates
```javascript
socket.emit('subscribe_updates', {
    type: 'all'  // or specific types
});
```

### Listen for Events

#### scan_started
```javascript
socket.on('scan_started', (data) => {
    // data.scan_id
    // data.config
    // data.subnet
});
```

#### scan_progress
```javascript
socket.on('scan_progress', (data) => {
    // data.scan_id
    // data.progress (0-100)
    // data.message
    // data.stage
});
```

#### device_discovered
```javascript
socket.on('device_discovered', (device) => {
    // device.ip
    // device.hostname
    // device.device_type
});
```

#### scan_completed
```javascript
socket.on('scan_completed', (results) => {
    // results.scan_id
    // results.success
    // results.devices_found
    // results.summary
});
```

#### network_alert
```javascript
socket.on('network_alert', (alert) => {
    // alert.type
    // alert.severity
    // alert.message
});
```

#### stats_update
```javascript
socket.on('stats_update', (stats) => {
    // Periodic statistics updates
});
```

## Error Codes

| Code | Description |
|------|-------------|
| `INVALID_SUBNET` | Invalid subnet format |
| `SCAN_IN_PROGRESS` | Another scan is already running |
| `DEVICE_NOT_FOUND` | Specified device not found |
| `DATABASE_ERROR` | Database operation failed |
| `SCANNER_ERROR` | Scanning operation failed |
| `PERMISSION_DENIED` | Insufficient privileges |
| `INVALID_PARAMS` | Invalid request parameters |
| `TIMEOUT` | Operation timed out |

## Rate Limiting

API endpoints have the following rate limits:
- Scan initiation: 1 per minute
- Device queries: 100 per minute
- Statistics: 60 per minute
- WebSocket messages: 100 per minute

## Best Practices

1. **Pagination**: Always use pagination for large result sets
2. **Filtering**: Use query parameters to filter results
3. **WebSocket**: Subscribe to WebSocket for real-time updates
4. **Error Handling**: Implement proper error handling for all API calls
5. **Timeouts**: Set appropriate timeouts for API requests
6. **Caching**: Cache frequently accessed data on the client side

## Examples

### Starting a Quick Scan
```javascript
async function quickScan() {
    const response = await fetch('http://localhost:5002/api/scan/start', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            subnet: 'auto',
            scanner_type: 'simple'
        })
    });
    
    const result = await response.json();
    console.log('Scan started:', result.scan_id);
}
```

### Monitoring Scan Progress
```javascript
socket.on('scan_progress', (data) => {
    updateProgressBar(data.progress);
    updateStatusMessage(data.message);
    
    if (data.progress === 100) {
        loadScanResults(data.scan_id);
    }
});
```

### Getting Device Details
```javascript
async function getDeviceInfo(ip) {
    const response = await fetch(`http://localhost:5002/api/devices/${ip}`);
    const device = await response.json();
    
    displayDeviceDetails(device);
    displayOpenPorts(device.ports);
    displayVulnerabilities(device.vulnerabilities);
}
```