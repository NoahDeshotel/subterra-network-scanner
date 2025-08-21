# System Architecture Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Network Scanning Pipeline](#network-scanning-pipeline)
5. [Database Design](#database-design)
6. [WebSocket Communication](#websocket-communication)
7. [Security Architecture](#security-architecture)
8. [Deployment Architecture](#deployment-architecture)

## System Overview

NetScope Pro follows a modern microservices architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────┐
│                   User Interface                     │
│                  (Web Browser)                       │
└────────────────────┬───────────────┬────────────────┘
                     │               │
                   HTTP            WebSocket
                     │               │
┌────────────────────▼───────────────▼────────────────┐
│                 Frontend Service                     │
│               (Nginx + Static Files)                 │
│                    Port 80                          │
└────────────────────┬───────────────┬────────────────┘
                     │               │
                 REST API       WebSocket
                     │               │
┌────────────────────▼───────────────▼────────────────┐
│                 Backend Service                      │
│              (Flask + SocketIO)                      │
│                   Port 5002                         │
├──────────────────────────────────────────────────────┤
│  • API Routes        • WebSocket Handler            │
│  • Scan Manager      • Inventory Manager            │
│  • Scanner Engine    • Progress Tracker             │
└────────────────────┬─────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────┐
│                   Data Layer                         │
│                (SQLite Database)                     │
│              enhanced_inventory.db                   │
└──────────────────────────────────────────────────────┘
```

## Component Architecture

### Backend Service Components

#### 1. Main Application (app.py)
- **Responsibilities**:
  - Flask application initialization
  - WebSocket server setup
  - Route registration
  - Global state management
  - Background task coordination

- **Key Classes**:
  - `ScanManager`: Orchestrates scanning operations
  - `EnhancedInventoryManager`: Database operations
  - `ScanProgressTracker`: Progress monitoring

#### 2. Scanner Module Structure

```
scanner/
├── main_scanner.py         # Core scanning orchestrator
├── advanced_scanner.py     # Enhanced scanning capabilities
├── subnet_scanner.py       # Large network handling
├── enhanced_discovery.py   # Discovery algorithms
├── enhanced_inventory.py   # Database management
├── scan_progress_tracker.py # Progress monitoring
└── scanner_capabilities.py # Feature detection
```

**Scanner Hierarchy**:
```
BaseScanner
    ├── SimpleScanner (ICMP + basic ports)
    ├── AdvancedScanner (Nmap integration)
    └── JobBasedScanner (Netdisco-style)
```

#### 3. API Module Structure

```
api/
├── routes.py           # REST endpoint definitions
└── websocket_handler.py # WebSocket event handlers
```

### Frontend Service Components

#### 1. Core Application (app.js)
- WebSocket connection management
- View routing and state management
- API communication layer
- Event handling system

#### 2. Dashboard Module (dashboard.js)
- Real-time statistics display
- Chart rendering (Chart.js)
- Device grid management
- Alert notifications

#### 3. Visualization Module (visualization.js)
- 3D network topology (Three.js)
- Force-directed graphs
- Device relationship mapping
- Interactive network explorer

## Data Flow

### Scan Initiation Flow

```
1. User triggers scan
    ↓
2. Frontend POST /api/scan/start
    ↓
3. Backend creates scan_id
    ↓
4. Backend spawns scan thread
    ↓
5. Immediate response to frontend
    ↓
6. WebSocket updates begin
```

### Real-time Update Flow

```
Scan Thread → Progress Update → WebSocket Emit → Frontend Update
     ↓              ↓                               ↓
Database    Progress Tracker                   UI Refresh
```

### Device Discovery Flow

```
1. IP Range Calculation
    ↓
2. Subnet Chunking (for large networks)
    ↓
3. Concurrent Host Scanning
    ├── ICMP Ping
    ├── TCP Port Scan
    ├── UDP Discovery
    └── SNMP Query
    ↓
4. Service Fingerprinting
    ↓
5. Device Classification
    ↓
6. Database Storage
    ↓
7. Change Detection
    ↓
8. WebSocket Notification
```

## Network Scanning Pipeline

### Phase 1: Network Preparation
```python
def prepare_network_scan(subnet):
    # Parse subnet
    network = ipaddress.ip_network(subnet)
    
    # Determine scan strategy
    if network.num_addresses > 65536:  # /16 or larger
        return chunk_large_network(network)
    elif network.num_addresses > 256:   # /24 to /16
        return optimized_scan_strategy(network)
    else:
        return standard_scan_strategy(network)
```

### Phase 2: Discovery Methods

1. **ICMP Discovery**
   - Ping sweep for responsive hosts
   - Fallback to TCP if ICMP blocked

2. **TCP Discovery**
   - SYN scan on common ports
   - Full connect scan as fallback
   - Service banner grabbing

3. **UDP Discovery**
   - SNMP (161)
   - DNS (53)
   - DHCP (67/68)
   - NTP (123)

4. **SNMP Discovery**
   - System information
   - Interface details
   - ARP tables
   - MAC addresses
   - Neighbor relationships

### Phase 3: Enrichment

```
Raw Discovery Data
    ↓
Port/Service Mapping
    ↓
OS Fingerprinting
    ↓
Vendor Identification
    ↓
Device Classification
    ↓
Vulnerability Matching
    ↓
Enriched Device Object
```

### Phase 4: Persistence

```python
async def persist_device(device_data):
    # Generate fingerprint
    fingerprint = DeviceFingerprint.from_device(device_data)
    
    # Check for existing device
    existing = await get_device_by_ip(device_data['ip'])
    
    if existing:
        # Detect changes
        changes = compare_fingerprints(existing.fingerprint, fingerprint)
        
        # Update device
        await update_device(device_data, changes)
        
        # Record changes
        await record_device_changes(changes)
    else:
        # New device
        await create_device(device_data)
        await record_new_device_event(device_data)
```

## Database Design

### Core Tables

#### devices
```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    ip TEXT UNIQUE NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    vendor TEXT,
    os TEXT,
    device_type TEXT,
    status TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    fingerprint_hash TEXT,
    -- Extended fields for inventory
    location TEXT,
    department TEXT,
    owner TEXT,
    criticality_level TEXT,
    notes TEXT
);
```

#### device_ports
```sql
CREATE TABLE device_ports (
    id INTEGER PRIMARY KEY,
    device_id INTEGER,
    port_number INTEGER,
    protocol TEXT,
    state TEXT,
    service_name TEXT,
    service_version TEXT,
    risk_level TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
```

#### device_changes
```sql
CREATE TABLE device_changes (
    id INTEGER PRIMARY KEY,
    device_id INTEGER,
    change_type TEXT,
    old_value TEXT,
    new_value TEXT,
    timestamp TIMESTAMP,
    scan_id TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);
```

### Relationships

```
devices (1) ──────< (N) device_ports
   │
   ├────< (N) device_changes
   │
   ├────< (N) device_interfaces
   │
   ├────< (N) vulnerabilities
   │
   └────< (N) device_neighbors
```

### Indexing Strategy

```sql
CREATE INDEX idx_devices_ip ON devices(ip);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_ports_device ON device_ports(device_id);
CREATE INDEX idx_changes_device ON device_changes(device_id);
CREATE INDEX idx_changes_timestamp ON device_changes(timestamp);
```

## WebSocket Communication

### Event Types

#### Client → Server
- `connect`: Initial connection
- `subscribe_updates`: Subscribe to specific events
- `request_scan_status`: Get scan progress
- `cancel_scan`: Abort running scan

#### Server → Client
- `scan_started`: Scan initiated
- `scan_progress`: Progress update
- `device_discovered`: New device found
- `scan_completed`: Scan finished
- `network_alert`: Security alert
- `stats_update`: Statistics refresh

### Message Format

```json
{
    "event": "scan_progress",
    "data": {
        "scan_id": "uuid",
        "progress": 45,
        "stage": "scanning",
        "message": "Scanning 192.168.1.0/24",
        "devices_found": 23,
        "timestamp": "2025-01-21T10:30:00Z"
    }
}
```

### Connection Management

```python
class WebSocketManager:
    def __init__(self):
        self.connections = {}
        self.subscriptions = defaultdict(set)
    
    def handle_connect(self, sid):
        self.connections[sid] = {
            'connected_at': datetime.now(),
            'subscriptions': set()
        }
    
    def handle_disconnect(self, sid):
        # Clean up subscriptions
        for event in self.subscriptions:
            self.subscriptions[event].discard(sid)
        del self.connections[sid]
    
    def broadcast(self, event, data, room=None):
        # Send to all or specific room
        socketio.emit(event, data, room=room)
```

## Security Architecture

### Network Isolation

```
Docker Network
    ├── Backend Container (privileged for raw sockets)
    ├── Frontend Container (restricted)
    └── Redis Container (internal only)
```

### Authentication & Authorization

Currently basic, planned enhancements:
- JWT token authentication
- Role-based access control
- API key management
- Audit logging

### Security Measures

1. **Input Validation**
   - Subnet format validation
   - Parameter sanitization
   - SQL injection prevention

2. **Rate Limiting**
   - Scan initiation throttling
   - API request limits
   - WebSocket message limits

3. **Privilege Management**
   - Minimal container privileges
   - Read-only volume mounts where possible
   - Non-root user execution (planned)

## Deployment Architecture

### Docker Composition

```yaml
services:
  backend:
    build: ./backend
    privileged: true  # Required for raw sockets
    networks:
      - scanner-net
    volumes:
      - ./data:/app/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5002/health"]
  
  frontend:
    build: ./frontend
    networks:
      - scanner-net
    depends_on:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
  
  redis:
    image: redis:alpine
    networks:
      - scanner-net
    volumes:
      - redis-data:/data

networks:
  scanner-net:
    driver: bridge

volumes:
  redis-data:
```

### Scaling Considerations

#### Horizontal Scaling (Future)
```
Load Balancer
    ├── Frontend Instance 1
    ├── Frontend Instance 2
    └── Frontend Instance N
    
API Gateway
    ├── Backend Instance 1 (Scanner Node)
    ├── Backend Instance 2 (Scanner Node)
    └── Backend Instance N (Scanner Node)
    
Shared Database
    └── PostgreSQL Cluster
```

#### Vertical Scaling
- Increase thread pool size for scanning
- Adjust memory limits for large networks
- Optimize database connection pooling

### Performance Optimizations

1. **Scanning Optimization**
   - Concurrent thread pools
   - Intelligent subnet chunking
   - Adaptive timeout adjustment
   - Result caching

2. **Database Optimization**
   - Connection pooling
   - Query optimization
   - Index management
   - Periodic vacuum

3. **Frontend Optimization**
   - Lazy loading
   - Virtual scrolling
   - WebSocket message batching
   - Client-side caching

### Monitoring Points

- Scanner thread health
- Database query performance
- WebSocket connection count
- Memory usage trends
- Network I/O patterns
- Error rates and types

## Configuration Management

### Environment Variables

```bash
# Core Settings
FLASK_ENV=production
SECRET_KEY=<secure-key>
DATABASE_PATH=/app/data/inventory.db

# Network Settings
HOST_SUBNET=192.168.1.0/24
SCAN_INTERVAL=3600
MAX_THREADS=50

# Feature Flags
ENABLE_SNMP=true
ENABLE_VULNERABILITY_SCAN=false
ENABLE_TOPOLOGY_MAPPING=true
```

### Configuration Hierarchy

```
1. Environment Variables (Highest Priority)
2. Configuration Files
3. Database Settings
4. Default Values (Lowest Priority)
```

## Error Handling Strategy

### Error Categories

1. **Recoverable Errors**
   - Network timeouts → Retry with backoff
   - Database locks → Queue and retry
   - Service unavailable → Fallback method

2. **Non-Recoverable Errors**
   - Invalid subnet format → User notification
   - Insufficient privileges → Error response
   - Database corruption → Alert and halt

### Error Flow

```
Error Occurs
    ↓
Categorize Error
    ↓
Log with Context
    ↓
Determine Recovery Strategy
    ├── Retry with Backoff
    ├── Fallback Method
    ├── Queue for Later
    └── Notify User
    ↓
Update Monitoring Metrics
```

## Future Architecture Considerations

1. **Microservices Decomposition**
   - Separate scanning service
   - Independent inventory service
   - Dedicated notification service

2. **Message Queue Integration**
   - RabbitMQ/Kafka for job queuing
   - Async processing pipeline
   - Event sourcing pattern

3. **Cloud Native Migration**
   - Kubernetes deployment
   - Service mesh integration
   - Cloud provider services

4. **Advanced Features**
   - Machine learning pipeline
   - Predictive analytics
   - Automated remediation