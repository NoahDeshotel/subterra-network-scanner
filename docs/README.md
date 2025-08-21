# NetScope Pro - Network Intelligence Platform

## Overview

NetScope Pro is an advanced network scanning and inventory management system designed for comprehensive network discovery, monitoring, and security analysis. Built with a modern microservices architecture, it provides real-time network intelligence through an intuitive web interface.

## Key Features

### Network Discovery
- **Multi-Protocol Scanning**: Supports ICMP, TCP, UDP, SNMP, and Nmap-based discovery
- **Intelligent Subnet Detection**: Automatically detects and scans network segments
- **Large Network Support**: Optimized scanning for /16 networks with smart chunking
- **Device Classification**: Automatic categorization based on open ports and services
- **Hostname Resolution**: DNS and NetBIOS name resolution

### Inventory Management
- **Comprehensive Device Tracking**: Maintains detailed device inventory with historical data
- **Change Detection**: Tracks changes in device status, services, and configurations
- **Device Lifecycle Management**: Monitors device appearance, disappearance, and returns
- **Custom Metadata**: Support for tags, notes, department, owner, and asset information
- **Export Capabilities**: CSV export for reporting and analysis

### Security Features
- **Vulnerability Detection**: Identifies potential security risks and CVEs
- **Port Risk Analysis**: Categorizes ports by risk level
- **Security Alerts**: Real-time alerts for high-risk services and new devices
- **Compliance Tracking**: Monitor device compliance status
- **Audit Trail**: Complete history of all network changes

### Real-Time Monitoring
- **WebSocket Updates**: Live progress updates during scans
- **Event-Driven Architecture**: Instant notifications for network events
- **Active Scan Tracking**: Monitor multiple concurrent scans
- **Performance Metrics**: Real-time statistics and network health

### Advanced Capabilities
- **SNMP Discovery**: Collect device details via SNMP v1/v2c/v3
- **Topology Mapping**: Build network topology from discovered relationships
- **MAC Address Collection**: ARP and switch MAC table harvesting
- **VLAN Detection**: Identify VLAN configurations
- **Service Fingerprinting**: Detailed service identification and versioning

## Technology Stack

### Backend
- **Python 3.x**: Core backend language
- **Flask**: RESTful API framework
- **Flask-SocketIO**: WebSocket support for real-time updates
- **SQLite**: Local database for inventory storage
- **Threading**: Concurrent scanning with thread pools
- **Nmap**: Advanced port scanning and service detection
- **python-nmap**: Python wrapper for Nmap integration

### Frontend
- **Vanilla JavaScript**: Modern ES6+ JavaScript
- **Socket.IO Client**: Real-time WebSocket communication
- **Chart.js**: Data visualization and charts
- **Three.js**: 3D network topology visualization
- **CSS3**: Modern styling with animations
- **Responsive Design**: Mobile-friendly interface

### Infrastructure
- **Docker**: Containerized deployment
- **Docker Compose**: Multi-container orchestration
- **Nginx**: Frontend web server
- **Redis**: Optional caching layer
- **Health Checks**: Built-in health monitoring

## System Architecture

The system follows a microservices architecture with three main components:

1. **Backend Service** (Port 5002)
   - RESTful API endpoints
   - WebSocket server
   - Scanning engine
   - Database management

2. **Frontend Service** (Port 80)
   - Static web application
   - Real-time dashboard
   - Interactive visualizations
   - Device management interface

3. **Data Layer**
   - SQLite database
   - Persistent volume storage
   - Scan results archive

## Project Structure

```
philadelphia/
├── backend/                 # Backend application
│   ├── app.py              # Main Flask application
│   ├── api/                # API routes and handlers
│   │   ├── routes.py       # REST API endpoints
│   │   └── websocket_handler.py
│   ├── scanner/            # Scanning modules
│   │   ├── main_scanner.py       # Core scanning logic
│   │   ├── advanced_scanner.py   # Enhanced scanning
│   │   ├── subnet_scanner.py     # Large network handling
│   │   ├── enhanced_discovery.py # Discovery engine
│   │   └── enhanced_inventory.py # Inventory management
│   └── utils/              # Utility modules
├── frontend/               # Frontend application
│   ├── src/               # JavaScript source
│   │   ├── app.js         # Main application
│   │   ├── dashboard.js   # Dashboard logic
│   │   └── visualization.js # Network visualizations
│   ├── index.html         # Main HTML page
│   └── nginx.conf         # Web server config
├── data/                  # Persistent data
│   └── enhanced_inventory.db # SQLite database
├── docs/                  # Documentation
├── docker-compose.yml     # Container orchestration
└── start.sh              # Startup script
```

## Database Schema

The system uses a comprehensive SQLite database with the following main tables:

- **devices**: Core device inventory
- **device_ports**: Open ports and services
- **device_interfaces**: Network interfaces (SNMP)
- **device_neighbors**: Network topology
- **device_changes**: Change history
- **scan_metadata**: Scan information
- **scan_jobs**: Job queue for scanning
- **vulnerabilities**: Security findings

## Scanner Types

The system supports multiple scanner types optimized for different scenarios:

1. **Simple Scanner**: Fast ping sweep with basic port checking
2. **Enhanced Scanner**: Multi-method discovery with service detection
3. **Job-Based Scanner**: Netdisco-inspired comprehensive scanning
4. **Subnet Scanner**: Optimized for large network segments

## API Overview

The backend provides a comprehensive REST API:

- `/health` - System health check
- `/api/status` - Scanner status
- `/api/scan/start` - Initiate network scan
- `/api/devices` - Device inventory
- `/api/statistics` - Network statistics
- `/api/vulnerabilities` - Security findings
- `/api/topology` - Network topology data
- `/api/alerts` - Security alerts

See [API.md](API.md) for complete documentation.

## Security Considerations

- Runs in privileged mode for raw socket access
- Supports environment-based configuration
- Secure WebSocket connections
- Input validation on all endpoints
- Rate limiting on scan initiation
- Audit logging for all operations

## Performance Optimization

- Concurrent scanning with thread pools
- Smart subnet chunking for large networks
- Caching of DNS and service lookups
- Database indexing for fast queries
- Lazy loading of device details
- WebSocket message batching

## Monitoring and Logging

- Comprehensive logging at all levels
- Scan progress tracking
- Performance metrics collection
- Error tracking and reporting
- WebSocket connection monitoring
- Database query optimization logs

## Future Enhancements

- SNMP v3 support
- IPv6 network scanning
- Cloud provider integration
- Machine learning for anomaly detection
- Custom plugin system
- Mobile application
- Distributed scanning nodes
- PostgreSQL support

## License

This is a proprietary network security tool designed for authorized network administration and security assessment purposes only.

## Support

For issues, questions, or contributions, please refer to the [DEVELOPMENT.md](DEVELOPMENT.md) guide.