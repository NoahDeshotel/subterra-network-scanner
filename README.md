# Dockerized Network Scanner & Visualization System

## 🚀 Enterprise-Grade Network Security Scanner

A comprehensive, dockerized network scanning and visualization system with real-time 3D network mapping, vulnerability analysis, and inventory management.

![Network Scanner](https://img.shields.io/badge/Version-2.0-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-green.svg)
![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6-yellow.svg)

## ✨ Features

### 🔍 Network Discovery & Scanning
- **Automated Host Discovery**: Intelligent subnet detection and comprehensive host enumeration
- **Port Scanning**: TCP/UDP port scanning with service detection
- **OS Fingerprinting**: Operating system detection and version identification
- **Vulnerability Assessment**: CVE detection with CVSS scoring
- **Service Enumeration**: Detailed service and version detection

### 📊 Advanced Visualization
- **3D Network Mapping**: Interactive Three.js-powered network topology
- **Real-time Updates**: Live scanning progress with WebSocket communication
- **Multiple View Modes**: Sphere, Force-directed, Tree, and Galaxy layouts
- **Risk-based Coloring**: Visual risk assessment with color-coded nodes
- **Interactive Details**: Click nodes for detailed host information

### 💾 Inventory Management
- **Persistent Storage**: SQLite database with comprehensive scan history
- **Change Tracking**: Monitor network changes between scans
- **Search & Filter**: Advanced filtering and search capabilities
- **Export Options**: CSV, PDF, and JSON export formats
- **Historical Analysis**: Track network evolution over time

### 🛡️ Security Features
- **JWT Authentication**: Secure API access with token-based auth
- **Rate Limiting**: API protection against abuse
- **Input Validation**: Sanitized inputs to prevent injection attacks
- **CORS Protection**: Cross-origin request security
- **SSL/TLS Support**: HTTPS encryption (certificates required)

### 📈 Reporting & Analytics
- **Executive Reports**: High-level security summaries
- **Technical Reports**: Detailed vulnerability assessments
- **Compliance Reports**: Regulatory compliance tracking
- **Risk Prioritization**: Smart vulnerability remediation priorities
- **Trend Analysis**: Historical security trend visualization

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Database      │
│   (Nginx)       │    │   (Flask)       │    │   (SQLite)      │
│                 │    │                 │    │                 │
│ • 3D Viz        │◄──►│ • API           │◄──►│ • Scans         │
│ • Dashboard     │    │ • Scanner       │    │ • Hosts         │
│ • Reports       │    │ • WebSockets    │    │ • Vulns         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │   Redis         │              │
         └──────────────│   (Cache)       │──────────────┘
                        │                 │
                        │ • Sessions      │
                        │ • Cache         │
                        └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- 8GB+ RAM (recommended)
- Network access to target subnets
- Linux/macOS (Windows with WSL2)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd network-scanner
   ```

2. **Configure environment**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

3. **Start the application**
   ```bash
   docker-compose up -d
   ```

4. **Access the web interface**
   ```
   http://localhost:80
   ```

### First Scan

1. Click "Start Scan" in the dashboard
2. Configure scan parameters:
   - **Subnet**: Auto-detect or specify (e.g., 192.168.1.0/24)
   - **Aggressive**: Enable for comprehensive scanning
   - **Vulnerabilities**: Include CVE detection
3. Monitor real-time progress
4. Explore results in 3D visualization

## 📋 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | - | Flask secret key (change this!) |
| `SCAN_INTERVAL` | `3600` | Automated scan interval (seconds) |
| `REDIS_URL` | `redis://redis:6379/0` | Redis connection URL |
| `JWT_SECRET` | - | JWT signing secret |
| `ADMIN_PASSWORD` | - | Admin user password |

### Scan Configuration

```yaml
# docker-compose.yml
services:
  backend:
    environment:
      - SCAN_INTERVAL=3600        # Scan every hour
      - AGGRESSIVE_SCAN=false     # Conservative scanning
      - ENABLE_VULNS=true         # Vulnerability detection
```

## 🔧 API Reference

### Authentication
```bash
# Login
POST /api/auth/login
{
  "username": "admin",
  "password": "your-password"
}

# Use token in headers
Authorization: Bearer <jwt-token>
```

### Scanning
```bash
# Start scan
POST /api/scan/start
{
  "subnet": "192.168.1.0/24",
  "aggressive": false
}

# Get scan status
GET /api/scan/status
```

### Inventory
```bash
# Get all hosts
GET /api/inventory?page=1&per_page=50&search=192.168

# Get host details
GET /api/inventory/{ip}

# Get vulnerabilities
GET /api/vulnerabilities?severity=critical
```

### Reports
```bash
# Generate report
POST /api/reports/generate
{
  "type": "executive",
  "format": "pdf"
}

# Export data
GET /api/export/csv?scan_id=20240101_120000
```

## 🎨 3D Visualization

### View Modes

- **Sphere**: Hosts arranged in 3D sphere
- **Force**: Physics-based node positioning
- **Tree**: Hierarchical tree structure
- **Galaxy**: Spiral galaxy layout

### Interactions

- **Mouse**: Rotate and zoom camera
- **Click**: Select nodes for details
- **Filter**: Show only critical vulnerabilities
- **Labels**: Toggle hostname labels

### Color Coding

| Color | Risk Level | CVSS Score |
|-------|------------|------------|
| 🔴 Red | Critical | 9.0-10.0 |
| 🟠 Orange | High | 7.0-8.9 |
| 🟡 Yellow | Medium | 4.0-6.9 |
| 🟢 Green | Low | 0.1-3.9 |
| 🔵 Blue | No Issues | 0.0 |
| 🟣 Purple | Local Host | - |

## 🛠️ Development

### Local Development

1. **Backend Development**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   python app.py
   ```

2. **Frontend Development**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

### Project Structure

```
network-scanner/
├── docker-compose.yml           # Docker orchestration
├── .env.example                 # Environment template
├── backend/                     # Python Flask backend
│   ├── app.py                  # Main application
│   ├── scanner/                # Core scanning modules
│   │   ├── network_scanner.py  # Nmap integration
│   │   ├── inventory_manager.py # Database operations
│   │   └── vulnerability_analyzer.py # CVE analysis
│   ├── api/                    # REST API endpoints
│   └── utils/                  # Utility functions
├── frontend/                   # React/Vanilla JS frontend
│   ├── src/                    # Source code
│   │   ├── main.js            # Application entry
│   │   ├── visualization.js   # 3D graphics
│   │   └── dashboard.js       # Charts & UI
│   └── nginx.conf             # Nginx configuration
└── data/                      # Persistent data
    ├── inventory.db           # SQLite database
    ├── scans/                 # Scan results
    └── reports/               # Generated reports
```

## 🔒 Security Considerations

### Network Permissions
- Requires privileged container for raw sockets
- Host network mode for comprehensive scanning
- Only scan networks you own or have permission

### Data Protection
- Sensitive scan data stored locally
- No external data transmission
- Configurable data retention policies

### Access Control
- JWT-based authentication
- Rate limiting on API endpoints
- Input validation and sanitization

## 📊 Performance

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4GB | 8GB+ |
| Storage | 10GB | 50GB+ |
| Network | 100Mbps | 1Gbps+ |

### Optimization Tips

1. **Scanning Performance**
   - Adjust parallelism in nmap commands
   - Use targeted port ranges for faster scans
   - Schedule scans during off-peak hours

2. **Database Performance**
   - Regular database maintenance
   - Index optimization for large datasets
   - Partition old scan data

3. **Frontend Performance**
   - Enable browser caching
   - Optimize 3D rendering for large networks
   - Use pagination for large datasets

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Ensure Docker has appropriate permissions
   sudo usermod -aG docker $USER
   docker-compose down && docker-compose up -d
   ```

2. **Scan Failures**
   ```bash
   # Check nmap installation
   docker exec -it network-scanner-backend nmap --version
   
   # Verify network connectivity
   docker exec -it network-scanner-backend ping 8.8.8.8
   ```

3. **Database Issues**
   ```bash
   # Reset database
   docker-compose down
   rm -rf data/inventory.db
   docker-compose up -d
   ```

4. **3D Visualization Problems**
   - Enable hardware acceleration in browser
   - Update browser to latest version
   - Check WebGL support: https://get.webgl.org/

### Logs & Debugging

```bash
# View application logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Access container shell
docker exec -it network-scanner-backend bash
docker exec -it network-scanner-frontend sh
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Guidelines

- Follow PEP 8 for Python code
- Use ESLint for JavaScript code
- Add tests for new features
- Update documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Notice

**IMPORTANT**: This tool is intended for network security assessment and should only be used on networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws and regulations. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before conducting any network scans.

## 🙏 Acknowledgments

- **Nmap Project**: Network scanning capabilities
- **Three.js**: 3D visualization framework
- **Flask**: Python web framework
- **Chart.js**: Data visualization
- **Docker**: Containerization platform

---

Made with ❤️ for network security professionals

