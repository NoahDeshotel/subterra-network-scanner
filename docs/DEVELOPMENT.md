# Development Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Development Setup](#development-setup)
3. [Running the Application](#running-the-application)
4. [Development Workflow](#development-workflow)
5. [Testing](#testing)
6. [Debugging](#debugging)
7. [Code Style](#code-style)
8. [Common Tasks](#common-tasks)
9. [Troubleshooting](#troubleshooting)
10. [Contributing](#contributing)

## Prerequisites

### System Requirements
- **OS**: Linux, macOS, or Windows with WSL2
- **Python**: 3.8 or higher
- **Node.js**: 14.x or higher (for frontend development)
- **Docker**: 20.10 or higher
- **Docker Compose**: 1.29 or higher
- **Git**: 2.x or higher

### Required Packages
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv nmap git curl

# macOS (with Homebrew)
brew install python nmap git

# Fedora/RHEL
sudo dnf install python3-pip python3-virtualenv nmap git
```

## Development Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd philadelphia
```

### 2. Backend Setup

#### Create Virtual Environment
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### Install Dependencies
```bash
pip install -r requirements.txt
```

#### Environment Configuration
```bash
cp ../env.example ../.env
# Edit .env with your configuration
```

#### Initialize Database
```bash
python -c "from scanner.enhanced_inventory import EnhancedInventoryManager; EnhancedInventoryManager().initialize_enhanced_db()"
```

### 3. Frontend Setup

#### Install Dependencies
```bash
cd frontend
npm install  # or yarn install
```

#### Development Server
```bash
npm run dev  # Starts Vite dev server
```

### 4. Docker Setup (Alternative)

#### Build Images
```bash
docker-compose build
```

#### Start Services
```bash
docker-compose up -d
```

## Running the Application

### Local Development (Without Docker)

#### Backend
```bash
cd backend
source venv/bin/activate
python app.py
# Server runs on http://localhost:5002
```

#### Frontend
```bash
cd frontend
npm run dev
# Development server on http://localhost:5173
```

### Docker Development
```bash
# Start all services
docker-compose up

# Start in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production Mode
```bash
# Build for production
docker-compose -f docker-compose.prod.yml build

# Deploy
docker-compose -f docker-compose.prod.yml up -d
```

## Development Workflow

### 1. Feature Development

#### Create Feature Branch
```bash
git checkout -b feature/your-feature-name
```

#### Backend Development Flow
```
1. Write/modify code in backend/
2. Add/update tests in backend/tests/
3. Run tests: pytest
4. Check linting: flake8
5. Test manually: python app.py
```

#### Frontend Development Flow
```
1. Write/modify code in frontend/src/
2. Use hot reload: npm run dev
3. Check console for errors
4. Test in browser
5. Build check: npm run build
```

### 2. API Development

#### Adding New Endpoint
```python
# backend/app.py or backend/api/routes.py

@app.route('/api/new-endpoint', methods=['GET', 'POST'])
def new_endpoint():
    """
    Document your endpoint purpose
    """
    try:
        # Implementation
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error in new_endpoint: {e}")
        return jsonify({'error': str(e)}), 500
```

#### WebSocket Event
```python
# backend/app.py

@socketio.on('new_event')
def handle_new_event(data):
    """Handle new WebSocket event"""
    # Process data
    emit('response_event', {'result': 'success'})
```

### 3. Scanner Module Development

#### Creating New Scanner
```python
# backend/scanner/custom_scanner.py

from .base_scanner import BaseScanner

class CustomScanner(BaseScanner):
    """Custom scanner implementation"""
    
    def scan(self, target):
        """Implement scanning logic"""
        results = []
        # Scanning implementation
        return results
```

#### Registering Scanner
```python
# backend/scanner/scanner_factory.py

SCANNER_TYPES = {
    'simple': SimpleScanner,
    'enhanced': EnhancedScanner,
    'custom': CustomScanner,  # Add your scanner
}
```

## Testing

### Backend Testing

#### Unit Tests
```bash
cd backend
pytest tests/unit/
```

#### Integration Tests
```bash
pytest tests/integration/
```

#### Test Coverage
```bash
pytest --cov=scanner --cov-report=html
# Open htmlcov/index.html in browser
```

#### Manual API Testing
```bash
# Test health endpoint
curl http://localhost:5002/health

# Test scan start
python test_backend_api.py

# Test all APIs
python test_all_apis.py
```

### Frontend Testing

#### Manual Testing
```bash
# Open test page
open test_scan.html
```

#### Browser Console Testing
```javascript
// Test WebSocket connection
const socket = io('http://localhost:5002');
socket.on('connect', () => console.log('Connected'));

// Test API call
fetch('http://localhost:5002/api/status')
    .then(r => r.json())
    .then(console.log);
```

### Scanner Testing

#### Test Single Host
```bash
cd backend
python -c "from scanner.main_scanner import scan_single_host; print(scan_single_host('127.0.0.1'))"
```

#### Test Subnet Scan
```bash
python test_subnet_scanner.py
```

#### Debug Scan
```bash
python debug_scan.py
```

## Debugging

### Backend Debugging

#### Enable Debug Logging
```python
# backend/app.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

#### Using Python Debugger
```python
import pdb
pdb.set_trace()  # Breakpoint
```

#### VS Code Launch Configuration
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Flask",
            "type": "python",
            "request": "launch",
            "module": "flask",
            "env": {
                "FLASK_APP": "backend/app.py",
                "FLASK_ENV": "development"
            },
            "args": ["run", "--port", "5002"],
            "jinja": true
        }
    ]
}
```

### Frontend Debugging

#### Browser DevTools
```javascript
// Add breakpoints
debugger;

// Console logging
console.log('Debug:', variable);

// Network tab for API calls
// WebSocket frames inspection
```

### Docker Debugging

#### Container Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend

# Last 100 lines
docker-compose logs --tail=100 backend
```

#### Execute Commands in Container
```bash
# Shell access
docker-compose exec backend bash

# Python shell
docker-compose exec backend python

# Run specific script
docker-compose exec backend python debug_scan.py
```

## Code Style

### Python Style Guide

#### PEP 8 Compliance
```bash
# Check style
flake8 backend/

# Auto-format
black backend/
```

#### Docstrings
```python
def function_name(param1: str, param2: int) -> dict:
    """
    Brief description of function.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    
    Raises:
        ValueError: When invalid input
    """
    pass
```

### JavaScript Style Guide

#### ESLint Configuration
```json
{
    "extends": "eslint:recommended",
    "rules": {
        "indent": ["error", 4],
        "quotes": ["error", "single"],
        "semi": ["error", "always"]
    }
}
```

#### JSDoc Comments
```javascript
/**
 * Brief description
 * @param {string} param1 - Description
 * @returns {Promise<Object>} Description
 */
async function functionName(param1) {
    // Implementation
}
```

## Common Tasks

### Adding New Dependencies

#### Backend
```bash
cd backend
pip install new-package
pip freeze > requirements.txt
```

#### Frontend
```bash
cd frontend
npm install new-package
# or
npm install --save-dev dev-package
```

### Database Operations

#### Reset Database
```bash
cd backend
rm ../data/enhanced_inventory.db
python -c "from scanner.enhanced_inventory import EnhancedInventoryManager; EnhancedInventoryManager().initialize_enhanced_db()"
```

#### Database Migration
```python
# backend/migrations/001_add_column.py
import sqlite3

def migrate():
    conn = sqlite3.connect('../data/enhanced_inventory.db')
    cursor = conn.cursor()
    cursor.execute('ALTER TABLE devices ADD COLUMN new_field TEXT')
    conn.commit()
    conn.close()
```

### Environment Variables

#### Required Variables
```bash
# .env file
SECRET_KEY=your-secret-key-here
DATABASE_PATH=/app/data/enhanced_inventory.db
HOST_SUBNET=192.168.1.0/24
SCAN_INTERVAL=3600
MAX_THREADS=50
FLASK_ENV=development
```

#### Loading in Python
```python
import os
from dotenv import load_dotenv

load_dotenv()
secret_key = os.getenv('SECRET_KEY')
```

### Performance Profiling

#### Backend Profiling
```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()
# Code to profile
profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(10)
```

#### Frontend Performance
```javascript
// Chrome DevTools Performance tab
// Lighthouse audits
// Network waterfall analysis
```

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port
lsof -i :5002  # macOS/Linux
netstat -ano | findstr :5002  # Windows

# Kill process
kill -9 <PID>
```

#### Permission Denied (Scanning)
```bash
# Run with sudo for raw socket access
sudo python app.py

# Or use Docker with privileged mode
docker-compose up
```

#### WebSocket Connection Failed
```javascript
// Check CORS settings
// Verify backend is running
// Check firewall rules
// Try different transports
const socket = io('http://localhost:5002', {
    transports: ['websocket', 'polling']
});
```

#### Database Locked
```python
# Increase timeout
conn = sqlite3.connect(db_path, timeout=30)

# Use WAL mode
conn.execute('PRAGMA journal_mode=WAL')
```

### Debug Checklist

1. **Backend Not Starting**
   - Check Python version
   - Verify all dependencies installed
   - Check port availability
   - Review error logs

2. **Frontend Not Loading**
   - Check backend URL in app.js
   - Verify CORS settings
   - Check browser console
   - Disable ad blockers

3. **Scanning Not Working**
   - Verify network permissions
   - Check subnet format
   - Test with localhost first
   - Review scanner logs

4. **WebSocket Issues**
   - Check firewall settings
   - Verify socket.io versions match
   - Test with simple echo
   - Check proxy configuration

## Contributing

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No sensitive data exposed
- [ ] Error handling implemented
- [ ] Logging added where appropriate
- [ ] Performance impact considered
- [ ] Security implications reviewed

### Commit Messages

Follow conventional commits:
```
feat: Add new scanner module
fix: Resolve WebSocket disconnect issue
docs: Update API documentation
test: Add unit tests for inventory manager
refactor: Simplify scan progress tracking
perf: Optimize database queries
```

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No warnings generated
```

## Additional Resources

### Documentation
- [README.md](README.md) - Project overview
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [API.md](API.md) - API documentation

### External Resources
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Socket.IO Documentation](https://socket.io/docs/)
- [Nmap Reference](https://nmap.org/book/)
- [Docker Documentation](https://docs.docker.com/)

### Tools
- **Postman**: API testing
- **Wireshark**: Network analysis
- **Chrome DevTools**: Frontend debugging
- **pgAdmin**: Database management (future PostgreSQL)

## Support

For questions or issues:
1. Check existing documentation
2. Search closed issues
3. Create new issue with details
4. Include logs and error messages
5. Provide steps to reproduce