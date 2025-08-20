#!/bin/bash

# Network Scanner Startup Script
# This script helps you get started with the network scanner

set -e

echo "🚀 Network Scanner & Visualization System"
echo "==========================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating from template..."
    cp env.example .env
    echo "✅ Created .env file from template"
    echo ""
    echo "📝 Please edit .env file with your configuration:"
    echo "   - Change SECRET_KEY to a secure random string"
    echo "   - Set ADMIN_PASSWORD to a strong password"
    echo "   - Adjust SCAN_INTERVAL if needed"
    echo ""
    read -p "Press Enter to continue after editing .env file..."
fi

# Create data directories
echo "📁 Creating data directories..."
mkdir -p data/{scans,reports,exports}
echo "✅ Data directories created"

# Check if containers are already running
if docker-compose ps | grep -q "Up"; then
    echo "⚠️  Containers are already running. Stopping them first..."
    docker-compose down
fi

# Build and start containers
echo "🔨 Building and starting containers..."
docker-compose up -d --build

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check if services are healthy
echo "🏥 Checking service health..."

# Check backend
if curl -f -s http://localhost:5000/health > /dev/null; then
    echo "✅ Backend is healthy"
else
    echo "❌ Backend is not responding"
    echo "   Check logs: docker-compose logs backend"
fi

# Check frontend
if curl -f -s http://localhost:80/health > /dev/null; then
    echo "✅ Frontend is healthy"
else
    echo "❌ Frontend is not responding"
    echo "   Check logs: docker-compose logs frontend"
fi

# Check Redis
if docker-compose exec redis redis-cli ping | grep -q "PONG"; then
    echo "✅ Redis is healthy"
else
    echo "❌ Redis is not responding"
    echo "   Check logs: docker-compose logs redis"
fi

echo ""
echo "🎉 Network Scanner is ready!"
echo ""
echo "📊 Web Interface: http://localhost:80"
echo "🔧 API Endpoint:  http://localhost:5000"
echo "📝 View Logs:     docker-compose logs -f"
echo ""
echo "⚠️  LEGAL NOTICE:"
echo "   Only scan networks you own or have explicit permission to test."
echo "   Unauthorized scanning may violate local laws and regulations."
echo ""
echo "🔐 Default Credentials:"
echo "   Username: admin"
echo "   Password: (check your .env file)"
echo ""
echo "📚 Documentation: See README.md for detailed usage instructions"
echo ""
echo "Happy scanning! 🔍"

