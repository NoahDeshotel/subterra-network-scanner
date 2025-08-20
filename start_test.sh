#!/bin/bash
# Start the backend and open test page

echo "Starting Subterra Network Scanner Test Environment"
echo "=================================================="

# Kill any existing Python processes on port 5000
echo "Stopping any existing backend processes..."
lsof -ti:5000 | xargs kill -9 2>/dev/null

# Start the backend
echo "Starting backend server..."
cd backend
python app.py &
BACKEND_PID=$!
echo "Backend started with PID: $BACKEND_PID"

# Wait for backend to start
echo "Waiting for backend to initialize..."
sleep 3

# Test if backend is responding
echo "Testing backend status..."
curl -s http://localhost:5000/api/status > /dev/null
if [ $? -eq 0 ]; then
    echo "✓ Backend is running"
else
    echo "✗ Backend failed to start"
    echo "Check the logs above for errors"
    exit 1
fi

# Open the test page
echo "Opening test page in browser..."
open ../test_scan.html

echo ""
echo "Test environment is ready!"
echo "=================================================="
echo "Backend PID: $BACKEND_PID"
echo "Test page: http://localhost:5000/test_scan.html"
echo ""
echo "To stop the backend, run: kill $BACKEND_PID"
echo "Or press Ctrl+C to stop everything"

# Wait for Ctrl+C
trap "echo 'Stopping backend...'; kill $BACKEND_PID; exit" INT
wait $BACKEND_PID