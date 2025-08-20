#!/usr/bin/env python3
"""Test WebSocket connection to the backend"""

import socketio
import time

# Create a Socket.IO client
sio = socketio.Client()

@sio.event
def connect():
    print("✅ Connected to backend WebSocket")

@sio.event
def connected(data):
    print(f"✅ Received 'connected' event: {data}")

@sio.event
def disconnect():
    print("❌ Disconnected from backend")

@sio.event
def connect_error(data):
    print(f"❌ Connection error: {data}")

# Try to connect
try:
    print("🔄 Attempting to connect to backend WebSocket...")
    sio.connect('http://localhost:8080')
    
    # Wait a bit to see if we receive any messages
    time.sleep(2)
    
    # Disconnect cleanly
    sio.disconnect()
    print("✅ Test completed successfully")
    
except Exception as e:
    print(f"❌ Failed to connect: {e}")