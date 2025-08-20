#!/usr/bin/env python3
"""
Scanner Capabilities Module
Provides information about scanner features and capabilities
"""

def get_scan_capabilities():
    """Return scanner system capabilities"""
    return {
        "discovery_methods": ["ping", "tcp", "hostname_resolution"],
        "scan_types": ["simple", "robust"],
        "features": [
            "concurrent_scanning",
            "progress_tracking",
            "real_time_updates",
            "device_classification",
            "port_scanning"
        ],
        "performance": {
            "max_concurrent_hosts": 50,
            "timeout_configurable": True,
            "subnet_size_limit": 256
        }
    }

def get_supported_protocols():
    """Return list of supported protocols"""
    return [
        "icmp",     # Ping
        "tcp",      # TCP port scanning
        "dns",      # Hostname resolution
        "http",     # Basic HTTP detection
        "https",    # HTTPS detection
        "ssh",      # SSH detection (port 22)
        "rdp"       # RDP detection (port 3389)
    ]

def get_device_classification_types():
    """Return device types that can be classified"""
    return [
        "server",
        "web_server",
        "workstation",
        "router",
        "switch",
        "printer",
        "iot_device",
        "unknown"
    ]

def get_vendor_database_info():
    """Return vendor database information"""
    return {
        "mac_vendor_lookup": False,  # Not implemented yet
        "os_fingerprinting": "basic",
        "service_detection": "port_based",
        "last_updated": "2024-01-01"
    }