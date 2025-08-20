#!/usr/bin/env python3
"""
Demo of Improved Network Scanner
Shows the new job-based Netdisco-inspired scanner in action
"""

import asyncio
import json
import time
import requests
from datetime import datetime

# Demo configuration
BACKEND_URL = "http://localhost:8080"
DEMO_SUBNET = "192.168.1.0/24"

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"🚀 {title}")
    print("="*60)

def print_section(title):
    """Print formatted section"""
    print(f"\n📊 {title}")
    print("-"*40)

async def demo_api_capabilities():
    """Demonstrate the API capabilities"""
    print_header("ENHANCED SCANNER API DEMONSTRATION")
    
    try:
        # 1. Check system status
        print_section("System Status")
        response = requests.get(f"{BACKEND_URL}/api/status")
        if response.status_code == 200:
            status = response.json()
            print(f"✅ Scanner Status: {status['status']}")
            print(f"📦 Version: {status['version']}")
            print(f"🔧 Available Scanners: {', '.join(status['available_scanners'])}")
            print(f"🎯 Default Scanner: {status['default_scanner']}")
            print(f"✨ Enhanced Features: {len(status['features'])} enabled")
        else:
            print(f"❌ Status check failed: {response.status_code}")
            return
        
        # 2. Get available scanners
        print_section("Available Scanners")
        response = requests.get(f"{BACKEND_URL}/api/scanners/available")
        if response.status_code == 200:
            scanners_info = response.json()
            for scanner_type, info in scanners_info['available_scanners'].items():
                print(f"🔍 {info['name']} ({scanner_type}):")
                print(f"    Description: {info['description']}")
                print(f"    Best for: {info['recommended_for']}")
                print(f"    Performance: {info['performance']}")
                print(f"    Features: {len(info.get('features', []))} capabilities")
                
            print(f"\n🧠 Auto-Selection Logic:")
            for condition, scanner in scanners_info['auto_selection_logic'].items():
                print(f"    {condition}: {scanner}")
        
        # 3. Get system capabilities
        print_section("System Capabilities")
        response = requests.get(f"{BACKEND_URL}/api/scanners/capabilities")
        if response.status_code == 200:
            caps = response.json()
            print(f"🌐 Supported Protocols: {len(caps['supported_protocols'])}")
            print(f"    {', '.join(caps['supported_protocols'][:10])}{'...' if len(caps['supported_protocols']) > 10 else ''}")
            
            print(f"🏷️  Device Types: {len(caps['device_types'])}")
            print(f"    {', '.join(caps['device_types'][:8])}{'...' if len(caps['device_types']) > 8 else ''}")
            
            print(f"🏢 Vendor Database: {caps['vendor_database']['vendor_oids_supported']} OIDs")
            print(f"⚙️  Job Types: {len(caps['job_types'])}")
            print(f"    {', '.join(caps['job_types'])}")
            
            print(f"🧠 Intelligent Features:")
            for feature, enabled in caps['intelligent_features'].items():
                status = "✅" if enabled else "❌"
                print(f"    {status} {feature.replace('_', ' ').title()}")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend. Please start the server with 'python app.py'")
        return False
    except Exception as e:
        print(f"❌ API demo failed: {e}")
        return False
    
    return True

async def demo_scanner_comparison():
    """Demonstrate scanner comparison"""
    print_header("SCANNER COMPARISON DEMO")
    
    print("This demo will run all three scanner types and compare their performance:")
    print("1. Simple Scanner - Basic ping sweep")
    print("2. Enhanced Scanner - Multi-method with Nmap")
    print("3. Job-Based Scanner - Netdisco-inspired with full capabilities")
    
    input("\n🎯 Press Enter to start the comparison demo...")
    
    # Run the comparison
    try:
        from scanner_comparison import ScannerComparison
        comparison = ScannerComparison()
        results = await comparison.run_comparison(DEMO_SUBNET)
        
        # Print results summary
        print_section("Comparison Results")
        for scanner, result in results.items():
            if result.get('success'):
                print(f"✅ {scanner}: {result['devices_found']} devices in {result['duration']:.1f}s")
            else:
                print(f"❌ {scanner}: Failed - {result.get('error', 'Unknown error')}")
        
        return results
        
    except ImportError:
        print("❌ Scanner comparison module not available")
        return None
    except Exception as e:
        print(f"❌ Comparison demo failed: {e}")
        return None

async def demo_live_scan():
    """Demonstrate a live scan using the API"""
    print_header("LIVE SCAN DEMONSTRATION")
    
    print(f"Starting a live scan of {DEMO_SUBNET} using the job-based scanner...")
    
    try:
        # Start scan
        scan_config = {
            "subnet": DEMO_SUBNET,
            "scanner_type": "job_based",
            "deep_scan": True,
            "topology_discovery": True,
            "vulnerability_scan": False  # Skip vulns for demo speed
        }
        
        print_section("Starting Scan")
        response = requests.post(f"{BACKEND_URL}/api/scan/start", json=scan_config)
        
        if response.status_code != 200:
            print(f"❌ Scan start failed: {response.status_code}")
            return None
        
        scan_info = response.json()
        scan_id = scan_info['scan_id']
        
        print(f"🎯 Scan started with ID: {scan_id}")
        print(f"🔧 Configuration: {scan_info['config']}")
        
        # Monitor progress
        print_section("Monitoring Progress")
        start_time = time.time()
        last_stage = None
        
        while True:
            # Get scan status
            response = requests.get(f"{BACKEND_URL}/api/scan/{scan_id}/status")
            if response.status_code != 200:
                print(f"❌ Status check failed: {response.status_code}")
                break
            
            status = response.json()
            progress = status.get('progress', {})
            
            # Print progress updates
            if progress:
                current_stage = progress.get('stage', 'unknown')
                message = progress.get('current_message', 'Processing...')
                step_progress = progress.get('step_progress', {})
                
                if current_stage != last_stage:
                    print(f"\n🔄 Stage: {current_stage}")
                    last_stage = current_stage
                
                if step_progress:
                    current = step_progress.get('current', 0)
                    total = step_progress.get('total', 0)
                    target = step_progress.get('target', '')
                    if total > 0:
                        percent = (current / total) * 100
                        print(f"    Progress: {current}/{total} ({percent:.1f}%) - {target}")
                
                print(f"    {message}")
            
            # Check if scan completed
            if not status.get('active', True):
                print(f"\n✅ Scan completed!")
                break
            
            # Check timeout
            if time.time() - start_time > 300:  # 5 minute timeout
                print(f"\n⏱️ Demo timeout reached")
                break
            
            await asyncio.sleep(2)
        
        # Get final results
        print_section("Final Results")
        response = requests.get(f"{BACKEND_URL}/api/devices")
        if response.status_code == 200:
            devices_info = response.json()
            devices = devices_info.get('devices', [])
            
            print(f"📊 Total devices found: {len(devices)}")
            
            # Show device breakdown
            device_types = {}
            vendors = {}
            
            for device in devices:
                device_type = device.get('device_type', 'unknown')
                vendor = device.get('vendor', 'unknown')
                device_types[device_type] = device_types.get(device_type, 0) + 1
                vendors[vendor] = vendors.get(vendor, 0) + 1
            
            print(f"🏷️  Device Types:")
            for dtype, count in sorted(device_types.items()):
                print(f"    {dtype}: {count}")
            
            print(f"🏢 Vendors:")
            for vendor, count in sorted(vendors.items()):
                if vendor != 'unknown':
                    print(f"    {vendor}: {count}")
            
            # Show sample devices
            print(f"\n📱 Sample Devices:")
            for device in devices[:5]:
                ip = device.get('ip', 'Unknown')
                hostname = device.get('hostname', 'N/A')
                device_type = device.get('device_type', 'unknown')
                vendor = device.get('vendor', 'Unknown')
                snmp = "✅" if device.get('snmp_capable') else "❌"
                
                print(f"    {ip:<15} {hostname:<20} {device_type:<12} {vendor:<15} SNMP:{snmp}")
        
        # Get scan logs
        print_section("Scan Logs Summary")
        response = requests.get(f"{BACKEND_URL}/api/scan/{scan_id}/logs?limit=10")
        if response.status_code == 200:
            logs_info = response.json()
            logs = logs_info.get('logs', [])
            
            print(f"📝 Recent log entries ({len(logs)} shown):")
            for log in logs[-10:]:  # Show last 10 entries
                timestamp = datetime.fromisoformat(log['timestamp']).strftime('%H:%M:%S')
                stage = log.get('stage', 'unknown')
                priority = log.get('priority', 'info')
                message = log.get('message', 'No message')
                
                priority_icon = {"info": "ℹ️", "warning": "⚠️", "error": "❌"}.get(priority, "📝")
                print(f"    {timestamp} [{stage}] {priority_icon} {message[:80]}{'...' if len(message) > 80 else ''}")
        
        return scan_id
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend. Please start the server first.")
        return None
    except Exception as e:
        print(f"❌ Live scan demo failed: {e}")
        return None

async def demo_job_based_features():
    """Demonstrate specific job-based scanner features"""
    print_header("JOB-BASED SCANNER FEATURES")
    
    print("🔬 Key features of the new job-based scanner:")
    
    features = [
        ("Event-Driven Architecture", "Jobs are queued and processed asynchronously with priority"),
        ("Breadth-First Discovery", "Neighbor discovery automatically spawns new scan jobs"),
        ("Historical Continuity", "Old data marked inactive, not deleted - maintains history"),
        ("Intelligent Deferral", "Failed devices get exponential backoff to avoid network hammering"),
        ("Comprehensive SNMP", "Full MIB support: System, Interface, Bridge, CDP, LLDP tables"),
        ("MAC Table Collection", "Switch forwarding tables collected and tracked over time"),
        ("ARP Table Collection", "Router neighbor caches provide IP-to-MAC mappings"),
        ("Topology Discovery", "CDP/LLDP protocols map network device relationships"),
        ("Device Classification", "Advanced patterns identify 10+ device types"),
        ("Vendor Identification", "Multiple methods: SNMP OIDs, MAC OUI, pattern matching"),
        ("Database Schema", "Designed for network management with proper relationships"),
        ("Job Priority System", "Critical infrastructure gets higher priority scanning")
    ]
    
    for i, (feature, description) in enumerate(features, 1):
        print(f"{i:2d}. ✨ {feature}")
        print(f"     {description}")
    
    print(f"\n🌟 This represents a complete rewrite of network scanning algorithms")
    print(f"   using proven techniques from Netdisco plus modern enhancements!")

async def main():
    """Main demo function"""
    print_header("IMPROVED NETWORK SCANNER DEMONSTRATION")
    
    print("Welcome to the demonstration of the improved network scanning system!")
    print("This demo will show the enhancements made using Netdisco-inspired algorithms.")
    print("\nThe new system includes:")
    print("✅ Job-based event-driven architecture")
    print("✅ Breadth-first network discovery") 
    print("✅ Historical data continuity")
    print("✅ Intelligent retry and deferral")
    print("✅ Comprehensive SNMP support")
    print("✅ Network topology mapping")
    print("✅ Enhanced device classification")
    
    # Menu system
    while True:
        print(f"\n🎯 DEMO OPTIONS:")
        print("1. 📊 Show API Capabilities")
        print("2. ⚖️  Run Scanner Comparison")
        print("3. 🔴 Live Scan Demo")
        print("4. 🔬 Job-Based Features Overview")
        print("5. 🚪 Exit")
        
        try:
            choice = input(f"\nSelect option (1-5): ").strip()
            
            if choice == '1':
                success = await demo_api_capabilities()
                if not success:
                    print("\n💡 Make sure the backend server is running: python app.py")
            
            elif choice == '2':
                results = await demo_scanner_comparison()
                if results:
                    print(f"\n💾 Comparison results saved to file")
            
            elif choice == '3':
                scan_id = await demo_live_scan()
                if scan_id:
                    print(f"\n🎉 Live scan completed: {scan_id}")
                else:
                    print("\n💡 Make sure the backend server is running: python app.py")
            
            elif choice == '4':
                await demo_job_based_features()
            
            elif choice == '5':
                print(f"\n👋 Demo completed!")
                break
            
            else:
                print("❌ Invalid option. Please select 1-5.")
                
        except KeyboardInterrupt:
            print(f"\n\n👋 Demo interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"❌ Demo error: {e}")
    
    print(f"\n🎉 Thank you for trying the improved network scanner!")
    print(f"Your scanning algorithms are now powered by job-based Netdisco architecture! 🚀")

if __name__ == "__main__":
    asyncio.run(main())