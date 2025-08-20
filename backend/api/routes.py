"""
API Routes Module
REST API endpoints for the network scanner
"""

import logging
from datetime import datetime
from flask import jsonify, request, send_file
from typing import Dict, Any

logger = logging.getLogger(__name__)

def create_api_routes(app, scanner, inventory, vuln_analyzer):
    """Create and register API routes"""
    
    @app.route('/api/status')
    def get_status():
        """Get scanner status"""
        return jsonify({
            'status': 'active',
            'version': '2.0.0',
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/scan/status')
    def get_scan_status():
        """Get current scan status"""
        from app import scan_state  # Import to avoid circular import
        return jsonify(scan_state)
    
    @app.route('/api/inventory')
    def get_inventory():
        """Get network inventory"""
        try:
            # Get pagination parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            search = request.args.get('search', '')
            
            # For now, return all hosts (pagination would be implemented here)
            hosts = inventory.get_all_hosts(search=search, page=page, per_page=per_page)
            return jsonify(hosts)
        except Exception as e:
            logger.error(f"Failed to get inventory: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/inventory/<ip>')
    def get_host_details(ip: str):
        """Get detailed information about a specific host"""
        try:
            host_details = inventory.get_host_details(ip)
            if not host_details:
                return jsonify({'error': 'Host not found'}), 404
            return jsonify(host_details)
        except Exception as e:
            logger.error(f"Failed to get host details: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/vulnerabilities')
    def get_vulnerabilities():
        """Get vulnerability summary"""
        try:
            severity_filter = request.args.get('severity', 'all')
            host_filter = request.args.get('host')
            
            vulns = inventory.get_vulnerabilities(
                severity=severity_filter,
                host=host_filter
            )
            return jsonify(vulns)
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/vulnerabilities/priority')
    def get_remediation_priority():
        """Get vulnerability remediation priority"""
        try:
            # Get all hosts with vulnerabilities
            hosts_with_vulns = inventory.get_hosts_with_vulnerabilities()
            priority_list = vuln_analyzer.get_remediation_priority(hosts_with_vulns)
            return jsonify(priority_list)
        except Exception as e:
            logger.error(f"Failed to get remediation priority: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/statistics')
    def get_statistics():
        """Get network statistics"""
        try:
            stats = {
                'total_hosts': inventory.get_host_count(),
                'total_vulnerabilities': inventory.get_vulnerability_count(),
                'critical_vulnerabilities': inventory.get_vulnerability_count(severity='critical'),
                'high_vulnerabilities': inventory.get_vulnerability_count(severity='high'),
                'open_ports': inventory.get_total_open_ports(),
                'last_scan': inventory.get_last_scan_time(),
                'security_score': calculate_security_score(inventory)
            }
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/scans')
    def get_scans():
        """Get scan history"""
        try:
            days = request.args.get('days', 30, type=int)
            scans = inventory.get_scan_history(days=days)
            return jsonify(scans)
        except Exception as e:
            logger.error(f"Failed to get scans: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/network/topology')
    def get_network_topology():
        """Get network topology data for visualization"""
        try:
            # Get the latest scan data
            latest_scan = inventory.get_latest_scan()
            if not latest_scan:
                return jsonify({'nodes': [], 'edges': []})
            
            # Generate topology data
            topology = generate_topology_data(latest_scan, scanner)
            return jsonify(topology)
        except Exception as e:
            logger.error(f"Failed to get network topology: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/reports/generate', methods=['POST'])
    def generate_report():
        """Generate a custom report"""
        try:
            data = request.json or {}
            report_type = data.get('type', 'summary')
            format_type = data.get('format', 'pdf')
            scan_id = data.get('scan_id')
            
            # Generate report based on type and format
            report_path = create_report(
                report_type=report_type,
                format_type=format_type,
                scan_id=scan_id,
                inventory=inventory,
                vuln_analyzer=vuln_analyzer
            )
            
            return send_file(report_path, as_attachment=True)
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/alerts')
    def get_alerts():
        """Get security alerts"""
        try:
            alerts = generate_security_alerts(inventory, vuln_analyzer)
            return jsonify(alerts)
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return jsonify({'error': str(e)}), 500

def calculate_security_score(inventory) -> float:
    """Calculate overall security score"""
    try:
        total_hosts = inventory.get_host_count()
        if total_hosts == 0:
            return 100.0
        
        critical_vulns = inventory.get_vulnerability_count(severity='critical')
        high_vulns = inventory.get_vulnerability_count(severity='high')
        
        # Simple scoring algorithm
        base_score = 100.0
        critical_penalty = critical_vulns * 20  # 20 points per critical
        high_penalty = high_vulns * 5  # 5 points per high
        
        score = max(0, base_score - critical_penalty - high_penalty)
        return round(score, 1)
    except:
        return 0.0

def generate_topology_data(scan_data, scanner):
    """Generate network topology for visualization"""
    import math
    
    nodes = []
    edges = []
    
    # Add local machine as center
    local_ip = scanner.get_local_ip()
    nodes.append({
        'id': local_ip,
        'label': 'Local Machine',
        'group': 'local',
        'x': 0,
        'y': 0,
        'z': 0
    })
    
    # Add discovered hosts in a circle
    hosts = scan_data.get('hosts', [])
    num_hosts = len(hosts)
    
    for i, host in enumerate(hosts):
        angle = (2 * math.pi * i) / num_hosts
        radius = 150
        
        # Determine risk level for grouping
        risk_level = 'low'
        if host.get('cves'):
            max_cvss = max((cve.get('cvss', 0) for cve in host['cves']), default=0)
            if max_cvss >= 9.0:
                risk_level = 'critical'
            elif max_cvss >= 7.0:
                risk_level = 'high'
            elif max_cvss >= 4.0:
                risk_level = 'medium'
        
        nodes.append({
            'id': host['ip'],
            'label': host.get('hostname', host['ip']),
            'group': risk_level,
            'x': radius * math.cos(angle),
            'y': radius * math.sin(angle),
            'z': 0,
            'data': host
        })
        
        # Add edge to local machine
        edges.append({
            'source': local_ip,
            'target': host['ip'],
            'value': len(host.get('ports', []))
        })
    
    return {'nodes': nodes, 'edges': edges}

def create_report(report_type, format_type, scan_id, inventory, vuln_analyzer):
    """Create a report file"""
    from pathlib import Path
    import json
    
    # Ensure reports directory exists
    reports_dir = Path('/app/data/reports')
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if format_type == 'json':
        # Generate JSON report
        report_data = {
            'type': report_type,
            'generated_at': datetime.now().isoformat(),
            'scan_id': scan_id,
            'summary': inventory.get_summary(),
            'vulnerabilities': inventory.get_vulnerabilities()
        }
        
        filename = f'report_{report_type}_{timestamp}.json'
        file_path = reports_dir / filename
        
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        return str(file_path)
    
    # For PDF reports (simplified implementation)
    filename = f'report_{report_type}_{timestamp}.pdf'
    file_path = reports_dir / filename
    
    # Create a simple text file for now (in production, use reportlab)
    with open(file_path, 'w') as f:
        f.write(f"Network Security Report - {report_type}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 50 + "\n\n")
        # Add report content here
    
    return str(file_path)

def generate_security_alerts(inventory, vuln_analyzer):
    """Generate security alerts based on current state"""
    alerts = []
    
    # Check for critical vulnerabilities
    critical_vulns = inventory.get_vulnerability_count(severity='critical')
    if critical_vulns > 0:
        alerts.append({
            'type': 'critical',
            'title': 'Critical Vulnerabilities Found',
            'message': f'{critical_vulns} critical vulnerabilities require immediate attention',
            'timestamp': datetime.now().isoformat(),
            'priority': 'high'
        })
    
    # Check for new hosts
    recent_hosts = inventory.get_hosts_since(hours=24)
    if recent_hosts:
        alerts.append({
            'type': 'info',
            'title': 'New Hosts Detected',
            'message': f'{len(recent_hosts)} new hosts discovered in the last 24 hours',
            'timestamp': datetime.now().isoformat(),
            'priority': 'medium'
        })
    
    # Check for hosts with many open ports
    high_port_hosts = inventory.get_hosts_with_many_ports(threshold=20)
    if high_port_hosts:
        alerts.append({
            'type': 'warning',
            'title': 'Hosts with Many Open Ports',
            'message': f'{len(high_port_hosts)} hosts have more than 20 open ports',
            'timestamp': datetime.now().isoformat(),
            'priority': 'medium'
        })
    
    return alerts

