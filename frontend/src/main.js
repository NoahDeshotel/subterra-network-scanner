/**
 * Main Application Entry Point
 * Network Scanner Frontend Application
 */

import './dashboard.js';
import './visualization.js';
import { io } from 'socket.io-client';

class NetworkScannerApp {
    constructor() {
        this.socket = null;
        this.currentView = 'dashboard';
        this.scanInProgress = false;
        
        this.init();
    }
    
    init() {
        console.log('🚀 Network Scanner App Starting...');
        
        // Initialize WebSocket connection
        this.initSocket();
        
        // Initialize event listeners
        this.initEventListeners();
        
        // Load initial data
        this.loadInitialData();
        
        // Initialize theme
        this.initTheme();
        
        console.log('✅ Network Scanner App Ready');
    }
    
    initSocket() {
        this.socket = io('/', {
            autoConnect: true,
            reconnection: true,
            reconnectionAttempts: 5,
            reconnectionDelay: 1000
        });
        
        this.socket.on('connect', () => {
            console.log('🔗 Connected to backend');
            this.updateConnectionStatus(true);
        });
        
        this.socket.on('disconnect', () => {
            console.log('❌ Disconnected from backend');
            this.updateConnectionStatus(false);
        });
        
        this.socket.on('scan_progress', (data) => {
            this.updateScanProgress(data.progress, data.message);
        });
        
        this.socket.on('scan_complete', (data) => {
            this.onScanComplete(data);
        });
        
        this.socket.on('host_discovered', (data) => {
            this.onHostDiscovered(data);
        });
        
        this.socket.on('security_alert', (data) => {
            this.showAlert(data.alert);
        });
    }
    
    initEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });
        
        // Scan button
        document.getElementById('scan-btn').addEventListener('click', () => {
            this.showScanModal();
        });
        
        // Scan modal events
        document.getElementById('cancel-scan').addEventListener('click', () => {
            this.hideScanModal();
        });
        
        document.getElementById('scan-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });
        
        // Theme toggle
        document.getElementById('theme-toggle').addEventListener('click', () => {
            this.toggleTheme();
        });
        
        // Export functionality
        document.getElementById('export-csv').addEventListener('click', () => {
            this.exportData('csv');
        });
        
        // Search functionality
        document.getElementById('inventory-search').addEventListener('input', (e) => {
            this.filterInventory(e.target.value);
        });
        
        // Filter functionality
        document.getElementById('severity-filter').addEventListener('change', (e) => {
            this.filterVulnerabilities(e.target.value);
        });
    }
    
    switchView(viewName) {
        // Hide all views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.remove('active');
        });
        
        // Show selected view
        const targetView = document.getElementById(`${viewName}-view`);
        if (targetView) {
            targetView.classList.add('active');
            
            // Update navigation
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            
            document.querySelector(`[data-view="${viewName}"]`).classList.add('active');
            
            this.currentView = viewName;
            
            // Load view-specific data
            this.loadViewData(viewName);
        }
    }
    
    loadViewData(viewName) {
        switch (viewName) {
            case 'dashboard':
                this.loadDashboardData();
                break;
            case '3d-map':
                this.load3DMapData();
                break;
            case 'inventory':
                this.loadInventoryData();
                break;
            case 'vulnerabilities':
                this.loadVulnerabilitiesData();
                break;
            case 'reports':
                this.loadReportsData();
                break;
        }
    }
    
    async loadInitialData() {
        try {
            // Load statistics
            const stats = await this.fetchAPI('/api/statistics');
            this.updateStatistics(stats);
            
            // Load alerts
            const alerts = await this.fetchAPI('/api/alerts');
            this.updateAlerts(alerts);
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
        }
    }
    
    async loadDashboardData() {
        try {
            const [stats, alerts, scans] = await Promise.all([
                this.fetchAPI('/api/statistics'),
                this.fetchAPI('/api/alerts'),
                this.fetchAPI('/api/scans?days=7')
            ]);
            
            this.updateStatistics(stats);
            this.updateAlerts(alerts);
            this.updateDashboardCharts(scans);
            
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
        }
    }
    
    async load3DMapData() {
        try {
            const topology = await this.fetchAPI('/api/network/topology');
            window.networkVisualization.updateTopology(topology);
        } catch (error) {
            console.error('Failed to load 3D map data:', error);
        }
    }
    
    async loadInventoryData() {
        try {
            const inventory = await this.fetchAPI('/api/inventory');
            this.updateInventoryTable(inventory);
        } catch (error) {
            console.error('Failed to load inventory data:', error);
        }
    }
    
    async loadVulnerabilitiesData() {
        try {
            const [vulnerabilities, priority] = await Promise.all([
                this.fetchAPI('/api/vulnerabilities'),
                this.fetchAPI('/api/vulnerabilities/priority')
            ]);
            
            this.updateVulnerabilitiesView(vulnerabilities);
            this.updateRemediationPriority(priority);
        } catch (error) {
            console.error('Failed to load vulnerabilities data:', error);
        }
    }
    
    loadReportsData() {
        // Load reports data
        console.log('Loading reports data...');
    }
    
    showScanModal() {
        document.getElementById('scan-modal').classList.remove('hidden');
    }
    
    hideScanModal() {
        document.getElementById('scan-modal').classList.add('hidden');
    }
    
    async startScan() {
        if (this.scanInProgress) {
            return;
        }
        
        const subnet = document.getElementById('subnet-input').value;
        const aggressive = document.getElementById('aggressive-scan').checked;
        const vulnScan = document.getElementById('vuln-scan').checked;
        
        try {
            const response = await this.fetchAPI('/api/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    subnet,
                    aggressive,
                    vulnerability_scan: vulnScan
                })
            });
            
            if (response.error) {
                throw new Error(response.error);
            }
            
            this.scanInProgress = true;
            this.hideScanModal();
            this.showScanProgress();
            
        } catch (error) {
            console.error('Failed to start scan:', error);
            alert('Failed to start scan: ' + error.message);
        }
    }
    
    showScanProgress() {
        const progressBar = document.getElementById('scan-progress');
        progressBar.classList.remove('hidden');
        
        // Update scan button
        const scanBtn = document.getElementById('scan-btn');
        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        scanBtn.disabled = true;
    }
    
    updateScanProgress(progress, message) {
        const progressFill = document.querySelector('.progress-fill');
        const progressText = document.querySelector('.progress-text');
        
        progressFill.style.width = `${progress}%`;
        progressText.textContent = message;
    }
    
    onScanComplete(data) {
        console.log('Scan completed:', data);
        
        this.scanInProgress = false;
        
        // Hide progress bar
        document.getElementById('scan-progress').classList.add('hidden');
        
        // Reset scan button
        const scanBtn = document.getElementById('scan-btn');
        scanBtn.innerHTML = '<i class="fas fa-radar"></i> Start Scan';
        scanBtn.disabled = false;
        
        // Refresh data
        this.loadInitialData();
        
        // Show completion notification
        this.showNotification(`Scan completed! Found ${data.host_count} hosts with ${data.vulnerability_count} vulnerabilities.`);
    }
    
    onHostDiscovered(data) {
        console.log('Host discovered:', data.host);
        // Could update real-time host counter here
    }
    
    updateStatistics(stats) {
        document.getElementById('total-hosts').textContent = stats.total_hosts || 0;
        document.getElementById('critical-vulns').textContent = stats.critical_vulnerabilities || 0;
        document.getElementById('open-ports').textContent = stats.open_ports || 0;
        document.getElementById('security-score').textContent = `${stats.security_score || 0}%`;
    }
    
    updateAlerts(alerts) {
        const container = document.getElementById('alerts-container');
        container.innerHTML = '';
        
        if (alerts.length === 0) {
            container.innerHTML = '<p class="text-gray">No recent alerts</p>';
            return;
        }
        
        alerts.forEach(alert => {
            const alertDiv = document.createElement('div');
            alertDiv.className = `alert ${alert.type}`;
            alertDiv.innerHTML = `
                <div class="alert-header">
                    <strong>${alert.title}</strong>
                    <span class="alert-time">${new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>
                <p>${alert.message}</p>
            `;
            container.appendChild(alertDiv);
        });
    }
    
    updateInventoryTable(inventory) {
        const tbody = document.getElementById('inventory-tbody');
        tbody.innerHTML = '';
        
        inventory.forEach(host => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${host.ip}</td>
                <td>${host.hostname || '-'}</td>
                <td>${host.mac_address || '-'}</td>
                <td>${host.os || '-'}</td>
                <td>${host.open_ports || 0}</td>
                <td>${host.vulnerabilities || 0}</td>
                <td><span class="risk-badge ${host.risk_level || 'low'}">${host.risk_level || 'Low'}</span></td>
                <td>${host.last_seen ? new Date(host.last_seen).toLocaleDateString() : '-'}</td>
                <td>
                    <button class="btn btn-sm" onclick="app.viewHostDetails('${host.ip}')">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }
    
    async viewHostDetails(ip) {
        try {
            const details = await this.fetchAPI(`/api/inventory/${ip}`);
            this.showHostDetailsModal(details);
        } catch (error) {
            console.error('Failed to load host details:', error);
        }
    }
    
    showHostDetailsModal(host) {
        // Implementation for host details modal
        console.log('Host details:', host);
    }
    
    filterInventory(searchTerm) {
        const rows = document.querySelectorAll('#inventory-tbody tr');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            const matches = text.includes(searchTerm.toLowerCase());
            row.style.display = matches ? '' : 'none';
        });
    }
    
    filterVulnerabilities(severity) {
        // Implementation for vulnerability filtering
        console.log('Filter vulnerabilities by:', severity);
    }
    
    async exportData(format) {
        try {
            const response = await fetch(`/api/export/${format}`, {
                method: 'GET'
            });
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `network_inventory.${format}`;
                a.click();
                window.URL.revokeObjectURL(url);
            }
        } catch (error) {
            console.error('Failed to export data:', error);
        }
    }
    
    initTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.body.setAttribute('data-theme', savedTheme);
    }
    
    toggleTheme() {
        const currentTheme = document.body.getAttribute('data-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        const icon = document.querySelector('#theme-toggle i');
        icon.className = newTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    }
    
    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connection-status');
        if (indicator) {
            indicator.className = connected ? 'connected' : 'disconnected';
        }
    }
    
    showAlert(alert) {
        // Show real-time alert
        console.log('Security alert:', alert);
    }
    
    showNotification(message) {
        // Simple notification implementation
        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--primary);
            color: white;
            padding: 1rem;
            border-radius: 0.5rem;
            z-index: 10000;
            animation: slideInRight 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
    
    async fetchAPI(endpoint, options = {}) {
        const response = await fetch(`${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.statusText}`);
        }
        
        return await response.json();
    }
}

// Initialize the application
const app = new NetworkScannerApp();

// Make app globally available for debugging
window.app = app;

export default app;
