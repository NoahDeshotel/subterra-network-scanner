/**
 * NetScope Pro - Advanced Network Intelligence Platform
 * 2025 Cutting-edge Network Analysis Application
 */

class NetScopeApp {
    constructor() {
        this.socket = null;
        this.currentView = 'overview';
        this.scanInProgress = false;
        this.charts = {};
        this.refreshInterval = null;
        
        this.init();
    }
    
    async init() {
        console.log('🚀 Initializing NetScope Pro...');
        
        // Initialize WebSocket connection
        this.setupWebSocket();
        
        // Setup event listeners
        this.setupEventListeners();
        
        // Initialize charts
        this.initializeCharts();
        
        // Load initial data
        await this.loadInitialData();
        
        // Start real-time updates
        this.startRealTimeUpdates();
        
        console.log('✅ NetScope Pro initialized successfully');
    }
    
    setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.hostname;
        const port = window.location.port || (window.location.protocol === 'https:' ? '443' : '80');
        
        this.socket = io({
            path: '/socket.io/',
            transports: ['websocket', 'polling']
        });
        
        this.socket.on('connect', () => {
            console.log('🔗 WebSocket connected');
            this.showToast('Connected to NetScope Pro', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('❌ WebSocket disconnected');
            this.showToast('Connection lost - attempting to reconnect...', 'warning');
        });
        
        this.socket.on('scan_progress', (data) => {
            this.updateScanProgress(data);
        });
        
        this.socket.on('device_discovered', (device) => {
            this.handleDeviceDiscovered(device);
        });
        
        this.socket.on('scan_complete', (results) => {
            this.handleScanComplete(results);
        });
        
        this.socket.on('network_alert', (alert) => {
            this.handleNetworkAlert(alert);
        });
    }
    
    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const view = item.dataset.view;
                if (view) {
                    this.switchView(view);
                    this.setActiveNavItem(item);
                }
            });
        });
        
        // Scan controls
        const scanBtn = document.getElementById('start-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => this.startQuickScan());
        }
        
        const discoveryScanBtn = document.getElementById('discovery-scan-btn');
        if (discoveryScanBtn) {
            discoveryScanBtn.addEventListener('click', () => this.startDiscoveryScan());
        }
        
        const emergencyScanBtn = document.getElementById('emergency-scan');
        if (emergencyScanBtn) {
            emergencyScanBtn.addEventListener('click', () => this.startEmergencyScan());
        }
        
        // Scan control buttons
        const pauseScanBtn = document.getElementById('pause-scan');
        if (pauseScanBtn) {
            pauseScanBtn.addEventListener('click', () => this.pauseScan());
        }
        
        const stopScanBtn = document.getElementById('stop-scan');
        if (stopScanBtn) {
            stopScanBtn.addEventListener('click', () => this.stopScan());
        }
        
        // Settings functionality
        const deleteDatabaseBtn = document.getElementById('delete-database-btn');
        if (deleteDatabaseBtn) {
            deleteDatabaseBtn.addEventListener('click', () => this.showDeleteDatabaseConfirmation());
        }
        
        // Modal functionality
        const modalCancel = document.getElementById('modal-cancel');
        const modalConfirm = document.getElementById('modal-confirm');
        if (modalCancel) {
            modalCancel.addEventListener('click', () => this.hideModal());
        }
        if (modalConfirm) {
            modalConfirm.addEventListener('click', () => this.handleModalConfirm());
        }
        
        // Timeline filters
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const period = btn.dataset.period;
                this.filterTimeline(period);
                this.setActiveFilter(btn);
            });
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
            this.currentView = viewName;
            
            // Load view-specific data
            this.loadViewData(viewName);
        }
    }
    
    setActiveNavItem(activeItem) {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        activeItem.classList.add('active');
    }
    
    setActiveFilter(activeFilter) {
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        activeFilter.classList.add('active');
    }
    
    async loadInitialData() {
        try {
            // Load network statistics
            await this.loadNetworkStatistics();
            
            // Load device data
            await this.loadDeviceData();
            
            // Load topology data
            await this.loadTopologyData();
            
            // Load security events
            await this.loadSecurityEvents();
            
        } catch (error) {
            console.error('❌ Error loading initial data:', error);
            this.showToast('Failed to load initial data', 'error');
        }
    }
    
    async loadNetworkStatistics() {
        try {
            const response = await this.apiCall('/api/statistics');
            const stats = response;
            
            // Update KPI cards
            this.updateKPICard('total-devices', stats.total_devices || stats.total_hosts || 0);
            this.updateKPICard('security-score', Math.round(stats.uptime_percentage || 95));
            this.updateKPICard('critical-vulns', stats.critical_vulnerabilities || 0);
            this.updateKPICard('network-activity', 'Normal');
            
            // Update last scan time
            if (stats.last_scan) {
                const lastScanElement = document.getElementById('last-scan-time');
                if (lastScanElement) {
                    lastScanElement.textContent = this.formatTimestamp(stats.last_scan);
                }
            }
            
            // Update device distribution chart
            if (stats.device_breakdown || stats.device_types) {
                this.updateDeviceDistributionChart(stats.device_breakdown || stats.device_types);
            }
            
        } catch (error) {
            console.error('❌ Error loading network statistics:', error);
        }
    }
    
    async loadDeviceData() {
        try {
            const response = await this.apiCall('/api/devices');
            const devices = response.devices || response || [];
            
            // Update discovery results
            this.updateDiscoveryResults({
                hostsFound: devices.length,
                newDevices: devices.filter(d => this.isRecentDevice(d)).length,
                openPorts: devices.reduce((sum, d) => sum + (d.open_ports || 0), 0),
                vulnerabilities: devices.reduce((sum, d) => sum + (d.vulnerabilities || 0), 0)
            });
            
        } catch (error) {
            console.error('❌ Error loading device data:', error);
        }
    }
    
    async loadTopologyData() {
        try {
            const response = await this.apiCall('/api/topology');
            this.renderNetworkTopology(response);
        } catch (error) {
            console.error('❌ Error loading topology data:', error);
        }
    }
    
    async loadSecurityEvents() {
        try {
            const response = await this.apiCall('/api/alerts');
            this.updateSecurityTimeline(response.alerts || []);
            this.updateActivityFeed(response.alerts || []);
        } catch (error) {
            console.error('❌ Error loading security events:', error);
        }
    }
    
    async loadViewData(viewName) {
        switch (viewName) {
            case 'overview':
                await this.loadNetworkStatistics();
                break;
            case 'discovery':
                await this.loadDiscoveryData();
                break;
            case 'topology':
                await this.loadTopologyData();
                break;
            case 'devices':
                await this.loadDeviceInventory();
                break;
            case 'vulnerabilities':
                await this.loadVulnerabilityData();
                break;
            case 'analytics':
                await this.loadAnalyticsData();
                break;
            case 'settings':
                await this.loadSettingsData();
                break;
        }
    }
    
    updateKPICard(cardId, value) {
        const element = document.getElementById(cardId);
        if (element) {
            // Animate value change
            const currentValue = parseInt(element.textContent) || 0;
            this.animateValue(element, currentValue, value);
        }
    }
    
    animateValue(element, start, end, duration = 1000) {
        const startTime = Date.now();
        const difference = end - start;
        
        const updateValue = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function for smooth animation
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(start + (difference * easeOut));
            
            element.textContent = current;
            
            if (progress < 1) {
                requestAnimationFrame(updateValue);
            } else {
                element.textContent = end;
            }
        };
        
        requestAnimationFrame(updateValue);
    }
    
    async startQuickScan() {
        if (this.scanInProgress) {
            this.showToast('Scan already in progress', 'warning');
            return;
        }
        
        try {
            const response = await this.apiCall('/api/scan/start', 'POST', {
                subnet: '10.0.0.0/24',
                scan_type: 'quick',
                aggressive: false
            });
            
            if (response.scan_id) {
                this.scanInProgress = true;
                this.showScanProgress();
                this.showToast('Quick scan started', 'success');
            }
        } catch (error) {
            console.error('❌ Error starting quick scan:', error);
            this.showToast('Failed to start scan', 'error');
        }
    }
    
    async startDiscoveryScan() {
        if (this.scanInProgress) {
            this.showToast('Scan already in progress', 'warning');
            return;
        }
        
        const subnet = document.getElementById('subnet-input')?.value || '10.0.0.0/24';
        const scanType = document.getElementById('scan-type')?.value || 'comprehensive';
        
        try {
            const response = await this.apiCall('/api/scan/start', 'POST', {
                subnet: subnet,
                scan_type: scanType,
                aggressive: scanType === 'comprehensive',
                vulnerability_scan: scanType === 'vulnerability'
            });
            
            if (response.scan_id) {
                this.scanInProgress = true;
                this.showScanProgress();
                this.showToast(`${scanType} scan started on ${subnet}`, 'success');
            }
        } catch (error) {
            console.error('❌ Error starting discovery scan:', error);
            this.showToast('Failed to start scan', 'error');
        }
    }
    
    async startEmergencyScan() {
        if (this.scanInProgress) {
            this.showToast('Emergency scan initiated - stopping current scan', 'warning');
            await this.stopScan();
        }
        
        try {
            const response = await this.apiCall('/api/scan/start', 'POST', {
                subnet: '10.0.0.0/16',
                scan_type: 'emergency',
                aggressive: true,
                vulnerability_scan: true,
                priority: 'high'
            });
            
            if (response.scan_id) {
                this.scanInProgress = true;
                this.showScanProgress();
                this.showToast('🚨 Emergency scan initiated', 'error');
            }
        } catch (error) {
            console.error('❌ Error starting emergency scan:', error);
            this.showToast('Failed to start emergency scan', 'error');
        }
    }
    
    showScanProgress() {
        const progressPanel = document.getElementById('scan-progress-panel');
        if (progressPanel) {
            progressPanel.style.display = 'block';
            progressPanel.scrollIntoView({ behavior: 'smooth' });
        }
    }
    
    updateScanProgress(data) {
        if (!data) return;
        
        // Update progress bar
        const progressFill = document.querySelector('.progress-fill');
        const progressText = document.getElementById('scan-progress-text');
        
        if (progressFill && data.progress !== undefined) {
            progressFill.style.width = `${data.progress}%`;
        }
        
        if (progressText && data.progress !== undefined) {
            progressText.textContent = `${Math.round(data.progress)}%`;
        }
        
        // Update scan stages
        if (data.stage || data.message) {
            this.updateScanStages(data);
        }
        
        // Update scan log
        if (data.log_entry || data.message) {
            this.addScanLogEntry(data);
        }
    }
    
    updateScanStages(data) {
        const stagesContainer = document.getElementById('scan-stages');
        if (!stagesContainer) return;
        
        // This would be populated with actual stage indicators
        // For now, we'll show the current stage
        const stageElement = document.createElement('div');
        stageElement.className = 'scan-stage';
        stageElement.innerHTML = `
            <div class="stage-indicator active">
                <i class="fas fa-spinner fa-spin"></i>
            </div>
            <div class="stage-content">
                <h4>${data.stage || 'Scanning'}</h4>
                <p>${data.message || 'Processing...'}</p>
            </div>
        `;
        
        stagesContainer.appendChild(stageElement);
        stageElement.scrollIntoView({ behavior: 'smooth' });
    }
    
    addScanLogEntry(data) {
        const logContainer = document.getElementById('scan-log');
        if (!logContainer) return;
        
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.innerHTML = `
            <span class="log-timestamp">${this.formatTimestamp(new Date())}</span>
            <span class="log-message">${data.log_entry || data.message}</span>
        `;
        
        logContainer.appendChild(logEntry);
        logEntry.scrollIntoView({ behavior: 'smooth' });
        
        // Keep only last 50 entries
        const entries = logContainer.querySelectorAll('.log-entry');
        if (entries.length > 50) {
            entries[0].remove();
        }
    }
    
    handleScanComplete(results) {
        this.scanInProgress = false;
        
        // Update progress to 100%
        this.updateScanProgress({ progress: 100 });
        
        // Show completion message
        this.showToast('Scan completed successfully!', 'success');
        
        // Refresh data
        this.loadInitialData();
        
        // Update discovery results
        if (results) {
            this.updateDiscoveryResults(results);
        }
    }
    
    updateDiscoveryResults(results) {
        const elements = {
            'hosts-found': results.hostsFound || 0,
            'new-devices': results.newDevices || 0,
            'open-ports': results.openPorts || 0,
            'vulnerabilities-found': results.vulnerabilities || 0
        };
        
        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateValue(element, parseInt(element.textContent) || 0, value);
            }
        });
    }
    
    handleDeviceDiscovered(device) {
        // Add visual indicator for new device
        this.showToast(`New device discovered: ${device.ip}`, 'info');
        
        // Update real-time counters
        const hostsFoundElement = document.getElementById('hosts-found');
        if (hostsFoundElement) {
            const current = parseInt(hostsFoundElement.textContent) || 0;
            this.animateValue(hostsFoundElement, current, current + 1);
        }
    }
    
    handleNetworkAlert(alert) {
        // Show alert notification
        this.showToast(alert.message, alert.severity || 'warning');
        
        // Add to activity feed
        this.addActivityFeedItem(alert);
    }
    
    initializeCharts() {
        // Device Distribution Chart
        const deviceChartCtx = document.getElementById('device-distribution-chart');
        if (deviceChartCtx) {
            this.charts.deviceDistribution = new Chart(deviceChartCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Servers', 'Workstations', 'Network Devices', 'IoT Devices'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            'rgba(0, 245, 255, 0.8)',
                            'rgba(0, 230, 118, 0.8)',
                            'rgba(255, 193, 7, 0.8)',
                            'rgba(255, 23, 68, 0.8)'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
    }
    
    updateDeviceDistributionChart(deviceTypes) {
        if (!this.charts.deviceDistribution || !deviceTypes) return;
        
        const labels = Object.keys(deviceTypes);
        const data = Object.values(deviceTypes);
        
        this.charts.deviceDistribution.data.labels = labels;
        this.charts.deviceDistribution.data.datasets[0].data = data;
        this.charts.deviceDistribution.update();
        
        // Update legend
        this.updateChartLegend('device-legend', labels, data);
    }
    
    updateChartLegend(legendId, labels, data) {
        const legendElement = document.getElementById(legendId);
        if (!legendElement) return;
        
        const colors = [
            'rgba(0, 245, 255, 0.8)',
            'rgba(0, 230, 118, 0.8)',
            'rgba(255, 193, 7, 0.8)',
            'rgba(255, 23, 68, 0.8)'
        ];
        
        legendElement.innerHTML = labels.map((label, index) => `
            <div class="legend-item">
                <div class="legend-color" style="background-color: ${colors[index % colors.length]}"></div>
                <span class="legend-label">${label}</span>
                <span class="legend-value">${data[index] || 0}</span>
            </div>
        `).join('');
    }
    
    renderNetworkTopology(topologyData) {
        const container = document.getElementById('network-topology');
        if (!container) return;
        
        if (!topologyData || !topologyData.nodes || topologyData.nodes.length === 0) {
            container.innerHTML = `
                <div class="topology-placeholder">
                    <i class="fas fa-project-diagram"></i>
                    <p>No topology data available</p>
                    <p class="text-muted">Run a network scan to discover topology</p>
                    <button class="btn-primary" onclick="window.netScope.startQuickScan()">
                        <i class="fas fa-radar"></i>
                        Start Discovery
                    </button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = `
            <div class="topology-placeholder">
                <i class="fas fa-project-diagram"></i>
                <p>Network topology visualization</p>
                <p class="text-muted">Nodes: ${topologyData.nodes.length} | Connections: ${topologyData.connections?.length || 0}</p>
                <p class="text-muted">Topology discovery in progress...</p>
            </div>
        `;
    }
    
    updateSecurityTimeline(events) {
        const container = document.getElementById('security-timeline');
        if (!container) return;
        
        if (!events || events.length === 0) {
            container.innerHTML = `
                <div class="timeline-placeholder">
                    <i class="fas fa-shield-alt"></i>
                    <p>No security events in the selected period</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = events.slice(0, 10).map(event => `
            <div class="timeline-event ${event.severity || 'info'}">
                <div class="event-time">${this.formatTimestamp(event.timestamp)}</div>
                <div class="event-content">
                    <h4>${event.title || 'Security Event'}</h4>
                    <p>${event.description || event.message}</p>
                </div>
            </div>
        `).join('');
    }
    
    updateActivityFeed(activities) {
        const container = document.getElementById('activity-feed');
        if (!container) return;
        
        if (!activities || activities.length === 0) {
            container.innerHTML = `
                <div class="activity-placeholder">
                    <i class="fas fa-activity"></i>
                    <p>No recent activity</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = activities.slice(0, 15).map(activity => `
            <div class="activity-item">
                <div class="activity-icon ${activity.type || 'info'}">
                    <i class="fas fa-${this.getActivityIcon(activity.type)}"></i>
                </div>
                <div class="activity-content">
                    <p>${activity.message}</p>
                    <span class="activity-time">${this.formatTimestamp(activity.timestamp)}</span>
                </div>
            </div>
        `).join('');
    }
    
    addActivityFeedItem(activity) {
        const container = document.getElementById('activity-feed');
        if (!container) return;
        
        const activityItem = document.createElement('div');
        activityItem.className = 'activity-item new';
        activityItem.innerHTML = `
            <div class="activity-icon ${activity.type || 'info'}">
                <i class="fas fa-${this.getActivityIcon(activity.type)}"></i>
            </div>
            <div class="activity-content">
                <p>${activity.message}</p>
                <span class="activity-time">${this.formatTimestamp(new Date())}</span>
            </div>
        `;
        
        container.insertBefore(activityItem, container.firstChild);
        
        // Remove new class after animation
        setTimeout(() => {
            activityItem.classList.remove('new');
        }, 500);
        
        // Keep only last 15 items
        const items = container.querySelectorAll('.activity-item');
        if (items.length > 15) {
            items[items.length - 1].remove();
        }
    }
    
    getActivityIcon(type) {
        const icons = {
            'scan': 'radar',
            'device': 'server',
            'security': 'shield-alt',
            'network': 'network-wired',
            'alert': 'exclamation-triangle',
            'info': 'info-circle',
            'warning': 'exclamation-triangle',
            'error': 'times-circle',
            'success': 'check-circle'
        };
        
        return icons[type] || 'circle';
    }
    
    startRealTimeUpdates() {
        // Update statistics every 30 seconds
        this.refreshInterval = setInterval(() => {
            if (this.currentView === 'overview') {
                this.loadNetworkStatistics();
            }
        }, 30000);
    }
    
    async apiCall(endpoint, method = 'GET', body = null) {
        const baseUrl = window.location.protocol + '//' + window.location.host;
        const url = baseUrl + endpoint;
        
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };
        
        if (body && method !== 'GET') {
            options.body = JSON.stringify(body);
        }
        
        try {
            const response = await fetch(url, options);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`❌ API call failed for ${endpoint}:`, error);
            throw error;
        }
    }
    
    showToast(message, type = 'info', duration = 5000) {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-content">
                <i class="fas fa-${this.getToastIcon(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="toast-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add event listener for close button
        toast.querySelector('.toast-close').addEventListener('click', () => {
            this.removeToast(toast);
        });
        
        container.appendChild(toast);
        
        // Auto remove after duration
        setTimeout(() => {
            this.removeToast(toast);
        }, duration);
        
        // Animate in
        requestAnimationFrame(() => {
            toast.classList.add('show');
        });
    }
    
    removeToast(toast) {
        toast.classList.add('removing');
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }
    
    getToastIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        
        return icons[type] || 'info-circle';
    }
    
    formatTimestamp(timestamp) {
        if (!timestamp) return '--';
        
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        // Less than 1 minute
        if (diff < 60000) {
            return 'Just now';
        }
        
        // Less than 1 hour
        if (diff < 3600000) {
            const minutes = Math.floor(diff / 60000);
            return `${minutes}m ago`;
        }
        
        // Less than 24 hours
        if (diff < 86400000) {
            const hours = Math.floor(diff / 3600000);
            return `${hours}h ago`;
        }
        
        // More than 24 hours
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    isRecentDevice(device) {
        if (!device.first_seen) return false;
        const deviceDate = new Date(device.first_seen);
        const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        return deviceDate > dayAgo;
    }
    
    filterTimeline(period) {
        // This would filter the timeline based on the selected period
        console.log(`Filtering timeline for period: ${period}`);
        // Implementation would depend on having the full timeline data
    }
    
    async pauseScan() {
        // Implementation for pausing scan
        this.showToast('Scan paused', 'warning');
    }
    
    async stopScan() {
        if (!this.scanInProgress) return;
        
        try {
            await this.apiCall('/api/scan/stop', 'POST');
            this.scanInProgress = false;
            this.showToast('Scan stopped', 'warning');
            
            // Hide progress panel
            const progressPanel = document.getElementById('scan-progress-panel');
            if (progressPanel) {
                progressPanel.style.display = 'none';
            }
        } catch (error) {
            console.error('❌ Error stopping scan:', error);
            this.showToast('Failed to stop scan', 'error');
        }
    }
    
    // Additional methods for other views would be implemented here
    async loadDiscoveryData() {
        try {
            // Show the scan progress panel but hide it if no scan is running
            const progressPanel = document.getElementById('scan-progress-panel');
            if (progressPanel && !this.scanInProgress) {
                progressPanel.style.display = 'none';
            }
            
            // Load recent scan results
            await this.loadDeviceData();
        } catch (error) {
            console.error('❌ Error loading discovery data:', error);
        }
    }
    
    async loadDeviceInventory() {
        try {
            const response = await this.apiCall('/api/devices');
            const devices = response.devices || [];
            
            // Create device inventory table
            this.renderDeviceInventoryTable(devices);
            
        } catch (error) {
            console.error('❌ Error loading device inventory:', error);
            this.showToast('Failed to load device inventory', 'error');
        }
    }
    
    async loadVulnerabilityData() {
        try {
            // Load vulnerability data
            const statsResponse = await this.apiCall('/api/statistics');
            const alertsResponse = await this.apiCall('/api/alerts');
            
            this.renderVulnerabilityDashboard(statsResponse, alertsResponse);
            
        } catch (error) {
            console.error('❌ Error loading vulnerability data:', error);
            this.showToast('Failed to load vulnerability data', 'error');
        }
    }
    
    async loadAnalyticsData() {
        try {
            const [statsResponse, devicesResponse] = await Promise.all([
                this.apiCall('/api/statistics'),
                this.apiCall('/api/devices')
            ]);
            
            this.renderAnalyticsDashboard(statsResponse, devicesResponse);
            
        } catch (error) {
            console.error('❌ Error loading analytics data:', error);
            this.showToast('Failed to load analytics data', 'error');
        }
    }
    
    renderDeviceInventoryTable(devices) {
        const devicesView = document.getElementById('devices-view');
        if (!devicesView) return;
        
        const tableHTML = `
            <div class="view-header">
                <h2>Device Inventory</h2>
                <div class="inventory-controls">
                    <input type="text" id="device-search" placeholder="Search devices..." class="glass-input">
                    <select id="device-filter" class="glass-select">
                        <option value="">All Types</option>
                        <option value="server">Servers</option>
                        <option value="router">Routers</option>
                        <option value="workstation">Workstations</option>
                        <option value="unknown">Unknown</option>
                    </select>
                </div>
            </div>
            
            <div class="inventory-stats">
                <div class="stat-item">
                    <span class="stat-value">${devices.length}</span>
                    <span class="stat-label">Total Devices</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${devices.filter(d => d.status === 'active').length}</span>
                    <span class="stat-label">Active</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${new Set(devices.map(d => d.device_type)).size}</span>
                    <span class="stat-label">Device Types</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value">${devices.filter(d => d.os).length}</span>
                    <span class="stat-label">Identified OS</span>
                </div>
            </div>
            
            <div class="devices-table-container">
                <table class="devices-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Type</th>
                            <th>OS</th>
                            <th>MAC Address</th>
                            <th>Last Seen</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${devices.map(device => `
                            <tr class="device-row ${device.status}">
                                <td class="device-ip">${device.ip}</td>
                                <td class="device-hostname">${device.hostname || 'Unknown'}</td>
                                <td class="device-type">
                                    <span class="type-badge ${device.device_type}">${device.device_type}</span>
                                </td>
                                <td class="device-os">${device.os ? device.os.substring(0, 30) + '...' : 'Unknown'}</td>
                                <td class="device-mac">${device.mac_address || 'Unknown'}</td>
                                <td class="device-last-seen">${this.formatTimestamp(device.last_seen)}</td>
                                <td class="device-status">
                                    <span class="status-indicator ${device.status}">${device.status}</span>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
        
        devicesView.innerHTML = tableHTML;
    }
    
    renderVulnerabilityDashboard(stats, alerts) {
        const vulnView = document.getElementById('vulnerabilities-view');
        if (!vulnView) return;
        
        const dashboardHTML = `
            <div class="view-header">
                <h2>Security Dashboard</h2>
                <div class="security-actions">
                    <button class="btn-primary" id="run-security-scan">
                        <i class="fas fa-shield-alt"></i>
                        Security Scan
                    </button>
                </div>
            </div>
            
            <div class="security-overview">
                <div class="security-metric critical">
                    <div class="metric-icon">
                        <i class="fas fa-exclamation-circle"></i>
                    </div>
                    <div class="metric-content">
                        <span class="metric-value">${stats.critical_vulnerabilities || 0}</span>
                        <span class="metric-label">Critical</span>
                    </div>
                </div>
                <div class="security-metric high">
                    <div class="metric-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="metric-content">
                        <span class="metric-value">${stats.high_vulnerabilities || 0}</span>
                        <span class="metric-label">High</span>
                    </div>
                </div>
                <div class="security-metric medium">
                    <div class="metric-icon">
                        <i class="fas fa-exclamation"></i>
                    </div>
                    <div class="metric-content">
                        <span class="metric-value">${stats.medium_vulnerabilities || 0}</span>
                        <span class="metric-label">Medium</span>
                    </div>
                </div>
                <div class="security-metric low">
                    <div class="metric-icon">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="metric-content">
                        <span class="metric-value">${stats.low_vulnerabilities || 0}</span>
                        <span class="metric-label">Low</span>
                    </div>
                </div>
            </div>
            
            <div class="security-alerts">
                <h3>Recent Security Events</h3>
                <div class="alerts-container">
                    ${alerts.length ? alerts.map(alert => `
                        <div class="alert-item ${alert.severity}">
                            <div class="alert-icon">
                                <i class="fas fa-${this.getAlertIcon(alert.severity)}"></i>
                            </div>
                            <div class="alert-content">
                                <h4>${alert.title}</h4>
                                <p>${alert.description}</p>
                                <span class="alert-time">${this.formatTimestamp(alert.timestamp)}</span>
                            </div>
                        </div>
                    `).join('') : '<p class="no-alerts">No security alerts at this time</p>'}
                </div>
            </div>
        `;
        
        vulnView.innerHTML = dashboardHTML;
    }
    
    renderAnalyticsDashboard(stats, devicesResponse) {
        const analyticsView = document.getElementById('analytics-view');
        if (!analyticsView) return;
        
        const devices = devicesResponse.devices || [];
        
        const dashboardHTML = `
            <div class="view-header">
                <h2>Network Analytics</h2>
            </div>
            
            <div class="analytics-grid">
                <div class="analytics-card">
                    <h3>Device Distribution</h3>
                    <canvas id="analytics-device-chart"></canvas>
                </div>
                
                <div class="analytics-card">
                    <h3>Operating Systems</h3>
                    <div class="os-breakdown">
                        ${this.generateOSBreakdown(devices)}
                    </div>
                </div>
                
                <div class="analytics-card">
                    <h3>Network Activity</h3>
                    <div class="activity-metrics">
                        <div class="activity-metric">
                            <span class="metric-label">Total Devices</span>
                            <span class="metric-value">${devices.length}</span>
                        </div>
                        <div class="activity-metric">
                            <span class="metric-label">Active Connections</span>
                            <span class="metric-value">${devices.filter(d => d.status === 'active').length}</span>
                        </div>
                        <div class="activity-metric">
                            <span class="metric-label">Recent Changes</span>
                            <span class="metric-value">${stats.recent_changes_24h || 0}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        analyticsView.innerHTML = dashboardHTML;
        
        // Initialize analytics charts
        this.initializeAnalyticsCharts(stats);
    }
    
    generateOSBreakdown(devices) {
        const osCount = {};
        devices.forEach(device => {
            const os = device.os ? device.os.split(' ')[0] : 'Unknown';
            osCount[os] = (osCount[os] || 0) + 1;
        });
        
        return Object.entries(osCount).map(([os, count]) => `
            <div class="os-item">
                <span class="os-name">${os}</span>
                <span class="os-count">${count}</span>
                <div class="os-bar">
                    <div class="os-bar-fill" style="width: ${(count / devices.length * 100)}%"></div>
                </div>
            </div>
        `).join('');
    }
    
    initializeAnalyticsCharts(stats) {
        const analyticsChartCtx = document.getElementById('analytics-device-chart');
        if (analyticsChartCtx && stats.device_breakdown) {
            const labels = Object.keys(stats.device_breakdown);
            const data = Object.values(stats.device_breakdown);
            
            new Chart(analyticsChartCtx, {
                type: 'pie',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: [
                            'rgba(0, 245, 255, 0.8)',
                            'rgba(0, 230, 118, 0.8)',
                            'rgba(255, 193, 7, 0.8)',
                            'rgba(255, 23, 68, 0.8)',
                            'rgba(156, 39, 176, 0.8)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
    }
    
    getAlertIcon(severity) {
        const icons = {
            'critical': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle',
            'low': 'check-circle'
        };
        return icons[severity] || 'info-circle';
    }
    
    async loadSettingsData() {
        try {
            // Check backend status
            await this.checkBackendStatus();
            
            // Load current settings
            this.loadCurrentSettings();
            
        } catch (error) {
            console.error('❌ Error loading settings data:', error);
            this.showToast('Failed to load settings', 'error');
        }
    }
    
    async checkBackendStatus() {
        try {
            const response = await this.apiCall('/api/status');
            const statusElement = document.getElementById('backend-status');
            if (statusElement) {
                statusElement.textContent = 'Connected';
                statusElement.className = 'status-badge connected';
            }
        } catch (error) {
            const statusElement = document.getElementById('backend-status');
            if (statusElement) {
                statusElement.textContent = 'Disconnected';
                statusElement.className = 'status-badge disconnected';
            }
        }
    }
    
    loadCurrentSettings() {
        // Load default subnet from localStorage or use default
        const defaultSubnet = localStorage.getItem('defaultSubnet') || '10.0.0.0/24';
        const scanTimeout = localStorage.getItem('scanTimeout') || '300';
        
        const subnetInput = document.getElementById('default-subnet');
        const timeoutInput = document.getElementById('scan-timeout');
        
        if (subnetInput) subnetInput.value = defaultSubnet;
        if (timeoutInput) timeoutInput.value = scanTimeout;
        
        // Add event listeners for settings changes
        if (subnetInput) {
            subnetInput.addEventListener('change', () => {
                localStorage.setItem('defaultSubnet', subnetInput.value);
                this.showToast('Default subnet updated', 'success');
            });
        }
        
        if (timeoutInput) {
            timeoutInput.addEventListener('change', () => {
                localStorage.setItem('scanTimeout', timeoutInput.value);
                this.showToast('Scan timeout updated', 'success');
            });
        }
    }
    
    showDeleteDatabaseConfirmation() {
        this.currentModalAction = 'deleteDatabase';
        this.showModal(
            'Delete Database',
            'This action will permanently delete all devices, scan history, and configuration data. This action cannot be undone. Are you sure you want to continue?'
        );
    }
    
    showModal(title, message) {
        const modal = document.getElementById('confirmation-modal');
        const titleElement = document.getElementById('modal-title');
        const messageElement = document.getElementById('modal-message');
        
        if (modal && titleElement && messageElement) {
            titleElement.textContent = title;
            messageElement.textContent = message;
            modal.classList.add('show');
        }
    }
    
    hideModal() {
        const modal = document.getElementById('confirmation-modal');
        if (modal) {
            modal.classList.remove('show');
        }
    }
    
    async handleModalConfirm() {
        if (this.currentModalAction === 'deleteDatabase') {
            await this.deleteDatabase();
        }
        this.hideModal();
    }
    
    async deleteDatabase() {
        try {
            this.showToast('Deleting database...', 'info');
            
            // Call backend API to delete database
            const response = await this.apiCall('/api/database/clear', 'POST');
            
            if (response.success) {
                this.showToast('Database cleared successfully', 'success');
                
                // Refresh the page to show empty state
                setTimeout(() => {
                    window.location.reload();
                }, 2000);
            } else {
                this.showToast('Failed to clear database', 'error');
            }
            
        } catch (error) {
            console.error('❌ Error deleting database:', error);
            this.showToast('Failed to clear database', 'error');
        }
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.netScope = new NetScopeApp();
});

// Export for use in other modules
export default NetScopeApp;
