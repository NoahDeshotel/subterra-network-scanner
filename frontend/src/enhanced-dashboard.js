/**
 * Enhanced Dashboard Module - Netdisco-Inspired UI
 * Advanced network visualization and management capabilities
 */

import Chart from 'chart.js/auto';

class EnhancedDashboard {
    constructor() {
        this.charts = new Map();
        this.websocket = null;
        this.devices = new Map();
        this.topology = { nodes: [], connections: [] };
        this.realTimeUpdates = true;
        this.currentView = 'dashboard';
        
        // API Configuration
        this.apiBaseUrl = this.getApiBaseUrl();
        
        // Enhanced chart configurations
        this.chartConfigs = {
            deviceTypes: {
                type: 'doughnut',
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { usePointStyle: true, color: '#ffffff' }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = Math.round((value / total) * 100);
                                    return `${label}: ${value} devices (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            },
            discoveryMethods: {
                type: 'bar',
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true, ticks: { color: '#ffffff' } },
                        x: { ticks: { color: '#ffffff' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#ffffff' } },
                        tooltip: {
                            callbacks: {
                                title: function(context) {
                                    return `Discovery Method: ${context[0].label}`;
                                },
                                label: function(context) {
                                    return `Devices discovered: ${context.parsed.y}`;
                                }
                            }
                        }
                    }
                }
            },
            changeTimeline: {
                type: 'line',
                options: {
                    responsive: true,
                    interaction: { intersect: false },
                    scales: {
                        x: { 
                            type: 'time',
                            time: { unit: 'hour' },
                            ticks: { color: '#ffffff' }
                        },
                        y: { 
                            beginAtZero: true,
                            ticks: { color: '#ffffff' }
                        }
                    },
                    plugins: {
                        legend: { labels: { color: '#ffffff' } }
                    }
                }
            },
            riskDistribution: {
                type: 'radar',
                options: {
                    responsive: true,
                    scales: {
                        r: {
                            beginAtZero: true,
                            ticks: { color: '#ffffff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    },
                    plugins: {
                        legend: { labels: { color: '#ffffff' } }
                    }
                }
            }
        };
        
        this.init();
    }
    
    getApiBaseUrl() {
        /**
         * Determine the correct API base URL based on environment
         */
        // Check if we're running in Docker (frontend container proxies to backend)
        if (window.location.port === '80' || window.location.port === '') {
            // In Docker, nginx proxies API calls - use same host
            return `${window.location.protocol}//${window.location.host}`;
        } else {
            // In development, API is on port 8080
            return `${window.location.protocol}//${window.location.hostname}:8080`;
        }
    }
    
    async apiCall(endpoint, options = {}) {
        /**
         * Make API call with proper base URL
         */
        const url = `${this.apiBaseUrl}${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
        };
        
        const finalOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, finalOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error);
            throw error;
        }
    }
    
    init() {
        console.log('🚀 Initializing Enhanced Dashboard...');
        
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.initializeComponents();
            });
        } else {
            this.initializeComponents();
        }
    }
    
    initializeComponents() {
        console.log('🔧 Initializing Enhanced Dashboard Components...');
        console.log(`🌐 API Base URL: ${this.apiBaseUrl}`);
        
        this.setupWebSocket();
        this.initializeCharts();
        this.setupEventListeners();
        this.loadInitialData();
        this.startPeriodicUpdates();
        
        console.log('✅ Enhanced Dashboard Ready');
    }
    
    setupWebSocket() {
        /**
         * Setup WebSocket connection for real-time updates
         */
        try {
            // Use the same host as API for WebSocket (nginx will proxy)
            const wsUrl = this.apiBaseUrl;
            console.log(`🔌 Connecting to WebSocket at: ${wsUrl}`);
            
            this.websocket = io(wsUrl, {
                transports: ['websocket', 'polling'],
                upgrade: true,
                rememberUpgrade: true,
                path: '/socket.io/'
            });
            
            this.websocket.on('connect', () => {
                console.log('🔌 WebSocket connected');
                this.websocket.emit('subscribe_updates', { type: 'all' });
            });
            
            this.websocket.on('disconnect', () => {
                console.log('🔌 WebSocket disconnected');
            });
            
            this.websocket.on('connect_error', (error) => {
                console.error('🔌 WebSocket connection error:', error);
                this.showNotification('Connection Error', 'Failed to connect to server. Please check if the backend is running.', 'error');
            });
            
            this.websocket.on('error', (error) => {
                console.error('🔌 WebSocket error:', error);
            });
            
            this.websocket.on('scan_started', (data) => {
                this.handleScanStarted(data);
            });
            
            this.websocket.on('scan_progress', (data) => {
                this.handleScanProgress(data);
            });
            
            this.websocket.on('scan_completed', (data) => {
                this.handleScanCompleted(data);
            });
            
            this.websocket.on('scan_failed', (data) => {
                this.handleScanFailed(data);
            });
            
            this.websocket.on('stats_update', (data) => {
                this.updateStatistics(data);
            });
            
            this.websocket.on('device_change', (data) => {
                this.handleDeviceChange(data);
            });
            
        } catch (error) {
            console.error('WebSocket setup failed:', error);
        }
    }
    
    initializeCharts() {
        /**
         * Initialize all dashboard charts (aligned with HTML IDs)
         */
        this.createVulnChart();
        this.createPortChart();
        this.createOsChart();
        this.createTimelineChart();
    }
    
    createVulnChart() {
        const canvas = document.getElementById('vuln-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#f44336', '#ff9800', '#ffc107', '#8bc34a'],
                    borderColor: '#ffffff',
                    borderWidth: 2
                }]
            },
            options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
        });
        this.charts.set('vuln', chart);
    }
    
    createPortChart() {
        const canvas = document.getElementById('port-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Open Ports per Host',
                    data: [],
                    backgroundColor: 'rgba(33, 150, 243, 0.6)',
                    borderColor: '#2196F3',
                    borderWidth: 1
                }]
            },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
        this.charts.set('ports', chart);
    }
    
    createTimelineChart() {
        const canvas = document.getElementById('timeline-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: 'New Devices', data: [], borderColor: '#4CAF50', backgroundColor: 'rgba(76,175,80,0.1)', tension: 0.4 },
                    { label: 'Config Changes', data: [], borderColor: '#FF9800', backgroundColor: 'rgba(255,152,0,0.1)', tension: 0.4 },
                    { label: 'Service Changes', data: [], borderColor: '#2196F3', backgroundColor: 'rgba(33,150,243,0.1)', tension: 0.4 }
                ]
            },
            options: { responsive: true }
        });
        this.charts.set('timeline', chart);
    }
    
    createOsChart() {
        const canvas = document.getElementById('os-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{ data: [], backgroundColor: ['#03A9F4','#4CAF50','#FFC107','#9C27B0','#795548','#607D8B'], borderColor: '#ffffff' }]
            },
            options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
        });
        this.charts.set('os', chart);
    }
    
    createTopologyVisualization() {
        /**
         * Create interactive network topology visualization
         */
        const container = document.getElementById('topology-container');
        if (!container) return;
        
        // This would implement a more sophisticated topology visualization
        // Using libraries like D3.js, Cytoscape.js, or custom WebGL
        container.innerHTML = `
            <div class="topology-controls">
                <button id="topology-refresh" class="btn btn-sm">
                    <i class="fas fa-sync"></i> Refresh
                </button>
                <button id="topology-layout" class="btn btn-sm">
                    <i class="fas fa-project-diagram"></i> Auto Layout
                </button>
                <select id="topology-filter">
                    <option value="all">All Devices</option>
                    <option value="routers">Routers Only</option>
                    <option value="switches">Switches Only</option>
                    <option value="servers">Servers Only</option>
                </select>
            </div>
            <div id="topology-canvas" class="topology-canvas">
                <div class="topology-placeholder">
                    <i class="fas fa-network-wired"></i>
                    <p>Loading network topology...</p>
                </div>
            </div>
        `;
        
        this.setupTopologyControls();
    }
    
    setupTopologyControls() {
        /**
         * Setup topology visualization controls
         */
        const refreshBtn = document.getElementById('topology-refresh');
        const layoutBtn = document.getElementById('topology-layout');
        const filterSelect = document.getElementById('topology-filter');
        
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.refreshTopology();
            });
        }
        
        if (layoutBtn) {
            layoutBtn.addEventListener('click', () => {
                this.applyAutoLayout();
            });
        }
        
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                this.filterTopology(e.target.value);
            });
        }
    }
    
    setupEventListeners() {
        /**
         * Setup enhanced event listeners
         */
        
        // Enhanced scan button
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => {
                this.showEnhancedScanDialog();
            });
        }
        
        // Real-time updates toggle
        const realtimeToggle = document.getElementById('realtime-toggle');
        if (realtimeToggle) {
            realtimeToggle.addEventListener('change', (e) => {
                this.realTimeUpdates = e.target.checked;
            });
        }
        
        // View switching
        document.querySelectorAll('[data-view]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchView(e.target.dataset.view);
            });
        });
        
        // Device search
        const deviceSearch = document.getElementById('device-search');
        if (deviceSearch) {
            deviceSearch.addEventListener('input', (e) => {
                this.searchDevices(e.target.value);
            });
        }
        
        // Export functionality
        const exportBtn = document.getElementById('export-data');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.showExportDialog();
            });
        }
    }
    
    showEnhancedScanDialog() {
        /**
         * Show enhanced scan configuration dialog
         */
        const dialog = document.createElement('div');
        dialog.className = 'modal enhanced-scan-modal';
        dialog.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2><i class="fas fa-radar"></i> Enhanced Network Scan</h2>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="scan-config-grid">
                        <div class="config-section">
                            <h3>Target Configuration</h3>
                            <div class="form-group">
                                <label for="scan-subnet">Subnet</label>
                                <input type="text" id="scan-subnet" value="auto" placeholder="e.g., 192.168.1.0/24">
                                <small>Use 'auto' to detect local subnet automatically</small>
                            </div>
                        </div>
                        
                        <div class="config-section">
                            <h3>Discovery Methods</h3>
                            <div class="form-group">
                                <label><input type="checkbox" id="enable-snmp" checked> SNMP Discovery</label>
                                <label><input type="checkbox" id="enable-nmap" checked> Nmap Scanning</label>
                                <label><input type="checkbox" id="enable-arp" checked> ARP Table Scan</label>
                                <label><input type="checkbox" id="topology-discovery" checked> Topology Discovery</label>
                            </div>
                        </div>
                        
                        <div class="config-section">
                            <h3>Scan Depth</h3>
                            <div class="form-group">
                                <label><input type="radio" name="scan-depth" value="quick" checked> Quick Scan</label>
                                <label><input type="radio" name="scan-depth" value="standard"> Standard Scan</label>
                                <label><input type="radio" name="scan-depth" value="deep"> Deep Scan (All Ports)</label>
                                <label><input type="checkbox" id="vulnerability-scan" checked> Include Vulnerability Scan</label>
                            </div>
                        </div>
                        
                        <div class="config-section">
                            <h3>SNMP Configuration</h3>
                            <div class="form-group">
                                <label for="snmp-communities">Communities (comma-separated)</label>
                                <input type="text" id="snmp-communities" value="public,private" placeholder="public,private,community">
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary modal-cancel">Cancel</button>
                    <button class="btn btn-primary scan-start">
                        <i class="fas fa-play"></i> Start Enhanced Scan
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(dialog);
        
        // Event listeners for modal
        dialog.querySelector('.modal-close').addEventListener('click', () => {
            document.body.removeChild(dialog);
        });
        
        dialog.querySelector('.modal-cancel').addEventListener('click', () => {
            document.body.removeChild(dialog);
        });
        
        dialog.querySelector('.scan-start').addEventListener('click', () => {
            this.startEnhancedScan(dialog);
        });
        
        dialog.style.display = 'block';
    }
    
    startEnhancedScan(dialog) {
        /**
         * Start enhanced network scan with configuration
         */
        const config = {
            subnet: dialog.querySelector('#scan-subnet').value,
            snmp_enabled: dialog.querySelector('#enable-snmp').checked,
            nmap_enabled: dialog.querySelector('#enable-nmap').checked,
            arp_enabled: dialog.querySelector('#enable-arp').checked,
            topology_discovery: dialog.querySelector('#topology-discovery').checked,
            vulnerability_scan: dialog.querySelector('#vulnerability-scan').checked,
            scan_depth: dialog.querySelector('input[name="scan-depth"]:checked').value,
            snmp_communities: dialog.querySelector('#snmp-communities').value.split(',').map(s => s.trim())
        };
        
        // Close dialog
        document.body.removeChild(dialog);
        
        // Show scan progress
        this.showScanProgress();
        
        // Start scan via API
        this.apiCall('/api/scan/start', {
            method: 'POST',
            body: JSON.stringify(config)
        })
        .then(data => {
            if (data.success) {
                console.log('Enhanced scan started:', data.scan_id);
            } else {
                this.showError('Failed to start scan: ' + data.error);
                this.hideScanProgress();
            }
        })
        .catch(error => {
            console.error('Scan start error:', error);
            this.showError('Failed to start scan: ' + error.message);
            this.hideScanProgress();
        });
    }
    
    showScanProgress() {
        /**
         * Show enhanced scan progress indicator
         */
        const progressContainer = document.getElementById('scan-progress');
        if (progressContainer) {
            progressContainer.classList.remove('hidden');
            progressContainer.innerHTML = `
                <div class="scan-progress-content">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 0%"></div>
                    </div>
                    <div class="progress-details">
                        <span class="progress-text">Initializing scan...</span>
                        <span class="progress-percentage">0%</span>
                    </div>
                    <div class="progress-stages">
                        <div class="stage" data-stage="discovery">Discovery</div>
                        <div class="stage" data-stage="scanning">Scanning</div>
                        <div class="stage" data-stage="analysis">Analysis</div>
                        <div class="stage" data-stage="inventory">Inventory</div>
                    </div>
                </div>
            `;
        }
    }
    
    updateScanProgress(data) {
        /**
         * Update scan progress display
         */
        const progressFill = document.querySelector('.progress-fill');
        const progressText = document.querySelector('.progress-text');
        const progressPercentage = document.querySelector('.progress-percentage');
        
        if (progressFill) {
            progressFill.style.width = `${data.progress}%`;
        }
        
        if (progressText) {
            progressText.textContent = data.message || 'Scanning...';
        }
        
        if (progressPercentage) {
            progressPercentage.textContent = `${data.progress}%`;
        }
        
        // Update stage indicators
        const stages = ['discovery', 'scanning', 'analysis', 'inventory'];
        const currentStageIndex = Math.floor(data.progress / 25);
        
        stages.forEach((stage, index) => {
            const stageElement = document.querySelector(`[data-stage="${stage}"]`);
            if (stageElement) {
                stageElement.classList.toggle('active', index === currentStageIndex);
                stageElement.classList.toggle('completed', index < currentStageIndex);
            }
        });
    }
    
    hideScanProgress() {
        const progressContainer = document.getElementById('scan-progress');
        if (progressContainer) {
            progressContainer.classList.add('hidden');
        }
    }
    
    loadInitialData() {
        /**
         * Load initial dashboard data
         */
        Promise.all([
            this.apiCall('/api/statistics/enhanced'),
            this.apiCall('/api/devices'),
            this.apiCall('/api/topology'),
            this.apiCall('/api/changes?hours=24')
        ])
        .then(([stats, devices, topology, changes]) => {
            this.updateStatistics(stats);
            this.updateDevicesData(devices);
            this.updateTopology(topology);
            this.updateChanges(changes);
        })
        .catch(error => {
            console.error('Failed to load initial data:', error);
        });
    }
    
    updateStatistics(stats) {
        /**
         * Update dashboard statistics
         */
        // Update stat cards using correct HTML IDs
        this.updateStatCard('total-hosts', stats.total_devices || 0);
        this.updateStatCard('critical-vulns', stats.critical_vulnerabilities || 0);
        this.updateStatCard('open-ports', stats.port_statistics?.total_open_ports || 0);
        this.updateStatCard('security-score', Math.round(stats.uptime_percentage || 0));
        // Update vulnerability chart
        this.updateVulnChart(stats);
    }

    updateVulnChart(stats) {
        const chart = this.charts.get('vuln');
        if (!chart) return;
        const crit = stats.critical_vulnerabilities || 0;
        const high = stats.high_vulnerabilities || 0;
        const med  = stats.medium_vulnerabilities || 0;
        const low  = stats.low_vulnerabilities || 0;
        chart.data.datasets[0].data = [crit, high, med, low];
        chart.update();
    }

    updatePortChartFromDevices(devices) {
        const chart = this.charts.get('ports');
        if (!chart) return;
        const labels = [];
        const data = [];
        devices.slice(0, 20).forEach(d => {
            labels.push(d.ip);
            data.push(d.open_ports || 0);
        });
        chart.data.labels = labels;
        chart.data.datasets[0].data = data;
        chart.update();
    }

    updateOsChartFromDevices(devices) {
        const chart = this.charts.get('os');
        if (!chart) return;
        const counts = {};
        devices.forEach(d => {
            const key = (d.os || 'Unknown').trim() || 'Unknown';
            counts[key] = (counts[key] || 0) + 1;
        });
        chart.data.labels = Object.keys(counts);
        chart.data.datasets[0].data = Object.values(counts);
        chart.update();
    }

    updateTimelineFromChanges(changes) {
        const chart = this.charts.get('timeline');
        if (!chart) return;
        // Group by hour
        const byHour = {};
        changes.forEach(c => {
            const ts = new Date(c.timestamp);
            const key = `${ts.getHours()}:00`;
            byHour[key] = byHour[key] || { new_device: 0, config: 0, service: 0 };
            if (c.change_type === 'new_device') byHour[key].new_device++;
            else if (c.change_type === 'service_changed') byHour[key].service++;
            else byHour[key].config++;
        });
        const labels = Object.keys(byHour).sort((a,b)=>parseInt(a)-parseInt(b));
        chart.data.labels = labels;
        chart.data.datasets[0].data = labels.map(k => byHour[k].new_device);
        chart.data.datasets[1].data = labels.map(k => byHour[k].config);
        chart.data.datasets[2].data = labels.map(k => byHour[k].service);
        chart.update();
    }

    updateDevicesData(devicesPayload) {
        /**
         * Populate inventory table and update charts from /api/devices
         */
        const devices = devicesPayload?.devices || [];
        // Inventory table
        const tbody = document.getElementById('inventory-tbody');
        if (tbody) {
            tbody.innerHTML = '';
            devices.forEach(d => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${d.ip || ''}</td>
                    <td>${d.hostname || ''}</td>
                    <td>${d.mac_address || ''}</td>
                    <td>${d.os || ''}</td>
                    <td>${d.open_ports || 0}</td>
                    <td>${d.vulnerabilities || 0}</td>
                    <td>${d.risk_level || 'normal'}</td>
                    <td>${d.last_seen || ''}</td>
                    <td><button class="btn btn-xs" data-ip="${d.ip}">Details</button></td>
                `;
                tbody.appendChild(tr);
            });
        }
        // Charts
        this.updatePortChartFromDevices(devices);
        this.updateOsChartFromDevices(devices);
    }

    updateChanges(changes) {
        /**
         * Render recent changes and update timeline chart
         */
        const container = document.getElementById('alerts-container');
        if (container && Array.isArray(changes)) {
            container.innerHTML = '';
            changes.slice(0, 10).forEach(c => {
                const div = document.createElement('div');
                div.className = `alert-item ${c.severity || 'info'}`;
                div.innerHTML = `
                    <div class="alert-icon"><i class="fas fa-bell"></i></div>
                    <div class="alert-content">
                        <div class="alert-title">${c.change_type || 'change'}</div>
                        <div class="alert-desc">${c.description || ''}</div>
                        <div class="alert-meta">${c.device_ip || ''} • ${c.timestamp || ''}</div>
                    </div>
                `;
                container.appendChild(div);
            });
        }
        this.updateTimelineFromChanges(changes || []);
    }
    
    updateDeviceTypesChart(breakdown) {
        const chart = this.charts.get('deviceTypes');
        if (!chart) return;
        
        chart.data.datasets[0].data = [
            breakdown.servers || 0,
            breakdown.workstations || 0,
            breakdown.routers + breakdown.switches || 0,
            breakdown.iot || 0,
            breakdown.unknown || 0
        ];
        
        chart.update();
    }
    
    updateDiscoveryMethodsChart(methods) {
        const chart = this.charts.get('discoveryMethods');
        if (!chart) return;
        
        // This would be based on actual discovery method statistics
        chart.data.datasets[0].data = [
            methods.snmp || 0,
            methods.nmap || 0,
            methods.arp || 0,
            methods.dns || 0,
            methods.manual || 0
        ];
        
        chart.update();
    }
    
    updateStatCard(cardId, value, change = null) {
        /**
         * Update a statistics card with animation
         */
        const valueElement = document.getElementById(cardId);
        if (!valueElement) return;
        
        const currentValue = parseInt(valueElement.textContent) || 0;
        const targetValue = parseInt(value) || 0;
        
        this.animateNumber(valueElement, currentValue, targetValue, 1000);
        
        if (change !== null) {
            const changeElement = valueElement.parentElement.querySelector('.stat-change');
            if (changeElement) {
                const changeText = change >= 0 ? `+${change}` : `${change}`;
                changeElement.textContent = `${changeText} from last scan`;
                changeElement.className = `stat-change ${change >= 0 ? 'positive' : 'negative'}`;
            }
        }
    }
    
    animateNumber(element, start, end, duration) {
        /**
         * Animate number changes with easing
         */
        const startTime = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            const current = Math.round(start + (end - start) * easeOutQuart);
            
            element.textContent = current.toLocaleString();
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    }
    
    // WebSocket event handlers
    handleScanStarted(data) {
        console.log('Scan started:', data.scan_id);
        this.showNotification('Scan started', 'Enhanced network scan in progress', 'info');
    }
    
    handleScanProgress(data) {
        this.updateScanProgress(data);
    }
    
    handleScanCompleted(data) {
        console.log('Scan completed:', data);
        this.hideScanProgress();
        this.showNotification('Scan completed', `Discovered ${data.results.devices_discovered} devices`, 'success');
        
        // Refresh dashboard data
        this.loadInitialData();
    }
    
    handleScanFailed(data) {
        console.error('Scan failed:', data);
        this.hideScanProgress();
        this.showNotification('Scan failed', data.error, 'error');
    }
    
    handleDeviceChange(data) {
        console.log('Device change detected:', data);
        
        // Update real-time if enabled
        if (this.realTimeUpdates) {
            this.showNotification('Device Change', `${data.change_type} on ${data.device_ip}`, 'warning');
        }
    }
    
    showNotification(title, message, type = 'info') {
        /**
         * Show enhanced toast notification
         */
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <div class="notification-icon">
                    <i class="fas ${this.getNotificationIcon(type)}"></i>
                </div>
                <div class="notification-text">
                    <div class="notification-title">${title}</div>
                    <div class="notification-message">${message}</div>
                </div>
                <button class="notification-close">&times;</button>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        notification.querySelector('.notification-close').addEventListener('click', () => {
            document.body.removeChild(notification);
        });
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (document.body.contains(notification)) {
                document.body.removeChild(notification);
            }
        }, 5000);
    }
    
    getNotificationIcon(type) {
        const icons = {
            'info': 'fa-info-circle',
            'success': 'fa-check-circle',
            'warning': 'fa-exclamation-triangle',
            'error': 'fa-times-circle'
        };
        return icons[type] || icons.info;
    }
    
    startPeriodicUpdates() {
        /**
         * Start periodic data updates (fallback for WebSocket)
         */
        setInterval(() => {
            if (!this.websocket || this.websocket.disconnected) {
                // Fallback to polling if WebSocket is not available
                this.loadInitialData();
            }
        }, 30000); // Update every 30 seconds
    }
    
    switchView(viewName) {
        /**
         * Switch between different dashboard views
         */
        // Hide all views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.remove('active');
        });
        
        // Show selected view
        const targetView = document.getElementById(`${viewName}-view`);
        if (targetView) {
            targetView.classList.add('active');
        }
        
        // Update navigation
        document.querySelectorAll('[data-view]').forEach(btn => {
            btn.classList.remove('active');
        });
        
        document.querySelector(`[data-view="${viewName}"]`)?.classList.add('active');
        
        this.currentView = viewName;
        
        // Load view-specific data
        this.loadViewData(viewName);
    }
    
    loadViewData(viewName) {
        /**
         * Load data specific to the current view
         */
        switch (viewName) {
            case 'topology':
                this.refreshTopology();
                break;
            case 'inventory':
                this.loadInventoryData();
                break;
            case 'changes':
                this.loadChangesData();
                break;
            default:
                // Dashboard view - already loaded
                break;
        }
    }
    
    refreshTopology() {
        this.apiCall('/api/topology')
            .then(data => this.updateTopology(data))
            .catch(error => console.error('Failed to load topology:', error));
    }
    
    updateTopology(topologyData) {
        this.topology = topologyData;
        this.renderTopologyVisualization();
    }
    
    renderTopologyVisualization() {
        /**
         * Render interactive topology visualization
         * This would implement actual network graph rendering
         */
        const canvas = document.getElementById('topology-canvas');
        if (!canvas) return;
        
        // Simplified topology rendering
        canvas.innerHTML = `
            <div class="topology-stats">
                <div class="topology-stat">
                    <span class="stat-label">Nodes:</span>
                    <span class="stat-value">${this.topology.nodes?.length || 0}</span>
                </div>
                <div class="topology-stat">
                    <span class="stat-label">Connections:</span>
                    <span class="stat-value">${this.topology.connections?.length || 0}</span>
                </div>
            </div>
            <div class="topology-graph">
                <p>Interactive topology visualization would be rendered here</p>
                <p>Using libraries like D3.js, Cytoscape.js, or custom WebGL</p>
            </div>
        `;
    }
    
    destroy() {
        /**
         * Cleanup resources
         */
        this.charts.forEach(chart => chart.destroy());
        this.charts.clear();
        
        if (this.websocket) {
            this.websocket.disconnect();
        }
    }
}

// Initialize enhanced dashboard
let enhancedDashboard = null;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        enhancedDashboard = new EnhancedDashboard();
        window.enhancedDashboard = enhancedDashboard;
    });
} else {
    enhancedDashboard = new EnhancedDashboard();
    window.enhancedDashboard = enhancedDashboard;
}

export default EnhancedDashboard;
