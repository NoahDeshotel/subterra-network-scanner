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
            
            this.websocket.on('devices_saved', (data) => {
                this.handleDevicesSaved(data);
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
        
        // Scanner selection information
        this.loadScannerCapabilities();
        
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
         * Show enhanced scan configuration dialog with scanner selection
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
                            <h3>Scanner Type</h3>
                            <div class="form-group">
                                <select id="scanner-type" class="form-control">
                                    <option value="auto">Auto-Select (Recommended)</option>
                                    <option value="job_based">Job-Based Scanner (Netdisco-Compatible)</option>
                                    <option value="enhanced">Enhanced Scanner</option>
                                    <option value="simple">Simple Scanner</option>
                                </select>
                                <small id="scanner-description">Automatically selects the best scanner for your network size</small>
                            </div>
                            
                            <div class="scanner-features" id="scanner-features">
                                <h4>Selected Scanner Features:</h4>
                                <ul id="feature-list">
                                    <li>✅ Automatic network size detection</li>
                                    <li>✅ Optimal performance for your subnet</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="config-section">
                            <h3>Advanced Options</h3>
                            <div class="form-group">
                                <label><input type="checkbox" id="deep-scan"> Deep Scan (Comprehensive)</label>
                                <label><input type="checkbox" id="topology-discovery" checked> Topology Discovery (CDP/LLDP)</label>
                                <label><input type="checkbox" id="vulnerability-scan"> Include Vulnerability Scan</label>
                            </div>
                        </div>
                        
                        <div class="config-section" id="snmp-config">
                            <h3>SNMP Configuration</h3>
                            <div class="form-group">
                                <label for="snmp-communities">Communities (comma-separated)</label>
                                <input type="text" id="snmp-communities" value="public,private" placeholder="public,private,community">
                                <small>Used for SNMP-based device discovery and profiling</small>
                            </div>
                        </div>
                        
                        <div class="config-section" id="scan-preview">
                            <h3>Scan Preview</h3>
                            <div class="preview-info">
                                <div class="preview-item">
                                    <span class="preview-label">Estimated Duration:</span>
                                    <span class="preview-value" id="estimated-duration">2-5 minutes</span>
                                </div>
                                <div class="preview-item">
                                    <span class="preview-label">Discovery Methods:</span>
                                    <span class="preview-value" id="discovery-methods">ICMP, DNS, SNMP</span>
                                </div>
                                <div class="preview-item">
                                    <span class="preview-label">Expected Features:</span>
                                    <span class="preview-value" id="expected-features">Device profiling, Classification</span>
                                </div>
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
        
        // Set up scanner type change handler
        const scannerTypeSelect = dialog.querySelector('#scanner-type');
        scannerTypeSelect.addEventListener('change', () => {
            this.updateScannerPreview(dialog, scannerTypeSelect.value);
        });
        
        // Initialize with default scanner preview
        this.updateScannerPreview(dialog, 'auto');
        
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
    
    async loadScannerCapabilities() {
        /**
         * Load available scanner capabilities from API
         */
        try {
            const data = await this.apiCall('/api/scanners/available');
            this.scannerCapabilities = data.available_scanners;
            this.autoSelectionLogic = data.auto_selection_logic;
        } catch (error) {
            console.error('Failed to load scanner capabilities:', error);
            // Set defaults if API call fails
            this.scannerCapabilities = {
                simple: { name: 'Simple Scanner', features: ['ping_sweep'], performance: 'Fast' },
                enhanced: { name: 'Enhanced Scanner', features: ['multi_method_discovery'], performance: 'Medium' },
                job_based: { name: 'Job-Based Scanner', features: ['comprehensive_discovery'], performance: 'Comprehensive' }
            };
        }
    }
    
    updateScannerPreview(dialog, scannerType) {
        /**
         * Update the scanner preview information
         */
        const description = dialog.querySelector('#scanner-description');
        const featureList = dialog.querySelector('#feature-list');
        const estimatedDuration = dialog.querySelector('#estimated-duration');
        const discoveryMethods = dialog.querySelector('#discovery-methods');
        const expectedFeatures = dialog.querySelector('#expected-features');
        
        const scannerInfo = this.scannerCapabilities?.[scannerType] || {};
        
        // Update description
        let descriptionText = scannerInfo.description || 'Scanner information not available';
        if (scannerType === 'auto') {
            descriptionText = 'Automatically selects the best scanner based on network size and requirements';
        }
        description.textContent = descriptionText;
        
        // Update features list
        featureList.innerHTML = '';
        const features = this.getScannerFeatures(scannerType);
        features.forEach(feature => {
            const li = document.createElement('li');
            li.innerHTML = `✅ ${feature}`;
            featureList.appendChild(li);
        });
        
        // Update preview information
        const previewData = this.getScannerPreviewData(scannerType);
        estimatedDuration.textContent = previewData.duration;
        discoveryMethods.textContent = previewData.methods;
        expectedFeatures.textContent = previewData.features;
        
        // Show/hide SNMP configuration based on scanner type
        const snmpConfig = dialog.querySelector('#snmp-config');
        if (scannerType === 'job_based' || scannerType === 'auto') {
            snmpConfig.style.display = 'block';
        } else if (scannerType === 'simple') {
            snmpConfig.style.display = 'none';
        }
    }
    
    getScannerFeatures(scannerType) {
        /**
         * Get feature list for scanner type
         */
        const features = {
            auto: [
                'Intelligent scanner selection',
                'Network size optimization',
                'Best performance for your network'
            ],
            job_based: [
                'Event-driven job queue',
                'Breadth-first network discovery',
                'SNMP comprehensive profiling',
                'CDP/LLDP topology mapping',
                'MAC table collection',
                'ARP table collection', 
                'Historical data continuity',
                'Intelligent retry logic',
                'Netdisco-compatible algorithms'
            ],
            enhanced: [
                'Multi-method host discovery',
                'Nmap port scanning',
                'Basic SNMP queries',
                'Device type classification',
                'Vulnerability detection'
            ],
            simple: [
                'Fast ICMP ping sweep',
                'Basic hostname resolution',
                'Simple device classification'
            ]
        };
        
        return features[scannerType] || ['Basic network scanning'];
    }
    
    getScannerPreviewData(scannerType) {
        /**
         * Get preview data for scanner type
         */
        const previewData = {
            auto: {
                duration: '2-8 minutes (varies by network)',
                methods: 'Auto-selected protocols',
                features: 'Optimized for your network'
            },
            job_based: {
                duration: '3-10 minutes',
                methods: 'ICMP, SNMP, CDP, LLDP, ARP, DNS',
                features: 'Complete network profiling, Topology mapping'
            },
            enhanced: {
                duration: '2-5 minutes', 
                methods: 'ICMP, TCP, UDP, SNMP, DNS',
                features: 'Port scanning, Vulnerability detection'
            },
            simple: {
                duration: '30 seconds - 2 minutes',
                methods: 'ICMP, DNS',
                features: 'Basic device discovery'
            }
        };
        
        return previewData[scannerType] || {
            duration: 'Unknown',
            methods: 'Basic protocols',
            features: 'Standard scanning'
        };
    }
    
    startEnhancedScan(dialog) {
        /**
         * Start enhanced network scan with configuration
         */
        const config = {
            subnet: dialog.querySelector('#scan-subnet').value,
            scanner_type: dialog.querySelector('#scanner-type').value,
            deep_scan: dialog.querySelector('#deep-scan').checked,
            topology_discovery: dialog.querySelector('#topology-discovery').checked,
            vulnerability_scan: dialog.querySelector('#vulnerability-scan').checked,
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
         * Show enhanced scan progress indicator with detailed statistics
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
                    <div class="scan-statistics">
                        <div class="stat-row">
                            <div class="stat-item">
                                <i class="fas fa-network-wired"></i>
                                <span class="stat-label">Addresses:</span>
                                <span class="stat-value" id="addresses-scanned">0/0</span>
                            </div>
                            <div class="stat-item">
                                <i class="fas fa-search"></i>
                                <span class="stat-label">Discovered:</span>
                                <span class="stat-value" id="devices-discovered">0</span>
                            </div>
                            <div class="stat-item">
                                <i class="fas fa-save"></i>
                                <span class="stat-label">Saved:</span>
                                <span class="stat-value" id="devices-saved">0</span>
                            </div>
                            <div class="stat-item">
                                <i class="fas fa-clock"></i>
                                <span class="stat-label">Elapsed:</span>
                                <span class="stat-value" id="scan-elapsed">0:00</span>
                            </div>
                        </div>
                        <div class="current-target" id="current-target" style="margin-top: 10px;">
                            <span class="target-label">Current:</span>
                            <span class="target-value" id="current-ip">Starting...</span>
                        </div>
                    </div>
                    <div class="progress-stages">
                        <div class="stage" data-stage="network_discovery">Network Discovery</div>
                        <div class="stage" data-stage="host_discovery">Host Discovery</div>
                        <div class="stage" data-stage="topology_mapping">Port Scanning</div>
                        <div class="stage" data-stage="data_processing">Saving Data</div>
                    </div>
                    <div class="job-based-details" id="job-details" style="display: none;">
                        <div class="job-stats">
                            <div class="stat-item">
                                <span class="stat-label">Jobs Completed:</span>
                                <span class="stat-value" id="jobs-completed">0</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Active Jobs:</span>
                                <span class="stat-value" id="active-jobs">0</span>
                            </div>
                            <div class="stat-item">
                                <span class="stat-label">Devices Found:</span>
                                <span class="stat-value" id="devices-found">0</span>
                            </div>
                        </div>
                        <div class="current-jobs" id="current-jobs">
                            <h5>Current Activities:</h5>
                            <div class="job-list" id="job-list"></div>
                        </div>
                    </div>
                </div>
            `;
            
            // Start elapsed time counter
            this.startScanTimer();
        }
    }
    
    updateScanProgress(data) {
        /**
         * Update scan progress display with detailed information
         */
        const progressFill = document.querySelector('.progress-fill');
        const progressText = document.querySelector('.progress-text');
        const progressPercentage = document.querySelector('.progress-percentage');
        
        // Extract detailed progress information
        let progressValue = 0;
        let progressMessage = 'Scanning...';
        let scannerType = 'enhanced';
        let devicesScanned = data.devices_scanned || 0;
        let devicesSaved = data.devices_saved || 0;
        let totalAddresses = data.total_addresses || 0;
        
        if (data.progress && typeof data.progress === 'object') {
            // New structure from scan_progress_tracker
            progressValue = data.progress.percentage || 0;
            progressMessage = data.progress.current_step || 'Scanning...';
            scannerType = data.progress.details?.scanner_type || 'enhanced';
            
            // Update stage indicators based on actual stage
            const currentStage = data.progress.stage;
            if (currentStage) {
                const stageMap = {
                    'initializing': 'network_discovery',
                    'network_discovery': 'network_discovery',
                    'host_discovery': 'host_discovery',
                    'topology_mapping': 'topology_mapping',
                    'data_processing': 'data_processing',
                    'finalizing': 'data_processing'
                };
                
                const stages = ['network_discovery', 'host_discovery', 'topology_mapping', 'data_processing'];
                stages.forEach(stage => {
                    const stageElement = document.querySelector(`[data-stage="${stage}"]`);
                    if (stageElement) {
                        const isActive = stageMap[currentStage] === stage;
                        const isCompleted = stages.indexOf(stage) < stages.indexOf(stageMap[currentStage]);
                        stageElement.classList.toggle('active', isActive);
                        stageElement.classList.toggle('completed', isCompleted);
                    }
                });
            }
        } else {
            // Legacy structure
            progressValue = data.progress || 0;
            progressMessage = data.message || 'Scanning...';
            scannerType = data.scanner_type || 'enhanced';
        }
        
        if (progressFill) {
            progressFill.style.width = `${progressValue}%`;
        }
        
        // Enhanced progress message with detailed stats
        if (progressText) {
            let detailedMessage = progressMessage;
            
            // Add detailed statistics if available
            if (totalAddresses > 0) {
                detailedMessage = `${progressMessage} | ${devicesScanned}/${totalAddresses} addresses scanned`;
                if (devicesSaved > 0) {
                    detailedMessage += ` | ${devicesSaved} devices saved`;
                }
            }
            
            progressText.textContent = detailedMessage;
        }
        
        if (progressPercentage) {
            progressPercentage.textContent = `${Math.round(progressValue)}%`;
        }
        
        // Update additional statistics display
        this.updateScanStatistics(data);
        
        // Handle job-based scanner specific progress
        if (scannerType === 'job_based' || data.enhanced) {
            this.updateJobBasedProgress(data);
        }
    }
    
    updateJobBasedProgress(data) {
        /**
         * Update job-based scanner specific progress information
         */
        // Show job-based details
        const jobDetails = document.getElementById('job-details');
        if (jobDetails) {
            jobDetails.style.display = 'block';
        }
        
        // Update job statistics
        const jobsCompleted = document.getElementById('jobs-completed');
        const activeJobs = document.getElementById('active-jobs');  
        const devicesFound = document.getElementById('devices-found');
        
        // Handle new progress structure
        let progressData = data;
        if (data.progress && typeof data.progress === 'object') {
            progressData = data.progress;
        }
        
        // Update from details if available
        if (progressData.details) {
            if (jobsCompleted && progressData.details.jobs_completed !== undefined) {
                jobsCompleted.textContent = progressData.details.jobs_completed;
            }
            if (activeJobs && progressData.details.active_jobs !== undefined) {
                activeJobs.textContent = progressData.details.active_jobs;
            }
            if (devicesFound && progressData.details.devices_found !== undefined) {
                devicesFound.textContent = progressData.details.devices_found;
            }
        }
        
        // Fallback to legacy structure
        if (data.jobs_executed) {
            if (jobsCompleted) jobsCompleted.textContent = data.jobs_executed.completed || 0;
            if (activeJobs) activeJobs.textContent = data.active_jobs || 0;
        }
        
        if (devicesFound && !progressData.details?.devices_found) {
            devicesFound.textContent = data.devices_found || data.devices_discovered || 0;
        }
        
        // Update current activities
        const jobList = document.getElementById('job-list');
        const activities = progressData.details?.current_activities || data.current_activities;
        
        if (jobList && activities) {
            jobList.innerHTML = '';
            activities.slice(0, 5).forEach(activity => {
                const activityDiv = document.createElement('div');
                activityDiv.className = 'job-activity';
                activityDiv.innerHTML = `
                    <span class="job-type">${activity.job_type || 'Unknown'}</span>
                    <span class="job-target">${activity.target || ''}</span>
                    <span class="job-status ${activity.status || 'pending'}">${activity.status || 'pending'}</span>
                `;
                jobList.appendChild(activityDiv);
            });
        }
        
        // Update enhanced stages
        const stageMapping = {
            'network_discovery': ['PINGSWEEP', 'DISCOVER'],
            'host_discovery': ['DISCOVER', 'PORTMAP'],
            'topology_mapping': ['TOPOLOGY', 'MACSUCK', 'ARPNIP'],
            'data_processing': ['completed']
        };
        
        const currentStage = data.current_stage || this.inferStageFromJobs(data);
        
        Object.keys(stageMapping).forEach(stage => {
            const stageElement = document.querySelector(`[data-stage="${stage}"]`);
            if (stageElement) {
                const isActive = stage === currentStage;
                const isCompleted = this.isStageCompleted(stage, currentStage);
                
                stageElement.classList.toggle('active', isActive);
                stageElement.classList.toggle('completed', isCompleted);
            }
        });
    }
    
    inferStageFromJobs(data) {
        /**
         * Infer current stage from job information
         */
        if (data.progress >= 90) return 'data_processing';
        if (data.progress >= 60) return 'topology_mapping';
        if (data.progress >= 30) return 'host_discovery';
        return 'network_discovery';
    }
    
    isStageCompleted(stage, currentStage) {
        /**
         * Check if a stage is completed
         */
        const stageOrder = ['network_discovery', 'host_discovery', 'topology_mapping', 'data_processing'];
        const stageIndex = stageOrder.indexOf(stage);
        const currentIndex = stageOrder.indexOf(currentStage);
        return stageIndex < currentIndex;
    }
    
    hideScanProgress() {
        const progressContainer = document.getElementById('scan-progress');
        if (progressContainer) {
            progressContainer.classList.add('hidden');
        }
        this.stopScanTimer();
    }
    
    loadInitialData() {
        /**
         * Load initial dashboard data
         */
        Promise.all([
            this.apiCall('/api/statistics/enhanced'),
            this.apiCall('/api/devices?per_page=1000'),  // Request all devices (up to 1000)
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
         * Update dashboard statistics with enhanced job-based scanner data
         */
        // Update basic stat cards using correct HTML IDs
        this.updateStatCard('total-hosts', stats.total_devices || stats.total_hosts || 0);
        this.updateStatCard('critical-vulns', stats.critical_vulnerabilities || 0);
        this.updateStatCard('open-ports', stats.port_statistics?.total_open_ports || 0);
        this.updateStatCard('security-score', Math.round(stats.uptime_percentage || 0));
        
        // Update enhanced statistics if available
        if (stats.enhanced || stats.job_based) {
            this.updateEnhancedStatistics(stats);
        }
        
        // Update vulnerability chart
        this.updateVulnChart(stats);
    }
    
    updateEnhancedStatistics(stats) {
        /**
         * Update enhanced statistics from job-based scanner
         */
        // Update topology information
        if (stats.topology_links !== undefined) {
            const topologyCard = document.getElementById('topology-links');
            if (topologyCard) {
                this.updateStatCard('topology-links', stats.topology_links);
            } else {
                // Create topology card if it doesn't exist
                this.createEnhancedStatCard('topology-links', 'Topology Links', stats.topology_links, 'fas fa-project-diagram');
            }
        }
        
        // Update SNMP devices count
        if (stats.snmp_devices !== undefined) {
            const snmpCard = document.getElementById('snmp-devices');
            if (snmpCard) {
                this.updateStatCard('snmp-devices', stats.snmp_devices);
            } else {
                this.createEnhancedStatCard('snmp-devices', 'SNMP Devices', stats.snmp_devices, 'fas fa-network-wired');
            }
        }
        
        // Update scan metadata if available
        if (stats.scan_metadata) {
            this.displayScanMetadata(stats.scan_metadata);
        }
        
        // Show enhanced features indicator
        const enhancedIndicator = document.getElementById('enhanced-indicator');
        if (enhancedIndicator) {
            enhancedIndicator.style.display = 'block';
            enhancedIndicator.innerHTML = `
                <i class="fas fa-star"></i>
                <span>Enhanced Scanner Active</span>
                ${stats.job_based ? '<small>Job-Based • Netdisco Compatible</small>' : '<small>Enhanced Features</small>'}
            `;
        }
    }
    
    createEnhancedStatCard(id, title, value, iconClass) {
        /**
         * Create enhanced stat card for new metrics
         */
        const statsContainer = document.querySelector('.stats-cards') || document.querySelector('.stats-grid');
        if (!statsContainer) return;
        
        const card = document.createElement('div');
        card.className = 'stat-card enhanced';
        card.innerHTML = `
            <div class="stat-icon">
                <i class="${iconClass}"></i>
            </div>
            <div class="stat-content">
                <div class="stat-value" id="${id}">${value}</div>
                <div class="stat-label">${title}</div>
                <div class="stat-change enhanced">Enhanced Feature</div>
            </div>
        `;
        
        statsContainer.appendChild(card);
    }
    
    displayScanMetadata(metadata) {
        /**
         * Display scan metadata from job-based scanner
         */
        const metadataContainer = document.getElementById('scan-metadata');
        if (!metadataContainer) return;
        
        metadataContainer.innerHTML = `
            <h4>Last Scan Information</h4>
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">Scanner Type:</span>
                    <span class="metadata-value">${metadata.scan_type || 'Unknown'}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Devices Discovered:</span>
                    <span class="metadata-value">${metadata.devices_discovered || 0}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Topology Links:</span>
                    <span class="metadata-value">${metadata.topology_links || 0}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">MAC Entries:</span>
                    <span class="metadata-value">${metadata.mac_entries || 0}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">ARP Entries:</span>
                    <span class="metadata-value">${metadata.arp_entries || 0}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">SNMP Devices:</span>
                    <span class="metadata-value">${metadata.snmp_devices || 0}</span>
                </div>
            </div>
        `;
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
        
        // Debug logging
        console.log('UpdateDevicesData called with:', devices.length, 'devices');
        const devicesWithPorts = devices.filter(d => d.ports && d.ports.length > 0);
        console.log('Devices with ports:', devicesWithPorts.length);
        if (devicesWithPorts.length > 0) {
            console.log('Sample device with ports:', devicesWithPorts[0]);
        }
        
        // Inventory table with enhanced job-based scanner data
        const tbody = document.getElementById('inventory-tbody');
        if (tbody) {
            tbody.innerHTML = '';
            devices.forEach(d => {
                const tr = document.createElement('tr');
                
                // Enhanced device row with additional information
                const deviceTypeIcon = this.getDeviceTypeIcon(d.device_type);
                const snmpIndicator = d.snmp_capable ? '<i class="fas fa-network-wired text-success" title="SNMP Capable"></i>' : '';
                const topologyIndicator = (d.has_cdp || d.has_lldp) ? '<i class="fas fa-project-diagram text-info" title="Topology Discovery"></i>' : '';
                
                // Add ports info to the row - now directly from device data
                const portInfo = this.formatPortsList(d.ports || []);
                if (d.ip === '10.0.0.1' || d.ip === '10.0.0.51') {
                    console.log(`Device ${d.ip} ports:`, d.ports, 'Formatted:', portInfo);
                }
                
                tr.innerHTML = `
                    <td>
                        ${deviceTypeIcon}
                        <span>${d.ip || ''}</span>
                    </td>
                    <td>${d.hostname || '<em>Unknown</em>'}</td>
                    <td>${d.mac_address || '<em>Unknown</em>'}</td>
                    <td>
                        <span class="device-type">${d.device_type || 'unknown'}</span>
                        ${d.vendor ? `<small class="text-muted"><br/>${d.vendor}</small>` : ''}
                    </td>
                    <td>${d.os || d.os_name || '<em>Unknown</em>'}</td>
                    <td>
                        <div class="ports-info" id="ports-${d.ip.replace(/\./g, '-')}">
                            <span class="port-count">${d.ports ? d.ports.length : 0} ports</span>
                            <div class="port-details" style="font-size: 0.85em; margin-top: 4px;">
                                ${portInfo}
                            </div>
                        </div>
                        ${d.scanner_type === 'job_based' ? '<small class="text-success">Enhanced</small>' : ''}
                    </td>
                    <td>
                        <div class="device-capabilities">
                            ${snmpIndicator}
                            ${topologyIndicator}
                            ${d.has_bridge_mib ? '<i class="fas fa-table text-warning" title="Bridge MIB"></i>' : ''}
                        </div>
                    </td>
                    <td>
                        <span class="timestamp">${this.formatTimestamp(d.last_seen) || ''}</span>
                        ${d.last_discover ? `<small class="text-muted"><br/>Discovered: ${this.formatTimestamp(d.last_discover)}</small>` : ''}
                    </td>
                    <td>
                        <button class="btn btn-xs btn-primary" data-ip="${d.ip}" onclick="enhancedDashboard.showDeviceDetails('${d.ip}')">
                            Details
                        </button>
                    </td>
                `;
                
                // Add enhanced row styling
                if (d.scanner_type === 'job_based') {
                    tr.classList.add('enhanced-device');
                }
                
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
    
    getDeviceTypeIcon(deviceType) {
        /**
         * Get icon for device type
         */
        const icons = {
            'router': '<i class="fas fa-route text-primary" title="Router"></i>',
            'switch': '<i class="fas fa-network-wired text-info" title="Switch"></i>',
            'firewall': '<i class="fas fa-shield-alt text-danger" title="Firewall"></i>',
            'server': '<i class="fas fa-server text-success" title="Server"></i>',
            'workstation': '<i class="fas fa-desktop text-secondary" title="Workstation"></i>',
            'printer': '<i class="fas fa-print text-warning" title="Printer"></i>',
            'phone': '<i class="fas fa-phone text-info" title="IP Phone"></i>',
            'camera': '<i class="fas fa-video text-danger" title="Camera"></i>',
            'wireless_controller': '<i class="fas fa-wifi text-primary" title="Wireless Controller"></i>',
            'access_point': '<i class="fas fa-broadcast-tower text-info" title="Access Point"></i>',
            'storage': '<i class="fas fa-hdd text-warning" title="Storage"></i>',
            'ups': '<i class="fas fa-battery-full text-success" title="UPS"></i>',
            'iot': '<i class="fas fa-microchip text-purple" title="IoT Device"></i>',
            'unknown': '<i class="fas fa-question-circle text-muted" title="Unknown Device"></i>'
        };
        
        return icons[deviceType] || icons['unknown'];
    }
    
    async fetchPortData() {
        /**
         * Fetch port data for all devices
         */
        try {
            const response = await this.apiCall('/api/ports');
            return response.devices_with_ports || [];
        } catch (error) {
            console.error('Failed to fetch port data:', error);
            return [];
        }
    }
    
    updateDevicesWithPorts(devices, portsData) {
        /**
         * Update device rows with port information
         */
        const portsMap = {};
        portsData.forEach(devicePorts => {
            portsMap[devicePorts.ip] = devicePorts.ports;
        });
        
        devices.forEach(device => {
            const ports = portsMap[device.ip] || [];
            const portElement = document.getElementById(`ports-${device.ip.replace(/\./g, '-')}`);
            if (portElement) {
                const portDetails = this.formatPortsList(ports);
                portElement.innerHTML = `
                    <span class="port-count">${ports.length} ports</span>
                    <div class="port-details" style="font-size: 0.85em; margin-top: 4px;">
                        ${portDetails}
                    </div>
                `;
            }
        });
    }
    
    formatPortsList(ports) {
        /**
         * Format ports list for display
         */
        if (!ports || ports.length === 0) {
            return '<em class="text-muted">No open ports detected</em>';
        }
        
        // Group ports by protocol
        const tcpPorts = ports.filter(p => p.protocol === 'tcp').map(p => {
            const serviceName = p.service_name ? ` (${p.service_name})` : '';
            return `${p.port_number}${serviceName}`;
        });
        
        const udpPorts = ports.filter(p => p.protocol === 'udp').map(p => {
            const serviceName = p.service_name ? ` (${p.service_name})` : '';
            return `${p.port_number}${serviceName}`;
        });
        
        let html = '';
        if (tcpPorts.length > 0) {
            html += `<div><strong>TCP:</strong> ${tcpPorts.slice(0, 5).join(', ')}${tcpPorts.length > 5 ? `, +${tcpPorts.length - 5} more` : ''}</div>`;
        }
        if (udpPorts.length > 0) {
            html += `<div><strong>UDP:</strong> ${udpPorts.slice(0, 5).join(', ')}${udpPorts.length > 5 ? `, +${udpPorts.length - 5} more` : ''}</div>`;
        }
        
        return html;
    }
    
    async showDeviceDetails(ip) {
        /**
         * Show detailed device information including all ports
         */
        try {
            // Fetch device details and ports
            const [device, portsResponse] = await Promise.all([
                this.apiCall(`/api/devices/${ip}`),
                this.apiCall(`/api/devices/${ip}/ports`)
            ]);
            
            const ports = portsResponse.ports || [];
            
            // Create detail modal
            const modal = document.createElement('div');
            modal.className = 'modal device-details-modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <div class="modal-header">
                        <h2><i class="fas fa-server"></i> Device Details: ${ip}</h2>
                        <button class="modal-close">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div class="device-info-grid">
                            <div class="info-section">
                                <h3>Basic Information</h3>
                                <table class="info-table">
                                    <tr><td>IP Address:</td><td>${device.ip || 'N/A'}</td></tr>
                                    <tr><td>Hostname:</td><td>${device.hostname || 'Unknown'}</td></tr>
                                    <tr><td>MAC Address:</td><td>${device.mac_address || 'Unknown'}</td></tr>
                                    <tr><td>Device Type:</td><td>${device.device_type || 'Unknown'}</td></tr>
                                    <tr><td>OS:</td><td>${device.os || device.os_name || 'Unknown'}</td></tr>
                                    <tr><td>Vendor:</td><td>${device.vendor || 'Unknown'}</td></tr>
                                    <tr><td>Last Seen:</td><td>${this.formatTimestamp(device.last_seen)}</td></tr>
                                </table>
                            </div>
                            
                            <div class="info-section">
                                <h3>Open Ports (${ports.length})</h3>
                                <div class="ports-list" style="max-height: 400px; overflow-y: auto;">
                                    ${this.formatDetailedPortsList(ports)}
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary modal-close">Close</button>
                        <button class="btn btn-primary" onclick="enhancedDashboard.startPortScan('${ip}')">
                            <i class="fas fa-sync"></i> Rescan Ports
                        </button>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
            modal.style.display = 'block';
            
            // Add close handlers
            modal.querySelectorAll('.modal-close').forEach(btn => {
                btn.addEventListener('click', () => {
                    document.body.removeChild(modal);
                });
            });
            
        } catch (error) {
            console.error('Failed to load device details:', error);
            this.showNotification('Error', 'Failed to load device details', 'error');
        }
    }
    
    formatDetailedPortsList(ports) {
        /**
         * Format detailed ports list for modal
         */
        if (!ports || ports.length === 0) {
            return '<p class="text-muted">No open ports detected</p>';
        }
        
        const html = `
            <table class="ports-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
                    ${ports.map(port => `
                        <tr>
                            <td>${port.port_number}</td>
                            <td>${port.protocol?.toUpperCase() || 'TCP'}</td>
                            <td><span class="badge badge-${port.state === 'open' ? 'success' : 'warning'}">${port.state || 'open'}</span></td>
                            <td>${port.service_name || '-'}</td>
                            <td><span class="badge badge-${this.getRiskBadgeClass(port.risk_level)}">${port.risk_level || 'low'}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        
        return html;
    }
    
    getRiskBadgeClass(riskLevel) {
        const classes = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        };
        return classes[riskLevel] || 'secondary';
    }
    
    async startPortScan(ip) {
        /**
         * Start a port scan for a specific device
         */
        try {
            const response = await this.apiCall('/api/scan/start', {
                method: 'POST',
                body: JSON.stringify({
                    subnet: `${ip}/32`,
                    deep_scan: true,
                    scanner_type: 'enhanced'
                })
            });
            
            if (response.success) {
                this.showNotification('Port Scan Started', `Scanning ports on ${ip}`, 'info');
            } else {
                this.showNotification('Scan Failed', response.error || 'Failed to start port scan', 'error');
            }
        } catch (error) {
            console.error('Failed to start port scan:', error);
            this.showNotification('Error', 'Failed to start port scan', 'error');
        }
    }
    
    formatTimestamp(timestamp) {
        /**
         * Format timestamp for display
         */
        if (!timestamp) return '';
        
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (e) {
            return timestamp;
        }
    }

    // WebSocket event handlers
    updateScanStatistics(data) {
        /**
         * Update detailed scan statistics
         */
        // Update addresses scanned
        const addressesElement = document.getElementById('addresses-scanned');
        if (addressesElement && data.total_addresses) {
            const scanned = data.devices_scanned || 0;
            const total = data.total_addresses;
            addressesElement.textContent = `${scanned}/${total}`;
        }
        
        // Update devices discovered
        const discoveredElement = document.getElementById('devices-discovered');
        if (discoveredElement) {
            discoveredElement.textContent = data.devices_found || data.devices_discovered || '0';
        }
        
        // Update devices saved
        const savedElement = document.getElementById('devices-saved');
        if (savedElement) {
            savedElement.textContent = data.devices_saved || '0';
        }
        
        // Update current IP being scanned
        const currentIpElement = document.getElementById('current-ip');
        if (currentIpElement && data.message) {
            // Extract IP from message if available
            const ipMatch = data.message.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);;
            if (ipMatch) {
                currentIpElement.textContent = ipMatch[1];
            }
        }
    }
    
    startScanTimer() {
        /**
         * Start timer to show elapsed scan time
         */
        this.scanStartTime = Date.now();
        
        // Update timer every second
        this.scanTimerInterval = setInterval(() => {
            const elapsed = Date.now() - this.scanStartTime;
            const minutes = Math.floor(elapsed / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            
            const elapsedElement = document.getElementById('scan-elapsed');
            if (elapsedElement) {
                elapsedElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            }
        }, 1000);
    }
    
    stopScanTimer() {
        /**
         * Stop the scan timer
         */
        if (this.scanTimerInterval) {
            clearInterval(this.scanTimerInterval);
            this.scanTimerInterval = null;
        }
    }
    
    handleScanStarted(data) {
        console.log('Scan started:', data.scan_id);
        const scannerType = data.config?.scanner_type || 'enhanced';
        const scannerName = this.getScannerDisplayName(scannerType);
        const totalAddresses = data.config?.total_addresses || 'unknown';
        this.showNotification('Scan Started', `${scannerName} scan in progress for ${totalAddresses} addresses`, 'info');
    }
    
    handleScanProgress(data) {
        this.updateScanProgress(data);
    }
    
    handleScanCompleted(data) {
        console.log('Scan completed:', data);
        this.hideScanProgress();
        
        const deviceCount = data.devices_found || data.results?.devices_discovered || 0;
        const scanType = data.summary?.scan_type || 'enhanced';
        const isJobBased = data.summary?.job_based || data.summary?.netdisco_compatible;
        
        let message = `Discovered ${deviceCount} devices`;
        
        if (isJobBased && data.summary?.jobs_executed) {
            const jobs = data.summary.jobs_executed;
            message += ` using ${jobs.completed || 0} jobs`;
            
            // Add enhanced features information
            if (data.summary.enhanced_features) {
                const features = data.summary.enhanced_features;
                const enhancedInfo = [];
                if (features.snmp_devices > 0) enhancedInfo.push(`${features.snmp_devices} SNMP`);
                if (features.topology_links > 0) enhancedInfo.push(`${features.topology_links} topology links`);
                if (features.mac_entries > 0) enhancedInfo.push(`${features.mac_entries} MAC entries`);
                
                if (enhancedInfo.length > 0) {
                    message += ` (${enhancedInfo.join(', ')})`;
                }
            }
        }
        
        this.showNotification('Scan Completed', message, 'success');
        
        // Refresh dashboard data
        this.loadInitialData();
    }
    
    getScannerDisplayName(scannerType) {
        /**
         * Get display name for scanner type
         */
        const names = {
            'auto': 'Auto-Selected',
            'job_based': 'Job-Based',
            'netdisco': 'Netdisco-Compatible', 
            'enhanced': 'Enhanced',
            'simple': 'Simple'
        };
        
        return names[scannerType] || 'Enhanced';
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
    
    handleDevicesSaved(data) {
        console.log('Devices saved:', data);
        
        // Update saved devices counter
        const savedElement = document.getElementById('devices-saved');
        if (savedElement) {
            savedElement.textContent = data.devices_saved || '0';
        }
        
        // Refresh device list if not too frequent
        if (!this.lastDeviceRefresh || Date.now() - this.lastDeviceRefresh > 5000) {
            this.lastDeviceRefresh = Date.now();
            // Reload devices to show newly saved ones
            this.apiCall('/api/devices?per_page=1000')
                .then(devices => this.updateDevicesData(devices))
                .catch(error => console.error('Failed to refresh devices:', error));
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
