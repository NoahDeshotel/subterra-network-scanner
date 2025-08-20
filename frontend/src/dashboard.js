/**
 * Dashboard Module
 * Handles dashboard charts and data visualization
 */

import Chart from 'chart.js/auto';

class Dashboard {
    constructor() {
        this.charts = new Map();
        this.chartConfigs = {
            vulnerability: {
                type: 'doughnut',
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                usePointStyle: true,
                                color: '#ffffff'
                            }
                        }
                    }
                }
            },
            ports: {
                type: 'bar',
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#ffffff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        },
                        x: {
                            ticks: { color: '#ffffff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: { color: '#ffffff' }
                        }
                    }
                }
            },
            os: {
                type: 'pie',
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                usePointStyle: true,
                                color: '#ffffff'
                            }
                        }
                    }
                }
            },
            timeline: {
                type: 'line',
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#ffffff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        },
                        x: {
                            ticks: { color: '#ffffff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: { color: '#ffffff' }
                        }
                    }
                }
            }
        };
        
        this.init();
    }
    
    init() {
        console.log('📊 Initializing Dashboard Charts...');
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.initializeCharts();
            });
        } else {
            this.initializeCharts();
        }
    }
    
    initializeCharts() {
        this.createVulnerabilityChart();
        this.createPortChart();
        this.createOSChart();
        this.createTimelineChart();
        
        console.log('✅ Dashboard Charts Ready');
    }
    
    createVulnerabilityChart() {
        const canvas = document.getElementById('vuln-chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            ...this.chartConfigs.vulnerability,
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#ff3366',
                        '#ffaa00',
                        '#ffff00',
                        '#00ff88'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            }
        });
        
        this.charts.set('vulnerability', chart);
    }
    
    createPortChart() {
        const canvas = document.getElementById('port-chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            ...this.chartConfigs.ports,
            data: {
                labels: ['HTTP/HTTPS', 'SSH', 'FTP', 'SMTP', 'DNS', 'Other'],
                datasets: [{
                    label: 'Open Ports',
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(0, 212, 255, 0.6)',
                    borderColor: '#00d4ff',
                    borderWidth: 2
                }]
            }
        });
        
        this.charts.set('ports', chart);
    }
    
    createOSChart() {
        const canvas = document.getElementById('os-chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            ...this.chartConfigs.os,
            data: {
                labels: ['Windows', 'Linux', 'macOS', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#0078d4',
                        '#ff6b35',
                        '#007acc',
                        '#6c757d'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            }
        });
        
        this.charts.set('os', chart);
    }
    
    createTimelineChart() {
        const canvas = document.getElementById('timeline-chart');
        if (!canvas) return;
        
        const ctx = canvas.getContext('2d');
        const chart = new Chart(ctx, {
            ...this.chartConfigs.timeline,
            data: {
                labels: [],
                datasets: [{
                    label: 'Critical Vulnerabilities',
                    data: [],
                    borderColor: '#ff3366',
                    backgroundColor: 'rgba(255, 51, 102, 0.1)',
                    tension: 0.4
                }, {
                    label: 'Total Hosts',
                    data: [],
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    tension: 0.4
                }]
            }
        });
        
        this.charts.set('timeline', chart);
    }
    
    updateVulnerabilityChart(data) {
        const chart = this.charts.get('vulnerability');
        if (!chart || !data) return;
        
        const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        
        if (data.vulnerabilities) {
            data.vulnerabilities.forEach(vuln => {
                const severity = vuln.severity?.toLowerCase() || 'low';
                if (counts[severity] !== undefined) {
                    counts[severity]++;
                }
            });
        }
        
        chart.data.datasets[0].data = [
            counts.critical,
            counts.high,
            counts.medium,
            counts.low
        ];
        
        chart.update();
    }
    
    updatePortChart(data) {
        const chart = this.charts.get('ports');
        if (!chart || !data) return;
        
        const portCounts = {
            'HTTP/HTTPS': 0,
            'SSH': 0,
            'FTP': 0,
            'SMTP': 0,
            'DNS': 0,
            'Other': 0
        };
        
        if (data.ports) {
            data.ports.forEach(port => {
                const service = port.service?.toLowerCase() || '';
                
                if (service.includes('http') || port.port === 80 || port.port === 443) {
                    portCounts['HTTP/HTTPS']++;
                } else if (service.includes('ssh') || port.port === 22) {
                    portCounts['SSH']++;
                } else if (service.includes('ftp') || port.port === 21) {
                    portCounts['FTP']++;
                } else if (service.includes('smtp') || port.port === 25) {
                    portCounts['SMTP']++;
                } else if (service.includes('dns') || port.port === 53) {
                    portCounts['DNS']++;
                } else {
                    portCounts['Other']++;
                }
            });
        }
        
        chart.data.datasets[0].data = Object.values(portCounts);
        chart.update();
    }
    
    updateOSChart(data) {
        const chart = this.charts.get('os');
        if (!chart || !data) return;
        
        const osCounts = {
            'Windows': 0,
            'Linux': 0,
            'macOS': 0,
            'Other': 0
        };
        
        if (data.hosts) {
            data.hosts.forEach(host => {
                const os = host.os?.toLowerCase() || '';
                
                if (os.includes('windows')) {
                    osCounts['Windows']++;
                } else if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian')) {
                    osCounts['Linux']++;
                } else if (os.includes('mac') || os.includes('darwin')) {
                    osCounts['macOS']++;
                } else {
                    osCounts['Other']++;
                }
            });
        }
        
        chart.data.datasets[0].data = Object.values(osCounts);
        chart.update();
    }
    
    updateTimelineChart(data) {
        const chart = this.charts.get('timeline');
        if (!chart || !data) return;
        
        if (data.scans && data.scans.length > 0) {
            const labels = [];
            const criticalVulns = [];
            const totalHosts = [];
            
            // Sort scans by date
            const sortedScans = data.scans.sort((a, b) => 
                new Date(a.timestamp) - new Date(b.timestamp)
            );
            
            sortedScans.forEach(scan => {
                const date = new Date(scan.timestamp).toLocaleDateString();
                labels.push(date);
                criticalVulns.push(scan.critical_vulnerabilities || 0);
                totalHosts.push(scan.host_count || 0);
            });
            
            chart.data.labels = labels;
            chart.data.datasets[0].data = criticalVulns;
            chart.data.datasets[1].data = totalHosts;
        }
        
        chart.update();
    }
    
    updateAllCharts(data) {
        this.updateVulnerabilityChart(data);
        this.updatePortChart(data);
        this.updateOSChart(data);
        this.updateTimelineChart(data);
    }
    
    animateStatCards() {
        const cards = document.querySelectorAll('.stat-card');
        
        cards.forEach((card, index) => {
            setTimeout(() => {
                card.style.animation = 'slideInUp 0.6s ease-out';
            }, index * 100);
        });
    }
    
    updateStatCard(cardId, value, change = null) {
        const valueElement = document.getElementById(cardId);
        if (!valueElement) return;
        
        // Animate value change
        const currentValue = parseInt(valueElement.textContent) || 0;
        const targetValue = parseInt(value) || 0;
        
        this.animateNumber(valueElement, currentValue, targetValue, 1000);
        
        // Update change indicator if provided
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
        const startTime = performance.now();
        
        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            
            const current = Math.round(start + (end - start) * easeOutQuart);
            element.textContent = current;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };
        
        requestAnimationFrame(animate);
    }
    
    showLoading(chartName) {
        const chart = this.charts.get(chartName);
        if (!chart) return;
        
        const canvas = chart.canvas;
        const ctx = canvas.getContext('2d');
        
        // Save current state
        chart._isLoading = true;
        
        // Draw loading spinner
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;
        
        const drawSpinner = () => {
            if (!chart._isLoading) return;
            
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            ctx.strokeStyle = '#00d4ff';
            ctx.lineWidth = 4;
            ctx.lineCap = 'round';
            
            const radius = 20;
            const angle = (Date.now() / 10) % 360;
            
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, 0, (angle * Math.PI) / 180);
            ctx.stroke();
            
            requestAnimationFrame(drawSpinner);
        };
        
        drawSpinner();
    }
    
    hideLoading(chartName) {
        const chart = this.charts.get(chartName);
        if (!chart) return;
        
        chart._isLoading = false;
        chart.update();
    }
    
    destroy() {
        this.charts.forEach(chart => {
            chart.destroy();
        });
        this.charts.clear();
    }
}

// Initialize dashboard when DOM is ready
let dashboardInstance = null;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        dashboardInstance = new Dashboard();
        window.dashboard = dashboardInstance;
    });
} else {
    dashboardInstance = new Dashboard();
    window.dashboard = dashboardInstance;
}

export default Dashboard;

