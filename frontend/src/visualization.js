/**
 * 3D Network Visualization Module
 * Uses Three.js for interactive 3D network mapping
 */

import * as THREE from 'three';

class NetworkVisualization {
    constructor() {
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.controls = null;
        this.nodes = new Map();
        this.edges = [];
        this.currentMode = 'sphere';
        this.showLabels = true;
        this.filterCritical = false;
        
        this.init();
    }
    
    init() {
        console.log('🎨 Initializing 3D Network Visualization...');
        
        const container = document.getElementById('network-3d-container');
        if (!container) {
            console.warn('3D container not found');
            return;
        }
        
        // Scene setup
        this.scene = new THREE.Scene();
        this.scene.background = new THREE.Color(0x060818);
        
        // Camera setup
        this.camera = new THREE.PerspectiveCamera(
            75,
            container.clientWidth / container.clientHeight,
            0.1,
            1000
        );
        this.camera.position.set(0, 0, 300);
        
        // Renderer setup
        this.renderer = new THREE.WebGLRenderer({ 
            antialias: true,
            alpha: true 
        });
        this.renderer.setSize(container.clientWidth, container.clientHeight);
        this.renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(this.renderer.domElement);
        
        // Controls setup (would need OrbitControls import)
        this.setupControls();
        
        // Lighting
        this.setupLighting();
        
        // Event listeners
        this.setupEventListeners();
        
        // Start render loop
        this.animate();
        
        console.log('✅ 3D Visualization Ready');
    }
    
    setupControls() {
        // Basic mouse controls implementation
        let isMouseDown = false;
        let mouseX = 0;
        let mouseY = 0;
        
        this.renderer.domElement.addEventListener('mousedown', (event) => {
            isMouseDown = true;
            mouseX = event.clientX;
            mouseY = event.clientY;
        });
        
        this.renderer.domElement.addEventListener('mousemove', (event) => {
            if (!isMouseDown) return;
            
            const deltaX = event.clientX - mouseX;
            const deltaY = event.clientY - mouseY;
            
            // Rotate camera around scene
            const spherical = new THREE.Spherical();
            spherical.setFromVector3(this.camera.position);
            spherical.theta -= deltaX * 0.01;
            spherical.phi += deltaY * 0.01;
            spherical.phi = Math.max(0.1, Math.min(Math.PI - 0.1, spherical.phi));
            
            this.camera.position.setFromSpherical(spherical);
            this.camera.lookAt(0, 0, 0);
            
            mouseX = event.clientX;
            mouseY = event.clientY;
        });
        
        this.renderer.domElement.addEventListener('mouseup', () => {
            isMouseDown = false;
        });
        
        // Mouse wheel zoom
        this.renderer.domElement.addEventListener('wheel', (event) => {
            event.preventDefault();
            const scale = event.deltaY > 0 ? 1.1 : 0.9;
            this.camera.position.multiplyScalar(scale);
        });
    }
    
    setupLighting() {
        // Ambient light
        const ambientLight = new THREE.AmbientLight(0x404040, 0.6);
        this.scene.add(ambientLight);
        
        // Directional light
        const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
        directionalLight.position.set(100, 100, 100);
        this.scene.add(directionalLight);
        
        // Point lights for effects
        const pointLight1 = new THREE.PointLight(0x00d4ff, 1, 200);
        pointLight1.position.set(50, 50, 50);
        this.scene.add(pointLight1);
        
        const pointLight2 = new THREE.PointLight(0xff3366, 0.5, 200);
        pointLight2.position.set(-50, -50, 50);
        this.scene.add(pointLight2);
    }
    
    setupEventListeners() {
        // View mode buttons
        document.querySelectorAll('.view-mode').forEach(button => {
            button.addEventListener('click', (e) => {
                const mode = e.target.dataset.mode;
                this.setViewMode(mode);
            });
        });
        
        // Control buttons
        document.getElementById('reset-view')?.addEventListener('click', () => {
            this.resetView();
        });
        
        document.getElementById('toggle-labels')?.addEventListener('click', () => {
            this.toggleLabels();
        });
        
        document.getElementById('filter-critical')?.addEventListener('click', () => {
            this.toggleCriticalFilter();
        });
        
        // Window resize
        window.addEventListener('resize', () => {
            this.onWindowResize();
        });
        
        // Mouse click for node selection
        this.renderer.domElement.addEventListener('click', (event) => {
            this.onNodeClick(event);
        });
    }
    
    updateTopology(data) {
        console.log('🔄 Updating network topology:', data);
        
        // Clear existing objects
        this.clearScene();
        
        // Add nodes
        if (data.nodes) {
            data.nodes.forEach(nodeData => {
                this.addNode(nodeData);
            });
        }
        
        // Add edges
        if (data.edges) {
            data.edges.forEach(edgeData => {
                this.addEdge(edgeData);
            });
        }
        
        // Apply current layout
        this.applyLayout(this.currentMode);
    }
    
    addNode(nodeData) {
        const geometry = new THREE.SphereGeometry(5, 32, 32);
        
        // Color based on risk level
        let color = 0x00d4ff; // Default blue
        switch (nodeData.group) {
            case 'critical':
                color = 0xff3366;
                break;
            case 'high':
                color = 0xffaa00;
                break;
            case 'medium':
                color = 0xffff00;
                break;
            case 'low':
                color = 0x00ff88;
                break;
            case 'self':
                color = 0x9966ff;
                break;
        }
        
        const material = new THREE.MeshPhongMaterial({ 
            color: color,
            emissive: color,
            emissiveIntensity: 0.2
        });
        
        const mesh = new THREE.Mesh(geometry, material);
        mesh.position.set(nodeData.x || 0, nodeData.y || 0, nodeData.z || 0);
        mesh.userData = nodeData;
        
        // Add glow effect for critical nodes
        if (nodeData.group === 'critical') {
            this.addGlowEffect(mesh);
        }
        
        this.scene.add(mesh);
        this.nodes.set(nodeData.id, mesh);
        
        // Add label if enabled
        if (this.showLabels) {
            this.addNodeLabel(mesh, nodeData.label);
        }
    }
    
    addEdge(edgeData) {
        const sourceNode = this.nodes.get(edgeData.source);
        const targetNode = this.nodes.get(edgeData.target);
        
        if (!sourceNode || !targetNode) {
            console.warn('Edge nodes not found:', edgeData);
            return;
        }
        
        const geometry = new THREE.BufferGeometry().setFromPoints([
            sourceNode.position,
            targetNode.position
        ]);
        
        const material = new THREE.LineBasicMaterial({ 
            color: 0x444444,
            opacity: 0.6,
            transparent: true
        });
        
        const line = new THREE.Line(geometry, material);
        line.userData = edgeData;
        
        this.scene.add(line);
        this.edges.push(line);
    }
    
    addGlowEffect(mesh) {
        const glowGeometry = new THREE.SphereGeometry(7, 32, 32);
        const glowMaterial = new THREE.MeshBasicMaterial({
            color: 0xff3366,
            transparent: true,
            opacity: 0.3
        });
        
        const glow = new THREE.Mesh(glowGeometry, glowMaterial);
        glow.position.copy(mesh.position);
        this.scene.add(glow);
        
        // Animate glow
        const animate = () => {
            glow.scale.x = glow.scale.y = glow.scale.z = 
                1 + 0.3 * Math.sin(Date.now() * 0.005);
            requestAnimationFrame(animate);
        };
        animate();
    }
    
    addNodeLabel(mesh, text) {
        // Simple text label implementation
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        canvas.width = 256;
        canvas.height = 64;
        
        context.fillStyle = 'rgba(0, 0, 0, 0.8)';
        context.fillRect(0, 0, canvas.width, canvas.height);
        
        context.fillStyle = '#ffffff';
        context.font = '20px Arial';
        context.textAlign = 'center';
        context.fillText(text, canvas.width / 2, canvas.height / 2 + 7);
        
        const texture = new THREE.CanvasTexture(canvas);
        const spriteMaterial = new THREE.SpriteMaterial({ map: texture });
        const sprite = new THREE.Sprite(spriteMaterial);
        sprite.position.copy(mesh.position);
        sprite.position.y += 15;
        sprite.scale.set(30, 7.5, 1);
        
        this.scene.add(sprite);
    }
    
    setViewMode(mode) {
        this.currentMode = mode;
        
        // Update button states
        document.querySelectorAll('.view-mode').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-mode="${mode}"]`).classList.add('active');
        
        this.applyLayout(mode);
    }
    
    applyLayout(mode) {
        const nodeArray = Array.from(this.nodes.values());
        const nodeCount = nodeArray.length;
        
        switch (mode) {
            case 'sphere':
                this.applySphereLayout(nodeArray);
                break;
            case 'force':
                this.applyForceLayout(nodeArray);
                break;
            case 'tree':
                this.applyTreeLayout(nodeArray);
                break;
            case 'galaxy':
                this.applyGalaxyLayout(nodeArray);
                break;
        }
        
        // Update edge positions
        this.updateEdgePositions();
    }
    
    applySphereLayout(nodes) {
        const radius = 100;
        
        nodes.forEach((node, index) => {
            const phi = Math.acos(-1 + (2 * index) / nodes.length);
            const theta = Math.sqrt(nodes.length * Math.PI) * phi;
            
            node.position.x = radius * Math.cos(theta) * Math.sin(phi);
            node.position.y = radius * Math.sin(theta) * Math.sin(phi);
            node.position.z = radius * Math.cos(phi);
        });
    }
    
    applyForceLayout(nodes) {
        // Simplified force-directed layout
        const iterations = 100;
        const k = Math.sqrt(200 * 200 / nodes.length);
        
        for (let i = 0; i < iterations; i++) {
            // Repulsive forces
            nodes.forEach(nodeA => {
                nodeA.force = new THREE.Vector3();
                
                nodes.forEach(nodeB => {
                    if (nodeA !== nodeB) {
                        const distance = nodeA.position.distanceTo(nodeB.position);
                        if (distance > 0) {
                            const repulsion = k * k / distance;
                            const direction = new THREE.Vector3()
                                .subVectors(nodeA.position, nodeB.position)
                                .normalize();
                            nodeA.force.add(direction.multiplyScalar(repulsion));
                        }
                    }
                });
            });
            
            // Apply forces
            nodes.forEach(node => {
                node.position.add(node.force.multiplyScalar(0.1));
            });
        }
    }
    
    applyTreeLayout(nodes) {
        // Simple tree layout
        const levels = Math.ceil(Math.log2(nodes.length + 1));
        const radius = 150;
        
        nodes.forEach((node, index) => {
            const level = Math.floor(Math.log2(index + 1));
            const positionInLevel = index - (Math.pow(2, level) - 1);
            const totalInLevel = Math.pow(2, level);
            
            const angle = (positionInLevel / totalInLevel) * 2 * Math.PI;
            const levelRadius = radius * (level + 1) / levels;
            
            node.position.x = levelRadius * Math.cos(angle);
            node.position.y = (level - levels / 2) * 50;
            node.position.z = levelRadius * Math.sin(angle);
        });
    }
    
    applyGalaxyLayout(nodes) {
        // Spiral galaxy layout
        nodes.forEach((node, index) => {
            const t = index / nodes.length;
            const spirals = 3;
            const radius = 150 * t;
            const angle = spirals * 2 * Math.PI * t;
            
            node.position.x = radius * Math.cos(angle);
            node.position.y = (Math.random() - 0.5) * 20;
            node.position.z = radius * Math.sin(angle);
        });
    }
    
    updateEdgePositions() {
        this.edges.forEach(edge => {
            const sourceNode = this.nodes.get(edge.userData.source);
            const targetNode = this.nodes.get(edge.userData.target);
            
            if (sourceNode && targetNode) {
                const positions = edge.geometry.attributes.position;
                positions.setXYZ(0, sourceNode.position.x, sourceNode.position.y, sourceNode.position.z);
                positions.setXYZ(1, targetNode.position.x, targetNode.position.y, targetNode.position.z);
                positions.needsUpdate = true;
            }
        });
    }
    
    resetView() {
        this.camera.position.set(0, 0, 300);
        this.camera.lookAt(0, 0, 0);
    }
    
    toggleLabels() {
        this.showLabels = !this.showLabels;
        
        // Remove existing labels
        const sprites = this.scene.children.filter(child => child instanceof THREE.Sprite);
        sprites.forEach(sprite => this.scene.remove(sprite));
        
        // Add labels if enabled
        if (this.showLabels) {
            this.nodes.forEach((node, id) => {
                this.addNodeLabel(node, node.userData.label);
            });
        }
    }
    
    toggleCriticalFilter() {
        this.filterCritical = !this.filterCritical;
        
        this.nodes.forEach(node => {
            if (this.filterCritical) {
                node.visible = node.userData.group === 'critical' || node.userData.group === 'self';
            } else {
                node.visible = true;
            }
        });
        
        this.edges.forEach(edge => {
            const sourceVisible = this.nodes.get(edge.userData.source)?.visible;
            const targetVisible = this.nodes.get(edge.userData.target)?.visible;
            edge.visible = sourceVisible && targetVisible;
        });
    }
    
    onNodeClick(event) {
        const rect = this.renderer.domElement.getBoundingClientRect();
        const mouse = new THREE.Vector2(
            ((event.clientX - rect.left) / rect.width) * 2 - 1,
            -((event.clientY - rect.top) / rect.height) * 2 + 1
        );
        
        const raycaster = new THREE.Raycaster();
        raycaster.setFromCamera(mouse, this.camera);
        
        const nodeObjects = Array.from(this.nodes.values());
        const intersects = raycaster.intersectObjects(nodeObjects);
        
        if (intersects.length > 0) {
            const clickedNode = intersects[0].object;
            this.showNodeDetails(clickedNode.userData);
        } else {
            this.hideNodeDetails();
        }
    }
    
    showNodeDetails(nodeData) {
        const panel = document.getElementById('node-details');
        if (!panel) return;
        
        panel.innerHTML = `
            <h3>${nodeData.label}</h3>
            <p><strong>IP:</strong> ${nodeData.id}</p>
            <p><strong>Group:</strong> ${nodeData.group}</p>
            ${nodeData.data ? `
                <p><strong>OS:</strong> ${nodeData.data.os || 'Unknown'}</p>
                <p><strong>Ports:</strong> ${nodeData.data.ports?.length || 0}</p>
                <p><strong>Vulnerabilities:</strong> ${nodeData.data.cves?.length || 0}</p>
            ` : ''}
        `;
        
        panel.classList.remove('hidden');
    }
    
    hideNodeDetails() {
        const panel = document.getElementById('node-details');
        if (panel) {
            panel.classList.add('hidden');
        }
    }
    
    clearScene() {
        // Remove all nodes and edges
        this.nodes.forEach(node => this.scene.remove(node));
        this.edges.forEach(edge => this.scene.remove(edge));
        
        // Remove labels
        const sprites = this.scene.children.filter(child => child instanceof THREE.Sprite);
        sprites.forEach(sprite => this.scene.remove(sprite));
        
        this.nodes.clear();
        this.edges = [];
    }
    
    onWindowResize() {
        const container = document.getElementById('network-3d-container');
        if (!container) return;
        
        this.camera.aspect = container.clientWidth / container.clientHeight;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(container.clientWidth, container.clientHeight);
    }
    
    animate() {
        requestAnimationFrame(() => this.animate());
        
        // Rotate nodes slightly for dynamic effect
        this.nodes.forEach(node => {
            node.rotation.y += 0.01;
        });
        
        this.renderer.render(this.scene, this.camera);
    }
}

// Initialize visualization when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.networkVisualization = new NetworkVisualization();
    });
} else {
    window.networkVisualization = new NetworkVisualization();
}

export default NetworkVisualization;

