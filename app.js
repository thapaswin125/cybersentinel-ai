// CyberSentinel AI Application JavaScript

// Application data from the provided JSON
const appData = {
  "threat_detection": {
    "current_threats": [
      {
        "id": "TH001",
        "type": "DDoS Attack",
        "severity": "High",
        "confidence": 0.94,
        "source_ip": "185.220.101.42",
        "target": "web-server-01",
        "timestamp": "2025-09-24T17:45:23Z",
        "ml_model": "Isolation Forest",
        "attack_vectors": ["TCP SYN Flood", "UDP Amplification"]
      },
      {
        "id": "TH002", 
        "type": "Malware Communication",
        "severity": "Critical",
        "confidence": 0.87,
        "source_ip": "192.168.1.105",
        "target": "external-c2.malware.net",
        "timestamp": "2025-09-24T17:42:11Z",
        "ml_model": "LSTM Neural Network",
        "attack_vectors": ["C2 Communication", "Data Exfiltration"]
      },
      {
        "id": "TH003",
        "type": "Phishing Campaign",
        "severity": "Medium",
        "confidence": 0.76,
        "source_ip": "203.45.67.89",
        "target": "email-server",
        "timestamp": "2025-09-24T17:38:45Z",
        "ml_model": "Random Forest",
        "attack_vectors": ["Email Spoofing", "Credential Harvesting"]
      }
    ],
    "model_performance": {
      "accuracy": 0.94,
      "precision": 0.91,
      "recall": 0.88,
      "f1_score": 0.89,
      "false_positive_rate": 0.06
    },
    "network_stats": {
      "total_packets": 2847291,
      "anomalous_packets": 1247,
      "threat_detections": 23,
      "blocked_connections": 156
    }
  },
  "osint_intelligence": {
    "feeds": [
      {
        "source": "DarkWeb Monitor",
        "intelligence_type": "Threat Actor Chatter",
        "indicator": "APT-29 planning healthcare sector targeting",
        "confidence": "High",
        "timestamp": "2025-09-24T16:30:00Z",
        "tags": ["APT29", "Healthcare", "Targeted Attack"]
      },
      {
        "source": "Social Media Scanner",
        "intelligence_type": "Leaked Credentials",
        "indicator": "Corporate email credentials on Telegram channels",
        "confidence": "Medium",
        "timestamp": "2025-09-24T15:45:00Z",
        "tags": ["Credential Leak", "Social Media", "Corporate"]
      },
      {
        "source": "Threat Intel Feeds",
        "intelligence_type": "IOC Discovery",
        "indicator": "New botnet C2 infrastructure identified",
        "confidence": "High", 
        "timestamp": "2025-09-24T14:20:00Z",
        "tags": ["Botnet", "C2", "Infrastructure"]
      }
    ],
    "threat_actors": [
      {
        "name": "APT-29 (Cozy Bear)",
        "last_activity": "2025-09-23",
        "target_sectors": ["Healthcare", "Government", "Technology"],
        "ttp_count": 47,
        "threat_level": "Critical"
      },
      {
        "name": "Lazarus Group",
        "last_activity": "2025-09-22", 
        "target_sectors": ["Financial", "Cryptocurrency", "Media"],
        "ttp_count": 52,
        "threat_level": "High"
      }
    ]
  },
  "misp_intelligence": {
    "events": [
      {
        "id": "MISP-001",
        "title": "Banking Trojan Campaign - Zeus Variant",
        "threat_level": "High",
        "analysis": "Ongoing",
        "timestamp": "2025-09-24T16:00:00Z",
        "ioc_count": 23,
        "attributes": ["IP", "Domain", "Hash", "URL"]
      },
      {
        "id": "MISP-002",
        "title": "Phishing Infrastructure - Office365 Impersonation", 
        "threat_level": "Medium",
        "analysis": "Complete",
        "timestamp": "2025-09-24T14:30:00Z",
        "ioc_count": 15,
        "attributes": ["Domain", "URL", "Email"]
      }
    ],
    "ioc_stats": {
      "total_iocs": 15847,
      "ip_addresses": 4521,
      "domains": 3892,
      "file_hashes": 4156,
      "urls": 3278
    }
  },
  "soar_automation": {
    "playbooks": [
      {
        "name": "DDoS Response Automation",
        "status": "Active",
        "last_executed": "2025-09-24T17:45:00Z",
        "success_rate": 0.94,
        "avg_response_time": "45 seconds"
      },
      {
        "name": "Malware Containment",
        "status": "Active", 
        "last_executed": "2025-09-24T17:42:00Z",
        "success_rate": 0.89,
        "avg_response_time": "2.3 minutes"
      },
      {
        "name": "Phishing Email Remediation",
        "status": "Active",
        "last_executed": "2025-09-24T16:15:00Z", 
        "success_rate": 0.92,
        "avg_response_time": "1.8 minutes"
      }
    ],
    "incident_queue": [
      {
        "id": "INC-001",
        "title": "Suspected Data Exfiltration",
        "priority": "Critical",
        "assigned_playbook": "Data Breach Response",
        "status": "In Progress",
        "eta": "5 minutes"
      },
      {
        "id": "INC-002", 
        "title": "Brute Force Login Attempts",
        "priority": "High",
        "assigned_playbook": "Account Lockout",
        "status": "Queued", 
        "eta": "2 minutes"
      }
    ]
  },
  "zero_trust": {
    "network_segments": [
      {
        "name": "DMZ",
        "devices": 12,
        "trust_score": 0.78,
        "policy_violations": 2,
        "status": "Healthy"
      },
      {
        "name": "Internal Network",
        "devices": 245,
        "trust_score": 0.92,
        "policy_violations": 0,
        "status": "Healthy"
      },
      {
        "name": "Guest Network", 
        "devices": 18,
        "trust_score": 0.45,
        "policy_violations": 5,
        "status": "Monitoring"
      }
    ],
    "access_attempts": [
      {
        "user": "john.smith@company.com",
        "resource": "File Server",
        "timestamp": "2025-09-24T17:40:00Z",
        "result": "Allowed",
        "trust_score": 0.94,
        "verification_methods": ["MFA", "Device Certificate"]
      },
      {
        "user": "unknown_device_192.168.1.55",
        "resource": "Database Server", 
        "timestamp": "2025-09-24T17:35:00Z",
        "result": "Denied",
        "trust_score": 0.23,
        "verification_methods": ["Failed Device Auth"]
      }
    ]
  },
  "quantum_security": {
    "algorithms": [
      {
        "name": "ML-KEM (Kyber)",
        "status": "Implemented",
        "strength": "Level 3",
        "performance": "Good",
        "compliance": "NIST Standard"
      },
      {
        "name": "ML-DSA (Dilithium)",
        "status": "Testing",
        "strength": "Level 2", 
        "performance": "Excellent",
        "compliance": "NIST Standard"
      },
      {
        "name": "Hybrid RSA-Kyber",
        "status": "Deployed",
        "strength": "Classical + PQC",
        "performance": "Moderate",
        "compliance": "Custom Implementation"
      }
    ],
    "threat_timeline": {
      "current_year": 2025,
      "quantum_advantage_estimated": 2035,
      "cryptographic_risk": "Low",
      "preparation_status": "On Track"
    }
  },
  "deception_technology": {
    "honeypots": [
      {
        "name": "Web Server Decoy",
        "type": "High Interaction",
        "location": "DMZ",
        "status": "Active",
        "interactions": 23,
        "threats_caught": 3
      },
      {
        "name": "Database Honey Trap",
        "type": "Medium Interaction", 
        "location": "Internal Network",
        "status": "Active",
        "interactions": 7,
        "threats_caught": 1
      },
      {
        "name": "Email Server Lure",
        "type": "Low Interaction",
        "location": "DMZ", 
        "status": "Active",
        "interactions": 45,
        "threats_caught": 8
      }
    ],
    "attacker_profiles": [
      {
        "id": "ACTOR-001",
        "first_seen": "2025-09-20T10:00:00Z",
        "interaction_count": 15,
        "skill_level": "Advanced",
        "techniques": ["SQL Injection", "XSS", "Directory Traversal"],
        "origin": "Eastern Europe"
      },
      {
        "id": "ACTOR-002", 
        "first_seen": "2025-09-23T14:30:00Z",
        "interaction_count": 8,
        "skill_level": "Intermediate", 
        "techniques": ["Brute Force", "Port Scanning"],
        "origin": "Southeast Asia"
      }
    ]
  }
};

// Chart colors
const chartColors = ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5', '#5D878F', '#DB4545', '#D2BA4C', '#964325', '#944454', '#13343B'];

// Global chart instances
let charts = {};

// Navigation functionality
function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const modules = document.querySelectorAll('.module');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Remove active class from all links and modules
            navLinks.forEach(nav => nav.classList.remove('active'));
            modules.forEach(mod => mod.classList.remove('active'));
            
            // Add active class to clicked link
            link.classList.add('active');
            
            // Show corresponding module
            const moduleId = link.dataset.module;
            const targetModule = document.getElementById(moduleId);
            if (targetModule) {
                targetModule.classList.add('active');
                
                // Initialize module-specific content
                initializeModule(moduleId);
            }
        });
    });
}

// Initialize module-specific content
function initializeModule(moduleId) {
    switch(moduleId) {
        case 'dashboard':
            initDashboard();
            break;
        case 'threat-detection':
            initThreatDetection();
            break;
        case 'osint':
            initOSINT();
            break;
        case 'misp':
            initMISP();
            break;
        case 'soar':
            initSOAR();
            break;
        case 'zero-trust':
            initZeroTrust();
            break;
        case 'quantum':
            initQuantumSecurity();
            break;
        case 'deception':
            initDeceptionTechnology();
            break;
    }
}

// Dashboard initialization
function initDashboard() {
    if (!charts.threatTimeline) {
        initThreatTimelineChart();
    }
    if (!charts.attackTypes) {
        initAttackTypesChart();
    }
}

// Threat Timeline Chart
function initThreatTimelineChart() {
    const ctx = document.getElementById('threatTimelineChart').getContext('2d');
    
    charts.threatTimeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['14:00', '15:00', '16:00', '17:00', '18:00'],
            datasets: [{
                label: 'Threats Detected',
                data: [8, 12, 15, 23, 18],
                borderColor: chartColors[0],
                backgroundColor: chartColors[0] + '20',
                fill: true,
                tension: 0.4
            }, {
                label: 'Threats Blocked',
                data: [7, 11, 13, 21, 17],
                borderColor: chartColors[1],
                backgroundColor: chartColors[1] + '20',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#e0e6ed' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#e0e6ed' }
                }
            },
            plugins: {
                legend: { 
                    labels: { color: '#e0e6ed' }
                }
            }
        }
    });
}

// Attack Types Chart
function initAttackTypesChart() {
    const ctx = document.getElementById('attackTypesChart').getContext('2d');
    
    charts.attackTypes = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['DDoS', 'Malware', 'Phishing', 'Brute Force', 'Other'],
            datasets: [{
                data: [35, 25, 20, 15, 5],
                backgroundColor: chartColors.slice(0, 5),
                borderColor: '#1a1f2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e0e6ed' }
                }
            }
        }
    });
}

// Threat Detection Module
function initThreatDetection() {
    renderThreatList();
    renderModelMetrics();
    if (!charts.networkTraffic) {
        initNetworkTrafficChart();
    }
}

function renderThreatList() {
    const container = document.getElementById('threatList');
    const threats = appData.threat_detection.current_threats;
    
    container.innerHTML = threats.map(threat => `
        <div class="threat-item" onclick="showThreatDetails('${threat.id}')">
            <div class="threat-header">
                <span class="threat-type">${threat.type}</span>
                <span class="threat-severity ${threat.severity.toLowerCase()}">${threat.severity}</span>
            </div>
            <div class="threat-details">
                <div><strong>Source:</strong> ${threat.source_ip}</div>
                <div><strong>Target:</strong> ${threat.target}</div>
                <div><strong>Confidence:</strong> ${(threat.confidence * 100).toFixed(1)}%</div>
                <div><strong>Model:</strong> ${threat.ml_model}</div>
            </div>
        </div>
    `).join('');
}

function renderModelMetrics() {
    const container = document.getElementById('modelMetrics');
    const metrics = appData.threat_detection.model_performance;
    
    container.innerHTML = Object.entries(metrics).map(([key, value]) => `
        <div class="metric-row">
            <span class="metric-name">${key.replace('_', ' ')}</span>
            <span class="metric-score">${(value * 100).toFixed(1)}%</span>
        </div>
    `).join('');
}

function initNetworkTrafficChart() {
    const ctx = document.getElementById('networkTrafficChart').getContext('2d');
    
    charts.networkTraffic = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Total Packets', 'Anomalous', 'Threats', 'Blocked'],
            datasets: [{
                label: 'Network Statistics',
                data: [2847291, 1247, 23, 156],
                backgroundColor: chartColors.slice(0, 4),
                borderColor: chartColors.slice(0, 4),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    type: 'logarithmic',
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#e0e6ed' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.1)' },
                    ticks: { color: '#e0e6ed' }
                }
            },
            plugins: {
                legend: { 
                    labels: { color: '#e0e6ed' }
                }
            }
        }
    });
}

// OSINT Module
function initOSINT() {
    renderIntelFeeds();
    renderThreatActors();
}

function renderIntelFeeds() {
    const container = document.getElementById('intelFeeds');
    const feeds = appData.osint_intelligence.feeds;
    
    container.innerHTML = feeds.map(feed => `
        <div class="intel-item">
            <div class="intel-header">
                <span class="intel-source">${feed.source}</span>
                <span class="intel-confidence ${feed.confidence.toLowerCase()}">${feed.confidence}</span>
            </div>
            <div class="intel-indicator">${feed.indicator}</div>
            <div class="intel-tags">
                ${feed.tags.map(tag => `<span class="intel-tag">${tag}</span>`).join('')}
            </div>
        </div>
    `).join('');
}

function renderThreatActors() {
    const container = document.getElementById('threatActors');
    const actors = appData.osint_intelligence.threat_actors;
    
    container.innerHTML = actors.map(actor => `
        <div class="actor-item">
            <div class="actor-name">${actor.name}</div>
            <div class="actor-stats">
                <div><strong>Last Activity:</strong> ${actor.last_activity}</div>
                <div><strong>Threat Level:</strong> ${actor.threat_level}</div>
                <div><strong>TTPs:</strong> ${actor.ttp_count}</div>
                <div><strong>Targets:</strong> ${actor.target_sectors.join(', ')}</div>
            </div>
        </div>
    `).join('');
}

// MISP Module
function initMISP() {
    renderMISPEvents();
    if (!charts.iocChart) {
        initIOCChart();
    }
}

function renderMISPEvents() {
    const container = document.getElementById('mispEvents');
    const events = appData.misp_intelligence.events;
    
    container.innerHTML = events.map(event => `
        <div class="intel-item">
            <div class="intel-header">
                <span class="intel-source">${event.id}</span>
                <span class="intel-confidence ${event.threat_level.toLowerCase()}">${event.threat_level}</span>
            </div>
            <div class="intel-indicator">${event.title}</div>
            <div class="actor-stats">
                <div><strong>Analysis:</strong> ${event.analysis}</div>
                <div><strong>IOCs:</strong> ${event.ioc_count}</div>
                <div><strong>Attributes:</strong> ${event.attributes.join(', ')}</div>
                <div><strong>Timestamp:</strong> ${new Date(event.timestamp).toLocaleString()}</div>
            </div>
        </div>
    `).join('');
}

function initIOCChart() {
    const ctx = document.getElementById('iocChart').getContext('2d');
    const stats = appData.misp_intelligence.ioc_stats;
    
    charts.iocChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['IP Addresses', 'Domains', 'File Hashes', 'URLs'],
            datasets: [{
                data: [stats.ip_addresses, stats.domains, stats.file_hashes, stats.urls],
                backgroundColor: chartColors.slice(0, 4),
                borderColor: '#1a1f2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e0e6ed' }
                }
            }
        }
    });
}

// SOAR Module
function initSOAR() {
    renderPlaybooks();
    renderIncidentQueue();
}

function renderPlaybooks() {
    const container = document.getElementById('playbooks');
    const playbooks = appData.soar_automation.playbooks;
    
    container.innerHTML = playbooks.map(playbook => `
        <div class="playbook-item">
            <div class="playbook-header">
                <span class="playbook-name">${playbook.name}</span>
                <span class="playbook-status">${playbook.status}</span>
            </div>
            <div class="playbook-stats">
                <div><strong>Success Rate:</strong> ${(playbook.success_rate * 100).toFixed(1)}%</div>
                <div><strong>Avg Response:</strong> ${playbook.avg_response_time}</div>
                <div><strong>Last Executed:</strong> ${new Date(playbook.last_executed).toLocaleTimeString()}</div>
            </div>
        </div>
    `).join('');
}

function renderIncidentQueue() {
    const container = document.getElementById('incidentQueue');
    const incidents = appData.soar_automation.incident_queue;
    
    container.innerHTML = incidents.map(incident => `
        <div class="incident-item">
            <div class="intel-header">
                <span class="intel-source">${incident.id}</span>
                <span class="incident-priority ${incident.priority.toLowerCase()}">${incident.priority}</span>
            </div>
            <div class="intel-indicator">${incident.title}</div>
            <div class="actor-stats">
                <div><strong>Playbook:</strong> ${incident.assigned_playbook}</div>
                <div><strong>Status:</strong> ${incident.status}</div>
                <div><strong>ETA:</strong> ${incident.eta}</div>
            </div>
        </div>
    `).join('');
}

// Zero Trust Module
function initZeroTrust() {
    renderNetworkSegments();
    renderAccessAttempts();
}

function renderNetworkSegments() {
    const container = document.getElementById('networkSegments');
    const segments = appData.zero_trust.network_segments;
    
    container.innerHTML = segments.map(segment => `
        <div class="segment-item">
            <div class="intel-header">
                <span class="intel-source">${segment.name}</span>
                <span class="trust-score">${(segment.trust_score * 100).toFixed(0)}%</span>
            </div>
            <div class="actor-stats">
                <div><strong>Devices:</strong> ${segment.devices}</div>
                <div><strong>Violations:</strong> ${segment.policy_violations}</div>
                <div><strong>Status:</strong> ${segment.status}</div>
            </div>
        </div>
    `).join('');
}

function renderAccessAttempts() {
    const container = document.getElementById('accessAttempts');
    const attempts = appData.zero_trust.access_attempts;
    
    container.innerHTML = attempts.map(attempt => `
        <div class="access-item">
            <div class="intel-header">
                <span class="intel-source">${attempt.user}</span>
                <span class="access-result ${attempt.result.toLowerCase()}">${attempt.result}</span>
            </div>
            <div class="actor-stats">
                <div><strong>Resource:</strong> ${attempt.resource}</div>
                <div><strong>Trust Score:</strong> ${(attempt.trust_score * 100).toFixed(0)}%</div>
                <div><strong>Verification:</strong> ${attempt.verification_methods.join(', ')}</div>
                <div><strong>Time:</strong> ${new Date(attempt.timestamp).toLocaleTimeString()}</div>
            </div>
        </div>
    `).join('');
}

// Quantum Security Module
function initQuantumSecurity() {
    renderQuantumAlgorithms();
    renderQuantumTimeline();
}

function renderQuantumAlgorithms() {
    const container = document.getElementById('quantumAlgorithms');
    const algorithms = appData.quantum_security.algorithms;
    
    container.innerHTML = algorithms.map(algo => `
        <div class="algorithm-item">
            <div class="intel-header">
                <span class="intel-source">${algo.name}</span>
                <span class="algorithm-status ${algo.status.toLowerCase()}">${algo.status}</span>
            </div>
            <div class="actor-stats">
                <div><strong>Strength:</strong> ${algo.strength}</div>
                <div><strong>Performance:</strong> ${algo.performance}</div>
                <div><strong>Compliance:</strong> ${algo.compliance}</div>
            </div>
        </div>
    `).join('');
}

function renderQuantumTimeline() {
    const container = document.getElementById('quantumTimeline');
    const timeline = appData.quantum_security.threat_timeline;
    
    container.innerHTML = `
        <div class="actor-stats">
            <div><strong>Current Year:</strong> ${timeline.current_year}</div>
            <div><strong>Quantum Advantage Est.:</strong> ${timeline.quantum_advantage_estimated}</div>
            <div><strong>Current Risk:</strong> ${timeline.cryptographic_risk}</div>
            <div><strong>Preparation Status:</strong> ${timeline.preparation_status}</div>
        </div>
    `;
}

// Deception Technology Module
function initDeceptionTechnology() {
    renderHoneypots();
    renderAttackerProfiles();
}

function renderHoneypots() {
    const container = document.getElementById('honeypots');
    const honeypots = appData.deception_technology.honeypots;
    
    container.innerHTML = honeypots.map(honeypot => `
        <div class="honeypot-item">
            <div class="intel-header">
                <span class="intel-source">${honeypot.name}</span>
                <span class="playbook-status">${honeypot.status}</span>
            </div>
            <div class="actor-stats">
                <div><strong>Type:</strong> ${honeypot.type}</div>
                <div><strong>Location:</strong> ${honeypot.location}</div>
                <div><strong>Interactions:</strong> ${honeypot.interactions}</div>
                <div><strong>Threats Caught:</strong> ${honeypot.threats_caught}</div>
            </div>
        </div>
    `).join('');
}

function renderAttackerProfiles() {
    const container = document.getElementById('attackerProfiles');
    const profiles = appData.deception_technology.attacker_profiles;
    
    container.innerHTML = profiles.map(profile => `
        <div class="actor-item">
            <div class="actor-name">${profile.id}</div>
            <div class="actor-stats">
                <div><strong>First Seen:</strong> ${new Date(profile.first_seen).toLocaleDateString()}</div>
                <div><strong>Interactions:</strong> ${profile.interaction_count}</div>
                <div><strong>Skill Level:</strong> ${profile.skill_level}</div>
                <div><strong>Origin:</strong> ${profile.origin}</div>
                <div><strong>Techniques:</strong> ${profile.techniques.join(', ')}</div>
            </div>
        </div>
    `).join('');
}

// Modal functionality
function showThreatDetails(threatId) {
    const threat = appData.threat_detection.current_threats.find(t => t.id === threatId);
    if (!threat) return;
    
    const modal = document.getElementById('alertModal');
    const title = document.getElementById('alertTitle');
    const body = document.getElementById('alertBody');
    
    title.textContent = `Threat Alert: ${threat.type}`;
    body.innerHTML = `
        <div class="threat-details-modal">
            <div class="detail-row"><strong>Threat ID:</strong> ${threat.id}</div>
            <div class="detail-row"><strong>Type:</strong> ${threat.type}</div>
            <div class="detail-row"><strong>Severity:</strong> ${threat.severity}</div>
            <div class="detail-row"><strong>Confidence:</strong> ${(threat.confidence * 100).toFixed(1)}%</div>
            <div class="detail-row"><strong>Source IP:</strong> ${threat.source_ip}</div>
            <div class="detail-row"><strong>Target:</strong> ${threat.target}</div>
            <div class="detail-row"><strong>ML Model:</strong> ${threat.ml_model}</div>
            <div class="detail-row"><strong>Attack Vectors:</strong> ${threat.attack_vectors.join(', ')}</div>
            <div class="detail-row"><strong>Timestamp:</strong> ${new Date(threat.timestamp).toLocaleString()}</div>
        </div>
    `;
    
    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('alertModal').classList.add('hidden');
}

// Real-time updates simulation
function simulateRealTimeUpdates() {
    setInterval(() => {
        // Update alert counter randomly
        const alertBadge = document.querySelector('.alert-badge');
        const currentAlerts = parseInt(alertBadge.textContent);
        const change = Math.random() > 0.7 ? (Math.random() > 0.5 ? 1 : -1) : 0;
        const newAlerts = Math.max(0, currentAlerts + change);
        alertBadge.textContent = newAlerts;
        
        // Flash the badge if alerts increased
        if (change > 0) {
            alertBadge.style.animation = 'flash 0.5s ease-in-out';
            setTimeout(() => alertBadge.style.animation = '', 500);
        }
    }, 5000);
}

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDashboard(); // Initialize dashboard by default
    simulateRealTimeUpdates();
});

// CSS animation for flashing alerts
const style = document.createElement('style');
style.textContent = `
    @keyframes flash {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .detail-row {
        margin-bottom: 12px;
        padding: 8px;
        background: rgba(0, 255, 136, 0.05);
        border-radius: 4px;
    }
    
    .threat-details-modal {
        color: #e0e6ed;
    }
`;
document.head.appendChild(style);

// Close modal on outside click
document.getElementById('alertModal').addEventListener('click', (e) => {
    if (e.target.id === 'alertModal') {
        closeModal();
    }
});

// Export functions for global access
window.showThreatDetails = showThreatDetails;
window.closeModal = closeModal;