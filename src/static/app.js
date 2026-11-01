// Light-SOC Dashboard Frontend JavaScript

// Configuration
const API_BASE = '/api';
const WS_URL = `ws://${window.location.host}/ws`;

// State
let accessToken = localStorage.getItem('light_soc_token') || null;
let ws = null;
let wsReconnectTimer = null;
let currentPage = 'dashboard';
let incidentsPage = 0;
const incidentsPerPage = 20;
let currentSeverityFilter = '';
let charts = {};

// DOM Elements
const loginModal = document.getElementById('loginModal');
const app = document.getElementById('app');
const loginForm = document.getElementById('loginForm');
const logoutBtn = document.getElementById('logoutBtn');
const menuBtn = document.getElementById('menuBtn');
const sidebar = document.getElementById('sidebar');
const sidebarOverlay = document.getElementById('sidebarOverlay');
const navLinks = document.querySelectorAll('.nav-link');
const pageContent = document.getElementById('pageContent');
const pageTitle = document.getElementById('pageTitle');
const currentUser = document.getElementById('currentUser');
const wsStatus = document.getElementById('wsStatus');
const wsStatusText = document.getElementById('wsStatusText');
const currentTime = document.getElementById('currentTime');

// Modals
const blockIpModal = document.getElementById('blockIpModal');
const blockIpForm = document.getElementById('blockIpForm');
const cancelBlockIp = document.getElementById('cancelBlockIp');
const agentCommandModal = document.getElementById('agentCommandModal');
const agentCommandForm = document.getElementById('agentCommandForm');
const cancelAgentCommand = document.getElementById('cancelAgentCommand');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupEventListeners();
    updateTime();
    setInterval(updateTime, 1000);
});

function checkAuth() {
    if (accessToken) {
        // Verify token by making a request
        fetch(`${API_BASE}/auth/me`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        })
        .then(res => {
            if (res.ok) {
                showApp();
            } else {
                logout();
            }
        })
        .catch(() => logout());
    } else {
        showLogin();
    }
}

function showLogin() {
    loginModal.classList.remove('hidden');
    app.classList.add('hidden');
}

function showApp() {
    loginModal.classList.add('hidden');
    app.classList.remove('hidden');
    currentUser.textContent = 'admin';
    connectWebSocket();
    navigateTo('dashboard');
    loadDashboardData();
}

function logout() {
    accessToken = null;
    localStorage.removeItem('light_soc_token');
    if (ws) {
        ws.close();
        ws = null;
    }
    showLogin();
}

function setupEventListeners() {
    // Login
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
            const res = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            if (res.ok) {
                const data = await res.json();
                accessToken = data.access_token;
                localStorage.setItem('light_soc_token', accessToken);
                showApp();
            } else {
                alert('Invalid credentials');
            }
        } catch (err) {
            alert('Login failed: ' + err.message);
        }
    });

    // Logout
    logoutBtn.addEventListener('click', logout);

    // Navigation
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            navigateTo(page);
            
            // Update active state
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            // Close mobile sidebar
            sidebar.classList.remove('open');
            sidebarOverlay.classList.add('hidden');
        });
    });

    // Mobile menu
    menuBtn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        sidebarOverlay.classList.toggle('hidden');
    });
    sidebarOverlay.addEventListener('click', () => {
        sidebar.classList.remove('open');
        sidebarOverlay.classList.add('hidden');
    });

    // Block IP Modal
    document.getElementById('blockIpBtn').addEventListener('click', () => {
        blockIpModal.classList.remove('hidden');
    });
    cancelBlockIp.addEventListener('click', () => {
        blockIpModal.classList.add('hidden');
        blockIpForm.reset();
    });
    blockIpForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ip = document.getElementById('blockIpInput').value;
        const reason = document.getElementById('blockReasonInput').value;
        const duration = parseInt(document.getElementById('blockDurationInput').value);
        
        try {
            const res = await apiPost('/blocked-ips', { ip, reason, duration });
            if (res.success) {
                blockIpModal.classList.add('hidden');
                blockIpForm.reset();
                loadBlockedIPs();
                loadDashboardData();
            }
        } catch (err) {
            alert(err.message);
        }
    });

    // Agent Command Modal
    cancelAgentCommand.addEventListener('click', () => {
        agentCommandModal.classList.add('hidden');
        agentCommandForm.reset();
    });
    agentCommandForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const agentId = document.getElementById('agentCommandAgentId').value;
        const command = document.getElementById('agentCommandSelect').value;
        let args = {};
        
        try {
            const argsInput = document.getElementById('agentCommandArgsInput').value;
            if (argsInput) args = JSON.parse(argsInput);
        } catch (err) {
            alert('Invalid JSON in arguments');
            return;
        }
        
        try {
            const res = await apiPost(`/agents/${agentId}/command`, { command, args });
            if (res.success) {
                agentCommandModal.classList.add('hidden');
                agentCommandForm.reset();
            }
        } catch (err) {
            alert(err.message);
        }
    });

    // Scan buttons
    document.getElementById('runFimScan').addEventListener('click', async () => {
        const btn = document.getElementById('runFimScan');
        btn.disabled = true;
        btn.textContent = 'Scanning...';
        try {
            await apiPost('/scans/fim');
            loadScanStatus();
        } finally {
            btn.disabled = false;
            btn.textContent = 'Run FIM Scan';
        }
    });

    document.getElementById('runVulnScan').addEventListener('click', async () => {
        const btn = document.getElementById('runVulnScan');
        btn.disabled = true;
        btn.textContent = 'Scanning...';
        try {
            await apiPost('/scans/vulnerability');
            loadScanStatus();
        } finally {
            btn.disabled = false;
            btn.textContent = 'Run Vulnerability Scan';
        }
    });

    document.getElementById('runScaScan').addEventListener('click', async () => {
        const btn = document.getElementById('runScaScan');
        btn.disabled = true;
        btn.textContent = 'Scanning...';
        try {
            await apiPost('/scans/sca');
            loadScanStatus();
        } finally {
            btn.disabled = false;
            btn.textContent = 'Run SCA Scan';
        }
    });

    document.getElementById('runTiUpdate').addEventListener('click', async () => {
        const btn = document.getElementById('runTiUpdate');
        btn.disabled = true;
        btn.textContent = 'Updating...';
        try {
            await apiPost('/scans/threat-intel');
            loadScanStatus();
        } finally {
            btn.disabled = false;
            btn.textContent = 'Update All Feeds';
        }
    });

    // Threat intel check
    document.getElementById('checkIpBtn').addEventListener('click', async () => {
        const ip = document.getElementById('checkIpInput').value.trim();
        if (!ip) return;
        const res = await apiGet(`/threat-intel/check-ip/${ip}`);
        showThreatIntelResult(res, 'IP');
    });

    document.getElementById('checkDomainBtn').addEventListener('click', async () => {
        const domain = document.getElementById('checkDomainInput').value.trim();
        if (!domain) return;
        const res = await apiGet(`/threat-intel/check-domain/${domain}`);
        showThreatIntelResult(res, 'Domain');
    });

    // Refresh buttons
    document.getElementById('refreshIncidents').addEventListener('click', loadIncidents);
    document.getElementById('refreshAgents').addEventListener('click', loadAgents);
    document.getElementById('refreshFeeds').addEventListener('click', loadThreatIntelFeeds);
    document.getElementById('prevIncidents').addEventListener('click', () => {
        if (incidentsPage > 0) { incidentsPage--; loadIncidents(); }
    });
    document.getElementById('nextIncidents').addEventListener('click', () => {
        incidentsPage++; loadIncidents();
    });
    document.getElementById('severityFilter').addEventListener('change', (e) => {
        currentSeverityFilter = e.target.value;
        incidentsPage = 0;
        loadIncidents();
    });

    // Change password
    document.getElementById('changePasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        // Would need backend endpoint
        alert('Password change requires backend implementation');
    });
}

function navigateTo(page) {
    currentPage = page;
    
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(p => p.classList.add('hidden'));
    
    // Show target page
    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.remove('hidden');
    }
    
    // Update title
    const titles = {
        'dashboard': 'Dashboard',
        'incidents': 'Incidents',
        'blocked-ips': 'Blocked IPs',
        'agents': 'Agents',
        'scans': 'Security Scans',
        'threat-intel': 'Threat Intelligence',
        'settings': 'Settings'
    };
    pageTitle.textContent = titles[page] || 'Dashboard';
    
    // Load page data
    switch(page) {
        case 'dashboard': loadDashboardData(); break;
        case 'incidents': loadIncidents(); break;
        case 'blocked-ips': loadBlockedIPs(); break;
        case 'agents': loadAgents(); break;
        case 'scans': loadScanStatus(); break;
        case 'threat-intel': loadThreatIntelFeeds(); break;
        case 'settings': loadSettings(); break;
    }
}

// API Helper Functions
async function apiRequest(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }
    
    const res = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
    });
    
    if (res.status === 401) {
        logout();
        throw new Error('Unauthorized');
    }
    
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Request failed' }));
        throw new Error(err.detail || 'Request failed');
    }
    
    return res.json();
}

async function apiGet(endpoint) {
    return apiRequest(endpoint, { method: 'GET' });
}

async function apiPost(endpoint, data) {
    return apiRequest(endpoint, { method: 'POST', body: JSON.stringify(data) });
}

async function apiDelete(endpoint) {
    return apiRequest(endpoint, { method: 'DELETE' });
}

// WebSocket
function connectWebSocket() {
    if (ws) ws.close();
    
    ws = new WebSocket(WS_URL);
    
    ws.onopen = () => {
        console.log('WebSocket connected');
        wsStatus.classList.remove('bg-gray-400');
        wsStatus.classList.add('bg-green-500');
        wsStatusText.textContent = 'Connected';
    };
    
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWebSocketMessage(msg);
        } catch (err) {
            console.error('WS message parse error:', err);
        }
    };
    
    ws.onclose = () => {
        console.log('WebSocket disconnected');
        wsStatus.classList.remove('bg-green-500');
        wsStatus.classList.add('bg-red-500');
        wsStatusText.textContent = 'Disconnected';
        
        // Reconnect
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = setTimeout(connectWebSocket, 5000);
    };
    
    ws.onerror = (err) => {
        console.error('WebSocket error:', err);
    };
}

function handleWebSocketMessage(msg) {
    switch(msg.type) {
        case 'initial_status':
        case 'status_update':
            updateDashboardStats(msg.data);
            break;
        case 'blocked_ip_added':
        case 'blocked_ip_removed':
            loadBlockedIPs();
            loadDashboardData();
            break;
        case 'pong':
            // Heartbeat response
            break;
    }
}

// Data Loading Functions
async function loadDashboardData() {
    try {
        const [status, incidents, blocked, agents] = await Promise.all([
            apiGet('/system/status'),
            apiGet('/incidents?limit=5'),
            apiGet('/blocked-ips'),
            apiGet('/agents')
        ]);
        
        updateDashboardStats(status);
        renderRecentIncidents(incidents);
        renderRecentBlocks(blocked);
        updateBadges(incidents.length, blocked.length, agents.length);
    } catch (err) {
        console.error('Failed to load dashboard:', err);
    }
}

function updateDashboardStats(status) {
    document.getElementById('statIncidents').textContent = status.total_incidents;
    document.getElementById('statBlocked').textContent = status.blocked_ips;
    document.getElementById('statAgents').textContent = Object.values(status.modules || {}).filter(m => m).length;
    document.getElementById('statThreats').textContent = status.threat_intel_indicators || 0;
    
    // Update charts
    updateSeverityChart(status);
    updateTimelineChart(status);
}

function updateBadges(incidents, blocked, agents) {
    const incidentBadge = document.getElementById('incidentBadge');
    const blockedBadge = document.getElementById('blockedBadge');
    const agentBadge = document.getElementById('agentBadge');
    
    incidentBadge.textContent = incidents;
    incidentBadge.classList.toggle('hidden', incidents === 0);
    
    blockedBadge.textContent = blocked;
    blockedBadge.classList.toggle('hidden', blocked === 0);
    
    agentBadge.textContent = agents;
    agentBadge.classList.toggle('hidden', agents === 0);
}

function renderRecentIncidents(incidents) {
    const container = document.getElementById('recentIncidents');
    
    if (!incidents.length) {
        container.innerHTML = '<div class="px-6 py-4 text-center text-gray-500">No recent incidents</div>';
        return;
    }
    
    container.innerHTML = incidents.map(inc => `
        <div class="px-6 py-4 hover:bg-gray-50">
            <div class="flex items-center justify-between">
                <div>
                    <p class="font-medium text-gray-900">${inc.incident_type}</p>
                    <p class="text-sm text-gray-500">${inc.attacker_ip} • ${inc.total_attempts} attempts</p>
                </div>
                <span class="px-2 py-1 text-xs font-medium rounded-full severity-${inc.severity.toLowerCase()}">${inc.severity}</span>
            </div>
        </div>
    `).join('');
}

function renderRecentBlocks(blocked) {
    const container = document.getElementById('recentBlocks');
    
    if (!blocked.length) {
        container.innerHTML = '<div class="px-6 py-4 text-center text-gray-500">No recent blocks</div>';
        return;
    }
    
    container.innerHTML = blocked.slice(0, 5).map(b => `
        <div class="px-6 py-4 hover:bg-gray-50">
            <div class="flex items-center justify-between">
                <div>
                    <p class="font-medium text-gray-900">${b.ip}</p>
                    <p class="text-sm text-gray-500">${b.reason}</p>
                </div>
                <span class="px-2 py-1 text-xs font-medium rounded-full ${b.active ? 'status-active' : 'status-inactive'}">
                    ${b.active ? 'Active' : 'Expired'}
                </span>
            </div>
        </div>
    `).join('');
}

// Incidents Page
async function loadIncidents() {
    try {
        const severityParam = currentSeverityFilter ? `&severity=${currentSeverityFilter}` : '';
        const incidents = await apiGet(`/incidents?limit=${incidentsPerPage}&offset=${incidentsPage * incidentsPerPage}${severityParam}`);
        
        const tbody = document.getElementById('incidentsBody');
        const info = document.getElementById('incidentsInfo');
        const prevBtn = document.getElementById('prevIncidents');
        const nextBtn = document.getElementById('nextIncidents');
        
        if (!incidents.length) {
            tbody.innerHTML = '<tr><td colspan="8" class="px-6 py-12 text-center text-gray-500">No incidents found</td></tr>';
            info.textContent = 'Showing 0 of 0 incidents';
            prevBtn.disabled = true;
            nextBtn.disabled = true;
            return;
        }
        
        tbody.innerHTML = incidents.map(inc => `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4">${formatDate(inc.created_at)}</td>
                <td class="px-6 py-4">${inc.incident_type}</td>
                <td class="px-6 py-4"><span class="px-2 py-1 text-xs font-medium rounded-full severity-${inc.severity.toLowerCase()}">${inc.severity}</span></td>
                <td class="px-6 py-4 font-mono">${inc.attacker_ip}</td>
                <td class="px-6 py-4">${inc.total_attempts}</td>
                <td class="px-6 py-4">${inc.successful ? '<span class="text-green-600">Yes</span>' : '<span class="text-gray-500">No</span>'}</td>
                <td class="px-6 py-4">${Math.round(inc.confidence * 100)}%</td>
                <td class="px-6 py-4 text-right">
                    <button onclick="viewIncident('${inc.id}')" class="text-blue-600 hover:text-blue-700 text-sm font-medium">View</button>
                </td>
            </tr>
        `).join('');
        
        info.textContent = `Showing ${incidentsPage * incidentsPerPage + 1} - ${incidentsPage * incidentsPerPage + incidents.length} incidents`;
        prevBtn.disabled = incidentsPage === 0;
        nextBtn.disabled = incidents.length < incidentsPerPage;
    } catch (err) {
        console.error('Failed to load incidents:', err);
        document.getElementById('incidentsBody').innerHTML = '<tr><td colspan="8" class="px-6 py-12 text-center text-red-500">Failed to load incidents</td></tr>';
    }
}

window.viewIncident = function(incidentId) {
    // Could open modal with details
    alert('Incident detail view - implement modal');
};

// Blocked IPs Page
async function loadBlockedIPs() {
    try {
        const blocked = await apiGet('/blocked-ips');
        const tbody = document.getElementById('blockedBody');
        
        if (!blocked.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-gray-500">No blocked IPs</td></tr>';
            return;
        }
        
        tbody.innerHTML = blocked.map(b => `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 font-mono">${b.ip}</td>
                <td class="px-6 py-4">${b.reason}</td>
                <td class="px-6 py-4">${formatDate(b.blocked_at)}</td>
                <td class="px-6 py-4">${b.expires_at ? formatDate(b.expires_at) : 'Never'}</td>
                <td class="px-6 py-4"><span class="px-2 py-1 text-xs font-medium rounded-full ${b.active ? 'status-active' : 'status-inactive'}">${b.active ? 'Active' : 'Expired'}</span></td>
                <td class="px-6 py-4 text-right">
                    ${b.active ? `<button onclick="unblockIp('${b.ip}')" class="text-red-600 hover:text-red-700 text-sm font-medium">Unblock</button>` : '<span class="text-gray-400 text-sm">Expired</span>'}
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to load blocked IPs:', err);
    }
}

window.unblockIp = async function(ip) {
    if (!confirm(`Unblock ${ip}?`)) return;
    try {
        await apiDelete(`/blocked-ips/${ip}`);
        loadBlockedIPs();
        loadDashboardData();
    } catch (err) {
        alert(err.message);
    }
};

// Agents Page
async function loadAgents() {
    try {
        const agents = await apiGet('/agents');
        const tbody = document.getElementById('agentsBody');
        
        if (!agents.length) {
            tbody.innerHTML = '<tr><td colspan="8" class="px-6 py-12 text-center text-gray-500">No agents connected</td></tr>';
            return;
        }
        
        tbody.innerHTML = agents.map(a => `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4">${a.name}</td>
                <td class="px-6 py-4 font-mono text-sm">${a.agent_id.substring(0, 12)}...</td>
                <td class="px-6 py-4">${a.ip}</td>
                <td class="px-6 py-4">${a.platform}</td>
                <td class="px-6 py-4"><span class="px-2 py-1 text-xs font-medium rounded-full status-${a.status.toLowerCase()}">${a.status}</span></td>
                <td class="px-6 py-4">${a.last_heartbeat ? formatDate(a.last_heartbeat) : 'Never'}</td>
                <td class="px-6 py-4">${a.tags.join(', ') || '-'}</td>
                <td class="px-6 py-4 text-right">
                    <button onclick="openAgentCommand('${a.agent_id}', '${a.name}')" class="text-blue-600 hover:text-blue-700 text-sm font-medium">Command</button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to load agents:', err);
    }
}

window.openAgentCommand = function(agentId, agentName) {
    document.getElementById('agentCommandAgentId').value = agentId;
    document.querySelector('#agentCommandModal h3').textContent = `Send Command to ${agentName}`;
    agentCommandModal.classList.remove('hidden');
};

// Scans Page
async function loadScanStatus() {
    try {
        const status = await apiGet('/scans/status');
        
        // FIM
        if (status.fim.enabled) {
            document.getElementById('fimStatus').textContent = 'Enabled';
            document.getElementById('fimStatus').className = 'status-badge status-active';
            document.getElementById('fimBaseline').textContent = status.fim.baseline_files || 0;
            document.getElementById('fimAlerts').textContent = status.fim.alerts || 0;
        } else {
            document.getElementById('fimStatus').textContent = 'Disabled';
            document.getElementById('fimStatus').className = 'status-badge status-inactive';
        }
        
        // Vulnerability
        if (status.vulnerability.enabled) {
            document.getElementById('vulnStatus').textContent = 'Enabled';
            document.getElementById('vulnStatus').className = 'status-badge status-active';
            document.getElementById('vulnTotal').textContent = status.vulnerability.total_packages || 0;
            document.getElementById('vulnVulnerable').textContent = status.vulnerability.vulnerable_packages || 0;
            document.getElementById('vulnCves').textContent = status.vulnerability.total_cves || 0;
        } else {
            document.getElementById('vulnStatus').textContent = 'Disabled';
            document.getElementById('vulnStatus').className = 'status-badge status-inactive';
        }
        
        // SCA
        if (status.sca.enabled) {
            document.getElementById('scaStatus').textContent = 'Enabled';
            document.getElementById('scaStatus').className = 'status-badge status-active';
            document.getElementById('scaTotal').textContent = status.sca.total_checks || 0;
            document.getElementById('scaPassed').textContent = status.sca.passed || 0;
            document.getElementById('scaFailed').textContent = status.sca.failed || 0;
        } else {
            document.getElementById('scaStatus').textContent = 'Disabled';
            document.getElementById('scaStatus').className = 'status-badge status-inactive';
        }
        
        // Threat Intel
        if (status.threat_intel.enabled) {
            document.getElementById('tiStatus').textContent = 'Enabled';
            document.getElementById('tiStatus').className = 'status-badge status-active';
            document.getElementById('tiIndicators').textContent = status.threat_intel.indicators || 0;
            document.getElementById('tiFeeds').textContent = status.threat_intel.feeds_active || 0;
            document.getElementById('tiLastUpdate').textContent = status.threat_intel.last_update ? formatDate(status.threat_intel.last_update) : 'Never';
        } else {
            document.getElementById('tiStatus').textContent = 'Disabled';
            document.getElementById('tiStatus').className = 'status-badge status-inactive';
        }
    } catch (err) {
        console.error('Failed to load scan status:', err);
    }
}

// Threat Intel Page
async function loadThreatIntelFeeds() {
    try {
        const feeds = await apiGet('/threat-intel/feeds');
        const tbody = document.getElementById('feedsBody');
        
        if (!feeds.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-gray-500">No feeds configured</td></tr>';
            return;
        }
        
        tbody.innerHTML = feeds.map(f => `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4">${f.name}</td>
                <td class="px-6 py-4">${f.feed_type}</td>
                <td class="px-6 py-4">${f.indicator_count}</td>
                <td class="px-6 py-4"><span class="px-2 py-1 text-xs font-medium rounded-full ${f.enabled && !f.last_error ? 'status-active' : 'status-inactive'}">${f.enabled && !f.last_error ? 'OK' : 'Error'}</span></td>
                <td class="px-6 py-4">${f.last_updated ? formatDate(f.last_updated) : 'Never'}</td>
                <td class="px-6 py-4 text-red-500 text-sm">${f.last_error || '-'}</td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Failed to load feeds:', err);
    }
}

function showThreatIntelResult(res, type) {
    const container = document.getElementById('tiCheckResult');
    container.classList.remove('hidden');
    
    if (!res.matches) {
        container.innerHTML = `<p class="text-green-600">${type} not found in threat intelligence</p>`;
        return;
    }
    
    container.innerHTML = `
        <p class="font-medium text-red-600 mb-2">${type} matches ${res.matches} threat indicator(s):</p>
        <div class="space-y-2">
            ${res.indicators.map(i => `
                <div class="bg-white p-3 rounded border border-gray-200">
                    <p class="font-medium">${i.type}: ${i.value}</p>
                    <p class="text-sm text-gray-500">Confidence: ${i.confidence}% • Severity: ${i.severity}</p>
                    <p class="text-sm text-gray-500">Source: ${i.source}</p>
                    ${i.description ? `<p class="text-sm text-gray-600 mt-1">${i.description}</p>` : ''}
                </div>
            `).join('')}
        </div>
    `;
}

// Settings Page
async function loadSettings() {
    // Would load system info
    document.getElementById('sysVersion').textContent = '0.1.0';
    document.getElementById('sysPython').textContent = '3.13.5';
    document.getElementById('sysPlatform').textContent = navigator.platform;
}

// Chart Functions
function updateSeverityChart(status) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    
    // This would use real data from incidents
    const data = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
            data: [0, 0, 0, 0], // Would be calculated from incidents
            backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#16a34a'],
            borderWidth: 0
        }]
    };
    
    if (charts.severity) {
        charts.severity.data = data;
        charts.severity.update();
    } else {
        charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true } }
                }
            }
        });
    }
}

function updateTimelineChart(status) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    // Mock data for now
    const data = {
        labels: ['6h', '5h', '4h', '3h', '2h', '1h', 'Now'],
        datasets: [{
            label: 'Incidents',
            data: [0, 0, 0, 0, 0, 0, 0],
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            fill: true,
            tension: 0.4
        }]
    };
    
    if (charts.timeline) {
        charts.timeline.data = data;
        charts.timeline.update();
    } else {
        charts.timeline = new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1 } }
                }
            }
        });
    }
}

// Utility Functions
function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function updateTime() {
    if (currentTime) {
        currentTime.textContent = new Date().toLocaleTimeString();
    }
}

// Make functions globally available
window.apiGet = apiGet;
window.apiPost = apiPost;
window.apiDelete = apiDelete;