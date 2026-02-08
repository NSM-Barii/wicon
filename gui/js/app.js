// NSM WICON - Main Application Script

class WiConApp {
    constructor() {
        this.devices = [];
        this.startTime = Date.now();
        this.updateInterval = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startUptime();
        this.loadDevices();
        this.startAutoRefresh();
        this.addLog('success', 'Application initialized successfully');
    }

    setupEventListeners() {
        // Refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.loadDevices();
            this.addLog('info', 'Manual refresh triggered');
        });

        // Clear log button
        document.getElementById('clear-log-btn').addEventListener('click', () => {
            this.clearLog();
        });
    }

    // Uptime counter
    startUptime() {
        setInterval(() => {
            const elapsed = Date.now() - this.startTime;
            const hours = Math.floor(elapsed / 3600000);
            const minutes = Math.floor((elapsed % 3600000) / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);

            const uptimeStr = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
            document.getElementById('uptime').textContent = uptimeStr;
        }, 1000);
    }

    // Auto-refresh devices every 5 seconds
    startAutoRefresh() {
        this.updateInterval = setInterval(() => {
            this.loadDevices();
        }, 5000);
    }

    // Load devices from API
    async loadDevices() {
        try {
            const response = await fetch('/api/devices');

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Convert dictionary to array
            // data is an object with SSIDs as keys: {ssid: {mac, channel, vendor, rssi, clients}}
            const devicesArray = Object.entries(data).map(([ssid, info]) => ({
                ssid: ssid,
                bssid: info.mac,
                channel: info.channel,
                signal: info.rssi,
                vendor: info.vendor,
                clients: info.clients,
                frequency: info.channel ? (info.channel <= 14 ? '2.4 GHz' : '5 GHz') : 'N/A',
                security: 'WPA2', // Default, can be updated if available
                status: 'ACTIVE'
            }));

            this.devices = devicesArray;

            this.updateConnectionStatus('ONLINE');
            this.updateDeviceCount(devicesArray.length);
            this.updateStats(devicesArray);
            this.renderDevices(devicesArray);

        } catch (error) {
            console.error('Error loading devices:', error);
            this.updateConnectionStatus('OFFLINE');
            this.addLog('error', `Failed to load devices: ${error.message}`);
            this.showEmptyState();
        }
    }

    // Update connection status
    updateConnectionStatus(status) {
        const statusElement = document.getElementById('connection-status');
        statusElement.textContent = status;
        statusElement.style.color = status === 'ONLINE' ? '#00ff41' : '#ff0040';
    }

    // Update device count
    updateDeviceCount(count) {
        document.getElementById('device-count').textContent = count;
    }

    // Update statistics
    updateStats(devices) {
        if (!devices || devices.length === 0) {
            document.getElementById('total-scans').textContent = '0';
            document.getElementById('secured-count').textContent = '0';
            document.getElementById('open-count').textContent = '0';
            document.getElementById('avg-signal').textContent = '0 dBm';
            return;
        }

        // Total scans
        document.getElementById('total-scans').textContent = devices.length;

        // Count secured vs open networks
        let securedCount = 0;
        let openCount = 0;
        let totalSignal = 0;

        devices.forEach(device => {
            // Check security
            const security = device.security || device.encryption || '';
            if (security && security.toLowerCase() !== 'open' && security !== '--') {
                securedCount++;
            } else {
                openCount++;
            }

            // Sum signal strength
            const signal = parseInt(device.signal || device.rssi || 0);
            totalSignal += signal;
        });

        document.getElementById('secured-count').textContent = securedCount;
        document.getElementById('open-count').textContent = openCount;

        // Average signal
        const avgSignal = devices.length > 0 ? Math.round(totalSignal / devices.length) : 0;
        document.getElementById('avg-signal').textContent = `${avgSignal} dBm`;
    }

    // Render devices table
    renderDevices(devices) {
        const tbody = document.getElementById('devices-tbody');

        if (!devices || devices.length === 0) {
            this.showEmptyState();
            return;
        }

        tbody.innerHTML = '';

        devices.forEach((device, index) => {
            const row = document.createElement('tr');

            // Extract device data with fallbacks
            const ssid = device.ssid || device.name || 'Hidden Network';
            const bssid = device.bssid || device.mac || 'N/A';
            const channel = device.channel || 'N/A';
            const signal = device.signal || device.rssi || 'N/A';
            const security = device.security || device.encryption || 'OPEN';
            const frequency = device.frequency || device.freq || 'N/A';

            // Determine signal strength class
            let signalClass = 'signal-weak';
            const signalValue = parseInt(signal);
            if (signalValue > -50) {
                signalClass = 'signal-strong';
            } else if (signalValue > -70) {
                signalClass = 'signal-medium';
            }

            // Determine status
            const status = device.status || 'ACTIVE';
            const statusClass = status === 'ACTIVE' ? 'status-active' : 'status-idle';

            row.innerHTML = `
                <td>${String(index + 1).padStart(3, '0')}</td>
                <td><strong>${this.escapeHtml(ssid)}</strong></td>
                <td><code>${this.escapeHtml(bssid)}</code></td>
                <td>${this.escapeHtml(channel)}</td>
                <td class="${signalClass}">${this.escapeHtml(signal)} dBm</td>
                <td>${this.escapeHtml(security)}</td>
                <td>${this.escapeHtml(frequency)}</td>
                <td><span class="status-badge ${statusClass}">${status}</span></td>
            `;

            // Add fade-in animation
            row.style.animation = `fadeIn 0.5s ease ${index * 0.05}s both`;

            tbody.appendChild(row);
        });

        this.addLog('success', `Loaded ${devices.length} device(s)`);
    }

    // Show empty state
    showEmptyState() {
        const tbody = document.getElementById('devices-tbody');
        tbody.innerHTML = `
            <tr class="loading-row">
                <td colspan="8">
                    <div class="loading">
                        <span class="loading-text">NO DEVICES DETECTED</span>
                    </div>
                </td>
            </tr>
        `;
    }

    // Add log entry
    addLog(type, message) {
        const logContainer = document.getElementById('log-container');
        const logEntry = document.createElement('div');
        logEntry.className = `log-entry ${type}`;

        const now = new Date();
        const timeStr = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;

        logEntry.innerHTML = `
            <span class="log-time">[${timeStr}]</span>
            <span class="log-message">${this.escapeHtml(message)}</span>
        `;

        logContainer.appendChild(logEntry);

        // Auto-scroll to bottom
        logContainer.scrollTop = logContainer.scrollHeight;

        // Limit log entries to 50
        const entries = logContainer.querySelectorAll('.log-entry');
        if (entries.length > 50) {
            entries[0].remove();
        }
    }

    // Clear log
    clearLog() {
        const logContainer = document.getElementById('log-container');
        logContainer.innerHTML = '';
        this.addLog('info', 'Log cleared');
    }

    // Escape HTML to prevent XSS
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }
}

// Add CSS animation for fade in
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.wiconApp = new WiConApp();
});
