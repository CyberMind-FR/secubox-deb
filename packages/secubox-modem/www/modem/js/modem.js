// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SecuBox-Deb :: Modem Dashboard JavaScript
 * CyberMind — https://cybermind.fr
 */

const API = '/api/v1/modem';
let signalChart = null;
let signalHistory = [];
let terminal = null;
let ws = null;
let currentSMSId = null;
let isConnected = false;

// === API Helpers ===

async function api(endpoint, method = 'GET', data = null) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (data) opts.body = JSON.stringify(data);
    try {
        const res = await fetch(API + endpoint, opts);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        return res.json();
    } catch (e) {
        console.error('API error:', e);
        throw e;
    }
}

// === Tab Switching ===

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab).classList.add('active');

        // Initialize tab-specific content
        if (tab.dataset.tab === 'terminal') {
            initTerminal();
        } else if (tab.dataset.tab === 'signal') {
            loadSignalHistory();
        } else if (tab.dataset.tab === 'sms') {
            loadSMS();
        }
    });
});

// === Status Loading ===

async function loadStatus() {
    try {
        const data = await api('/status');

        isConnected = data.connected;

        // Update badge
        const badge = document.getElementById('status-badge');
        if (data.connected) {
            badge.className = 'badge connected';
            badge.textContent = data.state;
        } else if (data.state === 'searching' || data.state === 'registering') {
            badge.className = 'badge searching';
            badge.textContent = data.state;
        } else {
            badge.className = 'badge disconnected';
            badge.textContent = data.state || 'No modem';
        }

        // Update stats
        document.getElementById('stat-operator').textContent = data.operator_name || '-';
        document.getElementById('stat-tech').textContent = data.access_technology || '-';
        document.getElementById('stat-signal').textContent = data.signal_quality ? data.signal_quality + '%' : '-';
        document.getElementById('stat-ip').textContent = data.ip_address || '-';

        // Update connect button
        const btn = document.getElementById('connect-btn');
        if (data.connected) {
            btn.textContent = 'Disconnect';
            btn.className = 'btn danger';
        } else {
            btn.textContent = 'Connect';
            btn.className = 'btn primary';
        }

        // Update info
        document.getElementById('info-model').textContent = data.model || '-';
        document.getElementById('info-state').textContent = data.state || '-';
        document.getElementById('info-imei').textContent = data.imei || '-';

    } catch (e) {
        console.error('Failed to load status:', e);
    }
}

async function loadInfo() {
    try {
        const data = await api('/info');
        document.getElementById('info-mfr').textContent = data.manufacturer || '-';
        document.getElementById('info-model').textContent = data.model || '-';
        document.getElementById('info-fw').textContent = data.firmware || '-';
        document.getElementById('info-imei').textContent = data.imei || '-';
    } catch (e) {
        console.error('Failed to load info:', e);
    }
}

async function loadSignal() {
    try {
        const data = await api('/signal');

        const quality = data.quality_percent;
        document.getElementById('signal-percent').textContent = quality !== null ? quality + '%' : '-';

        // Update signal bars
        const bars = document.querySelectorAll('#signal-bars .bar');
        const level = quality !== null ? Math.ceil(quality / 20) : 0;
        bars.forEach((bar, i) => {
            bar.classList.remove('active', 'fair', 'poor');
            if (i < level) {
                if (quality >= 60) bar.classList.add('active');
                else if (quality >= 30) bar.classList.add('fair');
                else bar.classList.add('poor');
            }
        });

        document.getElementById('sig-rssi').textContent = data.rssi !== null ? data.rssi + ' dBm' : '- dBm';
        document.getElementById('sig-rsrp').textContent = data.rsrp !== null ? data.rsrp + ' dBm' : '- dBm';
        document.getElementById('sig-rsrq').textContent = data.rsrq !== null ? data.rsrq + ' dB' : '- dB';
        document.getElementById('sig-sinr').textContent = data.sinr !== null ? data.sinr + ' dB' : '- dB';

    } catch (e) {
        console.error('Failed to load signal:', e);
    }
}

// === Signal Chart ===

async function loadSignalHistory() {
    try {
        const data = await api('/signal/history?minutes=60&limit=120');
        signalHistory = data.records || [];

        // Update stats
        const stats = data.stats || {};
        document.getElementById('stats-count').textContent = stats.count || '-';
        document.getElementById('stats-rsrp-avg').textContent = stats.rsrp_avg ? stats.rsrp_avg.toFixed(1) + ' dBm' : '-';
        document.getElementById('stats-rsrp-range').textContent = stats.rsrp_min && stats.rsrp_max
            ? stats.rsrp_min.toFixed(0) + ' / ' + stats.rsrp_max.toFixed(0) + ' dBm' : '-';
        document.getElementById('stats-sinr-avg').textContent = stats.sinr_avg ? stats.sinr_avg.toFixed(1) + ' dB' : '-';

        updateSignalChart();

    } catch (e) {
        console.error('Failed to load signal history:', e);
    }
}

function updateSignalChart() {
    const metric = document.getElementById('signal-metric').value;
    const ctx = document.getElementById('signal-chart');

    const labels = signalHistory.map(r => {
        const d = new Date(r.timestamp);
        return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
    });

    const values = signalHistory.map(r => r[metric]);

    const metricLabels = {
        rsrp: 'RSRP (dBm)',
        rssi: 'RSSI (dBm)',
        sinr: 'SINR (dB)',
        quality_percent: 'Quality (%)'
    };

    if (signalChart) {
        signalChart.destroy();
    }

    signalChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: metricLabels[metric],
                data: values,
                borderColor: '#2196f3',
                backgroundColor: 'rgba(33, 150, 243, 0.1)',
                fill: true,
                tension: 0.3,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: metric === 'quality_percent',
                    max: metric === 'quality_percent' ? 100 : undefined,
                }
            }
        }
    });
}

// === SMS ===

async function loadSMS() {
    try {
        const data = await api('/sms');
        const list = document.getElementById('sms-list');

        if (!data.messages || data.messages.length === 0) {
            list.innerHTML = '<p style="color: var(--p31-dim); text-align: center; padding: 2rem;">No messages</p>';
            return;
        }

        list.innerHTML = data.messages.map(m => `
            <div class="sms-item" onclick="showSMSDetail('${m.id}', '${m.number}', '${m.timestamp}', \`${m.text.replace(/`/g, '\\`')}\`)">
                <div class="from">${m.number}</div>
                <div class="preview">${m.text.substring(0, 50)}${m.text.length > 50 ? '...' : ''}</div>
                <div class="time">${new Date(m.timestamp).toLocaleString()}</div>
            </div>
        `).join('');

    } catch (e) {
        console.error('Failed to load SMS:', e);
    }
}

function showSMSDetail(id, number, timestamp, text) {
    currentSMSId = id;
    document.getElementById('sms-detail-from').textContent = number;
    document.getElementById('sms-detail-time').textContent = new Date(timestamp).toLocaleString();
    document.getElementById('sms-detail-text').textContent = text;
    document.getElementById('sms-detail-modal').classList.add('show');
}

function closeSMSDetailModal() {
    document.getElementById('sms-detail-modal').classList.remove('show');
    currentSMSId = null;
}

function showComposeModal() {
    document.getElementById('compose-modal').classList.add('show');
}

function closeComposeModal() {
    document.getElementById('compose-modal').classList.remove('show');
    document.getElementById('sms-to').value = '';
    document.getElementById('sms-text').value = '';
    updateCharCount();
}

function updateCharCount() {
    const text = document.getElementById('sms-text').value;
    document.getElementById('sms-chars').textContent = text.length + '/160';
}

async function sendSMS() {
    const number = document.getElementById('sms-to').value.trim();
    const text = document.getElementById('sms-text').value.trim();

    if (!number || !text) {
        alert('Please enter number and message');
        return;
    }

    try {
        const result = await api('/sms/send', 'POST', { number, text });
        if (result.success) {
            alert('Message sent!');
            closeComposeModal();
            loadSMS();
        } else {
            alert('Failed to send: ' + (result.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function replyToSMS() {
    const number = document.getElementById('sms-detail-from').textContent;
    closeSMSDetailModal();
    document.getElementById('sms-to').value = number;
    showComposeModal();
}

async function deleteSMSDetail() {
    if (!currentSMSId || !confirm('Delete this message?')) return;

    try {
        await api('/sms/' + currentSMSId, 'DELETE');
        closeSMSDetailModal();
        loadSMS();
    } catch (e) {
        alert('Failed to delete: ' + e.message);
    }
}

// === Terminal ===

function initTerminal() {
    if (terminal) return;

    const container = document.getElementById('terminal');
    terminal = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'Courier Prime, monospace',
        theme: {
            background: '#1e1e1e',
            foreground: '#00dd44',
            cursor: '#00dd44',
        }
    });
    terminal.open(container);
    terminal.writeln('SecuBox AT Command Console');
    terminal.writeln('Type AT commands and press Enter');
    terminal.writeln('');

    connectWebSocket();
}

function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(protocol + '//' + location.host + API + '/at/console');

    ws.onopen = () => {
        terminal.writeln('\x1b[32m[Connected]\x1b[0m');
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'rx') {
                terminal.writeln('\x1b[33m' + data.data + '\x1b[0m');
            } else if (data.type === 'tx') {
                terminal.writeln('\x1b[36m> ' + data.data + '\x1b[0m');
            } else if (data.type === 'error') {
                terminal.writeln('\x1b[31mERROR: ' + data.message + '\x1b[0m');
            } else if (data.type === 'status') {
                terminal.writeln('\x1b[32m[Port: ' + data.port + ']\x1b[0m');
            }
        } catch (e) {
            terminal.writeln(event.data);
        }
    };

    ws.onclose = () => {
        terminal.writeln('\x1b[31m[Disconnected]\x1b[0m');
    };

    ws.onerror = (e) => {
        terminal.writeln('\x1b[31m[WebSocket Error]\x1b[0m');
        console.error('WebSocket error:', e);
    };
}

function terminalReconnect() {
    if (ws) ws.close();
    setTimeout(connectWebSocket, 500);
}

function terminalClear() {
    if (terminal) terminal.clear();
}

function sendATCommand() {
    const input = document.getElementById('at-input');
    const command = input.value.trim();
    if (!command) return;

    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'command', command: command }));
    } else {
        // Fallback to REST API
        api('/at/command', 'POST', { command: command })
            .then(result => {
                if (terminal) {
                    terminal.writeln('\x1b[36m> ' + command + '\x1b[0m');
                    (result.response || []).forEach(line => {
                        terminal.writeln('\x1b[33m' + line + '\x1b[0m');
                    });
                }
            })
            .catch(e => {
                if (terminal) terminal.writeln('\x1b[31mError: ' + e.message + '\x1b[0m');
            });
    }

    input.value = '';
}

// === Settings ===

async function loadConfig() {
    try {
        const data = await api('/config');
        document.getElementById('cfg-apn').value = data.apn || '';
        document.getElementById('cfg-user').value = data.user || '';
        document.getElementById('cfg-iptype').value = data.ip_type || 'ipv4';
        document.getElementById('cfg-auto').checked = data.auto_connect || false;
    } catch (e) {
        console.error('Failed to load config:', e);
    }
}

async function saveConfig() {
    const config = {
        apn: document.getElementById('cfg-apn').value,
        user: document.getElementById('cfg-user').value,
        password: document.getElementById('cfg-pass').value,
        ip_type: document.getElementById('cfg-iptype').value,
        auto_connect: document.getElementById('cfg-auto').checked,
    };

    try {
        await api('/config', 'POST', config);
        alert('Configuration saved');
    } catch (e) {
        alert('Failed to save: ' + e.message);
    }
}

async function loadAPNDatabase() {
    try {
        const data = await api('/apn/database');
        const list = document.getElementById('apn-list');

        let html = '';
        for (const [country, apns] of Object.entries(data.apns)) {
            html += `<h4 style="margin: 0.5rem 0; color: var(--p31-decay);">${country.toUpperCase()}</h4>`;
            apns.forEach(apn => {
                html += `<div style="padding: 0.5rem; cursor: pointer; border-bottom: 1px solid var(--p31-ghost);"
                    onclick="selectAPN('${apn.apn}', '${apn.user || ''}')">
                    <strong>${apn.operator}</strong><br>
                    <span style="color: var(--p31-dim); font-size: 0.85rem;">${apn.apn}</span>
                </div>`;
            });
        }
        list.innerHTML = html;
    } catch (e) {
        console.error('Failed to load APN database:', e);
    }
}

function selectAPN(apn, user) {
    document.getElementById('cfg-apn').value = apn;
    document.getElementById('cfg-user').value = user;
}

// === Connection Control ===

async function toggleConnection() {
    if (isConnected) {
        try {
            await api('/disconnect', 'POST');
            loadStatus();
        } catch (e) {
            alert('Failed to disconnect: ' + e.message);
        }
    } else {
        const apn = document.getElementById('cfg-apn').value.trim();
        if (!apn) {
            alert('Please configure APN in Settings tab first');
            return;
        }

        try {
            await api('/connect', 'POST', {
                apn: apn,
                user: document.getElementById('cfg-user').value,
                password: document.getElementById('cfg-pass').value,
                ip_type: document.getElementById('cfg-iptype').value,
            });
            loadStatus();
        } catch (e) {
            alert('Failed to connect: ' + e.message);
        }
    }
}

// === Modem Control ===

async function resetModem() {
    if (!confirm('Reset modem? Connection will be lost temporarily.')) return;
    try {
        await api('/reset', 'POST');
        alert('Modem reset initiated');
        setTimeout(refreshAll, 5000);
    } catch (e) {
        alert('Failed: ' + e.message);
    }
}

async function powerOff() {
    if (!confirm('Power off modem?')) return;
    try {
        await api('/power/off', 'POST');
        alert('Modem powered off');
        loadStatus();
    } catch (e) {
        alert('Failed: ' + e.message);
    }
}

async function powerOn() {
    try {
        await api('/power/on', 'POST');
        alert('Modem powering on');
        setTimeout(loadStatus, 3000);
    } catch (e) {
        alert('Failed: ' + e.message);
    }
}

// === Refresh All ===

function refreshAll() {
    loadStatus();
    loadInfo();
    loadSignal();
}

// === Initialize ===

refreshAll();
loadConfig();
loadAPNDatabase();

// Auto-refresh every 30 seconds
setInterval(() => {
    loadStatus();
    loadSignal();
}, 30000);
