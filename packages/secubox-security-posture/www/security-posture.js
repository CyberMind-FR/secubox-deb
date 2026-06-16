/**
 * SecuBox Security Posture - Hub Integration
 * 
 * Lightweight integration for embedding security posture widgets in the hub dashboard.
 * 
 * Usage:
 *   <script src="/security-posture/security-posture.js"></script>
 *   <script>SecuBoxSecurityPosture.init({ apiPath: '/api/v1/security-posture' });</script>
 * 
 * Then use:
 *   SecuBoxSecurityPosture.renderDefconBadge('target-element-id');
 *   SecuBoxSecurityPosture.renderSummaryCard('target-element-id');
 */

// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

'use strict';

const SecuBoxSecurityPosture = (function() {
    // Configuration
    let config = {
        apiPath: '/api/v1/security-posture',
        refreshInterval: 30000,
        debug: false
    };
    
    // State
    const state = {
        data: null,
        timers: new Map(),
        initialized: false
    };
    
    // DEFCON level info
    const DEFCON_LEVELS = {
        defcon_1: { name: 'DEFCON 1', emoji: '🔴', color: '#991b1b', bg: 'rgba(153, 27, 27, 0.15)', desc: 'MAXIMUM • Critical breach', blink: true },
        defcon_2: { name: 'DEFCON 2', emoji: '🔴', color: '#ef4444', bg: 'rgba(239, 68, 68, 0.15)', desc: 'SEVERE • Major incident', blink: false },
        defcon_3: { name: 'DEFCON 3', emoji: '🟠', color: '#f97316', bg: 'rgba(249, 115, 22, 0.15)', desc: 'HEIGHTENED • Active threats', blink: false },
        defcon_4: { name: 'DEFCON 4', emoji: '🟡', color: '#86efac', bg: 'rgba(134, 239, 172, 0.15)', desc: 'INCREASED CHATTER • Minor issues', blink: false },
        defcon_5: { name: 'DEFCON 5', emoji: '🟢', color: '#22c55e', bg: 'rgba(34, 197, 94, 0.15)', desc: 'NORMAL • All systems operational', blink: false }
    };
    
    // Log helper
    function log(...args) {
        if (config.debug) console.log('[SecuBox-SP]', ...args);
    }
    
    // Fetch JSON
    async function fetchJSON(endpoint) {
        try {
            const url = `${config.apiPath}${endpoint}`;
            const response = await fetch(url);
            if (!response.ok) {
                log(`API error: ${response.status} ${url}`);
                return null;
            }
            return await response.json();
        } catch (error) {
            log('Fetch error:', error);
            return null;
        }
    }
    
    // Fetch all data
    async function fetchAllData() {
        const [defcon, cspn, tpn, perf, overview] = await Promise.all([
            fetchJSON('/defcon/summary'),
            fetchJSON('/cspn/summary'),
            fetchJSON('/tpn/summary'),
            fetchJSON('/performance/summary'),
            fetchJSON('/overview')
        ]);
        
        state.data = { defcon, cspn, tpn, perf, overview };
        return state.data;
    }
    
    // Format percentage
    function formatPercent(value, decimals = 1) {
        if (value === null || value === undefined) return '--%';
        return `${value.toFixed(decimals)}%`;
    }
    
    // Get DEFCON info
    function getDefconInfo(level) {
        return DEFCON_LEVELS[level] || DEFCON_LEVELS.defcon_5;
    }
    
    // Create element helper
    function createElement(tag, props = {}, children = []) {
        const el = document.createElement(tag);
        Object.entries(props).forEach(([key, value]) => {
            if (key === 'style') {
                Object.entries(value).forEach(([k, v]) => el.style[k] = v);
            } else if (key === 'dataset') {
                Object.entries(value).forEach(([k, v]) => el.dataset[k] = v);
            } else if (key === 'className') {
                el.className = value;
            } else if (key === 'textContent') {
                el.textContent = value;
            } else if (key === 'innerHTML') {
                el.innerHTML = value;
            } else {
                el[key] = value;
            }
        });
        children.forEach(child => {
            if (typeof child === 'string') {
                el.appendChild(document.createTextNode(child));
            } else if (child instanceof Node) {
                el.appendChild(child);
            }
        });
        return el;
    }
    
    // Render DEFCON Badge
    function renderDefconBadge(targetId, options = {}) {
        const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
        if (!target) {
            log(`Target element not found: ${targetId}`);
            return;
        }
        
        const badge = createElement('defcon-badge', {
            apiPath: config.apiPath,
            refresh: Math.round(config.refreshInterval / 1000)
        });
        
        if (options.compact) badge.setAttribute('compact', '');
        if (options.tooltip) badge.setAttribute('tooltip', options.tooltip);
        
        target.appendChild(badge);
        return badge;
    }
    
    // Render DEFCON Card
    function renderDefconCard(targetId, options = {}) {
        const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
        if (!target) {
            log(`Target element not found: ${targetId}`);
            return;
        }
        
        const card = createElement('defcon-card', {
            apiPath: config.apiPath,
            refresh: Math.round(config.refreshInterval / 1000)
        });
        
        target.appendChild(card);
        return card;
    }
    
    // Render Mini DEFCON Display
    function renderMiniDefcon(targetId) {
        const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
        if (!target) {
            log(`Target element not found: ${targetId}`);
            return;
        }
        
        const container = createElement('div', {
            className: 'secubox-sp-mini-defcon',
            style: {
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.25rem 0.75rem',
                borderRadius: '0.375rem',
                fontFamily: 'system-ui, sans-serif',
                fontSize: '0.875rem',
                fontWeight: '500'
            }
        });
        
        const emoji = createElement('span', { className: 'secubox-sp-emoji', textContent: '⏳' });
        const level = createElement('span', { className: 'secubox-sp-level', textContent: 'Loading...' });
        const score = createElement('span', { className: 'secubox-sp-score', textContent: '', style: { opacity: 0.7 } });
        
        container.appendChild(emoji);
        container.appendChild(level);
        container.appendChild(score);
        target.appendChild(container);
        
        // Update function
        const update = async () => {
            const data = await fetchJSON('/defcon/summary');
            if (data) {
                const info = getDefconInfo(data.level || 'defcon_5');
                emoji.textContent = data.emoji || info.emoji;
                level.textContent = info.name;
                score.textContent = formatPercent(data.score);
                container.style.background = data.color || info.bg;
                container.style.color = info.color;
                if (info.blink) emoji.style.animation = 'blink 1s infinite';
            }
        };
        
        // Initial update and periodic refresh
        update();
        const interval = setInterval(update, config.refreshInterval);
        state.timers.set(container, interval);
        
        return container;
    }
    
    // Render Summary Card
    function renderSummaryCard(targetId, options = {}) {
        const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
        if (!target) {
            log(`Target element not found: ${targetId}`);
            return;
        }
        
        const container = createElement('div', {
            className: 'secubox-sp-summary-card',
            style: {
                background: '#1a1a1a',
                border: '1px solid #27272a',
                borderRadius: '0.75rem',
                padding: '1rem',
                fontFamily: 'system-ui, sans-serif'
            }
        });
        
        const title = createElement('h3', {
            className: 'secubox-sp-title',
            textContent: options.title || 'Security Posture',
            style: {
                fontSize: '0.875rem',
                color: '#71717a',
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                margin: '0 0 0.75rem'
            }
        });
        
        const defcon = createElement('div', {
            className: 'secubox-sp-defcon',
            style: {
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                marginBottom: '0.75rem'
            }
        });
        const defconEmoji = createElement('span', { className: 'secubox-sp-defcon-emoji', textContent: '⏳', style: { fontSize: '1.25rem' } });
        const defconLevel = createElement('span', { className: 'secubox-sp-defcon-level', textContent: 'Loading...' });
        
        defcon.appendChild(defconEmoji);
        defcon.appendChild(defconLevel);
        
        const combinedScore = createElement('div', {
            className: 'secubox-sp-combined',
            style: {
                fontSize: '1.5rem',
                fontWeight: '700',
                fontFamily: 'monospace',
                marginBottom: '0.5rem'
            }
        });
        
        const statusBar = createElement('div', {
            className: 'secubox-sp-bar',
            style: {
                height: '6px',
                background: '#27272a',
                borderRadius: '3px',
                overflow: 'hidden',
                marginBottom: '0.75rem'
            }
        });
        const barFill = createElement('div', {
            className: 'secubox-sp-bar-fill',
            style: {
                height: '100%',
                borderRadius: '3px',
                width: '0%',
                transition: 'width 0.5s ease'
            }
        });
        statusBar.appendChild(barFill);
        
        const compliance = createElement('div', {
            className: 'secubox-sp-compliance',
            style: {
                display: 'grid',
                gridTemplateColumns: 'repeat(3, 1fr)',
                gap: '0.75rem'
            }
        });
        
        const cspnItem = createElement('div', {
            className: 'secubox-sp-compliance-item',
            style: { textAlign: 'center', fontSize: '0.75rem' }
        });
        const cspnLabel = createElement('div', { textContent: 'CSPN', style: { color: '#71717a', marginBottom: '0.25rem' } });
        const cspnValue = createElement('div', { textContent: '--%', style: { fontWeight: '600' } });
        cspnItem.appendChild(cspnLabel);
        cspnItem.appendChild(cspnValue);
        
        const tpnItem = createElement('div', {
            className: 'secubox-sp-compliance-item',
            style: { textAlign: 'center', fontSize: '0.75rem' }
        });
        const tpnLabel = createElement('div', { textContent: 'TPN', style: { color: '#71717a', marginBottom: '0.25rem' } });
        const tpnValue = createElement('div', { textContent: '--%', style: { fontWeight: '600' } });
        tpnItem.appendChild(tpnLabel);
        tpnItem.appendChild(tpnValue);
        
        const perfItem = createElement('div', {
            className: 'secubox-sp-compliance-item',
            style: { textAlign: 'center', fontSize: '0.75rem' }
        });
        const perfLabel = createElement('div', { textContent: 'Perf', style: { color: '#71717a', marginBottom: '0.25rem' } });
        const perfValue = createElement('div', { textContent: '--%', style: { fontWeight: '600' } });
        perfItem.appendChild(perfLabel);
        perfItem.appendChild(perfValue);
        
        compliance.appendChild(cspnItem);
        compliance.appendChild(tpnItem);
        compliance.appendChild(perfItem);
        
        container.appendChild(title);
        container.appendChild(defcon);
        container.appendChild(combinedScore);
        container.appendChild(statusBar);
        container.appendChild(compliance);
        target.appendChild(container);
        
        // Update function
        const update = async () => {
            const [defconData, overview] = await Promise.all([
                fetchJSON('/defcon/summary'),
                fetchJSON('/overview')
            ]);
            
            if (defconData) {
                const info = getDefconInfo(defconData.level || 'defcon_5');
                defconEmoji.textContent = defconData.emoji || info.emoji;
                defconLevel.textContent = info.name;
                if (info.blink) defconEmoji.style.animation = 'blink 1s infinite';
            }
            
            if (overview) {
                combinedScore.textContent = `${formatPercent(overview.combined_score)}`;
                barFill.style.width = `${overview.combined_score || 0}%`;
                barFill.style.background = overview.overall_color || '#6b7280';
                
                if (overview.cspn) {
                    cspnValue.textContent = formatPercent(overview.cspn.score);
                    cspnItem.style.color = overview.cspn.compliant ? '#22c55e' : '#ef4444';
                }
                if (overview.tpn_media) {
                    tpnValue.textContent = formatPercent(overview.tpn_media.score);
                    tpnItem.style.color = overview.tpn_media.compliant ? '#3b82f6' : '#ef4444';
                }
                if (overview.performance) {
                    perfValue.textContent = formatPercent(overview.performance.score);
                    perfItem.style.color = overview.performance.score >= 80 ? '#22c55e' : overview.performance.score >= 60 ? '#eab308' : '#ef4444';
                }
            }
        };
        
        // Initial update and periodic refresh
        update();
        const interval = setInterval(update, config.refreshInterval);
        state.timers.set(container, interval);
        
        return container;
    }
    
    // Render Compliance Badge
    function renderComplianceBadge(targetId, type = 'cspn') {
        const target = typeof targetId === 'string' ? document.getElementById(targetId) : targetId;
        if (!target) {
            log(`Target element not found: ${targetId}`);
            return;
        }
        
        const container = createElement('span', {
            className: `secubox-sp-compliance-badge secubox-sp-${type}`,
            style: {
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.375rem',
                padding: '0.25rem 0.625rem',
                borderRadius: '0.375rem',
                fontSize: '0.75rem',
                fontWeight: '600',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
            }
        });
        
        const icon = createElement('span', { className: 'secubox-sp-icon', textContent: '⏳' });
        const label = createElement('span', { className: 'secubox-sp-label', textContent: type.toUpperCase() });
        const score = createElement('span', { className: 'secubox-sp-score', textContent: '' });
        
        container.appendChild(icon);
        container.appendChild(label);
        container.appendChild(score);
        target.appendChild(container);
        
        const threshold = type === 'cspn' ? 70 : type === 'tpn' ? 85 : 80;
        
        const update = async () => {
            const endpoint = type === 'cspn' ? '/cspn/summary' : type === 'tpn' ? '/tpn/summary' : '/performance/summary';
            const data = await fetchJSON(endpoint);
            if (data?.summary) {
                const s = data.summary;
                const isCompliant = s.is_compliant || s.score >= threshold;
                const color = isCompliant ? (type === 'cspn' ? '#22c55e' : type === 'tpn' ? '#3b82f6' : '#22c55e') : '#ef4444';
                const bg = isCompliant ? `rgba(${color === '#22c55e' ? '34,197,94' : color === '#3b82f6' ? '59,130,246' : '34,197,94'}, 0.15)` : 'rgba(239,68,68,0.15)';
                
                icon.textContent = isCompliant ? '✓' : '✗';
                score.textContent = ` ${formatPercent(s.compliance_score || s.score)}`;
                container.style.background = bg;
                container.style.color = color;
                container.style.border = `1px solid ${color}`;
            }
        };
        
        update();
        const interval = setInterval(update, config.refreshInterval);
        state.timers.set(container, interval);
        
        return container;
    }
    
    // Destroy/cleanup
    function destroy() {
        state.timers.forEach((timer, element) => {
            clearInterval(timer);
        });
        state.timers.clear();
        state.data = null;
        state.initialized = false;
    }
    
    // Initialize
    function init(userConfig = {}) {
        if (state.initialized) return;
        
        // Merge config
        config = { ...config, ...userConfig };
        
        // Ensure defcon-badge.js is loaded
        if (!customElements.get('defcon-badge')) {
            const script = document.createElement('script');
            script.src = config.apiPath.replace('/api/v1/security-posture', '') + '/security-posture/defcon-badge.js';
            document.head.appendChild(script);
        }
        if (!customElements.get('defcon-card')) {
            const script = document.createElement('script');
            script.src = config.apiPath.replace('/api/v1/security-posture', '') + '/security-posture/defcon-badge.js';
            document.head.appendChild(script);
        }
        
        state.initialized = true;
        log('SecuBox Security Posture integration initialized');
        
        return {
            config,
            renderDefconBadge,
            renderDefconCard,
            renderMiniDefcon,
            renderSummaryCard,
            renderComplianceBadge,
            destroy,
            refresh: fetchAllData
        };
    }
    
    // Return public API
    return {
        init,
        config,
        renderDefconBadge,
        renderDefconCard,
        renderMiniDefcon,
        renderSummaryCard,
        renderComplianceBadge,
        destroy,
        refresh: fetchAllData
    };
})();

// Auto-initialize if needed
if (typeof window !== 'undefined' && window.SecuBoxSecurityPosture) {
    // Already loaded
} else {
    window.SecuBoxSecurityPosture = SecuBoxSecurityPosture;
}
