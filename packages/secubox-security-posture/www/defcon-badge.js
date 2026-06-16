/**
 * SecuBox Security Posture - DEFCON Badge Component
 * 
 * A reusable JavaScript component that displays the current DEFCON level
 * and security score. Can be embedded in any SecuBox dashboard.
 * 
 * Usage:
 *   <script src="/security-posture/defcon-badge.js"></script>
 *   <div id="defcon-badge"></div>
 *   <script>initDefconBadge();</script>
 * 
 * Or with custom element:
 *   <defcon-badge socket="/run/secubox/security-posture.sock"></defcon-badge>
 */

// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

'use strict';

/**
 * DEFCON Badge - Web Component
 * 
 * Displays current DEFCON level with color-coded badge and security score.
 */
class DefconBadge extends HTMLElement {
    constructor() {
        super();
        this.socketPath = this.getAttribute('socket') || '/run/secubox/security-posture.sock';
        this.apiPath = this.getAttribute('api-path') || '/api/v1/security-posture';
        this.refreshInterval = parseInt(this.getAttribute('refresh') || '30');
        this.data = null;
        this.timestamp = null;
    }

    connectedCallback() {
        this.render();
        this.fetchData();
        this.startRefresh();
    }

    disconnectedCallback() {
        this.stopRefresh();
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === 'socket' || name === 'api-path' || name === 'refresh') {
            this.socketPath = this.getAttribute('socket') || '/run/secubox/security-posture.sock';
            this.apiPath = this.getAttribute('api-path') || '/api/v1/security-posture';
            this.refreshInterval = parseInt(this.getAttribute('refresh') || '30');
            this.fetchData();
        }
    }

    static get observedAttributes() {
        return ['socket', 'api-path', 'refresh'];
    }

    render() {
        this.innerHTML = `
            <style>
                .defcon-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 0.75rem;
                    padding: 0.5rem 1rem;
                    border-radius: 0.5rem;
                    font-family: system-ui, -apple-system, sans-serif;
                    font-size: 0.875rem;
                    font-weight: 500;
                    background: rgba(0, 0, 0, 0.05);
                    transition: all 0.2s ease;
                }
                
                .defcon-badge .emoji {
                    font-size: 1.25rem;
                }
                
                .defcon-badge .level {
                    font-weight: 700;
                    font-family: monospace;
                }
                
                .defcon-badge .score {
                    opacity: 0.8;
                }
                
                .defcon-badge .blink {
                    animation: blink 1s infinite;
                }
                
                @keyframes blink {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.5; }
                }
                
                .defcon-badge .status-bar {
                    height: 4px;
                    width: 60px;
                    border-radius: 2px;
                    background: rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                    margin-left: 0.5rem;
                }
                
                .defcon-badge .status-bar .fill {
                    height: 100%;
                    border-radius: 2px;
                    transition: width 0.3s ease, background-color 0.3s ease;
                }
                
                .defcon-badge.compact {
                    padding: 0.25rem 0.75rem;
                }
                
                .defcon-badge.compact .score {
                    display: none;
                }
                
                .defcon-badge.tooltip {
                    position: relative;
                }
                
                .defcon-badge.tooltip::after {
                    content: attr(data-tooltip);
                    position: absolute;
                    bottom: 100%;
                    left: 50%;
                    transform: translateX(-50%);
                    padding: 0.5rem 0.75rem;
                    border-radius: 0.375rem;
                    background: rgba(0, 0, 0, 0.9);
                    color: white;
                    font-size: 0.75rem;
                    white-space: nowrap;
                    opacity: 0;
                    visibility: hidden;
                    transition: opacity 0.2s, visibility 0.2s;
                    z-index: 100;
                    pointer-events: none;
                }
                
                .defcon-badge.tooltip:hover::after {
                    opacity: 1;
                    visibility: visible;
                }
            </style>
            
            <div class="defcon-badge" data-loading="true">
                <span class="emoji">⏳</span>
                <span class="level">Loading...</span>
                <span class="score"></span>
                <div class="status-bar">
                    <div class="fill" style="width: 0%;"></div>
                </div>
            </div>
        `;
    }

    async fetchData() {
        try {
            const response = await fetch(`${this.apiPath}/defcon/summary`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            this.data = await response.json();
            this.timestamp = new Date().toISOString();
            this.updateDisplay();
        } catch (error) {
            console.error('Failed to fetch DEFCON data:', error);
            this.showError(error.message);
        }
    }

    updateDisplay() {
        if (!this.data) {
            return;
        }

        const badge = this.querySelector('.defcon-badge');
        const emoji = badge.querySelector('.emoji');
        const level = badge.querySelector('.level');
        const score = badge.querySelector('.score');
        const fill = badge.querySelector('.fill');

        // Remove loading state
        badge.removeAttribute('data-loading');

        // Update content
        emoji.textContent = this.data.emoji || '⚪';
        level.textContent = this.formatLevel(this.data.defcon);
        score.textContent = `${this.data.score.toFixed(1)}/100`;

        // Update colors
        const color = this.data.color || '#6b7280';
        badge.style.background = color;
        badge.style.color = this.getContrastColor(color);
        fill.style.background = color;
        fill.style.width = `${this.data.score}%`;

        // Add blink class if needed
        if (this.data.blink) {
            badge.classList.add('blink');
        } else {
            badge.classList.remove('blink');
        }

        // Add tooltip
        if (this.data.description) {
            badge.classList.add('tooltip');
            badge.setAttribute('data-tooltip', this.data.description);
        }
    }

    formatLevel(level) {
        if (!level) return 'N/A';
        return level.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    getContrastColor(hexColor) {
        // Convert hex to RGB
        const r = parseInt(hexColor.substr(1, 2), 16);
        const g = parseInt(hexColor.substr(3, 2), 16);
        const b = parseInt(hexColor.substr(5, 2), 16);
        
        // Calculate luminance
        const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
        
        // Return black or white based on luminance
        return luminance > 0.5 ? '#000' : '#fff';
    }

    showError(error) {
        const badge = this.querySelector('.defcon-badge');
        const emoji = badge.querySelector('.emoji');
        const level = badge.querySelector('.level');
        const score = badge.querySelector('.score');

        badge.removeAttribute('data-loading');
        emoji.textContent = '❌';
        level.textContent = 'Error';
        score.textContent = error || 'Failed to load';
        badge.style.background = '#ef4444';
        badge.style.color = '#fff';
    }

    startRefresh() {
        if (this.refreshInterval > 0) {
            this.refreshTimer = setInterval(() => {
                this.fetchData();
            }, this.refreshInterval * 1000);
        }
    }

    stopRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
}

/**
 * DEFCON Card - Larger display with more details
 */
class DefconCard extends HTMLElement {
    constructor() {
        super();
        this.socketPath = this.getAttribute('socket') || '/run/secubox/security-posture.sock';
        this.apiPath = this.getAttribute('api-path') || '/api/v1/security-posture';
        this.refreshInterval = parseInt(this.getAttribute('refresh') || '60');
        this.data = null;
    }

    connectedCallback() {
        this.render();
        this.fetchData();
        this.startRefresh();
    }

    disconnectedCallback() {
        this.stopRefresh();
    }

    render() {
        this.innerHTML = `
            <style>
                .defcon-card {
                    background: var(--surface, #fff);
                    border: 1px solid var(--border, #e5e7eb);
                    border-radius: 0.75rem;
                    padding: 1rem;
                    font-family: system-ui, -apple-system, sans-serif;
                    max-width: 400px;
                }
                
                .defcon-card .header {
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                    margin-bottom: 1rem;
                }
                
                .defcon-card .badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 0.5rem;
                    padding: 0.25rem 0.75rem;
                    border-radius: 0.375rem;
                    font-weight: 600;
                    font-size: 0.875rem;
                }
                
                .defcon-card .title {
                    font-size: 0.875rem;
                    color: var(--muted, #6b7280);
                    margin-top: 0.25rem;
                }
                
                .defcon-card .score-display {
                    display: flex;
                    align-items: baseline;
                    gap: 0.5rem;
                    margin-bottom: 1rem;
                }
                
                .defcon-card .score-value {
                    font-size: 2.5rem;
                    font-weight: 700;
                    line-height: 1;
                }
                
                .defcon-card .score-max {
                    font-size: 1rem;
                    opacity: 0.7;
                }
                
                .defcon-card .status-bar {
                    height: 8px;
                    width: 100%;
                    border-radius: 4px;
                    background: var(--border, #e5e7eb);
                    overflow: hidden;
                    margin-bottom: 1rem;
                }
                
                .defcon-card .status-bar .fill {
                    height: 100%;
                    border-radius: 4px;
                    transition: width 0.5s ease;
                }
                
                .defcon-card .details {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 0.75rem;
                }
                
                .defcon-card .detail-item {
                    display: flex;
                    flex-direction: column;
                    gap: 0.125rem;
                }
                
                .defcon-card .detail-label {
                    font-size: 0.75rem;
                    color: var(--muted, #6b7280);
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                }
                
                .defcon-card .detail-value {
                    font-size: 0.875rem;
                    font-weight: 500;
                }
                
                .defcon-card .compliance {
                    display: flex;
                    gap: 1rem;
                    margin-top: 1rem;
                    padding-top: 1rem;
                    border-top: 1px solid var(--border, #e5e7eb);
                }
                
                .defcon-card .compliance-item {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    font-size: 0.875rem;
                }
                
                .defcon-card .compliance-item .icon {
                    width: 1rem;
                    height: 1rem;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 0.75rem;
                }
                
                .defcon-card .timestamp {
                    font-size: 0.75rem;
                    color: var(--muted, #6b7280);
                    text-align: right;
                    margin-top: 0.5rem;
                }
            </style>
            
            <div class="defcon-card">
                <div class="header">
                    <div class="badge" data-loading="true">
                        <span>⏳</span>
                        <span>Loading...</span>
                    </div>
                    <div class="title">Security Posture</div>
                </div>
                
                <div class="score-display">
                    <span class="score-value">--</span>
                    <span class="score-max">/100</span>
                </div>
                
                <div class="status-bar">
                    <div class="fill" style="width: 0%;"></div>
                </div>
                
                <div class="details" data-loading="true">
                    <div class="detail-item">
                        <span class="detail-label">Level</span>
                        <span class="detail-value">--</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Network</span>
                        <span class="detail-value">--%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Threat</span>
                        <span class="detail-value">--%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Access</span>
                        <span class="detail-value">--%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Data</span>
                        <span class="detail-value">--%</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Resilience</span>
                        <span class="detail-value">--%</span>
                    </div>
                </div>
                
                <div class="compliance">
                    <div class="compliance-item" data-cspn="loading">
                        <span class="icon">⏳</span>
                        <span>CSPN</span>
                    </div>
                    <div class="compliance-item" data-tpn="loading">
                        <span class="icon">⏳</span>
                        <span>TPN</span>
                    </div>
                    <div class="compliance-item" data-perf="loading">
                        <span class="icon">⏳</span>
                        <span>Performance</span>
                    </div>
                </div>
                
                <div class="timestamp">--</div>
            </div>
        `;
    }

    async fetchData() {
        try {
            const response = await fetch(`${this.apiPath}/overview`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            this.data = await response.json();
            this.timestamp = new Date().toISOString();
            this.updateDisplay();
        } catch (error) {
            console.error('Failed to fetch overview data:', error);
            this.showError(error.message);
        }
    }

    updateDisplay() {
        if (!this.data) {
            return;
        }

        const card = this.querySelector('.defcon-card');
        const badge = card.querySelector('.badge');
        const scoreValue = card.querySelector('.score-value');
        const scoreMax = card.querySelector('.score-max');
        const fill = card.querySelector('.status-bar .fill');
        const details = card.querySelector('.details');
        const cspnItem = card.querySelector('[data-cspn]');
        const tpnItem = card.querySelector('[data-tpn]');
        const perfItem = card.querySelector('[data-perf]');
        const timestamp = card.querySelector('.timestamp');

        // Remove loading states
        badge.removeAttribute('data-loading');
        details.removeAttribute('data-loading');
        cspnItem.removeAttribute('data-cspn');
        tpnItem.removeAttribute('data-tpn');
        perfItem.removeAttribute('data-perf');

        // Update badge
        const emoji = this.data.defcon.emoji || this.data.overall_emoji || '⚪';
        const level = this.formatLevel(this.data.defcon.level);
        badge.innerHTML = `<span>${emoji}</span><span>${level}</span>`;
        badge.style.background = this.data.defcon.color || this.data.overall_color || '#6b7280';
        badge.style.color = this.getContrastColor(this.data.defcon.color || this.data.overall_color || '#6b7280');

        // Update score
        scoreValue.textContent = this.data.combined_score.toFixed(1);
        
        // Update status bar
        fill.style.background = this.data.overall_color || '#6b7280';
        fill.style.width = `${this.data.combined_score}%`;

        // Update category scores
        const categoryScores = this.data.defcon.category_scores || {};
        const detailItems = details.querySelectorAll('.detail-item');
        const categories = ['network', 'threat', 'access', 'data', 'resilience'];
        
        categories.forEach((cat, index) => {
            if (detailItems[index]) {
                const label = detailItems[index].querySelector('.detail-label');
                const value = detailItems[index].querySelector('.detail-value');
                label.textContent = cat.charAt(0).toUpperCase() + cat.slice(1);
                value.textContent = `${categoryScores[cat]?.toFixed(1) || 'N/A'}%`;
            }
        });

        // Update compliance items
        this.updateComplianceItem(cspnItem, this.data.cspn);
        this.updateComplianceItem(tpnItem, this.data.tpn_media);
        this.updateComplianceItem(perfItem, { compliant: true, score: this.data.performance.score });

        // Update timestamp
        timestamp.textContent = this.formatTimestamp(this.timestamp);
    }

    updateComplianceItem(item, data) {
        const icon = item.querySelector('.icon');
        const textSpan = item.querySelector('span:last-child');
        
        const compliant = data?.compliant || data?.score >= (data?.threshold || 80);
        const score = data?.score || 0;
        
        icon.textContent = compliant ? '✓' : '✗';
        icon.style.background = compliant ? '#22c55e' : '#ef4444';
        icon.style.color = '#fff';
        
        const label = textSpan.textContent;
        textSpan.textContent = `${label}: ${score.toFixed(1)}%`;
    }

    formatLevel(level) {
        if (!level) return 'N/A';
        return level.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    formatTimestamp(isoString) {
        if (!isoString) return '--';
        const date = new Date(isoString);
        return date.toLocaleString();
    }

    getContrastColor(hexColor) {
        const r = parseInt(hexColor.substr(1, 2), 16);
        const g = parseInt(hexColor.substr(3, 2), 16);
        const b = parseInt(hexColor.substr(5, 2), 16);
        const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
        return luminance > 0.5 ? '#000' : '#fff';
    }

    showError(error) {
        const badge = this.querySelector('.defcon-card .badge');
        badge.innerHTML = `<span>❌</span><span>Error</span>`;
        badge.style.background = '#ef4444';
        badge.style.color = '#fff';
        badge.removeAttribute('data-loading');
    }

    startRefresh() {
        if (this.refreshInterval > 0) {
            this.refreshTimer = setInterval(() => {
                this.fetchData();
            }, this.refreshInterval * 1000);
        }
    }

    stopRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
}

/**
 * Initialize DEFCON badge for an element
 */
function initDefconBadge(elementId = 'defcon-badge', options = {}) {
    const element = document.getElementById(elementId);
    if (!element) {
        console.error(`Element with ID '${elementId}' not found`);
        return;
    }
    
    const badge = document.createElement('defcon-badge');
    if (options.socket) badge.setAttribute('socket', options.socket);
    if (options.apiPath) badge.setAttribute('api-path', options.apiPath);
    if (options.refresh) badge.setAttribute('refresh', options.refresh);
    if (options.compact) badge.classList.add('compact');
    
    element.appendChild(badge);
}

/**
 * Initialize DEFCON card for an element
 */
function initDefconCard(elementId = 'defcon-card', options = {}) {
    const element = document.getElementById(elementId);
    if (!element) {
        console.error(`Element with ID '${elementId}' not found`);
        return;
    }
    
    const card = document.createElement('defcon-card');
    if (options.socket) card.setAttribute('socket', options.socket);
    if (options.apiPath) card.setAttribute('api-path', options.apiPath);
    if (options.refresh) card.setAttribute('refresh', options.refresh);
    
    element.appendChild(card);
}

/**
 * Register custom elements
 */
if (!customElements.get('defcon-badge')) {
    customElements.define('defcon-badge', DefconBadge);
}
if (!customElements.get('defcon-card')) {
    customElements.define('defcon-card', DefconCard);
}

/**
 * Auto-initialize on DOM load
 */
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Auto-initialize any existing elements
        document.querySelectorAll('defcon-badge:not([initialized])').forEach(el => {
            el.setAttribute('initialized', 'true');
        });
        document.querySelectorAll('defcon-card:not([initialized])').forEach(el => {
            el.setAttribute('initialized', 'true');
        });
    });
} else {
    // Already loaded, initialize now
    document.querySelectorAll('defcon-badge:not([initialized])').forEach(el => {
        el.setAttribute('initialized', 'true');
    });
    document.querySelectorAll('defcon-card:not([initialized])').forEach(el => {
        el.setAttribute('initialized', 'true');
    });
}

/**
 * Export for module usage
 */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        DefconBadge,
        DefconCard,
        initDefconBadge,
        initDefconCard
    };
}
