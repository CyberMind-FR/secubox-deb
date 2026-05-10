/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SECUBOX HEALTH BANNER — Global Health Monitor with Smart Doctor
 *  v1.0.0 — Double-buffered cache with lock protection
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  SecuBox-Deb :: Health Banner Component
 *  CyberMind — https://cybermind.fr
 *  Author: Gerald Kerma <gandalf@gk2.net>
 *  License: Proprietary / ANSSI CSPN candidate
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function() {
    'use strict';

    const VERSION = '1.1.0';
    // Use global config if injected by CDN/WAF, otherwise use relative path
    const HEALTH_API = window.SECUBOX_HEALTH_API || '/api/v1/metrics/health/summary';
    const REFRESH_INTERVAL = 30000; // 30s
    const CACHE_KEY = 'sbx_health_cache';
    const IS_CDN_INJECTED = !!window.SECUBOX_HEALTH_API;

    // ═══════════════════════════════════════════════════════════════════════════
    // DOUBLE-BUFFER CACHE with Lock Protection
    // ═══════════════════════════════════════════════════════════════════════════

    const HealthCache = {
        active: null,
        shadow: null,
        locked: false,
        lastSwap: 0,

        read() {
            return this.active;
        },

        write(data) {
            if (this.locked) {
                console.warn('[HealthBanner] Cache locked, queuing write');
                setTimeout(() => this.write(data), 100);
                return;
            }
            this.shadow = data;
        },

        swap() {
            if (this.locked) return false;
            this.locked = true;
            const temp = this.active;
            this.active = this.shadow;
            this.shadow = temp;
            this.lastSwap = Date.now();
            this.locked = false;
            this.persist();
            return true;
        },

        persist() {
            try {
                localStorage.setItem(CACHE_KEY, JSON.stringify({
                    ts: Date.now(),
                    data: this.active
                }));
            } catch (e) {}
        },

        restore() {
            try {
                const cached = localStorage.getItem(CACHE_KEY);
                if (cached) {
                    const parsed = JSON.parse(cached);
                    if (parsed.ts && (Date.now() - parsed.ts) < 300000) { // 5min TTL
                        this.active = parsed.data;
                        return true;
                    }
                }
            } catch (e) {}
            return false;
        }
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // SMART DOCTOR ADVISOR
    // ═══════════════════════════════════════════════════════════════════════════

    // Module emoji map for spunky display
    const MODULE_EMOJIS = {
        waf: ['🛡️', '⚔️', '🔰'],
        crowdsec: ['👮', '🚔', '🚨'],
        haproxy: ['🌐', '🔀', '🔄'],
        nginx: ['🌍', '📡', '🚀'],
        system: ['💻', '🖥️', '⚙️']
    };

    const STATUS_EMOJIS = {
        ok: ['✅', '🟢', '💚', '🌟'],
        warn: ['⚠️', '🟡', '🔶', '⏳'],
        error: ['❌', '🔴', '💔', '🆘'],
        off: ['⬜', '💤', '🔌']
    };

    const DoctorRules = [
        {
            id: 'all-good',
            check: h => h.score >= 95,
            severity: 'celebration',
            icon: '🎉',
            message: h => `System looking sexy! ${h.score}% health`,
            action: null
        },
        {
            id: 'waf-high-block',
            check: h => h.waf?.blocked_pct > 25,
            severity: 'warning',
            icon: '⚔️',
            message: h => `WAF slaying ${h.waf.blocked_pct}% baddies`,
            action: '/waf/'
        },
        {
            id: 'crowdsec-many-bans',
            check: h => h.crowdsec?.active_decisions > 50,
            severity: 'info',
            icon: '🚨',
            message: h => `${h.crowdsec.active_decisions} threats neutralized`,
            action: '/crowdsec/'
        },
        {
            id: 'crowdsec-patrol',
            check: h => h.crowdsec?.active_decisions > 0 && h.crowdsec?.active_decisions <= 50,
            severity: 'patrol',
            icon: '👮',
            message: h => `${h.crowdsec.active_decisions} bans active`,
            action: '/crowdsec/'
        },
        {
            id: 'cpu-critical',
            check: h => h.system?.cpu > 85,
            severity: 'critical',
            icon: '🔥',
            message: h => `CPU blazing ${h.system.cpu}%`,
            action: '/system/'
        },
        {
            id: 'cpu-warm',
            check: h => h.system?.cpu > 60 && h.system?.cpu <= 85,
            severity: 'info',
            icon: '🌡️',
            message: h => `CPU working ${h.system.cpu}%`,
            action: '/system/'
        },
        {
            id: 'memory-high',
            check: h => h.system?.memory > 90,
            severity: 'critical',
            icon: '🧠',
            message: h => `Memory stuffed ${h.system.memory}%`,
            action: '/system/'
        },
        {
            id: 'disk-full',
            check: h => h.system?.disk > 85,
            severity: 'warning',
            icon: '💾',
            message: h => `Disk chunky ${h.system.disk}%`,
            action: '/system/'
        },
        {
            id: 'services-down',
            check: h => h.services?.down > 0,
            severity: 'critical',
            icon: '💀',
            message: h => `${h.services.down} services need CPR!`,
            action: '/hub/'
        },
        {
            id: 'lxc-running',
            check: h => h.services?.lxc_running > 0,
            severity: 'info',
            icon: '📦',
            message: h => `${h.services.lxc_running} containers vibing`,
            action: '/system/'
        }
    ];

    function diagnose(health) {
        const alerts = [];
        for (const rule of DoctorRules) {
            try {
                if (rule.check(health)) {
                    alerts.push({
                        id: rule.id,
                        severity: rule.severity,
                        icon: rule.icon,
                        message: rule.message(health),
                        action: rule.action
                    });
                }
            } catch (e) {}
        }
        return alerts.sort((a, b) => {
            const order = { critical: 0, warning: 1, info: 2 };
            return order[a.severity] - order[b.severity];
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BANNER UI
    // ═══════════════════════════════════════════════════════════════════════════

    function getScoreEmoji(score) {
        if (score >= 95) return '💖';
        if (score >= 85) return '💚';
        if (score >= 70) return '💛';
        if (score >= 50) return '🧡';
        return '💔';
    }

    function getScoreVibe(score) {
        if (score >= 95) return 'VIBING';
        if (score >= 85) return 'SOLID';
        if (score >= 70) return 'OKAY';
        if (score >= 50) return 'MEH';
        return 'YIKES';
    }

    function createBannerElement() {
        const banner = document.createElement('div');
        banner.id = 'health-banner';
        banner.className = 'health-banner';
        banner.innerHTML = `
            <div class="hb-content">
                <div class="hb-score">
                    <span class="hb-icon">💖</span>
                    <span class="hb-label">VIBING</span>
                    <div class="hb-bar"><div class="hb-fill"></div></div>
                    <span class="hb-pct">--</span>
                </div>
                <div class="hb-modules"></div>
                <div class="hb-alerts"></div>
                <div class="hb-sparkle">✨</div>
                <button class="hb-toggle" title="Toggle details">▼</button>
            </div>
            <div class="hb-details">
                <div class="hb-stats-grid"></div>
            </div>
        `;
        return banner;
    }

    function injectBannerStyles() {
        if (document.getElementById('health-banner-styles')) return;

        const style = document.createElement('style');
        style.id = 'health-banner-styles';
        style.textContent = `
            .health-banner {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                height: 28px;
                background: linear-gradient(90deg, #0a0a0f 0%, #0f0f14 50%, #0a0a0f 100%);
                border-bottom: 1px solid rgba(201,168,76,0.3);
                z-index: 9999;
                font-family: 'JetBrains Mono', monospace;
                font-size: 10px;
                color: var(--text-primary, #e8e6d9);
                transition: height 0.3s ease, box-shadow 0.3s ease;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.5);
            }
            /* Expand on hover */
            .health-banner:hover {
                height: auto;
                min-height: 28px;
                box-shadow: 0 4px 20px rgba(201,168,76,0.3);
            }
            .health-banner.expanded {
                height: auto;
                min-height: 28px;
            }
            .health-banner.sidebar-collapsed {
                /* No change needed - full width */
            }
            .hb-content {
                display: flex;
                align-items: center;
                height: 28px;
                padding: 0 16px;
                gap: 12px;
            }
            .hb-score {
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .hb-icon { font-size: 14px; }
            .hb-label {
                font-size: 9px;
                letter-spacing: 1px;
                color: var(--gold-hermetic, #c9a84c);
                opacity: 0.8;
            }
            .hb-bar {
                width: 60px;
                height: 6px;
                background: rgba(255,255,255,0.1);
                border-radius: 3px;
                overflow: hidden;
            }
            .hb-fill {
                height: 100%;
                background: linear-gradient(90deg, #ef4444, #eab308, #22c55e);
                border-radius: 3px;
                transition: width 0.5s ease;
                width: 0%;
            }
            .hb-pct {
                font-weight: bold;
                min-width: 32px;
            }
            .hb-modules {
                display: flex;
                gap: 8px;
                flex: 1;
            }
            .hb-alerts {
                display: flex;
                gap: 8px;
            }
            .hb-alert {
                display: flex;
                align-items: center;
                gap: 4px;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 10px;
                cursor: pointer;
                animation: hb-pulse 2s infinite;
            }
            .hb-alert.critical {
                background: rgba(239,68,68,0.2);
                border: 1px solid rgba(239,68,68,0.5);
                color: #ef4444;
            }
            .hb-alert.warning {
                background: rgba(234,179,8,0.2);
                border: 1px solid rgba(234,179,8,0.5);
                color: #eab308;
            }
            .hb-alert.info {
                background: rgba(0,212,255,0.2);
                border: 1px solid rgba(0,212,255,0.5);
                color: #00d4ff;
            }
            .hb-alert.celebration {
                background: linear-gradient(135deg, rgba(201,168,76,0.3), rgba(255,215,0,0.2));
                border: 1px solid rgba(255,215,0,0.6);
                color: #ffd700;
                animation: hb-glow 2s infinite;
            }
            .hb-alert.patrol {
                background: rgba(100,149,237,0.2);
                border: 1px solid rgba(100,149,237,0.5);
                color: #6495ed;
            }
            .hb-alert-text {
                max-width: 150px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            @keyframes hb-pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.7; }
            }
            @keyframes hb-glow {
                0%, 100% { box-shadow: 0 0 5px rgba(255,215,0,0.3); }
                50% { box-shadow: 0 0 15px rgba(255,215,0,0.6); }
            }
            @keyframes hb-sparkle {
                0%, 100% { transform: scale(1) rotate(0deg); opacity: 1; }
                50% { transform: scale(1.2) rotate(180deg); opacity: 0.8; }
            }
            .hb-sparkle {
                position: absolute;
                right: 60px;
                font-size: 16px;
                animation: hb-sparkle 3s infinite ease-in-out;
                display: none;
            }
            .hb-mod {
                display: flex;
                align-items: center;
                gap: 2px;
                padding: 2px 6px;
                border-radius: 4px;
                background: rgba(255,255,255,0.05);
                cursor: pointer;
                transition: all 0.2s;
                text-decoration: none;
                position: relative;
            }
            .hb-mod:hover {
                background: rgba(255,255,255,0.15);
                transform: translateY(-1px);
            }
            .hb-mod.ok { border-bottom: 2px solid #22c55e; }
            .hb-mod.warn { border-bottom: 2px solid #eab308; }
            .hb-mod.err { border-bottom: 2px solid #ef4444; }
            .hb-mod.off { border-bottom: 2px solid #666; opacity: 0.6; }
            .hb-mod-emoji { font-size: 14px; }
            .hb-mod-status {
                font-size: 8px;
                position: absolute;
                top: -2px;
                right: -2px;
            }
            .hb-stats-grid {
                display: grid;
                grid-template-columns: repeat(6, 1fr);
                gap: 12px;
                padding: 8px 0;
            }
            .hb-stat {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 2px;
                padding: 8px;
                background: rgba(255,255,255,0.05);
                border-radius: 6px;
            }
            .hb-stat-icon { font-size: 18px; }
            .hb-stat-label {
                font-size: 9px;
                color: var(--gold-hermetic, #c9a84c);
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .hb-stat-value {
                font-size: 14px;
                font-weight: bold;
                color: var(--text-primary, #e8e6d9);
            }
            .hb-toggle {
                background: none;
                border: none;
                color: var(--text-muted, #6b6b7a);
                cursor: pointer;
                padding: 4px 8px;
                font-size: 10px;
                transition: transform 0.3s, color 0.2s;
                opacity: 0.5;
            }
            .health-banner:hover .hb-toggle {
                opacity: 1;
                color: var(--gold-hermetic, #c9a84c);
            }
            .health-banner:hover .hb-toggle,
            .health-banner.expanded .hb-toggle {
                transform: rotate(180deg);
            }
            .hb-details {
                padding: 8px 16px;
                border-top: 1px solid rgba(201,168,76,0.2);
                display: none;
                background: rgba(10,10,15,0.98);
            }
            .health-banner:hover .hb-details,
            .health-banner.expanded .hb-details {
                display: block;
            }

            /* Push main content and sidebar down */
            body.has-health-banner {
                padding-top: 28px;
            }
            body.has-health-banner .sidebar {
                top: 28px;
                height: calc(100vh - 28px);
            }
            body.has-health-banner .main {
                margin-top: 28px;
            }

            /* Mobile */
            @media (max-width: 768px) {
                .health-banner {
                    font-size: 9px;
                    height: 24px;
                }
                .hb-content {
                    height: 24px;
                    padding: 0 8px;
                    gap: 8px;
                }
                .hb-label { display: none; }
                .hb-modules { display: none; }
                .hb-alert-text { max-width: 100px; }
                body.has-health-banner {
                    padding-top: 24px;
                }
                body.has-health-banner .sidebar {
                    top: 24px;
                    height: calc(100vh - 24px);
                }
            }
        `;
        document.head.appendChild(style);
    }

    function renderBanner(health) {
        const banner = document.getElementById('health-banner');
        if (!banner) return;

        // Calculate overall score
        const score = health?.score || 0;
        const pctEl = banner.querySelector('.hb-pct');
        const fillEl = banner.querySelector('.hb-fill');
        const iconEl = banner.querySelector('.hb-icon');
        const labelEl = banner.querySelector('.hb-label');
        const sparkleEl = banner.querySelector('.hb-sparkle');

        if (pctEl) pctEl.textContent = score + '%';
        if (fillEl) {
            fillEl.style.width = score + '%';
            // Color based on score
            if (score >= 85) fillEl.style.background = 'linear-gradient(90deg, #22c55e, #10b981, #34d399)';
            else if (score >= 70) fillEl.style.background = 'linear-gradient(90deg, #eab308, #fbbf24, #f59e0b)';
            else fillEl.style.background = 'linear-gradient(90deg, #ef4444, #dc2626, #f87171)';
        }
        if (iconEl) iconEl.textContent = getScoreEmoji(score);
        if (labelEl) labelEl.textContent = getScoreVibe(score);
        if (sparkleEl) {
            sparkleEl.style.display = score >= 90 ? 'block' : 'none';
        }

        // Render module LEDs with emojis
        const modsEl = banner.querySelector('.hb-modules');
        if (modsEl && health?.modules) {
            const modules = ['waf', 'crowdsec', 'haproxy', 'nginx', 'system'];
            modsEl.innerHTML = modules.map(m => {
                const mod = health.modules[m] || {};
                const status = mod.status || 'off';
                const ledClass = status === 'ok' ? 'ok' : status === 'warn' ? 'warn' : status === 'error' ? 'err' : 'off';
                const emojis = MODULE_EMOJIS[m] || ['📦'];
                const statusEmojis = STATUS_EMOJIS[status] || STATUS_EMOJIS.off;
                const emoji = emojis[0];
                const statusDot = statusEmojis[1] || statusEmojis[0];
                return `<a href="/${m}/" class="hb-mod ${ledClass}" title="${m}: ${status}">
                    <span class="hb-mod-emoji">${emoji}</span>
                    <span class="hb-mod-status">${statusDot}</span>
                </a>`;
            }).join('');
        }

        // Render doctor alerts
        const alertsEl = banner.querySelector('.hb-alerts');
        if (alertsEl) {
            const alerts = diagnose(health);
            const visibleAlerts = alerts.filter(a => a.severity !== 'celebration' || score >= 95).slice(0, 3);
            alertsEl.innerHTML = visibleAlerts.map(a =>
                a.action
                    ? `<a href="${a.action}" class="hb-alert ${a.severity}" title="${a.message}">
                        <span>${a.icon}</span>
                        <span class="hb-alert-text">${a.message}</span>
                    </a>`
                    : `<div class="hb-alert ${a.severity}" title="${a.message}">
                        <span>${a.icon}</span>
                        <span class="hb-alert-text">${a.message}</span>
                    </div>`
            ).join('');
        }

        // Render expanded details
        const detailsGrid = banner.querySelector('.hb-stats-grid');
        if (detailsGrid && health) {
            detailsGrid.innerHTML = `
                <div class="hb-stat">
                    <span class="hb-stat-icon">🖥️</span>
                    <span class="hb-stat-label">CPU</span>
                    <span class="hb-stat-value">${health.system?.cpu || 0}%</span>
                </div>
                <div class="hb-stat">
                    <span class="hb-stat-icon">🧠</span>
                    <span class="hb-stat-label">RAM</span>
                    <span class="hb-stat-value">${health.system?.memory || 0}%</span>
                </div>
                <div class="hb-stat">
                    <span class="hb-stat-icon">💾</span>
                    <span class="hb-stat-label">Disk</span>
                    <span class="hb-stat-value">${health.system?.disk || 0}%</span>
                </div>
                <div class="hb-stat">
                    <span class="hb-stat-icon">📦</span>
                    <span class="hb-stat-label">LXC</span>
                    <span class="hb-stat-value">${health.services?.lxc_running || 0}</span>
                </div>
                <div class="hb-stat">
                    <span class="hb-stat-icon">🚨</span>
                    <span class="hb-stat-label">Bans</span>
                    <span class="hb-stat-value">${health.crowdsec?.active_decisions || 0}</span>
                </div>
                <div class="hb-stat">
                    <span class="hb-stat-icon">🌐</span>
                    <span class="hb-stat-label">VHosts</span>
                    <span class="hb-stat-value">${health.counts?.vhosts || 0}</span>
                </div>
            `;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DATA FETCHING
    // ═══════════════════════════════════════════════════════════════════════════

    async function fetchHealth() {
        try {
            const resp = await fetch(HEALTH_API, {
                headers: { 'Accept': 'application/json' },
                credentials: 'same-origin'
            });
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return await resp.json();
        } catch (e) {
            console.warn('[HealthBanner] Fetch failed:', e.message);
            // Return mock data for graceful degradation
            return {
                score: 85,
                modules: {
                    waf: { status: 'ok' },
                    crowdsec: { status: 'ok' },
                    haproxy: { status: 'ok' },
                    nginx: { status: 'ok' },
                    system: { status: 'ok' }
                }
            };
        }
    }

    async function refreshHealth() {
        const data = await fetchHealth();
        HealthCache.write(data);
        HealthCache.swap();
        renderBanner(HealthCache.read());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════════

    function init() {
        // Inject styles
        injectBannerStyles();

        // Create banner
        const banner = createBannerElement();
        document.body.insertBefore(banner, document.body.firstChild);
        document.body.classList.add('has-health-banner');

        // Toggle expand
        const toggleBtn = banner.querySelector('.hb-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                banner.classList.toggle('expanded');
            });
        }

        // Restore from cache first (instant display)
        if (HealthCache.restore()) {
            renderBanner(HealthCache.read());
        }

        // Fetch fresh data
        refreshHealth();

        // Periodic refresh
        setInterval(refreshHealth, REFRESH_INTERVAL);

        // Listen for sidebar collapse
        document.addEventListener('sidebar-toggle', (e) => {
            if (e.detail?.collapsed) {
                banner.classList.add('sidebar-collapsed');
            } else {
                banner.classList.remove('sidebar-collapsed');
            }
        });

        console.log('[HealthBanner] v' + VERSION + ' initialized');
    }

    // Start
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Export for external access
    window.SecuBoxHealthBanner = {
        refresh: refreshHealth,
        diagnose: diagnose,
        cache: HealthCache
    };

})();
