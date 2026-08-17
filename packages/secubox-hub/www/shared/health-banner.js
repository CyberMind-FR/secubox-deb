// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

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

    // Prevent double-init if the script is loaded twice
    // (e.g. once by index.html and once injected via nginx sub_filter
    // or the mitmproxy WAF banner injection).
    if (window.__SBX_HEALTH_BANNER__) return;
    window.__SBX_HEALTH_BANNER__ = true;

    // A page can opt out of the operator health banner with
    // <meta name="sbx-no-health-banner"> in its <head> (e.g. a public-facing
    // blog where the operator banner is noise). This runs reliably because the
    // WAF injects the banner loader AFTER the page <head>, so the meta is
    // already parsed; and it is CSP-safe (no inline script needed on the
    // opting-out page, unlike a window flag).
    if (document.querySelector('meta[name="sbx-no-health-banner"]')) return;

    const VERSION = '1.4.7';
    const VISITOR_ORIGIN_API = window.SECUBOX_VISITOR_ORIGIN_API
        || '/api/v1/metrics/visitor-origin';
    const LIVE_HOSTS_API     = window.SECUBOX_LIVE_HOSTS_API
        || '/api/v1/metrics/live-hosts';
    const CERT_STATUS_API    = window.SECUBOX_CERT_STATUS_API
        || '/api/v1/metrics/cert-status';
    const COOKIE_AUDIT_API   = window.SECUBOX_COOKIE_AUDIT_SUMMARY
        || '/api/v1/cookie-audit/summary';
    const LIVE_REFRESH_INTERVAL = 30000; // 30 s
    // Use global config if injected by CDN/WAF, otherwise use relative path
    const HEALTH_API = window.SECUBOX_HEALTH_API || '/api/v1/metrics/health/summary';
    const REFRESH_INTERVAL = 30000; // 30s
    const CACHE_KEY = 'sbx_health_cache';
    const IS_CDN_INJECTED = !!window.SECUBOX_HEALTH_API;

    // Alert actions (/crowdsec/, /waf/, /system/, /hub/, …) are relative paths
    // that only resolve on the canonical hub vhost. When the banner is
    // sub_filter-injected on cross-domain vhosts (yacy.maegia.tv,
    // auth.maegia.tv, gitea.gk2.secubox.in, …), those paths 404. Detect the
    // hub allowlist so we render alerts as static <div>s off-hub.
    // Override: set window.SECUBOX_HUB_VHOST = true on a known hub-equivalent host.
    function isHubVhost() {
        if (window.SECUBOX_HUB_VHOST === true)  return true;
        if (window.SECUBOX_HUB_VHOST === false) return false;
        const h = window.location.hostname;
        if (h === 'localhost' || h === '127.0.0.1') return true;
        if (h === '192.168.1.200') return true;
        if (h.endsWith('.gk2.secubox.in')) return true;
        return false;
    }

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

    function renderSslStatus(ssl) {
        if (!ssl) return '';

        const statusConfig = {
            ok: { emoji: '🔒', label: 'Certificate OK' },
            warn: { emoji: '🔐', label: 'Certificate expiring soon' },
            error: { emoji: '🔓', label: 'Certificate critical' },
            expired: { emoji: '🔓', label: 'Certificate EXPIRED' },
            unknown: { emoji: '❓', label: 'Certificate unknown' }
        };

        const config = statusConfig[ssl.status] || statusConfig.unknown;
        const days = ssl.days_remaining;
        const daysText = ssl.status === 'expired' ? 'EXPIRÉ' :
                         days !== null ? `${days}j` : '--';

        return `
            <div class="hb-ssl ssl-${ssl.status}" title="${config.label} — ${ssl.domain || 'unknown'}">
                <span class="hb-ssl-icon">${config.emoji}</span>
                <span class="hb-ssl-days">${daysText}</span>
            </div>
        `;
    }

    function createBannerElement() {
        // Create trigger button (always visible)
        const trigger = document.createElement('div');
        trigger.id = 'health-banner-trigger';
        trigger.className = 'hb-trigger';
        trigger.innerHTML = `
            <span class="hb-trigger-icon">◀</span>
            <span class="hb-trigger-score">--</span>
        `;

        // Create banner panel (hidden by default)
        const banner = document.createElement('div');
        banner.id = 'health-banner';
        banner.className = 'health-banner';
        banner.innerHTML = `
            <div class="hb-content">
                <div class="hb-score">
                    <span class="hb-icon">💖</span>
                    <div class="hb-score-info">
                        <span class="hb-label">VIBING</span>
                        <div class="hb-bar"><div class="hb-fill"></div></div>
                    </div>
                    <span class="hb-pct">--</span>
                </div>
                <div class="hb-ssl-container"></div>
                <div class="hb-alerts"></div>
                <div class="hb-sparkle">✨</div>
                <div class="hb-details">
                    <div class="hb-stats-grid"></div>
                </div>
                <div class="hb-footer">v${VERSION}</div>
            </div>
        `;

        return { banner, trigger };
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // LIVE PANEL — VisitorOrigin / LiveHosts / CertStatus (issue #92)
    // ═══════════════════════════════════════════════════════════════════════════

    function sectionContainer(id) {
        let el = document.getElementById(id);
        if (!el) {
            el = document.createElement('div');
            el.id = id;
            el.className = 'sbx-live-section';
            // Append inside .hb-content (the scrollable area) instead of the
            // outer banner element. Insert before .hb-details so live sections
            // sit between alerts and the bottom stats grid.
            const content = document.querySelector('#health-banner .hb-content');
            if (content) {
                const details = content.querySelector('.hb-details');
                if (details) {
                    content.insertBefore(el, details);
                } else {
                    content.appendChild(el);
                }
            }
        }
        return el;
    }

    function hideSection(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    }

    function showSection(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
    }

    function renderVisitorOrigin(data) {
        if (!data || !data.enabled || !data.entries || !data.entries.length) {
            hideSection('sbx-visitor-origin');
            return;
        }
        const el = sectionContainer('sbx-visitor-origin');
        const rows = data.entries.map(e =>
            `<div class="sbx-row"><span class="sbx-asn">AS${e.asn}</span> <span class="sbx-org">${e.org}</span><span class="sbx-count">${e.count}</span></div>`
        ).join('');
        el.innerHTML = `<div class="sbx-section-title">VisitorOrigin · ${data.window_minutes}min · top ${data.entries.length}</div>${rows}`;
        showSection('sbx-visitor-origin');
    }

    function renderLiveHosts(data) {
        if (!data || !data.enabled || !data.entries || !data.entries.length) {
            hideSection('sbx-live-hosts');
            return;
        }
        const el = sectionContainer('sbx-live-hosts');
        const rows = data.entries.map(e =>
            `<div class="sbx-row"><span class="sbx-host">${e.host}</span><span class="sbx-count">${e.count}</span></div>`
        ).join('');
        el.innerHTML = `<div class="sbx-section-title">LiveHosts · ${data.window_minutes}min · top ${data.entries.length}</div>${rows}`;
        showSection('sbx-live-hosts');
    }

    function renderCertStatus(data) {
        if (!data || !data.enabled || !data.summary || !data.summary.total) {
            hideSection('sbx-cert-status');
            return;
        }
        const el = sectionContainer('sbx-cert-status');
        const s = data.summary;
        const next = data.next_renewal
            ? `<div class="sbx-row">next renewal: ${data.next_renewal.host} · ${data.next_renewal.days}d</div>`
            : '';
        el.innerHTML =
            `<div class="sbx-section-title">CertStatus · ${s.total} total</div>` +
            `<div class="sbx-row">✓ ${s.valid} valid · ⚠ ${s.expiring_soon} soon · ✗ ${s.expiring_critical + s.expired} critical</div>` +
            next;
        showSection('sbx-cert-status');
    }

    function renderCookieAudit(data) {
        // Hidden until aggregator is enabled and has at least one host.
        if (!data || !data.enabled || !data.summary || !data.summary.host_count) {
            hideSection('sbx-cookie-audit');
            return;
        }
        const el = sectionContainer('sbx-cookie-audit');
        const s = data.summary;
        const byCat = s.by_category || {};
        const violationClass = s.violation_count > 0 ? 'sbx-rgpd-violation' : 'sbx-rgpd-ok';
        const violationIcon  = s.violation_count > 0 ? '⚠' : '✓';
        el.innerHTML =
            `<div class="sbx-section-title">CookieAudit · ${s.host_count} vhost${s.host_count > 1 ? 's' : ''}</div>` +
            `<div class="sbx-row ${violationClass}">` +
                `<span>${violationIcon} RGPD</span>` +
                `<span class="sbx-count">${s.violation_count} viol · ${s.hosts_with_violations} hosts</span>` +
            `</div>` +
            `<div class="sbx-row sbx-cookie-cat">` +
                `<span>strict</span><span class="sbx-count">${byCat.strictly_necessary || 0}</span>` +
            `</div>` +
            `<div class="sbx-row sbx-cookie-cat">` +
                `<span>func</span><span class="sbx-count">${byCat.functional || 0}</span>` +
            `</div>` +
            `<div class="sbx-row sbx-cookie-cat">` +
                `<span>analytics</span><span class="sbx-count">${byCat.analytics || 0}</span>` +
            `</div>` +
            `<div class="sbx-row sbx-cookie-cat">` +
                `<span>marketing</span><span class="sbx-count">${byCat.marketing || 0}</span>` +
            `</div>` +
            ((byCat.unclassified || 0) > 0
                ? `<div class="sbx-row sbx-cookie-cat"><span>?? unclassified</span><span class="sbx-count">${byCat.unclassified}</span></div>`
                : '');
        showSection('sbx-cookie-audit');
    }

    async function pollLivePanel() {
        const fetchSafe = async (url) => {
            try {
                const r = await fetch(url, { credentials: 'omit' });
                if (!r.ok) return null;
                return await r.json();
            } catch (e) { return null; }
        };
        const [vo, lh, cs, ca] = await Promise.all([
            fetchSafe(VISITOR_ORIGIN_API),
            fetchSafe(LIVE_HOSTS_API),
            fetchSafe(CERT_STATUS_API),
            fetchSafe(COOKIE_AUDIT_API),
        ]);
        if (vo) renderVisitorOrigin(vo); else hideSection('sbx-visitor-origin');
        if (lh) renderLiveHosts(lh);     else hideSection('sbx-live-hosts');
        if (cs) renderCertStatus(cs);    else hideSection('sbx-cert-status');
        if (ca) renderCookieAudit(ca);   else hideSection('sbx-cookie-audit');
    }

    function injectBannerStyles() {
        if (document.getElementById('health-banner-styles')) return;

        const style = document.createElement('style');
        style.id = 'health-banner-styles';
        style.textContent = `
            /* SIDE-SLIDING HEALTH BANNER */
            /* Hidden by default, slides from right, pushes content */

            .health-banner {
                position: fixed;
                top: 0;
                right: 0;
                width: 0;
                height: 100vh;
                background: linear-gradient(180deg, #0a0a0f 0%, #0f0f14 50%, #0a0a0f 100%);
                border-left: 1px solid rgba(201,168,76,0.3);
                z-index: 9998;
                font-family: 'JetBrains Mono', monospace;
                font-size: 10px;
                color: var(--text-primary, #e8e6d9);
                transition: width 0.3s ease, box-shadow 0.3s ease;
                overflow: hidden;
                box-shadow: -4px 0 20px rgba(0,0,0,0.5);
            }

            /* Hidden trigger button - always visible */
            .hb-trigger {
                position: fixed;
                top: 50%;
                right: 0;
                transform: translateY(-50%);
                width: 24px;
                height: 60px;
                background: linear-gradient(180deg, #0a0a0f 0%, #1a1a24 100%);
                border: 1px solid rgba(201,168,76,0.4);
                border-right: none;
                border-radius: 8px 0 0 8px;
                z-index: 9999;
                cursor: pointer;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                gap: 4px;
                transition: all 0.3s ease;
            }
            .hb-trigger:hover {
                width: 32px;
                background: linear-gradient(180deg, #1a1a24 0%, #2a2a34 100%);
                border-color: rgba(201,168,76,0.8);
                box-shadow: -4px 0 15px rgba(201,168,76,0.2);
            }
            .hb-trigger-icon {
                font-size: 14px;
                transition: transform 0.3s ease;
            }
            .hb-trigger-score {
                font-size: 8px;
                color: var(--gold-hermetic, #c9a84c);
                font-weight: bold;
                writing-mode: vertical-rl;
                text-orientation: mixed;
            }
            body.health-banner-open .hb-trigger {
                right: 280px;
            }
            body.health-banner-open .hb-trigger-icon {
                transform: rotate(180deg);
            }

            /* Expanded state */
            .health-banner.expanded {
                width: 280px;
            }

            .hb-content {
                display: flex;
                flex-direction: column;
                padding: 16px;
                gap: 16px;
                width: 280px;
                height: 100%;
                overflow-y: auto;
            }

            /* Score section */
            .hb-score {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 12px;
                background: rgba(255,255,255,0.05);
                border-radius: 8px;
                border: 1px solid rgba(201,168,76,0.2);
            }
            .hb-icon { font-size: 24px; }
            .hb-score-info {
                flex: 1;
            }
            .hb-label {
                font-size: 10px;
                letter-spacing: 1px;
                color: var(--gold-hermetic, #c9a84c);
                display: block;
                margin-bottom: 4px;
            }
            .hb-bar {
                width: 100%;
                height: 8px;
                background: rgba(255,255,255,0.1);
                border-radius: 4px;
                overflow: hidden;
            }
            .hb-fill {
                height: 100%;
                background: linear-gradient(90deg, #ef4444, #eab308, #22c55e);
                border-radius: 4px;
                transition: width 0.5s ease;
                width: 0%;
            }
            .hb-pct {
                font-size: 18px;
                font-weight: bold;
                color: var(--text-primary, #e8e6d9);
            }

            /* SSL Certificate Status */
            .hb-ssl {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 8px 12px;
                background: rgba(255,255,255,0.03);
                border-radius: 6px;
                border: 1px solid rgba(255,255,255,0.08);
                font-size: 11px;
            }
            .hb-ssl-icon { font-size: 14px; }
            .hb-ssl-days { font-weight: 600; }
            .hb-ssl.ssl-ok { border-color: rgba(0, 255, 65, 0.3); }
            .hb-ssl.ssl-ok .hb-ssl-days { color: #00ff41; }
            .hb-ssl.ssl-warn { border-color: rgba(255, 193, 7, 0.3); }
            .hb-ssl.ssl-warn .hb-ssl-days { color: #ffc107; }
            .hb-ssl.ssl-error { border-color: rgba(230, 57, 70, 0.3); }
            .hb-ssl.ssl-error .hb-ssl-days { color: #e63946; }
            .hb-ssl.ssl-expired {
                border-color: rgba(230, 57, 70, 0.5);
                background: rgba(230, 57, 70, 0.1);
                animation: ssl-blink 1s infinite;
            }
            .hb-ssl.ssl-expired .hb-ssl-days { color: #e63946; }
            @keyframes ssl-blink { 50% { opacity: 0.6; } }
            .hb-ssl.ssl-unknown { border-color: rgba(107, 107, 122, 0.3); }
            .hb-ssl.ssl-unknown .hb-ssl-days { color: #6b6b7a; }

            /* Alerts */
            .hb-alerts {
                display: flex;
                flex-direction: column;
                gap: 6px;
            }
            .hb-alert {
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 8px 10px;
                border-radius: 6px;
                font-size: 10px;
                cursor: pointer;
                text-decoration: none;
            }
            .hb-alert.critical {
                background: rgba(239,68,68,0.15);
                border: 1px solid rgba(239,68,68,0.4);
                color: #ef4444;
            }
            .hb-alert.warning {
                background: rgba(234,179,8,0.15);
                border: 1px solid rgba(234,179,8,0.4);
                color: #eab308;
            }
            .hb-alert.info {
                background: rgba(0,212,255,0.15);
                border: 1px solid rgba(0,212,255,0.4);
                color: #00d4ff;
            }
            .hb-alert.celebration {
                background: linear-gradient(135deg, rgba(201,168,76,0.2), rgba(255,215,0,0.15));
                border: 1px solid rgba(255,215,0,0.5);
                color: #ffd700;
            }
            .hb-alert.patrol {
                background: rgba(100,149,237,0.15);
                border: 1px solid rgba(100,149,237,0.4);
                color: #6495ed;
            }
            .hb-alert-icon { font-size: 14px; }
            .hb-alert-text {
                flex: 1;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }

            /* Stats grid */
            .hb-details {
                margin-top: auto;
                padding-top: 12px;
                border-top: 1px solid rgba(201,168,76,0.2);
            }
            .hb-stats-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 8px;
            }
            .hb-stat {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 2px;
                padding: 8px;
                background: rgba(255,255,255,0.03);
                border-radius: 6px;
            }
            .hb-stat-icon { font-size: 16px; }
            .hb-stat-label {
                font-size: 8px;
                color: var(--gold-hermetic, #c9a84c);
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .hb-stat-value {
                font-size: 14px;
                font-weight: bold;
                color: var(--text-primary, #e8e6d9);
            }

            .hb-sparkle {
                position: absolute;
                top: 10px;
                right: 10px;
                font-size: 16px;
                animation: hb-sparkle 3s infinite ease-in-out;
                display: none;
            }
            .hb-footer {
                position: absolute;
                bottom: 5px;
                left: 50%;
                transform: translateX(-50%);
                font-size: 9px;
                color: #444;
                font-family: monospace;
            }
            .hb-toggle { display: none; } /* Hidden in sidebar mode */

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

            /* Push main content when banner is open */
            body.health-banner-open .main,
            body.health-banner-open .sidebar + .main {
                margin-right: 280px;
                transition: margin-right 0.3s ease;
            }

            /* Mobile: slide from bottom */
            @media (max-width: 768px) {
                .health-banner {
                    top: auto;
                    bottom: 0;
                    right: 0;
                    left: 0;
                    width: 100%;
                    height: 0;
                    border-left: none;
                    border-top: 1px solid rgba(201,168,76,0.3);
                }
                .health-banner.expanded {
                    width: 100%;
                    height: 60vh;
                }
                .hb-trigger {
                    top: auto;
                    bottom: 0;
                    right: 50%;
                    transform: translateX(50%);
                    width: 60px;
                    height: 24px;
                    border-radius: 8px 8px 0 0;
                    border-bottom: none;
                    flex-direction: row;
                }
                body.health-banner-open .hb-trigger {
                    right: 50%;
                    bottom: 60vh;
                }
                .hb-trigger-score {
                    writing-mode: horizontal-tb;
                }
                .hb-content {
                    width: 100%;
                }
                .hb-stats-grid {
                    grid-template-columns: repeat(3, 1fr);
                }
                body.health-banner-open .main {
                    margin-right: 0;
                    margin-bottom: 60vh;
                }
            }
            .sbx-live-section { padding: 6px 10px; border-top: 1px solid var(--text-muted, #6b6b7a); font-size: 11px; line-height: 1.4; }
            .sbx-section-title { font-weight: 600; color: var(--gold-hermetic, #c9a84c); margin-bottom: 2px; }
            .sbx-row { display: flex; justify-content: space-between; gap: 8px; }
            .sbx-row .sbx-count { color: var(--cyber-cyan, #00d4ff); font-variant-numeric: tabular-nums; }
            .sbx-row .sbx-asn { color: var(--matrix-green, #00ff41); }
            .sbx-rgpd-violation { color: #ef4444; font-weight: 600; }
            .sbx-rgpd-violation .sbx-count { color: #ef4444; }
            .sbx-rgpd-ok { color: var(--matrix-green, #00ff41); }
            .sbx-rgpd-ok .sbx-count { color: var(--matrix-green, #00ff41); }
            .sbx-cookie-cat { font-size: 10px; color: var(--text-muted, #6b6b7a); padding-left: 8px; }
            .sbx-cookie-cat .sbx-count { color: var(--text-primary, #e8e6d9); }
        `;
        document.head.appendChild(style);
    }

    function renderBanner(health) {
        const banner = document.getElementById('health-banner');
        const trigger = document.getElementById('health-banner-trigger');
        if (!banner) return;

        // Calculate overall score
        const score = health?.score || 0;
        const pctEl = banner.querySelector('.hb-pct');
        const fillEl = banner.querySelector('.hb-fill');
        const iconEl = banner.querySelector('.hb-icon');
        const labelEl = banner.querySelector('.hb-label');
        const sparkleEl = banner.querySelector('.hb-sparkle');

        // Update trigger score
        if (trigger) {
            const triggerScore = trigger.querySelector('.hb-trigger-score');
            const triggerIcon = trigger.querySelector('.hb-trigger-icon');
            if (triggerScore) triggerScore.textContent = score + '%';
            if (triggerIcon) triggerIcon.textContent = getScoreEmoji(score);
        }

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

        // Update SSL status
        const sslContainer = banner.querySelector('.hb-ssl-container');
        if (sslContainer && health.ssl) {
            sslContainer.innerHTML = renderSslStatus(health.ssl);
        }

        // Render doctor alerts. Actions are hub-relative paths, so when we are
        // injected on a cross-domain vhost (yacy.maegia.tv, auth.maegia.tv, …)
        // we render alerts as static <div>s — never a broken clickable link.
        const alertsEl = banner.querySelector('.hb-alerts');
        if (alertsEl) {
            const alerts = diagnose(health);
            const visibleAlerts = alerts.filter(a => a.severity !== 'celebration' || score >= 95).slice(0, 5);
            const hub = isHubVhost();
            // Alerts are always non-clickable (#290). The previous <a href>
            // branch emitted relative URLs that resolved to whatever host the
            // banner was embedded on — e.g. https://oracle.ganimed.fr/system/
            // when loaded cross-origin. Banner stays purely informational;
            // the dashboard sidebar is the canonical navigation surface.
            alertsEl.innerHTML = visibleAlerts.map(a =>
                `<div class="hb-alert ${a.severity}" title="${a.message}">
                    <span class="hb-alert-icon">${a.icon}</span>
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
            // Pass current domain for SSL certificate check
            const currentDomain = window.location.hostname;
            const apiUrl = HEALTH_API + (HEALTH_API.includes('?') ? '&' : '?') + 'domain=' + encodeURIComponent(currentDomain);

            const resp = await fetch(apiUrl, {
                headers: { 'Accept': 'application/json' },
                credentials: 'omit'  // Cross-origin request
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
        pollLivePanel();
        setInterval(pollLivePanel, LIVE_REFRESH_INTERVAL);

        // Create banner and trigger
        const { banner, trigger } = createBannerElement();
        document.body.appendChild(trigger);
        document.body.appendChild(banner);

        // ── SPA re-inject guard (#750) ─────────────────────────────────────
        // SPA sites (x.com, Next.js news) rebuild <body> on hydration, wiping
        // our appended nodes; the one-shot __SBX_HEALTH_BANNER__ guard then
        // blocks any re-init, so the banner never returns. Re-attach the
        // already-created nodes — and re-add the styles if <head> was cleared
        // too — whenever they detach. The closure keeps the refs alive even
        // after the DOM node is wiped, and re-appending the SAME nodes
        // preserves their event listeners.
        function ensureMounted() {
            injectBannerStyles(); // id-guarded: no-op when the <style> is present
            const body = document.body;
            if (!body) return;
            if (!trigger.isConnected) body.appendChild(trigger);
            if (!banner.isConnected) {
                body.appendChild(banner);
                // Re-sync the layout-shift class: a body wiped while the banner
                // was expanded loses 'health-banner-open' on the fresh body.
                body.classList.toggle('health-banner-open', banner.classList.contains('expanded'));
            }
        }
        try {
            // childList on <html> catches a full <body> element swap (cheap, no subtree).
            new MutationObserver(ensureMounted)
                .observe(document.documentElement, { childList: true });
        } catch (_) { /* MutationObserver unsupported → the interval below covers it */ }
        // Fallback for body.innerHTML='' (children cleared, body element kept),
        // which a childList-only observer on <html> does not see.
        setInterval(ensureMounted, 1500);

        // Toggle banner on trigger click
        trigger.addEventListener('click', () => {
            const isOpen = banner.classList.toggle('expanded');
            document.body.classList.toggle('health-banner-open', isOpen);
        });

        // Close on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && banner.classList.contains('expanded')) {
                banner.classList.remove('expanded');
                document.body.classList.remove('health-banner-open');
            }
        });

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

        console.log('[HealthBanner] v' + VERSION + ' initialized (sidebar mode)');
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
