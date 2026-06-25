/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SECUBOX SIDEBAR — Health-Aware Navigation + Hybrid Skin Injector
 *  v2.33.0 — Resilient sidebar with self-reinject and error recovery
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  SecuBox-Deb :: Sidebar Component
 *  CyberMind — https://cybermind.fr
 *  Author: Gerald Kerma <gandalf@gk2.net>
 *  License: Proprietary / ANSSI CSPN candidate
 *
 *  Features:
 *  - Automatic hybrid skin CSS injection (design-tokens, sidebar, hybrid-skin)
 *  - Health-aware LED indicators with batch endpoint
 *  - Version & dev_stage badges
 *  - CHECKED = hide unknown, UNCHECKED = show all
 *  - Resilient error handling with self-reinject mechanism
 *  - Graceful degradation on API failures
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function() {
    const MENU_API = '/api/v1/hub/public/menu';
    const BATCH_HEALTH_API = '/api/v1/hub/public/health-batch';
    const VERSION = 'v2.39.0';

    // Resilience settings
    const HEARTBEAT_INTERVAL = 15000;  // 15s - check sidebar health
    const MAX_RETRY_ATTEMPTS = 3;
    const RETRY_DELAY = 2000;  // 2s between retries
    const MENU_CACHE_KEY = 'sbx_menu_cache';
    const MENU_CACHE_TTL = 3600000;  // 1 hour menu cache
    let sidebarHealthy = true;
    let retryCount = 0;
    let heartbeatTimer = null;

    // Pre-cached menu for instant display during API warmup
    function loadCachedMenu() {
        try {
            var cached = localStorage.getItem(MENU_CACHE_KEY);
            if (cached) {
                // Safety check - if starts with < it's HTML not JSON
                if (cached.charAt(0) === '<') {
                    console.warn('[Sidebar] Cache corrupted (HTML), clearing');
                    localStorage.removeItem(MENU_CACHE_KEY);
                    return null;
                }
                var data = JSON.parse(cached);
                if (data.timestamp && (Date.now() - data.timestamp) < MENU_CACHE_TTL) {
                    console.log('[Sidebar] Using cached menu (age: ' + Math.round((Date.now() - data.timestamp)/1000) + 's)');
                    return data.menu;
                }
            }
        } catch (e) {
            console.warn('[Sidebar] Menu cache parse error, clearing:', e.message);
            localStorage.removeItem(MENU_CACHE_KEY);
        }
        return null;
    }

    function saveCachedMenu(menu) {
        try {
            localStorage.setItem(MENU_CACHE_KEY, JSON.stringify({
                timestamp: Date.now(),
                menu: menu
            }));
        } catch (e) {
            console.log('[Sidebar] Menu cache save error:', e);
        }
    }

    // ── Sidebar HTML pre-cache (v2.39.0) ────────────────────────
    // Previous versions saved the menu DATA in cache but only used
    // it as a FALLBACK when the API failed. Operators still saw a
    // "Loading…" placeholder for 200-2000ms on every page transition.
    // v2.39.0 caches the fully rendered sidebar HTML and paints it
    // immediately on load. The fresh API result then overwrites it
    // (LEDs etc. update from the actual /health-batch call). Net:
    // instant skeleton, no perceived delay.
    const SIDEBAR_HTML_CACHE_KEY = 'sbx_sidebar_html_v1';
    function saveCachedSidebarHTML(html) {
        try {
            localStorage.setItem(SIDEBAR_HTML_CACHE_KEY, JSON.stringify({
                ts: Date.now(),
                html: html,
            }));
        } catch (e) {
            // Quota exceeded etc. — silent: cache is best-effort.
        }
    }
    function loadCachedSidebarHTML() {
        try {
            var raw = localStorage.getItem(SIDEBAR_HTML_CACHE_KEY);
            if (!raw || raw.charAt(0) !== '{') return null;
            var data = JSON.parse(raw);
            if (!data.ts || (Date.now() - data.ts) > MENU_CACHE_TTL) return null;
            return data.html;
        } catch (e) {
            try { localStorage.removeItem(SIDEBAR_HTML_CACHE_KEY); } catch (_) {}
            return null;
        }
    }

    // Status bar metrics cache for instant display
    function loadStatusBarCache() {
        try {
            var cached = localStorage.getItem(STATUS_BAR_CACHE_KEY);
            if (cached) {
                if (cached.charAt(0) === '<') {
                    localStorage.removeItem(STATUS_BAR_CACHE_KEY);
                    return null;
                }
                var data = JSON.parse(cached);
                if (data.ts && (Date.now() - data.ts) < STATUS_BAR_CACHE_TTL) {
                    return data;
                }
            }
        } catch (e) {
            localStorage.removeItem(STATUS_BAR_CACHE_KEY);
        }
        return null;
    }

    function saveStatusBarCache(metrics) {
        try {
            localStorage.setItem(STATUS_BAR_CACHE_KEY, JSON.stringify({
                ts: Date.now(),
                ...metrics
            }));
        } catch (e) {}
    }

    // Apply cached status bar values instantly (before API fetch)
    function applyCachedStatusBar() {
        var cached = loadStatusBarCache();
        if (!cached) return false;

        console.log('[Sidebar] Applying cached status bar (age: ' + Math.round((Date.now() - cached.ts)/1000) + 's)');

        // Hardware LED
        var lmHw = document.getElementById('lm-hw');
        if (lmHw && cached.hwMax !== undefined) {
            lmHw.textContent = cached.hwMax + '%';
            lmHw.className = 'led-metric-val ' + (cached.hwMax > 80 ? 'error' : cached.hwMax > 50 ? 'warn' : 'ok');
            lmHw.title = cached.hwTooltip || ('Hardware: ' + cached.hwMax + '%');
        }

        // Services LED
        var lmSvc = document.getElementById('lm-svc');
        if (lmSvc && cached.svcOk !== undefined) {
            lmSvc.textContent = cached.svcOk + '/' + cached.svcTotal;
            lmSvc.className = 'led-metric-val ' + (cached.svcErr > 0 ? 'error' : cached.svcWarn > 0 ? 'warn' : 'ok');
            lmSvc.title = cached.svcTooltip || (cached.svcOk + ' services OK');
        }

        // Security LED
        var lmSec = document.getElementById('lm-sec');
        if (lmSec && cached.secTotal !== undefined) {
            lmSec.textContent = cached.secTotal + '🛡️';
            lmSec.title = cached.secTooltip || ('Security: ' + cached.secTotal + ' threats mitigated');
            var threatLevel = (cached.alerts || 0) + (cached.wafThreats || 0);
            if (cached.secTotal > 50) {
                lmSec.className = 'led-metric-val info';
            } else if (threatLevel > 100) {
                lmSec.className = 'led-metric-val error';
            } else if (threatLevel > 20) {
                lmSec.className = 'led-metric-val warn';
            } else {
                lmSec.className = 'led-metric-val ok';
            }
        }

        return true;
    }

    // Status bar notification - inline in menu bar + sidebar sync LED
    function showStatusBarNotification(text, type) {
        var icons = { progress: '🔄', live: '🔴', cached: '📦', error: '⚠️', info: '💾' };
        var icon = icons[type] || '⏳';

        // Update sidebar sync LED (left side)
        var syncLed = document.getElementById('sync-led');
        var lmSync = document.getElementById('lm-sync');
        if (syncLed && lmSync) {
            syncLed.className = 'sync-led ' + (type === 'progress' ? 'fetching' : type);
            syncLed.textContent = icon;
            lmSync.textContent = text.replace(/[^\w\s]/g, '').trim().substring(0, 8);
            lmSync.title = 'Sync: ' + text + (type === 'cached' ? ' (from localStorage)' : type === 'live' ? ' (fresh from API)' : '');
        }
    }

    function hideStatusBarNotification() {
        var syncLed = document.getElementById('sync-led');
        if (syncLed) {
            syncLed.className = 'sync-led';
            syncLed.textContent = '✓';
        }
    }

    // Page-specific metrics configuration
    const PAGE_METRICS_CONFIG = {
        '/crowdsec/': { metrics: ['bans', 'alerts', 'decisions'], api: '/api/v1/crowdsec/stats' },
        '/waf/': { metrics: ['blocked', 'threats', 'inspected'], api: '/api/v1/waf/stats' },
        '/wireguard/': { metrics: ['peers', 'tx', 'rx'], api: '/api/v1/wireguard/status' },
        '/netdata/': { metrics: ['cpu', 'mem', 'disk'], api: '/api/v1/hub/dashboard' },
        '/dpi/': { metrics: ['flows', 'protocols', 'hosts'], api: '/api/v1/dpi/stats' },
        '/nac/': { metrics: ['devices', 'blocked', 'quarantine'], api: '/api/v1/nac/stats' },
        '/qos/': { metrics: ['bandwidth', 'rules', 'shaped'], api: '/api/v1/qos/stats' },
        '/soc/': { metrics: ['bans', 'blocked', 'alerts'], api: null },  // Combined from multiple APIs
        '/hub/': { metrics: ['services', 'uptime', 'health'], api: '/api/v1/hub/dashboard' },
        '/system/': { metrics: ['cpu', 'mem', 'uptime'], api: '/api/v1/hub/dashboard' },
        '/certs/': { metrics: ['certs', 'expiring', 'domains'], api: '/api/v1/certs/stats' },
        '/metablogizer/': { metrics: ['sites', 'published', 'nginx'], api: '/api/v1/metablogizer/status' },
        '/vhost/': { metrics: ['vhosts', 'active', 'backends'], api: '/api/v1/vhost/stats' },
        '/eye-remote/': { metrics: ['connected', 'boot', 'serial'], api: '/api/v1/eye-remote/status' },
        '/metrics/': { metrics: ['cpu', 'mem', 'load'], api: '/api/v1/metrics/summary' },
        '/': { metrics: ['services', 'threats', 'health'], api: '/api/v1/hub/dashboard' }
    };

    const PAGE_METRIC_ICONS = {
        // Security
        bans: '🚫', alerts: '🔔', decisions: '⚖️', blocked: '🛡️', threats: '⚠️', inspected: '🔍',
        // Network
        peers: '👥', tx: '📤', rx: '📥', requests: '📨', flows: '🌊', protocols: '📋',
        // System
        cpu: '💻', mem: '🧠', disk: '💾', net: '📡', load: '📊', uptime: '⏱️', temp: '🌡️',
        // Devices
        hosts: '🖥️', devices: '📱', quarantine: '🔒', connected: '🔌',
        // QoS
        bandwidth: '📶', rules: '📜', shaped: '🎚️',
        // Services
        services: '⚙️', health: '💚', active: '✅', backends: '🔄',
        // Certs
        certs: '📜', expiring: '⏰', domains: '🌐',
        // Metablogizer
        sites: '🌍', published: '📢', nginx: '🔧',
        // Eye Remote
        boot: '🚀', serial: '📟'
    };

    // Page metrics cache
    const PAGE_METRICS_CACHE_KEY = 'sbx_page_metrics_cache';
    const PAGE_METRICS_CACHE_TTL = 30000;  // 30 seconds

    function loadPageMetricsCache(path) {
        try {
            var cached = localStorage.getItem(PAGE_METRICS_CACHE_KEY);
            if (cached) {
                var data = JSON.parse(cached);
                if (data[path] && (Date.now() - data[path].ts) < PAGE_METRICS_CACHE_TTL) {
                    return data[path].metrics;
                }
            }
        } catch (e) {}
        return null;
    }

    function savePageMetricsCache(path, metrics) {
        try {
            var cached = {};
            try { cached = JSON.parse(localStorage.getItem(PAGE_METRICS_CACHE_KEY) || '{}'); } catch (e) {}
            cached[path] = { ts: Date.now(), metrics: metrics };
            localStorage.setItem(PAGE_METRICS_CACHE_KEY, JSON.stringify(cached));
        } catch (e) {}
    }

    async function loadPageMetrics(forceRefresh) {
        var pagePath = window.location.pathname;
        var container = document.getElementById('gmb-page-metrics');
        if (!container) return;

        // Find matching config
        var config = null;
        var matchedPath = null;
        for (var path in PAGE_METRICS_CONFIG) {
            if (pagePath === path || pagePath.startsWith(path)) {
                config = PAGE_METRICS_CONFIG[path];
                matchedPath = path;
                break;
            }
        }

        if (!config) {
            container.innerHTML = '';
            return;
        }

        // Check cache first (unless forced refresh)
        if (!forceRefresh) {
            var cachedMetrics = loadPageMetricsCache(matchedPath);
            if (cachedMetrics) {
                renderPageMetrics(container, config.metrics, cachedMetrics, true);
                // Refresh in background after 100ms
                setTimeout(function() { loadPageMetrics(true); }, 100);
                return;
            }
        }

        // Show placeholders while loading
        container.innerHTML = config.metrics.map(function(m) {
            return '<span class="page-metric loading" title="' + m + '"><span class="pm-icon">' + (PAGE_METRIC_ICONS[m] || '📊') + '</span><span class="pm-val">--</span></span>';
        }).join('');

        // Fetch data based on page
        var token = localStorage.getItem('sbx_token');
        var headers = token ? { 'Authorization': 'Bearer ' + token } : {};
        var metricsData = {};

        try {
            if (pagePath.startsWith('/soc/') || pagePath === '/' || pagePath === '/hub/') {
                // SOC/Hub page: combine CrowdSec + WAF stats
                var [csRes, wafRes, dashRes] = await Promise.all([
                    safeFetch('/api/v1/crowdsec/stats', { headers: headers }, 3000),
                    safeFetch('/api/v1/waf/stats', { headers: headers }, 3000),
                    safeFetch('/api/v1/hub/dashboard', { headers: headers }, 3000)
                ]);
                if (csRes.ok) {
                    metricsData.bans = csRes.data.active_bans || csRes.data.decisions || 0;
                    metricsData.alerts = csRes.data.alerts_today || 0;
                    metricsData.decisions = csRes.data.total_decisions || metricsData.bans;
                }
                if (wafRes.ok) {
                    metricsData.blocked = wafRes.data.blocked_24h || wafRes.data.blocked || 0;
                    metricsData.threats = (metricsData.bans || 0) + (metricsData.blocked || 0);
                    metricsData.inspected = wafRes.data.inspected_24h || wafRes.data.requests || 0;
                }
                if (dashRes.ok && dashRes.data) {
                    var d = dashRes.data;
                    metricsData.cpu = d.cpu_percent || d.cpu || 0;
                    metricsData.mem = d.memory_percent || d.mem || 0;
                    metricsData.disk = d.disk_percent || d.disk || 0;
                    metricsData.uptime = d.uptime || '--';
                    if (d.modules) {
                        metricsData.services = Object.keys(d.modules).length;
                        var okCount = Object.values(d.modules).filter(function(mod) { return mod.status === 'ok'; }).length;
                        metricsData.health = okCount + '/' + metricsData.services;
                    }
                }
            } else if (config.api) {
                var res = await safeFetch(config.api, { headers: headers }, 3000);
                if (res.ok && res.data) {
                    var d = res.data;
                    // Map API response to metric names with multiple fallbacks
                    config.metrics.forEach(function(m) {
                        if (d[m] !== undefined) metricsData[m] = d[m];
                        else if (d[m + '_count'] !== undefined) metricsData[m] = d[m + '_count'];
                        else if (d[m + '_24h'] !== undefined) metricsData[m] = d[m + '_24h'];
                        else if (d['active_' + m] !== undefined) metricsData[m] = d['active_' + m];
                        else if (d['total_' + m] !== undefined) metricsData[m] = d['total_' + m];
                        else if (d[m + '_percent'] !== undefined) metricsData[m] = d[m + '_percent'] + '%';
                        // Special cases
                        else if (m === 'services' && d.modules) metricsData[m] = Object.keys(d.modules).length;
                        else if (m === 'health' && d.modules) {
                            var okCount = Object.values(d.modules).filter(function(mod) { return mod.status === 'ok'; }).length;
                            metricsData[m] = okCount + '/' + Object.keys(d.modules).length;
                        }
                        else if (m === 'sites' && d.site_count !== undefined) metricsData[m] = d.site_count;
                        else if (m === 'published' && d.published_count !== undefined) metricsData[m] = d.published_count;
                        else if (m === 'nginx' && d.running !== undefined) metricsData[m] = d.running ? '✓' : '✗';
                        else if (m === 'peers' && d.peer_count !== undefined) metricsData[m] = d.peer_count;
                        else if (m === 'certs' && d.total !== undefined) metricsData[m] = d.total;
                        else if (m === 'expiring' && d.expiring_soon !== undefined) metricsData[m] = d.expiring_soon;
                    });
                }
            }
        } catch (e) {
            console.log('[Sidebar] Page metrics error:', e);
        }

        // Save to cache and render
        savePageMetricsCache(matchedPath, metricsData);
        renderPageMetrics(container, config.metrics, metricsData, false);
    }

    function renderPageMetrics(container, metrics, data, fromCache) {
        container.innerHTML = metrics.map(function(m) {
            var val = data[m] !== undefined ? data[m] : '--';
            var cls = 'page-metric';
            // Highlight security metrics
            if (typeof val === 'number' && val > 0) {
                if (m === 'bans' || m === 'blocked' || m === 'alerts' || m === 'threats' || m === 'quarantine' || m === 'expiring') {
                    cls += val > 10 ? ' alert' : ' highlight';
                }
            }
            // Format large numbers
            if (typeof val === 'number' && val > 999) {
                val = (val / 1000).toFixed(1) + 'k';
            }
            var cacheIndicator = fromCache ? ' 📦' : '';
            return '<span class="' + cls + '" title="' + m + ': ' + val + cacheIndicator + '"><span class="pm-icon">' + (PAGE_METRIC_ICONS[m] || '📊') + '</span><span class="pm-val">' + val + '</span></span>';
        }).join('');
    }

    // API status checker
    var lastApiStatus = 'unknown';
    var apiLatency = 0;

    async function checkApiStatus() {
        var btn = document.getElementById('api-status-btn');
        var icon = document.getElementById('api-status-icon');
        if (!btn || !icon) return;

        btn.className = 'menu-btn api-status checking';
        btn.title = 'API Status: checking...';
        icon.textContent = '🔌';

        var token = localStorage.getItem('sbx_token');
        var headers = token ? { 'Authorization': 'Bearer ' + token } : {};

        try {
            var startTime = Date.now();
            var result = await safeFetch('/api/v1/hub/health', { headers: headers }, 5000);
            apiLatency = Date.now() - startTime;

            if (result.ok) {
                lastApiStatus = 'connected';
                btn.className = 'menu-btn api-status connected';
                btn.title = 'API Connected (' + apiLatency + 'ms)\nClick to check again';
                icon.textContent = '✅';
            } else {
                lastApiStatus = 'error';
                btn.className = 'menu-btn api-status disconnected';
                btn.title = 'API Error: ' + (result.error || 'Unknown') + '\nClick to retry';
                icon.textContent = '⚠️';
            }
        } catch (e) {
            lastApiStatus = 'disconnected';
            btn.className = 'menu-btn api-status disconnected';
            btn.title = 'API Disconnected: ' + e.message + '\nClick to retry';
            icon.textContent = '❌';
        }

        return { status: lastApiStatus, latency: apiLatency };
    }

    // Round UI Module Colors (6-module system)
    const MODULE_COLORS = {
        AUTH: { color: '#C04E24', metric: 'cpu', label: 'CPU' },
        WALL: { color: '#9A6010', metric: 'mem', label: 'MEM' },
        BOOT: { color: '#803018', metric: 'disk', label: 'DISK' },
        MIND: { color: '#3D35A0', metric: 'load', label: 'LOAD' },
        ROOT: { color: '#0A5840', metric: 'temp', label: 'TEMP' },
        MESH: { color: '#104A88', metric: 'net', label: 'NET' }
    };
    // Theme system removed - hybrid-skin is the universal theme
    const HEALTH_CACHE_KEY = 'sbx_health_cache';
    const STATUS_BAR_CACHE_KEY = 'sbx_statusbar_cache';
    const SORT_PREF_KEY = 'sbx_health_sort';

    const HEALTH_CACHE_TTL = 300000;       // 5 min - cache validity
    const STATUS_BAR_CACHE_TTL = 60000;    // 1 min - status bar cache
    const HEALTH_REFRESH_INTERVAL = 30000; // 30s - update interval
    const HEALTH_REQUEST_TIMEOUT = 4000;
    const BATCH_SIZE = 8;

    // Hybrid skin CSS files (injected automatically)
    const HYBRID_SKIN_CSS = [
        '/shared/design-tokens.css',
        '/shared/sidebar.css',
        '/shared/hybrid-skin.css'
    ];

    let ALL_MODULES = [];

    const LED_EMOJI = { ok: '🟢', warn: '🟡', error: '🔴', unknown: '⚫', checking: '🔵' };
    // Dice icons for metric visualization (⚀=1 to ⚅=6)
    // Eyemote metric icons based on level (low to high)
    function getMetricIcon(pct, type) {
        // Eyemote icons based on metric type and level
        const icons = {
            cpu: ['🟢', '🟡', '🟠', '🔴', '🔥', '💀'],
            mem: ['🟢', '🟡', '🟠', '🔴', '🧠', '💥'],
            disk: ['🟢', '🟡', '🟠', '🔴', '💾', '⚠️'],
            load: ['🟢', '🟡', '🟠', '🔴', '📈', '💣'],
            temp: ['❄️', '🟢', '🟡', '🟠', '🔴', '🔥'],
            net: ['📡', '🟢', '🟡', '🟠', '🔴', '📵']
        };
        const levels = icons[type] || ['⚪', '🟢', '🟡', '🟠', '🔴', '💀'];
        if (pct < 17) return levels[0];
        if (pct < 33) return levels[1];
        if (pct < 50) return levels[2];
        if (pct < 67) return levels[3];
        if (pct < 83) return levels[4];
        return levels[5];
    }

    // Page icons for menu bar
    const PAGE_ICONS = {
        '/': '🏠', '/hub/': '🏠', '/soc/': '🛡️', '/waf/': '🔥', '/crowdsec/': '👁️',
        '/wireguard/': '🔐', '/netdata/': '📊', '/system/': '⚙️', '/vhost/': '🌐',
        '/dpi/': '🔍', '/netmodes/': '🔀', '/qos/': '📶', '/nac/': '🚫',
        '/auth/': '🔑', '/cdn/': '💾', '/mediaflow/': '🎬', '/portal/': '🚪',
        '/metrics/': '📈', '/certs/': '📜', '/vortex-dns/': '🌀', '/eye-remote/': '👁️',
        '/sentinelle/': '📡', '/lyrion/': '🎵', '/grafana/': '📈',
        '/zigbee/': '🐝', '/yacy/': '🔍', '/rustdesk/': '🖥️', '/mqtt/': '📡'
    };

    // window._menuDataCache is populated by buildMenu() after the
    // /api/v1/hub/public/menu fetch — every menu item carries its own
    // emoji icon already (the menu.d entries). Reading from there
    // saves the parallel hardcoded PAGE_ICONS table from going stale.
    function getPageIcon(path) {
        // 1) Pinned hardcoded paths (loaded before menu fetch settles).
        for (var p in PAGE_ICONS) {
            if (path === p || path.startsWith(p)) return PAGE_ICONS[p];
        }
        // 2) Fallback to live menu data — every module ships its own
        // icon, so this catches everything PAGE_ICONS doesn't list.
        try {
            var data = window._menuDataCache;
            if (data && Array.isArray(data.categories)) {
                for (var i = 0; i < data.categories.length; i++) {
                    var items = data.categories[i].items || [];
                    for (var j = 0; j < items.length; j++) {
                        var it = items[j];
                        if (!it.path || !it.icon) continue;
                        if (path === it.path || path.startsWith(it.path)) {
                            return it.icon;
                        }
                    }
                }
            }
        } catch (_) { /* ignore */ }
        return '📦';
    }

    // ============================================
    // HYBRID SKIN INJECTION (Centralized)
    // ============================================

    function injectHybridSkin() {
        // Skip if already injected
        if (document.getElementById('secubox-hybrid-skin-injected')) return;

        // Create marker
        var marker = document.createElement('meta');
        marker.id = 'secubox-hybrid-skin-injected';
        marker.name = 'secubox-skin';
        marker.content = 'hybrid';
        document.head.appendChild(marker);

        // 1. Inject hybrid skin CSS files (append to end for priority)
        HYBRID_SKIN_CSS.forEach(function(cssPath) {
            if (document.querySelector('link[href="' + cssPath + '"]')) return;
            var link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = cssPath;
            document.head.appendChild(link);
        });

        // 2. Add hybrid-skin class to body (CSS uses !important to override)
        document.body.classList.add('hybrid-skin');

        // 3. Add hybrid-main to main content
        var main = document.querySelector('.main, .main-content, main');
        if (main) main.classList.add('hybrid-main');

        // 4. Force dark background via inline style (highest priority)
        document.body.style.setProperty('background', 'var(--bg-deep, #050810)', 'important');
        document.body.style.setProperty('background-image',
            'radial-gradient(ellipse at 30% 20%, rgba(20,140,102,0.05) 0%, transparent 50%), ' +
            'radial-gradient(ellipse at 70% 80%, rgba(44,112,192,0.03) 0%, transparent 50%)', 'important');

        // 5. Force sidebar glass morphism via inline style
        var sidebar = document.getElementById('sidebar') || document.querySelector('.sidebar');
        if (sidebar) {
            sidebar.style.setProperty('background', 'rgba(17, 23, 32, 0.85)', 'important');
            sidebar.style.setProperty('backdrop-filter', 'blur(20px)', 'important');
            sidebar.style.setProperty('-webkit-backdrop-filter', 'blur(20px)', 'important');
            sidebar.style.setProperty('border-right', '1px solid rgba(255, 255, 255, 0.08)', 'important');
            sidebar.style.setProperty('box-shadow', '2px 0 20px rgba(0,0,0,0.3)', 'important');
        }

        // 5b. Force dark backgrounds on sidebar header and footer
        setTimeout(function() {
            var sidebarHeader = document.querySelector('.sidebar-header');
            var sidebarFooter = document.querySelector('.sidebar-footer');
            if (sidebarHeader) {
                sidebarHeader.style.setProperty('background', 'transparent', 'important');
                sidebarHeader.style.setProperty('background-color', 'transparent', 'important');
            }
            if (sidebarFooter) {
                sidebarFooter.style.setProperty('background', 'transparent', 'important');
                sidebarFooter.style.setProperty('background-color', 'transparent', 'important');
            }
        }, 100);

        // 5c. Inject global TOP menu bar (replaces page headers)
        if (!document.getElementById('global-menu-bar')) {
            var pageTitle = document.title.replace(' - SecuBox', '').replace('SecuBox ', '') || 'Dashboard';
            var pagePath = window.location.pathname;
            var pageIcon = getPageIcon(pagePath);

            var menuBar = document.createElement('div');
            menuBar.id = 'global-menu-bar';
            menuBar.className = 'global-menu-bar';
            menuBar.innerHTML = '<div class="menu-left">' +
                '<span class="menu-icon">' + pageIcon + '</span>' +
                '<span class="menu-title" id="gmb-title">' + pageTitle + '</span>' +
                // Health Bumper with sync emojis
                '<div class="health-bumper" id="gmb-health-bumper" onclick="SecuBoxSidebar.showStatusPanel()" title="System Health">' +
                '<span class="hb-led" id="hb-led">●</span>' +
                '<span class="hb-status" id="hb-status">NOMINAL</span>' +
                '</div>' +
                // Smart Strip (6 mini modules) - moved to top bar with hover tooltips
                '<div class="smart-strip" id="gmb-smart-strip">' +
                '<div class="strip-module" data-mod="AUTH" data-metric="cpu" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><span class="strip-icon" id="ss-icon-cpu" style="font-size:0.9rem;">🎯</span><span class="strip-val" id="ss-cpu">--</span></div>' +
                '<div class="strip-module" data-mod="WALL" data-metric="mem" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><span class="strip-icon" id="ss-icon-mem" style="font-size:0.9rem;">🔥</span><span class="strip-val" id="ss-mem">--</span></div>' +
                '<div class="strip-module" data-mod="BOOT" data-metric="disk" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><span class="strip-icon" id="ss-icon-disk" style="font-size:0.9rem;">🚀</span><span class="strip-val" id="ss-disk">--</span></div>' +
                '<div class="strip-module" data-mod="MIND" data-metric="load" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><span class="strip-icon" id="ss-icon-load" style="font-size:0.9rem;">🤖</span><span class="strip-val" id="ss-load">--</span></div>' +
                '<div class="strip-module" data-mod="ROOT" data-metric="temp" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><span class="strip-icon" id="ss-icon-temp" style="font-size:0.9rem;">💻</span><span class="strip-val" id="ss-temp">--</span></div>' +
                '<div class="strip-module" data-mod="MESH" data-metric="net" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><span class="strip-icon" id="ss-icon-net" style="font-size:0.9rem;">⚙️</span><span class="strip-val" id="ss-net">--</span></div>' +
                '</div>' +
                // Popup container for hover details
                '<div class="strip-popup" id="strip-popup"></div>' +
                // Page-specific context metrics (dynamic based on current module)
                '<div class="page-metrics" id="gmb-page-metrics"></div>' +
                '</div><div class="menu-right">' +
                '<div class="hw-led-tooltip" id="hw-led-tooltip"></div>' +
                '<button class="menu-btn api-status" id="api-status-btn" onclick="SecuBoxSidebar.checkApiStatus()" title="API Status: checking..."><span id="api-status-icon">🔌</span></button>' +
                '<button class="menu-btn" onclick="location.reload()" title="Refresh">🔄</button>' +
                '<button class="menu-btn" onclick="location.href=\'/system/\'" title="Settings">⚙️</button>' +
                '<button class="menu-btn danger" onclick="SecuBoxSidebar.logout()" title="Logout">🚪</button>' +
                '</div>';
            document.body.insertBefore(menuBar, document.body.firstChild);

            // Hide original page headers
            setTimeout(function() {
                document.querySelectorAll('.page-header, .header, header:not(.global-menu-bar)').forEach(function(h) {
                    if (!h.classList.contains('global-menu-bar') && !h.closest('.global-menu-bar')) {
                        h.style.display = 'none';
                    }
                });
            }, 50);

            // Initialize page metrics and API status
            setTimeout(function() {
                loadPageMetrics();
                checkApiStatus();
                // Refresh page metrics every 30s
                setInterval(function() { loadPageMetrics(true); }, 30000);
                // Refresh API status every 60s
                setInterval(checkApiStatus, 60000);
            }, 100);
        }

        // 5d. Inject global BOTTOM status bar with health + Smart Strip
        if (!document.getElementById('global-status-bar')) {
            var statusBar = document.createElement('div');
            statusBar.id = 'global-status-bar';
            statusBar.className = 'global-status-bar';
            statusBar.innerHTML = '<div class="status-left">' +
                // Main health LED with tri-level pulsing
                '<div class="status-item health-led-container" onclick="SecuBoxSidebar.showStatusPanel()" title="Click for details">' +
                '<div class="health-led-main" id="gsb-led-main"></div>' +
                '<span class="status-value" id="gsb-health">--</span></div>' +
                '<div class="status-item"><span class="status-label">Mode</span><span class="status-value info" id="gsb-mode">--</span></div>' +
                '<div class="status-item"><span class="status-label">Auth</span><span class="status-value" id="gsb-auth">--</span></div>' +
                '</div><div class="status-right">' +
                '<div class="status-item metric-bar"><span class="status-label">CPU</span><div class="bar-container"><div class="bar-fill" id="gsb-cpu-bar"></div></div><span class="status-value" id="gsb-cpu">--%</span></div>' +
                '<div class="status-item metric-bar"><span class="status-label">MEM</span><div class="bar-container"><div class="bar-fill" id="gsb-mem-bar"></div></div><span class="status-value" id="gsb-mem">--%</span></div>' +
                '<div class="status-item metric-bar"><span class="status-label">DISK</span><div class="bar-container"><div class="bar-fill" id="gsb-disk-bar"></div></div><span class="status-value" id="gsb-disk">--%</span></div>' +
                '<div class="status-item"><span class="status-label">Uptime</span><span class="status-value" id="gsb-uptime">--</span></div>' +
                '<div class="status-item"><span class="status-value" style="color: var(--muted-dark);">CyberMind</span></div>' +
                '</div>';
            document.body.appendChild(statusBar);
            // Apply cached status bar values FIRST (instant display)
            var hadCache = applyCachedStatusBar();
            if (hadCache) showStatusBarNotification('📦 cached', 'info');
            // Then fetch fresh data (async update)
            loadStatusBarData();
            // Start LED pulse sync
            startLedPulseSync();
            // Start hardware LED status refresh (reads actual sysfs colors)
            startLedStatusRefresh();
        }

        // 6. Force dark on ALL light backgrounds in main content
        function forceDarkTheme() {
            document.querySelectorAll('.main, .main *, .content, .content *, main, main *, .main-content, .main-content *').forEach(function(el) {
                var style = window.getComputedStyle(el);
                var bg = style.backgroundColor;
                // If background is light (RGB > 150), force dark
                if (bg && bg !== 'transparent' && bg !== 'rgba(0, 0, 0, 0)') {
                    var match = bg.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
                    if (match) {
                        var r = parseInt(match[1]), g = parseInt(match[2]), b = parseInt(match[3]);
                        // Light background detection (average > 150)
                        if ((r + g + b) / 3 > 150) {
                            el.style.setProperty('background', 'rgba(17, 23, 32, 0.5)', 'important');
                            el.style.setProperty('background-color', 'rgba(17, 23, 32, 0.5)', 'important');
                        }
                    }
                }
                // Force text color on all elements
                var color = style.color;
                if (color) {
                    var colorMatch = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
                    if (colorMatch) {
                        var cr = parseInt(colorMatch[1]), cg = parseInt(colorMatch[2]), cb = parseInt(colorMatch[3]);
                        // Dark text on dark bg = bad, lighten it
                        if ((cr + cg + cb) / 3 < 100) {
                            el.style.setProperty('color', 'rgba(232, 230, 217, 0.85)', 'important');
                        }
                    }
                }
            });
        }

        // Run immediately and after short delay (for dynamic content)
        forceDarkTheme();
        setTimeout(forceDarkTheme, 200);
        setTimeout(forceDarkTheme, 500);

        console.log('[Sidebar ' + VERSION + '] Hybrid skin applied');
    }

    // LED Pulse Sync - synchronized pulsing across all health indicators
    let ledPulsePhase = 0;
    let systemHealthLevel = 'ok'; // 'ok', 'warn', 'error'

    // LED Double-buffer state (confirm writes before visual update)
    let ledBufferActive = { led1: '#00dd44', led2: '#00dd44', led3: '#00dd44' };
    let ledBufferShadow = { led1: '#00dd44', led2: '#00dd44', led3: '#00dd44' };
    let ledBufferConfirmed = true;

    // Real hardware LED colors from API (fetched from sysfs)
    let ledColorsFromHardware = null;  // { led1: '#rrggbb', led2: '#rrggbb', led3: '#rrggbb' }
    let ledFetchInProgress = false;

    // Fetch real LED status from hardware via API
    async function fetchHardwareLedStatus() {
        if (ledFetchInProgress) return;
        ledFetchInProgress = true;
        try {
            var result = await safeFetch('/api/v1/hub/public/led_status', {}, 3000);
            if (result.ok && result.data) {
                ledColorsFromHardware = {
                    led1: result.data.led1 || '#00dd44',
                    led2: result.data.led2 || '#00dd44',
                    led3: result.data.led3 || '#00dd44'
                };
            }
        } catch (e) {
            console.log('[Sidebar] LED status fetch error:', e);
        }
        ledFetchInProgress = false;
    }

    // Start periodic LED status refresh (every 5 seconds)
    function startLedStatusRefresh() {
        fetchHardwareLedStatus();  // Initial fetch
        setInterval(fetchHardwareLedStatus, 5000);  // Refresh every 5s
    }

    // Metrics history for sparkline histograms with localStorage persistence
    const STRIP_HISTORY_MAX = 60;  // 60 samples = ~30 min at 30s refresh
    const STRIP_CACHE_KEY = 'sbx_strip_history';
    const STRIP_CACHE_TTL = 3600000;  // 1 hour max age

    // Load cached history from localStorage
    function loadStripHistoryCache() {
        try {
            var cached = localStorage.getItem(STRIP_CACHE_KEY);
            if (cached) {
                if (cached.charAt(0) !== '{') {
                    localStorage.removeItem(STRIP_CACHE_KEY);
                    return {};
                }
                var data = JSON.parse(cached);
                // Check if cache is still valid
                if (data.timestamp && (Date.now() - data.timestamp) < STRIP_CACHE_TTL) {
                    return data.history || {};
                }
            }
        } catch (e) {
            console.log('[Sidebar] Strip history cache load error:', e);
        }
        return { cpu: [], mem: [], disk: [], load: [], temp: [], net: [] };
    }

    // Save history to localStorage
    function saveStripHistoryCache(history) {
        try {
            localStorage.setItem(STRIP_CACHE_KEY, JSON.stringify({
                timestamp: Date.now(),
                history: history
            }));
        } catch (e) {
            console.log('[Sidebar] Strip history cache save error:', e);
        }
    }

    let stripMetricsHistory = loadStripHistoryCache();
    let currentStripMetrics = {
        cpu: 0, mem: 0, disk: 0, load: 0, temp: 0, net: 0
    };

    // Module metadata for popup with official SecuBox emoji icons and colors
    const STRIP_MODULE_INFO = {
        AUTH: { color: '#C04E24', emoji: '🎯', metric: 'cpu', label: 'CPU Usage', unit: '%', desc: 'Authentication module - Processor utilization' },
        WALL: { color: '#9A6010', emoji: '🔥', metric: 'mem', label: 'Memory', unit: '%', desc: 'Firewall module - RAM utilization' },
        BOOT: { color: '#803018', emoji: '🚀', metric: 'disk', label: 'Disk', unit: '%', desc: 'Boot module - Storage utilization' },
        MIND: { color: '#3D35A0', emoji: '🤖', metric: 'load', label: 'Load', unit: 'x', desc: 'AI module - System load average' },
        ROOT: { color: '#0A5840', emoji: '💻', metric: 'temp', label: 'Temp', unit: '°C', desc: 'Core module - CPU temperature' },
        MESH: { color: '#104A88', emoji: '⚙️', metric: 'net', label: 'Signal', unit: 'dB', desc: 'Network module - WiFi signal strength' }
    };

    function showStripPopup(el) {
        var popup = document.getElementById('strip-popup');
        if (!popup) return;

        var mod = el.dataset.mod;
        var metric = el.dataset.metric;
        var info = STRIP_MODULE_INFO[mod];
        if (!info) return;

        var value = currentStripMetrics[metric] || 0;
        var history = stripMetricsHistory[metric] || [];

        // Build sparkline HTML
        var sparkline = history.map(function(v) {
            var pct = metric === 'load' ? Math.min(100, v * 25) :
                      metric === 'temp' ? Math.min(100, Math.max(0, (v - 30) * 2)) :
                      metric === 'net' ? Math.min(100, Math.max(0, 100 + v)) : v;
            var h = Math.max(2, (pct / 100) * 24);
            var c = pct > 80 ? 'error' : pct > 50 ? 'warn' : 'ok';
            return '<div class="spark-bar ' + c + '" style="height:' + h + 'px;background:' + info.color + '"></div>';
        }).join('');

        // Format value
        var displayVal = metric === 'load' ? value.toFixed(2) : Math.round(value);
        var statusClass = metric === 'load' ? (value > 4 ? 'error' : value > 2 ? 'warn' : 'ok') :
                          metric === 'temp' ? (value > 70 ? 'error' : value > 55 ? 'warn' : 'ok') :
                          metric === 'net' ? (value < -70 ? 'error' : value < -60 ? 'warn' : 'ok') :
                          (value > 80 ? 'error' : value > 50 ? 'warn' : 'ok');

        popup.innerHTML = '<div class="popup-header" style="border-color:' + info.color + '">' +
            '<span class="popup-emoji" style="font-size:1.4rem;margin-right:8px;filter:drop-shadow(0 0 4px ' + info.color + ');">' + info.emoji + '</span>' +
            '<span class="popup-mod" style="color:' + info.color + '">' + mod + '</span>' +
            '<span class="popup-label">' + info.label + '</span>' +
            '</div>' +
            '<div class="popup-value ' + statusClass + '">' + displayVal + '<span class="popup-unit">' + info.unit + '</span></div>' +
            '<div class="popup-sparkline">' + sparkline + '</div>' +
            '<div class="popup-desc">' + info.desc + '</div>';

        // On mobile, CSS handles positioning (bottom sheet style)
        if (window.innerWidth <= 768) {
            popup.style.left = '';
            popup.style.top = '';
            popup.style.display = 'block';
            return;
        }

        // Desktop: Position popup below the element, centered
        var rect = el.getBoundingClientRect();
        var popupWidth = 180;  // Match CSS min-width
        var popupLeft = rect.left + (rect.width / 2) - (popupWidth / 2);

        // Ensure popup doesn't overflow right edge
        var maxLeft = window.innerWidth - popupWidth - 20;
        if (popupLeft > maxLeft) popupLeft = maxLeft;

        // Ensure popup doesn't overflow left edge (past sidebar 220px)
        var minLeft = 230;
        if (popupLeft < minLeft) popupLeft = minLeft;

        popup.style.left = popupLeft + 'px';
        popup.style.top = (rect.bottom + 10) + 'px';
        popup.style.display = 'block';
    }

    function hideStripPopup() {
        var popup = document.getElementById('strip-popup');
        if (popup) popup.style.display = 'none';
    }

    // Hardware LED tooltip - shows detailed health info with multi-layer histogram
    // layer: 1=Hardware, 2=Services, 3=Security
    function showHwLedTooltip(el, layer) {
        var tooltip = document.getElementById('hw-led-tooltip');
        if (!tooltip) return;

        var healthLabels = { ok: 'NOMINAL', warn: 'WARNING', error: 'CRITICAL' };
        var healthColors = { ok: '#00dd44', warn: '#ffb347', error: '#ff4466', info: '#4488ff' };

        // Calculate stats from history (top/max/medium)
        function getStats(arr) {
            if (!arr || arr.length === 0) return { cur: 0, max: 0, avg: 0 };
            var cur = arr[arr.length - 1] || 0;
            var max = Math.max.apply(null, arr);
            var sum = arr.reduce(function(a, b) { return a + b; }, 0);
            var avg = Math.round(sum / arr.length);
            return { cur: cur, max: max, avg: avg };
        }

        // Multi-layer histogram bars (top=max, medium=avg, bottom=current)
        function makeHistoBar(stats, color) {
            var maxPct = Math.min(100, stats.max);
            var avgPct = Math.min(100, stats.avg);
            var curPct = Math.min(100, stats.cur);
            return '<div class="histo-bar">' +
                '<div class="histo-layer histo-max" style="width:' + maxPct + '%;background:' + color + ';opacity:0.3"></div>' +
                '<div class="histo-layer histo-avg" style="width:' + avgPct + '%;background:' + color + ';opacity:0.5"></div>' +
                '<div class="histo-layer histo-cur" style="width:' + curPct + '%;background:' + color + '"></div>' +
                '</div>';
        }

        var content = '';
        var layerTitles = { 1: 'HARDWARE', 2: 'SERVICES', 3: 'SECURITY' };
        var layerIcons = { 1: '⚙️', 2: '🔧', 3: '🛡️' };

        if (layer === 1) {
            // Hardware layer - CPU, MEM, DISK, LOAD
            var cpuStats = getStats(stripMetricsHistory.cpu);
            var memStats = getStats(stripMetricsHistory.mem);
            var diskStats = getStats(stripMetricsHistory.disk);
            var loadStats = getStats(stripMetricsHistory.load);
            var hwMax = Math.max(cpuStats.cur, memStats.cur);
            var hwLevel = hwMax > 80 ? 'error' : hwMax > 50 ? 'warn' : 'ok';

            content = '<div class="hw-tooltip-header" style="color:' + healthColors[hwLevel] + '">' +
                '<span class="hw-tooltip-icon">' + layerIcons[1] + '</span> ' + layerTitles[1] + ' — ' + healthLabels[hwLevel] +
                '</div>' +
                '<div class="hw-tooltip-metrics">' +
                '<div class="hw-metric-row"><span class="hw-metric-label">CPU</span>' + makeHistoBar(cpuStats, '#C04E24') + '<span class="hw-metric-vals">' + cpuStats.cur + '% / ' + cpuStats.max + '%</span></div>' +
                '<div class="hw-metric-row"><span class="hw-metric-label">MEM</span>' + makeHistoBar(memStats, '#9A6010') + '<span class="hw-metric-vals">' + memStats.cur + '% / ' + memStats.max + '%</span></div>' +
                '<div class="hw-metric-row"><span class="hw-metric-label">DISK</span>' + makeHistoBar(diskStats, '#803018') + '<span class="hw-metric-vals">' + diskStats.cur + '% / ' + diskStats.max + '%</span></div>' +
                '<div class="hw-metric-row"><span class="hw-metric-label">LOAD</span>' + makeHistoBar({cur: loadStats.cur * 25, max: loadStats.max * 25, avg: loadStats.avg * 25}, '#3D35A0') + '<span class="hw-metric-vals">' + (loadStats.cur).toFixed(1) + ' / ' + (loadStats.max).toFixed(1) + '</span></div>' +
                '</div>' +
                '<div class="hw-tooltip-legend"><span>■ Current</span><span style="opacity:0.5">■ Average</span><span style="opacity:0.3">■ Max</span></div>';

        } else if (layer === 2) {
            // Services layer - count ok/warn/error/total
            var counts = { ok: 0, warn: 0, error: 0, unknown: 0 };
            Object.keys(healthCache).forEach(function(mod) {
                var st = healthCache[mod] && healthCache[mod].status;
                if (st === 'ok') counts.ok++;
                else if (st === 'warn') counts.warn++;
                else if (st === 'error') counts.error++;
                else counts.unknown++;
            });
            var total = counts.ok + counts.warn + counts.error + counts.unknown;
            var svcLevel = counts.error > 0 ? 'error' : counts.warn > 0 ? 'warn' : 'ok';

            content = '<div class="hw-tooltip-header" style="color:' + healthColors[svcLevel] + '">' +
                '<span class="hw-tooltip-icon">' + layerIcons[2] + '</span> ' + layerTitles[2] + ' — ' + healthLabels[svcLevel] +
                '</div>' +
                '<div class="hw-tooltip-metrics svc-metrics">' +
                '<div class="svc-stat"><span class="svc-count" style="color:#00dd44">' + counts.ok + '</span><span class="svc-label">OK</span></div>' +
                '<div class="svc-stat"><span class="svc-count" style="color:#ffb347">' + counts.warn + '</span><span class="svc-label">WARN</span></div>' +
                '<div class="svc-stat"><span class="svc-count" style="color:#ff4466">' + counts.error + '</span><span class="svc-label">ERROR</span></div>' +
                '<div class="svc-stat"><span class="svc-count" style="color:#666">' + counts.unknown + '</span><span class="svc-label">UNKNOWN</span></div>' +
                '</div>' +
                '<div class="hw-tooltip-footer">' + counts.ok + ' / ' + total + ' services healthy</div>';

        } else if (layer === 3) {
            // Security layer - bans, alerts, crowdsec status
            var bans = currentStripMetrics.bans || 0;
            var alerts = currentStripMetrics.alerts || 0;
            var secLevel = bans > 50 ? 'info' : bans > 20 ? 'warn' : alerts > 0 ? 'warn' : 'ok';
            var secLabel = bans > 50 ? 'ACTIVE MITIGATION' : healthLabels[secLevel === 'info' ? 'ok' : secLevel];

            content = '<div class="hw-tooltip-header" style="color:' + healthColors[secLevel] + '">' +
                '<span class="hw-tooltip-icon">' + layerIcons[3] + '</span> ' + layerTitles[3] + ' — ' + secLabel +
                '</div>' +
                '<div class="hw-tooltip-metrics sec-metrics">' +
                '<div class="sec-stat"><span class="sec-icon">🚫</span><span class="sec-count">' + bans + '</span><span class="sec-label">Active Bans</span></div>' +
                '<div class="sec-stat"><span class="sec-icon">⚠️</span><span class="sec-count">' + alerts + '</span><span class="sec-label">Recent Alerts</span></div>' +
                '</div>' +
                '<div class="hw-tooltip-footer">CrowdSec ' + (bans > 0 ? 'actively blocking threats' : 'monitoring') + '</div>';
        }

        tooltip.innerHTML = content;

        // On mobile, CSS handles positioning (centered at bottom)
        if (window.innerWidth <= 768) {
            tooltip.style.left = '';
            tooltip.style.top = '';
            tooltip.style.display = 'block';
            return;
        }

        // Desktop: Position tooltip - check if inside sidebar (left < 220px)
        var rect = el.getBoundingClientRect();
        var tooltipLeft = rect.left;

        // If element is in sidebar (left < 220), position tooltip to the right of it
        if (rect.left < 220) {
            tooltipLeft = rect.right + 10;
        }

        tooltip.style.left = tooltipLeft + 'px';
        tooltip.style.top = rect.top + 'px';
        tooltip.style.display = 'block';
    }

    function hideHwLedTooltip() {
        var tooltip = document.getElementById('hw-led-tooltip');
        if (tooltip) tooltip.style.display = 'none';
    }

    function startLedPulseSync() {
        // Sync pulse every 100ms for smooth animation
        setInterval(function() {
            ledPulsePhase = (ledPulsePhase + 1) % 20; // 2 second cycle
            var opacity = 0.4 + 0.6 * Math.sin(ledPulsePhase * Math.PI / 10);

            // Update main LED
            var mainLed = document.getElementById('gsb-led-main');
            if (mainLed) {
                mainLed.style.opacity = opacity;
                // Color based on health level
                var colors = { ok: '#00dd44', warn: '#ffb347', error: '#ff4466' };
                mainLed.style.background = colors[systemHealthLevel] || colors.ok;
                mainLed.style.boxShadow = '0 0 ' + (8 + ledPulsePhase % 5) + 'px ' + (colors[systemHealthLevel] || colors.ok);
            }

            // Update strip LEDs (glow intensity based on phase)
            document.querySelectorAll('.strip-led').forEach(function(led) {
                var baseOpacity = 0.6 + 0.4 * Math.sin(ledPulsePhase * Math.PI / 10);
                led.style.opacity = baseOpacity;
            });

            // Update 3 vertical RGB LEDs in top bar (like MOCHAbin physical LEDs)
            // Using double-buffer pattern: shadow → confirm → active → visual
            // NOW reads actual hardware LED colors from API instead of generic health level
            // Different pulse rates: LED1=1 pulse, LED2=2 pulses, LED3=4 pulses per cycle
            var hwLed1 = document.getElementById('hw-led-1');
            var hwLed2 = document.getElementById('hw-led-2');
            var hwLed3 = document.getElementById('hw-led-3');

            if (hwLed1 && hwLed2 && hwLed3) {
                // Base brightness is HIGH (color visible), pulse adds glow
                // LED1: slow pulse (1x), LED2: medium (2x), LED3: fast (4x)
                var pulse1 = 0.8 + 0.2 * Math.sin(ledPulsePhase * Math.PI / 20);  // slowest
                var pulse2 = 0.8 + 0.2 * Math.sin(ledPulsePhase * Math.PI / 10);  // medium
                var pulse3 = 0.8 + 0.2 * Math.sin(ledPulsePhase * Math.PI / 5);   // fastest
                var glowSize1 = 4 + 3 * Math.sin(ledPulsePhase * Math.PI / 20);
                var glowSize2 = 4 + 3 * Math.sin(ledPulsePhase * Math.PI / 10);
                var glowSize3 = 4 + 3 * Math.sin(ledPulsePhase * Math.PI / 5);

                // Step 1: Write to shadow buffer from hardware LED colors (if available)
                // LED1=Hardware health (bottom), LED2=Services (middle), LED3=Security (top)
                if (ledColorsFromHardware) {
                    // Use actual hardware LED colors from sysfs via API
                    ledBufferShadow = {
                        led1: ledColorsFromHardware.led1,
                        led2: ledColorsFromHardware.led2,
                        led3: ledColorsFromHardware.led3
                    };
                } else {
                    // Fallback to generic health level colors until API data arrives
                    var hwColors = { ok: '#00dd44', warn: '#ffb347', error: '#ff4466' };
                    if (systemHealthLevel === 'error') {
                        ledBufferShadow = { led1: hwColors.warn, led2: hwColors.warn, led3: hwColors.error };
                    } else if (systemHealthLevel === 'warn') {
                        ledBufferShadow = { led1: hwColors.warn, led2: hwColors.ok, led3: hwColors.warn };
                    } else {
                        ledBufferShadow = { led1: hwColors.ok, led2: hwColors.ok, led3: hwColors.ok };
                    }
                }

                // Step 2: Confirm shadow buffer by reading back (simulate with delay check)
                ledBufferConfirmed = (ledBufferShadow.led1 && ledBufferShadow.led2 && ledBufferShadow.led3);

                // Step 3: Swap shadow → active only if confirmed
                if (ledBufferConfirmed) {
                    ledBufferActive = { ...ledBufferShadow };
                }

                // Step 4: Visual update from active buffer only
                hwLed1.style.background = ledBufferActive.led1;
                hwLed2.style.background = ledBufferActive.led2;
                hwLed3.style.background = ledBufferActive.led3;

                // Apply different pulse rates to each LED (color always visible, glow pulses)
                hwLed1.style.opacity = pulse1;
                hwLed1.style.boxShadow = '0 0 ' + glowSize1 + 'px ' + ledBufferActive.led1 + ', inset 0 0 3px rgba(255,255,255,0.3)';
                hwLed2.style.opacity = pulse2;
                hwLed2.style.boxShadow = '0 0 ' + glowSize2 + 'px ' + ledBufferActive.led2 + ', inset 0 0 3px rgba(255,255,255,0.3)';
                hwLed3.style.opacity = pulse3;
                hwLed3.style.boxShadow = '0 0 ' + glowSize3 + 'px ' + ledBufferActive.led3 + ', inset 0 0 3px rgba(255,255,255,0.3)';
            }

            // Update top bar health bumper
            var topHealth = document.getElementById('gmb-health-bumper');
            if (topHealth) {
                topHealth.style.opacity = opacity;
            }
        }, 100);
    }

    // Load status bar data from API (with safe fetch)
    async function loadStatusBarData() {
        var token = localStorage.getItem('sbx_token');
        var headers = token ? { 'Authorization': 'Bearer ' + token } : {};

        // Show progress notification
        showStatusBarNotification('🔄 fetching...', 'progress');

        // Cache data to save at end
        var cacheData = {};

        try {
            // Load dashboard for version and uptime (using safe fetch)
            var result = await safeFetch('/api/v1/hub/dashboard', { headers: headers }, 5000);
            if (result.ok) {
                var data = result.data;
                if (data.build_info && data.build_info.version) {
                    var el = document.getElementById('gsb-version');
                    if (el) el.textContent = 'v' + data.build_info.version;
                }
                if (data.uptime) {
                    var el = document.getElementById('gsb-uptime');
                    if (el) el.textContent = data.uptime;
                }
            }

            // Load boot mode (using safe fetch)
            var modeResult = await safeFetch('/api/v1/hub/boot_mode', { headers: headers }, 3000);
            if (modeResult.ok) {
                var modeData = modeResult.data;
                var modeEl = document.getElementById('gsb-mode');
                if (modeEl && modeData.mode) {
                    modeEl.textContent = modeData.mode.charAt(0).toUpperCase() + modeData.mode.slice(1);
                    modeEl.className = 'status-value ' + (modeData.mode === 'kiosk' ? 'info' : 'warn');
                }
            }

            // Load auth mode (using safe fetch)
            var authResult = await safeFetch('/api/v1/hub/auth_mode', { headers: headers }, 3000);
            if (authResult.ok) {
                var authData = authResult.data;
                var authEl = document.getElementById('gsb-auth');
                if (authEl && authData.mode) {
                    authEl.textContent = authData.mode;
                    authEl.className = 'status-value ' + (authData.mode.toLowerCase() === 'zkp' ? 'ok' : '');
                }
            }

            // Load CPU, memory, and disk from dashboard (using safe fetch)
            var dashResult = await safeFetch('/api/v1/hub/dashboard', { headers: headers }, 5000);
            if (dashResult.ok) {
                var dashData = dashResult.data;
                var cpuEl = document.getElementById('gsb-cpu');
                var cpuBar = document.getElementById('gsb-cpu-bar');
                var memEl = document.getElementById('gsb-mem');
                var memBar = document.getElementById('gsb-mem-bar');
                var diskEl = document.getElementById('gsb-disk');
                var diskBar = document.getElementById('gsb-disk-bar');

                // Helper: get color class based on percentage
                function getBarColor(pct) {
                    if (pct > 80) return 'bar-error';
                    if (pct > 50) return 'bar-warn';
                    return 'bar-ok';
                }

                // Extract all metrics
                var cpu = Math.round(dashData.cpu_percent || 0);
                var mem = Math.round(dashData.memory_percent || 0);
                var disk = Math.round(dashData.disk_percent || 0);
                var load = (dashData.load_avg || [0])[0];
                var temp = Math.round(dashData.cpu_temp || 45);
                var net = Math.round(dashData.wifi_rssi || -50);

                // Update status bar metrics
                if (cpuEl) {
                    cpuEl.textContent = cpu + '%';
                    cpuEl.className = 'status-value ' + (cpu > 80 ? 'error' : cpu > 50 ? 'warn' : 'ok');
                    if (cpuBar) {
                        cpuBar.style.width = cpu + '%';
                        cpuBar.className = 'bar-fill ' + getBarColor(cpu);
                    }
                }
                if (memEl) {
                    memEl.textContent = mem + '%';
                    memEl.className = 'status-value ' + (mem > 80 ? 'error' : mem > 50 ? 'warn' : 'ok');
                    if (memBar) {
                        memBar.style.width = mem + '%';
                        memBar.className = 'bar-fill ' + getBarColor(mem);
                    }
                }
                if (diskEl) {
                    diskEl.textContent = disk + '%';
                    diskEl.className = 'status-value ' + (disk > 80 ? 'error' : disk > 50 ? 'warn' : 'ok');
                    if (diskBar) {
                        diskBar.style.width = disk + '%';
                        diskBar.className = 'bar-fill ' + getBarColor(disk);
                    }
                }
                if (dashData.uptime) {
                    var uptimeEl = document.getElementById('gsb-uptime');
                    if (uptimeEl) uptimeEl.textContent = dashData.uptime;
                }

                // Update Smart Strip values and history with persistence
                currentStripMetrics = { cpu: cpu, mem: mem, disk: disk, load: load, temp: temp, net: net };

                // Track history for sparklines
                Object.keys(currentStripMetrics).forEach(function(k) {
                    if (!stripMetricsHistory[k]) stripMetricsHistory[k] = [];
                    stripMetricsHistory[k].push(currentStripMetrics[k]);
                    if (stripMetricsHistory[k].length > STRIP_HISTORY_MAX) {
                        stripMetricsHistory[k].shift();
                    }
                });

                // Persist to localStorage every update
                saveStripHistoryCache(stripMetricsHistory);

                var ssCpu = document.getElementById('ss-cpu');
                var ssMem = document.getElementById('ss-mem');
                var ssDisk = document.getElementById('ss-disk');
                var ssLoad = document.getElementById('ss-load');
                var ssTemp = document.getElementById('ss-temp');
                var ssNet = document.getElementById('ss-net');

                if (ssCpu) ssCpu.textContent = cpu + '%';
                if (ssMem) ssMem.textContent = mem + '%';
                if (ssDisk) ssDisk.textContent = disk + '%';
                if (ssLoad) ssLoad.textContent = load.toFixed(1);
                if (ssTemp) ssTemp.textContent = temp + '°';
                if (ssNet) ssNet.textContent = net + 'dB';

                // Icons are static (official SecuBox: 🎯🔥🚀🤖💻⚙️) - no dynamic updates

                // Determine overall health level (tri-level)
                var maxVal = Math.max(cpu, mem, disk);
                if (maxVal > 80 || temp > 70) {
                    systemHealthLevel = 'error';
                } else if (maxVal > 50 || temp > 55 || load > 4) {
                    systemHealthLevel = 'warn';
                } else {
                    systemHealthLevel = 'ok';
                }

                // Update Health Bumper in top bar
                var hbLed = document.getElementById('hb-led');
                var hbStatus = document.getElementById('hb-status');
                if (hbLed && hbStatus) {
                    var hbColors = { ok: '#00dd44', warn: '#ffb347', error: '#ff4466' };
                    var hbLabels = { ok: 'NOMINAL', warn: 'WARNING', error: 'CRITICAL' };
                    hbLed.style.color = hbColors[systemHealthLevel];
                    hbLed.style.textShadow = '0 0 8px ' + hbColors[systemHealthLevel];
                    hbStatus.textContent = hbLabels[systemHealthLevel];
                    hbStatus.style.color = hbColors[systemHealthLevel];
                }
            }

            // Load health summary from batch endpoint (using safe fetch)
            var healthResult = await safeFetch('/api/v1/hub/public/health-batch', { headers: headers }, 5000);
            if (healthResult.ok) {
                var healthData = healthResult.data;
                var healthEl = document.getElementById('gsb-health');
                if (healthEl && healthData.modules) {
                    var ok = 0, warn = 0, err = 0, total = 0;
                    Object.values(healthData.modules).forEach(function(m) {
                        total++;
                        if (m.status === 'ok') ok++;
                        else if (m.status === 'warn' || m.status === 'degraded') warn++;
                        else if (m.status === 'error') err++;
                    });
                    var emoji = err > 0 ? '🔴' : warn > 0 ? '🟡' : '🟢';
                    healthEl.innerHTML = emoji + ' ' + ok + '/' + total;
                    healthEl.className = 'status-value ' + (err > 0 ? 'error' : warn > 0 ? 'warn' : 'ok');
                    healthEl.title = ok + ' OK, ' + warn + ' warnings, ' + err + ' errors';

                    // Update LED metrics in sidebar header (sync with health bumper)
                    var lmHw = document.getElementById('lm-hw');
                    var lmSvc = document.getElementById('lm-svc');
                    var lmSec = document.getElementById('lm-sec');

                    // LED1 (Hardware): CPU%
                    if (lmHw) {
                        var hwMax = Math.max(currentStripMetrics.cpu || 0, currentStripMetrics.mem || 0);
                        lmHw.textContent = hwMax + '%';
                        lmHw.className = 'led-metric-val ' + (hwMax > 80 ? 'error' : hwMax > 50 ? 'warn' : 'ok');
                        lmHw.title = 'Hardware: CPU ' + (currentStripMetrics.cpu || 0) + '%, MEM ' + (currentStripMetrics.mem || 0) + '%';
                        // Save to cache
                        cacheData.hwMax = hwMax;
                        cacheData.hwTooltip = lmHw.title;
                        cacheData.cpu = currentStripMetrics.cpu;
                        cacheData.mem = currentStripMetrics.mem;
                    }

                    // LED2 (Services): ok/total
                    if (lmSvc) {
                        lmSvc.textContent = ok + '/' + total;
                        lmSvc.className = 'led-metric-val ' + (err > 0 ? 'error' : warn > 0 ? 'warn' : 'ok');
                        lmSvc.title = 'Services: ' + ok + ' OK, ' + warn + ' warnings, ' + err + ' errors';
                        // Save to cache
                        cacheData.svcOk = ok;
                        cacheData.svcWarn = warn;
                        cacheData.svcErr = err;
                        cacheData.svcTotal = total;
                        cacheData.svcTooltip = lmSvc.title;
                    }

                    // LED3 (Security): fetch bans from CrowdSec
                    if (lmSec) {
                        // Will be updated by separate security fetch
                        lmSec.textContent = '...';
                    }
                }
            }

            // Fetch security metrics (CrowdSec + WAF combined) - parallel fetch
            var lmSec = document.getElementById('lm-sec');
            var [csResult, wafResult] = await Promise.all([
                safeFetch('/api/v1/crowdsec/stats', { headers: headers }, 3000),
                safeFetch('/api/v1/waf/stats', { headers: headers }, 3000)
            ]);

            var bans = 0, alerts = 0, wafThreats = 0, wafBlocked = 0;

            if (csResult.ok) {
                var csData = csResult.data;
                bans = csData.active_bans || csData.decisions || 0;
                alerts = csData.alerts_today || 0;
            }

            if (wafResult.ok) {
                var wafData = wafResult.data;
                wafThreats = wafData.threats_24h || wafData.alerts_24h || 0;
                wafBlocked = wafData.blocked_24h || wafData.blocked || 0;
            }

            // Store for tooltip
            currentStripMetrics.bans = bans;
            currentStripMetrics.alerts = alerts;
            currentStripMetrics.wafThreats = wafThreats;
            currentStripMetrics.wafBlocked = wafBlocked;

            if (lmSec) {
                var totalThreats = bans + wafBlocked;
                lmSec.textContent = totalThreats + '🛡️';
                lmSec.title = '🛡️ Security: ' + bans + ' IPs banned (CrowdSec), ' + wafBlocked + ' blocked (WAF), ' + alerts + ' alerts, ' + wafThreats + ' threats';

                // Color based on combined threat level
                var threatLevel = alerts + wafThreats;
                if (totalThreats > 50) {
                    lmSec.className = 'led-metric-val info';  // Blue - active mitigation
                } else if (threatLevel > 100) {
                    lmSec.className = 'led-metric-val error';
                } else if (threatLevel > 20) {
                    lmSec.className = 'led-metric-val warn';
                } else {
                    lmSec.className = 'led-metric-val ok';
                }

                // Save to cache
                cacheData.secTotal = totalThreats;
                cacheData.secTooltip = lmSec.title;
                cacheData.bans = bans;
                cacheData.alerts = alerts;
                cacheData.wafThreats = wafThreats;
                cacheData.wafBlocked = wafBlocked;
            }

            // Save all collected data to cache
            if (cacheData.hwMax !== undefined || cacheData.svcOk !== undefined || cacheData.secTotal !== undefined) {
                saveStatusBarCache(cacheData);
                hideStatusBarNotification();
                showStatusBarNotification('🔴 live', 'live');
            }
        } catch (e) {
            console.log('[Sidebar] Status bar data error:', e);
            hideStatusBarNotification();
            showStatusBarNotification('⚠️ error', 'error');
        }

        // Refresh every 30s
        setTimeout(loadStatusBarData, 30000);
    }

    let healthCache = {};
    let healthCheckInProgress = {};
    let offlineCounters = {};
    // TRUE = hide black/unknown (show only green+yellow+red), FALSE = show all
    let hideUnknownEnabled = false;

    // ============================================
    // RESILIENCE & SAFE PARSING
    // ============================================

    // Safe JSON parse - never throws, returns null on error
    function safeJsonParse(text, fallback) {
        if (!text || typeof text !== 'string') return fallback || null;
        try {
            return JSON.parse(text);
        } catch (e) {
            console.warn('[Sidebar] JSON parse error:', e.message, 'Input:', text.substring(0, 100));
            return fallback || null;
        }
    }

    // Safe fetch with JSON - handles all error cases gracefully
    async function safeFetch(url, options, timeout) {
        timeout = timeout || 5000;
        var ctrl = new AbortController();
        var tm = setTimeout(function() { ctrl.abort(); }, timeout);

        try {
            var res = await fetch(url, { ...options, signal: ctrl.signal });
            clearTimeout(tm);

            if (!res.ok) {
                return { ok: false, status: res.status, error: 'HTTP ' + res.status };
            }

            var ct = res.headers.get('content-type') || '';
            var text = await res.text();

            // Check if response is JSON
            if (!ct.includes('application/json') && !text.trim().startsWith('{') && !text.trim().startsWith('[')) {
                return { ok: false, status: res.status, error: 'Not JSON', text: text };
            }

            var data = safeJsonParse(text, null);
            if (data === null) {
                return { ok: false, status: res.status, error: 'Invalid JSON', text: text };
            }

            return { ok: true, status: res.status, data: data };
        } catch (e) {
            clearTimeout(tm);
            if (e.name === 'AbortError') {
                return { ok: false, status: 0, error: 'Timeout' };
            }
            return { ok: false, status: 0, error: e.message || 'Network error' };
        }
    }

    // Check if sidebar is functioning
    function checkSidebarHealth() {
        var sidebar = document.getElementById('sidebar');
        var nav = sidebar ? sidebar.querySelector('.sidebar-nav') : null;
        var hasItems = nav && nav.querySelectorAll('.nav-item').length > 0;

        if (!sidebar || !nav || !hasItems) {
            console.warn('[Sidebar] Health check failed: sidebar=' + !!sidebar + ', nav=' + !!nav + ', items=' + hasItems);
            sidebarHealthy = false;
            return false;
        }

        sidebarHealthy = true;
        return true;
    }

    // Self-reinject mechanism - rebuilds sidebar if broken
    function startHeartbeat() {
        if (heartbeatTimer) clearInterval(heartbeatTimer);

        heartbeatTimer = setInterval(function() {
            if (!checkSidebarHealth()) {
                console.log('[Sidebar] Heartbeat detected issue, attempting reinject...');
                reinjectSidebar();
            }
        }, HEARTBEAT_INTERVAL);
    }

    // Reinject sidebar with exponential backoff
    async function reinjectSidebar() {
        if (retryCount >= MAX_RETRY_ATTEMPTS) {
            console.error('[Sidebar] Max retry attempts reached, showing fallback');
            showFallbackSidebar();
            retryCount = 0;
            return;
        }

        retryCount++;
        console.log('[Sidebar] Reinject attempt ' + retryCount + '/' + MAX_RETRY_ATTEMPTS);

        // Wait before retry with exponential backoff
        await new Promise(function(resolve) {
            setTimeout(resolve, RETRY_DELAY * retryCount);
        });

        try {
            await buildSidebar();
            retryCount = 0;
            console.log('[Sidebar] Reinject successful');
        } catch (e) {
            console.error('[Sidebar] Reinject failed:', e);
            if (retryCount >= MAX_RETRY_ATTEMPTS) {
                showFallbackSidebar();
                retryCount = 0;
            }
        }
    }

    // Minimal fallback sidebar when everything fails
    function showFallbackSidebar() {
        var sidebar = document.getElementById('sidebar');
        if (!sidebar) return;

        sidebar.innerHTML = '<div class="sidebar-header">' +
            '<a href="/"><span class="logo-icon">🔒</span><div><span class="logo">SECUBOX</span>' +
            '<span class="logo-version">⚠️ ' + VERSION + '</span></div></a></div>' +
            '<div class="sidebar-nav">' +
            '<div class="nav-section"><div class="nav-section-title"><span>⚠️ OFFLINE MODE</span></div>' +
            '<div class="nav-items">' +
            '<a href="/" class="nav-item"><span class="icon">🏠</span><span>Dashboard</span></a>' +
            '<a href="/system/" class="nav-item"><span class="icon">⚙️</span><span>System</span></a>' +
            '<a href="/crowdsec/" class="nav-item"><span class="icon">👁️</span><span>CrowdSec</span></a>' +
            '<a href="/soc/" class="nav-item"><span class="icon">🛡️</span><span>SOC</span></a>' +
            '</div></div></div>' +
            '<div class="sidebar-footer">' +
            '<div style="color:#ff6b6b;font-size:0.75rem;padding:0.5rem;">API unavailable - showing cached links</div>' +
            '<button onclick="SecuBoxSidebar.forceReinject()" style="width:100%;padding:0.5rem;background:#4466ff;color:#fff;border:none;border-radius:4px;cursor:pointer;">🔄 Retry</button>' +
            '</div>';

        console.log('[Sidebar] Fallback mode activated');
    }

    // ============================================
    // HELPERS
    // ============================================

    function getHealthEndpoint(mod) {
        return '/api/v1/' + mod + '/health';
    }

    function getPagePath(mod) {
        if (mod === 'hub') return '/';
        return '/' + mod + '/';
    }

    function getModuleFromPath(path) {
        if (!path || path === '/' || path === '/index.html') return 'hub';
        var m = path.match(/^\/([a-z0-9-]+)/);
        return m ? m[1] : null;
    }

    function extractModulesFromMenu(data) {
        var modules = [];
        if (data && data.categories) {
            data.categories.forEach(function(cat) {
                if (cat.items) {
                    cat.items.forEach(function(item) {
                        var mod = getModuleFromPath(item.path);
                        if (mod && modules.indexOf(mod) === -1) modules.push(mod);
                    });
                }
            });
        }
        return modules;
    }

    // ============================================
    // PRE-CACHE
    // ============================================

    function loadPreCache() {
        try {
            var cached = localStorage.getItem(HEALTH_CACHE_KEY);
            if (!cached) return null;
            var data = JSON.parse(cached);
            // Keep ALL entries - don't discard based on TTL
            // TTL only used to decide what to refresh, not what to show
            if (Object.keys(data).length > 0) {
                healthCache = data;
                return data;
            }
        } catch (e) {}
        return null;
    }

    function savePreCache(health) {
        try {
            var existing = {};
            try { var c = localStorage.getItem(HEALTH_CACHE_KEY); if (c) existing = JSON.parse(c); } catch (e) {}
            for (var mod in health) {
                existing[mod] = {
                    status: health[mod].status,
                    msg: health[mod].msg,
                    version: health[mod].version,
                    dev_stage: health[mod].dev_stage,
                    timestamp: health[mod].timestamp || Date.now()
                };
            }
            localStorage.setItem(HEALTH_CACHE_KEY, JSON.stringify(existing));
        } catch (e) {}
    }

    // ============================================
    // DEV STAGE BADGES
    // ============================================

    function getDevStageBadge(stage) {
        if (stage === 'alpha') return '<span class="dev-badge alpha" title="Alpha">α</span>';
        if (stage === 'beta') return '<span class="dev-badge beta" title="Beta">β</span>';
        return ''; // No badge for production
    }

    function getVersionTooltip(version, devStage) {
        if (!version) return '';
        var stage = devStage && devStage !== 'production' ? ' (' + devStage + ')' : '';
        return 'v' + version + stage;
    }

    // ============================================
    // HEALTH CHECKS
    // ============================================

    async function checkModuleHealth(mod) {
        var endpoint = getHealthEndpoint(mod);

        if (healthCheckInProgress[mod]) {
            return healthCache[mod] || { status: 'checking', msg: 'In progress', timestamp: Date.now() };
        }
        healthCheckInProgress[mod] = true;

        try {
            var token = localStorage.getItem('sbx_token');
            var headers = token ? { 'Authorization': 'Bearer ' + token } : {};

            // Use safe fetch for resilience
            var result = await safeFetch(endpoint, { headers: headers }, HEALTH_REQUEST_TIMEOUT);
            healthCheckInProgress[mod] = false;

            if (!result.ok) {
                // Handle specific error cases
                if (result.status === 404) {
                    return { status: 'error', msg: 'No API', timestamp: Date.now() };
                }
                if (result.error === 'Timeout') {
                    return { status: 'error', msg: 'Timeout', timestamp: Date.now() };
                }
                if (result.error === 'Not JSON') {
                    return { status: 'unknown', msg: 'No health API', timestamp: Date.now() };
                }
                if (result.error === 'Invalid JSON') {
                    return { status: 'unknown', msg: 'Invalid JSON', timestamp: Date.now() };
                }
                return { status: 'error', msg: result.error || 'HTTP ' + result.status, timestamp: Date.now() };
            }

            // Successfully got JSON response
            var d = result.data;
            var version = d.version || null;
            var devStage = d.dev_stage || 'production';

            if (d.status === 'ok' || d.healthy === true || d.status === 'healthy') {
                return { status: 'ok', msg: d.message || 'OK', version: version, dev_stage: devStage, timestamp: Date.now() };
            }
            if (d.status === 'degraded' || d.status === 'warn' || d.warning) {
                return { status: 'warn', msg: d.message || 'Degraded', version: version, dev_stage: devStage, timestamp: Date.now() };
            }
            return { status: 'error', msg: d.message || d.status || 'Error', version: version, dev_stage: devStage, timestamp: Date.now() };

        } catch (e) {
            healthCheckInProgress[mod] = false;
            console.warn('[Sidebar] Health check error for ' + mod + ':', e);
            return { status: 'error', msg: 'Check failed', timestamp: Date.now() };
        }
    }

    async function checkPageFallback(mod, page, headers) {
        try {
            var ctrl = new AbortController();
            var tm = setTimeout(function() { ctrl.abort(); }, 2000);
            var res = await fetch(page, { method: 'HEAD', headers: headers, signal: ctrl.signal });
            clearTimeout(tm);

            if (res.ok) {
                return { status: 'unknown', msg: 'Page exists', timestamp: Date.now() };
            }
            if (res.status === 401 || res.status === 403) {
                return { status: 'unknown', msg: 'Auth required', timestamp: Date.now() };
            }
            if (res.status === 404) {
                return { status: 'error', msg: 'Not found', timestamp: Date.now() };
            }
            return { status: 'error', msg: 'HTTP ' + res.status, timestamp: Date.now() };
        } catch (e) {
            return { status: 'error', msg: 'Unreachable', timestamp: Date.now() };
        }
    }

    async function checkAllHealth(immediate) {
        var now = Date.now();

        if (!immediate && Object.keys(healthCache).length > 0) {
            var newest = 0;
            for (var mod in healthCache) {
                if (healthCache[mod].timestamp > newest) newest = healthCache[mod].timestamp;
            }
            if (now - newest < HEALTH_REFRESH_INTERVAL) {
                setTimeout(refreshStaleHealth, 100);
                return healthCache;
            }
        }

        var modules = ALL_MODULES.length > 0 ? ALL_MODULES : Object.keys(healthCache);
        if (modules.length === 0) return healthCache;

        // Set modules without status to checking (preserve existing valid statuses)
        modules.forEach(function(mod) {
            var existing = healthCache[mod];
            if (!existing) {
                healthCache[mod] = { status: 'checking', msg: 'Checking...', timestamp: Date.now() };
            } else if (existing._rechecking) {
                // Already marked for recheck by forceRefresh, keep visual status
            } else if (existing.status === 'unknown') {
                healthCache[mod] = { status: 'checking', msg: 'Checking...', timestamp: Date.now() };
            }
            // If already ok/warn/error, keep that status until new result arrives
        });

        // #740: ONE batch call instead of one /api/v1/<mod>/health per module.
        // The per-module loop fired ~119 requests every cycle and hammered the
        // aggregator's single shared event loop (board-wide 502s). The hub batch
        // endpoint returns every module's status in a single hit.
        await applyHealthBatch(modules);
        return healthCache;
    }

    // Populate healthCache for `modules` from the single hub batch endpoint
    // (/api/v1/hub/public/health-batch — served by the dedicated hub process,
    // double-buffered). Replaces the per-module health storm.
    async function applyHealthBatch(modules) {
        var token = localStorage.getItem('sbx_token');
        var headers = token ? { 'Authorization': 'Bearer ' + token } : {};
        var res = await safeFetch(BATCH_HEALTH_API, { headers: headers }, 5000);
        if (!res.ok || !res.data || !res.data.modules) return;
        var mods = res.data.modules;
        modules.forEach(function(mod) {
            var hb = mods[mod] || mods[mod.replace(/_/g, '-')] || mods[mod.replace(/-/g, '_')];
            healthCache[mod] = hb
                ? { status: hb.status, msg: hb.msg || '', timestamp: Date.now() }
                : { status: 'unknown', msg: 'no health API', timestamp: Date.now() };
        });
        updateAllLEDs();
        try { savePreCache(healthCache); } catch (e) {}
    }

    async function refreshStaleHealth() {
        var now = Date.now();
        var stale = [];

        ALL_MODULES.forEach(function(mod) {
            var c = healthCache[mod];
            if (!c || (now - (c.timestamp || 0)) > HEALTH_REFRESH_INTERVAL) stale.push(mod);
        });

        if (stale.length === 0) return;

        // #740: refresh stale modules via the single batch endpoint, not one
        // /health request per module.
        await applyHealthBatch(stale);

        // Save cache once at end, no re-sort needed
        savePreCache(healthCache);
        updateStatusIndicator();
    }

    // ============================================
    // SORTING — MOVE, NOT CLONE
    // ============================================

    // Cache DOM items to survive master-top removal
    var _cachedItems = null;

    function applySorting() {
        var navContainer = document.querySelector('.sidebar-nav');
        if (!navContainer) return;

        // Cache items BEFORE removing master-top
        if (!_cachedItems) {
            _cachedItems = Array.from(document.querySelectorAll('.sidebar-nav .nav-item[data-module]'));
        }

        // Remove master-top if exists
        var masterTop = document.getElementById('master-top-section');
        if (masterTop) masterTop.remove();

        // Show all cached items
        _cachedItems.forEach(function(item) {
            item.style.display = '';
        });

        // Show all original sections
        document.querySelectorAll('.nav-section').forEach(function(s) {
            s.style.display = '';
        });

        if (hideUnknownEnabled) {
            applyFilteredSort(navContainer, _cachedItems);
        } else {
            sortWithinCategories(_cachedItems);
        }
    }

    function sortWithinCategories(cachedItems) {
        var order = { 'ok': 0, 'healthy': 0, 'warn': 1, 'degraded': 1, 'unknown': 2, 'checking': 2, 'error': 3 };
        document.querySelectorAll('.nav-items').forEach(function(container) {
            var items = cachedItems ? cachedItems.filter(function(i) { return container.contains(i) || i.parentNode === null; })
                                    : Array.from(container.querySelectorAll('.nav-item[data-module]'));
            items.sort(function(a, b) {
                var hA = healthCache[a.dataset.module];
                var hB = healthCache[b.dataset.module];
                var sA = hA ? (hA._rechecking && hA._prevStatus ? hA._prevStatus : hA.status) : 'unknown';
                var sB = hB ? (hB._rechecking && hB._prevStatus ? hB._prevStatus : hB.status) : 'unknown';
                var oA = (order[sA] !== undefined) ? order[sA] : 2;
                var oB = (order[sB] !== undefined) ? order[sB] : 2;
                return oA - oB;
            });
            items.forEach(function(item) { container.appendChild(item); });
        });
    }

    function applyFilteredSort(navContainer, cachedItems) {
        // Use cached items or query DOM
        var allItems = cachedItems || Array.from(navContainer.querySelectorAll('.nav-item[data-module]'));

        console.log('[Filter] Items:', allItems.length, 'Cache:', Object.keys(healthCache).length);

        // Separate into visible (ok, warn, error, checking) and hidden (unknown only)
        var visible = [];
        var hidden = [];

        allItems.forEach(function(item) {
            var mod = item.dataset.module;
            if (!mod) {
                // Skip items without valid module ID
                hidden.push(item);
                item.style.display = 'none';
                return;
            }

            var h = healthCache[mod];
            var status = h ? h.status : 'checking';  // Default to checking, not unknown

            // If rechecking, use previous status if it was valid (green/yellow/red)
            if (h && h._rechecking && h._prevStatus) {
                status = h._prevStatus;
            }

            // Show: green, yellow, red, AND blue (checking)
            // Hide: only black (unknown)
            var isVisible = (status === 'ok' || status === 'healthy' || status === 'warn' || status === 'degraded' || status === 'error' || status === 'checking');
            if (isVisible) {
                visible.push(item);
            } else {
                console.log('[Filter] Hiding:', mod, 'status:', status);
                hidden.push(item);
                item.style.display = 'none';
            }
        });

        // Sort visible items: green first, then yellow, then blue, then red
        visible.sort(function(a, b) {
            var hA = healthCache[a.dataset.module];
            var hB = healthCache[b.dataset.module];
            // Use _prevStatus during recheck to maintain sort order
            var sA = hA ? (hA._rechecking && hA._prevStatus ? hA._prevStatus : hA.status) : 'checking';
            var sB = hB ? (hB._rechecking && hB._prevStatus ? hB._prevStatus : hB.status) : 'checking';

            var order = { 'ok': 0, 'healthy': 0, 'warn': 1, 'degraded': 1, 'checking': 2, 'error': 3 };
            var oA = (order[sA] !== undefined) ? order[sA] : 2;
            var oB = (order[sB] !== undefined) ? order[sB] : 2;

            if (oA !== oB) return oA - oB;
            return a.textContent.trim().toLowerCase().localeCompare(b.textContent.trim().toLowerCase());
        });

        // Create filtered section
        var masterTop = document.createElement('div');
        masterTop.id = 'master-top-section';
        masterTop.className = 'nav-section';

        var okCount = visible.filter(function(i) {
            var s = (healthCache[i.dataset.module] || {}).status;
            return s === 'ok' || s === 'healthy';
        }).length;

        console.log('[Filter] Visible:', visible.length, 'Hidden:', hidden.length);

        masterTop.innerHTML = '<div class="nav-section-title master-top-title"><span>🎯 ACTIVE (' + okCount + '/' + visible.length + ' OK) — ' + hidden.length + ' hidden</span></div><div class="nav-items" id="master-top-items"></div>';
        navContainer.insertBefore(masterTop, navContainer.firstChild);

        var masterItems = document.getElementById('master-top-items');
        console.log('[Filter] masterItems:', masterItems ? 'found' : 'NOT FOUND');

        // Move visible items
        visible.forEach(function(item) {
            item.style.display = '';
            masterItems.appendChild(item);
        });

        // Hide original category sections
        document.querySelectorAll('.nav-section:not(#master-top-section)').forEach(function(s) {
            s.style.display = 'none';
        });
    }

    // ============================================
    // LED Updates
    // ============================================

    function updateAllLEDs() {
        document.querySelectorAll('.nav-item[data-module]').forEach(function(item) {
            var mod = item.dataset.module;
            var h = healthCache[mod];
            if (h) updateSingleLED(item, h);
        });
    }

    function updateSingleLED(item, h) {
        var mod = item.dataset.module;
        var led = item.querySelector('.status-led');
        if (!led || !h) return;

        // Simple: always update LED to match health status
        var displayStatus = h.status;

        // During recheck with valid previous, show previous with pulse
        if (h._rechecking && h._prevStatus && h._prevStatus !== 'unknown') {
            displayStatus = h._prevStatus;
            led.classList.add('led-pulse');
        } else {
            led.classList.toggle('led-pulse', h.status === 'checking');
        }

        led.textContent = LED_EMOJI[displayStatus] || LED_EMOJI.unknown;
        led.title = h.msg || h.status;

        // Visual effects for offline/fading
        if (h.status === 'error') {
            offlineCounters[mod] = (offlineCounters[mod] || 0) + 1;
            item.classList.remove('has-msg', 'reappear');
            if (offlineCounters[mod] >= 3) item.classList.add('fading');
            if (offlineCounters[mod] >= 6) { item.classList.add('offline'); item.classList.remove('fading'); }
        } else {
            var wasOffline = item.classList.contains('offline') || item.classList.contains('fading');
            offlineCounters[mod] = 0;
            item.classList.remove('offline', 'fading');
            if (wasOffline && h.status === 'ok') {
                item.classList.add('reappear');
                setTimeout(function() { item.classList.remove('reappear'); }, 600);
            }
            if (h.status === 'warn') item.classList.add('has-msg');
            else item.classList.remove('has-msg');
        }
    }

    function updateLEDs(health) {
        updateAllLEDs();
        applySorting();
        savePreCache(health);
        updateStatusIndicator();
    }

    function updateStatusIndicator() {
        var ind = document.getElementById('status-indicator');
        if (!ind) return;

        var ok = 0, warn = 0, err = 0, unk = 0;
        for (var mod in healthCache) {
            var s = healthCache[mod].status;
            if (s === 'ok') ok++;
            else if (s === 'warn') warn++;
            else if (s === 'error') err++;
            else unk++;
        }

        var total = ok + warn + err + unk;
        var em = err > 0 ? '❌' : (warn > 0 ? '⚠️' : '✅');
        ind.innerHTML = '<span>' + em + '</span><span>' + ok + '/' + total + '</span>';
        ind.title = ok + ' OK, ' + warn + ' warn, ' + err + ' error, ' + unk + ' unknown';
        ind.onclick = showStatusPanel;
    }

    function showStatusPanel() {
        var ex = document.getElementById('status-panel');
        if (ex) { ex.remove(); return; }

        var ok = 0, warn = 0, err = 0, unk = 0;
        for (var mod in healthCache) {
            var s = healthCache[mod].status;
            if (s === 'ok') ok++;
            else if (s === 'warn') warn++;
            else if (s === 'error') err++;
            else unk++;
        }

        var p = document.createElement('div');
        p.id = 'status-panel';
        p.className = 'status-panel';

        var html = '<div class="status-panel-header"><span>Health Status (' + ALL_MODULES.length + ' modules)</span><button onclick="document.getElementById(\'status-panel\').remove()">✕</button></div>' +
            '<div class="status-panel-summary"><div class="ok">🟢 ' + ok + '</div><div class="warn">🟡 ' + warn + '</div><div class="err">🔴 ' + err + '</div><div class="unk">⚫ ' + unk + '</div></div>' +
            '<div class="status-panel-list">';

        // List errors and warnings
        var mods = Object.keys(healthCache).sort(function(a, b) {
            var order = { error: 0, warn: 1, unknown: 2, checking: 3, ok: 4 };
            return (order[healthCache[a].status] || 2) - (order[healthCache[b].status] || 2);
        });

        mods.forEach(function(mod) {
            var h = healthCache[mod];
            if (h.status !== 'ok') {
                var em = LED_EMOJI[h.status] || '⚫';
                html += '<div class="status-item"><span>' + em + '</span><span class="status-mod">' + mod + '</span><span class="status-msg">' + h.msg + '</span></div>';
            }
        });

        html += '</div><div class="status-panel-footer"><button onclick="SecuBoxSidebar.forceRefresh();document.getElementById(\'status-panel\').remove();">🔄 Recheck All</button></div>';
        p.innerHTML = html;
        document.body.appendChild(p);
    }

    // ============================================
    // Theme & Preferences
    // ============================================

    function getHideUnknownPref() { try { return localStorage.getItem(SORT_PREF_KEY) === 'true'; } catch (e) { return false; } }
    function setHideUnknownPref(enabled) { try { localStorage.setItem(SORT_PREF_KEY, enabled ? 'true' : 'false'); hideUnknownEnabled = enabled; } catch (e) {} }

    // Theme switching removed - hybrid-skin is the universal theme
    function setTheme() {
        // No-op: hybrid-skin is now the only theme
    }

    function toggleHideUnknown() {
        hideUnknownEnabled = !hideUnknownEnabled;
        setHideUnknownPref(hideUnknownEnabled);
        var btn = document.getElementById('filter-btn');
        if (btn) {
            btn.classList.toggle('active', hideUnknownEnabled);
            btn.title = hideUnknownEnabled ? 'Showing active only' : 'Showing all';
        }
        applySorting();
    }

    function getCurrentUser() {
        try { var t = localStorage.getItem('sbx_token'); if (t) { var p = JSON.parse(atob(t.split('.')[1])); return p.sub || p.username || 'admin'; } } catch (e) {}
        return 'admin';
    }

    // ============================================
    // Navigation
    // ============================================

    async function preflightCheck(mod, url) {
        var led = document.querySelector('.nav-item[data-module="' + mod + '"] .status-led');
        if (led) { led.textContent = LED_EMOJI.checking; led.classList.add('led-pulse'); }

        var h = await checkModuleHealth(mod);
        healthCache[mod] = h;

        if (led) {
            led.textContent = LED_EMOJI[h.status] || LED_EMOJI.unknown;
            led.classList.remove('led-pulse');
            led.title = h.msg;
        }

        if (h.status === 'error') showQuickError(mod, h);
        return true;
    }

    function showQuickError(mod, h) {
        var t = document.createElement('div');
        t.className = 'health-toast';
        t.innerHTML = '<div class="health-toast-content"><span>' + LED_EMOJI.error + '</span><span>' + mod + '</span><span>' + h.msg + '</span></div>';
        document.body.appendChild(t);
        setTimeout(function() { t.remove(); }, 3000);
    }

    async function navClick(ev, mod, url) {
        if (!mod) return true;
        ev.preventDefault();
        handleMobileNavClick();  // Close sidebar on mobile
        await preflightCheck(mod, url);
        window.location.href = url;
        return false;
    }

    function startClock(el) {
        var u = function() { el.textContent = new Date().toTimeString().split(' ')[0]; };
        u();
        setInterval(u, 1000);
    }

    function injectStyles() {
        if (document.getElementById('sidebar-extra-styles')) return;
        var s = document.createElement('style');
        s.id = 'sidebar-extra-styles';
        s.textContent = '.status-led{font-size:0.9em;margin-left:auto;}.status-led.led-pulse{animation:ledPulse 0.8s infinite;}@keyframes ledPulse{0%,100%{opacity:1;}50%{opacity:0.4;}}.nav-item{display:flex;align-items:center;gap:0.5rem;transition:opacity 0.3s,transform 0.3s;}.nav-item.offline{opacity:0;height:0;padding:0;margin:0;overflow:hidden;}.nav-item.fading{opacity:0.3;}.nav-item.reappear{animation:fadeIn 0.5s;}@keyframes fadeIn{from{opacity:0;transform:translateX(-10px);}to{opacity:1;transform:translateX(0);}}' +
            '.filter-btn{display:flex;align-items:center;gap:0.3rem;font-size:0.9rem;padding:0.3rem 0.5rem;cursor:pointer;color:var(--text-dim,#666);border-radius:4px;border:1px solid currentColor;}.filter-btn:hover{background:rgba(0,0,0,0.05);}.filter-btn.active{color:var(--p31-peak,#00dd44);background:rgba(0,221,68,0.1);border-color:var(--p31-peak,#00dd44);}' +
            '.status-indicator{display:flex;align-items:center;gap:0.3rem;font-size:0.7rem;padding:0.2rem 0.5rem;cursor:pointer;border-radius:4px;}' +
            '.status-panel{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:90%;max-width:400px;max-height:70vh;background:#1a1a2e;color:#e8e6d9;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.5);z-index:10001;overflow:hidden;font-family:monospace;}.status-panel-header{display:flex;justify-content:space-between;align-items:center;padding:0.75rem 1rem;background:#252540;font-size:0.9rem;}.status-panel-header button{background:none;border:none;color:#888;font-size:1rem;cursor:pointer;}.status-panel-summary{display:grid;grid-template-columns:repeat(4,1fr);gap:0.5rem;padding:0.75rem;background:#1e1e32;}.status-panel-summary div{text-align:center;padding:0.4rem;border-radius:4px;background:#252540;font-size:0.75rem;}.status-panel-list{max-height:250px;overflow-y:auto;padding:0.5rem;}.status-item{display:flex;align-items:center;gap:0.5rem;padding:0.4rem;font-size:0.75rem;border-bottom:1px solid #333;}.status-mod{font-weight:bold;min-width:80px;}.status-msg{color:#888;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}.status-panel-footer{padding:0.75rem;background:#252540;}.status-panel-footer button{width:100%;padding:0.5rem;background:#4466ff;color:#fff;border:none;border-radius:4px;cursor:pointer;}' +
            '.master-top-title{background:rgba(0,221,68,0.15);color:var(--p31-peak,#00dd44);font-weight:bold;}' +
            '.health-toast{position:fixed;top:1rem;right:1rem;z-index:10000;animation:toastIn 0.3s;}.health-toast-content{display:flex;align-items:center;gap:0.5rem;background:rgba(255,68,68,0.95);color:#fff;padding:0.5rem 1rem;border-radius:8px;font-size:0.8rem;}@keyframes toastIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}' +
            '@keyframes statusbar-progress{0%{width:0%;opacity:0.5;}50%{width:100%;opacity:1;}100%{width:0%;opacity:0.5;}}' +
            '.sync-status{border-bottom:1px dashed rgba(100,150,200,0.2);padding-bottom:4px;margin-bottom:2px;}' +
            '.sync-led{font-size:10px;width:14px;height:14px;display:flex;align-items:center;justify-content:center;border-radius:3px;transition:all 0.3s;}' +
            '.sync-led.fetching{animation:syncPulse 0.8s infinite;background:rgba(68,170,255,0.2);}' +
            '.sync-led.cached{background:rgba(100,200,150,0.15);color:#5f8;}' +
            '.sync-led.live{background:rgba(255,100,100,0.15);color:#f88;}' +
            '.sync-led.error{background:rgba(255,68,68,0.2);color:#f55;}' +
            '.sync-val{font-size:9px!important;min-width:45px;}' +
            '@keyframes syncPulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.5;transform:scale(0.9);}}' +
            '.page-metrics{display:flex;gap:6px;align-items:center;margin-left:8px;padding-left:8px;border-left:1px solid rgba(100,150,200,0.2);}' +
            '.page-metric{display:flex;align-items:center;gap:2px;font-size:10px;padding:2px 6px;border-radius:10px;background:rgba(50,100,150,0.15);cursor:help;transition:all 0.2s;}' +
            '.page-metric:hover{background:rgba(50,100,150,0.25);transform:scale(1.05);}' +
            '.page-metric .pm-icon{font-size:11px;}' +
            '.page-metric .pm-val{font-family:monospace;font-weight:bold;color:#8cf;}' +
            '.page-metric.highlight{background:rgba(100,200,100,0.2);}.page-metric.highlight .pm-val{color:#5f8;}' +
            '.page-metric.alert{background:rgba(255,100,100,0.2);}.page-metric.alert .pm-val{color:#f88;}' +
            '.page-metric.loading{opacity:0.6;}.page-metric.loading .pm-val{animation:pmPulse 1s infinite;}' +
            '@keyframes pmPulse{0%,100%{opacity:1;}50%{opacity:0.3;}}' +
            // Inline sync status in menu bar
            '@keyframes syncProgressAnim{0%{width:0%;}50%{width:100%;}100%{width:0%;}}' +
            '.api-status{position:relative;}.api-status.connected{background:rgba(50,200,100,0.2)!important;border-color:rgba(50,200,100,0.4)!important;}' +
            '.api-status.disconnected{background:rgba(255,100,100,0.2)!important;border-color:rgba(255,100,100,0.4)!important;animation:apiPulse 1s infinite;}' +
            '.api-status.checking{animation:apiPulse 0.5s infinite;}' +
            '@keyframes apiPulse{0%,100%{opacity:1;}50%{opacity:0.5;}}' +
            // Mobile hamburger and overlay
            // Mobile hamburger toggle (hidden by default, JS controls visibility)
            '.sidebar-toggle{display:none;position:fixed;top:0.75rem;left:0.75rem;z-index:1002;background:var(--surface-dark,#1a1a2e);border:1px solid var(--border-dark,#333);color:var(--text-primary,#e8e6d9);width:40px;height:40px;font-size:1.4rem;cursor:pointer;align-items:center;justify-content:center;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.3);transition:all 0.2s;}' +
            '.sidebar-toggle:hover{background:var(--surface-hover,#252540);transform:scale(1.05);}' +
            '.sidebar-toggle:active{transform:scale(0.95);}' +
            '.sidebar-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:999;opacity:0;transition:opacity 0.3s;}' +
            '.sidebar-overlay.active{display:block;opacity:1;}' +
            // Smart mobile mode (class-based, not just media query)
            '.mobile-mode .sidebar{transform:translateX(-100%);transition:transform 0.3s ease;z-index:1000;}' +
            '.mobile-mode .sidebar.open{transform:translateX(0);}' +
            '.mobile-mode .sidebar.mobile-hidden{transform:translateX(-100%);}' +
            '.mobile-mode .main,.mobile-mode .main-content{margin-left:0!important;}' +
            // Fallback media query for initial load before JS runs
            '@media(max-width:768px){.sidebar:not(.open){transform:translateX(-100%);}.main,.main-content{margin-left:0!important;}}';

        document.head.appendChild(s);
    }

    // ============================================
    // Mobile Toggle
    // ============================================

    // ============================================
    // Smart Mobile Detection
    // ============================================

    var _mobileMode = false;
    var _mobileInitialized = false;

    function isTouchDevice() {
        // Primary input must be touch (no hover + coarse pointer).
        // Capability-only checks ('ontouchstart', maxTouchPoints) wrongly
        // fire on touchscreen laptops where the mouse is the primary input.
        return !!(window.matchMedia &&
            window.matchMedia('(hover: none) and (pointer: coarse)').matches);
    }

    function isNarrowViewport() {
        return window.innerWidth <= 768;
    }

    function shouldUseMobileMode() {
        // Smart detection: touch device OR narrow viewport
        return isTouchDevice() || isNarrowViewport();
    }

    function applyMobileMode(enable) {
        var sidebar = document.getElementById('sidebar');
        var toggle = document.getElementById('sidebar-toggle');
        var overlay = document.getElementById('sidebar-overlay');
        var body = document.body;

        if (enable) {
            body.classList.add('mobile-mode');
            if (toggle) toggle.style.display = 'flex';
            if (sidebar && !sidebar.classList.contains('open')) {
                sidebar.classList.add('mobile-hidden');
            }
            _mobileMode = true;
        } else {
            body.classList.remove('mobile-mode');
            if (toggle) toggle.style.display = 'none';
            if (sidebar) {
                sidebar.classList.remove('mobile-hidden', 'open');
            }
            if (overlay) overlay.classList.remove('active');
            _mobileMode = false;
        }

        console.log('[Sidebar] Mobile mode:', enable ? 'ON' : 'OFF',
            '(touch:', isTouchDevice(), ', narrow:', isNarrowViewport(), ')');
    }

    function checkMobileMode() {
        var shouldBeMobile = shouldUseMobileMode();
        if (shouldBeMobile !== _mobileMode) {
            applyMobileMode(shouldBeMobile);
        }
    }

    function createMobileToggle() {
        // Don't create if already exists
        if (document.getElementById('sidebar-toggle')) return;

        // Create hamburger button (hidden by default, shown via applyMobileMode)
        var toggle = document.createElement('button');
        toggle.id = 'sidebar-toggle';
        toggle.className = 'sidebar-toggle';
        toggle.innerHTML = '☰';
        toggle.style.display = 'none';
        toggle.setAttribute('aria-label', 'Toggle menu');
        toggle.onclick = function() {
            toggleMobileSidebar();
        };
        document.body.appendChild(toggle);

        // Create overlay
        var overlay = document.createElement('div');
        overlay.id = 'sidebar-overlay';
        overlay.className = 'sidebar-overlay';
        overlay.onclick = function() {
            closeMobileSidebar();
        };
        document.body.appendChild(overlay);

        // Initial check
        checkMobileMode();

        // Listen for resize and orientation changes
        var resizeTimeout;
        window.addEventListener('resize', function() {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(checkMobileMode, 150);
        });

        window.addEventListener('orientationchange', function() {
            setTimeout(checkMobileMode, 300);
        });

        _mobileInitialized = true;
    }

    function toggleMobileSidebar() {
        var sidebar = document.getElementById('sidebar');
        var overlay = document.getElementById('sidebar-overlay');
        var toggle = document.getElementById('sidebar-toggle');
        if (!sidebar) return;

        var isOpen = sidebar.classList.contains('open');
        if (isOpen) {
            closeMobileSidebar();
        } else {
            sidebar.classList.remove('mobile-hidden');
            sidebar.classList.add('open');
            if (overlay) overlay.classList.add('active');
            if (toggle) toggle.innerHTML = '✕';
        }
    }

    function closeMobileSidebar() {
        var sidebar = document.getElementById('sidebar');
        var overlay = document.getElementById('sidebar-overlay');
        var toggle = document.getElementById('sidebar-toggle');
        if (sidebar) {
            sidebar.classList.remove('open');
            if (_mobileMode) sidebar.classList.add('mobile-hidden');
        }
        if (overlay) overlay.classList.remove('active');
        if (toggle) toggle.innerHTML = '☰';
    }

    // Close sidebar on nav item click (mobile)
    function handleMobileNavClick() {
        if (window.innerWidth <= 768) {
            closeMobileSidebar();
        }
    }

    // ============================================
    // Build Sidebar
    // ============================================

    async function buildSidebar() {
        var sidebar = document.getElementById('sidebar');
        if (!sidebar) return;

        // Pre-seed _menuDataCache from localStorage so getPageIcon() finds
        // module icons during the initial paint, before the API fetch lands.
        try {
            var preMenu = loadCachedMenu();
            if (preMenu && preMenu.categories) window._menuDataCache = preMenu;
        } catch (_) {}

        // Inject hybrid skin CSS (centralized for all modules)
        injectHybridSkin();

        injectStyles();
        hideUnknownEnabled = getHideUnknownPref();

        // v2.39.0: paint the cached sidebar HTML instantly. The API
        // fetch below overwrites it within ~200ms-2s with the fresh
        // structure + live LED states. Operators stop seeing a
        // "Loading…" flash on every page transition.
        var cachedHTML = loadCachedSidebarHTML();
        if (cachedHTML) {
            sidebar.innerHTML = cachedHTML;
            console.log('[Sidebar] Instant render from HTML cache');
        } else {
            sidebar.innerHTML = '<div class="sidebar-header"><a href="/"><span class="logo-icon">🔒</span><div><span class="logo">SECUBOX</span><span class="logo-version">🚀 ' + VERSION + '</span></div></a>' +
                '<div class="header-leds-metrics" id="header-leds-metrics">' +
                '<div class="led-metric-row sync-status" id="sync-status-row"><div class="sync-led" id="sync-led">⏳</div><span class="led-metric-val sync-val" id="lm-sync" title="Data sync status">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,3)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-3"></div><span class="led-metric-val" id="lm-sec">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,2)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-2"></div><span class="led-metric-val" id="lm-svc">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,1)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-1"></div><span class="led-metric-val" id="lm-hw">--</span></div>' +
                '</div></div>' +
                '<div class="sidebar-nav"><div class="nav-section"><div class="nav-section-title"><span>Loading...</span></div></div></div>';
        }

        try {
            var token = localStorage.getItem('sbx_token');
            var headers = token ? { 'Authorization': 'Bearer ' + token } : {};
            var data = null;
            var fromCache = false;

            // Strategy: Try cache first for instant display, then update from API
            var cachedMenu = loadCachedMenu();

            // Use safe fetch with timeout (API can be slow during warmup)
            var result = await safeFetch(MENU_API, { headers: headers }, 20000);

            if (result.ok && result.data && result.data.categories) {
                data = result.data;
                saveCachedMenu(data);  // Update cache with fresh data
                console.log('[Sidebar] Menu from API');
            } else if (cachedMenu && cachedMenu.categories) {
                // API failed but we have cache - use it
                data = cachedMenu;
                fromCache = true;
                console.log('[Sidebar] Menu from cache (API failed: ' + (result.error || 'unknown') + ')');
            } else if (result.status === 401) {
                window.location.href = '/login.html';
                return;
            } else {
                console.warn('[Sidebar] Menu API error:', result.error);
                throw new Error('Menu API: ' + (result.error || 'No data'));
            }

            if (!data || !data.categories) {
                console.warn('[Sidebar] Invalid menu structure:', data);
                throw new Error('Invalid menu structure');
            }

            // Expose for getPageIcon() fallback (top page bar icon lookup).
            try { window._menuDataCache = data; } catch (_) {}

            // Refresh top page bar icon now that fresh menu data is in.
            try {
                var gmbIcon = document.querySelector('#global-menu-bar .menu-icon');
                if (gmbIcon) {
                    var freshIcon = getPageIcon(window.location.pathname);
                    if (freshIcon && freshIcon !== gmbIcon.textContent) {
                        gmbIcon.textContent = freshIcon;
                    }
                }
            } catch (_) {}

            ALL_MODULES = extractModulesFromMenu(data);
            console.log('[Sidebar ' + VERSION + '] ' + ALL_MODULES.length + ' modules');

            var curPath = window.location.pathname;
            var user = getCurrentUser();

            // Load pre-cache but keep items as checking until verified
            var preCache = loadPreCache();

            var menuHTML = '';
            data.categories.forEach(function(cat) {
                var hasActive = cat.items.some(function(i) {
                    return curPath === i.path || (i.path !== '/' && curPath.startsWith(i.path));
                });
                var collapsed = !hasActive;

                menuHTML += '<div class="nav-section' + (collapsed ? ' collapsed' : '') + '">' +
                    '<div class="nav-section-title" onclick="this.closest(\'.nav-section\').classList.toggle(\'collapsed\');this.querySelector(\'.toggle-icon\').textContent=this.closest(\'.nav-section\').classList.contains(\'collapsed\')?\'\u25B6\':\'\u25BC\';">' +
                    '<span><span class="cat-icon">' + cat.icon + '</span> ' + cat.name.toUpperCase() + '</span>' +
                    '<span class="toggle-icon">' + (collapsed ? '\u25B6' : '\u25BC') + '</span></div>' +
                    '<div class="nav-items">';

                cat.items.forEach(function(item) {
                    var isActive = curPath === item.path || (item.path !== '/' && curPath.startsWith(item.path));
                    var mod = getModuleFromPath(item.path) || '';  // Ensure consistent key (never null)

                    // Start with checking (blue) - will be updated when actual check completes
                    var initialLED = LED_EMOJI.checking;
                    var initialTitle = 'Checking...';

                    // Only track modules with valid IDs
                    if (mod) {
                        // Use cache only if fresh, otherwise set to checking
                        if (preCache && preCache[mod] && preCache[mod].status !== 'checking') {
                            initialLED = LED_EMOJI[preCache[mod].status] || LED_EMOJI.unknown;
                            initialTitle = preCache[mod].msg || preCache[mod].status;
                            healthCache[mod] = preCache[mod];
                        } else {
                            // IMPORTANT: Add to healthCache as 'checking' so filter shows them
                            healthCache[mod] = { status: 'checking', msg: 'Checking...', timestamp: Date.now() };
                        }
                    }

                    // Get version/dev_stage for badge and tooltip
                    var devStage = (preCache && preCache[mod]) ? preCache[mod].dev_stage : null;
                    var version = (preCache && preCache[mod]) ? preCache[mod].version : null;
                    var devBadge = getDevStageBadge(devStage);
                    var versionTip = getVersionTooltip(version, devStage);
                    var fullTitle = versionTip ? (initialTitle + ' | ' + versionTip) : initialTitle;

                    menuHTML += '<a href="' + item.path + '" class="nav-item' + (isActive ? ' active' : '') + '" data-module="' + mod + '" onclick="return SecuBoxSidebar.navClick(event,\'' + mod + '\',\'' + item.path + '\')">' +
                        '<span class="icon">' + item.icon + '</span>' +
                        '<span>' + item.name + '</span>' +
                        devBadge +
                        '<span class="status-led" title="' + fullTitle + '">' + initialLED + '</span></a>';
                });

                menuHTML += '</div></div>';
            });

            sidebar.innerHTML = '<div class="sidebar-header"><a href="/"><span class="logo-icon">🔒</span><div><span class="logo">SECUBOX</span><span class="logo-version">🚀 ' + VERSION + '</span></div></a>' +
                '<div class="header-leds-metrics" id="header-leds-metrics">' +
                '<div class="led-metric-row sync-status" id="sync-status-row"><div class="sync-led" id="sync-led">⏳</div><span class="led-metric-val sync-val" id="lm-sync" title="Data sync status">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,3)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-3"></div><span class="led-metric-val" id="lm-sec">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,2)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-2"></div><span class="led-metric-val" id="lm-svc">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,1)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-1"></div><span class="led-metric-val" id="lm-hw">--</span></div>' +
                '</div></div>' +
                '<div class="sidebar-nav">' + menuHTML + '</div>' +
                '<div class="sidebar-footer">' +
                '<div class="sidebar-clock" id="sidebar-clock">00:00:00</div>' +
                '<div class="sidebar-user"><span class="sidebar-user-avatar">👤</span><div class="sidebar-user-info"><div class="sidebar-user-name">' + user + '</div><div class="sidebar-user-role">OPERATOR</div></div><button class="sidebar-logout" onclick="localStorage.removeItem(\'sbx_token\');window.location.href=\'/login.html\';">EXIT</button></div>' +
                '</div>';

            // v2.39.0: persist this fully-rendered HTML so the next
            // page transition can paint it instantly (see
            // loadCachedSidebarHTML() at the top of loadSidebar).
            saveCachedSidebarHTML(sidebar.innerHTML);

            var clock = document.getElementById('sidebar-clock');
            if (clock) startClock(clock);

            // If pre-cache exists, display immediately then refresh in background
            if (preCache && Object.keys(preCache).length > 0) {
                console.log('[Sidebar ' + VERSION + '] Using pre-cache, async refresh in background');
                updateStatusIndicator();
                applySorting();
                // Background refresh after 2s (async, no blue flicker)
                setTimeout(function() {
                    refreshStaleHealth();
                }, 2000);
            } else {
                // No cache - start health checks
                checkAllHealth(false).then(updateLEDs);
                setTimeout(applySorting, 300);
            }

            // Periodic refresh (background, stale modules only)
            setInterval(function() {
                refreshStaleHealth();
            }, HEALTH_REFRESH_INTERVAL);

        } catch (e) {
            console.error('[Sidebar] Build error:', e);
            // Show fallback sidebar but allow retry
            showFallbackSidebar();
        }

        // Start heartbeat monitor
        startHeartbeat();

        // Create mobile hamburger toggle
        createMobileToggle();
    }

    // ============================================
    // Public API
    // ============================================

    window.SecuBoxSidebar = {
        build: buildSidebar,
        toggleTheme: function() { /* Dark theme only */ },
        logout: function() {
            localStorage.removeItem('sbx_token');
            localStorage.removeItem('secubox_token');
            window.location.href = '/login.html';
        },
        // Resilience functions
        forceReinject: function() {
            retryCount = 0;
            console.log('[Sidebar] Manual reinject requested');
            return reinjectSidebar();
        },
        isHealthy: function() { return sidebarHealthy; },
        checkHealth: checkAllHealth,
        checkModule: checkModuleHealth,
        updateLEDs: updateLEDs,
        navClick: navClick,
        preflightCheck: preflightCheck,
        getCache: function() { return healthCache; },
        toggleHideUnknown: toggleHideUnknown,
        refreshStale: refreshStaleHealth,
        showStatusPanel: showStatusPanel,
        showStripPopup: showStripPopup,
        hideStripPopup: hideStripPopup,
        showHwLedTooltip: showHwLedTooltip,
        hideHwLedTooltip: hideHwLedTooltip,
        checkApiStatus: checkApiStatus,
        loadPageMetrics: loadPageMetrics,
        toggleMobile: toggleMobileSidebar,
        closeMobile: closeMobileSidebar,
        isMobileMode: function() { return _mobileMode; },
        isTouchDevice: isTouchDevice,
        checkMobileMode: checkMobileMode,
        getAllModules: function() { return ALL_MODULES; },
        forceRefresh: function(mod) {
            if (mod) {
                // Keep previous status for visual continuity, mark as checking
                var prev = healthCache[mod];
                healthCache[mod] = {
                    status: 'checking',
                    msg: 'Checking...',
                    timestamp: Date.now(),
                    _prevStatus: prev ? prev.status : null
                };
                updateAllLEDs();
                return checkModuleHealth(mod).then(function(h) {
                    healthCache[mod] = h;
                    updateLEDs(healthCache);
                    return h;
                });
            } else {
                // DON'T clear cache - preserve green/yellow/red while refreshing
                // Just invalidate timestamps to force recheck
                localStorage.removeItem(HEALTH_CACHE_KEY);
                Object.keys(healthCache).forEach(function(m) {
                    var prev = healthCache[m];
                    var prevStatus = prev ? prev.status : null;
                    // Keep visual status, mark as needing refresh
                    healthCache[m] = {
                        status: prevStatus && prevStatus !== 'checking' && prevStatus !== 'unknown'
                            ? prevStatus : 'checking',
                        msg: 'Rechecking...',
                        timestamp: 0, // Force stale
                        _rechecking: true,
                        _prevStatus: prevStatus  // Store for filtering
                    };
                });
                updateAllLEDs();
                return checkAllHealth(true).then(updateLEDs);
            }
        }
    };

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildSidebar);
    else buildSidebar();
})();
