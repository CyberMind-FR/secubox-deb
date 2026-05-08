/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SECUBOX SIDEBAR — Health-Aware Navigation + Hybrid Skin Injector
 *  v2.25.2 — Smart Strip with persistent histogram cache (60 samples, 1h TTL)
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
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function() {
    const MENU_API = '/api/v1/hub/public/menu';
    const BATCH_HEALTH_API = '/api/v1/hub/public/health-batch';
    const VERSION = 'v2.32.0';

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
    const SORT_PREF_KEY = 'sbx_health_sort';

    const HEALTH_CACHE_TTL = 300000;       // 5 min - cache validity
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

    // Page icons for menu bar
    const PAGE_ICONS = {
        '/': '🏠', '/hub/': '🏠', '/soc/': '🛡️', '/waf/': '🔥', '/crowdsec/': '👁️',
        '/wireguard/': '🔐', '/netdata/': '📊', '/system/': '⚙️', '/vhost/': '🌐',
        '/dpi/': '🔍', '/netmodes/': '🔀', '/qos/': '📶', '/nac/': '🚫',
        '/auth/': '🔑', '/cdn/': '💾', '/mediaflow/': '🎬', '/portal/': '🚪',
        '/metrics/': '📈', '/certs/': '📜', '/vortex-dns/': '🌀', '/eye-remote/': '👁️'
    };

    function getPageIcon(path) {
        for (var p in PAGE_ICONS) {
            if (path === p || path.startsWith(p)) return PAGE_ICONS[p];
        }
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
                '<div class="strip-module" data-mod="AUTH" data-metric="cpu" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><div class="strip-led" style="background:#C04E24"></div><span class="strip-val" id="ss-cpu">--</span></div>' +
                '<div class="strip-module" data-mod="WALL" data-metric="mem" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><div class="strip-led" style="background:#9A6010"></div><span class="strip-val" id="ss-mem">--</span></div>' +
                '<div class="strip-module" data-mod="BOOT" data-metric="disk" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><div class="strip-led" style="background:#803018"></div><span class="strip-val" id="ss-disk">--</span></div>' +
                '<div class="strip-module" data-mod="MIND" data-metric="load" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><div class="strip-led" style="background:#3D35A0"></div><span class="strip-val" id="ss-load">--</span></div>' +
                '<div class="strip-module" data-mod="ROOT" data-metric="temp" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><div class="strip-led" style="background:#0A5840"></div><span class="strip-val" id="ss-temp">--</span></div>' +
                '<div class="strip-module" data-mod="MESH" data-metric="net" onmouseenter="SecuBoxSidebar.showStripPopup(this)" onmouseleave="SecuBoxSidebar.hideStripPopup()"><div class="strip-led" style="background:#104A88"></div><span class="strip-val" id="ss-net">--</span></div>' +
                '</div>' +
                // Popup container for hover details
                '<div class="strip-popup" id="strip-popup"></div>' +
                '</div><div class="menu-right">' +
                '<div class="hw-led-tooltip" id="hw-led-tooltip"></div>' +
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
            loadStatusBarData();
            // Start LED pulse sync
            startLedPulseSync();
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

    // Metrics history for sparkline histograms with localStorage persistence
    const STRIP_HISTORY_MAX = 60;  // 60 samples = ~30 min at 30s refresh
    const STRIP_CACHE_KEY = 'sbx_strip_history';
    const STRIP_CACHE_TTL = 3600000;  // 1 hour max age

    // Load cached history from localStorage
    function loadStripHistoryCache() {
        try {
            var cached = localStorage.getItem(STRIP_CACHE_KEY);
            if (cached) {
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

    // Module metadata for popup with icons
    const STRIP_MODULE_INFO = {
        AUTH: { color: '#C04E24', metric: 'cpu', label: 'CPU Usage', unit: '%', icon: '/eye-remote/assets/icons/auth-22.png', desc: 'Authentication module - Processor utilization' },
        WALL: { color: '#9A6010', metric: 'mem', label: 'Memory', unit: '%', icon: '/eye-remote/assets/icons/wall-22.png', desc: 'Firewall module - RAM utilization' },
        BOOT: { color: '#803018', metric: 'disk', label: 'Disk', unit: '%', icon: '/eye-remote/assets/icons/boot-22.png', desc: 'Boot module - Storage utilization' },
        MIND: { color: '#3D35A0', metric: 'load', label: 'Load', unit: 'x', icon: '/eye-remote/assets/icons/mind-22.png', desc: 'AI module - System load average' },
        ROOT: { color: '#0A5840', metric: 'temp', label: 'Temp', unit: '°C', icon: '/eye-remote/assets/icons/root-22.png', desc: 'Core module - CPU temperature' },
        MESH: { color: '#104A88', metric: 'net', label: 'Signal', unit: 'dB', icon: '/eye-remote/assets/icons/mesh-22.png', desc: 'Network module - WiFi signal strength' }
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
            '<img class="popup-icon" src="' + info.icon + '" alt="' + mod + '" onerror="this.style.display=\'none\'">' +
            '<span class="popup-mod" style="color:' + info.color + '">' + mod + '</span>' +
            '<span class="popup-label">' + info.label + '</span>' +
            '</div>' +
            '<div class="popup-value ' + statusClass + '">' + displayVal + '<span class="popup-unit">' + info.unit + '</span></div>' +
            '<div class="popup-sparkline">' + sparkline + '</div>' +
            '<div class="popup-desc">' + info.desc + '</div>';

        // Position popup below the element, centered
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

        // Position tooltip - check if inside sidebar (left < 220px)
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
            var hwColors = { ok: '#00dd44', warn: '#ffb347', error: '#ff4466' };
            var hwLed1 = document.getElementById('hw-led-1');
            var hwLed2 = document.getElementById('hw-led-2');
            var hwLed3 = document.getElementById('hw-led-3');

            if (hwLed1 && hwLed2 && hwLed3) {
                var baseOpacity = 0.7 + 0.3 * Math.sin(ledPulsePhase * Math.PI / 10);
                var glowSize = 4 + (ledPulsePhase % 6);

                // Step 1: Write to shadow buffer based on health level
                // LED1=Hardware, LED2=Services, LED3=Security (bottom to top)
                if (systemHealthLevel === 'error') {
                    ledBufferShadow = { led1: hwColors.ok, led2: hwColors.warn, led3: hwColors.error };
                } else if (systemHealthLevel === 'warn') {
                    ledBufferShadow = { led1: hwColors.ok, led2: hwColors.warn, led3: hwColors.warn };
                } else {
                    ledBufferShadow = { led1: hwColors.ok, led2: hwColors.ok, led3: hwColors.ok };
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

                [hwLed1, hwLed2, hwLed3].forEach(function(led) {
                    led.style.opacity = baseOpacity;
                    led.style.boxShadow = '0 0 ' + glowSize + 'px ' + led.style.background;
                });
            }

            // Update top bar health bumper
            var topHealth = document.getElementById('gmb-health-bumper');
            if (topHealth) {
                topHealth.style.opacity = opacity;
            }
        }, 100);
    }

    // Load status bar data from API
    async function loadStatusBarData() {
        var token = localStorage.getItem('sbx_token');
        var headers = token ? { 'Authorization': 'Bearer ' + token } : {};

        try {
            // Load dashboard for version and uptime
            var res = await fetch('/api/v1/hub/dashboard', { headers: headers });
            if (res.ok) {
                var data = await res.json();
                if (data.build_info && data.build_info.version) {
                    var el = document.getElementById('gsb-version');
                    if (el) el.textContent = 'v' + data.build_info.version;
                }
                if (data.uptime) {
                    var el = document.getElementById('gsb-uptime');
                    if (el) el.textContent = data.uptime;
                }
            }

            // Load boot mode
            var modeRes = await fetch('/api/v1/hub/boot_mode', { headers: headers });
            if (modeRes.ok) {
                var modeData = await modeRes.json();
                var modeEl = document.getElementById('gsb-mode');
                if (modeEl && modeData.mode) {
                    modeEl.textContent = modeData.mode.charAt(0).toUpperCase() + modeData.mode.slice(1);
                    modeEl.className = 'status-value ' + (modeData.mode === 'kiosk' ? 'info' : 'warn');
                }
            }

            // Load auth mode
            var authRes = await fetch('/api/v1/hub/auth_mode', { headers: headers });
            if (authRes.ok) {
                var authData = await authRes.json();
                var authEl = document.getElementById('gsb-auth');
                if (authEl && authData.mode) {
                    authEl.textContent = authData.mode;
                    authEl.className = 'status-value ' + (authData.mode.toLowerCase() === 'zkp' ? 'ok' : '');
                }
            }

            // Load CPU, memory, and disk from dashboard
            var dashRes = await fetch('/api/v1/hub/dashboard', { headers: headers });
            if (dashRes.ok) {
                var dashData = await dashRes.json();
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

            // Load health summary from batch endpoint
            var healthRes = await fetch('/api/v1/hub/public/health-batch', { headers: headers });
            if (healthRes.ok) {
                var healthData = await healthRes.json();
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
                    }

                    // LED2 (Services): ok/total
                    if (lmSvc) {
                        lmSvc.textContent = ok + '/' + total;
                        lmSvc.className = 'led-metric-val ' + (err > 0 ? 'error' : warn > 0 ? 'warn' : 'ok');
                    }

                    // LED3 (Security): fetch bans from CrowdSec
                    if (lmSec) {
                        // Will be updated by separate security fetch
                        lmSec.textContent = '...';
                    }
                }
            }

            // Fetch security metrics (CrowdSec bans)
            try {
                var secRes = await fetch('/api/v1/crowdsec/stats', { headers: headers });
                if (secRes.ok) {
                    var secData = await secRes.json();
                    var lmSec = document.getElementById('lm-sec');
                    if (lmSec) {
                        var bans = secData.active_bans || secData.decisions || 0;
                        var alerts = secData.alerts_today || 0;
                        lmSec.textContent = bans + 'B';
                        lmSec.title = bans + ' bans, ' + alerts + ' alerts today';
                        // Blue if actively blocking, else based on alert level
                        if (bans > 20) {
                            lmSec.className = 'led-metric-val info';  // Blue - active mitigation
                        } else if (alerts > 50) {
                            lmSec.className = 'led-metric-val error';
                        } else if (alerts > 10) {
                            lmSec.className = 'led-metric-val warn';
                        } else {
                            lmSec.className = 'led-metric-val ok';
                        }
                    }
                }
            } catch (e) {
                var lmSec = document.getElementById('lm-sec');
                if (lmSec) lmSec.textContent = '?';
            }
        } catch (e) {
            console.log('[Sidebar] Status bar data error:', e);
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
        var fallbackPage = getPagePath(mod);

        if (healthCheckInProgress[mod]) {
            return healthCache[mod] || { status: 'checking', msg: 'In progress', timestamp: Date.now() };
        }
        healthCheckInProgress[mod] = true;

        try {
            var token = localStorage.getItem('sbx_token');
            var headers = token ? { 'Authorization': 'Bearer ' + token } : {};
            var ctrl = new AbortController();
            var tm = setTimeout(function() { ctrl.abort(); }, HEALTH_REQUEST_TIMEOUT);

            try {
                var res = await fetch(endpoint, { headers: headers, signal: ctrl.signal });
                clearTimeout(tm);

                if (res.ok) {
                    var ct = res.headers.get('content-type') || '';
                    if (ct.includes('application/json')) {
                        var text = await res.text();
                        try {
                            var d = JSON.parse(text);
                            healthCheckInProgress[mod] = false;
                            // Extract version and dev_stage from standard health response
                            var version = d.version || null;
                            var devStage = d.dev_stage || 'production';
                            if (d.status === 'ok' || d.healthy === true || d.status === 'healthy') {
                                return { status: 'ok', msg: d.message || 'OK', version: version, dev_stage: devStage, timestamp: Date.now() };
                            }
                            if (d.status === 'degraded' || d.status === 'warn' || d.warning) {
                                return { status: 'warn', msg: d.message || 'Degraded', version: version, dev_stage: devStage, timestamp: Date.now() };
                            }
                            return { status: 'error', msg: d.message || d.status || 'Error', version: version, dev_stage: devStage, timestamp: Date.now() };
                        } catch (parseErr) {
                            // JSON parse failed - treat as unknown
                            healthCheckInProgress[mod] = false;
                            return { status: 'unknown', msg: 'Invalid JSON', timestamp: Date.now() };
                        }
                    } else {
                        // HTML response - no health API
                        healthCheckInProgress[mod] = false;
                        return { status: 'unknown', msg: 'No health API', timestamp: Date.now() };
                    }
                }

                // Non-200 response = error (no fallback)
                healthCheckInProgress[mod] = false;
                if (res.status === 404) {
                    return { status: 'error', msg: 'No API', timestamp: Date.now() };
                }
                return { status: 'error', msg: 'HTTP ' + res.status, timestamp: Date.now() };

            } catch (fetchError) {
                clearTimeout(tm);
                healthCheckInProgress[mod] = false;
                if (fetchError.name === 'AbortError') {
                    return { status: 'error', msg: 'Timeout', timestamp: Date.now() };
                }
                return { status: 'error', msg: 'Network error', timestamp: Date.now() };
            }
        } catch (e) {
            healthCheckInProgress[mod] = false;
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

        for (var i = 0; i < modules.length; i += BATCH_SIZE) {
            var batch = modules.slice(i, i + BATCH_SIZE);
            var results = await Promise.allSettled(batch.map(function(mod) {
                return checkModuleHealth(mod);
            }));

            results.forEach(function(result, idx) {
                var mod = batch[idx];
                if (result.status === 'fulfilled') {
                    healthCache[mod] = result.value;
                } else {
                    healthCache[mod] = { status: 'error', msg: 'Check failed', timestamp: Date.now() };
                }
            });

            // Update LEDs after each batch
            updateAllLEDs();
        }

        return healthCache;
    }

    async function refreshStaleHealth() {
        var now = Date.now();
        var stale = [];

        ALL_MODULES.forEach(function(mod) {
            var c = healthCache[mod];
            if (!c || (now - (c.timestamp || 0)) > HEALTH_REFRESH_INTERVAL) stale.push(mod);
        });

        if (stale.length === 0) return;

        // Incremental update - update each LED as result comes in
        for (var i = 0; i < stale.length; i += BATCH_SIZE) {
            var batch = stale.slice(i, i + BATCH_SIZE);
            await Promise.allSettled(batch.map(async function(mod) {
                var result = await checkModuleHealth(mod);
                healthCache[mod] = result;
                // Update single LED immediately
                var item = document.querySelector('.nav-item[data-module="' + mod + '"]');
                if (item) updateSingleLED(item, result);
            }));
        }

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
            '.health-toast{position:fixed;top:1rem;right:1rem;z-index:10000;animation:toastIn 0.3s;}.health-toast-content{display:flex;align-items:center;gap:0.5rem;background:rgba(255,68,68,0.95);color:#fff;padding:0.5rem 1rem;border-radius:8px;font-size:0.8rem;}@keyframes toastIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}';
        document.head.appendChild(s);
    }

    // ============================================
    // Build Sidebar
    // ============================================

    async function buildSidebar() {
        var sidebar = document.getElementById('sidebar');
        if (!sidebar) return;

        // Inject hybrid skin CSS (centralized for all modules)
        injectHybridSkin();

        injectStyles();
        hideUnknownEnabled = getHideUnknownPref();

        sidebar.innerHTML = '<div class="sidebar-header"><a href="/"><span class="logo-icon">🔒</span><div><span class="logo">SECUBOX</span><span class="logo-version">🚀 ' + VERSION + '</span></div></a>' +
            '<div class="header-leds-metrics" id="header-leds-metrics">' +
            '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,3)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-3"></div><span class="led-metric-val" id="lm-sec">--</span></div>' +
            '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,2)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-2"></div><span class="led-metric-val" id="lm-svc">--</span></div>' +
            '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,1)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-1"></div><span class="led-metric-val" id="lm-hw">--</span></div>' +
            '</div></div>' +
            '<div class="sidebar-nav"><div class="nav-section"><div class="nav-section-title"><span>Loading...</span></div></div></div>';

        try {
            var token = localStorage.getItem('sbx_token');
            var headers = token ? { 'Authorization': 'Bearer ' + token } : {};
            var res = await fetch(MENU_API, { headers: headers });
            if (res.status === 401) { window.location.href = '/portal/login.html'; return; }

            var data = await res.json();
            if (!data || !data.categories) throw new Error('Invalid menu');

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
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,3)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-3"></div><span class="led-metric-val" id="lm-sec">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,2)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-2"></div><span class="led-metric-val" id="lm-svc">--</span></div>' +
                '<div class="led-metric-row" onmouseenter="SecuBoxSidebar.showHwLedTooltip(this,1)" onmouseleave="SecuBoxSidebar.hideHwLedTooltip()"><div class="hw-led-v" id="hw-led-1"></div><span class="led-metric-val" id="lm-hw">--</span></div>' +
                '</div></div>' +
                '<div class="sidebar-nav">' + menuHTML + '</div>' +
                '<div class="sidebar-footer">' +
                '<div class="sidebar-clock" id="sidebar-clock">00:00:00</div>' +
                '<div class="sidebar-user"><span class="sidebar-user-avatar">👤</span><div class="sidebar-user-info"><div class="sidebar-user-name">' + user + '</div><div class="sidebar-user-role">OPERATOR</div></div><button class="sidebar-logout" onclick="localStorage.removeItem(\'sbx_token\');window.location.href=\'/portal/login.html\';">EXIT</button></div>' +
                '</div>';

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
            console.error('[Sidebar] Error:', e);
            sidebar.innerHTML = '<div class="sidebar-header"><a href="/"><span class="logo-icon">🔒</span><span class="logo">SECUBOX</span></a></div><div class="sidebar-nav"><a href="/" class="nav-item">Dashboard</a></div>';
        }
    }

    // ============================================
    // Public API
    // ============================================

    window.SecuBoxSidebar = {
        build: buildSidebar,
        toggleTheme: function() { /* Removed - hybrid-skin is the only theme */ },
        logout: function() {
            localStorage.removeItem('sbx_token');
            localStorage.removeItem('secubox_token');
            window.location.href = '/portal/login.html';
        },
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
