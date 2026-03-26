/**
 * ═══════════════════════════════════════════════════════════════
 *  SECUBOX SIDEBAR — CRT P31 Phosphor Theme
 *  Dynamic menu with VT100 aesthetic
 *  Includes light/dark theme toggle
 *
 *  Usage:
 *    <nav class="sidebar" id="sidebar"></nav>
 *    <script src="/shared/sidebar.js"></script>
 * ═══════════════════════════════════════════════════════════════
 */

(function() {
    const MENU_API = '/api/v1/hub/menu';
    const VERSION = 'v1.2.0';
    const THEME_KEY = 'sbx_theme';

    // Theme configuration
    const THEMES = {
        light: {
            css: '/shared/crt-light.css',
            sidebar: '/shared/sidebar-light.css',
            icon: '☀️',
            label: 'LIGHT'
        },
        dark: {
            css: '/shared/crt-system.css',
            sidebar: '/shared/sidebar.css',
            icon: '🌙',
            label: 'DARK'
        }
    };

    // Get current theme from localStorage or default to light
    function getCurrentTheme() {
        return localStorage.getItem(THEME_KEY) || 'light';
    }

    // Set theme and update CSS links
    function setTheme(theme) {
        localStorage.setItem(THEME_KEY, theme);
        const config = THEMES[theme];

        // Find and update CSS links
        const links = document.querySelectorAll('link[rel="stylesheet"]');
        links.forEach(link => {
            const href = link.getAttribute('href');
            if (href.includes('crt-light.css') || href.includes('crt-system.css')) {
                link.setAttribute('href', config.css);
            }
            if (href.includes('sidebar-light.css') || href.includes('sidebar.css')) {
                // Only update if it's a sidebar CSS (not the main sidebar.js)
                if (href.endsWith('.css')) {
                    link.setAttribute('href', config.sidebar);
                }
            }
        });

        // Update body class
        document.body.classList.remove('crt-light', 'crt-body', 'crt-scanlines');
        if (theme === 'light') {
            document.body.classList.add('crt-light');
        } else {
            document.body.classList.add('crt-body', 'crt-scanlines');
        }

        // Update toggle button if exists
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            const otherTheme = theme === 'light' ? 'dark' : 'light';
            toggleBtn.innerHTML = `<span class="theme-icon">${THEMES[otherTheme].icon}</span>`;
            toggleBtn.title = `Switch to ${otherTheme} mode`;
        }

        // Update inline CSS variables for pages with inline styles
        updateInlineThemeVars(theme);
    }

    // Update CSS variables for inline styles
    function updateInlineThemeVars(theme) {
        const root = document.documentElement;
        if (theme === 'light') {
            // Light theme - mint green palette
            root.style.setProperty('--tube-light', '#e8f5e9');
            root.style.setProperty('--tube-pale', '#c8e6c9');
            root.style.setProperty('--tube-soft', '#a5d6a7');
            root.style.setProperty('--tube-mist', '#81c784');
            root.style.setProperty('--tube-dark', '#1b3d1c');
            root.style.setProperty('--tube-black', '#e8f5e9');
            root.style.setProperty('--tube-deep', '#c8e6c9');
            root.style.setProperty('--tube-bezel', '#a5d6a7');
            root.style.setProperty('--tube-muted', '#81c784');
            root.style.setProperty('--p31-peak', '#00dd44');
            root.style.setProperty('--p31-hot', '#00ff55');
            root.style.setProperty('--p31-mid', '#009933');
            root.style.setProperty('--p31-dim', '#006622');
            root.style.setProperty('--p31-ghost', '#003311');
            root.style.setProperty('--p31-decay', '#cc7722');
            root.style.setProperty('--p31-decay-dim', '#996611');
            root.style.setProperty('--accent', '#00dd44');
            // Legacy mappings
            root.style.setProperty('--bg-dark', '#e8f5e9');
            root.style.setProperty('--bg-card', '#c8e6c9');
            root.style.setProperty('--bg-sidebar', '#e8f5e9');
            root.style.setProperty('--border', '#a5d6a7');
            root.style.setProperty('--text', '#1b3d1c');
            root.style.setProperty('--text-dim', '#006622');
            root.style.setProperty('--primary', '#00dd44');
            root.style.setProperty('--cyan', '#00dd44');
            root.style.setProperty('--green', '#00dd44');
            // C3BOX mesh dashboard variables
            root.style.setProperty('--bg', '#e8f5e9');
            root.style.setProperty('--fg', '#006622');
            root.style.setProperty('--dim', '#c8e6c9');
        } else {
            // Dark theme - blue-tinted palette (matching crt-system.css)
            root.style.setProperty('--tube-light', '#0a0e14');
            root.style.setProperty('--tube-pale', '#1a1f2e');
            root.style.setProperty('--tube-soft', '#252a3a');
            root.style.setProperty('--tube-mist', '#3a4050');
            root.style.setProperty('--tube-dark', '#66ffaa');
            root.style.setProperty('--tube-black', '#0a0e14');
            root.style.setProperty('--tube-deep', '#1a1f2e');
            root.style.setProperty('--tube-bezel', '#252a3a');
            root.style.setProperty('--tube-muted', '#3a4050');
            root.style.setProperty('--p31-peak', '#33ff66');
            root.style.setProperty('--p31-hot', '#66ffaa');
            root.style.setProperty('--p31-mid', '#22cc44');
            root.style.setProperty('--p31-dim', '#0f8822');
            root.style.setProperty('--p31-ghost', '#0a4420');
            root.style.setProperty('--p31-decay', '#ffb347');
            root.style.setProperty('--p31-decay-dim', '#cc7722');
            root.style.setProperty('--accent', '#00ff88');
            // Legacy mappings
            root.style.setProperty('--bg-dark', '#0a0e14');
            root.style.setProperty('--bg-card', '#1a1f2e');
            root.style.setProperty('--bg-sidebar', '#0a0e14');
            root.style.setProperty('--border', '#252a3a');
            root.style.setProperty('--text', '#66ffaa');
            root.style.setProperty('--text-dim', '#22cc44');
            root.style.setProperty('--primary', '#33ff66');
            root.style.setProperty('--cyan', '#33ff66');
            root.style.setProperty('--green', '#33ff66');
            // C3BOX mesh dashboard variables
            root.style.setProperty('--bg', '#0a0e14');
            root.style.setProperty('--fg', '#33ff66');
            root.style.setProperty('--dim', '#1a1f2e');
        }
    }

    // Toggle between themes
    function toggleTheme() {
        const current = getCurrentTheme();
        const next = current === 'light' ? 'dark' : 'light';
        setTheme(next);
    }

    // Inject additional CRT styles
    const style = document.createElement('style');
    style.textContent = `
        @import url('https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

        .theme-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.5rem;
            margin: 0.5rem 0;
            border: 1px solid var(--p31-dim, #006622);
            border-radius: 4px;
            background: transparent;
            color: var(--p31-mid, #009933);
            cursor: pointer;
            font-family: inherit;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            transition: all 0.2s;
            width: 100%;
        }
        .theme-toggle:hover {
            border-color: var(--p31-peak, #00dd44);
            color: var(--p31-peak, #00dd44);
            background: rgba(0, 221, 68, 0.1);
        }
        .theme-icon {
            font-size: 1.1rem;
        }
    `;
    document.head.appendChild(style);

    // Clock updater
    function startClock(el) {
        function tick() {
            const d = new Date();
            const H = String(d.getHours()).padStart(2, '0');
            const M = String(d.getMinutes()).padStart(2, '0');
            const S = String(d.getSeconds()).padStart(2, '0');
            el.textContent = H + ':' + M + ':' + S;
        }
        tick();
        setInterval(tick, 1000);
    }

    // Toggle section collapse
    function toggleSection(e) {
        const section = e.currentTarget.closest('.nav-section');
        if (section) {
            section.classList.toggle('collapsed');
            const icon = e.currentTarget.querySelector('.toggle-icon');
            if (icon) {
                icon.textContent = section.classList.contains('collapsed') ? '▶' : '▼';
            }
        }
    }

    // Mobile toggle
    function toggleMobile() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.toggle('open');
        }
    }

    // Logout handler
    function logout() {
        localStorage.removeItem('sbx_token');
        localStorage.removeItem('sbx_user');
        window.location.href = '/portal/login.html';
    }

    // Get current user from token
    function getCurrentUser() {
        try {
            const token = localStorage.getItem('sbx_token');
            if (token) {
                const payload = JSON.parse(atob(token.split('.')[1]));
                return payload.sub || 'admin';
            }
        } catch (e) {}
        return 'admin';
    }

    async function loadSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (!sidebar) return;

        const currentTheme = getCurrentTheme();
        const otherTheme = currentTheme === 'light' ? 'dark' : 'light';

        // Show loading state with CRT effect
        sidebar.innerHTML = `
            <div class="sidebar-header">
                <a href="/">
                    <span class="logo-icon">🔒</span>
                    <div>
                        <span class="logo">SECUBOX</span>
                        <span class="logo-version">${VERSION}</span>
                    </div>
                </a>
            </div>
            <div class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title" style="color: #0f8822;">
                        <span>LOADING...</span>
                        <span class="toggle-icon" style="animation: blink-cursor 1.2s step-start infinite;">█</span>
                    </div>
                </div>
            </div>
        `;

        try {
            const res = await fetch(MENU_API);
            const data = await res.json();

            if (!data || !data.categories) {
                throw new Error('Invalid menu data');
            }

            const currentPath = window.location.pathname;
            const user = getCurrentUser();

            const menuHTML = data.categories.map(cat => `
                <div class="nav-section">
                    <div class="nav-section-title" onclick="this.closest('.nav-section').classList.toggle('collapsed'); this.querySelector('.toggle-icon').textContent = this.closest('.nav-section').classList.contains('collapsed') ? '▶' : '▼';">
                        <span>${cat.icon} ${cat.name.toUpperCase()}</span>
                        <span class="toggle-icon">▼</span>
                    </div>
                    <div class="nav-items">
                        ${cat.items.map(item => {
                            const isActive = currentPath === item.path ||
                                (item.path !== '/' && currentPath.startsWith(item.path));
                            const statusClass = item.active ? 'active' : '';
                            return `<a href="${item.path}" class="nav-item${isActive ? ' active' : ''}">
                                <span class="icon">${item.icon}</span>
                                <span>${item.name}</span>
                                <span class="status-dot ${statusClass}"></span>
                            </a>`;
                        }).join('')}
                    </div>
                </div>
            `).join('');

            sidebar.innerHTML = `
                <div class="sidebar-header">
                    <a href="/">
                        <span class="logo-icon">🔒</span>
                        <div>
                            <span class="logo">SECUBOX</span>
                            <span class="logo-version">${VERSION}</span>
                        </div>
                    </a>
                </div>
                <div class="sidebar-nav">
                    ${menuHTML}
                </div>
                <div class="sidebar-footer">
                    <button class="theme-toggle" id="theme-toggle" onclick="window.SecuBoxSidebar.toggleTheme()" title="Switch to ${otherTheme} mode">
                        <span class="theme-icon">${THEMES[otherTheme].icon}</span>
                    </button>
                    <div class="sidebar-clock" id="sidebar-clock">00:00:00</div>
                    <div class="sidebar-user">
                        <span class="sidebar-user-avatar">👤</span>
                        <div class="sidebar-user-info">
                            <div class="sidebar-user-name">${user}</div>
                            <div class="sidebar-user-role">OPERATOR</div>
                        </div>
                        <button class="sidebar-logout" onclick="localStorage.removeItem('sbx_token'); window.location.href='/portal/login.html';">EXIT</button>
                    </div>
                </div>
            `;

            // Start clock
            const clockEl = document.getElementById('sidebar-clock');
            if (clockEl) startClock(clockEl);

        } catch (e) {
            console.error('Failed to load menu:', e);
            // Fallback minimal menu
            sidebar.innerHTML = `
                <div class="sidebar-header">
                    <a href="/">
                        <span class="logo-icon">🔒</span>
                        <div>
                            <span class="logo">SECUBOX</span>
                            <span class="logo-version">${VERSION}</span>
                        </div>
                    </a>
                </div>
                <div class="sidebar-nav">
                    <div class="nav-section">
                        <div class="nav-section-title">
                            <span>📊 DASHBOARD</span>
                            <span class="toggle-icon">▼</span>
                        </div>
                        <div class="nav-items">
                            <a href="/" class="nav-item">
                                <span class="icon">🏠</span>
                                <span>Dashboard</span>
                            </a>
                            <a href="/system/" class="nav-item">
                                <span class="icon">⚙️</span>
                                <span>System</span>
                            </a>
                        </div>
                    </div>
                    <div class="nav-section">
                        <div class="nav-section-title">
                            <span>🛡️ SECURITY</span>
                            <span class="toggle-icon">▼</span>
                        </div>
                        <div class="nav-items">
                            <a href="/crowdsec/" class="nav-item">
                                <span class="icon">🛡️</span>
                                <span>CrowdSec</span>
                            </a>
                            <a href="/wireguard/" class="nav-item">
                                <span class="icon">🔐</span>
                                <span>WireGuard</span>
                            </a>
                        </div>
                    </div>
                </div>
                <div class="sidebar-footer">
                    <button class="theme-toggle" id="theme-toggle" onclick="window.SecuBoxSidebar.toggleTheme()" title="Switch to ${otherTheme} mode">
                        <span class="theme-icon">${THEMES[otherTheme].icon}</span>
                    </button>
                    <div class="sidebar-clock" id="sidebar-clock">00:00:00</div>
                </div>
            `;

            const clockEl = document.getElementById('sidebar-clock');
            if (clockEl) startClock(clockEl);
        }

        // Add mobile toggle button
        if (!document.querySelector('.sidebar-toggle')) {
            const toggle = document.createElement('button');
            toggle.className = 'sidebar-toggle';
            toggle.innerHTML = '☰';
            toggle.onclick = () => sidebar.classList.toggle('open');
            document.body.appendChild(toggle);
        }

        // Apply current theme
        setTheme(currentTheme);
    }

    // Load sidebar when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadSidebar);
    } else {
        loadSidebar();
    }

    // Export for manual use
    window.SecuBoxSidebar = {
        reload: loadSidebar,
        toggleTheme: toggleTheme,
        setTheme: setTheme,
        getTheme: getCurrentTheme
    };
})();
