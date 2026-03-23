/**
 * ═══════════════════════════════════════════════════════════════
 *  SECUBOX SIDEBAR — CRT P31 Phosphor Theme
 *  Dynamic menu with VT100 aesthetic
 *
 *  Usage:
 *    <nav class="sidebar" id="sidebar"></nav>
 *    <script src="/shared/sidebar.js"></script>
 * ═══════════════════════════════════════════════════════════════
 */

(function() {
    const MENU_API = '/api/v1/hub/menu';
    const VERSION = 'v1.1.0';

    // Inject additional CRT styles
    const style = document.createElement('style');
    style.textContent = `
        @import url('https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap');
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
    }

    // Load sidebar when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadSidebar);
    } else {
        loadSidebar();
    }

    // Export for manual refresh
    window.SecuBoxSidebar = { reload: loadSidebar };
})();
