/**
 * SecuBox Shared Sidebar - Dynamic Menu
 * Include this script in all module frontends for consistent navigation.
 *
 * Usage:
 *   <nav class="sidebar" id="sidebar"></nav>
 *   <script src="/shared/sidebar.js"></script>
 */

(function() {
    const MENU_API = '/api/v1/hub/menu';

    // CSS for status dots (inject if not present)
    const style = document.createElement('style');
    style.textContent = `
        .status-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--red, #f85149); margin-left: auto; }
        .status-dot.active { background: var(--green, #3fb950); box-shadow: 0 0 6px var(--green, #3fb950); }
        .nav-section-title { cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
    `;
    document.head.appendChild(style);

    async function loadSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (!sidebar) return;

        // Show loading state
        sidebar.innerHTML = `
            <div class="sidebar-header">
                <a href="/" style="text-decoration: none;">
                    <div class="logo"><span>S</span><span>E</span><span>C</span><span>U</span>BOX</div>
                </a>
            </div>
            <div class="nav-section">
                <div class="nav-section-title">Loading...</div>
            </div>
        `;

        try {
            const res = await fetch(MENU_API);
            const data = await res.json();

            if (!data || !data.categories) {
                console.error('Invalid menu data');
                return;
            }

            const currentPath = window.location.pathname;

            const menuHTML = data.categories.map(cat => `
                <div class="nav-section">
                    <div class="nav-section-title">${cat.icon} ${cat.name.toUpperCase()} <span>▼</span></div>
                    ${cat.items.map(item => {
                        const isActive = currentPath === item.path ||
                            (item.path !== '/' && currentPath.startsWith(item.path));
                        const statusDot = item.active
                            ? '<span class="status-dot active"></span>'
                            : '<span class="status-dot"></span>';
                        return `<a href="${item.path}" class="nav-item${isActive ? ' active' : ''}">
                            <span class="icon">${item.icon}</span> ${item.name} ${statusDot}
                        </a>`;
                    }).join('')}
                </div>
            `).join('');

            sidebar.innerHTML = `
                <div class="sidebar-header">
                    <a href="/" style="text-decoration: none;">
                        <div class="logo"><span>S</span><span>E</span><span>C</span><span>U</span>BOX</div>
                    </a>
                </div>
                ${menuHTML}
            `;

        } catch (e) {
            console.error('Failed to load menu:', e);
            // Fallback to minimal menu
            sidebar.innerHTML = `
                <div class="sidebar-header">
                    <a href="/" style="text-decoration: none;">
                        <div class="logo"><span>S</span><span>E</span><span>C</span><span>U</span>BOX</div>
                    </a>
                </div>
                <div class="nav-section">
                    <div class="nav-section-title">📊 DASHBOARD</div>
                    <a href="/" class="nav-item"><span class="icon">🏠</span> Dashboard</a>
                </div>
            `;
        }
    }

    // Load sidebar when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadSidebar);
    } else {
        loadSidebar();
    }
})();
