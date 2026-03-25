# SecuBox CRT P31 Phosphor Theme for OpenWrt LuCI

## Objective
Apply the SecuBox CRT P31 phosphor green terminal aesthetic to all OpenWrt LuCI
modules, creating a consistent retro-futuristic security dashboard experience
identical to the Debian SecuBox UI.

## Design Specification

### Color Palette (P31 Phosphor Green)
```css
:root {
    /* P31 Phosphor Green Scale */
    --p31-peak: #33ff66;      /* Maximum brightness - headers, active elements */
    --p31-hot: #66ffaa;       /* High brightness - hover states */
    --p31-mid: #22cc44;       /* Medium brightness - body text */
    --p31-dim: #0f8822;       /* Low brightness - secondary text, borders */
    --p31-ghost: #052210;     /* Ghosting/afterglow - subtle backgrounds */

    /* Phosphor Decay (amber for warnings/errors) */
    --p31-decay: #ffb347;     /* Warning/caution */
    --p31-decay-dim: #cc7722; /* Muted warning */

    /* CRT Tube Colors */
    --tube-black: #050803;    /* Deep CRT black */
    --tube-deep: #080d05;     /* Card backgrounds */
    --tube-bezel: #0d1208;    /* Panel borders */

    /* Semantic Aliases */
    --bg-dark: var(--tube-black);
    --bg-card: var(--tube-deep);
    --border: var(--p31-ghost);
    --text: var(--p31-mid);
    --text-bright: var(--p31-peak);
    --text-dim: var(--p31-dim);

    /* Glow Effects */
    --bloom-text: 0 0 2px var(--p31-peak), 0 0 6px var(--p31-peak), 0 0 14px rgba(51,255,102,0.5);
    --bloom-soft: 0 0 6px var(--p31-peak), 0 0 14px rgba(51,255,102,0.5);
    --bloom-box: 0 0 8px rgba(51,255,102,0.3), inset 0 0 4px rgba(51,255,102,0.1);
}
```

### Typography
```css
/* CRT Monospace Font Stack */
body {
    font-family: 'Courier Prime', 'IBM Plex Mono', 'Fira Code',
                 'Courier New', 'Lucida Console', monospace;
    font-size: 14px;
    line-height: 1.5;
    letter-spacing: 0.02em;
}

/* Scanline Text Effect */
.crt-text {
    text-shadow: var(--bloom-text);
    animation: textFlicker 0.1s infinite;
}

@keyframes textFlicker {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.98; }
}
```

### CRT Screen Effects
```css
/* Scanlines Overlay */
.scanlines::before {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    background: repeating-linear-gradient(
        0deg,
        rgba(0, 0, 0, 0.15),
        rgba(0, 0, 0, 0.15) 1px,
        transparent 1px,
        transparent 2px
    );
    z-index: 9999;
}

/* Screen Curvature (subtle) */
.crt-screen {
    border-radius: 8px;
    box-shadow:
        inset 0 0 60px rgba(0, 0, 0, 0.5),
        inset 0 0 10px rgba(51, 255, 102, 0.1);
}

/* Phosphor Bloom on Focus */
input:focus, select:focus, button:focus {
    outline: none;
    border-color: var(--p31-mid);
    box-shadow: var(--bloom-box);
}
```

## OpenWrt LuCI Implementation

### File Structure
```
luci-theme-secubox/
├── Makefile
├── htdocs/
│   └── luci-static/
│       └── secubox/
│           ├── cascade.css          # Main theme CSS
│           ├── crt-engine.js        # CRT effects engine
│           ├── crt-components.js    # Reusable UI components
│           └── fonts/
│               └── CourierPrime.woff2
├── luasrc/
│   └── luci/view/themes/secubox/
│       ├── header.htm
│       ├── footer.htm
│       └── sysauth.htm              # Login page
└── root/
    └── etc/uci-defaults/
        └── 90-luci-theme-secubox    # Set as default theme
```

### Main Stylesheet (cascade.css)
```css
/* ============================================
   SecuBox CRT P31 Theme for OpenWrt LuCI
   CyberMind — SecuBox — 2026
   ============================================ */

/* === Reset & Base === */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html, body {
    background: var(--tube-black);
    color: var(--p31-mid);
    font-family: 'Courier Prime', monospace;
    min-height: 100vh;
}

/* === Header === */
header.main {
    background: var(--tube-deep);
    border-bottom: 1px solid var(--p31-ghost);
    padding: 0.75rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

header .brand {
    font-size: 1.2rem;
    color: var(--p31-peak);
    text-shadow: var(--bloom-text);
    font-weight: bold;
    letter-spacing: 2px;
}

header .brand::before {
    content: '[ ';
    color: var(--p31-dim);
}

header .brand::after {
    content: ' ]';
    color: var(--p31-dim);
}

/* === Navigation Sidebar === */
nav.main-left {
    background: var(--tube-deep);
    border-right: 1px solid var(--p31-ghost);
    width: 220px;
    min-height: calc(100vh - 50px);
    padding: 1rem 0;
}

nav.main-left ul {
    list-style: none;
}

nav.main-left li a {
    display: block;
    padding: 0.6rem 1.2rem;
    color: var(--p31-dim);
    text-decoration: none;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-left: 2px solid transparent;
    transition: all 0.2s ease;
}

nav.main-left li a:hover {
    color: var(--p31-mid);
    background: rgba(51, 255, 102, 0.05);
    border-left-color: var(--p31-dim);
}

nav.main-left li.active a {
    color: var(--p31-peak);
    background: rgba(51, 255, 102, 0.1);
    border-left-color: var(--p31-peak);
    text-shadow: var(--bloom-soft);
}

/* Category Headers */
nav.main-left li.category {
    padding: 0.8rem 1.2rem 0.4rem;
    color: var(--p31-ghost);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    border-bottom: 1px solid var(--p31-ghost);
    margin-top: 0.5rem;
}

/* === Main Content === */
main.main-right {
    flex: 1;
    padding: 1.5rem;
    background: var(--tube-black);
}

/* === Cards/Panels === */
.cbi-map, .cbi-section, fieldset, .panel {
    background: var(--tube-deep);
    border: 1px solid var(--p31-ghost);
    border-radius: 4px;
    padding: 1rem;
    margin-bottom: 1rem;
}

.cbi-section-node {
    background: transparent;
    border: none;
}

/* Section Headers */
.cbi-section h3, legend, .panel-title {
    color: var(--p31-peak);
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    border-bottom: 1px solid var(--p31-ghost);
    text-shadow: var(--bloom-soft);
}

/* === Tables === */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
}

th {
    color: var(--p31-dim);
    font-weight: normal;
    text-transform: uppercase;
    font-size: 0.75rem;
    letter-spacing: 1px;
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--p31-ghost);
    background: var(--tube-black);
}

td {
    padding: 0.75rem;
    border-bottom: 1px solid var(--p31-ghost);
    color: var(--p31-mid);
}

tr:hover td {
    background: rgba(51, 255, 102, 0.03);
}

/* === Forms === */
input[type="text"],
input[type="password"],
input[type="number"],
input[type="email"],
textarea,
select {
    background: var(--tube-black);
    border: 1px solid var(--p31-ghost);
    color: var(--p31-mid);
    padding: 0.5rem 0.75rem;
    font-family: inherit;
    font-size: 0.9rem;
    border-radius: 3px;
    width: 100%;
    max-width: 400px;
}

input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--p31-mid);
    box-shadow: var(--bloom-box);
}

input::placeholder {
    color: var(--p31-ghost);
}

/* Checkboxes & Radio */
input[type="checkbox"],
input[type="radio"] {
    accent-color: var(--p31-peak);
}

/* === Buttons === */
.cbi-button, button, input[type="submit"], input[type="button"] {
    background: transparent;
    border: 1px solid var(--p31-dim);
    color: var(--p31-mid);
    padding: 0.5rem 1rem;
    font-family: inherit;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    cursor: pointer;
    border-radius: 3px;
    transition: all 0.2s ease;
}

.cbi-button:hover, button:hover {
    color: var(--p31-peak);
    border-color: var(--p31-mid);
    text-shadow: var(--bloom-soft);
}

.cbi-button-save, .cbi-button-apply, .btn-primary {
    border-color: var(--p31-mid);
    color: var(--p31-peak);
}

.cbi-button-save:hover, .btn-primary:hover {
    background: var(--p31-mid);
    color: var(--tube-black);
    text-shadow: none;
}

.cbi-button-remove, .cbi-button-reset, .btn-danger {
    border-color: var(--p31-decay-dim);
    color: var(--p31-decay);
}

.cbi-button-remove:hover, .btn-danger:hover {
    background: var(--p31-decay);
    color: var(--tube-black);
    text-shadow: none;
}

/* === Status Badges === */
.badge, .label {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-radius: 2px;
    border: 1px solid;
}

.badge-success, .label-success {
    border-color: var(--p31-mid);
    color: var(--p31-peak);
    background: rgba(51, 255, 102, 0.1);
}

.badge-warning, .label-warning {
    border-color: var(--p31-decay-dim);
    color: var(--p31-decay);
    background: rgba(255, 179, 71, 0.1);
}

.badge-danger, .label-danger {
    border-color: #ff4466;
    color: #ff6688;
    background: rgba(255, 68, 102, 0.1);
}

.badge-info, .label-info {
    border-color: var(--p31-dim);
    color: var(--p31-mid);
    background: rgba(51, 255, 102, 0.05);
}

/* === Alerts/Notifications === */
.alert, .notice {
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
    border: 1px solid;
}

.alert-success, .notice.success {
    background: rgba(51, 255, 102, 0.1);
    border-color: var(--p31-dim);
    color: var(--p31-mid);
}

.alert-warning, .notice.warning {
    background: rgba(255, 179, 71, 0.1);
    border-color: var(--p31-decay-dim);
    color: var(--p31-decay);
}

.alert-error, .notice.error {
    background: rgba(255, 68, 102, 0.1);
    border-color: #ff4466;
    color: #ff6688;
}

/* === Progress Bars === */
.cbi-progressbar, .progress {
    background: var(--tube-black);
    border: 1px solid var(--p31-ghost);
    border-radius: 2px;
    height: 20px;
    overflow: hidden;
}

.cbi-progressbar > div, .progress-bar {
    background: linear-gradient(90deg, var(--p31-dim), var(--p31-mid));
    height: 100%;
    box-shadow: 0 0 10px var(--p31-mid);
    transition: width 0.3s ease;
}

/* === Tabs === */
.cbi-tabmenu, .tabs {
    display: flex;
    border-bottom: 1px solid var(--p31-ghost);
    margin-bottom: 1rem;
}

.cbi-tabmenu li, .tabs .tab {
    list-style: none;
}

.cbi-tabmenu li a, .tabs .tab {
    display: block;
    padding: 0.6rem 1rem;
    color: var(--p31-dim);
    text-decoration: none;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    border: 1px solid transparent;
    border-bottom: none;
    margin-bottom: -1px;
    cursor: pointer;
    background: transparent;
}

.cbi-tabmenu li.cbi-tab a, .tabs .tab.active {
    color: var(--p31-peak);
    border-color: var(--p31-ghost);
    background: var(--tube-deep);
    text-shadow: var(--bloom-soft);
}

/* === Tooltips === */
[data-tooltip] {
    position: relative;
}

[data-tooltip]::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translateX(-50%);
    background: var(--tube-deep);
    border: 1px solid var(--p31-dim);
    color: var(--p31-mid);
    padding: 0.4rem 0.6rem;
    font-size: 0.75rem;
    white-space: nowrap;
    border-radius: 3px;
    opacity: 0;
    visibility: hidden;
    transition: all 0.2s ease;
}

[data-tooltip]:hover::after {
    opacity: 1;
    visibility: visible;
}

/* === Footer === */
footer.main {
    background: var(--tube-deep);
    border-top: 1px solid var(--p31-ghost);
    padding: 0.5rem 1.5rem;
    font-size: 0.75rem;
    color: var(--p31-dim);
    text-align: center;
}

/* === Responsive === */
@media (max-width: 768px) {
    nav.main-left {
        width: 100%;
        min-height: auto;
        border-right: none;
        border-bottom: 1px solid var(--p31-ghost);
    }

    main.main-right {
        padding: 1rem;
    }
}

/* === Login Page === */
.login-container {
    max-width: 400px;
    margin: 10vh auto;
    padding: 2rem;
    background: var(--tube-deep);
    border: 1px solid var(--p31-ghost);
    border-radius: 6px;
    text-align: center;
}

.login-container h1 {
    color: var(--p31-peak);
    text-shadow: var(--bloom-text);
    margin-bottom: 2rem;
    letter-spacing: 3px;
}

.login-container input {
    width: 100%;
    max-width: none;
    margin-bottom: 1rem;
}

.login-container button {
    width: 100%;
    padding: 0.75rem;
}

/* === Dashboard Widgets === */
.widget {
    background: var(--tube-deep);
    border: 1px solid var(--p31-ghost);
    border-radius: 4px;
    padding: 1rem;
}

.widget-header {
    color: var(--p31-peak);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 0.75rem;
    text-shadow: var(--bloom-soft);
}

.widget-value {
    font-size: 2rem;
    color: var(--p31-peak);
    text-shadow: var(--bloom-text);
    font-weight: bold;
}

.widget-value.warning {
    color: var(--p31-decay);
    text-shadow: 0 0 6px var(--p31-decay);
}

.widget-value.danger {
    color: #ff6688;
    text-shadow: 0 0 6px #ff4466;
}

.widget-label {
    font-size: 0.7rem;
    color: var(--p31-dim);
    text-transform: uppercase;
}
```

### CRT Effects Engine (crt-engine.js)
```javascript
// SecuBox CRT P31 Effects Engine
// CyberMind — SecuBox — 2026

(function() {
    'use strict';

    // Add scanlines overlay
    function addScanlines() {
        if (document.querySelector('.scanlines')) return;
        const scanlines = document.createElement('div');
        scanlines.className = 'scanlines';
        document.body.appendChild(scanlines);
    }

    // CRT flicker effect
    function enableFlicker() {
        document.body.classList.add('crt-flicker');
    }

    // Typewriter effect for headers
    function typewriterEffect(element, speed = 50) {
        const text = element.textContent;
        element.textContent = '';
        element.style.visibility = 'visible';

        let i = 0;
        function type() {
            if (i < text.length) {
                element.textContent += text.charAt(i);
                i++;
                setTimeout(type, speed);
            }
        }
        type();
    }

    // Boot sequence animation
    function bootSequence() {
        const bootText = [
            '[ SECUBOX MESH DAEMON ]',
            'Initializing P31 phosphor display...',
            'Loading security modules...',
            'mDNS discovery: ACTIVE',
            'Mesh topology: ONLINE',
            'System ready.'
        ];

        const container = document.createElement('div');
        container.id = 'boot-sequence';
        container.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--tube-black);
            z-index: 10000;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            font-family: 'Courier Prime', monospace;
            color: var(--p31-mid);
        `;

        document.body.appendChild(container);

        let lineIndex = 0;
        function showLine() {
            if (lineIndex < bootText.length) {
                const line = document.createElement('div');
                line.style.cssText = `
                    opacity: 0;
                    margin: 0.3rem 0;
                    ${lineIndex === 0 ? 'font-size: 1.2rem; color: var(--p31-peak); text-shadow: var(--bloom-text);' : ''}
                `;
                line.textContent = bootText[lineIndex];
                container.appendChild(line);

                setTimeout(() => {
                    line.style.transition = 'opacity 0.3s';
                    line.style.opacity = '1';
                }, 50);

                lineIndex++;
                setTimeout(showLine, 300);
            } else {
                setTimeout(() => {
                    container.style.transition = 'opacity 0.5s';
                    container.style.opacity = '0';
                    setTimeout(() => container.remove(), 500);
                }, 800);
            }
        }

        showLine();
    }

    // Phosphor glow on interactive elements
    function addPhosphorGlow() {
        document.querySelectorAll('button, .cbi-button, a').forEach(el => {
            el.addEventListener('mouseenter', () => {
                el.style.textShadow = 'var(--bloom-soft)';
            });
            el.addEventListener('mouseleave', () => {
                el.style.textShadow = '';
            });
        });
    }

    // Terminal cursor blink for inputs
    function addTerminalCursor() {
        document.querySelectorAll('input[type="text"], input[type="password"]').forEach(input => {
            input.addEventListener('focus', () => {
                input.style.caretColor = 'var(--p31-peak)';
            });
        });
    }

    // Initialize CRT effects
    function init() {
        addScanlines();
        addPhosphorGlow();
        addTerminalCursor();

        // Optional: enable boot sequence on first visit
        if (!sessionStorage.getItem('crt-booted')) {
            bootSequence();
            sessionStorage.setItem('crt-booted', 'true');
        }
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Export for manual use
    window.SecuBoxCRT = {
        addScanlines,
        enableFlicker,
        typewriterEffect,
        bootSequence,
        addPhosphorGlow
    };
})();
```

### OpenWrt Package Makefile
```makefile
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-theme-secubox
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Gerald KERMA <devel@cybermind.fr>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/luci-theme-secubox
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=4. Themes
  TITLE:=SecuBox CRT P31 Phosphor Theme
  DEPENDS:=+luci-base
  PKGARCH:=all
endef

define Package/luci-theme-secubox/description
  CRT P31 phosphor green terminal theme for SecuBox mesh network appliance.
  Features scanlines, phosphor glow effects, and retro-futuristic aesthetic.
endef

define Build/Compile
endef

define Package/luci-theme-secubox/install
	$(INSTALL_DIR) $(1)/www/luci-static/secubox
	$(CP) ./htdocs/luci-static/secubox/* $(1)/www/luci-static/secubox/
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/themes/secubox
	$(CP) ./luasrc/luci/view/themes/secubox/* $(1)/usr/lib/lua/luci/view/themes/secubox/
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./root/etc/uci-defaults/90-luci-theme-secubox $(1)/etc/uci-defaults/
endef

define Package/luci-theme-secubox/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	uci set luci.main.mediaurlbase='/luci-static/secubox'
	uci commit luci
}
endef

$(eval $(call BuildPackage,luci-theme-secubox))
```

### UCI Default Script
```sh
#!/bin/sh
# Set SecuBox CRT theme as default

uci -q batch <<-EOF
	set luci.main.mediaurlbase='/luci-static/secubox'
	commit luci
EOF

exit 0
```

## Module-Specific Styling

### Status Dashboard Widgets
```css
/* Dashboard grid */
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

/* System status widget */
.status-widget {
    background: var(--tube-deep);
    border: 1px solid var(--p31-ghost);
    border-radius: 4px;
    padding: 1rem;
    text-align: center;
}

.status-widget .icon {
    font-size: 2rem;
    margin-bottom: 0.5rem;
}

.status-widget.online .icon {
    color: var(--p31-peak);
    text-shadow: var(--bloom-text);
}

.status-widget.offline .icon {
    color: #ff4466;
    text-shadow: 0 0 6px #ff4466;
}
```

### Network Topology SVG
```css
/* Topology visualization */
.topology-container {
    background: var(--tube-black);
    border: 1px solid var(--p31-ghost);
    border-radius: 4px;
    padding: 1rem;
}

.topology-container svg {
    width: 100%;
    height: 400px;
}

.topology-node circle {
    fill: var(--p31-dim);
    stroke: var(--p31-mid);
    stroke-width: 2;
}

.topology-node.relay circle {
    fill: var(--p31-decay-dim);
    stroke: var(--p31-decay);
}

.topology-node.active circle {
    fill: var(--p31-mid);
    stroke: var(--p31-peak);
    filter: url(#glow);
}

.topology-edge {
    stroke: var(--p31-ghost);
    stroke-width: 1;
}

.topology-edge.active {
    stroke: var(--p31-dim);
    stroke-width: 2;
    animation: edgePulse 2s infinite;
}

@keyframes edgePulse {
    0%, 100% { opacity: 0.5; }
    50% { opacity: 1; }
}
```

## Testing Checklist

- [ ] Theme loads without CSS errors
- [ ] Scanlines overlay visible
- [ ] P31 green colors applied consistently
- [ ] Buttons have proper hover glow
- [ ] Tables styled correctly
- [ ] Forms have focus glow effect
- [ ] Status badges display properly
- [ ] Login page styled
- [ ] Responsive on mobile
- [ ] Boot sequence animation works
- [ ] Navigation sidebar styled
- [ ] All LuCI pages inherit theme

---

## Reference: Debian Implementation

The Debian CRT theme files are located at:
- `packages/*/www/*/index.html` - Per-module pages with CRT styling
- `common/www/shared/sidebar.css` - Shared sidebar styles
- `common/www/shared/crt-engine.js` - CRT effects engine
- `common/www/shared/crt-components.js` - Reusable UI components

---

*CyberMind — SecuBox — 2026*
