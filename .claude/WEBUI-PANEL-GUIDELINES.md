# SecuBox WebUI Panel Guidelines

*Version 1.1 — 2026-07-12 · reference implementations: `/certs/`, `/wireguard/`, `/billets/`*

**This is the canonical, DEFAULT look-and-feel for all SecuBox webui module
management.** Every admin panel (`admin.gk2.secubox.in/<module>/`) and every
module's own admin interface MUST follow it: the **cyan "hybrid-dark" terminal**
convention — dark glass + **Courier Prime** + **cyan `#00d4ff`** as the single
accent + emoji-guided density. It is distinct from the C3BOX hermetic charter
(`DESIGN-CHARTER.md`, Cinzel/gold): admin panels use THIS.

Canonical examples to copy from: `packages/secubox-certs/www/certs/index.html`
(the reference), `packages/secubox-wireguard/www/wireguard/index.html`, and
`packages/secubox-billets/` (`www/billets/index.html` panel + `api/static/billets-admin.css`).

### Two variants (same palette/typography/emoji)

- **Aggregator-hosted panel** (`admin.gk2/<module>/`): link `/shared/hybrid-dark.css`
  + `/shared/sidebar.js`, body `class="hybrid-dark"`, then the `:root` palette
  from §2 (e.g. `/billets/` panel).
- **Self-contained module vhost** (a module served on its OWN vhost, no `/shared/`,
  e.g. `billets.gk2/admin`): inline the SAME `:root` palette + Courier Prime + the
  component classes in a local stylesheet (`billets-admin.css`), no shared sidebar
  — the module supplies its own top nav in the same style. **Same tokens, same
  emoji, same components — just self-hosted.**

---

## 1. Page skeleton (mandatory)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox — <Module Name></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/shared/hybrid-skin.css">
    <style>/* :root palette + component classes — see §2/§4 */</style>
</head>
<body class="hybrid-dark">
    <nav class="sidebar" id="sidebar"></nav>
    <script src="/shared/sidebar.js"></script>
    <main class="main">
        <header class="header">
            <div><h1>🔐 <Module Name></h1><div class="sub" id="subline">…</div></div>
            <div class="btn-group"><button class="btn" onclick="refresh()">↻ Refresh</button></div>
        </header>
        <!-- stat grid, cards, lists … -->
    </main>
    <div class="toast" id="toast"></div>
    <script>/* fetch + render + refresh() every 15–60s */</script>
</body>
</html>
```

- **Navbar is shared, never hand-rolled:** `<nav class="sidebar" id="sidebar"></nav>`
  + `<script src="/shared/sidebar.js"></script>`. The module only needs a
  `menu.d/NN-<id>.json` entry (already present for registered modules) — the
  sidebar renders itself from it. Do not build a `<ul>` of links.
- **Body class is `hybrid-dark`.** Keep the `/shared/hybrid-skin.css` link (it
  supplies the sidebar + base), then override locally with the `:root` palette.
- Self-contained: one `index.html`, all CSS/JS inline. No build step, no framework.

---

## 2. Palette (`:root`, copy verbatim)

```css
:root {
    --p31-dim: #6b7b8b;      /* muted labels */
    --bg-dark: #0d1117;      /* page ground */
    --bg-card: rgba(30, 40, 55, 0.8);
    --bg-row:  rgba(20, 30, 45, 0.6);   /* list rows / inputs */
    --border:  rgba(100, 150, 200, 0.2);
    --text:    #e8e6d9;
    --cyan:    #00d4ff;      /* PRIMARY accent — headings, active, primary btn */
    --red:     #ff4466;  --orange: #ff9944;  --yellow: #ffcc00;
    --green:   #00dd44;  --blue:   #4488ff;   --purple: #a371f7;
}
```

- **Cyan is the one accent.** Spend boldness there (title glow, primary buttons,
  active tab, links). Everything else is quiet glass.
- Semantic colours (red/orange/yellow/green) encode STATE (expired/critical/
  warning/healthy, down/up), never decoration. blue/purple for rx/tx-style
  secondary metrics.
- Ground is `#0d1117`; cards are translucent (`backdrop-filter: blur(10px)`).

## 3. Typography

- Font: **`'Courier Prime', monospace`** everywhere (body, headings, data).
- `h1`: `1.4rem`, `color: var(--cyan)`, `text-shadow: 0 0 10px var(--cyan)`.
- Uppercase labels (`.stat-card .label`, `.tab`, form labels) with
  `letter-spacing: 0.05–0.1em`, `font-size: 0.6–0.7rem`, `color: var(--p31-dim)`.
- Numeric columns: `font-variant-numeric: tabular-nums`.

---

## 4. Component vocabulary (reuse these class names)

- **Layout:** `.sidebar` (fixed 220px), `.main` (`margin-left:220px; padding:1.5rem; padding-top:60px`).
- **Header:** `.header` (flex space-between, wrap), `.header h1`, `.header .sub`, `.btn-group`.
- **Buttons:** `.btn`, `.btn.primary` (cyan), `.btn.danger` (red), `.btn.good`
  (green), `.btn.sm`, `:disabled { opacity:.5 }`. Uppercase, `border-radius:6px`,
  hover → cyan border + glow.
- **Stat grid:** `.grid` (`repeat(auto-fit, minmax(120px,1fr))`) of `.stat-card`
  (`.value` big + `text-shadow:0 0 10px currentColor`, `.label` uppercase muted).
  Colour the value via `.stat-card.cyan|green|blue|purple|orange .value`.
- **Cards:** `.card` (glass, `border-radius:8px`, `blur(10px)`), `.card h3` cyan.
- **Tabs:** `.tabs` + `.tab` (`.tab.active` → cyan text + `border-bottom` cyan),
  `.tab-content.active { display:block }`.
- **Lists:** dense rows on `--bg-row`, `border-left: 3px solid <state colour>`,
  `hover` → cyan tint + `translateX(2px)`. Left status glyph, cyan primary field,
  muted metadata right-aligned.
- **Toast:** `.toast` fixed bottom-right, cyan bg (`.toast.error` red), auto-hide
  ~3s via `toast(msg, isError)`.
- **Modal:** `.modal`/`.modal.show` (flex overlay), `.modal-content` glass,
  close on backdrop click.
- **Scrollbar:** thin (`::-webkit-scrollbar{width:5px}`) muted→cyan on hover.
- **Responsive:** `@media (max-width:768px){ .main{margin-left:0} … }` — collapse
  secondary columns, never scroll the body sideways.

## 5. Emoji conventions

Emoji are functional glyphs, not decoration — one per concept, consistent:

- State/health: 💀 expired · 🔴 critical · 🟠/🟡 warning · 💚/🟢 healthy/online ·
  ⚪ idle/offline · ● UP / ○ DOWN pills.
- Actions: ↻ refresh · ➕/+ add · 🔄 renew · ⏹ stop · ▶ start · 🗑️ delete · 🔒 auth.
- Domains: 🔐 vpn/crypto · 🛡️ security/waf · 👥 users · 🧰 toolbox · 🕸️ mesh ·
  📜 certs · 📊 stats · 📁 files · 🤝 handshake · ⬇️ rx / ⬆️ tx.
- Header `h1` leads with the module's menu.d icon.

---

## 6. Behaviour & data

- **Auth:** read the bearer token from `localStorage.getItem('sbx_token')` (the
  ONLY correct key) and send `Authorization: Bearer <token>` on mutating calls.
  On `401` toast "🔒 Login required", never hard-fail. GET/read endpoints that are
  public omit it.
- **Refresh:** poll the cheap status endpoint on an interval (15s for live ops,
  60s for slow stats) via a single `refresh()`; also a manual ↻ button.
- **Never hand-interpolate untrusted values into inline `onclick`.** Escape every
  API value that reaches `innerHTML` with an `esc()` helper, and drive row/card
  actions with `data-*` attributes + one delegated listener (see wireguard). A
  name with a quote must not break out of a handler string.
- **Heavy/large lists:** fetch, then render a bounded/filtered view by default
  (e.g. connected-only) with an explicit "Show all" — don't dump hundreds of DOM
  rows. Cache/stale-while-revalidate on the server for expensive endpoints.
- **Destructive actions confirm()** — and warn explicitly when an action can cut
  the operator's own access (see wireguard admin/mesh bring-down guard).

## 7. Checklist for a new/reskinned panel

- [ ] `hybrid-dark` body + `/shared/hybrid-skin.css` + shared `#sidebar` + `sidebar.js`
- [ ] Courier Prime, `:root` cyan palette verbatim, cyan-glow `h1`
- [ ] stat grid + glass cards + the shared button/list/toast/modal classes
- [ ] emoji glyphs from §5, one per concept
- [ ] `sbx_token` bearer on mutations, 401-toast, `refresh()` loop + ↻
- [ ] `esc()` on all injected values, `data-*` delegation, no onclick interpolation
- [ ] responsive `@media (max-width:768px)`, body never scrolls sideways
- [ ] menu.d entry present (navbar auto-renders it)

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie · LicenseRef-CMSD-1.0*
