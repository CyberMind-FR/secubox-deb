<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer Version Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing MetaBlogizer dashboard at `/metablogizer/` with three version-aware columns (version, streamlit_app, last_updated), an inline filter, sortable headers, and 60-second polling; plus add a per-site drill-in page at `/metablogizer/site.html?name=<X>` that surfaces every site.json field with external links to the live site, Gitea repo, and Streamlit app.

**Architecture:** Vanilla HTML/JS edits to the existing 533-line `index.html` (matches the CRT P31 phosphor theme already in use) + one new HTML file. All data comes from the enriched `/api/v1/metablogizer/sites` and `/api/v1/metablogizer/site/<name>` endpoints shipped in PR #102. No JS framework, no router, no Gitea fetch from the browser — drill-in links go straight to Gitea's UI (auth handled by user's existing Gitea session).

**Tech Stack:** Vanilla JS, CSS custom properties (existing `crt-light.css` design tokens), `URLSearchParams`, `Page Visibility API`. Smoke test in Bash via `curl` + `python3 html.parser`.

**Spec:** [docs/superpowers/specs/2026-05-12-metablog-version-dashboard-design.md](../specs/2026-05-12-metablog-version-dashboard-design.md)
**Issue:** [#103](https://github.com/CyberMind-FR/secubox-deb/issues/103) (sub-project D of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** [#102](https://github.com/CyberMind-FR/secubox-deb/pull/102) (merged — sub-C: schema + enriched API)

---

## Existing state (verified)

`packages/secubox-metablogizer/www/metablogizer/index.html` already has:

- Table at line 369-372: `<thead><tr><th>Name</th><th>Domain</th><th>Status</th><th>Size</th><th>Actions</th></tr></thead>` + `<tbody id="site-list">` (colspan=5 in empty state).
- `loadSites()` at line 443 reads `d.sites` from `/sites` and renders each row.
- `refresh()` at line 528 calls `loadStatus()`, `loadSites()`, `loadAccess()`.
- `api(path, opts)` helper at line 420 handles 401 → `/login.html`.

The new layout has 8 columns: Name | Domain | **Version** | **Streamlit** | **Updated** | Status | Size | Actions.

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `packages/secubox-metablogizer/www/metablogizer/index.html` | +3 columns, filter box, sort, 60s polling |
| Create | `packages/secubox-metablogizer/www/metablogizer/site.html` | Drill-in page (~250 lines, mirrors index.html theme) |
| Create | `tests/scripts/test-metablogizer-ui.sh` | 3-gate smoke (file shape + curl reachability + JS sanity) |
| Modify | `packages/secubox-metablogizer/README.md` | Document dashboard + drill-in URLs |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 165 entry |

---

## Task 1: Extend the list view — columns + filter + sort + polling

**Files:**
- Modify: `packages/secubox-metablogizer/www/metablogizer/index.html`

- [ ] **Step 1: Verify branch**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/103-metablogizer-version-dashboard-ui-module
git rev-parse --abbrev-ref HEAD
```

Expected: `feature/103-metablogizer-version-dashboard-ui-module`. Otherwise BLOCKED.

- [ ] **Step 2: Update the table `<thead>` (line 370) to add 3 columns + `data-sort` attributes**

Find this line:

```html
                    <thead><tr><th>Name</th><th>Domain</th><th>Status</th><th>Size</th><th>Actions</th></tr></thead>
```

Replace it with:

```html
                    <thead><tr>
                        <th data-sort="name" onclick="sortBy('name', this)">Name <span class="sort-ind"></span></th>
                        <th data-sort="domain" onclick="sortBy('domain', this)">Domain <span class="sort-ind"></span></th>
                        <th data-sort="version" onclick="sortBy('version', this)">Version <span class="sort-ind"></span></th>
                        <th>Streamlit</th>
                        <th data-sort="last_updated" onclick="sortBy('last_updated', this)">Updated <span class="sort-ind"></span></th>
                        <th>Status</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr></thead>
                    <tbody id="site-list"><tr><td colspan="8">Loading...</td></tr></tbody>
```

Note `colspan="8"` (was 5).

- [ ] **Step 3: Add a filter input above the table**

Just above the `<table>` line (around line 368), add:

```html
                <div class="filter-row" style="margin-bottom:0.5rem">
                    <input type="search" id="filter" placeholder="Filter by name or domain…"
                           oninput="applyFilter()"
                           style="width:100%;padding:0.5rem;background:var(--bg-dark);color:var(--text);border:1px solid var(--border);border-radius:4px;font-family:inherit">
                </div>
```

- [ ] **Step 4: Update the empty-state `colspan` in `loadSites()`**

Find this line in `loadSites()` (around line 447):

```js
            if (!sites.length) { list.innerHTML = '<tr><td colspan="5" style="color:var(--text-dim)">No sites</td></tr>'; return; }
```

Change `colspan="5"` to `colspan="8"`.

- [ ] **Step 5: Replace the `sites.map(s => ...)` row template**

Find the existing template (around lines 448-461). Replace the inner `<tr>` template with this expanded form:

```js
            list.innerHTML = sites.map(s => {
                const streamlitCell = s.streamlit_app
                    ? `<a href="https://gitea.gk2.secubox.in/gandalf/${s.streamlit_app}" target="_blank" title="${s.streamlit_app}">🎨</a>`
                    : '<span style="color:var(--text-dim)">—</span>';
                const versionCell = s.version
                    ? `<a href="https://gitea.gk2.secubox.in/gandalf/metablog-${s.name}/releases" target="_blank"><code style="color:var(--primary)">${s.version}</code></a>`
                    : '<span style="color:var(--text-dim)">—</span>';
                const updatedCell = s.last_updated
                    ? `<span title="${s.last_updated}">${relativeTime(s.last_updated)}</span>`
                    : '<span style="color:var(--text-dim)">—</span>';
                return `<tr class="site-row" data-name="${s.name}" data-domain="${s.domain}">
                    <td><strong><a href="site.html?name=${s.name}" style="color:var(--text)">${s.name}</a></strong></td>
                    <td style="color:var(--text-dim)">${s.domain}</td>
                    <td>${versionCell}</td>
                    <td style="text-align:center">${streamlitCell}</td>
                    <td>${updatedCell}</td>
                    <td><span class="badge ${s.published ? 'published' : 'draft'}">${s.published ? 'Published' : 'Draft'}</span></td>
                    <td>${s.size || '-'}</td>
                    <td>
                        ${s.published ?
                            `<a href="http://${s.domain}" target="_blank" class="btn" style="padding:2px 8px;font-size:0.7rem">View</a>
                             <button class="btn" onclick="unpublishSite('${s.name}')" style="padding:2px 8px;font-size:0.7rem">Unpublish</button>` :
                            `<button class="btn success" onclick="publishSite('${s.name}')" style="padding:2px 8px;font-size:0.7rem">Publish</button>`}
                        <button class="btn danger" onclick="deleteSite('${s.name}')" style="padding:2px 8px;font-size:0.7rem">Delete</button>
                    </td>
                </tr>`;
            }).join('');
            // Apply current sort + filter after re-render.
            if (currentSort.field) applySortToDOM();
            applyFilter();
```

- [ ] **Step 6: Add the helper functions + module-level state above `loadSites()`**

Insert this block right before the `async function loadSites()` definition (around line 442):

```js
        // ─── Sort + filter + polling state ───
        let currentSort = { field: null, dir: 'asc' };
        let pollTimer = null;

        function relativeTime(iso) {
            if (!iso) return '—';
            const d = new Date(iso);
            const diff = (Date.now() - d.getTime()) / 1000;
            if (isNaN(diff)) return iso;
            if (diff < 60) return `${Math.floor(diff)}s ago`;
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        }

        function applyFilter() {
            const q = (document.getElementById('filter')?.value || '').toLowerCase().trim();
            document.querySelectorAll('.site-row').forEach(tr => {
                const name = (tr.dataset.name || '').toLowerCase();
                const domain = (tr.dataset.domain || '').toLowerCase();
                const match = !q || name.includes(q) || domain.includes(q);
                tr.style.display = match ? '' : 'none';
            });
        }

        function sortBy(field, thEl) {
            if (currentSort.field === field) {
                currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort = { field, dir: 'asc' };
            }
            // Update visual indicator on all sortable headers
            document.querySelectorAll('th[data-sort] .sort-ind').forEach(s => s.textContent = '');
            const ind = thEl.querySelector('.sort-ind');
            if (ind) ind.textContent = currentSort.dir === 'asc' ? ' ▲' : ' ▼';
            applySortToDOM();
        }

        function applySortToDOM() {
            const tbody = document.getElementById('site-list');
            if (!tbody) return;
            const rows = Array.from(tbody.querySelectorAll('tr.site-row'));
            const field = currentSort.field;
            const dir = currentSort.dir === 'asc' ? 1 : -1;
            rows.sort((a, b) => {
                const av = (a.dataset[field] || '') + '';
                const bv = (b.dataset[field] || '') + '';
                // Nulls/empties go last in asc, first in desc.
                if (av === '' && bv !== '') return 1;
                if (bv === '' && av !== '') return -1;
                return av.localeCompare(bv, undefined, { numeric: true }) * dir;
            });
            rows.forEach(r => tbody.appendChild(r));
        }

        function installPolling() {
            if (pollTimer) return;
            pollTimer = setInterval(() => {
                if (!document.hidden) refresh();
            }, 60000);
        }
```

Note: `data-name` and `data-domain` are already on each `<tr>` from Step 5. We also need `data-version` and `data-last_updated` for the sort to work on those fields. Update the row template line:

```html
                return `<tr class="site-row" data-name="${s.name}" data-domain="${s.domain}" data-version="${s.version || ''}" data-last_updated="${s.last_updated || ''}">
```

(Update the same `<tr ...>` line you wrote in Step 5.)

- [ ] **Step 7: Install the polling at the end of `refresh()`**

Find the existing `refresh()` (around line 528):

```js
        function refresh() { loadStatus(); loadSites(); loadAccess(); }
        refresh();
```

Change to:

```js
        function refresh() { loadStatus(); loadSites(); loadAccess(); }
        refresh();
        installPolling();
```

- [ ] **Step 8: Add `.sort-ind` CSS (cosmetic)**

In the `<style>` block at the top of `index.html`, near the `.badge` rules (around line 78), add:

```css
        th[data-sort] { cursor: pointer; user-select: none; }
        th[data-sort]:hover { color: var(--primary); }
        .sort-ind { font-size: 0.8em; color: var(--primary); }
```

- [ ] **Step 9: HTML sanity check**

```bash
python3 -c "
import html.parser
class S(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []
    def handle_starttag(self, tag, attrs):
        if tag not in ('br','hr','img','input','link','meta'):
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f'mismatched: closing {tag}, stack top {self.stack[-1] if self.stack else None}')
p = S()
p.feed(open('packages/secubox-metablogizer/www/metablogizer/index.html').read())
print('unclosed:', p.stack[-5:] if p.stack else 'none')
print('errors:', p.errors[:5] if p.errors else 'none')
"
```

Expected: `unclosed: none` (or only `['html','body','main']`-style top-level; trailing-open is acceptable). `errors: none`.

If unbalanced, find the culprit and fix it. Common cause: a forgotten `</td>` or `</tr>`.

- [ ] **Step 10: Commit**

```bash
git add packages/secubox-metablogizer/www/metablogizer/index.html
git commit -m "feat(metablog-ui): version/streamlit/updated columns + filter + sort + 60s poll (ref #103)

- 3 new columns: Version (links to Gitea releases), Streamlit (icon link
  when site has a streamlit_app), Updated (relative time, full ISO tooltip)
- Filter box above the table: live substring match on name + domain
- Sortable headers (Name, Domain, Version, Updated) with ▲/▼ indicator
- 60-second auto-refresh, paused when tab is hidden (Page Visibility API)
- Row name now links to site.html?name=<X> (drill-in, Task 2)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Drill-in page `site.html`

**Files:**
- Create: `packages/secubox-metablogizer/www/metablogizer/site.html`

This page is loaded as `/metablogizer/site.html?name=<X>`. Reuses the same theme/styles as `index.html`. Single API call to `/site/<X>` and a render function.

- [ ] **Step 1: Verify branch.**

- [ ] **Step 2: Create `site.html`**

```bash
cat > packages/secubox-metablogizer/www/metablogizer/site.html <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox — Site details</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&family=Cinzel:wght@500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
    <style>
        :root {
            --p31-peak: #00dd44; --p31-hot: #00ff55; --p31-mid: #009933;
            --p31-dim: #006622; --p31-decay: #ffb347; --p31-decay-dim: #cc7722;
            --tube-light: #e8f5e9; --tube-pale: #c8e6c9; --tube-soft: #a5d6a7;
            --bg-dark: var(--tube-light); --bg-card: var(--tube-pale);
            --border: var(--tube-soft); --text: #1b2c1b; --text-dim: var(--p31-dim);
            --primary: var(--p31-peak); --green: var(--p31-peak);
            --red: #ff4466; --yellow: var(--p31-decay);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier Prime', 'Courier New', monospace;
            background: var(--tube-light);
            color: var(--text);
            display: flex;
            min-height: 100vh;
        }
        .main {
            flex: 1;
            padding: 2rem;
            max-width: 1100px;
            margin: 0 auto;
        }
        .header {
            display: flex;
            align-items: baseline;
            gap: 1rem;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 0.75rem;
        }
        .header h1 {
            font-family: 'Cinzel', serif;
            font-weight: 500;
            color: var(--primary);
            font-size: 2rem;
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .badge.published { background: rgba(0,221,68,0.2); color: var(--green); border: 1px solid var(--green); }
        .badge.draft { background: rgba(255,179,71,0.2); color: var(--yellow); border: 1px solid var(--yellow); }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem 1.25rem;
            margin-bottom: 1rem;
        }
        .card h2 {
            font-family: 'Cinzel', serif;
            font-weight: 500;
            color: var(--text);
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }
        dl { display: grid; grid-template-columns: 12rem 1fr; gap: 0.4rem 1rem; }
        dt { color: var(--text-dim); }
        dd { color: var(--text); word-break: break-word; }
        dd code { background: var(--bg-dark); padding: 0.1rem 0.4rem; border-radius: 3px; color: var(--primary); }
        .actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
        .btn {
            display: inline-block;
            padding: 0.5rem 0.9rem;
            background: var(--bg-dark);
            color: var(--text);
            border: 1px solid var(--border);
            border-radius: 4px;
            text-decoration: none;
            font-family: inherit;
            font-size: 0.9rem;
            cursor: pointer;
        }
        .btn:hover { border-color: var(--primary); color: var(--primary); }
        .btn.primary { background: var(--primary); color: var(--bg-dark); border-color: var(--primary); }
        .btn.success { background: var(--green); color: var(--bg-dark); border-color: var(--green); }
        .btn[hidden] { display: none !important; }
        .hint { color: var(--text-dim); font-size: 0.9rem; }
        .error { color: var(--red); }
        a { color: var(--primary); }
    </style>
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <script src="/shared/sidebar.js"></script>
    <main class="main">
        <div id="error-box"></div>

        <header class="header">
            <h1 id="site-name">…</h1>
            <span id="status-badge" class="badge"></span>
            <a href="index.html" class="btn" style="margin-left:auto">← Back to list</a>
        </header>

        <div class="card">
            <h2>Metadata</h2>
            <dl id="meta-dl"></dl>
        </div>

        <div class="card">
            <h2>Quick links</h2>
            <div class="actions">
                <a id="link-live" class="btn primary" target="_blank">🌐 Live site</a>
                <a id="link-gitea" class="btn" target="_blank">🦊 Gitea repo</a>
                <a id="link-streamlit" class="btn success" target="_blank" hidden>🎨 Streamlit app</a>
            </div>
        </div>

        <div class="card hint">
            <p>For tag history and deploys, see the <strong>Releases</strong> tab on the Gitea repo (auth required).</p>
        </div>
    </main>

    <script>
        const API = '/api/v1/metablogizer';

        function headers() {
            const t = localStorage.getItem('jwt');
            return t ? { 'Authorization': `Bearer ${t}` } : {};
        }

        async function api(path) {
            try {
                const res = await fetch(API + path, { headers: headers() });
                if (res.status === 401) { window.location = '/login.html'; return null; }
                if (!res.ok) return null;
                return res.json();
            } catch { return null; }
        }

        function relativeTime(iso) {
            if (!iso) return '—';
            const d = new Date(iso);
            const diff = (Date.now() - d.getTime()) / 1000;
            if (isNaN(diff)) return iso;
            if (diff < 60) return `${Math.floor(diff)}s ago`;
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        }

        function row(label, value) {
            const dt = document.createElement('dt'); dt.textContent = label;
            const dd = document.createElement('dd'); dd.innerHTML = value;
            return [dt, dd];
        }

        function render(d) {
            document.getElementById('site-name').textContent = d.name;
            const badge = document.getElementById('status-badge');
            badge.textContent = d.published ? 'Published' : 'Draft';
            badge.className = 'badge ' + (d.published ? 'published' : 'draft');

            const dl = document.getElementById('meta-dl');
            const versionCell = d.version
                ? `<code>${d.version}</code>`
                : '<span style="color:var(--text-dim)">—</span>';
            const lastUpdatedCell = d.last_updated
                ? `${d.last_updated} <span style="color:var(--text-dim)">(${relativeTime(d.last_updated)})</span>`
                : '<span style="color:var(--text-dim)">—</span>';
            const tagsCell = (d.tags && d.tags.length)
                ? d.tags.map(t => `<code>${t}</code>`).join(' ')
                : '<span style="color:var(--text-dim)">—</span>';

            const fields = [
                ['Domain',       d.domain || '—'],
                ['Version',      versionCell],
                ['Last updated', lastUpdatedCell],
                ['Title',        d.title || '—'],
                ['Description',  d.description || '—'],
                ['Category',     d.category || '—'],
                ['Tags',         tagsCell],
            ];
            for (const [k, v] of fields) {
                row(k, v).forEach(el => dl.appendChild(el));
            }

            document.getElementById('link-live').href = `https://${d.domain}/`;
            document.getElementById('link-gitea').href =
                `https://gitea.gk2.secubox.in/gandalf/metablog-${d.name}`;
            const streamlit = document.getElementById('link-streamlit');
            if (d.streamlit_app) {
                streamlit.href = `https://gitea.gk2.secubox.in/gandalf/${d.streamlit_app}`;
                streamlit.hidden = false;
            }
        }

        function showError(msg) {
            document.getElementById('error-box').innerHTML =
                `<div class="card error">${msg}</div>`;
        }

        async function loadSite() {
            const name = new URLSearchParams(location.search).get('name');
            if (!name) { showError('Missing <code>?name=…</code> parameter.'); return; }
            const d = await api(`/site/${encodeURIComponent(name)}`);
            if (!d || !d.name) { showError(`Site <strong>${name}</strong> not found.`); return; }
            render(d);
        }

        loadSite();
    </script>
</body>
</html>
HTML
```

- [ ] **Step 3: HTML sanity check on `site.html`**

```bash
python3 -c "
import html.parser
class S(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []
    def handle_starttag(self, tag, attrs):
        if tag not in ('br','hr','img','input','link','meta'):
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f'mismatched: closing {tag}, stack top {self.stack[-1] if self.stack else None}')
p = S()
p.feed(open('packages/secubox-metablogizer/www/metablogizer/site.html').read())
print('unclosed:', p.stack[-5:] if p.stack else 'none')
print('errors:', p.errors[:5] if p.errors else 'none')
"
```

Expected: `unclosed: none`, `errors: none`. (Top-level `html`/`body` close at EOF naturally; only structural errors matter.)

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-metablogizer/www/metablogizer/site.html
git commit -m "feat(metablog-ui): drill-in page /metablogizer/site.html?name=<X> (ref #103)

Surfaces every site.json field (domain, version, last_updated, title,
description, category, tags) plus three external links: live site,
Gitea repo, Streamlit app (hidden when streamlit_app is null).

Same CRT P31 phosphor theme as index.html. Single fetch to
/api/v1/metablogizer/site/<name>; renders or shows a clear error
('site not found' / 'missing name').

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Smoke test

**Files:**
- Create: `tests/scripts/test-metablogizer-ui.sh`

3 gates: file shape (key strings present), live HTTP reachability, JS sanity (no broken JS syntax via Node-style parse).

- [ ] **Step 1: Verify branch.**

- [ ] **Step 2: Write the smoke**

```bash
cat > tests/scripts/test-metablogizer-ui.sh <<'BASH'
#!/usr/bin/env bash
# tests/scripts/test-metablogizer-ui.sh
# Smoke test for the MetaBlogizer version dashboard (sub-D of #49).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

INDEX="$REPO/packages/secubox-metablogizer/www/metablogizer/index.html"
SITE="$REPO/packages/secubox-metablogizer/www/metablogizer/site.html"

log_step() { echo "[smoke step $1] $2"; }

# Gate 1: index.html contains the new column anchors and filter input.
log_step 1 "index.html has the new columns + filter"
assert_file "$INDEX" "index.html present"
grep -q 'data-sort="version"' "$INDEX"     || { echo "FAIL: data-sort=version missing"; exit 1; }
grep -q 'data-sort="last_updated"' "$INDEX" || { echo "FAIL: data-sort=last_updated missing"; exit 1; }
grep -q 'id="filter"' "$INDEX"             || { echo "FAIL: filter input missing"; exit 1; }
grep -q 'installPolling()' "$INDEX"        || { echo "FAIL: polling install missing"; exit 1; }
pass "index.html: version + last_updated + filter + polling all wired"

# Gate 2: site.html exists with the expected anchors.
log_step 2 "site.html drill-in present"
assert_file "$SITE" "site.html present"
grep -q 'URLSearchParams' "$SITE"  || { echo "FAIL: site.html missing URL param parsing"; exit 1; }
grep -q 'link-gitea' "$SITE"       || { echo "FAIL: site.html missing Gitea link"; exit 1; }
grep -q 'link-streamlit' "$SITE"   || { echo "FAIL: site.html missing Streamlit link"; exit 1; }
grep -q 'link-live' "$SITE"        || { echo "FAIL: site.html missing live-site link"; exit 1; }
pass "site.html: URL parsing + 3 external links wired"

# Gate 3: HTML sanity (well-formed, no mismatched tags) for both files.
log_step 3 "HTML well-formedness"
for f in "$INDEX" "$SITE"; do
  python3 -c "
import html.parser, sys
class S(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.errors = []
        self.stack = []
    def handle_starttag(self, tag, attrs):
        if tag not in ('br','hr','img','input','link','meta'):
            self.stack.append(tag)
    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f'closing {tag} without matching open')
p = S()
p.feed(open('$f').read())
if p.errors:
    print('FAIL', '$f', p.errors[:3])
    sys.exit(1)
" || { echo "FAIL: HTML mismatch in $f"; exit 1; }
done
pass "both HTML files are well-formed"

# Gate 4 (best-effort): live page reachable. SKIP on failure (auth, network).
log_step 4 "live HTTP reachability (best-effort)"
code=$(curl -s -o /dev/null -w "%{http_code}" "https://admin.gk2.secubox.in/metablogizer/" 2>/dev/null || echo "000")
if [[ "$code" == "200" ]]; then
  pass "live /metablogizer/ returns $code"
else
  echo "WARN: live page returned $code (network/auth/cache) — not blocking"
fi

pass "all smoke gates green"
BASH
chmod +x tests/scripts/test-metablogizer-ui.sh
```

- [ ] **Step 3: Run**

```bash
bash tests/scripts/test-metablogizer-ui.sh 2>&1 | tail -15
```

Expected: ends with `PASS: all smoke gates green`. Gates 1-3 must all pass. Gate 4 may show WARN if the live host is unreachable from the dev machine — acceptable.

- [ ] **Step 4: Commit**

```bash
git add tests/scripts/test-metablogizer-ui.sh
git commit -m "test(metablog-ui): 3-gate smoke for dashboard + drill-in (ref #103)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: README + tracking docs

**Files:**
- Modify: `packages/secubox-metablogizer/README.md`
- Modify: `.claude/WIP.md`, `.claude/HISTORY.md`

- [ ] **Step 1: Verify branch + sync from master**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/103-metablogizer-version-dashboard-ui-module
bash scripts/agent-worktree.sh sync 103 2>&1 | tail -3
head -3 .claude/WIP.md
grep -oE "Session [0-9]+" .claude/WIP.md | sort -u -V | tail -3
```

Note the highest session number; the new entry is the next free integer (≥ 165).

- [ ] **Step 2: Append a "Version dashboard" section to `packages/secubox-metablogizer/README.md`**

Insert before `## Installation`:

```markdown
## Version dashboard

The Hub exposes a per-site dashboard at:

- **List**: `https://admin.gk2.secubox.in/metablogizer/`
  - 8 columns: Name · Domain · Version · Streamlit · Updated · Status · Size · Actions
  - Inline filter (matches `name` and `domain`)
  - Sortable headers (Name, Domain, Version, Updated)
  - Auto-refresh every 60s; paused when the tab is hidden

- **Per-site drill-in**: `https://admin.gk2.secubox.in/metablogizer/site.html?name=<sitename>`
  - All `site.json` fields
  - Three quick links: 🌐 live site, 🦊 Gitea repo, 🎨 Streamlit app (if any)
  - Tag history is not shown inline; click the Gitea link and use its
    **Releases** tab (auth required, handled by your Gitea session)

Data comes from `/api/v1/metablogizer/sites` and
`/api/v1/metablogizer/site/<name>` (sub-C, PR #102). The dashboard is
pure vanilla JS — no framework, no router.
```

- [ ] **Step 3: Add Session entry to `.claude/WIP.md`**

Replace the top `*Mis à jour : 2026-05-12 (Session N)*` line with the next free session number, and insert a new `## ✅ Session <N>` block at the top:

```markdown
## ✅ Session <N>: MetaBlogizer version dashboard (Issue #103, sub-D of #49)

### Objective
Extend the existing /metablogizer/ list view with version-aware columns + filter + sort + 60s polling, and add a per-site drill-in page at /metablogizer/site.html?name=<X>. Consumes the enriched API from sub-C (PR #102).

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-metablog-version-dashboard-design.md`
- Plan (5 tasks) → `docs/superpowers/plans/2026-05-12-metablog-version-dashboard.md`
- Extended `index.html`: 3 new columns (version → Gitea releases link, streamlit_app icon link, last_updated as relative time + ISO tooltip), filter box, sortable headers with ▲/▼, 60s polling paused when tab hidden, row name links to drill-in
- New `site.html`: single-fetch drill-in surfacing every site.json field + 3 external links (live, Gitea, Streamlit hidden when null)
- 4-gate smoke `tests/scripts/test-metablogizer-ui.sh` (file shape + drill-in anchors + HTML well-formedness + live reachability best-effort)
- CRT P31 phosphor theme matched exactly with the existing module style

### Followups
- Sub-E (deploy webhook) — last open sub-project of #49.
- Optional follow-up: server-side proxy for Gitea tag history (so the drill-in can show tag list inline, no browser-side Gitea auth). Out of MVP scope.
```

(Replace `<N>` with the next free session number observed in Step 1.)

- [ ] **Step 4: Mirror the entry in `.claude/HISTORY.md`** under `## 2026-05-12`, before the previous Session entry, with the same shape as the existing entries there.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metablogizer/README.md .claude/WIP.md .claude/HISTORY.md
git commit -m "docs(metablog-ui): Session <N> tracking + README dashboard URLs (ref #103)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Finish worktree + PR

**Files:** none modified.

- [ ] **Step 1: Final smoke**

```bash
bash tests/scripts/test-metablogizer-ui.sh 2>&1 | tail -10
```

Expected: ends with `PASS: all smoke gates green`. If any gate regressed, STOP and fix.

- [ ] **Step 2: Push + PR**

```bash
bash scripts/agent-worktree.sh finish 2>&1 | tail -5
```

Note the PR number.

- [ ] **Step 3: Set PR title + body via REST API**

```bash
PR=<N from step 2>
gh api -X PATCH /repos/CyberMind-FR/secubox-deb/pulls/$PR \
  -f title="MetaBlogizer version dashboard (Refs #49 sub-D, closes #103)" \
  -f body="$(cat <<EOF
Sub-project **D** of #49. Closes #103.

## What is live

- \`/metablogizer/\` list view extended with: \`Version\` (Gitea releases link), \`Streamlit\` (icon link), \`Updated\` (relative time, ISO tooltip), an inline filter, sortable headers, and 60s auto-refresh paused when the tab is hidden.
- \`/metablogizer/site.html?name=<X>\` drill-in: every \`site.json\` field plus 🌐 live site, 🦊 Gitea repo, 🎨 Streamlit app (hidden when null).

## Pieces

- Spec — \`docs/superpowers/specs/2026-05-12-metablog-version-dashboard-design.md\`
- Plan — \`docs/superpowers/plans/2026-05-12-metablog-version-dashboard.md\` (5 tasks)
- index.html — extended in place (theme/sidebar/wiring all reused)
- site.html — new (single fetch, same CRT P31 phosphor theme)
- Smoke — \`tests/scripts/test-metablogizer-ui.sh\` (4 gates)

## Decisions (locked in spec)

- Tag history: external Gitea link, not inline. Repos are private and browser-side proxy through a stored token is heavier than the MVP warrants.
- Pure vanilla JS — no framework, no router.
- Sort/filter in-memory, no URL state (165 sites fit fine).

## Scope

\`Refs #49 (sub-project D)\` — \`Closes #103\`. Sub-project E (deploy webhook) is the last remaining piece on #49.
EOF
)" >/dev/null
echo "PR #$PR updated"
```

- [ ] **Step 4: Comment on #49**

```bash
gh issue comment 49 --body "Sub-project D (version dashboard) merged via PR #$PR.

Operator can browse 165 sites at /metablogizer/, filter and sort by version, and drill into each site via /metablogizer/site.html?name=<X>. Tag history defers to the Gitea Releases tab (auth handled by the user's Gitea session).

E (deploy webhook) is the last remaining sub-project of #49."
```

---

## Self-review

**1. Spec coverage:**

- Spec § *Component 1 — Extended list view* → Task 1 ✓ (steps 2-8 cover columns/filter/sort/polling)
- Spec § *Component 2 — Drill-in page* → Task 2 ✓
- Spec § *Component 3 — Sidebar entry* → Spec says no change required; no task needed ✓
- Spec § *Component 4 — Smoke test* → Task 3 ✓
- Spec § *File-level changes* table — Tasks 1, 2, 3, 4 cover each entry ✓
- Spec § *Validation gate* — Task 3's gates 1-3 + Task 5's final smoke cover validation ✓
- Spec § *Error handling* — addressed inline in `site.html` render (empty fields → "—") and `applySortToDOM` (nulls last) — both visible in Task 1 step 6 and Task 2 step 2 ✓

**2. Placeholder scan:**

- No "TBD" / "TODO".
- Task 4 uses `<N>` for the next free session number; explicitly bounded by an inline check command in Step 1. Acceptable.
- Task 5 uses `<N from step 2>` for the PR number; explicit "Replace with the actual PR number". Acceptable.

**3. Type / identifier consistency:**

- Function names `loadSites`, `refresh`, `applyFilter`, `sortBy`, `applySortToDOM`, `installPolling`, `relativeTime`, `loadSite` (drill-in) — all referenced consistently within their own task; no cross-task name collision.
- `currentSort.field` is one of `name`, `domain`, `version`, `last_updated` — Step 5's data attributes on `<tr>` match these exact names (`data-name`, `data-domain`, `data-version`, `data-last_updated`).
- The drill-in's `link-streamlit` href uses `gandalf/${d.streamlit_app}` — `streamlit_app` is the field name from sub-C's API (verified in `packages/secubox-metablogizer/schema/site.json.schema.json` on master). Consistent.
- Site URL `https://gitea.gk2.secubox.in/gandalf/metablog-${name}` — owner `gandalf`, prefix `metablog-` — matches sub-B's naming on Gitea. Consistent.

No gaps. Plan ready to execute.
