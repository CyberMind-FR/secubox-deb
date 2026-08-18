<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer Version Dashboard — Design

**Date:** 2026-05-12
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Issue:** [#103](https://github.com/CyberMind-FR/secubox-deb/issues/103) (sub-project D of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** [#102](https://github.com/CyberMind-FR/secubox-deb/pull/102) (merged — sub-C: schema + enriched API)

## Context

`packages/secubox-metablogizer/www/metablogizer/index.html` already exists (533 lines, served live at `https://admin.gk2.secubox.in/metablogizer/`). It has a tabbed layout (Sites / Access / Actions), stat cards, a sites table that consumes `/api/v1/metablogizer/sites`, and the CRT P31 phosphor theme.

What's missing for D:

- Columns for `version`, `streamlit_app`, `last_updated` (sub-C now exposes these on the API).
- A filter box (165 sites is too many to scroll).
- Sortable columns.
- A 60-second auto-refresh (today: manual button only).
- A per-site drill-in page.

## Goal

Extend the existing list view with version-aware columns, filter, sort, and polling — plus add a per-site drill-in page that surfaces every site.json field and links out to Gitea / live site / Streamlit app.

## Non-goals

- Editing site.json from the UI (no inline edit, no form posts).
- Triggering deploys / rollbacks (sub-E concern).
- Per-tag diff view inside the UI (operator follows the external Gitea link).
- Fetching Gitea tag history from the browser (repos are private — needs server-side proxying, defer to a separate iteration).
- Bulk operations (multi-select, batch publish, etc.).

## Decisions taken in brainstorming

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scaffold or extend? | Extend the existing 533-line `index.html` | Avoid duplicating layout/theme/sidebar wiring; UI lives in `packages/secubox-metablogizer/www/metablogizer/` per the established Hub pattern |
| Drill-in route | Separate file `site.html?name=<X>` (query-string param) | Deep-linkable; one URL maps to one site; no JS router needed |
| Tag history in drill-in | **External link to Gitea** (no inline fetch) | Repos are private; browser-side Gitea auth is brittle. Operator clicks → opens Gitea Releases tab in a new tab |
| Sort/filter scope | In-memory JS, no URL state | 165 items fit easily; URL state adds complexity without UX win |
| Refresh cadence | 60 s polling, paused when tab hidden | Cheap (one API call); `document.hidden` skip avoids waste |
| Streamlit link | Visible only when `streamlit_app != null` | Half the sites have one, half don't |

## Architecture

### Component 1 — Extended list view (`index.html`)

The existing `loadSites()` function takes `d.sites` from the API and renders 5 columns. We add 3 columns and 3 toolbar features.

**New table columns** (between `domain` and `published`):

| Column | Source | Render |
|--------|--------|--------|
| Version | `s.version` (from `.deploy.json` or `git describe`) | `<code class="version">v1.0.0</code>` — links to `https://gitea.gk2.secubox.in/gandalf/metablog-<name>` (releases tab anchor) |
| Streamlit | `s.streamlit_app` | If non-null: 🎨 icon + link to `https://gitea.gk2.secubox.in/gandalf/streamlit-<name>`. If null: empty cell |
| Updated | `s.last_updated` | Relative time ("2d ago") via small format helper; tooltip shows the full ISO 8601 |

**Filter box** — placed above the table, inside the existing `<div class="card">` that wraps the Sites tab:

```html
<input type="search"
       id="filter"
       placeholder="Filter by name or domain…"
       oninput="applyFilter()">
```

`applyFilter()` walks `.site-row` `<tr>`s and toggles `display: none` based on case-insensitive substring match.

**Sortable headers** — each `<th>` carries `data-sort="<field>"` and a click handler:

```html
<th data-sort="name" onclick="sortBy(this)">Name <span class="sort-ind"></span></th>
```

`sortBy(th)` toggles asc/desc, updates the `sort-ind` to ▲/▼, and re-renders the rows. Current sort state lives in two module-level vars: `currentSort = {field: 'name', dir: 'asc'}`.

**60-second polling** — at the end of `refresh()`:

```js
setInterval(() => { if (!document.hidden) refresh(); }, 60000);
```

Just once; subsequent calls don't stack timers. The function is wrapped in a guard so the timer isn't installed twice.

### Component 2 — Drill-in page (`site.html`)

New file at `packages/secubox-metablogizer/www/metablogizer/site.html`. Same CRT P31 phosphor theme via `<link rel="stylesheet" href="/shared/crt-light.css">` and inline `<style>` block matching `index.html`.

Structure:

```
<sidebar>  (from /shared/sidebar.js, same as index.html)
<main>
  <header>
    <h1 class="cinzel">{{name}}</h1>
    <span class="badge published|draft">…</span>
  </header>
  <div class="card">
    <h2>Metadata</h2>
    <dl>
      <dt>Domain</dt>      <dd>{{domain}}</dd>
      <dt>Version</dt>     <dd><code>{{version}}</code></dd>
      <dt>Last updated</dt><dd>{{last_updated}} ({{relative}})</dd>
      <dt>Title</dt>       <dd>{{title or "—"}}</dd>
      <dt>Description</dt> <dd>{{description or "—"}}</dd>
      <dt>Category</dt>    <dd>{{category or "—"}}</dd>
      <dt>Tags</dt>        <dd>{{tags.join(", ") or "—"}}</dd>
    </dl>
  </div>
  <div class="card actions">
    <h2>Quick links</h2>
    <a class="btn primary" href="https://{{domain}}/" target="_blank">🌐 Live site</a>
    <a class="btn" href="https://gitea.gk2.secubox.in/gandalf/metablog-{{name}}" target="_blank">🦊 Gitea repo</a>
    {{#streamlit_app}}
      <a class="btn success" href="https://gitea.gk2.secubox.in/gandalf/streamlit-{{name}}" target="_blank">🎨 Streamlit app</a>
    {{/streamlit_app}}
  </div>
  <div class="card hint">
    <p>For tag history and deploys, see the
       <strong>Releases</strong> tab on the Gitea repo (auth required).</p>
  </div>
</main>
```

JS:

```js
async function loadSite() {
  const name = new URLSearchParams(location.search).get('name');
  if (!name) { document.body.innerHTML = '<p>Missing ?name=…</p>'; return; }
  const d = await api(`/site/${name}`);
  if (!d || !d.name) { document.body.innerHTML = `<p>Site ${name} not found</p>`; return; }
  render(d);
}
```

`render(d)` substitutes the placeholders and toggles the Streamlit button visibility.

No polling on this page — site metadata changes rarely. Operator hits browser refresh if needed.

### Component 3 — Sidebar entry

Already exists in `packages/secubox-hub/www/shared/sidebar.js:182`:

```js
'/metablogizer/': { metrics: ['sites', 'published', 'nginx'], api: '/api/v1/metablogizer/status' },
```

No change required for sub-D.

### Component 4 — Smoke test

`tests/scripts/test-metablogizer-ui.sh` runs against the live Hub. Three gates:

1. `curl -s https://admin.gk2.secubox.in/metablogizer/` → HTTP 200, body contains `data-sort="version"` and `id="filter"`.
2. `curl -s https://admin.gk2.secubox.in/metablogizer/site.html?name=zkp` → HTTP 200, body contains `zkp` and `gitea.gk2.secubox.in/gandalf/metablog-zkp`.
3. JS sanity: HTML must validate as well-formed (no unclosed tags) — use `python3 -c "import html.parser; …"` to walk the file and count open/close tags. (No need for a full headless-browser test.)

If the live Hub deploys behind auth (it does), gate 1 may need a JWT for the actual page render. The smoke is acceptable if step 1 returns 200 even with a redirect to login — we're checking that the file *exists* and is served. The actual contents are validated by the JS-level check on the file in the repo.

## File-level changes

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `packages/secubox-metablogizer/www/metablogizer/index.html` | +3 columns, filter box, sort handlers, 60s polling |
| Create | `packages/secubox-metablogizer/www/metablogizer/site.html` | Drill-in page (≈ 200-250 lines) |
| Create | `tests/scripts/test-metablogizer-ui.sh` | 3-gate smoke |
| Modify | `packages/secubox-metablogizer/README.md` | Document the dashboard URL + drill-in URL pattern |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 165 entry |

## Validation gate

Done when:

1. `bash tests/scripts/test-metablogizer-ui.sh` reports all 3 gates green.
2. Visiting `https://admin.gk2.secubox.in/metablogizer/` shows 165 rows with the new columns populated. (Spot-check: `zkp` has `v1.0.0`, `last_updated` shows a relative time.)
3. Typing in the filter box reduces the visible row count live.
4. Clicking the `Name` `<th>` toggles ▲ / ▼ and re-sorts the table.
5. Visiting `https://admin.gk2.secubox.in/metablogizer/site.html?name=zkp` shows the drill-in card with all fields, plus 3 external links (the Streamlit one is hidden if `streamlit_app` is null).
6. Leaving the tab open 60s triggers a single refresh (verify via DevTools Network panel).

## Error handling

| Failure | Detection | Response |
|---------|-----------|----------|
| `/sites` returns 401 | Existing `api()` helper already redirects to `/login.html` | No change needed |
| `/site/<name>` returns 404 | Drill-in's `render(d)` sees `!d.name` | Render "Site not found" message |
| `last_updated` is null | Renderer | Show "—" instead of relative time |
| `streamlit_app` is null | Renderer | Hide the Streamlit button (display: none) |
| User opens `site.html` with no `?name=` | URL parser | Render "Missing ?name=…" |
| Sort on a column where some rows have `null` (e.g. last_updated) | JS comparator | Nulls sort last in ascending, first in descending |
| 60s timer would fire while tab hidden | `document.hidden` check | Skip refresh, wait for the next interval |

## Testing

Operational + DOM-based. No unit tests for the JS (vanilla, small surface). The smoke test verifies HTTP reachability and key string presence. Manual eyeball pass on a live render covers the rest.

## Open questions

None blocking. The deferred Gitea tag fetch is documented as a future enhancement.

## Licensing

CMSD-1.0. HTML/JS files inherit the existing module's licensing header (kept as-is on edit, added to new `site.html` to match the file already serving as `index.html`).
