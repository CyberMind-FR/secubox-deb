<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2d (#social top-5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show the top-5 trackers by default in the `#social` panel with a "tout afficher" expander, and HTML-escape the tracker domain — a pure frontend change to `loadSocial()`.

**Architecture:** Edit the tracker-table render block in `loadSocial()` (`www/toolbox/index.html`). The aggregate already returns top-50 `by_tracker_domain`; render the first 5 visible, rows 6+ hidden behind a toggle. Vanilla JS, no backend change.

**Tech Stack:** vanilla JS in `www/toolbox/index.html`. No Python impact. Issue #633.

**Spec:** `docs/superpowers/specs/2026-06-17-anti-track-v2-plan2d-social-top5-design.md`.

**Conventions:** worktree `secubox-deb-worktrees/633-…` branch `feature/633-…`; commits end `(ref #633)`.

**Verified current code** (the block to replace, in `loadSocial`):
```javascript
    const td = agg.by_tracker_domain || [];
    trk.innerHTML = td.length
        ? '<table><thead><tr><th>Tracker domain</th><th>hits</th><th>clients</th></tr></thead><tbody>' +
          td.map(r => `<tr><td><code>${r.tracker_domain}</code></td><td>${r.hits}</td><td>${r.clients}</td></tr>`).join('') +
          '</tbody></table>'
        : '<div class="empty">aucun tracker dans la fenêtre</div>';
```

---

### Task 1: top-5 default + toggle + escape in `loadSocial`

**Files:**
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` (the tracker block in `loadSocial`)

- [ ] **Step 1: Locate the block**

Run: `cd packages/secubox-toolbox && grep -n "by_tracker_domain\|social-trackers\|aucun tracker" www/toolbox/index.html`
Confirm the block matches the "Verified current code" above (the `const td = ...; trk.innerHTML = ...` lines).

- [ ] **Step 2: Replace the block**

Replace exactly that `const td = ...` / `trk.innerHTML = ...` block with:
```javascript
    const td = agg.by_tracker_domain || [];
    const escT = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (!td.length) {
        trk.innerHTML = '<div class="empty">aucun tracker dans la fenêtre</div>';
    } else {
        const row = r => `<tr class="sbx-trk-row"><td><code>${escT(r.tracker_domain)}</code></td><td>${r.hits}</td><td>${r.clients}</td></tr>`;
        const head = '<table><thead><tr><th>Tracker domain</th><th>hits</th><th>clients</th></tr></thead><tbody>';
        const top = td.slice(0, 5).map(row).join('');
        const rest = td.slice(5).map(row).join('');
        let html = head + top;
        if (td.length > 5) {
            html += '<tr id="sbx-trk-more" style="display:none">' + '</tr>'.repeat(0) + '';  // placeholder removed below
        }
        // Build the hidden rows + toggle without nesting <tr> incorrectly:
        if (td.length > 5) {
            html = head + top + '</tbody></table>'
                 + '<table style="margin-top:0"><tbody id="sbx-trk-rest" style="display:none">' + rest + '</tbody></table>'
                 + `<button type="button" id="sbx-trk-toggle" onclick="(function(b){var x=document.getElementById('sbx-trk-rest');var on=x.style.display==='none';x.style.display=on?'':'none';b.textContent=on?'▴ réduire':('▾ tout afficher ('+${td.length}+')');})(this)" style="margin-top:6px;background:none;border:0;color:var(--p31,#2C70C0);cursor:pointer;font-size:0.8rem">▾ tout afficher (${td.length})</button>`;
        } else {
            html = head + top + '</tbody></table>';
        }
        trk.innerHTML = html;
    }
```

NOTE: keep it simpler if the above feels convoluted — the REQUIRED behavior is: (a)
escape `tracker_domain` via `escT`; (b) ≤5 → render all in one table, no toggle;
(c) >5 → render the top-5 table, then the remaining rows in a second `<tbody>` that
starts `display:none`, then a toggle button that flips that display and swaps its
label between `▾ tout afficher (N)` and `▴ réduire`. A clean equivalent
implementation is acceptable as long as it produces valid HTML (no stray
placeholder line — delete the `// placeholder` line) and the static checks in Step 3
pass. Prefer the clean form:
```javascript
    const td = agg.by_tracker_domain || [];
    const escT = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (!td.length) {
        trk.innerHTML = '<div class="empty">aucun tracker dans la fenêtre</div>';
    } else {
        const row = r => `<tr><td><code>${escT(r.tracker_domain)}</code></td><td>${r.hits}</td><td>${r.clients}</td></tr>`;
        const top = td.slice(0, 5).map(row).join('');
        const rest = td.slice(5).map(row).join('');
        let html = '<table><thead><tr><th>Tracker domain</th><th>hits</th><th>clients</th></tr></thead>'
                 + '<tbody>' + top + '</tbody>';
        if (rest) {
            html += '<tbody id="sbx-trk-rest" style="display:none">' + rest + '</tbody>';
        }
        html += '</table>';
        if (rest) {
            html += `<button type="button" onclick="(function(b){var x=document.getElementById('sbx-trk-rest');var on=x.style.display==='none';x.style.display=on?'':'none';b.textContent=on?'▴ réduire':'▾ tout afficher (${td.length})';})(this)" style="margin-top:6px;background:none;border:0;color:var(--p31,#2C70C0);cursor:pointer;font-size:0.8rem">▾ tout afficher (${td.length})</button>`;
        }
        trk.innerHTML = html;
    }
```
USE THE CLEAN FORM above (two `<tbody>` in one table + a toggle button). Discard the
convoluted first variant entirely.

- [ ] **Step 3: Static verification**

Run from `packages/secubox-toolbox`:
- `grep -n "escT\|sbx-trk-rest\|tout afficher\|td.slice(0, 5)" www/toolbox/index.html` → all present.
- `python -c "import pathlib;t=pathlib.Path('www/toolbox/index.html').read_text();assert t.count('<script')==t.count('</script>');assert 'escT(r.tracker_domain)' in t and 'sbx-trk-rest' in t and 'td.slice(0, 5)' in t;print('ok')"` → `ok`.
- Quick brace/paren sanity on the toggle: ensure no unescaped backtick/quote breaks the template literal — `python -c "import pathlib;t=pathlib.Path('www/toolbox/index.html').read_text();assert \"tout afficher (\" in t;print('toggle ok')"`.
- `python -m pytest tests/ -q` → unchanged (~57; frontend-only).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/www/toolbox/index.html
git commit -m "feat(toolbox): #social shows top-5 trackers + tout-afficher toggle, escape domain (ref #633)"
```

---

### Task 2: changelog + gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Bump changelog**

`head -3 debian/changelog` (top should be `2.6.46-1~bookworm1` on this branch). Add a new top entry `2.6.47-1~bookworm1`, dch format, author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17:
```
  * Anti-Track v2 Plan 2d (#633): #social tracker table shows the top-5 by
    default with a "tout afficher" toggle for the rest; tracker domain
    HTML-escaped in the render (stored-XSS hardening). Pure frontend.
```

- [ ] **Step 2: Gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect unchanged green ~57).
Run: `python -c "import pathlib;t=pathlib.Path('www/toolbox/index.html').read_text();assert t.count('<script')==t.count('</script>');print('html ok')"`.
Run: `dpkg-parsechangelog -l debian/changelog | grep Version` → `2.6.47-1~bookworm1`.
Run: `git status --short` → empty after commit.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog for Anti-Track v2 Plan 2d (ref #633)"
```

---

## Self-Review

**Spec coverage:**
- top-5 default + "tout afficher (N)" toggle revealing rows 6+ → Task 1 (two-`<tbody>` + button). ✓
- ≤5 → no toggle → Task 1 (`if (rest)` guards the toggle). ✓
- escape `tracker_domain` → Task 1 (`escT`). ✓
- empty-list guard preserved (`aucun tracker dans la fenêtre`) → Task 1. ✓
- no backend change, other #social tables untouched → only the tracker block edited. ✓
- changelog/ship → Task 2 (www already shipped by debian/rules). ✓

**Placeholder scan:** the first code variant in Task 1 Step 2 intentionally contains a `// placeholder` line and is explicitly DISCARDED in favor of the clean form below it — the plan instructs to USE THE CLEAN FORM. No placeholder reaches the code.

**Type consistency:** `escT` defined and used on `tracker_domain` only; `td.slice(0,5)`/`.slice(5)`; toggle id `sbx-trk-rest` referenced by the button handler — consistent. `hits`/`clients` are ints, rendered unescaped (safe).

**Rollout:** cosmetic, data-neutral; ships with #633. No gating, no shared-dir changes.
