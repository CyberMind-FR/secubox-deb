<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2d: #social top-5 tracker view

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox`
- **Issue:** #633
- **Status:** Design approved, pending implementation plan
- **Origin:** operator request — "5 first top trackers only from list" in #social.

---

## 1. Goal

Tighten the `#social` panel's tracker table to show the **top-5** most-prevalent
trackers by default, with a **"tout afficher" toggle** to reveal the rest. The
aggregate endpoint already returns the top-50 by hits (`social.aggregate` →
`by_tracker_domain` sorted desc, `[:50]`), so this is a **pure frontend** change to
`loadSocial()` in `www/toolbox/index.html`. While editing that render block,
**HTML-escape `tracker_domain`** (observed-SNI-derived → same stored-XSS class
closed in Plan 2c-T4).

The blacklist-cap half of the operator's "both" choice is already shipped as the
cookie-xsite `COOKIE_XSITE_TOP_N=5` cap in Plan 2a — out of scope here.

### Decisions (from brainstorming)

| Question | Decision |
|---|---|
| #social top-5 | UI: show top-5 by default + "tout afficher (N)" expander |
| Blacklist cap | Already done (Plan 2a `COOKIE_XSITE_TOP_N=5`) — not in 2d |

---

## 2. Architecture / change

Single edit to the tracker-table render in `loadSocial()` (`www/toolbox/index.html`):

- Build the full rows from `agg.by_tracker_domain` (unchanged source), but render
  only the first **5** `<tr>` visible; wrap rows 6..N in a `<tbody>` (or rows) that
  starts hidden, plus a toggle control:
  - If `td.length <= 5`: render all, no toggle.
  - Else: render top-5 + a `<button>`/link **"▾ tout afficher (N)"** that, on click,
    reveals the hidden rows and flips its label to **"▴ réduire"** (and back).
- Implementation stays vanilla JS consistent with the file: a tiny inline `esc()`
  (escape `& < >`) applied to `tracker_domain`; the toggle uses a one-line handler
  that toggles a CSS `hidden`/`display` on the overflow rows and swaps the label.
- `hits`/`clients` are integers from the API — rendered as-is (no escape needed).

No backend change, no new endpoint, no new socket. The KPI line and the other
#social tables (clients / CDN / antibot / opgrade / device-blocks) are untouched.

## 3. Error handling

- The existing `agg.__error` / empty-list guards in `loadSocial` are preserved
  (`aucun tracker dans la fenêtre` when `td` is empty).
- The toggle is purely client-side DOM; if JS for the toggle errors it degrades to
  showing the top-5 (the hidden rows simply stay hidden) — no data loss.

## 4. Tests

No JS test harness in this package (consistent with 2c-T4). Static verification:
- `loadSocial` contains the top-5 slice + the "tout afficher" toggle + `esc(` on
  the tracker domain.
- `<script>` tags remain balanced; `python -m pytest tests/ -q` stays green
  (frontend change → no Python impact).

## 5. Rollout

Cosmetic, behavior-neutral on data. Ships with the rest of #633. No toggle, no
gating, no shared-dir/mode changes. The www dir is already shipped by `debian/rules`.

## 6. Out of scope

- Backend `by_tracker_domain` limit (stays top-50; UI just shows 5 first).
- The cookie-xsite blacklist cap (Plan 2a).
- Other #social tables.
