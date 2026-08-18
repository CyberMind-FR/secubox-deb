<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — Cookies cross-site tracker detection (surface R3 social-graph)

- **Issue:** #749
- **Date:** 2026-06-26
- **Status:** Approved (brainstorm), pending implementation plan
- **Author:** Gérald Kerma / CyberMind

## Problem

The operator wants to *detect cross-site-used cookies and their tracking targets*
("detecter les cross used et les target de suivis"). Investigation showed the
cross-site **correlation already exists** but is invisible to humans:

- `secubox_toolbox/learn.py::cookie_xsite_trackers()` (Anti-Track v2, #633) runs
  `GROUP BY cookie_id_hash, tracker_domain HAVING COUNT(DISTINCT src_site) >= 2`
  over `social_edges` (toolbox.db). It returns only a **top-N domain list**
  consumed by the **auto-blocker** — no detail, no operator view.
- `social_edges` is populated by `sbxmitm/social.go` → `/__toolbox/social-event`
  ingest. Live state (2026-06-26): 841 edges, src_site mostly valid
  (`leparisien.fr`=566, `google.com`=110, `chatgpt.com`=40 …; 84 rows have the
  literal string `"null"`).

So the gap is purely **surfacing** the existing correlation for the operator:
*which trackers follow our R3 visitors across N sites, with which cookies,
affecting how many clients.*

## Decisions (from brainstorm)

- **Population / source:** the **R3 social-graph** (3rd-party trackers following
  our tunnel visitors), NOT the WAF server-side cookie-audit self-audit angle.
- **Surface:** a panel inside the existing **secubox-cookies** dashboard.
- **Source of truth:** `social_edges` in `toolbox.db`, owned and exposed by the
  toolbox. The cookies dashboard consumes a toolbox endpoint; it does not read
  the DB directly (perms + duplication).
- **Auth path:** the cookies dashboard runs in the operator's browser, which
  already carries the operator JWT — it fetches the toolbox endpoint directly.
  No server-to-server auth.

## Approach (chosen: A)

**A — Toolbox aggregation endpoint + cookies WebUI panel (chosen).**
Single source of truth, reuses the existing query, no perms/auth friction.

**B — Duplicate the aggregation in the cookies module reading toolbox.db
(rejected).** `toolbox.db` is `0640 secubox-toolbox`; the cookies module runs as
`secubox` → perms friction + duplicated correlation logic.

## Components

### 1. Toolbox — read-only aggregation

New pure function (sibling of `cookie_xsite_trackers`), e.g.
`cookie_xsite_detail(conn, hours: int = 24, top_n: int = 50) -> list[dict]`:

- Reuses the cross-site predicate
  (`HAVING COUNT(DISTINCT src_site) >= 2`) but returns **rich rows** per
  registrable tracker domain:
  - `tracker_domain` (registrable)
  - `sites` — sorted list of distinct `src_site` (excludes `''` and `'null'`)
  - `site_count`
  - `client_count` — distinct `client_mac_hash`
  - `cookie_count` — distinct `cookie_id_hash`
  - `pre_consent_hits` — count where `consent_state = 'pre_consent'`
  - `last_seen` — max ts (epoch)
- Window: only edges with `ts >= now - hours*3600`.
- Ranking: by `client_count` desc, then `site_count` desc, then domain — capped
  to `top_n`.
- Defensive: returns `[]` on any `sqlite3.Error` (mirrors existing pattern).

New endpoint (toolbox FastAPI, JWT, read-only):

```
GET /admin/cookie-crosssite?hours=24&top=50
→ { "trackers": [ {tracker_domain, sites, site_count, client_count,
                   cookie_count, pre_consent_hits, last_seen}, … ],
    "window_hours": 24, "generated_at": <epoch> }
```

Placed next to the existing `/admin/social-aggregate` route. Reaches `social_edges`
through the same connection helper the other social endpoints use.

### 2. secubox-cookies — WebUI panel

In `packages/secubox-cookies/www/cookies/index.html`:

- New section **"🕸️ Trackers cross-site"** in the existing "Cookie Tracker"
  dashboard.
- A table sorted by client_count then site_count, columns:
  *Tracker · Sites suivis (badge N + tooltip listing the sites) · Clients ·
  Cookies · Pré-consent · Vu (relative).*
- `loadCrossSite()` does `fetch('/api/v1/toolbox/admin/cookie-crosssite?hours=24')`
  with the standard JWT-bearing fetch helper already used by the dashboard.
- Graceful degradation: empty `trackers` (or fetch failure) renders an
  informative empty state ("aucune donnée R3 récente — tunnel captif inactif"),
  never a broken table.
- No new dependency, no new service, no backend change in the cookies module
  itself (pure frontend addition consuming the toolbox endpoint).

## Data flow

```
sbxmitm/social.go  →  POST /__toolbox/social-event  →  social_edges (toolbox.db)
        (existing)            (existing)                    (existing)
                                                                │
                                  cookie_xsite_detail()  ◀──────┘   (new)
                                          │
                              GET /admin/cookie-crosssite           (new)
                                          │
                cookies dashboard loadCrossSite() fetch + render    (new)
```

## Testing

- **Unit (toolbox):** seed an in-memory sqlite `social_edges` with a tracker on
  ≥2 distinct sites + a 1-site tracker; assert `cookie_xsite_detail` returns only
  the cross-site one with correct `site_count` / `client_count` / `cookie_count`,
  excludes `src_site IN ('','null')`, respects the time window and `top_n` cap.
- **Endpoint:** assert `GET /admin/cookie-crosssite` requires JWT, returns the
  envelope shape, and is read-only.
- **Frontend:** manual — verify the panel renders rows from a live/seeded
  endpoint and shows the empty state when `trackers` is `[]`.

## Out of scope

- Fixing the R3 capture flow (edges stale since ~15:45 = idle tunnel, not this
  feature's bug).
- Re-correlating / re-deriving edges (reuse `social_edges` as-is).
- Migrating the 84 `src_site='null'` rows (filtered at read time instead).
- The WAF server-side cookie-audit self-audit angle (explicitly deprioritised in
  the brainstorm).

## Privacy

All identifiers exposed are already hashed at source: `client_mac_hash` (rotating
daily salt), `cookie_id_hash` (sha256 truncated, raw cookie values never reach the
ingest). The endpoint exposes counts and registrable tracker/site domains only —
no raw cookie values, no client identity. Consistent with the toolbox R2 doctrine.
