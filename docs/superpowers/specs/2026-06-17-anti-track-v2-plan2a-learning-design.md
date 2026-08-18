<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2a: Learning → Blacklist (domain lists)

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox`
- **Issue:** #633
- **Status:** Design approved, pending implementation plan
- **Parent spec:** `docs/superpowers/specs/2026-06-17-anti-tracking-v2-design.md` (§5.1)
- **Builds on:** Plan 1 (the `privacy.py` brain already reads `learned-trackers.txt`
  and `pure-trackers.txt`; this plan produces them).

---

## 1. Goal

Extend the existing hourly `autolearn` job so the blacklist is learned from the
board's own traffic with two new, safe signals:

1. **cookie-xsite** — a domain that sets a third-party cookie whose id is reused
   across ≥2 of the user's sites pre-consent (the textbook definition of a
   tracking cookie). This is the realisation of *"utiliser les domaines des
   cookies traceurs pour blacklister."* Because it is new and false positives
   blacklist a domain, it is **capped to the top-N most-prevalent** setters.
2. **pure-trackers promotion** — populate `pure-trackers.txt`, the allowlist
   Plan 1's `classify()` consults to *hard-block* (DNS/nft/204) rather than poison.
   Today that file is absent, so the engine is poison-only; this plan gives it a
   curated seed plus conservative auto-promotion.

This plan produces **domain lists only**. IP resolution, the CDN/cloud allowlist,
exclusive-tracker-IP computation, nft drop, and the dns-guard feed are **Plan 2b**
(enforcement) — moved there because they need network resolution and the allowlist,
which are enforcement concerns. The webui items (`#social` top-5, `#filtres`
bypass panel) are **Plan 2c/2d**.

### Decisions locked during brainstorming

| Question | Decision |
|---|---|
| Top-N cap scope | Cap **only** the new cookie-xsite signal; opgrade + threat-intel stay uncapped |
| Top-N value | Default **5** (`COOKIE_XSITE_TOP_N`, env-overridable) |
| pure-trackers population | **Curated seed + conservative auto-promote** |
| Auto-promote safety proxy | seen ≥3 sites AND `cdn_vendor IS NULL` AND never first-party |

---

## 2. Architecture

A new pure-Python module `secubox_toolbox/learn.py` holds the testable logic;
the existing `sbin/secubox-toolbox-autolearn` script imports it and calls the
functions. This lets us unit-test the SQL/threshold logic against an in-memory
SQLite database instead of exercising the script end-to-end.

```
sbin/secubox-toolbox-autolearn  (hourly timer, EXISTING — extended)
   ├─ existing: threat_intel domains + social opgrade (≥2 sites)   → learned set
   ├─ NEW: learn.cookie_xsite_trackers(conn, top_n)  → top-N domains, tag cookie-xsite
   │        → folded into the learned set
   ├─ writes /var/lib/secubox/toolbox/learned-trackers.txt (atomic)  [EXISTING file]
   └─ NEW: learn.pure_trackers(conn, learned, seed)  → pure set
            → writes /var/lib/secubox/toolbox/pure-trackers.txt (atomic) [NEW file]

secubox_toolbox/learn.py  (NEW, pure functions, no network, unit-tested)
   • cookie_xsite_trackers(conn, top_n) -> list[str]
   • pure_trackers(conn, learned, seed) -> set[str]
   • PURE_SEED  (curated constant)
```

**Files**
- **New:** `secubox_toolbox/learn.py`, `tests/test_learn.py`.
- **Extended:** `sbin/secubox-toolbox-autolearn` (call the two new functions, write
  the new file).
- **Untouched:** `social.py`/`social_graph.py` schema, the timer, the existing
  opgrade/threat-intel learning, Plan 1's `privacy.py` (already reads both files).

**Boundary.** `learn.py` is pure: it takes a `sqlite3.Connection` and returns
lists/sets; it never resolves DNS, touches nft, or writes files. The script owns
I/O (DB open, atomic file writes). This keeps the learning logic testable in
isolation.

---

## 3. cookie-xsite signal — `cookie_xsite_trackers(conn, top_n)`

**Definition.** A `tracker_domain` is a cross-site cookie tracker when a single
`cookie_id_hash` it set is observed across **≥2 distinct `src_site`** values in
`social_edges`, with at least one observation in a **pre-consent** state.

**Query shape** (over `social_edges`; columns confirmed present:
`tracker_domain`, `src_site`, `cookie_id_hash`, `consent_state`):
```sql
SELECT tracker_domain,
       COUNT(DISTINCT src_site)        AS sites,
       COUNT(DISTINCT client_mac_hash) AS clients,
       SUM(hits)                       AS hits
FROM social_edges
WHERE cookie_id_hash IS NOT NULL AND cookie_id_hash <> ''
GROUP BY cookie_id_hash, tracker_domain
HAVING sites >= 2
   AND <pre-consent evidence: consent_state indicates pre-consent>
```
The pre-consent predicate uses the same `consent_state` encoding `social.fold_recent`
already uses (verify the exact sentinel during implementation: the value written
before a consent cookie is seen). Results are folded to **registrable domain**
(reusing `privacy.registrable`), aggregated, then ranked by `clients` desc, then
`hits` desc. Return the **top-N** registrable domains (`N = top_n`).

**Cap.** `COOKIE_XSITE_TOP_N` default **5**, overridable via env (mirrors the
existing `MIN_SITES`/`MAX_ENTRIES` constants in the autolearn script). Only this
signal is capped; the existing signals are unaffected.

**Output.** The returned domains are unioned into the existing learned set and
written to `learned-trackers.txt`. (The file format is one host per line; the
reason tag `cookie-xsite` is recorded in a trailing comment field so the UI can
show provenance — keep the first whitespace-delimited token the bare host so
Plan 1's loader, which reads `tok[0]`, is unaffected.)

---

## 4. pure-trackers promotion — `pure_trackers(conn, learned, seed)`

`pure-trackers.txt` is the allowlist Plan 1 consults to hard-block. Populated from
two sources, unioned:

**Curated seed** (`PURE_SEED`, a module constant): unambiguous pure beacon/ad
hosts that never carry first-party content — `google-analytics.com`,
`doubleclick.net`, `scorecardresearch.com`, plus the hosts in `ad_ghost._AD_HOST`
(import or mirror the registrable forms). These are always present regardless of
observed traffic.

**Conservative auto-promote.** A domain in `learned` is promoted to pure only when
**all** hold:
- seen on **≥3 distinct sites** (from `social_nodes.sites_jsonl` / distinct
  `src_site`), AND
- `social_host_meta.cdn_vendor IS NULL` — it is **not** a CDN, so hard-blocking it
  will not strip cached page content (the safety proxy for "not load-bearing"), AND
- its registrable domain is **never itself a first-party site** in the data (its
  registrable never equals the registrable of any observed `src_site`).

Anything failing these stays **loadbearing** (poison, never block) — fail-safe.

**Output.** `pure-trackers.txt`, one registrable host per line, atomic write.
Eligibility ≠ enforcement: Plan 1 still only hard-blocks when `privacy_enforce=true`
(dark by default), so this file is inert until the engine is armed.

---

## 5. autolearn wiring, config, error handling

- The script opens the toolbox SQLite DB (existing pattern), calls
  `cookie_xsite_trackers` and `pure_trackers`, and writes both files via
  temp-file + `os.replace` (atomic; matches existing list writes).
- `COOKIE_XSITE_TOP_N` constant (default 5) read from env like the existing
  `MIN_SITES`.
- **Error handling:** each new signal is wrapped so a query failure logs and yields
  an empty contribution rather than aborting the whole autolearn run (the existing
  opgrade/threat-intel learning must still complete). A missing/locked DB → both
  new outputs are skipped, previous files left intact (atomic writes guarantee no
  partial state). Fail toward *fewer* blacklist entries, never a corrupt file.
- No new daemon, no new timer, no hot-path cost — all of this is the offline hourly
  job.

---

## 6. Tests (`tests/test_learn.py`, in-memory SQLite)

Build a tiny `social_edges` / `social_nodes` / `social_host_meta` fixture and assert:
- **cookie-xsite:** a `cookie_id_hash` on ≥2 sites pre-consent → its domain is
  returned; a cookie on a single site → not returned; a post-consent-only cookie →
  not returned; `top_n` truncates to the most-prevalent N (rank by clients then hits);
  results are registrable-folded.
- **pure auto-promote:** a learned tracker on ≥3 sites with `cdn_vendor IS NULL`
  and never first-party → promoted; same host with a `cdn_vendor` set → NOT promoted;
  same host seen on only 2 sites → NOT promoted; a host whose registrable also
  appears as a `src_site` → NOT promoted; the curated seed is always present.
- **purity of `learn.py`:** functions perform no file/network I/O (they take a
  connection, return data).

---

## 7. Out of scope (later plans)

- IP resolution, CDN/cloud allowlist, exclusive-tracker-IP set, nft drop,
  dns-guard feed → **Plan 2b**.
- `#social` top-5 UI + blacklist-display, `#filtres` bypass panel with source →
  **Plan 2c/2d**.
- ignore_hosts curated seed of cert-pinned hosts → **Plan 2c**.
