<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Sentinel Activation + ToolBoX Surfaces (WebUI tab · kbin report · PDF) — Design

**Date:** 2026-07-06
**Related:** #823 (sbxmitm Sentinel engine, merged dark via #824)
**Status:** Design — pending user review

---

## Goal

Bring the `sbx-sentinel` compromise-detection daemon **live** and surface its
findings on every place the ToolBoX user/admin looks at their security, then
produce a demo artifact.

1. **Activate Sentinel** on gk2 — async / report-only / defensive. Currently
   dark: no binary deployed, units installed `--no-enable --no-start`,
   `SENTINEL_HTTP_ADDR` empty. Run the daemon consuming the sbxmitm mirror
   channel, with a localhost status HTTP.
2. **Three surfaces** for the detections:
   - **A. WebUI ToolBoX tab** — a fleet view (all recent detections) in the
     admin portal (`www/toolbox/index.html`, sub-tab nav #513, `:8088`).
   - **B. kbin report HTML tab** — a per-device tab in the ephemeral "mon
     rapport" (`conf/report-live.html.j2`), keyed on the report's `mac_hash`.
   - **C. PDF report section** — a Sentinel section in `render_pdf`
     (`reports.py`), same per-device data.
3. **Test + use** the daemon end-to-end (placeholder-IOC flow → verdict →
   visible on all three surfaces).
4. **Demo prompt** — after it works, produce a GPT prompt (doc artifact)
   demonstrating the kbin's augmentation by this new Sentinel function group.

Non-goal: enabling the inline hot-path *blocking* gate. Sentinel stays
report-only (heuristic/zero-click never auto-block; `FinalizeAction`
threshold 85). All surfaces carry `mac_hash` only — no other PII.

---

## Background — what already exists

- **Daemon** `sbx-sentinel` (Go, `packages/secubox-toolbox-ng/cmd/sbx-sentinel`):
  consumes the mirror channel, runs analyzers (IOC gate / spyware / YARA-stub /
  behavioral), records verdicts to a bbolt store, exposes a read-only status HTTP:
  - `GET /stats`    → `{"detections":N,"blocked":N,"spyware":N}`
  - `GET /verdicts?limit=N` → list of
    `{class,severity,confidence,action,evidence,mac_hash,ts,report}`
    (`report` = rendered plain-text threat report; keys lowercase).
  Bound to `SENTINEL_HTTP_ADDR`; **empty = disabled** (current state).
  Store already has `Recent(limit)` and `ByMac(macHash, limit)`.
- **Env** `/etc/secubox/sentinel.env`: `SENTINEL_ENABLED=0`,
  `SENTINEL_MIRROR_SOCK=/run/secubox/sentinel-mirror.sock`,
  `SENTINEL_STORE_DB=/var/lib/secubox/sentinel/verdicts.db`,
  `SENTINEL_HTTP_ADDR=` (empty), pack/overlay dirs, feed URLs.
- **Units**: `sbx-sentinel.service`, `secubox-sentinel-feeds.{service,timer}` —
  installed disabled, not started.
- **Portal** (`secubox-toolbox`, Python/FastAPI, `:8088`):
  - Tabs in `www/toolbox/index.html`: `<nav class="tabs" id="tabs">` of
    `<button data-tab="…" onclick="switchTab('…')">` + `<section class="panel"
    id="panel-…">`. Existing: overview, clients, filtres, social, ads, reseau,
    tor, config. P31 light skin.
  - Routes: `APIRouter(tags=["toolbox"])` in `secubox_toolbox/api.py`.
  - Per-device report: `build_report_data(mac_hash, session_data)` →
    `render_pdf(report)` (PDF) and `conf/report-live.html.j2` (HTML). The HTML
    already has a tabbed shell (#699: `.tabs`/`.tab-pane`); the PDF already has
    `_section` "🚨 ANALYSE COMPROMISSION" and "THREAT INTEL" sections.

Board state (gk2, 2026-07-06): `sbx-sentinel` binary **absent**; portal active;
ng-workers active. `secubox-sentinelle-gsm.service` is unrelated — out of scope.

---

## Part 1 — Activation (deploy/ops)

**Async, report-only, defensive.** The daemon observes *mirrored* traffic and
records verdicts; it never sits in the hot path. Inline blocking stays off.

Executed as the plan's first deployment task (gk2, source-first):

1. **Build** `secubox-toolbox-ng` from master (cgo-free default → `sbx-sentinel`
   + `sbxmitm`, packs, env, units, tmpfiles).
2. **Deploy** to gk2: `sbx-sentinel` binary (`/usr/sbin/sbx-sentinel`),
   `packs/base`, `sentinel.env`, units, tmpfiles. Deploy the rebuilt `sbxmitm`
   worker binary **only if** the running workers lack the mirror-emit hook
   (verify first; don't churn workers needlessly).
3. **Configure** `/etc/secubox/sentinel.env`:
   `SENTINEL_HTTP_ADDR=127.0.0.1:8790` (localhost only — proxied by the portal;
   no external exposure, no nft opening). Optionally enable the feeds timer for
   the live-feed overlay.
4. **Wire the mirror**: confirm sbxmitm ng-workers emit to
   `/run/secubox/sentinel-mirror.sock`. If a worker redeploy is needed, restart
   the 4 workers **sequentially with socket-wait** (no mass restart — gk2 rule).
5. **Enable + start** `sbx-sentinel.service` (single unit). Respect
   `RuntimeDirectoryPreserve=yes`; never touch shared `/run/secubox` (1777) /
   `/var/lib/secubox` parents.
6. **Verify** (functional): `curl 127.0.0.1:8790/stats` + `/verdicts` return;
   drive benign + placeholder-IOC flows through the tunnel, confirm a verdict is
   recorded; daemon RSS bounded; portal + aggregator unaffected.

**Reversibility:** `systemctl disable --now sbx-sentinel` + clear
`SENTINEL_HTTP_ADDR` → dark. All surfaces degrade to "inactive".

---

## Part 2 — Go: per-mac verdict filter (`cmd/sbx-sentinel/http.go`)

The per-device surfaces (B, C) need this device's detections. Add a `mac` query
param to the existing `/verdicts` handler:

- `GET /verdicts?mac=<hash>&limit=N` → `store.ByMac(mac, limit)` (bounded like
  today). `mac` absent → unchanged `store.Recent(limit)` (no regression).
- Same `verdictView` response shape. Fail-safe: bad/empty `mac` → empty list.

Test: `mac=` filters to that hash; `mac` absent behaves as before; unknown mac
→ `[]`.

---

## Part 3 — Python shared link + assessment (`secubox_toolbox/sentinel_link.py`)

One new module, consumed by all three surfaces. **Never raises** — a dark or
wedged daemon must never break the portal or a report.

- `daemon_base() -> str|None` — resolve HTTP base from `SENTINEL_HTTP_ADDR`
  (env / `sentinel.env`), `127.0.0.1:8790` fallback; None if truly unset.
- `fetch_stats() -> dict` — GET `/stats` (timeout ~1.5s). Fail → `{}`.
- `fetch_verdicts(limit) -> list[dict]` — GET `/verdicts?limit=` (fleet). Fail → `[]`.
- `fetch_detections(mac_hash, limit) -> list[dict]` — GET `/verdicts?mac=&limit=`
  (per-device). Fail → `[]`.
- `assess(detections) -> dict` — pure compromise/evaluation summary:
  - `tier`: `clean` (none) · `suspicious` (report-only / heuristic / zero-click)
    · `compromised` (a high-confidence `block`-action spyware/malware verdict).
    Heuristic/zero-click **never** escalate to `compromised` (Sentinel invariant).
  - `worst_severity`, `worst_confidence`, `count`, `dominant_class`,
    `strongest` (the single highest-severity detection).
  - `disposition(action)` helper → `block`→"Bloquée", `report`→"Détectée —
    observée" (honest; no "blocked before any data left" over-claim — folds in
    #823 blocker #5 at the presentation layer).

---

## Part 4 — Surface A: WebUI ToolBoX tab (fleet)

### 4a. Portal proxy routes (`api.py`), admin-auth like sibling routes
- `GET /api/v1/sentinel/stats` → `fetch_stats()`; daemon down → HTTP 200
  `{"active":false,"detections":0,"blocked":0,"spyware":0}`; up →
  `{"active":true, …}`.
- `GET /api/v1/sentinel/verdicts?limit=N` → `fetch_verdicts(N)`; fail → `[]`,
  HTTP 200. Never 5xx on Sentinel state; daemon HTTP stays localhost-only.

### 4b. Tab (`www/toolbox/index.html`), P31 skin, existing `.tabs`/`.panel`
- Nav: `<button data-tab="sentinel" onclick="switchTab('sentinel')">🛡️
  Sentinelle</button>` (after "tor", before "config").
- `<section class="panel" id="panel-sentinel">` + `loadSentinel()` rendering:
  1. **Évaluation** — banner from `assess().tier`: 🟢 Aucune compromission /
     🟠 Activité suspecte / 🔴 Compromission confirmée + score row.
  2. **Détections** — table: class, severity, confidence, disposition, time,
     expandable `report`.
  3. **État** — daemon active/dark + `{detections,blocked,spyware}` counters.
- Lazy fetch on first switch (like other panels).
- Dark daemon → one calm line "Sentinelle inactive — aucune donnée de détection
  réseau." (not an error).

---

## Part 5 — Surface B: kbin report HTML tab (per-device)

`build_report_data(mac_hash, session_data)` folds a `sentinel` key:
`{"active":bool, "assess":assess(detections), "detections":detections}` using
`fetch_detections(mac_hash)` (fail-safe: absent daemon → `active:false`, empty).

`conf/report-live.html.j2` gains a tab in the existing `.tabs`/`.tab-pane` shell
(#699): 🛡️ **Compromission** — three cards mirroring Part 4b (Compromission
banner, Évaluation score, Détections table with expandable report), keyed on the
report's own device. Dark/empty → calm "Sentinelle inactive" state, never an
error. Uses the report's arcade-HUD skin already in the file.

---

## Part 6 — Surface C: PDF report section (per-device)

`render_pdf(report)` (`reports.py`) gains a Sentinel section fed by the same
`report["sentinel"]` key (built in Part 5, so both HTML and PDF share one data
path). Rendered with the existing `_section`/`_kv` helpers, placed near the
current "ANALYSE COMPROMISSION" block:

- **🛡️ SENTINELLE — COMPROMISSION** — tier verdict line (clean/suspect/
  compromised) + `worst_severity`/`worst_confidence`/`count`/`dominant_class`.
- **DÉTECTIONS** — one row per verdict: class, disposition (honest), time,
  key evidence. `mac_hash` only.
- Empty/dark → a single "Sentinelle inactive — aucune détection" line (the PDF
  must render even with no Sentinel data — text-fallback safe).

---

## Part 7 — Demo prompt (doc artifact, after it works)

Once activation + all three surfaces are verified, write a GPT prompt to
`docs/demos/2026-07-06-kbin-sentinel-augmentation-prompt.md` that demonstrates
the kbin's new capability group: the prompt frames the kbin (ToolBoX) as now
detecting commercial-spyware / exploit / botnet compromise on-network and
surfacing it per-device (report + PDF) and fleet-wide (portal), and asks the
model to narrate/showcase the augmentation. Content only — no code.

---

## Data flow

```
sbxmitm ng-workers ─mirror sock─▶ sbx-sentinel ─▶ bbolt store
                                       │
                            /stats  /verdicts[?mac=]  (127.0.0.1:8790)
                                       │
   ┌───────────────────────────┬──────┴───────────────┐
   ▼ portal /api/v1/sentinel/* ▼ build_report_data     ▼ (same key)
 WebUI tab (fleet)        kbin HTML tab (per-device)  PDF section (per-device)
```

---

## Error handling

- Daemon unreachable / HTTP disabled → proxy `active:false` + empty (HTTP 200);
  report surfaces render an "inactive" state. No 5xx, no broken PDF.
- Malformed JSON → treated as unreachable.
- Proxy/fetch timeout ~1.5s so a wedged daemon can't stall a portal request or a
  report build.
- Auth: proxy routes require the portal's admin auth; report surfaces inherit
  the report's existing HMAC-token / `mac_hash` scoping (a report only ever
  shows its own device's detections). No new public surface.

---

## Testing

- **Go**: `/verdicts?mac=` filters to that mac; `mac` absent unchanged; unknown
  mac → `[]`.
- **Python** `sentinel_link`: `assess()` tier table (clean / report-only→suspect
  / block→compromised / heuristic→suspect-never-compromised); `fetch_*` fail-safe
  (daemon down → `{}`/`[]`, no raise; bad JSON → same); `build_report_data`
  folds the `sentinel` key (present when up, `active:false` when down).
- **Python** routes: daemon up (monkeypatched) → 200 data; down → 200
  inactive/empty; unauth rejected like siblings.
- **PDF** `render_pdf`: renders a Sentinel section with detections; renders the
  "inactive" line with no data; text-fallback path safe.
- **Templates**: `node --check` extracted inline JS (index.html + report-live);
  panels render clean / detections / inactive states.
- **Activation (gk2, functional)**: placeholder-IOC flow → verdict visible on
  all three surfaces; benign ignored; RSS bounded; portal/aggregator unaffected.

---

## Files

- `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http.go` — **modify** (`mac` param).
- `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http_test.go` — **modify**.
- `packages/secubox-toolbox/secubox_toolbox/sentinel_link.py` — **create**.
- `packages/secubox-toolbox/secubox_toolbox/api.py` — **modify** (proxy routes).
- `packages/secubox-toolbox/secubox_toolbox/reports.py` — **modify**
  (`build_report_data` folds `sentinel`; `render_pdf` Sentinel section).
- `packages/secubox-toolbox/www/toolbox/index.html` — **modify** (fleet tab).
- `packages/secubox-toolbox/conf/report-live.html.j2` — **modify** (per-device tab).
- `packages/secubox-toolbox/tests/` — **create/modify**.
- `docs/demos/2026-07-06-kbin-sentinel-augmentation-prompt.md` — **create** (Part 7).
- `/etc/secubox/sentinel.env` on gk2 — **configure** (`SENTINEL_HTTP_ADDR`);
  source default stays empty (activation is per-board).

---

## Out of scope (deferred)

- Inline hot-path blocking activation.
- The Go `RenderReport` daemon-text disposition fix (#823 blocker #5) — the
  surfaces label disposition honestly at presentation; the daemon-text fix stays
  tracked on #823.
- Live-feed timer tuning; YARA cgo build.
