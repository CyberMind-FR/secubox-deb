<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Aggregate MITM protection stats in the #ads card — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn the #ads card's single narrow "blocked" number into an honest labeled breakdown of the full MITM protection: ad-block 204s (existing) + trackers detected (social_edges) + pages cosmetically cleaned (new sbxmitm counter) + network drops (blacklist nft).

**Architecture:** Task 1 is Python-only (trackers + network_drops added to the ad-stats payload + a WebUI breakdown) — immediate value, no engine redeploy. Task 2 adds a Go `cosmeticPages` counter in sbxmitm, flushed via the existing ad-event channel, stored, and surfaced.

**Tech Stack:** Python/FastAPI + sqlite3 (toolbox), Go (sbxmitm), vanilla JS (toolbox WebUI), pytest + `go test`.

## Global Constraints
- New Python files carry `# SPDX-License-Identifier: LicenseRef-CMSD-1.0`. New Go logic keeps the file's existing header.
- **Honest breakdown, not a sum:** the four metrics are different units (blocks / trackers / pages / drops) — label them separately; never add them into one number.
- Reuse existing helpers: `store._conn()`, the `social_edges` table (same toolbox.db), the existing ad-event flush (`adstats.go` payload + `/__toolbox/ad-event` handler), the blacklist nft drops parse (api.py `admin_blacklist`).
- `trackers_seen` = `COUNT(DISTINCT cookie_id_hash)` over `social_edges` in the window (exclude empty cookie ids).
- Commits reference `(ref #755)`. No "Claude Code"/"Generated with" strings.
- Tests: `cd packages/secubox-toolbox && python -m pytest tests/<file> -v` ; Go: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -count=1`.

## File Structure
- Modify `packages/secubox-toolbox/secubox_toolbox/store.py` — `ad_stats` adds `trackers_seen` + `pages_cleaned`; new `record_cosmetic_pages`.
- Modify `packages/secubox-toolbox/secubox_toolbox/api.py` — `admin_ad_stats` adds `network_drops`; `toolbox_ad_event` ingests `cosmetic_pages`.
- Modify `packages/secubox-toolbox/www/toolbox/index.html` — the #ads card breakdown.
- Modify `packages/secubox-toolbox-ng/cmd/sbxmitm/adstats.go` + `main.go` — the `cosmeticPages` counter + flush.
- Tests: `packages/secubox-toolbox/tests/test_ads_aggregate.py`, `packages/secubox-toolbox-ng/cmd/sbxmitm/cosmetic_count_test.go`.

---

### Task 1: Python — trackers_seen + network_drops + WebUI breakdown

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/store.py` (`ad_stats`)
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (`admin_ad_stats`)
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` (#ads card)
- Test: `packages/secubox-toolbox/tests/test_ads_aggregate.py`

**Interfaces:**
- Produces: `store.ad_stats(...)` dict gains `trackers_seen: int` (and `pages_cleaned: int`, defaulted 0 here — Task 2 fills it); `admin_ad_stats(...)` dict gains `network_drops: int`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_ads_aggregate.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for the #ads aggregate breakdown (ref #755)."""
import sqlite3
import time
from secubox_toolbox import store


def _seed_db(tmp_path, monkeypatch):
    db = tmp_path / "toolbox.db"
    c = sqlite3.connect(str(db))
    c.executescript(
        "CREATE TABLE ad_block_stats(ad_host TEXT, site TEXT, action TEXT, hits INTEGER, bytes INTEGER, last_seen REAL, PRIMARY KEY(ad_host,site,action));"
        "CREATE TABLE ad_block_client_host(mac_hash TEXT, ad_host TEXT, hits INTEGER, last_seen REAL, PRIMARY KEY(mac_hash,ad_host));"
        "CREATE TABLE social_edges(ts INTEGER, client_mac_hash TEXT, src_site TEXT, tracker_domain TEXT, cookie_id_hash TEXT, ja4_hash TEXT, consent_state TEXT);"
    )
    now = int(time.time())
    # two distinct cookie-trackers in window, one duplicate, one stale (>24h)
    for cid, ts in [("A", now-60), ("A", now-30), ("B", now-60), ("C", now-90000), ("", now-10)]:
        c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,tracker_domain,cookie_id_hash,ja4_hash,consent_state) VALUES(?,?,?,?,?,?,?)",
                  (ts, "m", "s", "t", cid, "j", "none_seen"))
    c.commit(); c.close()
    monkeypatch.setattr(store, "DB_PATH", db)
    return db


def test_ad_stats_trackers_seen_distinct_in_window(tmp_path, monkeypatch):
    _seed_db(tmp_path, monkeypatch)
    out = store.ad_stats(hours=24)
    # distinct non-empty cookie ids in the last 24h = {A, B}; C is stale, "" excluded
    assert out["trackers_seen"] == 2
    assert out["pages_cleaned"] == 0  # no cosmetic_events table yet → 0 (Task 2 fills it)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ads_aggregate.py -v`
Expected: FAIL — `KeyError: 'trackers_seen'`.

- [ ] **Step 3: Implement store.ad_stats additions**

In `store.py`, in `ad_stats`, inside the `with _conn() as c:` block (after the existing `top_visitors` query, before the function returns `out`), add:

```python
            # #755 — trackers detected/poisoned by the MITM in the window: distinct
            # cross-site cookie-identifier hashes seen on social_edges. This is the
            # "Trackers" half of the card (the 204 ad-block is the "pubs" half).
            try:
                r = c.execute(
                    "SELECT COUNT(DISTINCT cookie_id_hash) FROM social_edges "
                    "WHERE last_seen IS NULL AND 0",  # placeholder replaced below
                ).fetchone()
            except sqlite3.Error:
                r = None
            out["trackers_seen"] = 0
            try:
                out["trackers_seen"] = int(c.execute(
                    "SELECT COUNT(DISTINCT cookie_id_hash) FROM social_edges "
                    "WHERE ts >= ? AND cookie_id_hash IS NOT NULL AND cookie_id_hash <> ''",
                    (int(cutoff),),
                ).fetchone()[0] or 0)
            except sqlite3.Error:
                out["trackers_seen"] = 0
            # #755 — pages where the cosmetic ad-hide style was injected (Task 2 writes
            # cosmetic_events; absent table → 0).
            out["pages_cleaned"] = 0
            try:
                out["pages_cleaned"] = int(c.execute(
                    "SELECT COALESCE(SUM(pages),0) FROM cosmetic_events WHERE ts >= ?",
                    (cutoff,),
                ).fetchone()[0] or 0)
            except sqlite3.Error:
                out["pages_cleaned"] = 0
```

Remove the dead placeholder block (the first `try/except` with `WHERE last_seen IS NULL AND 0`) — it was only to show the shape; keep ONLY the two real queries (`trackers_seen` and `pages_cleaned`). (`cutoff` is the existing local `cutoff = time.time() - hours*3600` already computed at the top of `ad_stats`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ads_aggregate.py -v`
Expected: PASS.

- [ ] **Step 5: Add network_drops to the endpoint**

In `api.py`, change `admin_ad_stats` (currently `return store.ad_stats(hours=h)`) to:

```python
async def admin_ad_stats(hours: int = 24) -> dict:
    """Contextual ad-block metrics for the #ads tab (read-only, kbin-safe)."""
    h = max(1, min(int(hours if hours is not None else 24), 168))
    out = store.ad_stats(hours=h)
    # #755 — network-layer drops (blacklist nft sets). Best-effort; 0 when the
    # blacklist is inert or unreadable. Reuses the admin_blacklist parse.
    try:
        bl = await admin_blacklist()
        out["network_drops"] = int(bl.get("drops", 0) or 0)
    except Exception:
        out["network_drops"] = 0
    return out
```

(Confirm `admin_blacklist` is defined ABOVE `admin_ad_stats` in api.py; it is referenced at module scope so definition order at call time is fine since both are coroutines resolved at runtime.)

- [ ] **Step 6: WebUI — render the breakdown**

In `packages/secubox-toolbox/www/toolbox/index.html`, find the line building the #ads KPI (around line 620, the `kpi.innerHTML = ...` that shows `Trackers &amp; pubs bloqués ${d.total_blocked}`). Replace that assignment with a labeled breakdown that keeps the existing "pubs bloquées" + bytes and ADDS the three new metrics:

```javascript
    kpi.innerHTML = `<span class="k">Pubs bloquées (204)</span> <span class="v">${d.total_blocked||0}</span>`
      + ` <span class="k">Trackers détectés</span> <span class="v">${d.trackers_seen||0}</span>`
      + ` <span class="k">Pages nettoyées</span> <span class="v">${d.pages_cleaned||0}</span>`
      + ` <span class="k">Drops réseau</span> <span class="v">${d.network_drops||0}</span>`
      + ` <span class="k" title="estimation : un contenu bloqué n'est jamais téléchargé, on ne peut pas mesurer les octets réels — ~45 Ko/blocage">Ko évités <span style="opacity:.6">(est.)</span></span> <span class="v">~${Math.round((d.total_bytes||0)/1024)}</span>`;
```

(Keep the surrounding code that builds `hostRows`/`siteRows` tables unchanged.)

- [ ] **Step 7: Run the test once more + commit**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ads_aggregate.py -v`
Expected: PASS.

```bash
git add packages/secubox-toolbox/secubox_toolbox/store.py packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/www/toolbox/index.html packages/secubox-toolbox/tests/test_ads_aggregate.py
git commit -m "feat(toolbox): #ads breakdown — trackers_seen + network_drops (ref #755)"
```

---

### Task 2: Go cosmetic-pages counter + flush + store + surface

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/adstats.go` (counter + payload field + flush)
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` (increment on injection)
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (`toolbox_ad_event` ingest)
- Modify: `packages/secubox-toolbox/secubox_toolbox/store.py` (`record_cosmetic_pages`)
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/cosmetic_count_test.go`, extend `packages/secubox-toolbox/tests/test_ads_aggregate.py`

**Interfaces:**
- Consumes: `store.ad_stats`'s `pages_cleaned` query (Task 1, reads `cosmetic_events`); the ad-event flush (`flushOnce`).
- Produces: `(*adStats).recordCosmetic()`, the `cosmetic_pages` JSON field on the ad-event payload; `store.record_cosmetic_pages(n: int)`.

- [ ] **Step 1: Write the failing Go test**

Create `packages/secubox-toolbox-ng/cmd/sbxmitm/cosmetic_count_test.go`:

```go
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package main

import "testing"

func TestCosmeticCounterSnapshotClears(t *testing.T) {
	a := newAdStats()
	a.recordCosmetic()
	a.recordCosmetic()
	if got := a.snapshotCosmetic(); got != 2 {
		t.Fatalf("snapshotCosmetic = %d, want 2", got)
	}
	if got := a.snapshotCosmetic(); got != 0 {
		t.Fatalf("snapshot must clear; second call = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -run TestCosmetic -v`
Expected: FAIL — `a.recordCosmetic undefined`.

- [ ] **Step 3: Implement the Go counter**

In `adstats.go`: add a field to the `adStats` struct (find `type adStats struct {`): a counter guarded by the existing struct mutex, or a dedicated `sync/atomic` int64. Use atomic to avoid touching the existing lock scope:

Add import `"sync/atomic"` if absent. Add to the `adStats` struct:
```go
	cosmetic atomic.Int64 // #755 — pages where the cosmetic ad-hide style was injected
```
Add methods:
```go
// recordCosmetic tallies one R3 HTML page that received the cosmetic ad-hide style.
func (a *adStats) recordCosmetic() { a.cosmetic.Add(1) }

// snapshotCosmetic atomically reads-and-clears the cosmetic page counter.
func (a *adStats) snapshotCosmetic() int64 { return a.cosmetic.Swap(0) }
```
In the ad-event payload struct (`adEventPayload`), add the field:
```go
	CosmeticPages int64 `json:"cosmetic_pages,omitempty"`
```
In `flushOnce` (where the payload `p` is assembled before marshal), set:
```go
	p.CosmeticPages = a.snapshotCosmetic()
```
Note: if `flushOnce` early-returns when ad block/candidate maps are empty, ensure a non-zero cosmetic count still gets POSTed — adjust the "is the snapshot empty?" guard to also consider `p.CosmeticPages > 0` so cosmetic-only windows still flush.

- [ ] **Step 4: Increment on injection (main.go)**

In `main.go`, in `mitmPipeline`, in the block `if out, ok := injectIntoBody(body, resp.Header.Get("Content-Encoding"), scriptBody, cspNonce, wg); ok {` — inside the `ok` branch (after `body = out`), add:
```go
		px.ads.recordCosmetic() // #755 — this R3 HTML page got the cosmetic ad-hide style
```

- [ ] **Step 5: Run the Go test + build**

Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -run TestCosmetic -v && GOFLAGS=-mod=vendor go build ./... && GOFLAGS=-mod=vendor go vet ./cmd/sbxmitm/`
Expected: PASS, build OK, vet clean.

- [ ] **Step 6: Python — store.record_cosmetic_pages + ad-event ingest**

In `store.py`, add (near `record_ad_blocks`):
```python
def record_cosmetic_pages(pages: int) -> None:
    """#755 — append one cosmetic-hide tally (pages cleaned since the last flush).
    ad_stats sums these over the window. Best-effort; never raises."""
    try:
        n = int(pages)
        if n <= 0:
            return
        with _conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS cosmetic_events(ts REAL, pages INTEGER)")
            c.execute("INSERT INTO cosmetic_events(ts, pages) VALUES(?, ?)", (time.time(), n))
    except Exception as e:
        log.debug("record_cosmetic_pages failed: %s", e)
```

In `api.py`, in `toolbox_ad_event`, after the existing `store.record_ad_blocks(...)` / `record_ad_candidates(...)` calls, add:
```python
        cp = payload.get("cosmetic_pages")
        if cp:
            store.record_cosmetic_pages(cp)
```
(Match the variable name the handler uses for the parsed JSON body — the brief's `payload` may be named `body`/`data` in the actual handler; use whatever it is. Guard so a missing/zero field is a no-op.)

- [ ] **Step 7: Extend the Python test (pages_cleaned now populated)**

Append to `tests/test_ads_aggregate.py`:
```python
def test_record_cosmetic_pages_summed_in_window(tmp_path, monkeypatch):
    _seed_db(tmp_path, monkeypatch)
    store.record_cosmetic_pages(3)
    store.record_cosmetic_pages(2)
    out = store.ad_stats(hours=24)
    assert out["pages_cleaned"] == 5
```

- [ ] **Step 8: Run both suites**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ads_aggregate.py -v` → PASS (3 tests).
Run: `cd packages/secubox-toolbox-ng && GOFLAGS=-mod=vendor go build ./... && GOFLAGS=-mod=vendor go test ./cmd/sbxmitm/ -count=1` → build OK, all PASS.

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-toolbox-ng/cmd/sbxmitm/adstats.go packages/secubox-toolbox-ng/cmd/sbxmitm/main.go packages/secubox-toolbox-ng/cmd/sbxmitm/cosmetic_count_test.go packages/secubox-toolbox/secubox_toolbox/store.py packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_ads_aggregate.py
git commit -m "feat(toolbox): cosmetic-pages counter → #ads 'Pages nettoyées' (ref #755)"
```

---

## Self-Review notes
- **Spec coverage:** trackers_seen (Task 1) ✓; network_drops (Task 1) ✓; pages_cleaned cosmetic counter end-to-end Go→store→ad_stats (Task 2) ✓; WebUI labeled breakdown, not a sum (Task 1 Step 6) ✓; honest units (each labeled) ✓.
- **No placeholders:** Step 3 explicitly instructs deleting the illustrative dead block; the only "match the actual var name" notes (the ad-event handler's body var) are verify-in-context, not gaps.
- **Type consistency:** `trackers_seen`/`pages_cleaned`/`network_drops`/`cosmetic_pages` keys are identical across store → api → WebUI → Go payload → store ingest.
- **Out of scope:** real DNS-sinkhole per-window counter (no endpoint exists; `network_drops` uses the blacklist nft drops, 0 until that layer reports) — flagged in the issue.
