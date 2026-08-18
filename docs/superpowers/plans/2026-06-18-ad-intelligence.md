<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Ad Intelligence Implementation Plan (#656)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Aggressive ad-URL learning + block/silent actions + contextual per-host/per-site metrics in a new #ads tab, built on `ad_ghost`.

**Spec:** `docs/superpowers/specs/2026-06-18-ad-intelligence.md`. Safety: allowlist always wins; `ad_learn` toggle; metrics make blocks visible; block-only (no IP-drop) = reversible.

All paths under `packages/secubox-toolbox/`. Tests: `python -m pytest` from there.

---

### Task 1: store — ad_block_stats + ad_candidates tables & helpers

**Files:** Modify `secubox_toolbox/store.py`; Test `tests/test_ad_store.py` (create)

- [ ] **Step 1: Failing test** `tests/test_ad_store.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from pathlib import Path
from secubox_toolbox import store


def _fresh(tmp_path, mp): mp.setattr(store, "DB_PATH", Path(tmp_path) / "t.db")


def test_record_and_aggregate(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_blocks([
        ("ads.example.com", "cnn.com", "block", 5, 5 * 1500),
        ("ads.example.com", "bbc.com", "block", 3, 3 * 1500),
        ("px.tracker.io", "cnn.com", "block", 2, 2 * 1500),
        ("cnn.com", "cnn.com", "silent", 4, 0),
    ])
    s = store.ad_stats(hours=24)
    assert s["total_blocked"] == 10            # block hits only
    assert s["by_action"]["block"] == 10 and s["by_action"]["silent"] == 4
    assert s["top_hosts"][0]["host"] == "ads.example.com" and s["top_hosts"][0]["hits"] == 8
    sites = {r["site"]: r["hits"] for r in s["top_sites"]}
    assert sites["cnn.com"] == 7               # block hits per site (5+2)


def test_record_upsert_accumulates(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_blocks([("a.com", "x.com", "block", 1, 1500)])
    store.record_ad_blocks([("a.com", "x.com", "block", 2, 3000)])
    s = store.ad_stats(hours=24)
    assert s["by_action"]["block"] == 3 and s["total_bytes"] == 4500


def test_candidates_capture_and_sites(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_candidates([("ad.x.io", "cnn.com", 1), ("ad.x.io", "bbc.com", 1),
                                ("ad.x.io", "cnn.com", 1)])
    rows = store.ad_candidate_sites(min_sites=2)
    assert "ad.x.io" in rows                    # seen on 2 distinct sites
    assert store.ad_candidate_sites(min_sites=3) == []
```
Run: `python -m pytest tests/test_ad_store.py -v` → FAIL.

- [ ] **Step 2: Implement** — add to `SCHEMA` in `store.py`:
```sql
CREATE TABLE IF NOT EXISTS ad_block_stats (
    ad_host TEXT, site TEXT, action TEXT,
    hits INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
    last_seen REAL, PRIMARY KEY (ad_host, site, action));
CREATE TABLE IF NOT EXISTS ad_candidates (
    host TEXT, site TEXT, hits INTEGER NOT NULL DEFAULT 0, last_seen REAL,
    PRIMARY KEY (host, site));
```
Add functions (after `_conn`):
```python
def record_ad_blocks(rows) -> None:
    """rows: iterable of (ad_host, site, action, hits, bytes). Batch upsert."""
    rows = [r for r in rows if r and r[0]]
    if not rows:
        return
    now = time.time()
    try:
        with _conn() as c:
            c.executemany(
                "INSERT INTO ad_block_stats(ad_host,site,action,hits,bytes,last_seen) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(ad_host,site,action) DO UPDATE SET "
                "hits=hits+excluded.hits, bytes=bytes+excluded.bytes, last_seen=excluded.last_seen",
                [(h, s or "", a, int(n), int(b), now) for (h, s, a, n, b) in rows])
    except Exception as e:
        log.debug("record_ad_blocks failed: %s", e)


def record_ad_candidates(rows) -> None:
    """rows: iterable of (host, site, hits)."""
    rows = [r for r in rows if r and r[0]]
    if not rows:
        return
    now = time.time()
    try:
        with _conn() as c:
            c.executemany(
                "INSERT INTO ad_candidates(host,site,hits,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(host,site) DO UPDATE SET hits=hits+excluded.hits, last_seen=excluded.last_seen",
                [(h, s or "", int(n), now) for (h, s, n) in rows])
    except Exception as e:
        log.debug("record_ad_candidates failed: %s", e)


def ad_candidate_sites(min_sites: int = 1, max_hosts: int = 5000) -> list:
    """Hosts seen as ad-candidates on >= min_sites DISTINCT sites."""
    try:
        with _conn() as c:
            return [r[0] for r in c.execute(
                "SELECT host FROM ad_candidates GROUP BY host "
                "HAVING COUNT(DISTINCT site) >= ? ORDER BY SUM(hits) DESC LIMIT ?",
                (min_sites, max_hosts))]
    except Exception:
        return []


def ad_stats(hours: int = 24, top: int = 25) -> dict:
    cutoff = time.time() - hours * 3600
    out = {"window_hours": hours, "total_blocked": 0, "total_bytes": 0,
           "by_action": {"block": 0, "silent": 0}, "top_hosts": [], "top_sites": []}
    try:
        with _conn() as c:
            for action, hits in c.execute(
                "SELECT action, SUM(hits) FROM ad_block_stats WHERE last_seen>=? GROUP BY action",
                (cutoff,)):
                out["by_action"][action] = int(hits or 0)
            out["total_blocked"] = out["by_action"].get("block", 0)
            r = c.execute("SELECT SUM(bytes) FROM ad_block_stats WHERE action='block' AND last_seen>=?",
                          (cutoff,)).fetchone()
            out["total_bytes"] = int((r and r[0]) or 0)
            out["top_hosts"] = [{"host": h, "hits": int(n), "bytes": int(b or 0)} for h, n, b in c.execute(
                "SELECT ad_host, SUM(hits), SUM(bytes) FROM ad_block_stats WHERE action='block' AND last_seen>=? "
                "GROUP BY ad_host ORDER BY SUM(hits) DESC LIMIT ?", (cutoff, top))]
            out["top_sites"] = [{"site": s, "hits": int(n)} for s, n in c.execute(
                "SELECT site, SUM(hits) FROM ad_block_stats WHERE action='block' AND last_seen>=? AND site<>'' "
                "GROUP BY site ORDER BY SUM(hits) DESC LIMIT ?", (cutoff, top))]
    except Exception as e:
        log.debug("ad_stats failed: %s", e)
    return out
```
- [ ] **Step 3: Pass** → `python -m pytest tests/test_ad_store.py -v`.
- [ ] **Step 4: Commit** `feat(toolbox): ad_block_stats + ad_candidates store helpers (ref #656)`

---

### Task 2: filters `ad_learn` toggle

**Files:** `secubox_toolbox/filters.py`; Test `tests/test_filters_adlearn.py`

- [ ] **Step 1: Failing test:**
```python
# tests/test_filters_adlearn.py
from secubox_toolbox import filters
def test_ad_learn_default_true(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.get_filters(force=True)["ad_learn"] is True
def test_ad_learn_set_bool(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.set_filters({"ad_learn": False})["ad_learn"] is False
```
- [ ] **Step 2:** add `"ad_learn": True,` to `DEFAULTS`; add `ad_learn` to the bool-coercion key list in `set_filters` (the `elif k in (...)` tuple).
- [ ] **Step 3: Pass.** **Step 4: Commit** `feat(toolbox): ad_learn filter toggle (ref #656)`

---

### Task 3: ad_ghost — contextual recording + candidates + allowlist + bg flush

**Files:** `mitmproxy_addons/ad_ghost.py`; Test `tests/test_ad_ghost_learn.py`

- [ ] **Step 1: Failing tests** (`tests/test_ad_ghost_learn.py`): allowlist host not blocked; 3rd-party ad-path request captured as candidate; first-party not; `_site_of` parses Referer registrable. Use a fake flow (mirror existing ad_ghost tests if any; else a `types.SimpleNamespace` with `request.pretty_host`, `request.path`, `request.headers`, `client_conn.peername=("10.99.1.2",0)`, and a settable `response`). Patch `get_filters` to `{ad_ghost:1, ad_ghost_block:1, ad_learn:1}` and `_ALLOW` set.

- [ ] **Step 2: Implement.** Add near the top constants:
```python
_ALLOW_PATH = "/var/lib/secubox/toolbox/ad-allowlist.txt"
_AD_PATH = re.compile(r"/ads?/|/adserver|/pagead|/gampad|/doubleclick|/beacon|"
                      r"/pixel|/collect|/track(ing)?|/telemetry|/metric", re.I)
_ctx = {}        # (host, site, action) -> [hits, bytes]
_cand = {}       # (host, site) -> hits
_allow = set(); _allow_mtime = 0.0
```
Add helpers:
```python
def _allowed(host: str) -> bool:
    global _allow, _allow_mtime
    try:
        m = os.stat(_ALLOW_PATH).st_mtime if os.path.exists(_ALLOW_PATH) else 0.0
        if m != _allow_mtime:
            _allow = set()
            if m:
                with open(_ALLOW_PATH, encoding="utf-8") as f:
                    for ln in f:
                        ln = ln.split("#", 1)[0].strip().lower()
                        if ln:
                            _allow.add(ln)
            _allow_mtime = m
    except Exception:
        pass
    h = (host or "").lower(); reg = _registrable(h) or h
    return h in _allow or reg in _allow


def _site_of(flow) -> str:
    try:
        ref = flow.request.headers.get("referer", "") or ""
        if ref:
            from urllib.parse import urlparse
            return _registrable(urlparse(ref).hostname or "") or ""
    except Exception:
        pass
    return ""
```
In `requestheaders`, AFTER computing `host` and the `blocked` decision, BEFORE the 204:
- if `_allowed(host)`: `return` (never block — allowlist wins).
- compute `site = _site_of(flow)`.
- on block: also `k=(host, site, "block"); v=_ctx.get(k) or [0,0]; v[0]+=1; v[1]+=_EST_BYTES_PER_REQ; _ctx[k]=v` (bounded: `if len(_ctx)<20000`).
- candidate capture (gated `f.get("ad_learn", True)`, only when NOT already blocked): if `site` and `_registrable(host) != _registrable(... site host ...)` (3rd-party) and `_AD_PATH.search(flow.request.path or "")`: `_cand[(host,site)] = _cand.get((host,site),0)+1` (bounded).
In `response` (cosmetic hide path), on `pages_cleaned`: record silent `_ctx[(site,site,"silent")]` where `site=_site_of(flow)`.
In `_flush`, after writing ghost.json, **offload** the `_ctx`/`_cand` snapshots to a bg thread (add a module `concurrent.futures.ThreadPoolExecutor(max_workers=1)`; submit `store.record_ad_blocks` + `store.record_ad_candidates`) then clear them. Import `store` lazily/guarded like other addons.

- [ ] **Step 3: Pass.** **Step 4: Commit** `feat(toolbox): ad_ghost contextual recording + candidates + allowlist (ref #656)`

---

### Task 4: `/admin/ad-stats` API

**Files:** `secubox_toolbox/api.py`; Test `tests/test_ad_stats_api.py`

- [ ] **Step 1: Failing test:** monkeypatch `api.store.ad_stats` → canned dict; call the handler; assert it returns it (+ clamps hours).
- [ ] **Step 2: Implement** (near other `/admin/*` GETs):
```python
@router.get("/admin/ad-stats")
async def admin_ad_stats(hours: int = 24) -> dict:
    """Contextual ad-block metrics for the #ads tab (read-only, kbin-safe)."""
    h = max(1, min(int(hours or 24), 168))
    return store.ad_stats(hours=h)
```
- [ ] **Step 3: Pass.** **Step 4: Commit** `feat(toolbox): GET /admin/ad-stats contextual metrics (ref #656)`

---

### Task 5: autolearn `_ad_feed` (promote candidates → blocklist)

**Files:** `sbin/secubox-toolbox-autolearn`; Test `tests/test_autolearn_adfeed.py`

- [ ] **Step 1: Failing test** (load script via exec like `test_autolearn_splice.py`): seed `ad_candidates` (host on ≥AD_MIN_SITES sites), seed `ad-allowlist.txt` with one host; call `_ad_feed()`; assert promoted hosts appended to `learned-trackers.txt`, allowlisted excluded, deduped.
- [ ] **Step 2: Implement:** env `AD_MIN_SITES = int(os.environ.get("SECUBOX_AD_MIN_SITES","1"))`, `AD_ALLOWLIST=os.environ.get("SECUBOX_AD_ALLOWLIST","/var/lib/secubox/toolbox/ad-allowlist.txt")`. `_ad_feed()`: gated on filters `ad_learn` (skip if false); query `SELECT host FROM ad_candidates GROUP BY host HAVING COUNT(DISTINCT site)>=AD_MIN_SITES`; subtract allowlist (host+registrable); MERGE into existing `learned-trackers.txt` (read existing, union, dedup, cap, atomic `os.replace`). Best-effort; never abort the run. Call it from `main()` alongside the other feeds.
- [ ] **Step 3: Pass.** **Step 4: Commit** `feat(toolbox): autolearn _ad_feed promotes ad-candidates to blocklist (ref #656)`

---

### Task 6: #ads dashboard tab

**Files:** `www/toolbox/index.html`

- [ ] **Step 1:** add nav button after the social tab:
`<button class="tab" data-tab="ads" onclick="switchTab('ads')">🛑 Pubs</button>`
and a `<section id="ads-section">` container with a KPI div + two table mounts
(mirror the social section markup).
- [ ] **Step 2:** in `switchTab`, add `if (name === 'ads') loadAds();`. Add:
```javascript
async function loadAds() {
    const d = await J('/admin/ad-stats?hours=24');
    const kpi = document.getElementById('ads-kpi');
    const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    if (!d || d.__error) { kpi.innerHTML = `<span class="k">err</span><span class="v">${(d&&d.__error)||'no data'}</span>`; return; }
    kpi.innerHTML = `<span class="k">Pubs bloquées</span> <span class="v">${d.total_blocked||0}</span>`
      + ` <span class="k">Ko économisés</span> <span class="v">${Math.round((d.total_bytes||0)/1024)}</span>`
      + ` <span class="k">Silenced</span> <span class="v">${(d.by_action&&d.by_action.silent)||0}</span>`
      + ` <span class="k">Fenêtre</span> <span class="v">${d.window_hours||24}h</span>`;
    const hostRows = (d.top_hosts||[]).map(r=>`<tr><td><code>${esc(r.host)}</code></td><td>${r.hits}</td><td>${Math.round((r.bytes||0)/1024)}</td></tr>`).join('');
    const siteRows = (d.top_sites||[]).map(r=>`<tr><td><code>${esc(r.site)}</code></td><td>${r.hits}</td></tr>`).join('');
    document.getElementById('ads-hosts').innerHTML = hostRows
      ? '<table><thead><tr><th>Ad host</th><th>bloqués</th><th>Ko</th></tr></thead><tbody>'+hostRows+'</tbody></table>'
      : '<div class="empty">aucune pub bloquée dans la fenêtre</div>';
    document.getElementById('ads-sites').innerHTML = siteRows
      ? '<table><thead><tr><th>Site</th><th>pubs bloquées</th></tr></thead><tbody>'+siteRows+'</tbody></table>'
      : '';
}
```
(Match existing ids/markup conventions; reuse the social section's CSS classes.)
- [ ] **Step 2b: Commit** `feat(toolbox): #ads dashboard tab — contextual ad-block stats (ref #656)`

---

### Task 7: changelog + full suite

- [ ] **Step 1:** new top changelog entry, version after current top (2.6.55 →
  **2.6.56**): summarise Ad Intelligence (aggressive learn + block/silent +
  #ads contextual metrics + allowlist/ad_learn safety). NOTE: 2.6.56 was
  previously used by the reverted #653 — confirm `head -1 debian/changelog`;
  since #653 was reverted on master, 2.6.56 is free again; if not, use the next
  free version.
- [ ] **Step 2:** `python -m pytest tests/ -q` all green; `bash -n` n/a (py);
  `python3 -c "import ast; ast.parse(open('sbin/secubox-toolbox-autolearn').read())"`.
- [ ] **Step 3: Commit** `chore(toolbox): changelog for Ad Intelligence (ref #656)`

## Self-review notes
- Recording is hot-path-safe: dict increments + one regex + bg-thread SQLite flush (mirror local_store/splice). Never blocks the proxy.
- Allowlist wins everywhere (ad_ghost `_allowed` early-return + autolearn exclusion).
- Aggressive default AD_MIN_SITES=1, env-tunable; ad_learn toggle stops growth.
- block-only (no IP-drop) → reversible; metrics surface every block per host/site.
- version: verify 2.6.56 free post-#653-revert.
