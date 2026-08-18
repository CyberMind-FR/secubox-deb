<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Cookies cross-site tracker detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the already-computed R3 cross-site tracker correlation (`social_edges`) to the operator as a detailed view in the secubox-cookies dashboard.

**Architecture:** A read-only aggregation function in the toolbox (`social.py`, next to `aggregate()`) folds `social_edges` into per-tracker cross-site detail; a toolbox endpoint `GET /admin/cookie-crosssite` exposes it (mirrors `/admin/social-aggregate`); the cookies dashboard adds a "Trackers cross-site" card whose JS fetches that endpoint directly (operator browser carries the JWT). No new service, no new dependency.

**Tech Stack:** Python 3.11 / FastAPI / sqlite3 (toolbox), vanilla HTML/JS (cookies dashboard), pytest.

## Global Constraints

- New Python files carry the SPDX header: `# SPDX-License-Identifier: LicenseRef-CMSD-1.0` + the CyberMind copyright block (copy from any sibling file in the module).
- Read-only over `social_edges`. No writes, no migration. Filter out `src_site IN ('', 'null')` at read time.
- Reuse `social._conn()`, `social._registrable_domain()`, `social._is_ip()` — do NOT reimplement.
- The new endpoint mirrors `admin_social_aggregate` exactly: no explicit `Depends` (admin gating is handled at the same layer as its siblings).
- Frontend fetch uses the existing `headers()` helper (Bearer `sbx_token`) and targets the absolute toolbox path `/api/v1/toolbox/admin/cookie-crosssite` (NOT the cookies `API` base).
- Commit messages reference `(ref #749)`. No Claude Code references / footers in commits.

---

### Task 1: Toolbox cross-site aggregation in `social.py`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/social.py` (add two functions next to `aggregate()` ~line 1025)
- Test: `packages/secubox-toolbox/tests/test_cookie_xsite_detail.py` (create)

**Interfaces:**
- Consumes: `social._conn()`, `social._registrable_domain(host)`, `social._is_ip(host)` (existing).
- Produces:
  - `_xsite_detail_from_conn(conn, since: int, top_n: int) -> list[dict]` — pure, over a conn. Each dict: `{tracker_domain:str, sites:list[str], site_count:int, client_count:int, cookie_count:int, pre_consent_hits:int, last_seen:int}`.
  - `cookie_xsite_detail(hours: int = 24, top_n: int = 50) -> dict` — envelope `{window_hours:int, generated_at:int, trackers:list[dict]}`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_cookie_xsite_detail.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for social.cookie_xsite_detail / _xsite_detail_from_conn (ref #749)."""
import sqlite3
from secubox_toolbox import social


def _edges_db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE social_edges (
            ts INTEGER, client_mac_hash TEXT, src_site TEXT,
            tracker_domain TEXT, cookie_id_hash TEXT, ja4_hash TEXT,
            consent_state TEXT DEFAULT 'none_seen');
    """)
    return c


def _add(c, ts, client, site, tracker, cid, consent="pre_consent"):
    c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
              "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
              "VALUES (?,?,?,?,?,'ja4',?)",
              (ts, client, site, tracker, cid, consent))


def test_crosssite_tracker_detected_with_detail():
    c = _edges_db()
    # same cookie id reused across 2 distinct sites -> cross-site
    _add(c, 100, "m1", "news.example", "www.criteo.com", "CID1")
    _add(c, 200, "m2", "shop.example2", "www.criteo.com", "CID1", consent="post_consent")
    c.commit()
    rows = social._xsite_detail_from_conn(c, since=0, top_n=50)
    assert len(rows) == 1
    t = rows[0]
    assert t["tracker_domain"] == "criteo.com"
    assert t["site_count"] == 2
    assert sorted(t["sites"]) == ["news.example", "shop.example2"]
    assert t["client_count"] == 2
    assert t["cookie_count"] == 1
    assert t["pre_consent_hits"] == 1
    assert t["last_seen"] == 200


def test_single_site_cookie_ignored():
    c = _edges_db()
    _add(c, 100, "m1", "news.example", "tracker.foo", "CID2")
    _add(c, 110, "m1", "news.example", "tracker.foo", "CID2")
    c.commit()
    assert social._xsite_detail_from_conn(c, since=0, top_n=50) == []


def test_null_and_empty_src_site_excluded():
    c = _edges_db()
    _add(c, 100, "m1", "null", "t.bar", "CID3")
    _add(c, 110, "m1", "", "t.bar", "CID3")
    _add(c, 120, "m1", "real.site", "t.bar", "CID3")
    c.commit()
    # only one VALID site remains for CID3 -> not cross-site
    assert social._xsite_detail_from_conn(c, since=0, top_n=50) == []


def test_window_filters_old_edges():
    c = _edges_db()
    _add(c, 100, "m1", "a.example", "t.win", "CIDW")
    _add(c, 200, "m1", "b.example2", "t.win", "CIDW")
    c.commit()
    assert social._xsite_detail_from_conn(c, since=150, top_n=50) == []


def test_ip_literal_tracker_dropped():
    c = _edges_db()
    _add(c, 100, "m1", "a.example", "192.0.2.5", "CIDIP")
    _add(c, 200, "m1", "b.example2", "192.0.2.5", "CIDIP")
    c.commit()
    assert social._xsite_detail_from_conn(c, since=0, top_n=50) == []


def test_ranking_and_top_n_cap():
    c = _edges_db()
    # tracker A: 2 clients ; tracker B: 1 client -> A ranks first
    _add(c, 100, "m1", "s1.x", "a.trk", "A1"); _add(c, 110, "m2", "s2.x", "a.trk", "A1")
    _add(c, 120, "m1", "s1.x", "b.trk", "B1"); _add(c, 130, "m1", "s2.x", "b.trk", "B1")
    c.commit()
    rows = social._xsite_detail_from_conn(c, since=0, top_n=1)
    assert len(rows) == 1
    assert rows[0]["tracker_domain"] == "trk"  # registrable of a.trk/b.trk


def test_envelope_shape_via_conn(monkeypatch):
    c = _edges_db()
    _add(c, 100, "m1", "news.example", "www.criteo.com", "CID1")
    _add(c, 200, "m2", "shop.example2", "www.criteo.com", "CID1")
    c.commit()

    class _Ctx:
        def __enter__(self): return c
        def __exit__(self, *a): return False

    monkeypatch.setattr(social, "_conn", lambda: _Ctx())
    out = social.cookie_xsite_detail(hours=24, top_n=50)
    assert out["window_hours"] == 24
    assert isinstance(out["generated_at"], int)
    assert out["trackers"][0]["tracker_domain"] == "criteo.com"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_cookie_xsite_detail.py -v`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.social' has no attribute '_xsite_detail_from_conn'`

- [ ] **Step 3: Implement the two functions**

In `packages/secubox-toolbox/secubox_toolbox/social.py`, immediately AFTER the `aggregate()` function, add:

```python
def _xsite_detail_from_conn(conn, since: int, top_n: int) -> list:
    """Pure cross-site tracker detail over a social_edges connection.

    A (tracker_domain, cookie_id_hash) pair is cross-site when its cookie id is
    observed on >= 2 DISTINCT valid src_sites (src_site not in '', 'null') within
    the window (ts >= since). For every such pair, aggregate per REGISTRABLE
    tracker domain (IP literals dropped). Ranked by client_count, then
    site_count, then domain; capped to top_n.
    """
    rows = conn.execute(
        "SELECT ts, client_mac_hash, src_site, tracker_domain, "
        "       cookie_id_hash, consent_state "
        "FROM social_edges "
        "WHERE ts >= ? "
        "  AND cookie_id_hash IS NOT NULL AND cookie_id_hash <> '' "
        "  AND src_site NOT IN ('', 'null') "
        "LIMIT 50000",
        (since,),
    ).fetchall()

    # Pass 1: which (raw tracker_domain, cookie_id_hash) pairs are cross-site.
    sites_per_pair: dict = {}
    for r in rows:
        key = (r["tracker_domain"], r["cookie_id_hash"])
        sites_per_pair.setdefault(key, set()).add(r["src_site"])
    xsite_pairs = {k for k, s in sites_per_pair.items() if len(s) >= 2}
    if not xsite_pairs:
        return []

    # Pass 2: aggregate the cross-site rows per registrable tracker domain.
    agg: dict = {}
    for r in rows:
        if (r["tracker_domain"], r["cookie_id_hash"]) not in xsite_pairs:
            continue
        dom = _registrable_domain(r["tracker_domain"])
        if not dom or _is_ip(dom):
            continue
        e = agg.setdefault(dom, {
            "tracker_domain": dom, "sites": set(), "clients": set(),
            "cookies": set(), "pre_consent_hits": 0, "last_seen": 0,
        })
        e["sites"].add(r["src_site"])
        e["clients"].add(r["client_mac_hash"])
        e["cookies"].add(r["cookie_id_hash"])
        if r["consent_state"] == "pre_consent":
            e["pre_consent_hits"] += 1
        if r["ts"] > e["last_seen"]:
            e["last_seen"] = r["ts"]

    out = [{
        "tracker_domain": e["tracker_domain"],
        "sites": sorted(e["sites"]),
        "site_count": len(e["sites"]),
        "client_count": len(e["clients"]),
        "cookie_count": len(e["cookies"]),
        "pre_consent_hits": e["pre_consent_hits"],
        "last_seen": e["last_seen"],
    } for e in agg.values()]
    out.sort(key=lambda t: (-t["client_count"], -t["site_count"],
                            t["tracker_domain"]))
    return out[:max(0, top_n)]


def cookie_xsite_detail(hours: int = 24, top_n: int = 50) -> Dict:
    """Operator view of cross-site tracker cookies over social_edges.

    Mirrors aggregate()'s envelope shape. JWT-gated in the API layer.
    """
    if hours < 1 or hours > 24 * 31:
        hours = 24
    if top_n < 1 or top_n > 500:
        top_n = 50
    now = int(time.time())
    since = now - hours * 3600
    out: Dict = {"window_hours": hours, "generated_at": now, "trackers": []}
    try:
        with _conn() as c:
            out["trackers"] = _xsite_detail_from_conn(c, since, top_n)
    except sqlite3.Error as e:
        log.warning("cookie_xsite_detail: DB error, returning empty: %s", e)
    return out
```

Note: confirm `time`, `sqlite3`, `log`, and the `Dict` typing alias are already imported at the top of `social.py` (they are — `aggregate()` uses `time` and `Dict`). If `log` is named differently in this module, match the existing logger name used elsewhere in `social.py`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_cookie_xsite_detail.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/social.py packages/secubox-toolbox/tests/test_cookie_xsite_detail.py
git commit -m "feat(toolbox): cookie_xsite_detail aggregation over social_edges (ref #749)"
```

---

### Task 2: Toolbox endpoint `GET /admin/cookie-crosssite`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (add endpoint next to `admin_social_aggregate`)
- Test: `packages/secubox-toolbox/tests/test_cookie_crosssite_api.py` (create)

**Interfaces:**
- Consumes: `social.cookie_xsite_detail(hours, top_n)` from Task 1.
- Produces: `admin_cookie_crosssite(hours: int = 24, top: int = 50) -> dict` — returns the envelope from `cookie_xsite_detail`.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_cookie_crosssite_api.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for GET /admin/cookie-crosssite (ref #749)."""
import asyncio
from secubox_toolbox import api, social

_CANNED = {
    "window_hours": 24,
    "generated_at": 1782000000,
    "trackers": [{
        "tracker_domain": "criteo.com", "sites": ["a.example", "b.example2"],
        "site_count": 2, "client_count": 3, "cookie_count": 1,
        "pre_consent_hits": 2, "last_seen": 1782000000,
    }],
}


def test_cookie_crosssite_returns_detail(monkeypatch):
    monkeypatch.setattr(social, "cookie_xsite_detail",
                        lambda hours=24, top_n=50, **kw: dict(_CANNED))
    result = asyncio.run(api.admin_cookie_crosssite(hours=24, top=50))
    assert result["trackers"][0]["tracker_domain"] == "criteo.com"
    assert result["trackers"][0]["site_count"] == 2
    assert result["window_hours"] == 24


def test_cookie_crosssite_forwards_params(monkeypatch):
    captured = {}

    def fake(hours=24, top_n=50, **kw):
        captured["hours"] = hours
        captured["top_n"] = top_n
        return dict(_CANNED)

    monkeypatch.setattr(social, "cookie_xsite_detail", fake)
    asyncio.run(api.admin_cookie_crosssite(hours=12, top=10))
    assert captured == {"hours": 12, "top_n": 10}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_cookie_crosssite_api.py -v`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.api' has no attribute 'admin_cookie_crosssite'`

- [ ] **Step 3: Implement the endpoint**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, immediately AFTER the `admin_social_aggregate` function (~line 2870), add:

```python
@router.get("/admin/cookie-crosssite")
async def admin_cookie_crosssite(hours: int = 24, top: int = 50) -> dict:
    """Operator view : cross-site tracker cookies (a cookie id reused across
    >= 2 first-party sites) with per-tracker site/client/cookie counts. Read-only
    over social_edges; same admin gating as the sibling /admin/* routes.
    """
    from . import social as _s
    return _s.cookie_xsite_detail(hours=hours, top_n=top)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_cookie_crosssite_api.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the full toolbox social/learn test slice (no regressions)**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_cookie_xsite_detail.py tests/test_cookie_crosssite_api.py tests/test_learn.py tests/test_social_edges.py -q`
Expected: PASS (all)

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_cookie_crosssite_api.py
git commit -m "feat(toolbox): GET /admin/cookie-crosssite endpoint (ref #749)"
```

---

### Task 3: Cookies dashboard "Trackers cross-site" panel

**Files:**
- Modify: `packages/secubox-cookies/www/cookies/index.html` (markup card in `#tab-trackers` + JS `loadCrossSite()` + wiring)

**Interfaces:**
- Consumes: `GET /api/v1/toolbox/admin/cookie-crosssite?hours=24` (Task 2), the existing `headers()` JS helper.
- Produces: a rendered table `#crosssite-table`; `loadCrossSite()` called from `switchTab('trackers')` and `refresh()`.

- [ ] **Step 1: Add the card markup**

In `packages/secubox-cookies/www/cookies/index.html`, inside `<div class="tab-content" id="tab-trackers">`, AFTER the existing "Known Tracker Patterns" `<div class="card">…</div>` (after its closing `</div>` for that card, before the `</div>` that closes `#tab-trackers`), insert:

```html
            <div class="card">
                <div class="card-title">
                    <span>🕸️ Trackers cross-site (R3)</span>
                    <span class="badge badge-cyan" id="crosssite-count">0</span>
                </div>
                <p class="empty" style="margin:0 0 .5rem">Cookies dont l'identifiant est réutilisé sur ≥2 sites first-party par le même client (source : tunnel captif R3).</p>
                <table>
                    <thead>
                        <tr>
                            <th>Tracker</th>
                            <th>Sites suivis</th>
                            <th>Clients</th>
                            <th>Cookies</th>
                            <th>Pré-consent</th>
                            <th>Vu</th>
                        </tr>
                    </thead>
                    <tbody id="crosssite-table">
                        <tr><td colspan="6" class="empty">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
```

- [ ] **Step 2: Add the `loadCrossSite()` JS function**

In the `<script>` block, immediately AFTER the `loadTrackers()` function (~line 758-773), add:

```javascript
        async function loadCrossSite() {
            const tbody = document.getElementById('crosssite-table');
            const countEl = document.getElementById('crosssite-count');
            try {
                const res = await fetch('/api/v1/toolbox/admin/cookie-crosssite?hours=24', { headers: headers() });
                if (!res.ok) throw new Error('http ' + res.status);
                const data = await res.json();
                const rows = (data && data.trackers) || [];
                countEl.textContent = rows.length;
                if (!rows.length) {
                    tbody.innerHTML = '<tr><td colspan="6" class="empty">Aucune donnée R3 récente — tunnel captif inactif.</td></tr>';
                    return;
                }
                tbody.innerHTML = rows.map(t => {
                    const sites = (t.sites || []).join(', ');
                    const seen = t.last_seen ? new Date(t.last_seen * 1000).toLocaleString() : '-';
                    const pc = t.pre_consent_hits > 0
                        ? `<span class="badge badge-red">${t.pre_consent_hits}</span>` : '0';
                    return `<tr>
                        <td><strong>${esc(t.tracker_domain)}</strong></td>
                        <td><span class="badge badge-cyan" title="${esc(sites)}">${t.site_count}</span></td>
                        <td>${t.client_count}</td>
                        <td>${t.cookie_count}</td>
                        <td>${pc}</td>
                        <td style="white-space:nowrap">${esc(seen)}</td>
                    </tr>`;
                }).join('');
            } catch (e) {
                countEl.textContent = '0';
                tbody.innerHTML = '<tr><td colspan="6" class="empty">Source R3 indisponible.</td></tr>';
            }
        }

        function esc(s) {
            return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
                { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        }
```

Note: if an `esc()` (HTML-escape) helper already exists in this `<script>`, do NOT add a second one — reuse the existing one and drop the `esc` definition above.

- [ ] **Step 3: Wire `loadCrossSite()` into tab switch and refresh**

In `switchTab(tab)`, find `case 'trackers': loadTrackers(); break;` and change it to:

```javascript
                case 'trackers': loadTrackers(); loadCrossSite(); break;
```

In `refresh()` (~line 943), add a `loadCrossSite();` call alongside the other `loadX()` calls in that function body.

- [ ] **Step 4: Syntax-check the page JS**

Run (extracts the inline script and runs it through node's parser; expect no output / exit 0):

```bash
cd packages/secubox-cookies/www/cookies
python3 - <<'PY'
import re,sys,subprocess,tempfile,os
h=open('index.html',encoding='utf-8').read()
m=re.search(r'<script>(.*?)</script>', h, re.S)
js=m.group(1)
f=tempfile.NamedTemporaryFile('w',suffix='.js',delete=False,encoding='utf-8'); f.write(js); f.close()
r=subprocess.run(['node','--check',f.name]); os.unlink(f.name); sys.exit(r.returncode)
PY
```
Expected: exit 0 (no syntax error). If `node` is unavailable, skip and rely on the manual browser check in Step 5.

- [ ] **Step 5: Manual verification (deploy to board, then browser)**

The cookies www is served by nginx from the deployed package. To verify against the live toolbox endpoint without a full rebuild, copy the edited file to the board and open the dashboard:

```bash
scp index.html root@192.168.1.200:/usr/share/secubox/cookies/www/cookies/index.html 2>/dev/null \
  || scp index.html root@192.168.1.200:/var/www/secubox/cookies/index.html
# confirm the toolbox endpoint answers (operator must be logged in for JWT in browser):
ssh root@192.168.1.200 "curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8088/admin/cookie-crosssite?hours=24"
```
Then open the cookies dashboard → **Trackers** tab → confirm the "🕸️ Trackers cross-site (R3)" card renders rows (or the graceful empty state if R3 is idle). Note: the exact nginx docroot for the cookies www is whatever `debian/install` maps `www/cookies/` to — confirm with `ssh root@192.168.1.200 'nginx -T 2>/dev/null | grep -A3 cookies'` if the scp path is uncertain.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-cookies/www/cookies/index.html
git commit -m "feat(cookies): cross-site trackers panel from toolbox R3 (ref #749)"
```

---

## Self-Review notes

- **Spec coverage:** Toolbox `cookie_xsite_detail` (Task 1) ✓; `GET /admin/cookie-crosssite` (Task 2) ✓; cookies WebUI panel + graceful R3-idle degradation (Task 3) ✓; src_site `''`/`null` filtered at read (Task 1 query) ✓; reuse of `social_edges` + `_registrable_domain`/`_is_ip` ✓; privacy (only hashes/counts/registrable domains exposed) ✓.
- **Home refinement vs spec:** the spec phrased the function as a "sibling of `cookie_xsite_trackers` (learn.py / social.py)"; this plan places it in `social.py` next to `aggregate()` because both are operator-view aggregations over `social_edges` and `aggregate()` is the closest existing pattern (envelope + `_conn` + `_registrable_domain`). This is within the spec's stated options.
- **Type consistency:** envelope keys (`window_hours`, `generated_at`, `trackers`) and row keys (`tracker_domain`, `sites`, `site_count`, `client_count`, `cookie_count`, `pre_consent_hits`, `last_seen`) are identical across Task 1 (producer), Task 2 (canned test), and Task 3 (renderer).
