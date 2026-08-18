<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox #clients — reset-all (#634) + device/geo emojis (#635) Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "reset all clients" admin action (#634) and per-client device/geo emojis (#635) to the toolbox `#clients` tab.

**Architecture:** Reuse the existing per-client `store.reset_client` + `social.wipe_mac` in a small `api._reset_all_clients()` helper behind a new `POST /admin/clients/reset-all` route (kbin-gated). Enrich `admin_clients_rich()` with a real device emoji (`avatar_analysis.classify_user_agent` of the latest `consents.user_agent`) and geo (`geo.lookup(ip)` → flag + asn_org). UI: render them in `loadClients()` + a reset-all button.

**Tech Stack:** FastAPI (`api.py`), `store.py`, `social.py`, `avatar_analysis.py`, `geo.py`, vanilla JS `www/toolbox/index.html`. pytest. Issues #634 + #635.

**Spec:** `docs/superpowers/specs/2026-06-17-toolbox-clients-reset-all-and-emojis-design.md`.

**Conventions:** worktree `secubox-deb-worktrees/634-…` branch `feature/634-…`; commits end `(ref #634)` / `(ref #635)`.

**Verified facts:**
- `store.list_clients() -> list[dict]` (mac_hash, ip, state, score, level, first_seen, last_seen; LIMIT 200). `store.reset_client(mac_hash) -> int`. `social.wipe_mac(mac_hash) -> int`.
- `avatar_analysis.classify_user_agent(ua) -> dict` (keys incl. `device`, `device_emoji`). `geo.lookup(key) -> dict` (keys incl. `flag`, `country_iso`, `asn_org`).
- `admin_clients_rich()` builds `enriched` dicts and sets `"device_emoji": "📱"` (placeholder to replace).
- Per-client route `POST /admin/clients/{mac_hash}/reset` (api.py) has NO in-code kbin gate. `_is_public_kbin(request)` helper exists (used by `/admin/filter-control/*`) and returns True when `Host` starts with `kbin.`.
- `loadClients()` (index.html) renders a 7-col table (MAC/IP/state/niveau/score/last/Actions), top-5; `#panel-clients` has a toolbar with a refresh button.
- `consents` table has `user_agent` + `ts` (store.py schema).

---

### Task 1: `store.latest_user_agent`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/store.py`
- Test: `packages/secubox-toolbox/tests/test_clients_reset_emoji.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_clients_reset_emoji.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
from secubox_toolbox import store


def _tmpdb(tmp_path, monkeypatch):
    import pathlib
    monkeypatch.setattr(store, "DB_PATH", pathlib.Path(tmp_path / "toolbox.db"))
    # force schema creation
    with store._conn() as c:
        pass
    return store


def test_latest_user_agent(tmp_path, monkeypatch):
    s = _tmpdb(tmp_path, monkeypatch)
    with s._conn() as c:
        c.execute("INSERT INTO consents(mac_hash,ts,ttl_seconds,ip,user_agent) "
                  "VALUES('m1',100,3600,'1.2.3.4','OldUA')")
        c.execute("INSERT INTO consents(mac_hash,ts,ttl_seconds,ip,user_agent) "
                  "VALUES('m1',200,3600,'1.2.3.4','Mozilla/5.0 (iPhone) NewUA')")
    assert s.latest_user_agent("m1") == "Mozilla/5.0 (iPhone) NewUA"
    assert s.latest_user_agent("nope") is None
```

Note: `consents` has PRIMARY KEY `mac_hash` — so two rows for `m1` would conflict. Use `INSERT OR REPLACE`, OR (better) make the test insert one row per mac and assert it; adjust: since consents is keyed by mac_hash, the "latest" is simply the single row. REWRITE the test body to a single consent row per mac:

```python
def test_latest_user_agent(tmp_path, monkeypatch):
    s = _tmpdb(tmp_path, monkeypatch)
    with s._conn() as c:
        c.execute("INSERT INTO consents(mac_hash,ts,ttl_seconds,ip,user_agent) "
                  "VALUES('m1',200,3600,'1.2.3.4','Mozilla/5.0 (iPhone) UA')")
    assert s.latest_user_agent("m1") == "Mozilla/5.0 (iPhone) UA"
    assert s.latest_user_agent("nope") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_reset_emoji.py::test_latest_user_agent -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.store' has no attribute 'latest_user_agent'`

- [ ] **Step 3: Implement in `store.py`**

```python
def latest_user_agent(mac_hash: str):
    """Most recent recorded User-Agent for a client (from consents), or None."""
    try:
        with _conn() as c:
            row = c.execute(
                "SELECT user_agent FROM consents "
                "WHERE mac_hash=? AND user_agent IS NOT NULL AND user_agent<>'' "
                "ORDER BY ts DESC LIMIT 1", (mac_hash,)).fetchone()
        return row["user_agent"] if row else None
    except sqlite3.Error:
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_reset_emoji.py -q`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/store.py packages/secubox-toolbox/tests/test_clients_reset_emoji.py
git commit -m "feat(toolbox): store.latest_user_agent for client device detection (ref #635)"
```

---

### Task 2: `_reset_all_clients` + `POST /admin/clients/reset-all` (#634)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py`
- Test: `packages/secubox-toolbox/tests/test_clients_reset_emoji.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_reset_all_clients_loops(monkeypatch):
    import secubox_toolbox.api as api
    from secubox_toolbox import store as st, social as so
    calls = {"reset": [], "wipe": []}
    monkeypatch.setattr(st, "list_clients", lambda: [{"mac_hash": "a"}, {"mac_hash": "b"}])
    monkeypatch.setattr(st, "reset_client", lambda mh: calls["reset"].append(mh) or 3)
    monkeypatch.setattr(so, "wipe_mac", lambda mh: calls["wipe"].append(mh) or 2)
    out = api._reset_all_clients()
    assert calls["reset"] == ["a", "b"] and calls["wipe"] == ["a", "b"]
    assert out == {"ok": True, "clients_reset": 2, "rows_deleted": 10}


def test_reset_all_clients_one_failure_continues(monkeypatch):
    import secubox_toolbox.api as api
    from secubox_toolbox import store as st, social as so
    monkeypatch.setattr(st, "list_clients", lambda: [{"mac_hash": "a"}, {"mac_hash": "b"}])
    def _rc(mh):
        if mh == "a":
            raise RuntimeError("boom")
        return 3
    monkeypatch.setattr(st, "reset_client", _rc)
    monkeypatch.setattr(so, "wipe_mac", lambda mh: 2)
    out = api._reset_all_clients()
    assert out["ok"] is True and out["clients_reset"] == 1  # 'a' failed, 'b' ok
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_reset_emoji.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.api' has no attribute '_reset_all_clients'`

- [ ] **Step 3: Implement in `api.py`**

Add the helper (near `admin_client_reset`):
```python
def _reset_all_clients() -> dict:
    """Apply the per-client reset to every client (events/consents/reports +
    social graph wiped, score zeroed, client row kept). One client's failure
    is logged and skipped. Returns counts."""
    from . import social as _s
    clients_reset = 0
    rows_deleted = 0
    for c in store.list_clients():
        mh = c.get("mac_hash")
        if not mh:
            continue
        try:
            rows_deleted += store.reset_client(mh)
            rows_deleted += _s.wipe_mac(mh)
            clients_reset += 1
        except Exception as e:
            log.warning("reset-all: client %s failed: %s", str(mh)[:8], e)
    log.info("admin reset-all: %d clients, %d rows", clients_reset, rows_deleted)
    return {"ok": True, "clients_reset": clients_reset, "rows_deleted": rows_deleted}
```
Add the route (near the per-client reset route). reset-all is bulk-destructive, so gate it on the public-kbin vhost (defense-in-depth; more conservative than the per-client route):
```python
@router.post("/admin/clients/reset-all")
async def admin_clients_reset_all(request: Request) -> dict:
    """RAZ ALL clients (bulk per-client reset). Blocked on the public kbin vhost."""
    if _is_public_kbin(request):
        raise HTTPException(403, "reset-all disabled on public vhost — use admin.gk2.secubox.in/toolbox/")
    return _reset_all_clients()
```
(Confirm `Request` and `HTTPException` are imported in api.py — they are, used by `/admin/filter-control/*`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_reset_emoji.py -q`
Expected: PASS (3 passed). Then full suite `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_clients_reset_emoji.py
git commit -m "feat(toolbox): POST /admin/clients/reset-all (bulk per-client reset, kbin-gated) (ref #634)"
```

---

### Task 3: enrich `admin_clients_rich` with device + geo (#635)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (`admin_clients_rich`)
- Test: `packages/secubox-toolbox/tests/test_clients_reset_emoji.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_clients_rich_enriches_device_and_geo(monkeypatch):
    import asyncio
    import secubox_toolbox.api as api
    from secubox_toolbox import store as st, geo as g, avatar_analysis as av
    monkeypatch.setattr(st, "list_clients", lambda: [
        {"mac_hash": "m1", "ip": "1.2.3.4", "state": "validated",
         "score": 10, "level": "r2", "first_seen": 0, "last_seen": 0}])
    monkeypatch.setattr(st, "latest_user_agent",
                        lambda mh: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2)")
    monkeypatch.setattr(g, "lookup",
                        lambda ip: {"flag": "🇫🇷", "country_iso": "FR", "asn_org": "OVH"})
    out = asyncio.get_event_loop().run_until_complete(api.admin_clients_rich())
    c = out["clients"][0]
    assert c["flag"] == "🇫🇷" and c["country_iso"] == "FR" and c["asn_org"] == "OVH"
    assert c["device_emoji"] and c["device_emoji"] != "📱" or c["device"]  # real device from UA
    assert "device" in c
```

(If `admin_clients_rich` is async, `asyncio` run is needed as above; if it's sync, call it directly — adapt during impl.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_reset_emoji.py::test_clients_rich_enriches_device_and_geo -q`
Expected: FAIL — the enriched client lacks `flag`/`country_iso`/`asn_org`/`device`.

- [ ] **Step 3: Implement in `admin_clients_rich`**

Add imports at the top of the function:
```python
    from . import avatar_analysis as _av, geo as _geo
```
Replace the `"device_emoji": "📱",  # placeholder …` line in the `enriched.append({...})` with real enrichment computed just before the append:
```python
        # #635 — real device emoji from the latest UA + country/hosting via geo
        dev_emoji, dev_label = "📱", ""
        try:
            ua = store.latest_user_agent(r.get("mac_hash") or "")
            if ua:
                cl = _av.classify_user_agent(ua)
                dev_emoji = cl.get("device_emoji") or dev_emoji
                dev_label = cl.get("device") or ""
        except Exception:
            pass
        flag = country_iso = asn_org = ""
        try:
            gi = _geo.lookup(r.get("ip") or "")
            flag = gi.get("flag", "") or ""
            country_iso = gi.get("country_iso", "") or ""
            asn_org = gi.get("asn_org", "") or ""
        except Exception:
            pass
```
and in the `enriched.append({...})` dict, replace `"device_emoji": "📱", …` with:
```python
            "device_emoji": dev_emoji,
            "device": dev_label,
            "flag": flag,
            "country_iso": country_iso,
            "asn_org": asn_org,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_clients_reset_emoji.py -q`
Expected: PASS. Then full suite `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_clients_reset_emoji.py
git commit -m "feat(toolbox): clients/rich device emoji (UA) + country flag + hosting (geo) (ref #635)"
```

---

### Task 4: UI — `loadClients` render + reset-all button

**Files:**
- Modify: `packages/secubox-toolbox/www/toolbox/index.html`

- [ ] **Step 1: Inspect the panel toolbar + loadClients**

Run: `cd packages/secubox-toolbox && grep -n "panel-clients\|loadClients\|id=\"clients\"\|resetClient" www/toolbox/index.html`
Read the `#panel-clients` toolbar markup and the `loadClients` row render (verified above).

- [ ] **Step 2: Add the device/flag/hosting to the row render**

In `loadClients()`, add an `esc` helper if not already in scope (reuse the file's pattern) and extend the IP cell to show device + flag + hosting. Replace the table header + the IP cell:
- Header: change `<th>IP</th>` to `<th>IP / type</th>`.
- IP cell: replace `<td>${c.ip || '—'}</td>` with:
```javascript
            <td>${c.ip || '—'} <span style="white-space:nowrap">${c.device_emoji||''} ${c.flag||''}</span>${c.asn_org ? `<br><span style="color:var(--p31-dim,#888);font-size:0.72rem" title="${escA(c.device||'')}">${escA(c.asn_org)}</span>` : ''}</td>
```
Add near the top of `loadClients` (or as a file-level helper if one exists):
```javascript
    const escA = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
```
(`escA` escapes `"` too since `device` goes into a `title="..."` attribute.)

- [ ] **Step 3: Add the "Reset all" button to the panel toolbar**

In the `#panel-clients` toolbar (next to the existing refresh button), add:
```html
            <button type="button" onclick="resetAllClients()" style="color:var(--red,#e63946)">↺ Reset all</button>
```
Add the handler near `resetClient`:
```javascript
async function resetAllClients() {
    if (!confirm('Remettre à zéro TOUS les clients ? (events, consentements, graphes social — scores remis à zéro, clients conservés)')) return;
    try {
        const r = await fetch(`${API}/admin/clients/reset-all`, {method:'POST'});
        const d = await r.json().catch(()=>({}));
        if (!r.ok) { alert('Reset all refusé: ' + (d.detail || r.status)); return; }
        await loadClients();
        if (typeof loadSocial === 'function') loadSocial();
    } catch (e) { alert('Reset all erreur: ' + e); }
}
```
(Match the file's existing `API` const + `resetClient` style. If `resetClient` uses a different fetch idiom, mirror it.)

- [ ] **Step 4: Static verification**

Run from `packages/secubox-toolbox`:
- `grep -n "resetAllClients\|IP / type\|escA\|device_emoji" www/toolbox/index.html` → all present.
- `python -c "import pathlib;t=pathlib.Path('www/toolbox/index.html').read_text();assert t.count('<script')==t.count('</script>');assert 'resetAllClients' in t and 'IP / type' in t;print('ok')"`
- `python -m pytest tests/ -q` (unchanged, frontend-only).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/www/toolbox/index.html
git commit -m "feat(toolbox): #clients UI — device/flag/hosting + Reset-all button (ref #634, #635)"
```

---

### Task 5: changelog + gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Bump changelog**

`head -3 debian/changelog` (top is `2.6.49-1~bookworm1` on master). Add a NEW top entry `2.6.50-1~bookworm1`, dch format (2 spaces before date), author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17:
```
  * #clients tab: bulk "reset all clients" admin action (#634, per-client reset
    applied to every client, kbin-gated); per-client device emoji (from UA),
    country flag + hosting/ASN via geo (#635).
```

- [ ] **Step 2: Gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green).
Run: `python -c "import ast; ast.parse(open('secubox_toolbox/api.py').read()); ast.parse(open('secubox_toolbox/store.py').read()); print('ok')"`.
Run: `python -c "import pathlib;t=pathlib.Path('www/toolbox/index.html').read_text();assert t.count('<script')==t.count('</script>');print('html ok')"`.
Run: `dpkg-parsechangelog -l debian/changelog | grep Version` → `2.6.50-1~bookworm1`.
Run: `git status --short` → empty after commit.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog 2.6.50 for #clients reset-all + emojis (ref #634, #635)"
```

---

## Self-Review

**Spec coverage:**
- §2 reset-all (reuse reset_client+wipe_mac, keep rows, fail-continue, kbin gate) → Tasks 2, 4. ✓
- §3 device (latest UA → classify) + geo (flag/asn) enrichment → Tasks 1, 3. ✓
- §3/§4 UI render + reset-all button → Task 4. ✓
- §4 error handling (per-client try/except in reset-all + enrichment; latest_ua OSError→None; escape free-text) → Tasks 1/2/3/4. ✓
- §5 tests → Tasks 1/2/3. ✓
- Packaging → Task 5. ✓
- **Gate correction:** the per-client reset has NO in-code kbin gate (vhost-level); reset-all ADDS `_is_public_kbin` (defense-in-depth for the bulk destructive op) — recorded so it isn't read as inconsistent with §2's "identical" wording.

**Placeholder scan:** none — every code step has complete code. Task 1's test has a self-correcting note (consents PK is mac_hash → single-row form is the one to use); the corrected form is given explicitly.

**Type consistency:** `store.latest_user_agent(mac_hash)->str|None` (Task 1) used in Task 3. `_reset_all_clients()->dict{ok,clients_reset,rows_deleted}` (Task 2) called by the route + asserted in tests. `classify_user_agent`→`device_emoji`/`device`; `geo.lookup`→`flag`/`country_iso`/`asn_org` consistent between Task 3 impl and the UI render (Task 4) + tests. `escA` used in the UI for `asn_org`/`device`.

**Rollout:** cosmetic + an operator action; no gating/engine/nft/DNS impact; ships in toolbox 2.6.50.
