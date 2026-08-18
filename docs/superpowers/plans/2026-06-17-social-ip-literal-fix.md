<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# social-graph IP-literal fix (#642) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop recording IP-literal "tracker" edges (client self-traffic to gk2 service IPs) and make the `#social` `total_trackers_seen` KPI consistent with the `by_tracker_domain` table.

**Architecture:** Two small changes in `secubox_toolbox/social.py`: an `_is_ip` guard in `_record_edge_sync` (the chokepoint), and computing `total_trackers_seen` from the existing non-IP `_byd` fold in `aggregate`.

**Tech Stack:** Python, sqlite3. pytest (in-memory). Issue #642. **Spec:** `docs/superpowers/specs/2026-06-17-social-ip-literal-fix-design.md`.

**Conventions:** worktree `secubox-deb-worktrees/642-…` branch `fix/642-…`; commits end `(ref #642)`.

**Verified facts:** `social.py`: `DB_PATH` (:44), `_conn()` (row_factory=Row, :151), `_record_edge_sync(client_mac_hash, src_site, tracker_domain, cookie_id_hash_val, ja4_hash, consent_state)` does the INSERT into `social_edges`, wrapped in try/except. `_is_ip(host)` (:700) = `_IP_RE.match` (IPv4) or `":" in h` (IPv6) — defined AFTER `_record_edge_sync` but resolved at call-time. `aggregate()` sets `out["total_trackers_seen"] = COUNT(DISTINCT tracker_domain)` (raw), then builds `_byd` (folded, `if not td or _is_ip(td): continue`) and `out["by_tracker_domain"] = sorted(_byd.values(), ...)[:50]`.

---

### Task 1: `_record_edge_sync` — drop IP-literal trackers

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/social.py` (`_record_edge_sync`)
- Test: `packages/secubox-toolbox/tests/test_social_edges.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_social_edges.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pathlib
from secubox_toolbox import social


def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(social, "DB_PATH", pathlib.Path(tmp_path / "toolbox.db"))
    with social._conn():
        pass
    return social


def _count(s):
    with s._conn() as c:
        return c.execute("SELECT COUNT(*) FROM social_edges").fetchone()[0]


def test_record_edge_skips_ip_literals(tmp_path, monkeypatch):
    s = _db(tmp_path, monkeypatch)
    # IPv4 + IPv6 literal trackers → NOT recorded
    s._record_edge_sync("m", "news.example", "82.67.100.75", "cid", "ja4", "none_seen")
    s._record_edge_sync("m", "news.example", "2001:db8::1", "cid", "ja4", "none_seen")
    assert _count(s) == 0
    # a real hostname tracker → recorded
    s._record_edge_sync("m", "news.example", "www.criteo.com", "cid", "ja4", "pre_consent")
    assert _count(s) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_social_edges.py::test_record_edge_skips_ip_literals -q`
Expected: FAIL — count is 2 then 3 (IP literals currently recorded).

- [ ] **Step 3: Add the guard in `_record_edge_sync`**

At the very top of `_record_edge_sync` (before the `try:`), add:
```python
    # #642 — never record IP-literal "trackers" (no SNI/hostname = the client's
    # own traffic to gk2 service IPs etc.); they're noise the domain views filter.
    if _is_ip(tracker_domain):
        return
```
(`_is_ip` is defined later in the module but resolved at call-time — fine.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_social_edges.py -q`
Expected: PASS (1 passed). Then full suite `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/social.py packages/secubox-toolbox/tests/test_social_edges.py
git commit -m "fix(toolbox): social drops IP-literal tracker edges (no-SNI self-traffic) (ref #642)"
```

---

### Task 2: `aggregate` — KPI consistency

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/social.py` (`aggregate`)
- Test: `packages/secubox-toolbox/tests/test_social_edges.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_aggregate_total_excludes_ip_literals(tmp_path, monkeypatch):
    s = _db(tmp_path, monkeypatch)
    # insert raw rows DIRECTLY (bypass the new guard) to simulate legacy IP rows
    import time as _t
    now = int(_t.time())
    with s._conn() as c:
        for td in ("www.criteo.com", "doubleclick.net", "82.67.100.75"):
            c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
                      "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
                      "VALUES(?,?,?,?,?,?,?)",
                      (now, "m", "news.example", td, "cid", "ja4", "none_seen"))
    agg = s.aggregate(hours=24)
    assert agg["total_trackers_seen"] == 2            # IP excluded
    assert len(agg["by_tracker_domain"]) == 2
    assert agg["total_trackers_seen"] == len(agg["by_tracker_domain"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_social_edges.py::test_aggregate_total_excludes_ip_literals -q`
Expected: FAIL — `total_trackers_seen == 3` (raw count includes the IP).

- [ ] **Step 3: Fix `aggregate`**

DELETE the raw assignment:
```python
            out["total_trackers_seen"] = c.execute(
                "SELECT COUNT(DISTINCT tracker_domain) FROM social_edges "
                "WHERE ts >= ?",
                (since,),
            ).fetchone()[0]
```
Then, immediately AFTER the `out["by_tracker_domain"] = sorted(_byd.values(), key=lambda x: -x["hits"])[:50]` line, add:
```python
            # #642 — KPI = distinct non-IP registrable trackers (matches the
            # table's universe; was a raw COUNT that surfaced IP literals).
            out["total_trackers_seen"] = len(_byd)
```
(Leave `active_clients` and everything else unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_social_edges.py -q`
Expected: PASS (2 passed). Then full suite `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/social.py packages/secubox-toolbox/tests/test_social_edges.py
git commit -m "fix(toolbox): #social total_trackers_seen = distinct non-IP registrable (KPI matches table) (ref #642)"
```

---

### Task 3: changelog + gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Bump changelog**

`head -3 debian/changelog` (top is `2.6.50-1~bookworm1` on master). Add `2.6.51-1~bookworm1`, dch format, author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17:
```
  * social-graph (#642): stop recording IP-literal "tracker" edges (no-SNI
    self-traffic to gk2 service IPs); #social "Trackers vus" KPI now counts
    distinct non-IP registrable trackers so it matches the Top-domains table.
```

- [ ] **Step 2: Gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green).
Run: `python -c "import ast; ast.parse(open('secubox_toolbox/social.py').read()); print('ok')"`.
Run: `dpkg-parsechangelog -l debian/changelog | grep Version` → `2.6.51-1~bookworm1`.
Run: `git status --short` → empty after commit.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog 2.6.51 for social IP-literal fix (ref #642)"
```

---

## Self-Review

**Spec coverage:** Issue B (guard in `_record_edge_sync`) → Task 1; Issue A (`total_trackers_seen = len(_byd)`) → Task 2; packaging → Task 3. ✓

**Placeholder scan:** none — complete code each step.

**Type consistency:** `_is_ip(host)->bool` (existing) reused in `_record_edge_sync`; `len(_byd)` is the count of the dict the table is built from → `total_trackers_seen == len(by_tracker_domain)` whenever distinct ≤50 (the test's case). For >50 distinct, KPI ≥ table length (correct: "N seen", table shows top 50) — not a contradiction.

**Rollout:** no schema change; legacy IP edges excluded from both metrics immediately + expire via 7-day retention. Deploy = portal restart (aggregate) + mitm-wg reload (record_edge). No enforcement impact.
