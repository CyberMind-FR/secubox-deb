<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2a (Learning → blacklist) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two safe learning signals to the hourly `autolearn` job — a top-N-capped **cookie-xsite** tracker signal that feeds `learned-trackers.txt`, and **pure-trackers** promotion (curated seed + conservative auto-promote) that produces `pure-trackers.txt` — both of which Plan 1's `privacy.py` brain already consumes.

**Architecture:** A new pure-Python module `secubox_toolbox/learn.py` holds the SQL/threshold logic (takes a `sqlite3.Connection`, returns lists/sets — no file or network I/O), unit-tested against an in-memory DB. The existing `sbin/secubox-toolbox-autolearn` script imports it, calls the two functions, and writes the list files atomically.

**Tech Stack:** Python 3.11, `sqlite3`, the existing `secubox_toolbox.privacy.registrable` (Plan 1). pytest. Issue #633.

**Spec:** `docs/superpowers/specs/2026-06-17-anti-track-v2-plan2a-learning-design.md`.

**Conventions:** SPDX header on new `.py` files; paths relative to `packages/secubox-toolbox/`; work in the worktree `secubox-deb-worktrees/633-anti-track-v2-layered-block-poison-anony` on branch `feature/633-…`; commits end `(ref #633)`, no AI footer.

**Key schema facts (verified):** `social_edges(ts, client_mac_hash, src_site, tracker_domain, cookie_id_hash NOT NULL, ja4_hash, consent_state DEFAULT 'none_seen')` — **no `hits` column** (raw event log; prevalence = `COUNT(*)`). `consent_state ∈ {none_seen, pre_consent, post_consent}`. `social_nodes(client_mac_hash, tracker_domain, hits, sites_jsonl, pre_consent_hits, …)`. `social_host_meta(tracker_domain, …, cdn_vendor, opgrade_vendor, antibot_vendor, …)`.

---

### Task 1: `learn.cookie_xsite_trackers`

**Files:**
- Create: `packages/secubox-toolbox/secubox_toolbox/learn.py`
- Test: `packages/secubox-toolbox/tests/test_learn.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_learn.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sqlite3
from secubox_toolbox import learn


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


def _add(c, client, site, tracker, cid, consent="pre_consent"):
    c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
              "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
              "VALUES (1,?,?,?,?,'ja4',?)",
              (client, site, tracker, cid, consent))


def test_cookie_xsite_crosssite_preconsent_detected():
    c = _edges_db()
    # same cookie id on 2 different sites, pre-consent → tracking cookie
    _add(c, "m1", "news.example", "www.criteo.com", "CID1")
    _add(c, "m1", "shop.example2", "www.criteo.com", "CID1")
    c.commit()
    out = learn.cookie_xsite_trackers(c, top_n=5)
    assert "criteo.com" in out          # registrable-folded


def test_cookie_xsite_single_site_ignored():
    c = _edges_db()
    _add(c, "m1", "news.example", "tracker.foo", "CID2")
    _add(c, "m1", "news.example", "tracker.foo", "CID2")  # same site twice
    c.commit()
    assert learn.cookie_xsite_trackers(c, top_n=5) == []


def test_cookie_xsite_post_consent_only_ignored():
    c = _edges_db()
    _add(c, "m1", "a.example", "t.bar", "CID3", consent="post_consent")
    _add(c, "m1", "b.example2", "t.bar", "CID3", consent="post_consent")
    c.commit()
    assert learn.cookie_xsite_trackers(c, top_n=5) == []


def test_cookie_xsite_top_n_cap_ranks_by_clients():
    c = _edges_db()
    # tracker A: 2 clients across 2 sites ; tracker B: 1 client across 2 sites
    _add(c, "m1", "s1.x", "a.trk", "A1"); _add(c, "m2", "s2.x", "a.trk", "A1")
    _add(c, "m1", "s1.x", "b.trk", "B1"); _add(c, "m1", "s2.x", "b.trk", "B1")
    c.commit()
    out = learn.cookie_xsite_trackers(c, top_n=1)
    assert out == ["a.trk"]             # higher distinct-client count wins
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_learn.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'secubox_toolbox.learn'`

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-toolbox/secubox_toolbox/learn.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: autolearn signals (Anti-Track v2 Plan 2a, #633)

Pure functions over a sqlite3 connection — no file/network I/O. Consumed by
sbin/secubox-toolbox-autolearn. Two signals:
  • cookie_xsite_trackers : cross-site pre-consent cookie setters (top-N capped)
  • pure_trackers         : hard-block allowlist (curated seed + auto-promote)
"""
from __future__ import annotations

import json
import sqlite3
from typing import Iterable

from secubox_toolbox.privacy import registrable


def cookie_xsite_trackers(conn: sqlite3.Connection, top_n: int = 5) -> list[str]:
    """Registrable tracker domains that set a cookie id reused across >=2 sites
    with at least one pre-consent observation, ranked by distinct clients then
    event count, truncated to top_n. Returns [] on any query error."""
    try:
        # 1) candidate raw tracker_domains: a cookie id seen on >=2 sites with
        #    >=1 pre-consent observation.
        candidates = set()
        for r in conn.execute(
            "SELECT tracker_domain "
            "FROM social_edges "
            "WHERE cookie_id_hash IS NOT NULL AND cookie_id_hash <> '' "
            "GROUP BY cookie_id_hash, tracker_domain "
            "HAVING COUNT(DISTINCT src_site) >= 2 "
            "   AND SUM(CASE WHEN consent_state='pre_consent' THEN 1 ELSE 0 END) > 0"
        ):
            d = registrable(r["tracker_domain"])
            if d:
                candidates.add(d)
        if not candidates:
            return []
        # 2) rank candidates by distinct clients then events, folded to eTLD+1.
        agg: dict[str, list[int]] = {}  # reg -> [clients_estimate, hits]
        for r in conn.execute(
            "SELECT tracker_domain, COUNT(*) AS hits, "
            "       COUNT(DISTINCT client_mac_hash) AS clients "
            "FROM social_edges GROUP BY tracker_domain"
        ):
            d = registrable(r["tracker_domain"])
            if not d or d not in candidates:
                continue
            cur = agg.setdefault(d, [0, 0])
            cur[0] += int(r["clients"])
            cur[1] += int(r["hits"])
        ranked = sorted(agg.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))
        return [d for d, _ in ranked[:max(0, top_n)]]
    except sqlite3.Error:
        return []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_learn.py -q`
Expected: PASS (4 passed)

Note: `registrable("www.criteo.com")` → `criteo.com`; `registrable("a.trk")`/`registrable("tracker.foo")` are 2-label → returned unchanged. The ranking test relies on summed distinct-clients per registrable; `a.trk` has 2 distinct clients vs `b.trk`'s 1.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/learn.py packages/secubox-toolbox/tests/test_learn.py
git commit -m "feat(toolbox): autolearn cookie-xsite signal (top-N capped) (ref #633)"
```

---

### Task 2: `learn.pure_trackers` + `PURE_SEED`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/learn.py`
- Test: `packages/secubox-toolbox/tests/test_learn.py`

- [ ] **Step 0: Verify the `cdn_vendor` column name**

Run: `cd packages/secubox-toolbox && grep -n "cdn_vendor\|CREATE TABLE IF NOT EXISTS social_host_meta" secubox_toolbox/social.py`
Expected: confirms `social_host_meta` has a `cdn_vendor` column. If the column is named differently, use that exact name in the query below and note it in the commit.

- [ ] **Step 1: Write the failing test (append to `tests/test_learn.py`)**

```python
def _nodes_db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE social_nodes (
            client_mac_hash TEXT, tracker_domain TEXT, hits INTEGER,
            sites_jsonl TEXT, pre_consent_hits INTEGER DEFAULT 0);
        CREATE TABLE social_host_meta (
            tracker_domain TEXT PRIMARY KEY, cdn_vendor TEXT,
            opgrade_vendor TEXT, antibot_vendor TEXT);
    """)
    return c


def _node(c, tracker, sites):
    c.execute("INSERT INTO social_nodes(client_mac_hash,tracker_domain,hits,"
              "sites_jsonl,pre_consent_hits) VALUES('m',?,1,?,1)",
              (tracker, json.dumps(sites)))


def _meta(c, tracker, cdn=None):
    c.execute("INSERT INTO social_host_meta(tracker_domain,cdn_vendor) "
              "VALUES(?,?)", (tracker, cdn))


def test_pure_seed_always_present():
    c = _nodes_db()
    pure = learn.pure_trackers(c, learned=set(), seed=learn.PURE_SEED)
    assert "google-analytics.com" in pure
    assert "doubleclick.net" in pure


def test_pure_autopromote_non_cdn_3sites():
    c = _nodes_db()
    _node(c, "evil.trk", ["a.com", "b.com", "c.com"])   # 3 sites
    _meta(c, "evil.trk", cdn=None)                       # not a CDN
    pure = learn.pure_trackers(c, learned={"evil.trk"}, seed=set())
    assert "evil.trk" in pure


def test_pure_not_promoted_when_cdn():
    c = _nodes_db()
    _node(c, "cdn.trk", ["a.com", "b.com", "c.com"])
    _meta(c, "cdn.trk", cdn="cloudflare")               # IS a CDN → never block
    pure = learn.pure_trackers(c, learned={"cdn.trk"}, seed=set())
    assert "cdn.trk" not in pure


def test_pure_not_promoted_under_3_sites():
    c = _nodes_db()
    _node(c, "small.trk", ["a.com", "b.com"])           # only 2 sites
    _meta(c, "small.trk", cdn=None)
    pure = learn.pure_trackers(c, learned={"small.trk"}, seed=set())
    assert "small.trk" not in pure


def test_pure_not_promoted_when_first_party():
    c = _nodes_db()
    # tracker registrable equals a first-party site it is seen on → never block
    _node(c, "shop.com", ["shop.com", "b.com", "c.com"])
    _meta(c, "shop.com", cdn=None)
    pure = learn.pure_trackers(c, learned={"shop.com"}, seed=set())
    assert "shop.com" not in pure
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_learn.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.learn' has no attribute 'PURE_SEED'`

- [ ] **Step 3: Write minimal implementation (append to `learn.py`)**

```python
# Curated seed of unambiguous pure beacon/ad hosts (registrable form). These
# never carry first-party content, so they are always safe to hard-block.
PURE_SEED: set[str] = {
    "google-analytics.com", "doubleclick.net", "googlesyndication.com",
    "googleadservices.com", "googletagservices.com", "scorecardresearch.com",
    "adnxs.com", "rubiconproject.com", "criteo.com", "taboola.com",
    "outbrain.com", "moatads.com", "amazon-adsystem.com", "adsrvr.org",
    "demdex.net", "krxd.net", "bluekai.com", "exelator.com",
}


def _sites_per_tracker(conn: sqlite3.Connection) -> dict[str, set]:
    """registrable tracker domain -> set of first-party site registrables."""
    out: dict[str, set] = {}
    for r in conn.execute("SELECT tracker_domain, sites_jsonl FROM social_nodes"):
        d = registrable(r["tracker_domain"])
        if not d:
            continue
        try:
            sites = json.loads(r["sites_jsonl"] or "[]")
        except (ValueError, TypeError):
            sites = []
        bucket = out.setdefault(d, set())
        for s in sites:
            rs = registrable(s)
            if rs:
                bucket.add(rs)
    return out


def pure_trackers(conn: sqlite3.Connection, learned: Iterable[str],
                  seed: Iterable[str] = PURE_SEED) -> set[str]:
    """Hard-block allowlist = curated seed ∪ conservatively auto-promoted
    learned trackers. Auto-promote requires: seen on >=3 distinct sites AND
    cdn_vendor IS NULL (not a CDN → not load-bearing) AND the tracker's
    registrable is never itself one of those first-party sites."""
    pure: set[str] = {registrable(s) or s for s in seed}
    learned_set = {registrable(d) or d for d in learned}
    try:
        # non-CDN hosts (cdn_vendor NULL/empty), folded to registrable
        non_cdn: set[str] = set()
        for r in conn.execute(
            "SELECT tracker_domain, cdn_vendor FROM social_host_meta"):
            if r["cdn_vendor"]:           # any non-null/non-empty cdn vendor → skip
                continue
            d = registrable(r["tracker_domain"])
            if d:
                non_cdn.add(d)
        sites = _sites_per_tracker(conn)
        for d in learned_set:
            ss = sites.get(d, set())
            if len(ss) < 3:
                continue                  # need >=3 distinct first-party sites
            if d not in non_cdn:
                continue                  # unknown or CDN → do not hard-block
            if d in ss:
                continue                  # tracker is itself first-party somewhere
            pure.add(d)
    except sqlite3.Error:
        pass                              # fail toward seed-only (fewer blocks)
    return pure
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_learn.py -q`
Expected: PASS (9 passed)

Note: a tracker is auto-promoted only if it is in `social_host_meta` with a NULL/empty `cdn_vendor` (so a learned host with no host-meta row at all is NOT promoted — conservative, intended).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/learn.py packages/secubox-toolbox/tests/test_learn.py
git commit -m "feat(toolbox): pure-trackers promotion (curated seed + conservative auto-promote) (ref #633)"
```

---

### Task 3: wire `learn.py` into the `autolearn` script

**Files:**
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-autolearn`
- Test: `packages/secubox-toolbox/tests/test_autolearn_integration.py`

The script currently learns threat-intel + opgrade into `learned-trackers.txt`. Add: import `learn`, union the cookie-xsite signal into the learned set, and write `pure-trackers.txt`. Make `DB`/`OUT`/the new `PURE_OUT` and `COOKIE_XSITE_TOP_N` env-overridable so the integration test can point them at temp paths.

- [ ] **Step 1: Write the failing integration test**

```python
# packages/secubox-toolbox/tests/test_autolearn_integration.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import os, sqlite3, subprocess, sys, pathlib, json

PKG = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = PKG / "sbin" / "secubox-toolbox-autolearn"


def _seed_db(path):
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE threat_intel (ioc TEXT, type TEXT);
        CREATE TABLE social_edges (ts INTEGER, client_mac_hash TEXT,
            src_site TEXT, tracker_domain TEXT, cookie_id_hash TEXT,
            ja4_hash TEXT, consent_state TEXT DEFAULT 'none_seen');
        CREATE TABLE social_nodes (client_mac_hash TEXT, tracker_domain TEXT,
            hits INTEGER, sites_jsonl TEXT, pre_consent_hits INTEGER DEFAULT 0);
        CREATE TABLE social_host_meta (tracker_domain TEXT PRIMARY KEY,
            cdn_vendor TEXT, opgrade_vendor TEXT, antibot_vendor TEXT);
    """)
    # cross-site pre-consent cookie tracker
    for site in ("a.example", "b.example2"):
        c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,"
                  "tracker_domain,cookie_id_hash,ja4_hash,consent_state) "
                  "VALUES(1,'m','%s','www.criteo.com','CID','j','pre_consent')" % site)
    # pure-eligible: 3 sites, non-CDN, learned via threat-intel
    c.execute("INSERT INTO threat_intel VALUES('evil.trk','domain')")
    c.execute("INSERT INTO social_nodes(client_mac_hash,tracker_domain,hits,"
              "sites_jsonl,pre_consent_hits) VALUES('m','evil.trk',1,?,1)",
              (json.dumps(["a.com", "b.com", "c.com"]),))
    c.execute("INSERT INTO social_host_meta(tracker_domain,cdn_vendor) "
              "VALUES('evil.trk',NULL)")
    c.commit(); c.close()


def test_autolearn_writes_both_lists(tmp_path):
    db = tmp_path / "toolbox.db"
    learned = tmp_path / "learned-trackers.txt"
    pure = tmp_path / "pure-trackers.txt"
    _seed_db(str(db))
    env = {**os.environ,
           "SECUBOX_AUTOLEARN_DB": str(db),
           "SECUBOX_AUTOLEARN_OUT": str(learned),
           "SECUBOX_AUTOLEARN_PURE_OUT": str(pure),
           "PYTHONPATH": str(PKG)}
    r = subprocess.run([sys.executable, str(SCRIPT)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    learned_txt = learned.read_text()
    assert "criteo.com" in learned_txt        # cookie-xsite signal
    assert "evil.trk" in learned_txt          # threat-intel (existing)
    pure_txt = pure.read_text()
    assert "google-analytics.com" in pure_txt  # seed
    assert "evil.trk" in pure_txt              # auto-promoted (3 sites, non-CDN)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_autolearn_integration.py -q`
Expected: FAIL — `pure-trackers.txt` not written (FileNotFoundError) / env vars ignored.

- [ ] **Step 3: Modify `sbin/secubox-toolbox-autolearn`**

(a) Make paths + cap env-overridable. Replace the constants block:
```python
DB = "/var/lib/secubox/toolbox/toolbox.db"
OUT = "/var/lib/secubox/toolbox/learned-trackers.txt"
MIN_SITES = 2          # cross-site threshold for operator-grade trackers
MAX_ENTRIES = 8000
```
with:
```python
import os
DB = os.environ.get("SECUBOX_AUTOLEARN_DB", "/var/lib/secubox/toolbox/toolbox.db")
OUT = os.environ.get("SECUBOX_AUTOLEARN_OUT",
                     "/var/lib/secubox/toolbox/learned-trackers.txt")
PURE_OUT = os.environ.get("SECUBOX_AUTOLEARN_PURE_OUT",
                          "/var/lib/secubox/toolbox/pure-trackers.txt")
MIN_SITES = 2          # cross-site threshold for operator-grade trackers
MAX_ENTRIES = 8000
COOKIE_XSITE_TOP_N = int(os.environ.get("SECUBOX_COOKIE_XSITE_TOP_N", "5"))

# Import the learning helpers (installed alongside under /usr/lib/secubox/toolbox).
sys.path.insert(0, os.environ.get("SECUBOX_TOOLBOX_LIB", "/usr/lib/secubox/toolbox"))
try:
    from secubox_toolbox import learn as _learn
except Exception:       # pragma: no cover - degraded mode
    _learn = None
```
(Keep the existing `import json, sqlite3, sys, time`. The integration test sets `PYTHONPATH` so `secubox_toolbox` imports from the package; in production the `sys.path.insert` covers it. The duplicate `import os` inside the file's later `os.replace` block — if present — is harmless, but prefer the top-level one; remove the inner `import os` near the write if it now shadows nothing.)

(b) After the existing opgrade block (after `c.close()` is currently called — MOVE the cookie-xsite query to BEFORE `c.close()` so the connection is still open). Concretely, just before `c.close()`, add:
```python
    # 3) NEW (#633): cross-site pre-consent cookie trackers, top-N capped.
    if _learn is not None:
        try:
            for d in _learn.cookie_xsite_trackers(c, top_n=COOKIE_XSITE_TOP_N):
                learned.add(d)
        except Exception:
            pass
    # compute pure-trackers (seed + conservative auto-promote) while DB open.
    pure: set = set(_learn.PURE_SEED) if _learn is not None else set()
    if _learn is not None:
        try:
            pure = _learn.pure_trackers(c, learned=learned, seed=_learn.PURE_SEED)
        except Exception:
            pass
```
(c) After writing `OUT` (after the existing `os.replace(tmp, OUT)` block), add an atomic write of `PURE_OUT`:
```python
    try:
        pout = sorted(x for x in pure if x)
        ptmp = PURE_OUT + ".tmp"
        with open(ptmp, "w", encoding="utf-8") as f:
            f.write("\n".join(pout) + ("\n" if pout else ""))
        os.replace(ptmp, PURE_OUT)
    except Exception as e:
        sys.stderr.write(f"autolearn: pure write failed: {e}\n")
```
(d) Update the final stderr manifest line to also report pure count, e.g. append `f" ; {len(pout)} pure"`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_autolearn_integration.py -q`
Expected: PASS (1 passed). Then full suite: `python -m pytest tests/ -q` (expect all green).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/sbin/secubox-toolbox-autolearn packages/secubox-toolbox/tests/test_autolearn_integration.py
git commit -m "feat(toolbox): autolearn writes learned-trackers (incl. cookie-xsite) + pure-trackers (ref #633)"
```

---

### Task 4: packaging + full gate

**Files:**
- Verify: `packages/secubox-toolbox/debian/rules` (the `cp -r secubox_toolbox …` already ships `learn.py` — confirm), `debian/changelog`.

- [ ] **Step 1: Confirm `learn.py` ships**

Run: `cd packages/secubox-toolbox && grep -n "cp -r secubox_toolbox" debian/rules`
Expected: a line copying the whole `secubox_toolbox` package to `/usr/lib/secubox/toolbox/` — so `learn.py` is included automatically. (No `debian/install` edit needed.) If the package is shipped file-by-file instead, add `learn.py`.

- [ ] **Step 2: Bump changelog**

Add a new top entry in `debian/changelog` (next version after the Plan-1 `2.6.42-1~bookworm1`, e.g. `2.6.43-1~bookworm1`), author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17, matching the existing dch format:
```
  * Anti-Track v2 Plan 2a (#633): autolearn cookie-xsite tracker signal
    (top-N capped, default 5) + pure-trackers.txt promotion (curated seed +
    conservative non-CDN/>=3-site auto-promote). Both lists consumed by the
    privacy brain; enforcement remains dark (privacy_enforce=false).
```

- [ ] **Step 3: Full suite + lint**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green, incl. the 30 Plan-1 tests + new learn/integration tests).
Run: `python -c "import ast; ast.parse(open('secubox_toolbox/learn.py').read()); print('ok')"` (expect `ok`).
Run: `python -m pyflakes secubox_toolbox/learn.py` if available (expect no output); else skip.
Run: `git status --short` (expect empty after commit).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog for Anti-Track v2 Plan 2a (ref #633)"
```

---

## Self-Review

**Spec coverage:**
- §3 cookie-xsite signal (≥2 sites, pre-consent, registrable-fold, top-N rank by clients→hits) → Task 1. ✓
- §3 cap default 5, env `COOKIE_XSITE_TOP_N`, only this signal capped → Task 1 (`top_n`) + Task 3 (env wiring); existing opgrade/threat-intel untouched. ✓
- §4 pure seed + auto-promote (≥3 sites, `cdn_vendor IS NULL`, never first-party) → Task 2. ✓
- §5 autolearn wiring, atomic writes, fail-toward-fewer-entries, no new daemon → Task 3. ✓
- §6 tests (cookie-xsite branches, pure branches, purity) → Tasks 1-2; integration → Task 3. ✓
- Packaging/ship → Task 4. ✓
- **Spec query correction applied:** spec §3 showed `SUM(hits)` but `social_edges` has no `hits` column — the plan uses `COUNT(*)`/`COUNT(DISTINCT client_mac_hash)`. Recorded here so it isn't read as a contradiction.
- **Provenance tag deferred:** spec §3 mentioned a trailing `cookie-xsite` comment tag; the plan keeps `learned-trackers.txt` in the existing plain one-host-per-line format (YAGNI; per-domain provenance for the UI is Plan 2c). Noted as an intentional simplification.

**Placeholder scan:** none — every code step has complete code. Task 2 Step 0 and Task 4 Step 1 are explicit verification steps (grep), not placeholders.

**Type consistency:** `cookie_xsite_trackers(conn, top_n)->list[str]` and `pure_trackers(conn, learned, seed)->set[str]` and `PURE_SEED:set[str]` are consistent between Task 1/2 defs and Task 3 calls. `registrable` is imported from `secubox_toolbox.privacy` (Plan 1) consistently. Env var names (`SECUBOX_AUTOLEARN_DB/OUT/PURE_OUT`, `SECUBOX_COOKIE_XSITE_TOP_N`, `SECUBOX_TOOLBOX_LIB`) match between Task 3 impl and the integration test.

**Rollout:** lists are inert until Plan 1's `privacy_enforce=true`. `pure-trackers.txt` only grants *eligibility* to hard-block. Deploy still respects board rules (no shared-parent mode changes; this task touches no dir modes).
