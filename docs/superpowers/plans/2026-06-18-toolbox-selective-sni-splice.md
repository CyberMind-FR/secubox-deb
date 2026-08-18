<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox Selective SNI-Splice (Lever A) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Splice (raw TCP passthrough) pure-asset HTTPS flows at the TLS ClientHello by SNI, so the GIL-bound mitm-wg workers only forge/decrypt/parse/run-addons on flows that need L7 work.

**Architecture:** New `tls_splice` addon (`tls_clienthello` hook) consults a pure classifier (`splice.py`) over a curated media seed ∪ autolearn-promoted never-HTML hosts; ships `tls_splice=observe` (dark) → flip to `on`. New `splice_host_obs` table feeds the learning. WAF + Go/Rust core out of scope.

**Tech Stack:** Python, mitmproxy 11 addon API, SQLite (WAL), pytest.

**Spec:** `docs/superpowers/specs/2026-06-18-toolbox-selective-sni-splice.md`

All paths below are under `packages/secubox-toolbox/`. Run tests from that dir with `python -m pytest` (fallback `python3 -m pytest`).

---

### Task 1: filters `tls_splice` toggle (off|observe|on, default observe)

**Files:** Modify `secubox_toolbox/filters.py`; Test `tests/test_filters_splice.py` (create)

- [ ] **Step 1: Failing test**

```python
# tests/test_filters_splice.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from secubox_toolbox import filters


def test_default_is_observe(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.get_filters(force=True)["tls_splice"] == "observe"


def test_bad_value_falls_back(monkeypatch, tmp_path):
    fp = tmp_path / "f.json"; fp.write_text(json.dumps({"tls_splice": "bogus"}))
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp))
    assert filters.get_filters(force=True)["tls_splice"] == "observe"


def test_set_filters_accepts_valid(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    out = filters.set_filters({"tls_splice": "on"})
    assert out["tls_splice"] == "on"
    out = filters.set_filters({"tls_splice": "nope"})
    assert out["tls_splice"] == "on"  # invalid ignored, prior kept
```

Run: `python -m pytest tests/test_filters_splice.py -v` → FAIL (`tls_splice` missing).

- [ ] **Step 2: Implement**

In `secubox_toolbox/filters.py`:
- Add to `DEFAULTS` (after the `"autolearn": True,` line):
  ```python
      "tls_splice": "observe",        # #649 off | observe | on  (asset SNI-splice)
  ```
- After `_VALID_PROTECTIVE = ("off", "alert", "spoof")` add:
  ```python
  _VALID_SPLICE = ("off", "observe", "on")
  ```
- In `get_filters`, after the `protective` validation block (line ~67-68) add:
  ```python
      if out.get("tls_splice") not in _VALID_SPLICE:
          out["tls_splice"] = DEFAULTS["tls_splice"]
  ```
- In `set_filters`, add a branch (after the `protective` branch):
  ```python
          elif k == "tls_splice" and v in _VALID_SPLICE:
              cur["tls_splice"] = v
  ```

- [ ] **Step 3: Pass** — `python -m pytest tests/test_filters_splice.py -v` → PASS.
- [ ] **Step 4: Commit** — `git add secubox_toolbox/filters.py tests/test_filters_splice.py && git commit -m "feat(toolbox): tls_splice filter toggle off|observe|on (ref #649)"`

---

### Task 2: `splice.py` classifier (pure)

**Files:** Create `secubox_toolbox/splice.py`, `tests/test_splice_classify.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_splice_classify.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import splice


def test_host_matches_exact_and_subdomain():
    pats = {"googlevideo.com", "fbcdn.net"}
    assert splice.host_matches("googlevideo.com", pats)
    assert splice.host_matches("r1---sn-x.googlevideo.com", pats)
    assert not splice.host_matches("notgooglevideo.com", pats)   # no false prefix
    assert not splice.host_matches("example.com", pats)


def test_should_splice_seed_and_learned():
    seed = {"googlevideo.com"}; learned = {"cdn.example.net"}; never = set()
    assert splice.should_splice("x.googlevideo.com", seed, learned, never)
    assert splice.should_splice("cdn.example.net", seed, learned, never)
    assert not splice.should_splice("news.example.com", seed, learned, never)


def test_never_wins():
    seed = {"evil-cdn.com"}; never = {"evil-cdn.com"}
    assert not splice.should_splice("evil-cdn.com", seed, set(), never)


def test_empty_sni_or_sets():
    assert not splice.should_splice("", {"a.com"}, set(), set())
    assert not splice.should_splice("a.com", set(), set(), set())


def test_load_seed_strips_comments(tmp_path):
    f = tmp_path / "seed.conf"
    f.write_text("# header\ngooglevideo.com  # yt\n\n  fbcdn.net\n")
    s = splice.load_splice_seed(str(f))
    assert s == {"googlevideo.com", "fbcdn.net"}
```

Run: `python -m pytest tests/test_splice_classify.py -v` → FAIL (no module).

- [ ] **Step 2: Implement** `secubox_toolbox/splice.py`

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: toolbox :: SNI-splice classifier (#649).

Pure helpers deciding, from the TLS SNI alone, whether a flow is a pure-asset
flow we can splice (raw passthrough, no MITM). Seed ∪ learned, minus a never-set
(trackers we block/poison, fortknox sites). Suffix match so CDN shards match.
"""
from __future__ import annotations

import os
from typing import Set


def _load_lines(path: str) -> Set[str]:
    out: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.split("#", 1)[0].strip().lower()
                if line:
                    out.add(line)
    except Exception:
        pass
    return out


def load_splice_seed(path: str) -> Set[str]:
    return _load_lines(path)


def load_learned_splice(path: str) -> Set[str]:
    return _load_lines(path)


def host_matches(host: str, patterns: Set[str]) -> bool:
    """True if host == pattern or host is a subdomain of pattern."""
    h = (host or "").lower().strip(".")
    if not h or not patterns:
        return False
    if h in patterns:
        return True
    for p in patterns:
        if h.endswith("." + p):
            return True
    return False


def should_splice(sni: str, seed: Set[str], learned: Set[str],
                  never: Set[str]) -> bool:
    s = (sni or "").lower().strip(".")
    if not s:
        return False
    if host_matches(s, never):      # never wins (trackers / fortknox)
        return False
    return host_matches(s, seed) or host_matches(s, learned)
```

- [ ] **Step 3: Pass** — `python -m pytest tests/test_splice_classify.py -v` → PASS.
- [ ] **Step 4: Commit** — `git add secubox_toolbox/splice.py tests/test_splice_classify.py && git commit -m "feat(toolbox): SNI-splice classifier (seed/learned/never) (ref #649)"`

---

### Task 3: curated media seed conf

**Files:** Create `conf/tls-splice-seed.conf`

- [ ] **Step 1: Create** `conf/tls-splice-seed.conf`

```
# SecuBox toolbox :: SNI-splice seed (#649)
# MEDIA/ASSET-SPECIFIC hosts only — NEVER generic CDN edges (cloudfront/fastly/
# akamai-edge) which also serve HTML apps; splicing those would blind the MITM
# to real pages. Suffix-matched (subdomains included). One host suffix per line.
googlevideo.com      # YouTube video streams (largest single hog)
ytimg.com            # YouTube thumbnails
gstatic.com          # Google static assets
ggpht.com            # Google user content / avatars
fbcdn.net            # Facebook / Instagram media
cdninstagram.com     # Instagram media
twimg.com            # Twitter / X media
licdn.com            # LinkedIn media
sndcdn.com           # SoundCloud audio
scdn.co              # Spotify audio
mzstatic.com         # Apple media / artwork
```

- [ ] **Step 2: Commit** — `git add conf/tls-splice-seed.conf && git commit -m "feat(toolbox): curated media SNI-splice seed (ref #649)"`

---

### Task 4: `splice_host_obs` table + store helpers

**Files:** Modify `secubox_toolbox/store.py`; Test `tests/test_splice_obs.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_splice_obs.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from pathlib import Path
from secubox_toolbox import store


def _fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", Path(tmp_path) / "t.db")


def test_record_and_never_html(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    for _ in range(20):
        store.record_splice_obs("cdn.assets.net", is_html=False)
    for _ in range(20):
        store.record_splice_obs("www.site.com", is_html=False)
    store.record_splice_obs("www.site.com", is_html=True)   # served HTML once
    hosts = store.never_html_hosts(min_hits=20)
    assert "cdn.assets.net" in hosts
    assert "www.site.com" not in hosts        # html_hits > 0 → excluded


def test_sampling_cap(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    for _ in range(100):
        store.record_splice_obs("x.net", is_html=False)
    # capped at 50 — never grows unbounded
    import sqlite3
    with store._conn() as c:
        hits = c.execute("SELECT hits FROM splice_host_obs WHERE host='x.net'").fetchone()[0]
    assert hits == 50
```

Run: `python -m pytest tests/test_splice_obs.py -v` → FAIL.

- [ ] **Step 2: Implement** in `secubox_toolbox/store.py`

Add to the `SCHEMA` string (before its closing `"""`):
```sql
CREATE TABLE IF NOT EXISTS splice_host_obs (
    host       TEXT PRIMARY KEY,
    hits       INTEGER NOT NULL DEFAULT 0,
    html_hits  INTEGER NOT NULL DEFAULT 0,
    last_seen  REAL
);
```

Add these functions (anywhere after `_conn`):
```python
_SPLICE_OBS_CAP = 50   # stop counting once we have enough signal per host


def record_splice_obs(host: str, is_html: bool) -> None:
    """Observe a MITM'd flow's host + whether it served text/html. Sampling-capped
    so writes stay bounded. Best-effort (never raises into the proxy path)."""
    h = (host or "").lower().strip(".")
    if not h:
        return
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO splice_host_obs(host, hits, html_hits, last_seen) "
                "VALUES(?, 1, ?, ?) "
                "ON CONFLICT(host) DO UPDATE SET "
                "  hits = MIN(hits + 1, ?), "
                "  html_hits = html_hits + ?, "
                "  last_seen = ? "
                "WHERE splice_host_obs.hits < ?",
                (h, 1 if is_html else 0, time.time(),
                 _SPLICE_OBS_CAP, 1 if is_html else 0, time.time(), _SPLICE_OBS_CAP),
            )
    except Exception as e:
        log.debug("splice obs failed: %s", e)


def never_html_hosts(min_hits: int = 20) -> list[str]:
    """Hosts observed >= min_hits times that NEVER served text/html."""
    try:
        with _conn() as c:
            rows = c.execute(
                "SELECT host FROM splice_host_obs WHERE hits >= ? AND html_hits = 0",
                (min_hits,),
            ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []
```
NOTE: confirm `_conn()` returns rows indexable by `[0]` (it uses default row
factory unless `row_factory` set — check; if `sqlite3.Row` is set, `r[0]` still
works). If `record_splice_obs`'s `WHERE ... hits < cap` guard interferes with the
`MIN(...)` (redundant), keep only the `WHERE` guard OR the `MIN` — pick the `MIN`
form and drop the trailing `WHERE` clause if the test shows the cap exceeded; the
test asserts hits==50.

- [ ] **Step 3: Pass** — `python -m pytest tests/test_splice_obs.py -v` → PASS. (If the ON CONFLICT cap logic misbehaves on the SQLite version, simplify to: read current hits, `if hits < cap` then increment — keep it passing the test.)
- [ ] **Step 4: Commit** — `git add secubox_toolbox/store.py tests/test_splice_obs.py && git commit -m "feat(toolbox): splice_host_obs table + record/never_html helpers (ref #649)"`

---

### Task 5: `tls_splice.py` addon

**Files:** Create `mitmproxy_addons/tls_splice.py`, `tests/test_tls_splice_addon.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_tls_splice_addon.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, json, types
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))
from secubox_toolbox import filters


def _addon(monkeypatch, tmp_path, mode):
    fp = tmp_path / "f.json"; fp.write_text(json.dumps({"tls_splice": mode}))
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp)); filters.get_filters(force=True)
    import tls_splice; importlib.reload(tls_splice)
    a = tls_splice.TlsSplice()
    a._seed = {"googlevideo.com"}; a._learned = set(); a._never = set()
    monkeypatch.setattr(a, "_refresh_sets", lambda: None)
    return tls_splice, a


def _ch(sni):
    d = types.SimpleNamespace()
    d.client_hello = types.SimpleNamespace(sni=sni)
    d.context = types.SimpleNamespace(client=types.SimpleNamespace(peername=("10.99.1.2", 5)))
    d.ignore_connection = False
    return d


def test_on_splices_seed_host(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "on")
    d = _ch("r1.googlevideo.com"); a.tls_clienthello(d)
    assert d.ignore_connection is True


def test_observe_does_not_splice(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "observe")
    d = _ch("r1.googlevideo.com"); a.tls_clienthello(d)
    assert d.ignore_connection is False


def test_off_returns_early(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "off")
    d = _ch("r1.googlevideo.com"); a.tls_clienthello(d)
    assert d.ignore_connection is False


def test_non_seed_not_spliced(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "on")
    d = _ch("news.example.com"); a.tls_clienthello(d)
    assert d.ignore_connection is False


def test_no_sni_not_spliced(monkeypatch, tmp_path):
    _, a = _addon(monkeypatch, tmp_path, "on")
    d = _ch(None); a.tls_clienthello(d)
    assert d.ignore_connection is False
```

Run: `python -m pytest tests/test_tls_splice_addon.py -v` → FAIL.

- [ ] **Step 2: Implement** `mitmproxy_addons/tls_splice.py`

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: toolbox :: selective SNI-splice (#649, Lever A).

At the TLS ClientHello, splice (raw passthrough, no forge/decrypt/parse/addons)
pure-asset flows decided from the SNI. Modes (filters.tls_splice):
  off     — never splice (legacy: MITM everything)
  observe — classify + log/count "would-splice", but still MITM (dark-launch)
  on      — actually splice
Also records per-host content-type observations (MITM'd flows) to feed the
autolearn never-HTML promotion. Registered FIRST in the mitm-wg addon chain.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time

if "/usr/lib/secubox/toolbox" not in sys.path:
    sys.path.insert(0, "/usr/lib/secubox/toolbox")

from secubox_toolbox import splice as _splice          # noqa: E402
from secubox_toolbox.filters import get_filters as _gf  # noqa: E402
try:
    from secubox_toolbox import store as _store          # noqa: E402
except Exception:  # pragma: no cover
    _store = None

log = logging.getLogger("secubox.toolbox.addons")

SEED_PATH = os.environ.get("SECUBOX_SPLICE_SEED",
                           "/usr/lib/secubox/toolbox/conf/tls-splice-seed.conf")
LEARNED_PATH = os.environ.get("SECUBOX_SPLICE_LEARNED",
                              "/var/lib/secubox/toolbox/splice-learned.txt")
PURE_PATH = os.environ.get("SECUBOX_PURE_TRACKERS",
                           "/var/lib/secubox/toolbox/pure-trackers.txt")
STATS = "/run/secubox/splice.json"

_counts = {"spliced": 0, "would_splice": 0, "mitm": 0, "since": int(time.time())}
_last_flush = 0.0


class TlsSplice:
    def __init__(self) -> None:
        self._seed: set = set()
        self._learned: set = set()
        self._never: set = set()
        self._mtimes: tuple = ()
        self._refresh_sets()

    def _refresh_sets(self) -> None:
        """Reload seed/learned/never sets when any backing file changes."""
        try:
            mtimes = tuple(
                os.stat(p).st_mtime if os.path.exists(p) else 0.0
                for p in (SEED_PATH, LEARNED_PATH, PURE_PATH))
        except Exception:
            mtimes = ()
        if mtimes == self._mtimes and self._seed:
            return
        self._seed = _splice.load_splice_seed(SEED_PATH)
        self._learned = _splice.load_learned_splice(LEARNED_PATH)
        never = _splice.load_learned_splice(PURE_PATH)   # pure trackers
        try:
            for s in _gf().get("fortknox_sites", []) or []:
                never.add(str(s).lower().strip("."))
        except Exception:
            pass
        self._never = never
        self._mtimes = mtimes

    def tls_clienthello(self, data) -> None:
        try:
            mode = _gf().get("tls_splice", "observe")
            if mode == "off":
                return
            # media_cache wants to see asset flows → don't splice when it's on
            if _gf().get("media_cache"):
                return
            sni = getattr(data.client_hello, "sni", None)
            if not sni:
                return
            self._refresh_sets()
            if not _splice.should_splice(sni, self._seed, self._learned, self._never):
                return
            if mode == "on":
                data.ignore_connection = True
                _counts["spliced"] += 1
            else:  # observe
                _counts["would_splice"] += 1
                log.info("tls-splice would-splice %s", sni)
            self._flush()
        except Exception as e:  # never break a connection
            log.debug("tls_splice clienthello error: %s", e)

    def response(self, flow) -> None:
        """Record host content-type on MITM'd flows (learning signal)."""
        if _store is None:
            return
        try:
            if _gf().get("tls_splice", "observe") == "off":
                return
            host = flow.request.pretty_host or ""
            ct = (flow.response.headers.get("content-type", "") or "").lower()
            _store.record_splice_obs(host, is_html=("text/html" in ct))
        except Exception:
            pass

    def _flush(self) -> None:
        global _last_flush
        now = time.time()
        if (now - _last_flush) < 5:
            return
        _last_flush = now
        try:
            os.makedirs(os.path.dirname(STATS), exist_ok=True)
            with open(STATS, "w", encoding="utf-8") as f:
                json.dump({**_counts, "updated": int(now)}, f)
        except Exception:
            pass


addons = [TlsSplice()]
```

- [ ] **Step 3: Pass** — `python -m pytest tests/test_tls_splice_addon.py -v` → PASS.
- [ ] **Step 4: Commit** — `git add mitmproxy_addons/tls_splice.py tests/test_tls_splice_addon.py && git commit -m "feat(toolbox): tls_splice addon — SNI-splice at ClientHello + obs recorder (ref #649)"`

---

### Task 6: autolearn `_splice_feed` promotion

**Files:** Modify `sbin/secubox-toolbox-autolearn`; Test `tests/test_autolearn_splice.py`

- [ ] **Step 1: Failing test**

```python
# tests/test_autolearn_splice.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import os, sqlite3, importlib.util, pathlib


def _load_autolearn():
    p = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-autolearn"
    spec = importlib.util.spec_from_loader("autolearn", loader=None)
    mod = importlib.util.module_from_spec(spec)
    exec(compile(p.read_text(), str(p), "exec"), mod.__dict__)
    return mod


def test_splice_feed_promotes_never_html(tmp_path, monkeypatch):
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE splice_host_obs(host TEXT PRIMARY KEY, hits INT, html_hits INT, last_seen REAL);"
        "INSERT INTO splice_host_obs VALUES('cdn.assets.net',25,0,0);"
        "INSERT INTO splice_host_obs VALUES('html.site.com',25,3,0);"
        "INSERT INTO splice_host_obs VALUES('low.hits.net',5,0,0);")
    con.commit(); con.close()
    out = tmp_path / "splice-learned.txt"
    monkeypatch.setenv("SECUBOX_AUTOLEARN_DB", str(db))
    monkeypatch.setenv("SECUBOX_SPLICE_LEARNED_OUT", str(out))
    al = _load_autolearn()
    n = al._splice_feed()
    learned = set(out.read_text().split())
    assert "cdn.assets.net" in learned       # never-HTML, >=20 hits
    assert "html.site.com" not in learned     # served HTML
    assert "low.hits.net" not in learned      # too few hits
    assert n == 1
```

Run: `python -m pytest tests/test_autolearn_splice.py -v` → FAIL.

- [ ] **Step 2: Implement** in `sbin/secubox-toolbox-autolearn`

Add near the other env paths (after `PURE_OUT`):
```python
SPLICE_LEARNED_OUT = os.environ.get(
    "SECUBOX_SPLICE_LEARNED_OUT",
    "/var/lib/secubox/toolbox/splice-learned.txt")
SPLICE_MIN_HITS = int(os.environ.get("SECUBOX_SPLICE_MIN_HITS", "20"))
SPLICE_MAX = 2000
```

Add the function (near `_dns_feed`):
```python
def _splice_feed() -> int:
    """Promote hosts that NEVER served text/html over >= SPLICE_MIN_HITS
    observations into the learned-splice file (registrable-folded, capped).
    Gated: skip when tls_splice == 'off'. Returns count written, or -1 if gated."""
    try:
        from secubox_toolbox.filters import get_filters
        if get_filters().get("tls_splice", "observe") == "off":
            return -1
    except Exception:
        pass
    try:
        con = sqlite3.connect(DB, timeout=5)
        rows = con.execute(
            "SELECT host FROM splice_host_obs WHERE hits >= ? AND html_hits = 0",
            (SPLICE_MIN_HITS,)).fetchall()
        con.close()
    except Exception as e:
        sys.stderr.write(f"autolearn: splice query failed: {e}\n")
        return -1
    hosts = sorted({(r[0] or "").lower().strip(".") for r in rows if r[0]})[:SPLICE_MAX]
    try:
        os.makedirs(os.path.dirname(SPLICE_LEARNED_OUT), exist_ok=True)
        tmp = SPLICE_LEARNED_OUT + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(hosts) + ("\n" if hosts else ""))
        os.replace(tmp, SPLICE_LEARNED_OUT)
    except Exception as e:
        sys.stderr.write(f"autolearn: splice write failed: {e}\n")
        return -1
    return len(hosts)
```

Call it from the script's main body (where `_dns_feed` etc. are invoked — find the bottom main section and add):
```python
    try:
        _n_splice = _splice_feed()
        sys.stderr.write(f"autolearn: {_n_splice} splice hosts learned\n")
    except Exception as e:
        sys.stderr.write(f"autolearn: splice feed error: {e}\n")
```
(Place it alongside the existing feed calls; keep it best-effort so it never aborts the run.)

- [ ] **Step 3: Pass** — `python -m pytest tests/test_autolearn_splice.py -v` → PASS.
- [ ] **Step 4: Commit** — `git add sbin/secubox-toolbox-autolearn tests/test_autolearn_splice.py && git commit -m "feat(toolbox): autolearn promotes never-HTML hosts to splice-learned (ref #649)"`

---

### Task 7: wiring (launch chain, debian/rules, changelog)

**Files:** Modify `sbin/secubox-toolbox-mitm-wg-launch`, `debian/rules`, `debian/changelog`

- [ ] **Step 1: Register addon FIRST** in `sbin/secubox-toolbox-mitm-wg-launch`

In the `for addon in ... ; do` list (currently begins `inject_xff utiq_defense ...`), prepend `tls_splice`:
```bash
for addon in tls_splice inject_xff utiq_defense protective_mode privacy_guard ad_ghost media_cache local_store social_graph inject_banner dpi cookies avatar ja4 soc_relay cert_pin_detect media_stats; do
```
(Its only acting hook is `tls_clienthello`, which fires before any requestheaders
addon regardless of order — so this doesn't disturb inject_xff's first-at-
requestheaders contract; placing it first is just clarity.)

- [ ] **Step 2: Install the seed conf** in `debian/rules`

Find the block that installs `conf/` (the bypass-seed install, near `conf/mitm-bypass-seed.conf`) and ensure the whole `conf/` dir (or the new file) lands at `/usr/lib/secubox/toolbox/conf/`. If there's an explicit per-file copy, add:
```make
	install -m 0644 conf/tls-splice-seed.conf $(DESTDIR)/usr/lib/secubox/toolbox/conf/
```
(If `conf/` is copied wholesale, no change needed — verify with `grep -n "conf/" debian/rules`.)

- [ ] **Step 3: Bump changelog** — new top entry in `debian/changelog`, version after the current top (`head -1 debian/changelog`):
```
secubox-toolbox (2.6.54-1~bookworm1) bookworm; urgency=medium

  * feat(#649): selective SNI-splice (Lever A). New tls_splice addon splices
    pure-asset flows (curated media seed + autolearn-promoted never-HTML hosts)
    at the TLS ClientHello — no forge/decrypt/parse/addons on those — so the
    GIL-bound R3 workers only do L7 work on flows that need it. Ships
    tls_splice=observe (dark: classify + log, still MITM); flip to `on` after
    soak. Kill-switch `off`. Trackers/fortknox/no-SNI/media_cache never spliced.

 -- Gerald KERMA <devel@cybermind.fr>  Thu, 18 Jun 2026 14:00:00 +0200
```
(Use the actual next version; if top is 2.6.53 → 2.6.54.)

- [ ] **Step 4: Full suite** — `python -m pytest tests/ -q` → all green (new + existing).
- [ ] **Step 5: bash -n** — `bash -n sbin/secubox-toolbox-mitm-wg-launch && python3 -c "import ast; ast.parse(open('sbin/secubox-toolbox-autolearn').read())"` → no errors.
- [ ] **Step 6: Commit** — `git add sbin/secubox-toolbox-mitm-wg-launch debian/rules debian/changelog && git commit -m "feat(toolbox): wire tls_splice addon + seed install + changelog 2.6.54 (ref #649)"`

---

## Self-Review notes
- Spec coverage: filters (T1), classifier (T2), seed (T3), obs/learning store (T4), addon incl. dark-launch modes + media_cache guard + recorder (T5), autolearn promotion (T6), wiring (T7). All spec sections mapped.
- Threshold consistency: obs sampling cap 50 (T4) ≥ promotion min_hits 20 (T4 test, T6) — a host can reach 20 never-HTML hits within the 50 cap. Consistent.
- `should_splice` never-set includes pure-trackers + fortknox (T2/T5). media_cache guard is in the addon (T5), not the pure classifier — keeps `splice.py` pure.
- Dark default `observe` (T1) means deploy is behavior-neutral until flip; matches spec rollout.
- Risk noted in T4 Step 2: verify the `ON CONFLICT ... MIN()/WHERE` cap on the target SQLite; fallback (read-then-write) given if needed to keep the test green.
