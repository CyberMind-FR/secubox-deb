<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Core (brain + hot path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `privacy.py` policy brain and the `privacy_guard.py` mitm addon that, per request, decides `allow | block(204) | poison | anonymize` (plus per-site Fort-Knox), forging a stable fake identity for load-bearing trackers — shipped dark (`privacy_enforce=false`, observe-only).

**Architecture:** Approach C. All subtle logic (tracker classification, the deterministic fake-identity jar, the layered verdict, registrable-domain/Fort-Knox) lives in a pure-Python module `secubox_toolbox/privacy.py`, unit-testable without mitmproxy. A thin addon `mitmproxy_addons/privacy_guard.py` only *applies* the verdict in request/response hooks. Existing `protective_mode.py` is refactored to share `privacy.py`'s tracker patterns (single source of truth).

**Tech Stack:** Python 3.11, mitmproxy addon API, `hmac`/`hashlib`, the existing `secubox_toolbox.filters` toggle store and `mitmproxy_addons._common.mac_hash_of` client identity. pytest. Issue #633.

**Scope note:** This is plan 1 of 3. Plan 2 = offline pipeline (autolearn cookie-xsite signal, exclusive-tracker-IP set, escalate nft-drop, dns-guard feed). Plan 3 = Privacy/Anti-Track webui panel. This plan delivers the HTTP-depth block + poison + anonymize, working and testable on its own.

**Conventions:** every new `.py` starts with the SPDX header block (see `.claude/CLAUDE.md` Python convention). Work happens in the worktree `secubox-deb-worktrees/633-anti-track-v2-layered-block-poison-anony`; all paths below are relative to `packages/secubox-toolbox/`. Commit messages end with `(ref #633)` and carry no AI-tool footer.

---

### Task 1: `privacy.py` — registrable domain + tracker classification

**Files:**
- Create: `packages/secubox-toolbox/secubox_toolbox/privacy.py`
- Test: `packages/secubox-toolbox/tests/test_privacy.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_privacy.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import privacy


def test_registrable_basic():
    assert privacy.registrable("www.google-analytics.com") == "google-analytics.com"
    assert privacy.registrable("a.b.example.co.uk") == "example.co.uk"
    assert privacy.registrable("example.com") == "example.com"
    assert privacy.registrable("") == ""


def test_is_tracker_static():
    assert privacy.is_tracker("www.google-analytics.com") is True
    assert privacy.is_tracker("connect.facebook.net") is True
    assert privacy.is_tracker("example.com") is False


def test_classify_non_tracker_is_none():
    assert privacy.classify("cdn.example.com", beacon_hint=False) == "none"


def test_classify_unknown_tracker_defaults_loadbearing():
    # a tracker we have NOT confirmed beacon-only must fail safe to poison
    assert privacy.classify("criteo.com", beacon_hint=False) == "loadbearing"


def test_classify_beacon_hint_is_pure():
    # a tracker whose request looks like a fire-and-forget beacon → pure (blockable)
    assert privacy.classify("google-analytics.com", beacon_hint=True) == "pure"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'secubox_toolbox.privacy'`

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-toolbox/secubox_toolbox/privacy.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: privacy brain (Anti-Track v2, #633)

Pure-Python policy: classify a host (none / pure / loadbearing), mint a stable
fabricated identity per (client, tracker), and return a per-request verdict
(allow | block | poison | anonymize). No mitmproxy import here — unit-testable.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Optional

# Single source of truth for 3rd-party tracker hosts. protective_mode.py and
# ad_ghost.py import is_tracker() / _TRACKER from here (#633).
_TRACKER = re.compile(
    r"(?:^|\.)(?:"
    r"doubleclick|googlesyndication|googleadservices|googletagmanager|"
    r"google-analytics|googletagservices|adservice\.google|"
    r"facebook\.com/tr|connect\.facebook\.net|facebook\.net|"
    r"scorecardresearch|chartbeat|hotjar|mixpanel|amplitude|"
    r"segment\.com|segment\.io|criteo|adnxs|rubiconproject|"
    r"taboola|outbrain|smartadserver|optimizely|fullstory|"
    r"newrelic|datadog|sentry|amazon-adsystem|adsrvr|adform|"
    r"yieldlove|moatads|adsystem|adserver|liveramp|bluekai|"
    r"krxd|demdex|agkn|tapad|exelator|utiq"
    r")",
    re.IGNORECASE,
)

# Multi-label public suffixes we care about (compact list; full PSL is overkill
# for a LAN privacy tool). Extend as needed.
_MULTI_TLD = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "com.br",
    "co.nz", "co.za", "com.cn", "com.tr",
}

# Learned-trackers list (written by autolearn in plan 2). Each non-comment line
# is a host; lines may carry a trailing reason tag we ignore here.
LEARNED_PATH = "/var/lib/secubox/toolbox/learned-trackers.txt"
# Hosts confirmed beacon-only (safe to hard-block). Written by autolearn (plan
# 2); absent for now → empty set, so everything fails safe to loadbearing.
PURE_PATH = "/var/lib/secubox/toolbox/pure-trackers.txt"

_lists_cache: dict = {"learned": set(), "pure": set(), "mtime": (0.0, 0.0)}


def registrable(host: str) -> str:
    """Best-effort registrable (eTLD+1) domain. Compact multi-TLD table."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD:
        return ".".join(parts[-3:])
    return last2


def _load_lists() -> None:
    def _mtime(p: str) -> float:
        try:
            return Path(p).stat().st_mtime
        except OSError:
            return 0.0

    lm, pm = _mtime(LEARNED_PATH), _mtime(PURE_PATH)
    if (lm, pm) == _lists_cache["mtime"]:
        return

    def _read(p: str) -> set:
        out = set()
        try:
            for line in Path(p).read_text(encoding="utf-8").splitlines():
                tok = line.strip().split()
                if tok and not tok[0].startswith("#"):
                    out.add(tok[0].lower())
        except OSError:
            pass
        return out

    _lists_cache["learned"] = _read(LEARNED_PATH)
    _lists_cache["pure"] = _read(PURE_PATH)
    _lists_cache["mtime"] = (lm, pm)


def is_tracker(host: str) -> bool:
    if not host:
        return False
    if _TRACKER.search(host):
        return True
    _load_lists()
    h = host.lower()
    return h in _lists_cache["learned"] or registrable(h) in _lists_cache["learned"]


def classify(host: str, beacon_hint: bool = False) -> str:
    """Return 'none' | 'pure' | 'loadbearing'.

    Fail-safe: a tracker we have NOT confirmed beacon-only is 'loadbearing'
    (poison, never block) so we never break a page.
    """
    if not is_tracker(host):
        return "none"
    _load_lists()
    h = host.lower()
    confirmed_pure = h in _lists_cache["pure"] or registrable(h) in _lists_cache["pure"]
    if confirmed_pure or beacon_hint:
        return "pure"
    return "loadbearing"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/privacy.py packages/secubox-toolbox/tests/test_privacy.py
git commit -m "feat(toolbox): privacy brain — registrable + tracker classification (ref #633)"
```

---

### Task 2: `privacy.py` — stable fake-identity jar

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/privacy.py`
- Test: `packages/secubox-toolbox/tests/test_privacy.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_privacy.py
import importlib


def test_fake_id_deterministic(tmp_path, monkeypatch):
    key = tmp_path / "privacy-jar.key"
    key.write_text("0123456789abcdef0123456789abcdef")
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None  # reset cache
    a = privacy.fake_id("clientHASH1", "criteo.com", "_ga")
    b = privacy.fake_id("clientHASH1", "criteo.com", "_ga")
    assert a == b and a is not None


def test_fake_id_differs_per_client(tmp_path, monkeypatch):
    key = tmp_path / "privacy-jar.key"
    key.write_text("0123456789abcdef0123456789abcdef")
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None
    a = privacy.fake_id("clientHASH1", "criteo.com", "_ga")
    b = privacy.fake_id("clientHASH2", "criteo.com", "_ga")
    assert a != b


def test_fake_id_format_shaping_ga(tmp_path, monkeypatch):
    key = tmp_path / "privacy-jar.key"
    key.write_text("k" * 32)
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None
    val = privacy.fake_id("c", "google-analytics.com", "_ga")
    assert re.match(r"^GA1\.2\.\d+\.\d+$", val), val


def test_fake_id_missing_key_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(tmp_path / "nope.key"))
    privacy._jar_key_cache["v"] = None
    assert privacy.fake_id("c", "criteo.com", "_ga") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.privacy' has no attribute 'fake_id'`

- [ ] **Step 3: Write minimal implementation**

```python
# add near the top imports of privacy.py
import hashlib
import hmac

# add after the lists section
JAR_KEY_PATH = "/etc/secubox/secrets/privacy-jar.key"
_jar_key_cache: dict = {"v": None}


def _jar_key() -> Optional[bytes]:
    if _jar_key_cache["v"] is None:
        try:
            raw = Path(JAR_KEY_PATH).read_bytes().strip()
            _jar_key_cache["v"] = raw or b""
        except OSError:
            _jar_key_cache["v"] = b""
    return _jar_key_cache["v"] or None


def _shape(name: str, digest: bytes) -> str:
    """Render the HMAC digest into the cookie's observed format so the target
    accepts it. Unknown names → opaque hex token."""
    n = (name or "").lower()
    i = int.from_bytes(digest[:8], "big")
    j = int.from_bytes(digest[8:16], "big")
    if n == "_ga" or n.startswith("_ga"):
        return "GA1.2.%d.%d" % (i % 10_000_000_000, j % 10_000_000_000)
    if n in ("_fbp",):
        return "fb.1.%d.%d" % (i % 10_000_000_000_000, j % 10_000_000_000)
    if n in ("uuid", "uid", "_pk_id") or len(name) >= 32:
        h = digest.hex()
        return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])
    return digest.hex()[:32]


def fake_id(client_hash: str, tracker: str, cookie_name: str) -> Optional[str]:
    """Stable fabricated cookie value for (client, tracker, cookie_name).

    Deterministic HMAC of stable inputs → identical across workers and restarts
    ('rémanent'), never derived from real client data. None if the seed key is
    unavailable (caller falls back to anonymize-drop)."""
    key = _jar_key()
    if not key or not client_hash or not tracker:
        return None
    msg = ("%s|%s|%s" % (client_hash, registrable(tracker), cookie_name)).encode()
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return _shape(cookie_name, digest)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: PASS (9 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/privacy.py packages/secubox-toolbox/tests/test_privacy.py
git commit -m "feat(toolbox): privacy brain — deterministic fake-identity jar (ref #633)"
```

---

### Task 3: `privacy.py` — layered `verdict()` + Fort-Knox

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/privacy.py`
- Test: `packages/secubox-toolbox/tests/test_privacy.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_privacy.py
def test_verdict_first_party_allows():
    v = privacy.verdict(host="api.example.com", site="example.com",
                        beacon_hint=False, fortknox=False)
    assert v == "allow"


def test_verdict_fortknox_blocks_third_party():
    v = privacy.verdict(host="cdn.other.com", site="example.com",
                        beacon_hint=False, fortknox=True)
    assert v == "block"


def test_verdict_fortknox_allows_first_party():
    v = privacy.verdict(host="static.example.com", site="example.com",
                        beacon_hint=False, fortknox=True)
    assert v == "allow"


def test_verdict_pure_tracker_blocks():
    v = privacy.verdict(host="google-analytics.com", site="example.com",
                        beacon_hint=True, fortknox=False)
    assert v == "block"


def test_verdict_loadbearing_tracker_poisons():
    v = privacy.verdict(host="criteo.com", site="example.com",
                        beacon_hint=False, fortknox=False)
    assert v == "poison"


def test_verdict_non_tracker_allows():
    v = privacy.verdict(host="fonts.googleapis.com", site="example.com",
                        beacon_hint=False, fortknox=False)
    assert v == "allow"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.privacy' has no attribute 'verdict'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to privacy.py
def same_site(host: str, site: str) -> bool:
    return bool(site) and registrable(host) == registrable(site)


def verdict(host: str, site: str, beacon_hint: bool = False,
            fortknox: bool = False) -> str:
    """Layered per-request decision. First match wins.

    Returns 'allow' | 'block' | 'poison'.  ('anonymize' is applied to ALL
    non-blocked flows separately by the addon, not a verdict branch.)
    """
    # 1. Fort Knox armed for this site → first-party only
    if fortknox:
        return "allow" if same_site(host, site) else "block"
    # 2. tracker classification
    kind = classify(host, beacon_hint=beacon_hint)
    if kind == "none":
        return "allow"
    if kind == "pure":
        return "block"
    return "poison"  # loadbearing
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: PASS (15 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/privacy.py packages/secubox-toolbox/tests/test_privacy.py
git commit -m "feat(toolbox): privacy brain — layered verdict + Fort-Knox (ref #633)"
```

---

### Task 4: `filters.py` — Anti-Track toggles

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/filters.py:19-33` (DEFAULTS) and `:66-89` (set_filters)
- Test: `packages/secubox-toolbox/tests/test_privacy_filters.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_privacy_filters.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from secubox_toolbox import filters


def test_privacy_defaults_safe(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    f = filters.get_filters(force=True)
    assert f["privacy_enforce"] is False     # ships dark
    assert f["privacy_poison"] is True
    assert f["privacy_anonymize"] is True
    assert f["privacy_ip_drop"] is False
    assert f["privacy_dns_feed"] is True
    assert f["fortknox_sites"] == []


def test_set_privacy_toggles(monkeypatch, tmp_path):
    p = tmp_path / "f.json"
    monkeypatch.setattr(filters, "FILTERS_PATH", str(p))
    filters.set_filters({"privacy_enforce": True,
                         "fortknox_sites": ["bank.example.com"]})
    saved = json.loads(p.read_text())
    assert saved["privacy_enforce"] is True
    assert saved["fortknox_sites"] == ["bank.example.com"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy_filters.py -q`
Expected: FAIL — `KeyError: 'privacy_enforce'`

- [ ] **Step 3: Write minimal implementation**

In `filters.py`, add to the `DEFAULTS` dict (after the `autolearn` line, before `ad_ghost_categories`):

```python
    "autolearn": True,              # #589 also block auto-learned bad hosts
    # ── Anti-Track v2 (#633) — ships dark; arm after observe-only soak ──
    "privacy_enforce": False,       # master switch; off = observe-only
    "privacy_poison": True,         # forge stable fake id for loadbearing trackers
    "privacy_anonymize": True,      # always-on header hygiene (DNT/GPC, strip op-hdrs)
    "privacy_ip_drop": False,       # nft-drop exclusive-tracker IPs (plan 2)
    "privacy_dns_feed": True,       # feed learned blacklist into dns-guard (plan 2)
    "fortknox_sites": [],           # per-site first-party-only opt-in
    "ad_ghost_categories": {        # cosmetic ghost groups
```

In `set_filters`, extend the accepted-keys logic. Replace the `elif k in ("banner", ...)` branch with:

```python
        elif k == "fortknox_sites" and isinstance(v, list):
            cur["fortknox_sites"] = [str(s).strip().lower() for s in v if str(s).strip()]
        elif k in ("banner", "ad_ghost", "ad_ghost_block", "media_cache", "autolearn",
                   "privacy_enforce", "privacy_poison", "privacy_anonymize",
                   "privacy_ip_drop", "privacy_dns_feed"):
            cur[k] = bool(v)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy_filters.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/filters.py packages/secubox-toolbox/tests/test_privacy_filters.py
git commit -m "feat(toolbox): Anti-Track filter toggles (privacy_*/fortknox), ship dark (ref #633)"
```

---

### Task 5: `privacy_guard.py` — hot-path addon

**Files:**
- Create: `packages/secubox-toolbox/mitmproxy_addons/privacy_guard.py`
- Test: `packages/secubox-toolbox/tests/test_privacy_guard.py`

The addon: reads filter toggles; resolves client identity via `_common.mac_hash_of`;
computes a `beacon_hint` (request has no `Accept: text/html` and path looks like a
collector); calls `privacy.verdict`; applies the action. `privacy_enforce=false` →
observe-only (count, never act). Always fail to `allow`+anonymize on any exception.

- [ ] **Step 1: Write the failing test** (uses mitmproxy's test flow factory)

```python
# packages/secubox-toolbox/tests/test_privacy_guard.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib
import pytest

# addons import 'from secubox_toolbox...' and sibling '_common'
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))

from mitmproxy.test import tflow, taddons   # noqa: E402
from secubox_toolbox import privacy, filters  # noqa: E402


def _mk_addon(monkeypatch, tmp_path, **toggles):
    # isolate filters + jar key
    fp = tmp_path / "filters.json"
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp))
    base = {"privacy_enforce": True, "privacy_poison": True,
            "privacy_anonymize": True, "fortknox_sites": []}
    base.update(toggles)
    fp.write_text(__import__("json").dumps(base))
    filters.get_filters(force=True)
    key = tmp_path / "jar.key"; key.write_text("k" * 32)
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None
    import privacy_guard
    importlib.reload(privacy_guard)
    # make client identity deterministic
    monkeypatch.setattr(privacy_guard, "_client_hash", lambda flow: "clientHASH")
    return privacy_guard.PrivacyGuard()


def test_pure_tracker_blocked_with_204(monkeypatch, tmp_path):
    addon = _mk_addon(monkeypatch, tmp_path)
    f = tflow.tflow()
    f.request.host = "google-analytics.com"
    f.request.path = "/collect?v=2"
    f.request.headers["accept"] = "*/*"          # beacon hint
    addon.request(f)
    assert f.response is not None and f.response.status_code == 204


def test_loadbearing_tracker_cookie_forged_not_dropped(monkeypatch, tmp_path):
    addon = _mk_addon(monkeypatch, tmp_path)
    f = tflow.tflow()
    f.request.host = "criteo.com"
    f.request.path = "/js/loader.js"
    f.request.headers["accept"] = "text/html"
    f.request.headers["cookie"] = "_ga=GA1.2.111.222"
    addon.requestheaders(f)
    assert f.response is None                      # not blocked
    assert "cookie" in f.request.headers           # forged, not dropped
    assert f.request.headers["cookie"] != "_ga=GA1.2.111.222"
    assert "DNT" in f.request.headers


def test_observe_only_does_not_act(monkeypatch, tmp_path):
    addon = _mk_addon(monkeypatch, tmp_path, privacy_enforce=False)
    f = tflow.tflow()
    f.request.host = "google-analytics.com"
    f.request.path = "/collect"
    f.request.headers["accept"] = "*/*"
    addon.request(f)
    assert f.response is None                       # observe-only: never blocks
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy_guard.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'privacy_guard'`

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-toolbox/mitmproxy_addons/privacy_guard.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: Anti-Track v2 hot-path addon (#633)

Applies privacy.verdict() per request: allow | block(204) | poison, plus
always-on anonymize. Thin by design — no classification or state math here.
Doctrine: DEFAULT OFF (privacy_enforce=false → observe-only), LOGGED, fail-safe
(any error → allow + anonymize, never 500 the client's page).
"""
from __future__ import annotations

import logging
import os
import sys
import time

from mitmproxy import http

if "/usr/lib/secubox/toolbox" not in sys.path:
    sys.path.insert(0, "/usr/lib/secubox/toolbox")
from secubox_toolbox import privacy            # noqa: E402
from secubox_toolbox.filters import get_filters  # noqa: E402
from _common import mac_hash_of                 # noqa: E402

log = logging.getLogger("secubox.toolbox.privacy_guard")
_AUDIT = "/var/log/secubox/audit.log"
_STATS = "/run/secubox/privacy.json"

# operator/carrier + re-identification headers stripped on every flow (anonymize)
_STRIP = (
    "msisdn", "x-msisdn", "x-up-calling-line-id", "x-up-subno",
    "x-nokia-msisdn", "x-acr", "x-vf-acr", "x-amobee-1", "x-amobee-2",
    "tm-user-id", "x-wap-profile", "x-wap-msisdn", "x-network-info",
    "x-forwarded-for", "forwarded", "x-real-ip", "via",
)
_BEACON_PATHS = ("/collect", "/pixel", "/track", "/beacon", "/b/ss", "/p.gif",
                 "/__utm.gif", "/ga", "/g/collect", "/tr")
_counts = {"blocks": 0, "poisons": 0, "anonymized": 0, "observed": 0,
           "since": int(time.time())}
_last_flush = 0.0


def _client_hash(flow: http.HTTPFlow):
    try:
        return mac_hash_of(flow.client_conn.peername[0])
    except Exception:
        return None


def _beacon_hint(flow: http.HTTPFlow) -> bool:
    accept = (flow.request.headers.get("accept") or "").lower()
    path = (flow.request.path or "").lower()
    if "text/html" in accept:
        return False
    return any(p in path for p in _BEACON_PATHS) or accept in ("*/*", "")


def _site_of(flow: http.HTTPFlow) -> str:
    # the first-party page is the Referer host if present, else the request host
    ref = flow.request.headers.get("referer") or ""
    if ref:
        try:
            from urllib.parse import urlparse
            return urlparse(ref).hostname or flow.request.pretty_host or ""
        except Exception:
            pass
    return flow.request.pretty_host or ""


def _audit(action: str, host: str, detail: str) -> None:
    try:
        with open(_AUDIT, "a", encoding="utf-8") as f:
            f.write("%s privacy %s host=%s %s\n" % (
                time.strftime("%Y-%m-%dT%H:%M:%S%z"), action, host, detail))
    except Exception:
        pass


def _flush(force: bool = False) -> None:
    global _last_flush
    now = time.time()
    if not force and (now - _last_flush) < 5:
        return
    _last_flush = now
    try:
        import json
        os.makedirs(os.path.dirname(_STATS), exist_ok=True)
        with open(_STATS, "w", encoding="utf-8") as f:
            json.dump({**_counts, "updated": int(now)}, f)
    except Exception:
        pass


def _anonymize(flow: http.HTTPFlow) -> None:
    for h in _STRIP:
        if h in flow.request.headers:
            del flow.request.headers[h]
    flow.request.headers["DNT"] = "1"
    flow.request.headers["Sec-GPC"] = "1"


class PrivacyGuard:
    """Apply the layered Anti-Track verdict in the hot path."""

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        try:
            f = get_filters()
            if not f.get("privacy_enforce"):
                # observe-only: count if it's a tracker, never act
                if privacy.is_tracker(flow.request.pretty_host or ""):
                    _counts["observed"] += 1
                    _flush()
                return

            host = flow.request.pretty_host or ""
            site = _site_of(flow)
            fortknox = privacy.registrable(site) in set(f.get("fortknox_sites") or [])
            v = privacy.verdict(host, site, beacon_hint=_beacon_hint(flow),
                                fortknox=fortknox)

            if v == "block":
                flow.response = http.Response.make(204, b"", {})
                _counts["blocks"] += 1
                _audit("block", host, "path=%s" % (flow.request.path or "")[:80])
            elif v == "poison" and f.get("privacy_poison"):
                self._poison(flow, host)
            # poison without privacy_poison, or 'allow' → fall through to anonymize

            if v != "block" and f.get("privacy_anonymize"):
                _anonymize(flow)
                _counts["anonymized"] += 1
            _flush()
        except Exception as e:                      # fail-safe: never break a page
            log.debug("privacy_guard requestheaders error: %s", e)
            try:
                _anonymize(flow)
            except Exception:
                pass

    def _poison(self, flow: http.HTTPFlow, host: str) -> None:
        ch = _client_hash(flow)
        cookie = flow.request.headers.get("cookie")
        if not ch or not cookie:
            # no identity or nothing to forge → fall back to drop (anonymize)
            if cookie:
                del flow.request.headers["cookie"]
            return
        forged = []
        for part in cookie.split(";"):
            if "=" not in part:
                forged.append(part)
                continue
            name, _, _val = part.strip().partition("=")
            fake = privacy.fake_id(ch, host, name)
            forged.append("%s=%s" % (name, fake) if fake else part.strip())
        flow.request.headers["cookie"] = "; ".join(p for p in forged if p)
        # degrade other vectors
        if "referer" in flow.request.headers:
            flow.request.headers["referer"] = "https://%s/" % (
                privacy.registrable(host) or host)
        _counts["poisons"] += 1
        _audit("poison", host, "cookies=%d" % len(forged))

    # convenience alias so tests / docs can call addon.request(flow)
    def request(self, flow: http.HTTPFlow) -> None:
        self.requestheaders(flow)


addons = [PrivacyGuard()]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy_guard.py -q`
Expected: PASS (3 passed). If mitmproxy is not installed in the dev venv, run
`pip install mitmproxy` first (it is a runtime dep of the package).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/mitmproxy_addons/privacy_guard.py packages/secubox-toolbox/tests/test_privacy_guard.py
git commit -m "feat(toolbox): privacy_guard hot-path addon (block/poison/anonymize) (ref #633)"
```

---

### Task 6: refactor `protective_mode.py` to share `privacy.is_tracker`

Keeps a single source of truth for tracker patterns (DRY). Behavior unchanged.

**Files:**
- Modify: `packages/secubox-toolbox/mitmproxy_addons/protective_mode.py:36-78`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_privacy.py
def test_protective_mode_uses_privacy_patterns():
    sys_path_dir = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "mitmproxy_addons")
    import sys; sys.path.insert(0, sys_path_dir)
    import protective_mode
    # protective_mode must delegate tracker detection to privacy (single source)
    assert protective_mode._is_tracker("connect.facebook.net") is True
    assert protective_mode._is_tracker("example.com") is False
    assert protective_mode.privacy.is_tracker is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py::test_protective_mode_uses_privacy_patterns -q`
Expected: FAIL — `AttributeError: module 'protective_mode' has no attribute 'privacy'`

- [ ] **Step 3: Write minimal implementation**

In `protective_mode.py`, after the existing `sys`/`re` imports add the shared brain and replace the local `_TRACKER`/`_is_tracker` with delegation:

```python
# at module import section
if "/usr/lib/secubox/toolbox" not in sys.path:
    sys.path.insert(0, "/usr/lib/secubox/toolbox")
from secubox_toolbox import privacy   # single source of tracker patterns (#633)
```

Delete the local `_TRACKER = re.compile(...)` block (lines ~37-50) and replace
`_is_tracker` (lines ~77-78) with:

```python
def _is_tracker(host: str) -> bool:
    return privacy.is_tracker(host or "")
```

Leave `_STRIP`, levels, audit, and the spoof body unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy.py -q`
Expected: PASS (16 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/mitmproxy_addons/protective_mode.py packages/secubox-toolbox/tests/test_privacy.py
git commit -m "refactor(toolbox): protective_mode delegates tracker detection to privacy brain (ref #633)"
```

---

### Task 7: Packaging — secret key provisioning + addon registration

**Files:**
- Modify: `packages/secubox-toolbox/debian/postinst` (add privacy-jar.key generation)
- Modify: `packages/secubox-toolbox/systemd/secubox-toolbox-mitm.service` (add `-s …/privacy_guard.py`)
- Modify: `packages/secubox-toolbox/debian/changelog` (version bump)

- [ ] **Step 1: Inspect the current postinst secret-handling**

Run: `cd packages/secubox-toolbox && grep -n "secrets\|toolbox-mac-salt\|install -d\|chown" debian/postinst | head -30`
Expected: shows how `/etc/secubox/secrets` and `toolbox-mac-salt` are created (mirror that pattern; do NOT alter shared-parent modes — `/etc/secubox` stays 0755, `secrets/` 0700).

- [ ] **Step 2: Add jar-key provisioning to postinst**

In `debian/postinst`, in the `configure` branch, after the existing
`toolbox-mac-salt` block, add (mirror the salt's owner/mode exactly):

```sh
# Anti-Track v2 (#633): deterministic fake-identity seed. 0600 secubox-toolbox.
JAR_KEY=/etc/secubox/secrets/privacy-jar.key
if [ ! -s "$JAR_KEY" ]; then
    install -d -m 0700 -o secubox-toolbox -g secubox-toolbox /etc/secubox/secrets
    umask 077
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$JAR_KEY"
    chmod 0600 "$JAR_KEY"
    chown secubox-toolbox:secubox-toolbox "$JAR_KEY" 2>/dev/null || true
fi
```

(If the package's daemon user differs from `secubox-toolbox`, match the
owner used by the existing `toolbox-mac-salt` block found in Step 1.)

- [ ] **Step 3: Register the addon in the mitm service**

In `systemd/secubox-toolbox-mitm.service`, append to the `ExecStart` addon list
(after the `protective_mode.py` line, keeping the trailing backslashes correct):

```
    -s /usr/lib/secubox/toolbox/mitmproxy_addons/protective_mode.py \
    -s /usr/lib/secubox/toolbox/mitmproxy_addons/privacy_guard.py \
    -s /usr/lib/secubox/toolbox/mitmproxy_addons/local_store.py
```

- [ ] **Step 4: Verify ordering — privacy_guard before local_store, after protective_mode**

Run: `cd packages/secubox-toolbox && grep -n "privacy_guard\|protective_mode\|local_store" systemd/secubox-toolbox-mitm.service`
Expected: `protective_mode` → `privacy_guard` → `local_store` in that order.

- [ ] **Step 5: Bump changelog + commit**

Add a `debian/changelog` entry (new version, e.g. `2.7.0`), then:

```bash
git add packages/secubox-toolbox/debian/postinst packages/secubox-toolbox/systemd/secubox-toolbox-mitm.service packages/secubox-toolbox/debian/changelog
git commit -m "feat(toolbox): provision privacy-jar.key + register privacy_guard addon (ref #633)"
```

---

### Task 8: Full suite + lint gate

- [ ] **Step 1: Run the whole toolbox test suite**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q`
Expected: all pass (existing `test_bundle.py` + the new privacy tests).

- [ ] **Step 2: Syntax-check the addon under the package layout**

Run: `cd packages/secubox-toolbox && python -c "import ast,sys; ast.parse(open('mitmproxy_addons/privacy_guard.py').read()); ast.parse(open('secubox_toolbox/privacy.py').read()); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Confirm SPDX headers present on new files**

Run: `cd packages/secubox-toolbox && head -1 secubox_toolbox/privacy.py mitmproxy_addons/privacy_guard.py`
Expected: both start with `# SPDX-License-Identifier: LicenseRef-CMSD-1.0`

- [ ] **Step 4: Commit any fixes**

```bash
git add -A && git commit -m "test(toolbox): Anti-Track v2 core suite green (ref #633)"
```

---

## Self-Review

**Spec coverage (this plan = HTTP-depth layer of the spec):**
- §3 verdict tree → Task 3 (verdict) + Task 5 (applied; Fort-Knox both). ✓
- §3 pure/load-bearing fail-safe → Task 1 `classify` (unknown→loadbearing). ✓
- §3 POISON forge-not-drop + signal degradation → Task 5 `_poison`. ✓
- §3 ANONYMIZE always-on → Task 5 `_anonymize`. ✓
- §3 protective_mode single source → Task 6. ✓
- §4 deterministic HMAC jar + format shaping + missing-key fallback → Task 2. ✓
- §6.1 filters toggles, ship dark → Task 4. ✓
- §6.3 fail-safe (allow+anonymize on error) → Task 5 except handler. ✓
- §4 secret 0600 / §7 addon registration → Task 7. ✓
- **Deferred to plan 2 (offline):** cookie-xsite blacklist signal, `pure-trackers.txt` population, exclusive-tracker-IP set, escalate nft-drop, dns-guard feed (§5), `privacy_ip_drop`/`privacy_dns_feed` enforcement. The toggles/loaders exist now; the producers come in plan 2.
- **Deferred to plan 3:** webui panel (§6.2).
- **Deferred (YAGNI for keystone):** `privacy_jar` SQLite exceptions table (§4) — deterministic path needs no storage; add when a server-assigned-id echo case appears.

**Placeholder scan:** none — every code step has complete code.

**Type consistency:** `verdict(host, site, beacon_hint, fortknox)` signature identical in Task 3 def and Task 5 call. `fake_id(client_hash, tracker, cookie_name)` identical in Task 2 and Task 5. `classify(host, beacon_hint)`, `is_tracker(host)`, `registrable(host)` consistent across Tasks 1/3/5/6. `JAR_KEY_PATH` / `_jar_key_cache["v"]` names match between Task 2 impl and tests.

**Rollout reminder:** deploy with `privacy_enforce=false`; verify `/run/secubox/privacy.json` `observed` counter climbs; review; then flip `privacy_enforce=true`. No mass daemon restart — only `secubox-toolbox-mitm.service` reload for the new addon.
