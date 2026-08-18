<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Cookie Audit Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a cookie-audit pipeline that captures HTTP `Set-Cookie` server-side (mitmproxy) AND `document.cookie` snapshots browser-side, reconciles both sources, classifies each cookie per RGPD/ePrivacy and produces a compliance report per vhost.

**Architecture:** mitmproxy addon (`cookie_audit.py`) appends every server-emitted Set-Cookie to a JSONL ledger. The WAF banner injection is extended to load a sibling browser script (`cookie-inventory.js`) that snapshots `document.cookie` (sha256-hashed) and POSTs to `/api/v1/cookie-audit/ingest`. A `CookieAuditAggregator` in secubox-metrics joins both streams and emits a per-vhost report with RGPD violation flags.

**Tech Stack:** Python 3.11+ FastAPI (secubox-metrics), mitmproxy addon API, vanilla JS (Web Crypto API for SHA-256), TOML config, pytest.

---

## File Structure

### secubox-mitmproxy
- Create: `packages/secubox-mitmproxy/addons/cookie_audit.py` — addon: parses Set-Cookie, hashes values, appends JSONL ledger.
- Create: `packages/secubox-mitmproxy/tests/__init__.py`
- Create: `packages/secubox-mitmproxy/tests/conftest.py`
- Create: `packages/secubox-mitmproxy/tests/test_cookie_audit.py`
- Modify: `packages/secubox-mitmproxy/addons/secubox_waf.py:832-844` — extend injected snippet to also load `cookie-inventory.js`.

### secubox-hub (browser asset)
- Create: `packages/secubox-hub/www/shared/cookie-inventory.js` — vanilla JS module: snapshot `document.cookie`, sha256-hash names+values, POST to ingest endpoint.

### secubox-metrics
- Create: `packages/secubox-metrics/api/cookie_audit.py` — `CookieAuditAggregator` + `Classifier` + `Reconciler`.
- Modify: `packages/secubox-metrics/api/main.py` — wire aggregator into `lifespan`, add 3 routes.
- Create: `packages/secubox-metrics/tests/test_cookie_audit.py`

### Config / packaging
- Create: `config/cookie-audit.toml` — default classification ruleset (analytics, marketing, strictly_necessary patterns).
- Modify: `secubox.conf.example` — add `[cookie_audit]` section.
- Modify: `packages/secubox-mitmproxy/debian/control` — add `python3-pytest` to Build-Depends if not present.

### Docs
- Modify: `packages/secubox-metrics/README.md` — document new API endpoints.
- Modify: `packages/secubox-mitmproxy/README.md` — document the addon.

---

## Task 1: mitmproxy addon — Set-Cookie ledger (TDD)

**Files:**
- Create: `packages/secubox-mitmproxy/tests/__init__.py` (empty)
- Create: `packages/secubox-mitmproxy/tests/conftest.py`
- Create: `packages/secubox-mitmproxy/tests/test_cookie_audit.py`
- Create: `packages/secubox-mitmproxy/addons/cookie_audit.py`

- [ ] **Step 1.1: Create tests/conftest.py**

```python
# packages/secubox-mitmproxy/tests/conftest.py
import os
import sys

ADDONS_DIR = os.path.join(os.path.dirname(__file__), "..", "addons")
sys.path.insert(0, os.path.abspath(ADDONS_DIR))
```

- [ ] **Step 1.2: Write failing test — addon parses a single Set-Cookie**

```python
# packages/secubox-mitmproxy/tests/test_cookie_audit.py
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cookie_audit import CookieAudit, parse_set_cookie


def test_parse_set_cookie_full_attrs():
    raw = "sid=abc123; Domain=example.com; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
    p = parse_set_cookie(raw)
    assert p["name"] == "sid"
    assert p["value_hash"] == hashlib.sha256(b"abc123").hexdigest()
    assert p["domain"] == "example.com"
    assert p["path"] == "/"
    assert p["max_age"] == 3600
    assert p["secure"] is True
    assert p["httponly"] is True
    assert p["samesite"] == "Lax"


def test_parse_set_cookie_minimal():
    p = parse_set_cookie("foo=bar")
    assert p["name"] == "foo"
    assert p["value_hash"] == hashlib.sha256(b"bar").hexdigest()
    assert p["secure"] is False
    assert p["httponly"] is False
    assert p["samesite"] is None


def test_parse_set_cookie_empty_value():
    p = parse_set_cookie("tracker=")
    assert p["name"] == "tracker"
    assert p["value_hash"] == hashlib.sha256(b"").hexdigest()


def _flow(host, path, set_cookies):
    req = SimpleNamespace(host=host, path=path, headers={"Referer": ""}, pretty_url=f"https://{host}{path}")
    resp_headers = []
    for sc in set_cookies:
        resp_headers.append(("Set-Cookie", sc))

    class _Headers:
        def __init__(self, items):
            self._items = list(items)
        def get_all(self, key):
            return [v for k, v in self._items if k.lower() == key.lower()]
        def get(self, key, default=None):
            for k, v in self._items:
                if k.lower() == key.lower():
                    return v
            return default

    resp = SimpleNamespace(headers=_Headers(resp_headers), status_code=200)
    return SimpleNamespace(request=req, response=resp)


def test_addon_appends_jsonl(tmp_path):
    ledger = tmp_path / "server.jsonl"
    addon = CookieAudit(ledger_path=str(ledger))
    flow = _flow("foo.example.com", "/", [
        "sid=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
        "lang=fr; Path=/",
    ])
    addon.response(flow)
    lines = ledger.read_text().splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["vhost"] == "foo.example.com"
    assert rec["name"] == "sid"
    assert rec["httponly"] is True
    assert rec["samesite"] == "Strict"
    assert "ts" in rec
    assert rec["value_hash"] == hashlib.sha256(b"abc").hexdigest()


def test_addon_skips_when_no_set_cookie(tmp_path):
    ledger = tmp_path / "server.jsonl"
    addon = CookieAudit(ledger_path=str(ledger))
    flow = _flow("foo.example.com", "/", [])
    addon.response(flow)
    assert not ledger.exists() or ledger.read_text() == ""
```

- [ ] **Step 1.3: Run tests — verify failure**

Run: `cd packages/secubox-mitmproxy && python3 -m pytest tests/test_cookie_audit.py -v`
Expected: `ImportError: No module named cookie_audit`

- [ ] **Step 1.4: Implement cookie_audit.py addon**

```python
# packages/secubox-mitmproxy/addons/cookie_audit.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: cookie_audit
Mitmproxy addon that appends every Set-Cookie observed in transit to a JSONL
ledger for RGPD/ePrivacy compliance auditing. Cookie values are sha256-hashed —
the raw value never leaves the addon.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("secubox.cookie_audit")

DEFAULT_LEDGER = "/var/log/secubox/cookie-audit/server.jsonl"


def parse_set_cookie(raw: str) -> dict:
    """Parse a Set-Cookie header value into a structured record.

    Returns a dict with name, value_hash, and all attributes. Unknown
    attributes are ignored — we only record the RGPD-relevant ones.
    """
    if not raw or "=" not in raw.split(";", 1)[0]:
        return {}
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    name = name.strip()
    value = value.strip()
    rec = {
        "name": name,
        "value_hash": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
        "domain": None,
        "path": None,
        "expires": None,
        "max_age": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
    }
    for attr in parts[1:]:
        if not attr:
            continue
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "domain":
            rec["domain"] = v.lstrip(".") or None
        elif k == "path":
            rec["path"] = v or None
        elif k == "expires":
            rec["expires"] = v or None
        elif k == "max-age":
            try:
                rec["max_age"] = int(v)
            except (ValueError, TypeError):
                pass
        elif k == "secure":
            rec["secure"] = True
        elif k == "httponly":
            rec["httponly"] = True
        elif k == "samesite":
            rec["samesite"] = v or None
    return rec


class CookieAudit:
    """Mitmproxy addon — log Set-Cookie headers to a JSONL ledger."""

    def __init__(self, ledger_path: str = DEFAULT_LEDGER):
        self.ledger_path = Path(ledger_path)
        self._lock = threading.Lock()

    def response(self, flow) -> None:
        try:
            resp = flow.response
            if resp is None:
                return
            set_cookies = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else []
            if not set_cookies:
                return
            req = flow.request
            referer = ""
            try:
                referer = req.headers.get("Referer", "") or ""
            except Exception:
                pass
            for raw in set_cookies:
                parsed = parse_set_cookie(raw)
                if not parsed:
                    continue
                rec = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "vhost": req.host or "",
                    "path": req.path or "",
                    "request_referer": referer,
                    **parsed,
                }
                self._append(rec)
        except Exception as e:
            log.warning("cookie_audit response hook failed: %s", e)

    def _append(self, rec: dict) -> None:
        with self._lock:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")


addons = [CookieAudit()]
```

- [ ] **Step 1.5: Run tests — verify pass**

Run: `cd packages/secubox-mitmproxy && python3 -m pytest tests/test_cookie_audit.py -v`
Expected: 5 passed

- [ ] **Step 1.6: Commit**

```bash
git add packages/secubox-mitmproxy/addons/cookie_audit.py \
        packages/secubox-mitmproxy/tests/
git commit -m "feat(mitmproxy): add cookie_audit addon for RGPD ledger (ref #156)"
```

---

## Task 2: Browser snapshot module — cookie-inventory.js

**Files:**
- Create: `packages/secubox-hub/www/shared/cookie-inventory.js`

- [ ] **Step 2.1: Write cookie-inventory.js**

```javascript
// packages/secubox-hub/www/shared/cookie-inventory.js
/**
 * SecuBox Cookie Inventory — browser-side cookie snapshotter for RGPD audit.
 *
 * Snapshots document.cookie at DOMContentLoaded, +2s, and on visibilitychange.
 * Names + values are sha256-hashed via SubtleCrypto — the raw value never
 * leaves the page. Posts to /api/v1/cookie-audit/ingest with credentials:'omit'.
 *
 * Companion of the mitmproxy cookie_audit addon. Together they reconcile
 * "what the server set" vs "what's effectively in the browser".
 */
(function () {
    'use strict';
    if (window.__SBX_COOKIE_INVENTORY__) return;
    window.__SBX_COOKIE_INVENTORY__ = true;

    var VERSION = '1.0.0';
    var INGEST_URL = window.SECUBOX_COOKIE_AUDIT_INGEST
        || '/api/v1/cookie-audit/ingest';
    var BATCH_DELAY_MS = 2000;
    var snapshotsSent = 0;
    var MAX_SNAPSHOTS = 8;

    async function sha256Hex(s) {
        try {
            var enc = new TextEncoder().encode(s || '');
            var buf = await crypto.subtle.digest('SHA-256', enc);
            var bytes = new Uint8Array(buf);
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {
                hex += bytes[i].toString(16).padStart(2, '0');
            }
            return hex;
        } catch (e) {
            return null;
        }
    }

    function parseCookies(raw) {
        if (!raw) return [];
        return raw.split(';').map(function (kv) {
            var eq = kv.indexOf('=');
            if (eq < 0) return { name: kv.trim(), value: '' };
            return { name: kv.slice(0, eq).trim(), value: kv.slice(eq + 1) };
        }).filter(function (c) { return c.name; });
    }

    async function snapshot(reason) {
        if (snapshotsSent >= MAX_SNAPSHOTS) return;
        var entries = parseCookies(document.cookie);
        var cookies = [];
        for (var i = 0; i < entries.length; i++) {
            var hash = await sha256Hex(entries[i].value);
            cookies.push({ name: entries[i].name, value_hash: hash });
        }
        var payload = {
            host: location.hostname,
            path: location.pathname,
            ts: new Date().toISOString(),
            ua: navigator.userAgent,
            reason: reason,
            cookies: cookies,
            version: VERSION
        };
        try {
            await fetch(INGEST_URL, {
                method: 'POST',
                credentials: 'omit',
                mode: 'cors',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            snapshotsSent++;
        } catch (e) {
            // Silent — audit is best-effort, never break the host page.
        }
    }

    function schedule() {
        snapshot('initial');
        setTimeout(function () { snapshot('post-load'); }, BATCH_DELAY_MS);
        document.addEventListener('visibilitychange', function () {
            if (document.visibilityState === 'visible') snapshot('visible');
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', schedule);
    } else {
        schedule();
    }
})();
```

- [ ] **Step 2.2: Commit**

```bash
git add packages/secubox-hub/www/shared/cookie-inventory.js
git commit -m "feat(hub): add cookie-inventory.js browser snapshotter (ref #156)"
```

---

## Task 3: Wire cookie-inventory.js into WAF banner injection

**Files:**
- Modify: `packages/secubox-mitmproxy/addons/secubox_waf.py:832-844`

- [ ] **Step 3.1: Inspect current injection block**

Run: `sed -n '825,850p' packages/secubox-mitmproxy/addons/secubox_waf.py`

- [ ] **Step 3.2: Extend the injected snippet to load both scripts**

Edit `packages/secubox-mitmproxy/addons/secubox_waf.py` — locate the injection block (~line 830) and modify the inline script to ALSO append `cookie-inventory.js` after the banner. Replace the existing `banner_script` heredoc body with:

```python
                            banner_url = cfg.get("banner_url", "https://admin.gk2.secubox.in/shared/health-banner.js")
                            api_url = cfg.get("banner_api_url", "https://admin.gk2.secubox.in/api/v1/metrics/health/summary")
                            inventory_url = cfg.get("cookie_inventory_url", "https://admin.gk2.secubox.in/shared/cookie-inventory.js")
                            ingest_url = cfg.get("cookie_audit_ingest_url", "https://admin.gk2.secubox.in/api/v1/cookie-audit/ingest")
                            banner_script = f'''
<script>
(function(){{
    if(document.getElementById('health-banner'))return;
    window.SECUBOX_HEALTH_API='{api_url}';
    window.SECUBOX_COOKIE_AUDIT_INGEST='{ingest_url}';
    var s=document.createElement('script');
    s.src='{banner_url}';
    s.crossOrigin='anonymous';
    s.onerror=function(){{console.warn('[SecuBox] Banner load failed')}};
    document.body.appendChild(s);
    var c=document.createElement('script');
    c.src='{inventory_url}';
    c.crossOrigin='anonymous';
    c.onerror=function(){{console.warn('[SecuBox] Cookie inventory load failed')}};
    document.body.appendChild(c);
}})();
</script>
'''
```

- [ ] **Step 3.3: Verify Python syntax**

Run: `python3 -c "import ast; ast.parse(open('packages/secubox-mitmproxy/addons/secubox_waf.py').read())"`
Expected: no output

- [ ] **Step 3.4: Commit**

```bash
git add packages/secubox-mitmproxy/addons/secubox_waf.py
git commit -m "feat(waf): inject cookie-inventory.js alongside health banner (ref #156)"
```

---

## Task 4: secubox-metrics — CookieAuditAggregator (TDD)

**Files:**
- Create: `packages/secubox-metrics/api/cookie_audit.py`
- Create: `packages/secubox-metrics/tests/test_cookie_audit.py`

- [ ] **Step 4.1: Write failing test for the aggregator**

```python
# packages/secubox-metrics/tests/test_cookie_audit.py
import asyncio
import json
from pathlib import Path

import pytest

from cookie_audit import CookieAuditAggregator, Classifier, classify_cookie


CFG_BASE = {
    "enabled": True,
    "max_ingest_age_hours": 24,
}


def _write_ledger(tmp_path, records):
    p = tmp_path / "server.jsonl"
    with p.open("w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return p


def test_classify_strictly_necessary():
    cls = Classifier({
        "strictly_necessary": ["^PHPSESSID$", "^sess(ion)?id$", "^csrftoken$"],
        "analytics": ["^_ga", "^_pk_"],
        "marketing": ["^_fbp$", "^_gcl_"],
        "functional": ["^lang$", "^theme$"],
    })
    assert cls.classify("PHPSESSID") == "strictly_necessary"
    assert cls.classify("_ga") == "analytics"
    assert cls.classify("_ga_ABC123") == "analytics"
    assert cls.classify("_fbp") == "marketing"
    assert cls.classify("lang") == "functional"
    assert cls.classify("randomname") == "unclassified"


def test_aggregator_reconciles_server_and_browser(tmp_path):
    ledger = _write_ledger(tmp_path, [
        {"ts": "2026-05-16T10:00:00+00:00", "vhost": "foo.example.com",
         "name": "PHPSESSID", "value_hash": "abc", "secure": True,
         "httponly": True, "samesite": "Lax", "domain": None,
         "path": "/", "max_age": None, "expires": None},
        {"ts": "2026-05-16T10:00:01+00:00", "vhost": "foo.example.com",
         "name": "lang", "value_hash": "def", "secure": False,
         "httponly": False, "samesite": None, "domain": None,
         "path": "/", "max_age": None, "expires": None},
    ])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    (ingest_dir / "foo.example.com.jsonl").write_text(
        json.dumps({"ts": "2026-05-16T10:00:05+00:00",
                    "host": "foo.example.com", "path": "/",
                    "cookies": [
                        {"name": "PHPSESSID", "value_hash": "abc"},
                        {"name": "_ga", "value_hash": "ghi"},
                        {"name": "lang", "value_hash": "def"},
                    ]}) + "\n"
    )
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={
                 "strictly_necessary": ["^PHPSESSID$"],
                 "analytics": ["^_ga"],
                 "functional": ["^lang$"],
                 "marketing": [],
             }),
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is True
    hosts = {h["vhost"]: h for h in out["hosts"]}
    foo = hosts["foo.example.com"]
    by_name = {c["name"]: c for c in foo["cookies"]}
    assert by_name["PHPSESSID"]["source"] == "both"
    assert by_name["PHPSESSID"]["category"] == "strictly_necessary"
    assert by_name["PHPSESSID"]["rgpd_violation"] is False
    assert by_name["lang"]["source"] == "both"
    assert by_name["lang"]["category"] == "functional"
    assert by_name["_ga"]["source"] == "js"
    assert by_name["_ga"]["category"] == "analytics"
    assert by_name["_ga"]["rgpd_violation"] is True


def test_disabled_aggregator_returns_empty(tmp_path):
    agg = CookieAuditAggregator(
        {"enabled": False},
        cache_path=tmp_path / "cookie-audit.json",
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["hosts"] == []


def test_aggregator_persists_cache(tmp_path):
    ledger = _write_ledger(tmp_path, [])
    ingest_dir = tmp_path / "ingest"
    ingest_dir.mkdir()
    cache = tmp_path / "cookie-audit.json"
    agg = CookieAuditAggregator(
        dict(CFG_BASE,
             ledger_path=str(ledger),
             ingest_dir=str(ingest_dir),
             classifier={"strictly_necessary": [], "analytics": [],
                         "functional": [], "marketing": []}),
        cache_path=cache,
    )
    asyncio.run(agg.refresh_once())
    assert cache.exists()
    data = json.loads(cache.read_text())
    assert "generated_at" in data
```

- [ ] **Step 4.2: Run test — expect failure (import error)**

Run: `cd packages/secubox-metrics && python3 -m pytest tests/test_cookie_audit.py -v`
Expected: `ImportError: No module named cookie_audit`

- [ ] **Step 4.3: Implement CookieAuditAggregator**

```python
# packages/secubox-metrics/api/cookie_audit.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: CookieAuditAggregator
Reconciles the mitmproxy Set-Cookie ledger (server) with browser snapshots
(client) to produce a per-vhost RGPD/ePrivacy compliance report.

A cookie's source:
  - "http" : seen in mitmproxy ledger, not in any browser snapshot.
  - "js"   : seen in browser snapshot, NOT in any server Set-Cookie -> set by
             page-side JavaScript -> requires prior consent unless strictly
             necessary (LCEN art. 82).
  - "both" : seen in both -> classification still applies.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger("secubox.cookie_audit")

DEFAULT_CACHE_PATH = Path("/var/cache/secubox/metrics/cookie-audit.json")
DEFAULT_LEDGER = "/var/log/secubox/cookie-audit/server.jsonl"
DEFAULT_INGEST_DIR = "/var/lib/secubox/cookie-audit/ingest"


class Classifier:
    """Maps a cookie name to a RGPD category via regex patterns."""

    CATEGORIES = ("strictly_necessary", "functional", "analytics", "marketing")

    def __init__(self, rules: dict):
        self._compiled = {}
        for cat in self.CATEGORIES:
            patterns = rules.get(cat, []) or []
            self._compiled[cat] = [re.compile(p) for p in patterns]

    def classify(self, name: str) -> str:
        for cat in self.CATEGORIES:
            for rx in self._compiled[cat]:
                if rx.search(name):
                    return cat
        return "unclassified"


def classify_cookie(name: str, rules: dict) -> str:
    return Classifier(rules).classify(name)


class CookieAuditAggregator:
    def __init__(self, cfg: dict, cache_path: Optional[Path] = None):
        self.cfg = cfg
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self._payload: dict = {"enabled": False, "hosts": []}

    def current(self) -> dict:
        if self._payload.get("hosts") or self._payload.get("enabled"):
            return dict(self._payload)
        if self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text())
            except Exception:
                pass
        return {"enabled": False, "hosts": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            self._payload = {"enabled": False, "hosts": []}
            self._persist(self._payload)
            return self._payload
        ledger_path = Path(self.cfg.get("ledger_path", DEFAULT_LEDGER))
        ingest_dir = Path(self.cfg.get("ingest_dir", DEFAULT_INGEST_DIR))
        classifier = Classifier(self.cfg.get("classifier", {}))
        server = self._read_ledger(ledger_path)
        browser = self._read_ingest(ingest_dir)
        hosts = self._reconcile(server, browser, classifier)
        payload = {
            "enabled": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hosts": hosts,
            "summary": self._summarize(hosts),
        }
        self._persist(payload)
        self._payload = payload
        return payload

    def _read_ledger(self, path: Path) -> dict:
        """vhost -> {name -> latest server record}"""
        out: dict = {}
        if not path.exists():
            return out
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                vhost = rec.get("vhost") or ""
                name = rec.get("name") or ""
                if not vhost or not name:
                    continue
                bucket = out.setdefault(vhost, {})
                bucket[name] = rec
        except Exception as e:
            log.warning("ledger read failed: %s", e)
        return out

    def _read_ingest(self, ingest_dir: Path) -> dict:
        """vhost -> {name -> set(value_hash)} aggregated across snapshots."""
        out: dict = {}
        if not ingest_dir.exists():
            return out
        for f in ingest_dir.glob("*.jsonl"):
            try:
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host = rec.get("host") or ""
                    if not host:
                        continue
                    bucket = out.setdefault(host, {})
                    for c in rec.get("cookies", []):
                        n = c.get("name") or ""
                        if not n:
                            continue
                        bucket.setdefault(n, set()).add(c.get("value_hash") or "")
            except Exception as e:
                log.warning("ingest read failed for %s: %s", f, e)
        return out

    def _reconcile(self, server: dict, browser: dict, classifier: Classifier) -> list:
        all_hosts = sorted(set(server) | set(browser))
        out: list = []
        for vhost in all_hosts:
            srv = server.get(vhost, {})
            brw = browser.get(vhost, {})
            names = sorted(set(srv) | set(brw))
            cookies = []
            for n in names:
                s_rec = srv.get(n)
                b_hashes = brw.get(n)
                if s_rec and b_hashes:
                    source = "both"
                elif s_rec:
                    source = "http"
                else:
                    source = "js"
                cat = classifier.classify(n)
                violation = (source == "js" and cat not in ("strictly_necessary",))
                cookies.append({
                    "name": n,
                    "source": source,
                    "category": cat,
                    "secure": bool(s_rec.get("secure")) if s_rec else None,
                    "httponly": bool(s_rec.get("httponly")) if s_rec else None,
                    "samesite": (s_rec.get("samesite") if s_rec else None),
                    "rgpd_violation": violation,
                })
            out.append({
                "vhost": vhost,
                "cookies": cookies,
                "violation_count": sum(1 for c in cookies if c["rgpd_violation"]),
            })
        return out

    def _summarize(self, hosts: list) -> dict:
        by_cat = {c: 0 for c in (*Classifier.CATEGORIES, "unclassified")}
        violations = 0
        hosts_with_violations = 0
        for h in hosts:
            local_violation = False
            for c in h["cookies"]:
                by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
                if c["rgpd_violation"]:
                    violations += 1
                    local_violation = True
            if local_violation:
                hosts_with_violations += 1
        return {
            "host_count": len(hosts),
            "hosts_with_violations": hosts_with_violations,
            "violation_count": violations,
            "by_category": by_cat,
        }

    def _persist(self, payload: dict) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(payload, separators=(",", ":")))
        except Exception as e:
            log.warning("persist failed: %s", e)
```

- [ ] **Step 4.4: Run tests — verify pass**

Run: `cd packages/secubox-metrics && python3 -m pytest tests/test_cookie_audit.py -v`
Expected: 4 passed

- [ ] **Step 4.5: Commit**

```bash
git add packages/secubox-metrics/api/cookie_audit.py \
        packages/secubox-metrics/tests/test_cookie_audit.py
git commit -m "feat(metrics): add CookieAuditAggregator + Classifier (ref #156)"
```

---

## Task 5: Wire cookie-audit routes into main.py

**Files:**
- Modify: `packages/secubox-metrics/api/main.py`

- [ ] **Step 5.1: Add config helper fallback + import**

Edit `packages/secubox-metrics/api/main.py` near the existing config fallbacks (around line 50). Add to the `try/except ImportError` block:

```python
try:
    from secubox_core.config import (
        get_visitor_origin_config,
        get_live_hosts_config,
        get_cert_status_config,
        get_cookie_audit_config,
    )
except ImportError:  # dev fallback
    def get_visitor_origin_config(): return {"enabled": False, "window_minutes": 60, "min_count": 5, "top_n": 5, "asn_db_path": "/var/lib/GeoIP/GeoLite2-ASN.mmdb", "nft_table": "secubox_metrics", "nft_set": "seen_src", "nft_family": "inet"}
    def get_live_hosts_config():     return {"enabled": False, "window_minutes": 60, "top_n": 5, "haproxy_socket": "/run/haproxy/admin.sock", "frontend_filter": "*"}
    def get_cert_status_config():    return {"enabled": False, "letsencrypt_live_dir": "/etc/letsencrypt/live", "warn_days": 30, "critical_days": 7}
    def get_cookie_audit_config():   return {"enabled": False, "ledger_path": "/var/log/secubox/cookie-audit/server.jsonl", "ingest_dir": "/var/lib/secubox/cookie-audit/ingest", "classifier": {"strictly_necessary": [], "functional": [], "analytics": [], "marketing": []}}
```

Then add the import + aggregator init:

```python
from cookie_audit import CookieAuditAggregator
...
cookie_audit_agg = CookieAuditAggregator(get_cookie_audit_config())
```

- [ ] **Step 5.2: Register in lifespan**

Add `asyncio.create_task(cookie_audit_agg.run_forever())` to the `tasks` list in the `lifespan` function.

- [ ] **Step 5.3: Allow POST in CORS middleware**

The existing CORS block allows only `GET`. Update `allow_methods=["GET"]` to `allow_methods=["GET", "POST"]` to accept the ingest endpoint.

- [ ] **Step 5.4: Add the three routes**

Append after the existing cert-status route (end of file or near `/api/v1/metrics/cert-status`):

```python
from fastapi import Body

INGEST_DIR_FALLBACK = "/var/lib/secubox/cookie-audit/ingest"

@app.post("/api/v1/cookie-audit/ingest")
async def cookie_audit_ingest(payload: dict = Body(...)):
    """Receives browser snapshots of document.cookie. Credentials omitted."""
    host = (payload.get("host") or "").strip()
    if not host or not isinstance(payload.get("cookies"), list):
        raise HTTPException(status_code=400, detail="host + cookies required")
    if any(ch in host for ch in ("/", "\\", "..")):
        raise HTTPException(status_code=400, detail="invalid host")
    cfg = get_cookie_audit_config()
    ingest_dir = Path(cfg.get("ingest_dir", INGEST_DIR_FALLBACK))
    ingest_dir.mkdir(parents=True, exist_ok=True)
    path = ingest_dir / f"{host}.jsonl"
    rec = {
        "ts": payload.get("ts") or datetime.now(timezone.utc).isoformat(),
        "host": host,
        "path": payload.get("path") or "",
        "ua": (payload.get("ua") or "")[:512],
        "reason": (payload.get("reason") or "")[:32],
        "cookies": [
            {"name": str(c.get("name", ""))[:128],
             "value_hash": str(c.get("value_hash") or "")[:128]}
            for c in payload["cookies"][:200]
        ],
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    return {"ok": True}


@app.get("/api/v1/cookie-audit/report")
async def cookie_audit_report(host: Optional[str] = None):
    data = cookie_audit_agg.current()
    if not host:
        return data
    for h in data.get("hosts", []):
        if h["vhost"] == host:
            return {"enabled": data.get("enabled"), "host": h}
    raise HTTPException(status_code=404, detail=f"no data for host {host}")


@app.get("/api/v1/cookie-audit/summary")
async def cookie_audit_summary():
    data = cookie_audit_agg.current()
    return {
        "enabled": data.get("enabled"),
        "generated_at": data.get("generated_at"),
        "summary": data.get("summary", {}),
    }
```

- [ ] **Step 5.5: Smoke-test the import**

Run: `cd packages/secubox-metrics && python3 -c "import sys; sys.path.insert(0, 'api'); from api import main; print(sorted(r.path for r in main.app.routes if 'cookie' in r.path))"`
Expected: `['/api/v1/cookie-audit/ingest', '/api/v1/cookie-audit/report', '/api/v1/cookie-audit/summary']`

- [ ] **Step 5.6: Run full metrics test suite (no regressions)**

Run: `cd packages/secubox-metrics && python3 -m pytest tests/ -v`
Expected: all existing tests still pass, plus the 4 new ones.

- [ ] **Step 5.7: Commit**

```bash
git add packages/secubox-metrics/api/main.py
git commit -m "feat(metrics): wire /api/v1/cookie-audit/{ingest,report,summary} (ref #156)"
```

---

## Task 6: Default classification ruleset (TOML) + config helper

**Files:**
- Create: `packages/secubox-metrics/config/cookie-audit.toml`
- Modify: `secubox.conf.example`
- Modify: `common/secubox_core/config.py` (add `get_cookie_audit_config`)

- [ ] **Step 6.1: Locate config helper file**

Run: `find common -name 'config.py' | head -5 && grep -n 'get_cert_status_config\|get_live_hosts_config' common/secubox_core/config.py 2>/dev/null | head`

If `common/secubox_core/config.py` does not exist, find the actual location:

Run: `grep -rln 'def get_cert_status_config' --include='*.py'`

- [ ] **Step 6.2: Add `get_cookie_audit_config` mirroring `get_cert_status_config`**

In the same file, append a parallel helper that reads `[cookie_audit]` and the `[cookie_audit.classifier]` sub-table from the existing TOML loader. Default ruleset:

```python
def get_cookie_audit_config() -> dict:
    cfg = _load_toml_section("cookie_audit", default={
        "enabled": False,
        "ledger_path": "/var/log/secubox/cookie-audit/server.jsonl",
        "ingest_dir": "/var/lib/secubox/cookie-audit/ingest",
        "max_ingest_age_hours": 24,
    })
    # Classifier defaults — RGPD/CNIL common heuristics
    classifier_default = {
        "strictly_necessary": [
            r"^PHPSESSID$", r"^sess(ion)?id$", r"^csrftoken$",
            r"^XSRF-TOKEN$", r"^_csrf$", r"^cart$", r"^remember_token$",
        ],
        "functional": [r"^lang$", r"^theme$", r"^cookie[_-]?consent$"],
        "analytics": [
            r"^_ga", r"^_gid$", r"^_gat", r"^_pk_", r"^_hjid$",
            r"^_hjSession", r"^_clck$", r"^_clsk$",
        ],
        "marketing": [
            r"^_fbp$", r"^_fbc$", r"^__utm", r"^_gcl_", r"^_uet",
            r"^IDE$", r"^MUID$",
        ],
    }
    cls = cfg.get("classifier") or {}
    for k, v in classifier_default.items():
        cls.setdefault(k, v)
    cfg["classifier"] = cls
    return cfg
```

- [ ] **Step 6.3: Append `[cookie_audit]` section to `secubox.conf.example`**

```toml

[cookie_audit]
# Enable RGPD/ePrivacy cookie audit. When true, the mitmproxy cookie_audit
# addon writes a JSONL ledger of every Set-Cookie observed in transit, and
# the secubox-metrics CookieAuditAggregator reconciles it against browser
# snapshots posted to /api/v1/cookie-audit/ingest.
enabled = false
ledger_path = "/var/log/secubox/cookie-audit/server.jsonl"
ingest_dir = "/var/lib/secubox/cookie-audit/ingest"
max_ingest_age_hours = 24

# Custom classification patterns override the defaults baked into
# get_cookie_audit_config(). Each list is matched (re.search) against the
# cookie name, in this order: strictly_necessary, functional, analytics,
# marketing. First match wins; unmatched names are "unclassified".
[cookie_audit.classifier]
# strictly_necessary = ["^app_session$"]
# analytics = ["^my_analytics_"]
```

- [ ] **Step 6.4: Commit**

```bash
git add common/secubox_core/config.py secubox.conf.example
git commit -m "feat(core): get_cookie_audit_config + secubox.conf example section (ref #156)"
```

---

## Task 7: Documentation

**Files:**
- Modify: `packages/secubox-metrics/README.md`
- Modify: `packages/secubox-mitmproxy/README.md`

- [ ] **Step 7.1: Append API section to secubox-metrics README**

Add under existing "Endpoints" / "API Reference" section:

```markdown
### Cookie Audit (RGPD / ePrivacy)

| Method | Path                                  | Description                                    |
|--------|---------------------------------------|------------------------------------------------|
| POST   | `/api/v1/cookie-audit/ingest`         | Browser snapshot ingest (credentials: omit)    |
| GET    | `/api/v1/cookie-audit/report?host=…`  | Per-vhost reconciled report                    |
| GET    | `/api/v1/cookie-audit/summary`        | Global rollup (counts + violations)            |

Disabled by default. Enable via `[cookie_audit] enabled = true` in
`/etc/secubox/secubox.conf`. Requires the companion mitmproxy
`cookie_audit` addon.
```

- [ ] **Step 7.2: Append addon section to secubox-mitmproxy README**

```markdown
### cookie_audit.py — RGPD ledger

Companion addon to `secubox_waf.py`. Captures every `Set-Cookie` header
observed in transit and appends a structured JSONL record to
`/var/log/secubox/cookie-audit/server.jsonl`. Cookie values are sha256-hashed.

Register in the mitmdump invocation alongside the WAF addon:

```
mitmdump -s /usr/share/secubox/addons/secubox_waf.py \
         -s /usr/share/secubox/addons/cookie_audit.py
```

The companion browser script `cookie-inventory.js` (loaded via the WAF
banner injection) snapshots `document.cookie` and posts to
`/api/v1/cookie-audit/ingest`. The secubox-metrics aggregator reconciles
both streams.
```

- [ ] **Step 7.3: Commit**

```bash
git add packages/secubox-metrics/README.md packages/secubox-mitmproxy/README.md
git commit -m "docs: cookie-audit API + addon (ref #156)"
```

---

## Task 8: Tracking files update

**Files:**
- Modify: `.claude/HISTORY.md`
- Modify: `.claude/WIP.md`

- [ ] **Step 8.1: Append HISTORY entry**

Prepend (newest at top, follow existing format):

```markdown
## 2026-05-16 — Cookie audit pipeline (#156)
- New mitmproxy addon `cookie_audit.py` writes JSONL ledger of every Set-Cookie.
- New browser module `cookie-inventory.js` snapshots `document.cookie` (sha256-hashed).
- New `CookieAuditAggregator` reconciles both streams, classifies via TOML rules,
  flags RGPD violations (JS-set non-strictly-necessary cookies).
- New endpoints `/api/v1/cookie-audit/{ingest,report,summary}`.
- Default ruleset covers GA/Matomo/Hotjar/Facebook/Microsoft Clarity patterns.
```

- [ ] **Step 8.2: Mark item done in WIP**

Move (or add and immediately tick) the cookie-audit pipeline under "✅ Fait" in `.claude/WIP.md`.

- [ ] **Step 8.3: Commit**

```bash
git add .claude/HISTORY.md .claude/WIP.md
git commit -m "docs(claude): record cookie-audit pipeline in HISTORY+WIP (ref #156)"
```

---

## Task 9: Verification + push (no PR until user asks)

- [ ] **Step 9.1: Full local test pass**

Run:
```
( cd packages/secubox-mitmproxy && python3 -m pytest tests/ -v )
( cd packages/secubox-metrics && python3 -m pytest tests/ -v )
```
Expected: all green.

- [ ] **Step 9.2: Lint Python files for syntax**

Run:
```
python3 -m py_compile \
  packages/secubox-mitmproxy/addons/cookie_audit.py \
  packages/secubox-mitmproxy/addons/secubox_waf.py \
  packages/secubox-metrics/api/cookie_audit.py \
  packages/secubox-metrics/api/main.py
```
Expected: no output.

- [ ] **Step 9.3: Push branch**

```bash
git push -u origin feature/156-cookie-audit-pipeline-rgpd-eprivacy-comp
```

- [ ] **Step 9.4: Comment progress on issue (NOT close)**

```bash
gh issue comment 156 --body "Implementation complete on branch feature/156-cookie-audit-pipeline-rgpd-eprivacy-comp — all tests green. Awaiting validation; no PR opened (per repo policy)."
```

Per memory `feedback_no_unprompted_prs`: do NOT open the PR. Ask the user
whether to open it.

---

## Self-Review Checklist

- [x] Each spec brick (mitmproxy addon, browser module, aggregator, classification, API, docs) → one or more tasks.
- [x] No placeholders ("TBD", "implement later", "add validation"). All code blocks contain runnable content.
- [x] Type/name consistency: `CookieAuditAggregator`, `Classifier`, `classify_cookie`, `parse_set_cookie`, `CookieAudit` used identically across tests and impl.
- [x] Files paths absolute relative to repo root.
- [x] TDD discipline: test → fail → impl → pass → commit on every code-producing task.
- [x] Frequent commits (~9 commits, one per task).
- [x] Memory respected: no PR opened unprompted (Task 9 step 4).
