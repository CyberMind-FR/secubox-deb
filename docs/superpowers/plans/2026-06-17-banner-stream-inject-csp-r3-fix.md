<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox R3 banner — CSP fallback + bundle cache-key fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the R2/R3 transparency banner on strict-CSP sites by falling back from the `stream_inject` loader to the CSP-tolerant legacy buffer path; and fix the bundle cache so wg/non-wg report_urls don't bleed.

**Architecture:** Two tiny, isolated edits in `secubox-toolbox`: (1) `inject_banner.InjectBanner.responseheaders` returns early on strict CSP (reusing the existing `_detect_csp_strict`), so the legacy `response` buffer path — which injects an inline-CSS banner with no external script/fetch — handles CSP-strict pages; (2) `bundle.get_bundle` keys its cache by `(client_id, is_wg)`.

**Tech Stack:** mitmproxy addon, Python. pytest + mitmproxy `tflow`. Issue #636.

**Spec:** `docs/superpowers/specs/2026-06-17-banner-stream-inject-csp-r3-fix-design.md`.

**Conventions:** worktree `secubox-deb-worktrees/636-…` branch `fix/636-…`; commits end `(ref #636)`. Paths relative to `packages/secubox-toolbox/`.

**Verified facts:** `_detect_csp_strict(flow)->bool` already exists in `inject_banner.py` (True when `script-src`/`default-src` present without `'unsafe-inline'`/nonce). `responseheaders` sets `resp.stream = _LoaderInjector(...)` + `flow.metadata["sbx_streamed"]=True` after the `banner`-filter check; the `response` buffer path early-returns if `sbx_streamed`. `bundle.get_bundle(client_id, is_wg=False)` caches via `_cache.get(client_id or "")` / `_cache[client_id or ""]=(now,bundle)`; `_report_url(client_id, is_wg)` is already correct.

---

### Task 1: CSP fallback in `responseheaders` (the real fix)

**Files:**
- Modify: `packages/secubox-toolbox/mitmproxy_addons/inject_banner.py` (`InjectBanner.responseheaders`)
- Test: `packages/secubox-toolbox/tests/test_banner_csp.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_banner_csp.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import sys, pathlib, importlib, json
ADDON_DIR = pathlib.Path(__file__).resolve().parents[1] / "mitmproxy_addons"
sys.path.insert(0, str(ADDON_DIR))

from mitmproxy.test import tflow, tutils      # noqa: E402
from secubox_toolbox import filters           # noqa: E402


def _addon(monkeypatch, tmp_path):
    fp = tmp_path / "filters.json"
    fp.write_text(json.dumps({"banner": True, "stream_inject": True}))
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp))
    filters.get_filters(force=True)
    import inject_banner
    importlib.reload(inject_banner)
    # force the client to look like an R3 WG peer so the level gate passes
    monkeypatch.setattr(inject_banner, "_client_level", lambda flow: "r3")
    return inject_banner


def _html_resp(ib, csp=None):
    f = tflow.tflow(resp=tutils.tresp())
    f.response.headers["content-type"] = "text/html; charset=utf-8"
    f.response.status_code = 200
    if csp:
        f.response.headers["content-security-policy"] = csp
    return f


def test_strict_csp_does_not_stream(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html_resp(ib, csp="script-src 'self'; object-src 'none'")  # no unsafe-inline/nonce
    ib.InjectBanner().responseheaders(f)
    assert not f.metadata.get("sbx_streamed")     # fell back to buffer path


def test_no_csp_streams(monkeypatch, tmp_path):
    ib = _addon(monkeypatch, tmp_path)
    f = _html_resp(ib, csp=None)
    ib.InjectBanner().responseheaders(f)
    assert f.metadata.get("sbx_streamed") is True  # streamed loader as before
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_banner_csp.py -q`
Expected: `test_strict_csp_does_not_stream` FAILS (currently streams regardless of CSP → `sbx_streamed` True). `test_no_csp_streams` passes.

- [ ] **Step 3: Add the CSP guard**

In `inject_banner.py`, in `InjectBanner.responseheaders`, immediately BEFORE the
`try:` block that does `resp.stream = _LoaderInjector(...)` / sets
`flow.metadata["sbx_streamed"]` (i.e. after the `banner`-filter check), insert:
```python
        # #636 — strict CSP would block the injected loader <script> and its
        # /__toolbox/bundle fetch → no banner. Don't stream; fall through to the
        # legacy buffer path, which injects an inline-CSS banner (no script/fetch)
        # that survives strict CSP.
        if _detect_csp_strict(flow):
            return
```
(Place it so the early `return` skips setting `sbx_streamed` — the `response`
buffer path then runs. Do not touch the other guards.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_banner_csp.py -q`
Expected: PASS (2 passed). If mitmproxy isn't importable, `pip install mitmproxy` then retry; if the `_client_level` monkeypatch name differs, read `inject_banner.py` for the actual level helper and patch that.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/mitmproxy_addons/inject_banner.py packages/secubox-toolbox/tests/test_banner_csp.py
git commit -m "fix(toolbox): banner stream_inject falls back to buffer path on strict CSP (ref #636)"
```

---

### Task 2: bundle cache key by `(client_id, is_wg)`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/bundle.py` (`get_bundle`)
- Test: `packages/secubox-toolbox/tests/test_bundle_cache.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_bundle_cache.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import bundle


def test_get_bundle_cache_keyed_by_is_wg(monkeypatch):
    bundle._cache.clear()
    wg = bundle.get_bundle("mh1", is_wg=True)
    r2 = bundle.get_bundle("mh1", is_wg=False)
    # wg → public kbin url ; non-wg → captive ; must NOT be served the cached wg one
    assert wg["report_url"] != r2["report_url"]
    assert wg["report_url"].startswith("https://kbin.gk2.secubox.in")
    assert r2["report_url"] == bundle.REPORT_URL_CAPTIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_bundle_cache.py -q`
Expected: FAIL — `r2["report_url"]` equals the cached wg public URL (cache keyed by client_id only).

- [ ] **Step 3: Key the cache by `(client_id, is_wg)`**

In `bundle.py` `get_bundle`, change the cache lookups/writes from the bare
`client_id` key to a tuple key:
```python
def get_bundle(client_id: str, is_wg: bool = False) -> dict:
    """Return the cached bundle for a client, rebuilding past the TTL. Fail-open."""
    try:
        now = time.time()
        key = (client_id or "", bool(is_wg))
        hit = _cache.get(key)
        if hit and (now - hit[0]) < BUNDLE_TTL:
            return hit[1]
        bundle = build_bundle(client_id, is_wg)
        _cache[key] = (now, bundle)
        return bundle
    except Exception:
        return {"v": 1, "client_id": client_id or "", "level": "r1",
                "pin": "", "report_url": REPORT_URL_CAPTIVE,
                "tracker_patterns": TRACKER_PATTERNS, "ts": int(time.time())}
```
(Only the cache key changes — `build_bundle`/`_report_url` are already correct.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_bundle_cache.py -q`
Expected: PASS. Then full suite `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/bundle.py packages/secubox-toolbox/tests/test_bundle_cache.py
git commit -m "fix(toolbox): bundle cache keyed by (client_id, is_wg) so wg/non-wg report_url don't bleed (ref #636)"
```

---

### Task 3: changelog + full gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Bump changelog**

Read the top version (`head -3 debian/changelog`). Add a NEW top entry with the next patch version (e.g. if top is `2.6.46-1~bookworm1` → `2.6.47-1~bookworm1`; if a different value, increment from whatever is actually on this branch's HEAD), dch format, author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17:
```
  * Banner stream_inject fix (#636): on strict-CSP sites, fall back from the
    loader-<script> injection to the legacy inline-CSS buffer path so the
    R2/R3 transparency banner renders (CSP would block the loader + its bundle
    fetch). Bundle cache keyed by (client_id, is_wg). NOTE: the R3 report link
    was NOT broken (real R3 clients send wg=1 → public kbin url).
```
(NOTE: this branch is off master, which may be at a different toolbox version than the #633 branch's 2.6.46. Use master's current toolbox version + 1.)

- [ ] **Step 2: Full gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green).
Run: `python -c "import ast; ast.parse(open('mitmproxy_addons/inject_banner.py').read()); ast.parse(open('secubox_toolbox/bundle.py').read()); print('ok')"`.
Run: `dpkg-parsechangelog -l debian/changelog | grep Version`.
Run: `git status --short` → empty after commit.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog for #636 banner CSP fallback (ref #636)"
```

---

## Self-Review

**Spec coverage:**
- Bug 1 CSP fallback (reuse `_detect_csp_strict`, early-return before `sbx_streamed`) → Task 1. ✓
- Bug 2 (minor) cache key by `(client_id, is_wg)` → Task 2. ✓
- Retracted report-url change — correctly NOT implemented (R3 link already correct); the changelog notes it. ✓
- Tests (strict-CSP→no stream / no-CSP→stream; cache wg≠non-wg) → Tasks 1, 2. ✓

**Placeholder scan:** none — complete code each step. Task 3 Step 1 says "increment from this branch's actual HEAD version" (a precise instruction, since this branch is off master not the #633 branch).

**Type consistency:** `_detect_csp_strict(flow)->bool`, `responseheaders` early-return semantics (no `sbx_streamed`), `get_bundle(client_id, is_wg)` cache-key tuple — all consistent with the verified existing signatures. `REPORT_URL_CAPTIVE`/`TRACKER_PATTERNS` are existing module names in bundle.py.

**Rollout:** behavior-restoring, no toggle. Deploy = rebuild + redeploy secubox-toolbox, reload mitm-wg workers. Verify on a strict-CSP site from an R3 client. No shared-dir/mode changes; no engine/nft/DNS impact.
