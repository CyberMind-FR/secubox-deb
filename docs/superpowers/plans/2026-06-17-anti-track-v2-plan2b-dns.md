<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2b-DNS (unbound NXDOMAIN feed) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make confirmed pure-tracker domains return NXDOMAIN to inspected clients by writing a toolbox-owned unbound drop-in from `pure-trackers.txt` and reloading unbound — gated dark behind `privacy_enforce && privacy_dns_feed`.

**Architecture:** A pure formatter `ip_dns.unbound_block_lines(pure_hosts)` returns the drop-in's config lines (registrable-folded `local-zone … always_nxdomain`). The hourly `autolearn`, after writing `pure-trackers.txt`, writes the drop-in atomically and reloads unbound — only when both flags are set. unbound is the live-verified client resolver (10.99.x/10.100.x); dns-guard is inactive and not used.

**Tech Stack:** Python 3.11 stdlib, `unbound-control reload`, the existing autolearn job, `secubox_toolbox.filters` (Plan 1 toggles) + `secubox_toolbox.privacy.registrable`. pytest. Issue #633.

**Spec:** `docs/superpowers/specs/2026-06-17-anti-track-v2-plan2b-dns-design.md`. Topology LIVE-VERIFIED on gk2 (`root@10.98.0.1`): unbound on 10.99.0.1/10.99.1.1/10.100.0.1, dns-guard inactive.

**Conventions:** worktree `secubox-deb-worktrees/633-…` branch `feature/633-…`; commits end `(ref #633)`. Paths relative to `packages/secubox-toolbox/`.

**Verified facts:** `autolearn` computes `pure` (set) before `c.close()` and writes `pout = sorted(x for x in pure if x)` to `PURE_OUT`; it imports `from secubox_toolbox import learn as _learn` after a `sys.path.insert(0, SECUBOX_TOOLBOX_LIB)`. `ip_dns.py` (Plan 2b) already imports `Callable/Iterable/List` + `registrable` and has a module `log`. `filters.FILTERS_PATH` is currently a hardcoded constant (no env override).

---

### Task 1: `ip_dns.unbound_block_lines`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/ip_dns.py`
- Test: `packages/secubox-toolbox/tests/test_ip_dns.py`

- [ ] **Step 1: Write the failing test (append to `tests/test_ip_dns.py`)**

```python
def test_unbound_block_lines_folds_dedups_sorts():
    lines = ip_dns.unbound_block_lines(
        ["www.criteo.com", "doubleclick.net", "criteo.com", ""])
    assert lines[0] == "server:"
    lz = [l for l in lines if "local-zone:" in l]
    assert lz == [
        '    local-zone: "criteo.com." always_nxdomain',
        '    local-zone: "doubleclick.net." always_nxdomain',
    ]


def test_unbound_block_lines_empty_has_only_server_header():
    lines = ip_dns.unbound_block_lines([])
    assert "server:" in lines
    assert not any("local-zone:" in l for l in lines)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ip_dns.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.ip_dns' has no attribute 'unbound_block_lines'`

- [ ] **Step 3: Write minimal implementation (append to `ip_dns.py`)**

```python
def unbound_block_lines(pure_hosts: Iterable[str]) -> list:
    """Render an unbound drop-in body that NXDOMAINs each pure-tracker domain.
    Registrable-folded, deduped, sorted. Always emits a `server:` header so the
    file is a valid (possibly empty) unbound conf.d drop-in."""
    zones = set()
    for h in pure_hosts:
        d = registrable(h) if h else ""
        if d:
            zones.add(d)
    lines = [
        "# SecuBox Anti-Track v2 (#633) — generated; do not edit by hand.",
        "# Pure-tracker domains NXDOMAIN'd for all unbound clients.",
        "server:",
    ]
    for d in sorted(zones):
        lines.append('    local-zone: "%s." always_nxdomain' % d)
    return lines
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ip_dns.py -q`
Expected: PASS (7 passed — 5 prior + 2 new)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/ip_dns.py packages/secubox-toolbox/tests/test_ip_dns.py
git commit -m "feat(toolbox): ip_dns unbound NXDOMAIN drop-in formatter (ref #633)"
```

---

### Task 2: `filters.py` — env-overridable path (enables subprocess gate testing)

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/filters.py:17`
- Test: `packages/secubox-toolbox/tests/test_privacy_filters.py`

The autolearn DNS step (Task 3) reads `filters.get_filters()` in a subprocess; to test the gate-ON path the test must point filters at a temp file via env. Make `FILTERS_PATH` honor `SECUBOX_FILTERS_PATH`.

- [ ] **Step 1: Write the failing test (append to `tests/test_privacy_filters.py`)**

```python
import importlib, os


def test_filters_path_env_override(monkeypatch, tmp_path):
    p = tmp_path / "f.json"
    p.write_text('{"privacy_enforce": true}')
    monkeypatch.setenv("SECUBOX_FILTERS_PATH", str(p))
    import secubox_toolbox.filters as flt
    importlib.reload(flt)
    try:
        assert flt.FILTERS_PATH == str(p)
        assert flt.get_filters(force=True)["privacy_enforce"] is True
    finally:
        monkeypatch.delenv("SECUBOX_FILTERS_PATH", raising=False)
        importlib.reload(flt)   # restore default for other tests
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy_filters.py::test_filters_path_env_override -q`
Expected: FAIL — `FILTERS_PATH` equals the hardcoded default, not the env value.

- [ ] **Step 3: Write minimal implementation**

In `filters.py`, change line 17 from:
```python
FILTERS_PATH = "/etc/secubox/toolbox/filters.json"
```
to:
```python
FILTERS_PATH = os.environ.get(
    "SECUBOX_FILTERS_PATH", "/etc/secubox/toolbox/filters.json")
```
(`os` is already imported in filters.py.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_privacy_filters.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/filters.py packages/secubox-toolbox/tests/test_privacy_filters.py
git commit -m "feat(toolbox): filters.json path env-overridable (SECUBOX_FILTERS_PATH) (ref #633)"
```

---

### Task 3: autolearn DNS-feed step (gated, atomic, reload)

**Files:**
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-autolearn`
- Test: `packages/secubox-toolbox/tests/test_autolearn_dns.py`

- [ ] **Step 1: Write the failing integration test**

```python
# packages/secubox-toolbox/tests/test_autolearn_dns.py
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
    c.commit(); c.close()


def _run(tmp_path, enforce, dns_feed):
    db = tmp_path / "toolbox.db"; _seed_db(str(db))
    filt = tmp_path / "filters.json"
    filt.write_text(json.dumps({"privacy_enforce": enforce,
                                "privacy_dns_feed": dns_feed}))
    dropin = tmp_path / "97-antitrack.conf"
    env = {**os.environ,
           "SECUBOX_AUTOLEARN_DB": str(db),
           "SECUBOX_AUTOLEARN_OUT": str(tmp_path / "learned.txt"),
           "SECUBOX_AUTOLEARN_PURE_OUT": str(tmp_path / "pure.txt"),
           "SECUBOX_FILTERS_PATH": str(filt),
           "SECUBOX_UNBOUND_BLOCK_CONF": str(dropin),
           "SECUBOX_UNBOUND_RELOAD": "0",          # no-op the reload in tests
           "PYTHONPATH": str(PKG)}
    r = subprocess.run([sys.executable, str(SCRIPT)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return dropin


def test_dns_dropin_written_when_armed(tmp_path):
    dropin = _run(tmp_path, enforce=True, dns_feed=True)
    assert dropin.exists()
    body = dropin.read_text()
    # PURE_SEED always includes google-analytics.com → an NXDOMAIN zone
    assert 'local-zone: "google-analytics.com." always_nxdomain' in body


def test_dns_dropin_not_written_when_dark(tmp_path):
    dropin = _run(tmp_path, enforce=False, dns_feed=True)
    assert not dropin.exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_autolearn_dns.py -q`
Expected: FAIL — drop-in not written (the autolearn DNS step doesn't exist yet).

- [ ] **Step 3: Edit `sbin/secubox-toolbox-autolearn`**

(a) Next to the existing `from secubox_toolbox import learn as _learn` guarded import, add `ip_dns` and the new env constants. Find:
```python
try:
    from secubox_toolbox import learn as _learn
except Exception:       # pragma: no cover - degraded mode
    _learn = None
```
and change to:
```python
try:
    from secubox_toolbox import learn as _learn
except Exception:       # pragma: no cover - degraded mode
    _learn = None
try:
    from secubox_toolbox import ip_dns as _ip_dns
except Exception:       # pragma: no cover
    _ip_dns = None

UNBOUND_BLOCK_CONF = os.environ.get(
    "SECUBOX_UNBOUND_BLOCK_CONF",
    "/etc/unbound/unbound.conf.d/97-secubox-antitrack-block.conf")
```

(b) Add a helper function near the top of the file (after the `registrable` def, before `def main`):
```python
def _dns_feed(pure_hosts) -> int:
    """Write the unbound NXDOMAIN drop-in for pure trackers + reload, gated by
    privacy_enforce && privacy_dns_feed. Returns the zone count written, or -1
    if the gate is off / unavailable (drop-in left untouched)."""
    if _ip_dns is None:
        return -1
    try:
        from secubox_toolbox.filters import get_filters
        f = get_filters()
    except Exception:
        return -1
    if not (f.get("privacy_enforce") and f.get("privacy_dns_feed")):
        return -1
    lines = _ip_dns.unbound_block_lines(pure_hosts)
    try:
        tmp = UNBOUND_BLOCK_CONF + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.replace(tmp, UNBOUND_BLOCK_CONF)
    except OSError as e:
        sys.stderr.write(f"autolearn: dns drop-in write failed: {e}\n")
        return -1
    if os.environ.get("SECUBOX_UNBOUND_RELOAD", "1") != "0":
        import subprocess
        try:
            subprocess.run(["unbound-control", "reload"], timeout=10,
                           capture_output=True)
        except Exception:
            try:
                subprocess.run(["systemctl", "reload", "unbound"], timeout=10,
                               capture_output=True)
            except Exception as e:
                sys.stderr.write(f"autolearn: unbound reload failed: {e}\n")
    return sum(1 for l in lines if "local-zone:" in l)
```

(c) Call it after the `pure-trackers.txt` write block (after the `if _learn is not None:` pure-write block, before the final manifest `sys.stderr.write`):
```python
    dns_zones = _dns_feed(pout)
```

(d) Extend the manifest line to report the DNS feed. Change the final stderr write's last f-string fragment from:
```python
        f" ; {len(pout)} pure\n")
```
to:
```python
        f" ; {len(pout)} pure ; dns_feed={dns_zones}\n")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_autolearn_dns.py -q`
Expected: PASS (2 passed). Then the autolearn suite: `python -m pytest tests/test_autolearn_integration.py tests/test_autolearn_dns.py -q` (both green), then full `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/sbin/secubox-toolbox-autolearn packages/secubox-toolbox/tests/test_autolearn_dns.py
git commit -m "feat(toolbox): autolearn writes unbound NXDOMAIN drop-in for pure trackers (dark-gated) (ref #633)"
```

---

### Task 4: packaging + full gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Confirm no new install needed**

Run: `cd packages/secubox-toolbox && grep -n "cp -r secubox_toolbox" debian/rules`
Expected: present — ships the modified `ip_dns.py`/`filters.py`. The drop-in is generated at runtime (not packaged), and `secubox-toolbox-autolearn` is already installed. No `debian/rules` change. Confirm and report.

- [ ] **Step 2: Bump changelog**

Add a new top entry `2.6.45-1~bookworm1` after `2.6.44-1~bookworm1`, dch format, author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17:
```
  * Anti-Track v2 Plan 2b-DNS (#633): autolearn writes an unbound NXDOMAIN
    drop-in (97-secubox-antitrack-block.conf) for confirmed pure-tracker
    domains + unbound-control reload, gated dark (privacy_enforce &&
    privacy_dns_feed). Targets unbound (the live client resolver); dns-guard
    is inactive on the board and intentionally not used. filters.json path is
    now env-overridable (SECUBOX_FILTERS_PATH) for testing.
```

- [ ] **Step 3: Full gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green, ~52 tests).
Run: `python -c "import ast; ast.parse(open('secubox_toolbox/ip_dns.py').read()); ast.parse(open('sbin/secubox-toolbox-autolearn').read()); ast.parse(open('secubox_toolbox/filters.py').read()); print('ok')"`.
Run: `dpkg-parsechangelog -l debian/changelog | grep Version` → `2.6.45-1~bookworm1`.
Run: `git status --short` → empty after commit.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog for Anti-Track v2 Plan 2b-DNS (ref #633)"
```

---

## Self-Review

**Spec coverage:**
- §3/§4 unbound drop-in formatter (registrable-fold, dedup, sort, always_nxdomain, server: header) → Task 1. ✓
- §5 autolearn gated write + atomic + reload + fail-safe → Task 3 (`_dns_feed`: gate off → -1 / drop-in untouched; write OSError → logged, -1; reload non-fatal with fallback). ✓
- §5 empty/missing pure list → empty `server:` drop-in (still written when armed so a previously-populated drop-in clears) → Task 1 (empty → header only) + Task 3 (writes whenever armed). ✓
- §2/§6 gating `privacy_enforce && privacy_dns_feed`, dark by default → Task 3 `_dns_feed` guard; subprocess test needs the filters path override → Task 2. ✓
- §6 tests (formatter folding/empty; integration armed-writes / dark-skips; reload stubbed via `SECUBOX_UNBOUND_RELOAD=0`) → Tasks 1, 3. ✓
- Packaging → Task 4 (runtime-generated drop-in, no new install). ✓

**Placeholder scan:** none — complete code in every code step.

**Type consistency:** `unbound_block_lines(pure_hosts) -> list` (Task 1) called with `pout` (a list) in Task 3. `_dns_feed(pure_hosts) -> int` returns -1 on gate-off/unavailable, else zone count; manifest uses `dns_zones`. Env names consistent across Task 3 impl and the Task 3 test (`SECUBOX_UNBOUND_BLOCK_CONF`, `SECUBOX_UNBOUND_RELOAD`, `SECUBOX_FILTERS_PATH`). `SECUBOX_FILTERS_PATH` honored by `filters.FILTERS_PATH` (Task 2).

**Rollout:** dark until `privacy_enforce && privacy_dns_feed`. Reload is fast + reversible. Before arming, confirm unbound is still the client resolver (live-verified now). No shared-dir mode changes; the drop-in lives under `/etc/unbound/unbound.conf.d/` (unbound-owned), written 0644 via temp+replace.
