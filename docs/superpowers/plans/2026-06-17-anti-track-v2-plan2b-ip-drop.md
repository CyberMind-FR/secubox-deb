<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2b (Exclusive-IP nft-drop) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hard-block at the IP layer — resolve confirmed **pure-tracker** domains to IPs and drop them into the existing nft `secubox_blacklist` set, but only for IPs not in a curated CDN/cloud allowlist, gated dark behind `privacy_enforce && privacy_ip_drop`.

**Architecture:** A new pure module `secubox_toolbox/ip_dns.py` holds the CDN-allowlist parsing and the exclusivity decision (no nft/DNS/network — takes a `resolve` callable + pre-loaded networks). `escalate.py` (which already owns `_resolve_ips`, `_nft_add_blacklist`, audit, and runs on the `secubox-escalate` timer) gains one gated step that reads `pure-trackers.txt`, applies the decision, and drops the IPs. A static `data/cdn-allowlist.txt` ships in the .deb.

**Tech Stack:** Python 3.11 stdlib `ipaddress`, the existing `escalate.py` nft/resolve plumbing, `secubox_toolbox.filters` (Plan 1 toggles). pytest. Issue #633.

**Spec:** `docs/superpowers/specs/2026-06-17-anti-track-v2-plan2b-enforcement-design.md` (§3, §4). **The §5 DNS-refuse feed is split to a separate follow-up plan** pending resolver-topology confirmation — NOT in this plan.

**Scope note:** Plan 2b-of-this-plan = IP layer only. DNS feed deferred. Conventions: SPDX header on new `.py`; paths relative to `packages/secubox-toolbox/`; worktree `secubox-deb-worktrees/633-…` branch `feature/633-…`; commits end `(ref #633)`.

**Verified facts:** `escalate.py` — `TABLE="inet secubox_blacklist"`, `_resolve_ips(host, timeout=2.0)->List[str]`, `_nft_add_blacklist(ip)->bool` (adds `{ ip timeout ESCALATE_TTL }` to `blacklist_v4`/`v6`), `_audit(msg)`, `ESCALATE_TTL` env default `"4h"`, `evaluate_and_apply()` is the timer entry. Plan 1 `filters.py` keys: `privacy_enforce` (default False), `privacy_ip_drop` (default False). Plan 2a writes `/var/lib/secubox/toolbox/pure-trackers.txt`.

---

### Task 1: `ip_dns.py` — CDN allowlist parsing + membership

**Files:**
- Create: `packages/secubox-toolbox/secubox_toolbox/ip_dns.py`
- Test: `packages/secubox-toolbox/tests/test_ip_dns.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_ip_dns.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import ip_dns


def test_load_cdn_allowlist_parses_and_skips(tmp_path):
    f = tmp_path / "cdn.txt"
    f.write_text(
        "# comment\n"
        "104.16.0.0/13\n"        # Cloudflare v4
        "\n"
        "2606:4700::/32\n"       # Cloudflare v6
        "not-a-cidr\n"           # malformed → skipped
    )
    nets = ip_dns.load_cdn_allowlist(str(f))
    assert len(nets) == 2


def test_ip_in_allowlist_v4_and_v6(tmp_path):
    f = tmp_path / "cdn.txt"
    f.write_text("104.16.0.0/13\n2606:4700::/32\n")
    nets = ip_dns.load_cdn_allowlist(str(f))
    assert ip_dns.ip_in_allowlist("104.16.5.5", nets) is True
    assert ip_dns.ip_in_allowlist("8.8.8.8", nets) is False
    assert ip_dns.ip_in_allowlist("2606:4700::1111", nets) is True
    assert ip_dns.ip_in_allowlist("garbage", nets) is False


def test_load_missing_file_returns_empty():
    assert ip_dns.load_cdn_allowlist("/no/such/file.txt") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ip_dns.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'secubox_toolbox.ip_dns'`

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-toolbox/secubox_toolbox/ip_dns.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: Anti-Track v2 Plan 2b IP/DNS helpers (#633)

Pure functions — no nft, no DNS, no file writes beyond reading the static CDN
allowlist. Consumed by escalate.py (exclusive-IP nft-drop). The CDN/cloud
allowlist is the collateral gate: an IP that belongs to shared infrastructure
(Cloudflare/Fastly/Akamai/Google/AWS/Azure) is NEVER dropped, even when a pure
tracker resolves there.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Callable, Iterable, List

log = logging.getLogger("secubox.toolbox.ip_dns")

CDN_ALLOWLIST_PATH = "/usr/lib/secubox/toolbox/data/cdn-allowlist.txt"


def load_cdn_allowlist(path: str = CDN_ALLOWLIST_PATH) -> list:
    """Parse a CIDR-per-line file into ip_network objects. Comments (#) and
    blank/malformed lines are skipped. Missing file → []."""
    nets = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return nets
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            log.warning("cdn-allowlist: skipping malformed CIDR %r", s)
    return nets


def ip_in_allowlist(ip: str, networks: Iterable) -> bool:
    """True if ip falls inside any allow-network. Malformed ip → False."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        if addr.version == net.version and addr in net:
            return True
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ip_dns.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/ip_dns.py packages/secubox-toolbox/tests/test_ip_dns.py
git commit -m "feat(toolbox): ip_dns CDN allowlist parsing + membership (ref #633)"
```

---

### Task 2: `ip_dns.exclusive_tracker_ips`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/ip_dns.py`
- Test: `packages/secubox-toolbox/tests/test_ip_dns.py`

- [ ] **Step 1: Write the failing test (append)**

```python
def test_exclusive_tracker_ips_excludes_cdn(tmp_path):
    f = tmp_path / "cdn.txt"
    f.write_text("104.16.0.0/13\n")          # Cloudflare range
    nets = ip_dns.load_cdn_allowlist(str(f))
    # stub resolver: pure1 → a non-CDN IP ; pure2 → a Cloudflare IP
    resolve = {"pure1.trk": ["203.0.113.7"],
               "pure2.trk": ["104.16.9.9"]}.get
    out = ip_dns.exclusive_tracker_ips(
        ["pure1.trk", "pure2.trk"], lambda h: resolve(h) or [], nets)
    assert out == {"203.0.113.7"}            # CDN IP excluded


def test_exclusive_tracker_ips_dedups_and_handles_empty():
    out = ip_dns.exclusive_tracker_ips(
        ["a.trk", "b.trk"],
        lambda h: ["198.51.100.5"],          # both resolve to same IP
        [])
    assert out == {"198.51.100.5"}
    assert ip_dns.exclusive_tracker_ips([], lambda h: ["1.2.3.4"], []) == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ip_dns.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.ip_dns' has no attribute 'exclusive_tracker_ips'`

- [ ] **Step 3: Write minimal implementation (append to `ip_dns.py`)**

```python
def exclusive_tracker_ips(pure_hosts: Iterable[str],
                          resolve: Callable[[str], List[str]],
                          allow_nets: Iterable) -> set:
    """Resolve each pure-tracker host and return the set of IPs that are NOT in
    the CDN/cloud allowlist (so safe to nft-drop). `resolve` is injected
    (escalate._resolve_ips in production) to keep this function pure/testable."""
    allow = list(allow_nets)
    drop: set = set()
    for host in pure_hosts:
        if not host:
            continue
        try:
            ips = resolve(host) or []
        except Exception:
            ips = []
        for ip in ips:
            if ip and not ip_in_allowlist(ip, allow):
                drop.add(ip)
    return drop
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_ip_dns.py -q`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/ip_dns.py packages/secubox-toolbox/tests/test_ip_dns.py
git commit -m "feat(toolbox): ip_dns exclusive-tracker-IP computation (CDN-gated) (ref #633)"
```

---

### Task 3: CDN allowlist data file

**Files:**
- Create: `packages/secubox-toolbox/data/cdn-allowlist.txt`
- Modify: `packages/secubox-toolbox/debian/rules` (ship `data/`)

- [ ] **Step 1: Create the data file**

Create `packages/secubox-toolbox/data/cdn-allowlist.txt` with a documented header and a curated starter set of major CDN/cloud CIDRs. Use these real published ranges (a conservative starter subset — the file header documents manual refresh):

```text
# SecuBox Anti-Track v2 (#633) — CDN / cloud IP allowlist.
# IPs inside these ranges are NEVER nft-dropped even when a pure tracker
# resolves there, to avoid blackholing shared infrastructure.
# One CIDR per line; '#' comments. Manual refresh on release from each
# provider's published ranges (Cloudflare/AWS/Google/Azure publish JSON;
# Fastly/Akamai via their docs). Conservative starter set — extend as needed.

# --- Cloudflare (https://www.cloudflare.com/ips/) ---
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32

# --- Fastly (https://api.fastly.com/public-ip-list) ---
151.101.0.0/16
199.232.0.0/16
2a04:4e40::/32
2a04:4e42::/32

# --- Akamai (representative; refresh from Akamai docs) ---
23.32.0.0/11
23.192.0.0/11
104.64.0.0/10
184.24.0.0/13

# --- Google (gstatic/googleusercontent/cloud; refresh from cloud.json) ---
8.8.4.0/24
8.8.8.0/24
34.64.0.0/10
35.190.0.0/17
142.250.0.0/15
172.217.0.0/16
216.58.192.0/19
2607:f8b0::/32
2a00:1450::/32

# --- Amazon (CloudFront/AWS; refresh from ip-ranges.json) ---
13.32.0.0/15
13.224.0.0/14
52.84.0.0/15
54.182.0.0/16
204.246.164.0/22
2600:9000::/28

# --- Microsoft Azure (representative; refresh from ServiceTags JSON) ---
13.64.0.0/11
20.33.0.0/16
40.64.0.0/10
2603:1000::/24
```

- [ ] **Step 2: Confirm/extend the `debian/rules` ship line for `data/`**

Run: `cd packages/secubox-toolbox && grep -n "data\|cp -r \|install -d" debian/rules | head`
The package installs into `/usr/lib/secubox/toolbox/`. Add a step (in `override_dh_auto_install`, alongside the existing `cp -r secubox_toolbox …` / `cp -r conf …` lines) to ship the data dir:
```make
	cp -r data                  debian/secubox-toolbox/usr/lib/secubox/toolbox/
```
(Match the surrounding indentation/style. This installs `data/cdn-allowlist.txt` → `/usr/lib/secubox/toolbox/data/cdn-allowlist.txt`, the default `ip_dns.CDN_ALLOWLIST_PATH`.)

- [ ] **Step 3: Verify the file parses**

Run: `cd packages/secubox-toolbox && python -c "from secubox_toolbox import ip_dns; n=ip_dns.load_cdn_allowlist('data/cdn-allowlist.txt'); print(len(n), 'networks'); assert len(n) > 30"`
Expected: prints a count > 30, no assertion error (confirms every non-comment line is a valid CIDR).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/data/cdn-allowlist.txt packages/secubox-toolbox/debian/rules
git commit -m "feat(toolbox): ship CDN/cloud allowlist for exclusive-IP gate (ref #633)"
```

---

### Task 4: wire exclusive-IP drop into `escalate.py`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/escalate.py`
- Test: `packages/secubox-toolbox/tests/test_escalate_pure_ip.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-toolbox/tests/test_escalate_pure_ip.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import escalate


def test_pure_ip_drop_gated_off_when_not_enforcing(tmp_path, monkeypatch):
    pure = tmp_path / "pure.txt"; pure.write_text("ga.trk\n")
    dropped = []
    monkeypatch.setattr(escalate, "_resolve_ips", lambda h: ["203.0.113.9"])
    monkeypatch.setattr(escalate, "_nft_add_blacklist",
                        lambda ip: dropped.append(ip) or True)
    # privacy_enforce False → no drops
    n = escalate.pure_tracker_ip_drop(
        pure_path=str(pure), allowlist_path=str(tmp_path / "none.txt"),
        enforce=False, ip_drop=True)
    assert n == 0 and dropped == []


def test_pure_ip_drop_applies_non_cdn_only(tmp_path, monkeypatch):
    pure = tmp_path / "pure.txt"; pure.write_text("ga.trk\ncdn.trk\n")
    cdn = tmp_path / "cdn.txt"; cdn.write_text("104.16.0.0/13\n")
    dropped = []
    resolve = {"ga.trk": ["203.0.113.9"], "cdn.trk": ["104.16.1.2"]}
    monkeypatch.setattr(escalate, "_resolve_ips", lambda h: resolve.get(h, []))
    monkeypatch.setattr(escalate, "_nft_add_blacklist",
                        lambda ip: dropped.append(ip) or True)
    monkeypatch.setattr(escalate, "_audit", lambda msg: None)
    n = escalate.pure_tracker_ip_drop(
        pure_path=str(pure), allowlist_path=str(cdn),
        enforce=True, ip_drop=True)
    assert dropped == ["203.0.113.9"]        # CDN IP 104.16.1.2 excluded
    assert n == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_escalate_pure_ip.py -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.escalate' has no attribute 'pure_tracker_ip_drop'`

- [ ] **Step 3: Write minimal implementation**

In `escalate.py`, add the import near the top (after the existing `from typing import ...`):
```python
from . import ip_dns
```
Add the constant near `ESCALATE_TTL`:
```python
PURE_TRACKERS_PATH = os.environ.get(
    "SECUBOX_PURE_TRACKERS", "/var/lib/secubox/toolbox/pure-trackers.txt")
```
Add the function (after `_cscli_decision`, before `evaluate_and_apply`):
```python
def pure_tracker_ip_drop(pure_path: str = PURE_TRACKERS_PATH,
                         allowlist_path: str = ip_dns.CDN_ALLOWLIST_PATH,
                         enforce: bool = False, ip_drop: bool = False) -> int:
    """Drop the IPs of confirmed pure-tracker domains into the nft blacklist,
    excluding CDN/cloud ranges. No-op unless enforce AND ip_drop. Returns the
    number of IPs dropped. Reversible (TTL) + audited."""
    if not (enforce and ip_drop):
        return 0
    try:
        hosts = [ln.split()[0].lower()
                 for ln in Path(pure_path).read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        return 0
    nets = ip_dns.load_cdn_allowlist(allowlist_path)
    ips = ip_dns.exclusive_tracker_ips(hosts, _resolve_ips, nets)
    dropped = 0
    for ip in sorted(ips):
        if _nft_add_blacklist(ip):
            dropped += 1
    if dropped:
        _audit(f"ESCALATE pure-tracker-ip dropped={dropped} ttl={ESCALATE_TTL}")
    return dropped
```
Then wire it into the timer entry `evaluate_and_apply()`: near the top of that function (after `summary = {...}` is initialised — read the function to place it correctly), add a gated call reading the Plan-1 filters:
```python
    # Anti-Track v2 (#633): pure-tracker exclusive-IP drop (dark unless armed).
    try:
        import sys as _sys
        _sys.path.insert(0, os.environ.get("SECUBOX_TOOLBOX_LIB",
                                           "/usr/lib/secubox/toolbox"))
        from secubox_toolbox.filters import get_filters as _gf
        _f = _gf()
        _n = pure_tracker_ip_drop(enforce=bool(_f.get("privacy_enforce")),
                                  ip_drop=bool(_f.get("privacy_ip_drop")))
        if _n:
            summary["actions"].append(f"pure-tracker-ip drop x{_n}")
    except Exception as e:
        log.warning("pure_tracker_ip_drop step failed: %s", e)
```
(Place this so a failure can't abort the existing escalation logic — wrap in its own try as shown. Adapt the `summary[...]` key to whatever the function actually returns; if `summary` has no `actions` list at that point, append to an existing list field or skip the summary mutation.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_escalate_pure_ip.py -q`
Expected: PASS (2 passed). Then full suite: `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/escalate.py packages/secubox-toolbox/tests/test_escalate_pure_ip.py
git commit -m "feat(toolbox): escalate drops exclusive pure-tracker IPs (dark-gated, CDN-safe) (ref #633)"
```

---

### Task 5: packaging + full gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Confirm `ip_dns.py` + `data/` ship**

Run: `cd packages/secubox-toolbox && grep -n "cp -r secubox_toolbox\|cp -r data" debian/rules`
Expected: `secubox_toolbox` (covers `ip_dns.py`) and the `data` line added in Task 3 both present.

- [ ] **Step 2: Bump changelog**

Add a new top entry in `debian/changelog`, next version after `2.6.43-1~bookworm1` → `2.6.44-1~bookworm1`, author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17, dch format:
```
  * Anti-Track v2 Plan 2b (#633): exclusive pure-tracker IP nft-drop via
    escalate.py, gated dark (privacy_enforce && privacy_ip_drop), with a
    shipped CDN/cloud allowlist (cdn-allowlist.txt) so shared-infra IPs are
    never blackholed. TTL'd + audited. DNS-refuse feed deferred to a follow-up.
```

- [ ] **Step 3: Full gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green — ~47 tests).
Run: `python -c "import ast; ast.parse(open('secubox_toolbox/ip_dns.py').read()); ast.parse(open('secubox_toolbox/escalate.py').read()); print('ok')"`.
Run: `python -m pyflakes secubox_toolbox/ip_dns.py` if available (expect none); else skip.
Run: `head -1 secubox_toolbox/ip_dns.py` (SPDX present).
Run: `dpkg-parsechangelog -l debian/changelog | grep Version` (`2.6.44-1~bookworm1`).
Run: `git status --short` (empty after commit).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog for Anti-Track v2 Plan 2b IP-drop (ref #633)"
```

---

## Self-Review

**Spec coverage (this plan = §3 + §4; §5 DNS deferred):**
- §3 CDN allowlist (static shipped, ipaddress parse, membership) → Tasks 1, 3. ✓
- §4 exclusive-IP computation (pure source, CDN-gated, dedup) → Task 2. ✓
- §4 escalate wiring (read pure-trackers, resolve via `_resolve_ips`, `_nft_add_blacklist` TTL, audit) → Task 4. ✓
- §1/§2 dark gating (`privacy_enforce && privacy_ip_drop`, both default-ish off) → Task 4 (`pure_tracker_ip_drop` returns 0 unless both true; filters read in `evaluate_and_apply`). ✓
- Packaging/ship → Tasks 3, 5. ✓
- **§5 DNS-refuse feed → DEFERRED** to a separate plan (dns-guard owns blocklist.txt; integration mechanism needs the resolver topology confirmed). Recorded as out-of-scope here.

**Placeholder scan:** none — complete code in every code step; Step-2/Step-1 greps are explicit verifications. The one adaptive instruction (Task 4 Step 3 "adapt the summary key") is bounded with a concrete fallback ("skip the summary mutation").

**Type consistency:** `load_cdn_allowlist(path)->list`, `ip_in_allowlist(ip, networks)->bool`, `exclusive_tracker_ips(pure_hosts, resolve, allow_nets)->set`, `pure_tracker_ip_drop(pure_path, allowlist_path, enforce, ip_drop)->int` — consistent across Tasks 1/2/4 and tests. `CDN_ALLOWLIST_PATH` constant reused. `_resolve_ips`/`_nft_add_blacklist`/`_audit` are the real escalate.py names (verified).

**Rollout:** inert until `privacy_enforce=true` AND `privacy_ip_drop=true`. nft adds are TTL'd (4h, auto-renew per timer run) + audited; CDN allowlist is the collateral gate; pure-only source guarantees no load-bearing tracker is IP-dropped. No shared-dir mode changes.
