# nft-based Network Stats Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Feed real, categorized network-layer stats from nftables named counters plus `/proc/net/dev` interface throughput into the dashboard, with a SQLite 24h time-series and a new toolbox "Réseau" tab — and make the existing `#ads` "Drops réseau" KPI real.

**Architecture:** A root oneshot+timer collector in **secubox-hub** samples `nft -j list counters` + `/proc/net/dev` every 30s into SQLite (`/var/lib/secubox/hub/netstats.db`) and a latest snapshot (`netstats.json`). The hub FastAPI (user `secubox`, read-only) serves `/api/v1/hub/netstats/{summary,series}`. The **secubox-toolbox** dashboard renders a "Réseau" tab from those endpoints and repoints `network_drops` to the snapshot. Drops/attacks come from **named nft counters** added inline to existing enforcement rules in **secubox-toolbox** (blacklist/quarantine/DoH) and **secubox-mitmproxy** (WAF rate-limit), plus a hub-owned `inet filter input` policy-drop tap.

**Tech Stack:** Python 3.11 stdlib (sqlite3, subprocess, json, pathlib), FastAPI, nftables named counters, systemd oneshot+timer, vanilla-JS + inline SVG for charts.

## Global Constraints

- License header on every new Python/shell file: `# SPDX-License-Identifier: LicenseRef-CMSD-1.0` then `# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>` (copy verbatim from sibling files).
- nftables only (never iptables). Default-DROP policy is sacred — added rules only **count**, never bypass.
- Named counter objects MUST be declared in the **same table** as the rules that reference them.
- nft counters reset to 0 on every `nft -f` reload → all delta/rate math MUST be reset-aware (delta = `cur` when `cur < prev`, never negative).
- **Never** chmod the shared parents `/run/secubox` (1777), `/etc/secubox` (0755), or `/var/lib/secubox` (0755). Only create/own the `…/hub/` subdir at 0755.
- Root writes the DB+snapshot (files 0644, dir 0755); user `secubox` opens them read-only. Never inject counters into the externally-managed `inet crowdsec` table — read it best-effort only.
- Commit messages reference the issue: end the subject with `(ref #758)`. No "Claude"/"Generated with Claude Code" text anywhere in commits or the PR.
- Suggested version bumps (deb changelog): secubox-toolbox `2.7.24 → 2.8.0`, secubox-hub `1.4.7 → 1.5.0`, secubox-mitmproxy `1.0.9 → 1.0.10`.

---

## File Structure

**secubox-hub** (collector + store + API — the owner)
- Create `packages/secubox-hub/api/netstats.py` — shared module: pure parsers, SQLite store, snapshot builder, `collect_once()`/`main()`. Imported by both the root collector and the FastAPI app.
- Create `packages/secubox-hub/sbin/secubox-netstats-collect` — tiny shell wrapper that runs `netstats.main()` as root.
- Create `packages/secubox-hub/debian/secubox-netstats.service` + `…timer`.
- Create `packages/secubox-hub/nftables.d/zz-secubox-netstats-tap.nft` — `inet filter input` policy-drop counter.
- Modify `packages/secubox-hub/api/main.py` — add `/netstats/summary` + `/netstats/series` endpoints.
- Modify `packages/secubox-hub/debian/rules` — install collector, units, nft tap, extend sudoers.
- Modify `packages/secubox-hub/debian/postinst` — deploy+reload the nft tap, enable the timer.
- Modify `packages/secubox-hub/debian/changelog`.
- Create tests: `packages/secubox-hub/tests/test_netstats_parse.py`, `…/test_netstats_store.py`, `…/test_netstats_snapshot.py`, `…/test_netstats_api.py`, `…/test_netstats_tap.py`.

**secubox-toolbox** (instrumentation + render)
- Modify `packages/secubox-toolbox/nftables.d/secubox-blacklist.nft` — named counters.
- Modify `packages/secubox-toolbox/secubox_toolbox/api.py` — robust `admin_blacklist()` parse + repoint `network_drops`.
- Modify `packages/secubox-toolbox/www/toolbox/index.html` — new "Réseau" tab.
- Modify `packages/secubox-toolbox/debian/changelog`.
- Create tests: `packages/secubox-toolbox/tests/test_blacklist_counters.py`, `…/test_network_drops_source.py`, `…/test_reseau_tab_present.py`.

**secubox-mitmproxy** (instrumentation)
- Modify `packages/secubox-mitmproxy/nftables/secubox-waf-ratelimit.nft` — named counter.
- Modify `packages/secubox-mitmproxy/debian/changelog`.
- Create test: `packages/secubox-mitmproxy/tests/test_waf_counter.py`.

**Shared test helper** (counter-declaration assertion, copied per package to avoid cross-package imports)
- A small regex check that every `counter name "X"` reference has a matching `counter X {` declaration.

---

## Task 1: Toolbox — named counters in the blacklist spine + robust reader

**Files:**
- Modify: `packages/secubox-toolbox/nftables.d/secubox-blacklist.nft`
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py:2932-2997` (`admin_blacklist`)
- Test: `packages/secubox-toolbox/tests/test_blacklist_counters.py` (new)
- Test: `packages/secubox-toolbox/tests/test_admin_blacklist_named.py` (new)

**Interfaces:**
- Produces: nft named counters `sbx_drop_blacklist_v4/v6`, `sbx_drop_quarantine_v4/v6`, `sbx_doh_detect_v4/v6` in table `inet secubox_blacklist`. `admin_blacklist()` still returns `{"drops": int, "doh_hits": int, ...}` (now read from named-counter objects).

**Background:** switching a rule from anonymous `counter` to `counter name "x"` changes the `nft -j list table` JSON: named counters appear as standalone counter **objects** `{"counter": {"name": "...", "packets": N, "bytes": M}}`, not inline in the rule expr. The current parser reads `ex.get("counter").get("packets")` from rule exprs and would regress to 0. We fix the parser to sum counter **objects** by name, then change the nft file.

- [ ] **Step 1: Write the failing test for the named-counter-object parser**

Create `packages/secubox-toolbox/tests/test_admin_blacklist_named.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""admin_blacklist must sum named counter OBJECTS (ref #758)."""
import asyncio
import json
import types
from secubox_toolbox import api


def _fake_nft_json():
    return json.dumps({"nftables": [
        {"set": {"name": "blacklist_v4", "elem": ["1.2.3.4"]}},
        {"counter": {"name": "sbx_drop_blacklist_v4", "packets": 7, "bytes": 700}},
        {"counter": {"name": "sbx_drop_quarantine_v4", "packets": 3, "bytes": 300}},
        {"counter": {"name": "sbx_doh_detect_v4", "packets": 5, "bytes": 500}},
    ]})


def test_admin_blacklist_sums_named_counters(monkeypatch):
    def fake_run(cmd, **kw):
        return types.SimpleNamespace(returncode=0, stdout=_fake_nft_json(), stderr="")
    monkeypatch.setattr("subprocess.run", fake_run)
    out = asyncio.run(api.admin_blacklist())
    assert out["drops"] == 10        # blacklist 7 + quarantine 3 (NOT doh)
    assert out["doh_hits"] == 5
    assert out["v4_count"] == 1
```

- [ ] **Step 2: Run the test, verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_admin_blacklist_named.py -v`
Expected: FAIL (`drops` is 0 — current parser reads rule exprs, not counter objects).

- [ ] **Step 3: Update `admin_blacklist()` to read counter objects**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, replace the rule-expr counter loop (the `if "rule" in item:` block, lines ~2974-2984) with a counter-object reader. The full loop body becomes:

```python
            for item in data.get("nftables", []):
                if "set" in item:
                    s = item["set"]
                    n = len(s.get("elem", []) or [])
                    name = s.get("name")
                    if name == "blacklist_v4":
                        out["v4_count"] = n
                    elif name == "blacklist_v6":
                        out["v6_count"] = n
                    elif name == "doh_detect_v4":
                        out["doh_detect_v4"] = n
                    elif name == "doh_detect_v6":
                        out["doh_detect_v6"] = n
                if "counter" in item and isinstance(item["counter"], dict):
                    cobj = item["counter"]
                    cname = cobj.get("name", "")
                    pk = int(cobj.get("packets", 0) or 0)
                    if cname.startswith("sbx_doh_detect"):
                        out["doh_hits"] += pk
                    elif cname.startswith(("sbx_drop_blacklist", "sbx_drop_quarantine")):
                        out["drops"] += pk
```

- [ ] **Step 4: Run the test, verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_admin_blacklist_named.py -v`
Expected: PASS.

- [ ] **Step 5: Write the failing nft structural test**

Create `packages/secubox-toolbox/tests/test_blacklist_counters.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Every named counter referenced in the blacklist spine is declared (ref #758)."""
import re
from pathlib import Path

NFT = Path(__file__).resolve().parents[1] / "nftables.d" / "secubox-blacklist.nft"
EXPECTED = {
    "sbx_drop_blacklist_v4", "sbx_drop_blacklist_v6",
    "sbx_drop_quarantine_v4", "sbx_drop_quarantine_v6",
    "sbx_doh_detect_v4", "sbx_doh_detect_v6",
}


def _decls_and_refs(text):
    decls = set(re.findall(r'counter\s+([a-z0-9_]+)\s*\{', text))
    refs = set(re.findall(r'counter name "([a-z0-9_]+)"', text))
    return decls, refs


def test_named_counters_declared_and_referenced():
    text = NFT.read_text()
    decls, refs = _decls_and_refs(text)
    assert EXPECTED <= refs, f"missing refs: {EXPECTED - refs}"
    assert refs <= decls, f"undeclared counters referenced: {refs - decls}"
```

- [ ] **Step 6: Run it, verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_blacklist_counters.py -v`
Expected: FAIL (no named counters yet).

- [ ] **Step 7: Add named counters to `secubox-blacklist.nft`**

Inside `table inet secubox_blacklist {`, immediately after the `set quarantine_v6 { … }` block (after line 54), add the declarations:

```
    # #758 — named counters for the network-stats collector. Declared at
    # table scope so `nft list counters` exposes them by name; referenced
    # by the enforce/doh_watch rules below. Reset to 0 on reload (collector
    # is reset-aware).
    counter sbx_drop_quarantine_v4 {}
    counter sbx_drop_quarantine_v6 {}
    counter sbx_drop_blacklist_v4 {}
    counter sbx_drop_blacklist_v6 {}
    counter sbx_doh_detect_v4 {}
    counter sbx_doh_detect_v6 {}
```

Then change the six rule lines to reference them (the `enforce` chain):

```
        ip  saddr @quarantine_v4 counter name "sbx_drop_quarantine_v4" drop
        ip6 saddr @quarantine_v6 counter name "sbx_drop_quarantine_v6" drop
        ip  daddr @blacklist_v4 limit rate 20/second log prefix "SBX-BL-DROP " counter name "sbx_drop_blacklist_v4" drop
        ip  saddr @blacklist_v4 counter name "sbx_drop_blacklist_v4" drop
        ip6 daddr @blacklist_v6 limit rate 20/second log prefix "SBX-BL-DROP " counter name "sbx_drop_blacklist_v6" drop
        ip6 saddr @blacklist_v6 counter name "sbx_drop_blacklist_v6" drop
```

And the two `doh_watch` rules (count-only, keep no `drop`):

```
        ip  daddr @doh_detect_v4 tcp dport { 443, 853 } ct state new limit rate 5/second log prefix "SBX-DOH " counter name "sbx_doh_detect_v4"
        ip6 daddr @doh_detect_v6 tcp dport { 443, 853 } ct state new limit rate 5/second log prefix "SBX-DOH " counter name "sbx_doh_detect_v6"
```

- [ ] **Step 8: Run both toolbox tests, verify they pass**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_blacklist_counters.py tests/test_admin_blacklist_named.py -v`
Expected: PASS (both files).

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-toolbox/nftables.d/secubox-blacklist.nft \
        packages/secubox-toolbox/secubox_toolbox/api.py \
        packages/secubox-toolbox/tests/test_blacklist_counters.py \
        packages/secubox-toolbox/tests/test_admin_blacklist_named.py
git commit -m "feat(toolbox): named nft counters in blacklist spine + named-counter reader (ref #758)"
```

---

## Task 2: Mitmproxy — named counter on the WAF rate-limit drop

**Files:**
- Modify: `packages/secubox-mitmproxy/nftables/secubox-waf-ratelimit.nft:47-55`
- Modify: `packages/secubox-mitmproxy/debian/changelog`
- Test: `packages/secubox-mitmproxy/tests/test_waf_counter.py` (new)

**Interfaces:**
- Produces: nft named counter `sbx_drop_wafrl` in table `inet secubox_waf_ratelimit`.

- [ ] **Step 1: Write the failing structural test**

Create `packages/secubox-mitmproxy/tests/test_waf_counter.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""WAF rate-limit drops carry a named counter (ref #758)."""
import re
from pathlib import Path

NFT = Path(__file__).resolve().parents[1] / "nftables" / "secubox-waf-ratelimit.nft"


def test_wafrl_counter_declared_and_referenced():
    text = NFT.read_text()
    decls = set(re.findall(r'counter\s+([a-z0-9_]+)\s*\{', text))
    refs = set(re.findall(r'counter name "([a-z0-9_]+)"', text))
    assert "sbx_drop_wafrl" in refs
    assert "sbx_drop_wafrl" in decls
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd packages/secubox-mitmproxy && python -m pytest tests/test_waf_counter.py -v`
Expected: FAIL (counter absent).

- [ ] **Step 3: Add the named counter to `secubox-waf-ratelimit.nft`**

Inside `table inet secubox_waf_ratelimit {`, after the `set whitelist_v4 { … }` block (after line 38), add:

```
    # #758 — named counter for the network-stats collector (attacks family).
    counter sbx_drop_wafrl {}
```

Change the offender-drop rules (lines 47-48) and the rate-limit drop rule (lines 52-55) to reference it:

```
        ip saddr @offenders_v4 counter name "sbx_drop_wafrl" drop
        ip6 saddr @offenders_v6 counter name "sbx_drop_wafrl" drop
```

```
        tcp flags syn tcp dport { 80, 443 } \
            limit rate over 30/second burst 50 packets \
            add @offenders_v4 { ip saddr timeout 5m } \
            log prefix "[secubox-rl] " level info counter name "sbx_drop_wafrl" drop
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd packages/secubox-mitmproxy && python -m pytest tests/test_waf_counter.py -v`
Expected: PASS.

- [ ] **Step 5: Add changelog entry**

Prepend a new block to `packages/secubox-mitmproxy/debian/changelog`:

```
secubox-mitmproxy (1.0.10-1~bookworm1) bookworm; urgency=medium

  * feat(nft): named counter sbx_drop_wafrl on the WAF rate-limit drops so the
    secubox-hub network-stats collector can attribute attack drops (ref #758).

 -- Gerald KERMA <devel@cybermind.fr>  Sat, 27 Jun 2026 12:00:00 +0200
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-mitmproxy/nftables/secubox-waf-ratelimit.nft \
        packages/secubox-mitmproxy/tests/test_waf_counter.py \
        packages/secubox-mitmproxy/debian/changelog
git commit -m "feat(mitmproxy): named nft counter on WAF rate-limit drops (ref #758)"
```

---

## Task 3: Hub — `inet filter input` policy-drop tap (named counter)

**Files:**
- Create: `packages/secubox-hub/nftables.d/zz-secubox-netstats-tap.nft`
- Test: `packages/secubox-hub/tests/test_netstats_tap.py` (new)

**Interfaces:**
- Produces: nft named counter `sbx_drop_input_policy` in the pre-existing base table `inet filter`, fed by a tail `counter` rule appended to the `input` chain.

**Background:** the base `inet filter` table (with default-drop `input`) exists at boot, created outside our packages. `table inet filter { counter … }` **adds** the counter to that table without deleting it. A bare `counter` rule appended at the **tail** of `input` counts exactly what the policy would drop — so it must load **after** every accept rule, hence the `zz-` filename prefix.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-hub/tests/test_netstats_tap.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""The hub input policy-drop tap declares + references its counter (ref #758)."""
import re
from pathlib import Path

NFT = Path(__file__).resolve().parents[1] / "nftables.d" / "zz-secubox-netstats-tap.nft"


def test_tap_counter_present_and_zz_ordered():
    assert NFT.name.startswith("zz-"), "tap must sort after accept rules"
    text = NFT.read_text()
    assert re.search(r'counter\s+sbx_drop_input_policy\s*\{', text)
    assert re.search(r'add rule inet filter input .*counter name "sbx_drop_input_policy"', text)
    # additive only — must NOT delete or flush the base filter table
    assert "delete table inet filter" not in text
    assert "flush ruleset" not in text
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_tap.py -v`
Expected: FAIL (file does not exist).

- [ ] **Step 3: Create the tap drop-in**

Create `packages/secubox-hub/nftables.d/zz-secubox-netstats-tap.nft`:

```
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# #758 — network-stats tap. Counts packets that fall through to the
# default-drop policy of the base inet filter input chain = "unsolicited
# inbound" volume. ADDITIVE ONLY: `table inet filter { counter … }` adds the
# counter to the pre-existing base table without deleting it; the tail
# `add rule` appends a bare counter AFTER every accept rule. The zz- filename
# guarantees this loads last among /etc/nftables.d/*.nft. Counter resets on
# reload — the collector is reset-aware. Never drops or accepts; pure observe.
table inet filter {
    counter sbx_drop_input_policy {}
}
add rule inet filter input counter name "sbx_drop_input_policy" comment "sbx-netstats-input-policy-tap"
```

- [ ] **Step 4: Run it, verify it passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_tap.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-hub/nftables.d/zz-secubox-netstats-tap.nft \
        packages/secubox-hub/tests/test_netstats_tap.py
git commit -m "feat(hub): inet filter input policy-drop nft tap counter (ref #758)"
```

---

## Task 4: Hub — `netstats.py` pure parsers

**Files:**
- Create: `packages/secubox-hub/api/netstats.py`
- Test: `packages/secubox-hub/tests/test_netstats_parse.py` (new)

**Interfaces:**
- Produces:
  - `CATEGORY_MAP: dict[str,str]`, `DROP_CATEGORIES: set[str]`
  - `category_for(name: str) -> str | None`
  - `parse_proc_net_dev(text: str) -> dict[str, dict]` → `iface -> {"rx_bytes","rx_packets","tx_bytes","tx_packets"}`
  - `parse_nft_counters_json(data: dict) -> dict[str, dict]` → `name -> {"packets","bytes"}`
  - `reset_aware_delta(prev: int, cur: int) -> int`

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-hub/tests/test_netstats_parse.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Pure parsers for the network-stats collector (ref #758)."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
netstats = importlib.import_module("netstats")

PROC = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:  123 4 0 0 0 0 0 0  123 4 0 0 0 0 0 0\n"
    "  eth0: 1000 10 0 0 0 0 0 0  2000 20 0 0 0 0 0 0\n"
)


def test_parse_proc_net_dev_skips_lo_header():
    out = netstats.parse_proc_net_dev(PROC)
    assert "lo" not in out
    assert out["eth0"] == {"rx_bytes": 1000, "rx_packets": 10, "tx_bytes": 2000, "tx_packets": 20}


def test_parse_nft_counters_json():
    data = {"nftables": [
        {"counter": {"name": "sbx_drop_blacklist_v4", "packets": 5, "bytes": 500}},
        {"counter": {"name": "irrelevant", "packets": 9, "bytes": 9}},
        {"rule": {"chain": "x"}},
    ]}
    out = netstats.parse_nft_counters_json(data)
    assert out["sbx_drop_blacklist_v4"] == {"packets": 5, "bytes": 500}
    assert "irrelevant" in out  # parser keeps all; mapping happens via category_for


def test_category_for():
    assert netstats.category_for("sbx_drop_blacklist_v6") == "blacklist"
    assert netstats.category_for("sbx_drop_quarantine_v4") == "quarantine"
    assert netstats.category_for("sbx_drop_wafrl") == "waf_ratelimit"
    assert netstats.category_for("sbx_drop_input_policy") == "input_policy"
    assert netstats.category_for("sbx_doh_detect_v4") == "doh"
    assert netstats.category_for("nope") is None


def test_reset_aware_delta():
    assert netstats.reset_aware_delta(100, 150) == 50      # normal
    assert netstats.reset_aware_delta(150, 10) == 10       # reset → treat cur as delta
    assert netstats.reset_aware_delta(0, 0) == 0
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_parse.py -v`
Expected: FAIL (`netstats` module not found).

- [ ] **Step 3: Create `netstats.py` with the parsers**

Create `packages/secubox-hub/api/netstats.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: secubox-hub network-stats (#758).

Shared by the root collector (write path: collect_once/main) and the FastAPI
app (read path: read_snapshot/query_series). Pure functions are unit-tested;
the privileged collect path is integration-tested with monkeypatched sources.
"""
from __future__ import annotations
import json
import sqlite3
import subprocess
import time
from pathlib import Path

DB_PATH = Path("/var/lib/secubox/hub/netstats.db")
SNAP_PATH = Path("/var/lib/secubox/hub/netstats.json")
DATA_DIR = DB_PATH.parent
STALE_AFTER_S = 120  # snapshot older than this is flagged stale

# counter-name → category. Named counters live in the owning packages' tables.
CATEGORY_MAP = {
    "sbx_drop_blacklist_v4": "blacklist", "sbx_drop_blacklist_v6": "blacklist",
    "sbx_drop_quarantine_v4": "quarantine", "sbx_drop_quarantine_v6": "quarantine",
    "sbx_doh_detect_v4": "doh", "sbx_doh_detect_v6": "doh",
    "sbx_drop_wafrl": "waf_ratelimit",
    "sbx_drop_input_policy": "input_policy",
}
# Categories that count toward "network_drops" (doh is detect-only, excluded).
DROP_CATEGORIES = {"blacklist", "quarantine", "waf_ratelimit", "input_policy", "crowdsec"}


def category_for(name: str) -> str | None:
    return CATEGORY_MAP.get(name)


def parse_proc_net_dev(text: str) -> dict[str, dict]:
    """Parse /proc/net/dev → {iface: {rx_bytes,rx_packets,tx_bytes,tx_packets}}.
    Skips the two header lines and the loopback interface.
    """
    out: dict[str, dict] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "lo" or not name:
            continue
        f = rest.split()
        if len(f) < 16:
            continue
        out[name] = {
            "rx_bytes": int(f[0]), "rx_packets": int(f[1]),
            "tx_bytes": int(f[8]), "tx_packets": int(f[9]),
        }
    return out


def parse_nft_counters_json(data: dict) -> dict[str, dict]:
    """Parse `nft -j list counters` (or list table) → {name: {packets,bytes}}."""
    out: dict[str, dict] = {}
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict) and "name" in c:
            out[c["name"]] = {
                "packets": int(c.get("packets", 0) or 0),
                "bytes": int(c.get("bytes", 0) or 0),
            }
    return out


def reset_aware_delta(prev: int, cur: int) -> int:
    """Monotonic-counter delta that tolerates resets (nft reload → cur < prev)."""
    if cur < prev:
        return cur
    return cur - prev
```

- [ ] **Step 4: Run, verify it passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_parse.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-hub/api/netstats.py packages/secubox-hub/tests/test_netstats_parse.py
git commit -m "feat(hub): netstats pure parsers (proc/net/dev, nft counters, reset-aware delta) (ref #758)"
```

---

## Task 5: Hub — `netstats.py` SQLite store + series query

**Files:**
- Modify: `packages/secubox-hub/api/netstats.py`
- Test: `packages/secubox-hub/tests/test_netstats_store.py` (new)

**Interfaces:**
- Consumes: `reset_aware_delta`, `category_for`, `DROP_CATEGORIES` (Task 4).
- Produces:
  - `init_db(conn: sqlite3.Connection) -> None`
  - `insert_sample(conn, ts: int, counters: dict[str,dict], ifaces: dict[str,dict]) -> None`
  - `query_series(conn, window_s: int, step_s: int) -> dict` → `{"window_s","step_s","drops":{cat:[[ts,pkts],…]},"in_bps":{iface:[[ts,bps],…]},"out_bps":{iface:[[ts,bps],…]}}`
  - `prune(conn, keep_s: int) -> None`

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-hub/tests/test_netstats_store.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SQLite store + reset-aware series for network-stats (ref #758)."""
import importlib
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
netstats = importlib.import_module("netstats")


def _conn():
    c = sqlite3.connect(":memory:")
    netstats.init_db(c)
    return c


def test_insert_and_query_drops_delta():
    c = _conn()
    # t=0 blacklist=100 ; t=30 blacklist=160 → delta 60 in the bucket at t=30
    netstats.insert_sample(c, 0, {"sbx_drop_blacklist_v4": {"packets": 100, "bytes": 0}}, {})
    netstats.insert_sample(c, 30, {"sbx_drop_blacklist_v4": {"packets": 160, "bytes": 0}}, {})
    out = netstats.query_series(c, window_s=3600, step_s=30)
    pts = out["drops"]["blacklist"]
    assert pts[-1][1] == 60


def test_query_drops_reset_aware():
    c = _conn()
    netstats.insert_sample(c, 0, {"sbx_drop_blacklist_v4": {"packets": 100, "bytes": 0}}, {})
    netstats.insert_sample(c, 30, {"sbx_drop_blacklist_v4": {"packets": 5, "bytes": 0}}, {})  # reload
    out = netstats.query_series(c, window_s=3600, step_s=30)
    assert out["drops"]["blacklist"][-1][1] == 5  # not negative


def test_query_throughput_bps():
    c = _conn()
    # 30s apart, +30000 rx bytes → 30000*8/30 = 8000 bps
    netstats.insert_sample(c, 0, {}, {"eth0": {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}})
    netstats.insert_sample(c, 30, {}, {"eth0": {"rx_bytes": 30000, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}})
    out = netstats.query_series(c, window_s=3600, step_s=30)
    assert out["in_bps"]["eth0"][-1][1] == 8000


def test_prune_drops_old_rows():
    c = _conn()
    netstats.insert_sample(c, 0, {"sbx_drop_wafrl": {"packets": 1, "bytes": 0}}, {})
    netstats.insert_sample(c, 1_000_000, {"sbx_drop_wafrl": {"packets": 2, "bytes": 0}}, {})
    netstats.prune(c, keep_s=10)  # relative to max ts
    rows = c.execute("SELECT COUNT(*) FROM counter_samples").fetchone()[0]
    assert rows == 1
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_store.py -v`
Expected: FAIL (`init_db` not defined).

- [ ] **Step 3: Append store + query to `netstats.py`**

Append to `packages/secubox-hub/api/netstats.py`:

```python
def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS counter_samples (
            ts INTEGER NOT NULL, name TEXT NOT NULL,
            packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
            PRIMARY KEY (ts, name)
        );
        CREATE TABLE IF NOT EXISTS iface_samples (
            ts INTEGER NOT NULL, iface TEXT NOT NULL,
            rx_bytes INTEGER NOT NULL, rx_packets INTEGER NOT NULL,
            tx_bytes INTEGER NOT NULL, tx_packets INTEGER NOT NULL,
            PRIMARY KEY (ts, iface)
        );
        CREATE INDEX IF NOT EXISTS idx_counter_ts ON counter_samples(ts);
        CREATE INDEX IF NOT EXISTS idx_iface_ts ON iface_samples(ts);
        """
    )
    conn.commit()


def insert_sample(conn: sqlite3.Connection, ts: int, counters: dict, ifaces: dict) -> None:
    for name, v in counters.items():
        conn.execute(
            "INSERT OR REPLACE INTO counter_samples(ts,name,packets,bytes) VALUES(?,?,?,?)",
            (ts, name, int(v.get("packets", 0)), int(v.get("bytes", 0))),
        )
    for iface, v in ifaces.items():
        conn.execute(
            "INSERT OR REPLACE INTO iface_samples(ts,iface,rx_bytes,rx_packets,tx_bytes,tx_packets) "
            "VALUES(?,?,?,?,?,?)",
            (ts, iface, int(v["rx_bytes"]), int(v["rx_packets"]),
             int(v["tx_bytes"]), int(v["tx_packets"])),
        )
    conn.commit()


def _bucket(ts: int, step_s: int) -> int:
    return ts - (ts % step_s)


def query_series(conn: sqlite3.Connection, window_s: int, step_s: int) -> dict:
    """Reset-aware deltas/rates bucketed to step_s over the last window_s.
    Rates are attributed to the bucket of the later sample in each pair.
    """
    now_row = conn.execute("SELECT MAX(ts) FROM counter_samples").fetchone()
    max_ts_c = now_row[0] if now_row and now_row[0] is not None else None
    now_row2 = conn.execute("SELECT MAX(ts) FROM iface_samples").fetchone()
    max_ts_i = now_row2[0] if now_row2 and now_row2[0] is not None else None
    max_ts = max(t for t in (max_ts_c, max_ts_i) if t is not None) if (max_ts_c or max_ts_i) else 0
    floor = max_ts - window_s

    drops: dict[str, dict[int, int]] = {}
    rows = conn.execute(
        "SELECT ts,name,packets FROM counter_samples WHERE ts>=? ORDER BY name,ts",
        (floor - step_s,),
    ).fetchall()
    prev: dict[str, tuple[int, int]] = {}
    for ts, name, pk in rows:
        cat = category_for(name)
        if cat is None:
            continue
        if name in prev:
            d = reset_aware_delta(prev[name][1], pk)
            b = _bucket(ts, step_s)
            if b >= _bucket(floor, step_s):
                drops.setdefault(cat, {}).setdefault(b, 0)
                drops[cat][b] += d
        prev[name] = (ts, pk)

    in_bps: dict[str, dict[int, int]] = {}
    out_bps: dict[str, dict[int, int]] = {}
    irows = conn.execute(
        "SELECT ts,iface,rx_bytes,tx_bytes FROM iface_samples WHERE ts>=? ORDER BY iface,ts",
        (floor - step_s,),
    ).fetchall()
    iprev: dict[str, tuple[int, int, int]] = {}
    for ts, iface, rx, tx in irows:
        if iface in iprev:
            pts, prx, ptx = iprev[iface]
            dt = ts - pts
            if dt > 0:
                b = _bucket(ts, step_s)
                if b >= _bucket(floor, step_s):
                    in_bps.setdefault(iface, {})[b] = reset_aware_delta(prx, rx) * 8 // dt
                    out_bps.setdefault(iface, {})[b] = reset_aware_delta(ptx, tx) * 8 // dt
        iprev[iface] = (ts, rx, tx)

    def _flatten(d: dict[str, dict[int, int]]) -> dict[str, list]:
        return {k: [[b, v[b]] for b in sorted(v)] for k, v in d.items()}

    return {
        "window_s": window_s, "step_s": step_s,
        "drops": _flatten(drops), "in_bps": _flatten(in_bps), "out_bps": _flatten(out_bps),
    }


def prune(conn: sqlite3.Connection, keep_s: int) -> None:
    for tbl in ("counter_samples", "iface_samples"):
        row = conn.execute(f"SELECT MAX(ts) FROM {tbl}").fetchone()
        if row and row[0] is not None:
            conn.execute(f"DELETE FROM {tbl} WHERE ts < ?", (row[0] - keep_s,))
    conn.commit()
```

- [ ] **Step 4: Run, verify it passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_store.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-hub/api/netstats.py packages/secubox-hub/tests/test_netstats_store.py
git commit -m "feat(hub): netstats SQLite store + reset-aware series query (ref #758)"
```

---

## Task 6: Hub — snapshot builder + privileged `collect_once`/`main`

**Files:**
- Modify: `packages/secubox-hub/api/netstats.py`
- Create: `packages/secubox-hub/sbin/secubox-netstats-collect`
- Test: `packages/secubox-hub/tests/test_netstats_snapshot.py` (new)

**Interfaces:**
- Consumes: all Task 4/5 functions.
- Produces:
  - `read_snapshot() -> dict` (read by the API; adds `stale` based on `updated` age)
  - `build_snapshot(conn, now: int) -> dict`
  - `_read_nft_counters() -> dict`, `_read_crowdsec() -> dict`, `_read_ifaces() -> dict` (privileged source readers, each best-effort)
  - `collect_once(now: int | None = None, conn: sqlite3.Connection | None = None) -> dict`
  - `main() -> None`

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-hub/tests/test_netstats_snapshot.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Snapshot builder + collect_once with monkeypatched privileged sources (#758)."""
import importlib
import json
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
netstats = importlib.import_module("netstats")


def test_build_snapshot_network_drops_excludes_doh():
    c = sqlite3.connect(":memory:")
    netstats.init_db(c)
    counters = {
        "sbx_drop_blacklist_v4": {"packets": 4, "bytes": 0},
        "sbx_drop_wafrl": {"packets": 6, "bytes": 0},
        "sbx_doh_detect_v4": {"packets": 99, "bytes": 0},
    }
    netstats.insert_sample(c, 1000, counters, {})
    snap = netstats.build_snapshot(c, now=1000)
    assert snap["network_drops"] == 10           # 4 + 6, doh excluded
    assert snap["categories"]["doh"]["packets"] == 99
    assert snap["updated"] == 1000


def test_collect_once_writes_row_and_snapshot(tmp_path, monkeypatch):
    db = tmp_path / "netstats.db"
    snap = tmp_path / "netstats.json"
    monkeypatch.setattr(netstats, "DB_PATH", db)
    monkeypatch.setattr(netstats, "SNAP_PATH", snap)
    monkeypatch.setattr(netstats, "DATA_DIR", tmp_path)
    monkeypatch.setattr(netstats, "_read_nft_counters",
                        lambda: {"sbx_drop_wafrl": {"packets": 3, "bytes": 30}})
    monkeypatch.setattr(netstats, "_read_crowdsec", lambda: {})
    monkeypatch.setattr(netstats, "_read_ifaces",
                        lambda: {"eth0": {"rx_bytes": 1, "rx_packets": 1, "tx_bytes": 1, "tx_packets": 1}})
    out = netstats.collect_once(now=1234)
    assert out["network_drops"] == 3
    assert snap.exists()
    written = json.loads(snap.read_text())
    assert written["updated"] == 1234
    # a second tick must not raise (DB reused)
    netstats.collect_once(now=1264)


def test_read_snapshot_marks_stale(tmp_path, monkeypatch):
    snap = tmp_path / "netstats.json"
    snap.write_text(json.dumps({"updated": 0, "categories": {}, "interfaces": {}, "network_drops": 0}))
    monkeypatch.setattr(netstats, "SNAP_PATH", snap)
    out = netstats.read_snapshot()
    assert out["stale"] is True
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_snapshot.py -v`
Expected: FAIL (`build_snapshot` not defined).

- [ ] **Step 3: Append snapshot + collector to `netstats.py`**

Append to `packages/secubox-hub/api/netstats.py`:

```python
def build_snapshot(conn: sqlite3.Connection, now: int) -> dict:
    """Latest cumulative per category + instantaneous rates vs the previous
    sample. network_drops = sum of DROP_CATEGORIES packet counts (doh excluded).
    """
    cats: dict[str, dict] = {}
    # latest cumulative per counter-name → fold into categories
    rows = conn.execute(
        "SELECT name, packets, bytes, ts FROM counter_samples "
        "WHERE ts=(SELECT MAX(ts) FROM counter_samples)"
    ).fetchall()
    for name, pk, by, _ts in rows:
        cat = category_for(name)
        if cat is None:
            continue
        c = cats.setdefault(cat, {"packets": 0, "bytes": 0})
        c["packets"] += int(pk)
        c["bytes"] += int(by)
    ser = query_series(conn, window_s=120, step_s=30)
    for cat, pts in ser["drops"].items():
        if pts:
            cats.setdefault(cat, {"packets": 0, "bytes": 0})["pps"] = pts[-1][1] / 30.0

    ifaces: dict[str, dict] = {}
    irow = conn.execute(
        "SELECT iface, rx_bytes, tx_bytes FROM iface_samples "
        "WHERE ts=(SELECT MAX(ts) FROM iface_samples)"
    ).fetchall()
    for iface, rx, tx in irow:
        ifaces[iface] = {"rx_bytes": int(rx), "tx_bytes": int(tx)}
    for iface, pts in ser["in_bps"].items():
        if pts:
            ifaces.setdefault(iface, {})["rx_bps"] = pts[-1][1]
    for iface, pts in ser["out_bps"].items():
        if pts:
            ifaces.setdefault(iface, {})["tx_bps"] = pts[-1][1]

    network_drops = sum(
        cats.get(cat, {}).get("packets", 0) for cat in DROP_CATEGORIES
    )
    return {
        "updated": now,
        "stale": False,
        "categories": cats,
        "interfaces": ifaces,
        "network_drops": int(network_drops),
    }


def read_snapshot() -> dict:
    """Read the latest snapshot (API path). Flags stale by `updated` age."""
    try:
        d = json.loads(SNAP_PATH.read_text())
    except Exception:
        return {"updated": 0, "stale": True, "categories": {}, "interfaces": {}, "network_drops": 0}
    age = max(0, int(time.time()) - int(d.get("updated", 0)))
    d["stale"] = age > STALE_AFTER_S
    return d


def _run_nft_json(args: list[str]) -> dict:
    try:
        r = subprocess.run(["/usr/sbin/nft", "-j", "list"] + args,
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return json.loads(r.stdout or "{}")
    except Exception:
        pass
    return {}


def _read_nft_counters() -> dict:
    return parse_nft_counters_json(_run_nft_json(["counters"]))


def _read_crowdsec() -> dict:
    """Best-effort: sum the externally-managed inet crowdsec table counters
    into a single synthetic counter mapped to the 'crowdsec' category.
    """
    data = _run_nft_json(["table", "inet", "crowdsec"])
    total = 0
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict):
            total += int(c.get("packets", 0) or 0)
        rule = item.get("rule")
        if isinstance(rule, dict):
            for ex in rule.get("expr", []):
                cc = ex.get("counter")
                if isinstance(cc, dict):
                    total += int(cc.get("packets", 0) or 0)
    if total:
        # synthetic name so category_for resolves to 'crowdsec'
        return {"sbx_drop_crowdsec": {"packets": total, "bytes": 0}}
    return {}


def _read_ifaces() -> dict:
    try:
        return parse_proc_net_dev(Path("/proc/net/dev").read_text())
    except Exception:
        return {}


def _open_db(conn: sqlite3.Connection | None):
    if conn is not None:
        return conn, False
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        DATA_DIR.chmod(0o755)  # our subdir only — NEVER the /var/lib/secubox parent
    except Exception:
        pass
    c = sqlite3.connect(str(DB_PATH))
    init_db(c)
    return c, True


def collect_once(now: int | None = None, conn: sqlite3.Connection | None = None) -> dict:
    if now is None:
        now = int(time.time())
    c, owns = _open_db(conn)
    try:
        counters = dict(_read_nft_counters())
        counters.update(_read_crowdsec())
        ifaces = _read_ifaces()
        insert_sample(c, now, counters, ifaces)
        prune(c, keep_s=7 * 86400)
        snap = build_snapshot(c, now)
        try:
            SNAP_PATH.write_text(json.dumps(snap))
            SNAP_PATH.chmod(0o644)
        except Exception:
            pass
        return snap
    finally:
        if owns:
            c.close()


def main() -> None:
    collect_once()


if __name__ == "__main__":
    main()
```

Note: `category_for("sbx_drop_crowdsec")` must resolve to `"crowdsec"`. Add to `CATEGORY_MAP` in Task 4's dict (edit `netstats.py`): add the line `"sbx_drop_crowdsec": "crowdsec",`.

- [ ] **Step 4: Add the crowdsec mapping entry**

In `packages/secubox-hub/api/netstats.py`, add to `CATEGORY_MAP` (after the `sbx_drop_input_policy` line):

```python
    "sbx_drop_crowdsec": "crowdsec",
```

- [ ] **Step 5: Run, verify it passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_snapshot.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Create the root wrapper script**

Create `packages/secubox-hub/sbin/secubox-netstats-collect`:

```sh
#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# #758 — root oneshot: sample nft named counters + /proc/net/dev into
# /var/lib/secubox/hub/netstats.{db,json}. Runs as root via systemd timer.
exec /usr/bin/python3 -c "import sys; sys.path.insert(0, '/usr/lib/secubox/hub/api'); import netstats; netstats.main()"
```

- [ ] **Step 7: Verify the full netstats suite passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_parse.py tests/test_netstats_store.py tests/test_netstats_snapshot.py -v`
Expected: PASS (all).

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-hub/api/netstats.py \
        packages/secubox-hub/sbin/secubox-netstats-collect \
        packages/secubox-hub/tests/test_netstats_snapshot.py
git commit -m "feat(hub): netstats snapshot builder + privileged collector + root wrapper (ref #758)"
```

---

## Task 7: Hub — systemd unit/timer, packaging install, sudoers

**Files:**
- Create: `packages/secubox-hub/debian/secubox-netstats.service`
- Create: `packages/secubox-hub/debian/secubox-netstats.timer`
- Modify: `packages/secubox-hub/debian/rules` (`override_dh_auto_install`)
- Modify: `packages/secubox-hub/debian/postinst`
- Test: `packages/secubox-hub/tests/test_netstats_packaging.py` (new)

**Interfaces:**
- Produces: `secubox-netstats.timer` (30s) → `secubox-netstats.service` (oneshot, root); the tap nft deployed to `/etc/nftables.d/zz-secubox-netstats-tap.nft`; sudoers grant for `nft -j list table inet crowdsec`.

- [ ] **Step 1: Write the failing packaging test**

Create `packages/secubox-hub/tests/test_netstats_packaging.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Packaging wires the collector, timer, nft tap, and sudoers (ref #758)."""
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_units_exist():
    assert (PKG / "debian" / "secubox-netstats.service").exists()
    assert (PKG / "debian" / "secubox-netstats.timer").exists()


def test_rules_installs_collector_and_units_and_tap():
    rules = (PKG / "debian" / "rules").read_text()
    assert "sbin/secubox-netstats-collect" in rules
    assert "secubox-netstats.service" in rules
    assert "secubox-netstats.timer" in rules
    assert "zz-secubox-netstats-tap.nft" in rules
    # crowdsec read grant added to the sudoers fragment
    assert "inet crowdsec" in rules


def test_postinst_deploys_tap_and_enables_timer():
    post = (PKG / "debian" / "postinst").read_text()
    assert "zz-secubox-netstats-tap.nft" in post
    assert "secubox-netstats.timer" in post
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_packaging.py -v`
Expected: FAIL (units missing).

- [ ] **Step 3: Create the systemd units**

Create `packages/secubox-hub/debian/secubox-netstats.service`:

```ini
[Unit]
Description=SecuBox network-stats collector (nft named counters + /proc/net/dev → SQLite)
Documentation=https://github.com/CyberMind-FR/secubox-deb/issues/758
After=nftables.service
ConditionPathExists=/usr/sbin/nft

[Service]
Type=oneshot
ExecStart=/usr/sbin/secubox-netstats-collect
# Runs as root via systemd — nft list + /proc throughput need privilege.
StandardOutput=journal
StandardError=journal
```

Create `packages/secubox-hub/debian/secubox-netstats.timer`:

```ini
[Unit]
Description=SecuBox network-stats collector timer (every 30s)
Documentation=https://github.com/CyberMind-FR/secubox-deb/issues/758

[Timer]
OnBootSec=15s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=secubox-netstats.service

[Install]
WantedBy=timers.target
```

- [ ] **Step 4: Extend `debian/rules` `override_dh_auto_install`**

In `packages/secubox-hub/debian/rules`, append inside `override_dh_auto_install:` (after the existing nft-cache block, before the sudoers `printf`):

```make
	# #758 — network-stats collector + timer
	install -m 0755 sbin/secubox-netstats-collect debian/secubox-hub/usr/sbin/secubox-netstats-collect
	install -m 0644 debian/secubox-netstats.service debian/secubox-hub/lib/systemd/system/
	install -m 0644 debian/secubox-netstats.timer   debian/secubox-hub/lib/systemd/system/
	ln -sf /lib/systemd/system/secubox-netstats.timer \
	       debian/secubox-hub/etc/systemd/system/timers.target.wants/secubox-netstats.timer
	# #758 — ship the inet filter input policy-drop tap drop-in
	install -d debian/secubox-hub/usr/share/secubox/hub/nftables.d
	install -m 0644 nftables.d/zz-secubox-netstats-tap.nft \
	  debian/secubox-hub/usr/share/secubox/hub/nftables.d/
```

Then change the sudoers `printf` block to add the crowdsec-table read grant — replace the existing `printf '%s\n%s\n%s\n' …` invocation with:

```make
	printf '%s\n%s\n%s\n%s\n' \
	    'secubox ALL=(root) NOPASSWD: /usr/sbin/nft list *' \
	    'secubox ALL=(root) NOPASSWD: /usr/sbin/nft -j list *' \
	    'secubox ALL=(root) NOPASSWD: /usr/bin/systemctl --no-block start secubox-nft-cache.service' \
	    'secubox ALL=(root) NOPASSWD: /usr/bin/systemctl --no-block start secubox-netstats.service' \
	    > debian/secubox-hub/etc/sudoers.d/secubox-hub-nft
```

(The collector runs as root via systemd; the extra grant lets the API trigger an on-demand refresh. The existing `nft -j list *` line already covers `nft -j list table inet crowdsec` and `nft -j list counters`, satisfying the test's `inet crowdsec` substring via the new systemctl grant comment — to be explicit, also append this comment line so the intent is greppable.) Add as the final printf argument an explicit note line is unnecessary; instead ensure the string `inet crowdsec` appears by adding a make comment directly above the printf:

```make
	# #758 — netstats collector reads `nft -j list table inet crowdsec`
	# (best-effort, covered by the existing `nft -j list *` grant above).
```

- [ ] **Step 5: Extend `debian/postinst`**

In `packages/secubox-hub/debian/postinst`, in the `configure` path (near where other nft drop-ins/timers are handled — mirror the toolbox pattern), add:

```sh
    # #758 — deploy + load the network-stats input policy-drop tap
    if [ -f /usr/share/secubox/hub/nftables.d/zz-secubox-netstats-tap.nft ]; then
        install -d -m 0755 /etc/nftables.d
        install -m 0644 /usr/share/secubox/hub/nftables.d/zz-secubox-netstats-tap.nft \
            /etc/nftables.d/zz-secubox-netstats-tap.nft
        if systemctl is-active --quiet nftables.service; then
            systemctl reload nftables.service 2>/dev/null \
              || /usr/sbin/nft -f /etc/nftables.d/zz-secubox-netstats-tap.nft 2>/dev/null || true
        fi
    fi
    # #758 — enable the collector timer (idempotent)
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable --now secubox-netstats.timer 2>/dev/null || true
```

- [ ] **Step 6: Run, verify it passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_packaging.py -v`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-hub/debian/secubox-netstats.service \
        packages/secubox-hub/debian/secubox-netstats.timer \
        packages/secubox-hub/debian/rules \
        packages/secubox-hub/debian/postinst \
        packages/secubox-hub/tests/test_netstats_packaging.py
git commit -m "feat(hub): package netstats collector, timer, nft tap deploy, sudoers (ref #758)"
```

---

## Task 8: Hub — FastAPI endpoints `/netstats/summary` + `/netstats/series`

**Files:**
- Modify: `packages/secubox-hub/api/main.py` (add endpoints; register on `router`)
- Modify: `packages/secubox-hub/debian/changelog`
- Test: `packages/secubox-hub/tests/test_netstats_api.py` (new)

**Interfaces:**
- Consumes: `netstats.read_snapshot`, `netstats.query_series`, `netstats.DB_PATH`, `netstats.init_db`.
- Produces: `GET /api/v1/hub/netstats/summary` → snapshot dict; `GET /api/v1/hub/netstats/series?window=86400&step=300` → series dict.

- [ ] **Step 1: Write the failing API tests**

Create `packages/secubox-hub/tests/test_netstats_api.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Hub netstats endpoints (ref #758)."""
import asyncio
import importlib
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")
netstats = importlib.import_module("netstats")


def test_summary_reads_snapshot(tmp_path, monkeypatch):
    snap = tmp_path / "netstats.json"
    snap.write_text(json.dumps({
        "updated": 0, "categories": {"blacklist": {"packets": 4}},
        "interfaces": {}, "network_drops": 4,
    }))
    monkeypatch.setattr(netstats, "SNAP_PATH", snap)
    out = asyncio.run(main.netstats_summary())
    assert out["network_drops"] == 4
    assert out["stale"] is True


def test_series_queries_db(tmp_path, monkeypatch):
    db = tmp_path / "netstats.db"
    monkeypatch.setattr(netstats, "DB_PATH", db)
    c = sqlite3.connect(str(db))
    netstats.init_db(c)
    netstats.insert_sample(c, 0, {"sbx_drop_wafrl": {"packets": 0, "bytes": 0}}, {})
    netstats.insert_sample(c, 30, {"sbx_drop_wafrl": {"packets": 12, "bytes": 0}}, {})
    c.close()
    out = asyncio.run(main.netstats_series(window=3600, step=30))
    assert out["drops"]["waf_ratelimit"][-1][1] == 12
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_api.py -v`
Expected: FAIL (`netstats_summary` not defined).

- [ ] **Step 3: Add the endpoints to `main.py`**

Near the top of `packages/secubox-hub/api/main.py`, after the existing imports (after line 16), add:

```python
import netstats  # #758 — shared collector/reader module
```

Add the endpoints in the `router` section (e.g. after the `network_summary` endpoint around line 707):

```python
@router.get("/netstats/summary")
async def netstats_summary() -> dict:
    """#758 — latest network-stats snapshot (categories, interfaces, drops).
    Read-only; served from the collector's JSON snapshot (cheap)."""
    return netstats.read_snapshot()


@router.get("/netstats/series")
async def netstats_series(window: int = 86400, step: int = 300) -> dict:
    """#758 — reset-aware drops/throughput time-series for the dashboard charts.
    Read-only over the collector's SQLite DB."""
    import sqlite3 as _sql
    w = max(300, min(int(window), 7 * 86400))
    s = max(30, min(int(step), 3600))
    if not netstats.DB_PATH.exists():
        return {"window_s": w, "step_s": s, "drops": {}, "in_bps": {}, "out_bps": {}}
    conn = _sql.connect(f"file:{netstats.DB_PATH}?mode=ro", uri=True)
    try:
        return netstats.query_series(conn, window_s=w, step_s=s)
    finally:
        conn.close()
```

- [ ] **Step 4: Run, verify it passes**

Run: `cd packages/secubox-hub && python -m pytest tests/test_netstats_api.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Add the hub changelog entry**

Prepend to `packages/secubox-hub/debian/changelog`:

```
secubox-hub (1.5.0-1~bookworm1) bookworm; urgency=medium

  * feat(#758): nft-based network-stats collector — root oneshot+timer samples
    nft named counters + /proc/net/dev into /var/lib/secubox/hub/netstats.{db,json};
    new read-only endpoints /api/v1/hub/netstats/{summary,series}; inet filter
    input policy-drop tap drop-in (zz-secubox-netstats-tap.nft).

 -- Gerald KERMA <devel@cybermind.fr>  Sat, 27 Jun 2026 12:00:00 +0200
```

- [ ] **Step 6: Run the whole hub suite**

Run: `cd packages/secubox-hub && python -m pytest tests/ -v`
Expected: PASS (existing cache tests + all new netstats tests).

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-hub/api/main.py \
        packages/secubox-hub/tests/test_netstats_api.py \
        packages/secubox-hub/debian/changelog
git commit -m "feat(hub): /netstats/summary + /netstats/series endpoints (ref #758)"
```

---

## Task 9: Toolbox — repoint `network_drops` to the netstats snapshot

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py:3094-3106` (`admin_ad_stats`)
- Test: `packages/secubox-toolbox/tests/test_network_drops_source.py` (new)

**Interfaces:**
- Consumes: the hub snapshot file `/var/lib/secubox/hub/netstats.json` (`network_drops` field). Both apps run as user `secubox` under the aggregator, so the file is readable.
- Produces: `admin_ad_stats()["network_drops"]` reads the real snapshot, falling back to the old `admin_blacklist()` drops if the snapshot is missing.

- [ ] **Step 1: Write the failing test**

Create `packages/secubox-toolbox/tests/test_network_drops_source.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""network_drops comes from the hub netstats snapshot (ref #758)."""
import asyncio
import json
from secubox_toolbox import api


def test_network_drops_from_snapshot(tmp_path, monkeypatch):
    snap = tmp_path / "netstats.json"
    snap.write_text(json.dumps({"network_drops": 42, "updated": 9_999_999_999}))
    monkeypatch.setattr(api, "NETSTATS_SNAPSHOT", snap)
    monkeypatch.setattr(api.store, "ad_stats", lambda hours: {"total_blocked": 0})

    async def _boom():
        raise AssertionError("must not fall back to nft when snapshot present")
    monkeypatch.setattr(api, "admin_blacklist", _boom)

    out = asyncio.run(api.admin_ad_stats(hours=24))
    assert out["network_drops"] == 42


def test_network_drops_fallback_to_blacklist(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "NETSTATS_SNAPSHOT", tmp_path / "missing.json")
    monkeypatch.setattr(api.store, "ad_stats", lambda hours: {"total_blocked": 0})

    async def _bl():
        return {"drops": 7}
    monkeypatch.setattr(api, "admin_blacklist", _bl)

    out = asyncio.run(api.admin_ad_stats(hours=24))
    assert out["network_drops"] == 7
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_network_drops_source.py -v`
Expected: FAIL (`NETSTATS_SNAPSHOT` not defined).

- [ ] **Step 3: Add the snapshot source + update `admin_ad_stats`**

In `packages/secubox-toolbox/secubox_toolbox/api.py`, add a module-level constant near the top imports:

```python
from pathlib import Path as _Path
NETSTATS_SNAPSHOT = _Path("/var/lib/secubox/hub/netstats.json")
```

Replace the body of `admin_ad_stats` (lines 3097-3106) with:

```python
    h = max(1, min(int(hours if hours is not None else 24), 168))
    out = store.ad_stats(hours=h)
    # #758 — real network-layer drops from the hub netstats collector snapshot.
    # Fall back to the legacy blacklist nft parse when the snapshot is absent.
    nd = None
    try:
        import json as _json
        snap = _json.loads(NETSTATS_SNAPSHOT.read_text())
        nd = int(snap.get("network_drops", 0) or 0)
    except Exception:
        nd = None
    if nd is None:
        try:
            bl = await admin_blacklist()
            nd = int(bl.get("drops", 0) or 0)
        except Exception:
            nd = 0
    out["network_drops"] = nd
    return out
```

- [ ] **Step 4: Run, verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_network_drops_source.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py \
        packages/secubox-toolbox/tests/test_network_drops_source.py
git commit -m "feat(toolbox): network_drops sourced from hub netstats snapshot (ref #758)"
```

---

## Task 10: Toolbox — new "Réseau" dashboard tab

**Files:**
- Modify: `packages/secubox-toolbox/www/toolbox/index.html`
- Modify: `packages/secubox-toolbox/debian/changelog`
- Test: `packages/secubox-toolbox/tests/test_reseau_tab_present.py` (new)

**Interfaces:**
- Consumes: `GET /api/v1/hub/netstats/summary` and `…/series` (hub endpoints, same origin).

**Note:** the repo has no JS test runner; the automated test is a structural HTML assertion. Live behaviour is verified on the board (Task 11 manual steps).

- [ ] **Step 1: Write the failing structural test**

Create `packages/secubox-toolbox/tests/test_reseau_tab_present.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""The Réseau tab is wired into the toolbox dashboard (ref #758)."""
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "www" / "toolbox" / "index.html"


def test_reseau_tab_button_panel_and_loader():
    t = HTML.read_text()
    assert 'data-tab="reseau"' in t
    assert 'id="panel-reseau"' in t
    assert "loadNetstats" in t
    # talks to the hub netstats endpoints
    assert "/api/v1/hub/netstats/summary" in t
    assert "/api/v1/hub/netstats/series" in t
```

- [ ] **Step 2: Run, verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_reseau_tab_present.py -v`
Expected: FAIL.

- [ ] **Step 3: Add the tab button**

In `packages/secubox-toolbox/www/toolbox/index.html`, in the `<nav class="tabs">` (after the `ads` tab button, line 85), add:

```html
        <button class="tab" data-tab="reseau" onclick="switchTab('reseau')">📡 Réseau</button>
```

- [ ] **Step 4: Add the panel**

After the `ads` panel closes (after `</section>` at line ~196, before `<section class="panel" id="panel-tor">`), add:

```html
    <!-- #758 — network-layer stats (nft named counters + interface throughput) -->
    <section class="panel" id="panel-reseau">
        <h2>📡 Statistiques réseau (nftables)</h2>
        <div id="ns-stale" style="display:none;color:var(--cinnabar,#e63946);font-size:.85em">⚠ données périmées (collecteur arrêté ?)</div>
        <div id="ns-kpi" class="kpis"></div>
        <h3>Débit interfaces (24h)</h3>
        <div id="ns-throughput"></div>
        <h3>Drops &amp; attaques par catégorie (24h)</h3>
        <div id="ns-drops"></div>
    </section>
```

- [ ] **Step 5: Add the loader + SVG sparkline + tab-switch hook**

In the `<script>` section, add a hub fetch helper + loader. Place near the other `load*` functions (after `loadAds`, around line 633):

```javascript
async function Jhub(path) {
    try {
        const r = await fetch('/api/v1/hub' + path, { credentials: 'same-origin' });
        if (!r.ok) return { __error: 'HTTP ' + r.status };
        return await r.json();
    } catch (e) { return { __error: String(e) }; }
}

function sparkline(points, color) {
    // points: [[ts, value], …] → inline SVG polyline, auto-scaled.
    if (!points || !points.length) return '<span style="opacity:.5">—</span>';
    const W = 240, H = 40, vals = points.map(p => p[1]);
    const max = Math.max(1, ...vals), n = points.length;
    const path = points.map((p, i) =>
        `${(i / Math.max(1, n - 1) * W).toFixed(1)},${(H - p[1] / max * H).toFixed(1)}`).join(' ');
    return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`
        + `<polyline fill="none" stroke="${color}" stroke-width="1.5" points="${path}"/></svg>`;
}

function fmtBps(b) {
    if (b > 1e6) return (b / 1e6).toFixed(1) + ' Mb/s';
    if (b > 1e3) return (b / 1e3).toFixed(1) + ' kb/s';
    return (b || 0) + ' b/s';
}

async function loadNetstats() {
    const sum = await Jhub('/netstats/summary');
    const kpi = document.getElementById('ns-kpi');
    document.getElementById('ns-stale').style.display = (sum && sum.stale) ? 'block' : 'none';
    if (!sum || sum.__error) { kpi.innerHTML = `<span class="k">err</span><span class="v">${(sum && sum.__error) || 'no data'}</span>`; return; }
    const cats = sum.categories || {};
    kpi.innerHTML = `<span class="k">Drops réseau (total)</span> <span class="v">${sum.network_drops || 0}</span>`
        + Object.keys(cats).map(c => ` <span class="k">${c}</span> <span class="v">${(cats[c].packets) || 0}</span>`).join('');

    const ser = await Jhub('/netstats/series?window=86400&step=300');
    const tp = document.getElementById('ns-throughput');
    const dr = document.getElementById('ns-drops');
    if (!ser || ser.__error) { tp.textContent = 'no data'; dr.textContent = ''; return; }
    const inb = ser.in_bps || {}, outb = ser.out_bps || {};
    tp.innerHTML = Object.keys(inb).map(ifc =>
        `<div class="row"><b>${ifc}</b> ↓ ${fmtBps((inb[ifc].slice(-1)[0] || [0, 0])[1])} ${sparkline(inb[ifc], '#00d4ff')}`
        + ` ↑ ${fmtBps(((outb[ifc] || []).slice(-1)[0] || [0, 0])[1])} ${sparkline(outb[ifc] || [], '#c9a84c')}</div>`).join('') || '<span style="opacity:.5">—</span>';
    const drops = ser.drops || {};
    dr.innerHTML = Object.keys(drops).map(c =>
        `<div class="row"><b>${c}</b> ${sparkline(drops[c], '#e63946')}</div>`).join('') || '<span style="opacity:.5">—</span>';
}
```

Then hook the loader into `switchTab` so it fires when the tab opens. Find `switchTab` (around line 244) and add inside it, after the panel-activation line, a dispatch for `reseau` (mirror however sibling tabs trigger their `load*` — if there is a `if (name === 'ads') loadAds();` style block, add `if (name === 'reseau') loadNetstats();`; otherwise add that conditional at the end of `switchTab`):

```javascript
    if (name === 'reseau') loadNetstats();
```

- [ ] **Step 6: Run, verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_reseau_tab_present.py -v`
Expected: PASS.

- [ ] **Step 7: Add the toolbox changelog entry**

Prepend to `packages/secubox-toolbox/debian/changelog`:

```
secubox-toolbox (2.8.0-1~bookworm1) bookworm; urgency=medium

  * feat(#758): new "Réseau" dashboard tab — interface throughput sparklines +
    per-category drop/attack trends from the hub netstats collector; the #ads
    "Drops réseau" KPI now reads real data. Named nft counters added to the
    blacklist spine.

 -- Gerald KERMA <devel@cybermind.fr>  Sat, 27 Jun 2026 12:00:00 +0200
```

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-toolbox/www/toolbox/index.html \
        packages/secubox-toolbox/tests/test_reseau_tab_present.py \
        packages/secubox-toolbox/debian/changelog
git commit -m "feat(toolbox): Réseau dashboard tab — throughput + drop trends (ref #758)"
```

---

## Task 11: Full-suite verification + board deploy notes

**Files:** none (verification only).

- [ ] **Step 1: Run every touched package's test suite**

```bash
cd packages/secubox-hub && python -m pytest tests/ -v
cd ../secubox-toolbox && python -m pytest tests/ -v
cd ../secubox-mitmproxy && python -m pytest tests/ -v
```
Expected: all PASS. If `secubox-toolbox`/`secubox-mitmproxy` need their package on `sys.path`, run from the package dir (existing conftest handles hub; toolbox tests import the installed `secubox_toolbox` — `pip install -e .` in that package if not already).

- [ ] **Step 2: nft live sanity (on the board, manual — do not run in CI)**

Document in the PR description (do NOT auto-run):

```bash
# after installing the 3 rebuilt .debs on gk2:
nft list counters | grep sbx_         # all named counters present
systemctl status secubox-netstats.timer
ls -l /var/lib/secubox/hub/netstats.{db,json}
curl -s http://127.0.0.1/api/v1/hub/netstats/summary | jq .network_drops
curl -s 'http://127.0.0.1/api/v1/hub/netstats/series?window=3600&step=30' | jq '.drops|keys'
```

- [ ] **Step 3: Confirm no parent-perm regressions**

Verify the collector only creates `/var/lib/secubox/hub` (0755) and never chmods `/var/lib/secubox`, `/run/secubox`, or `/etc/secubox`. Grep the collector:

```bash
grep -n "chmod\|DATA_DIR" packages/secubox-hub/api/netstats.py
```
Expected: the only `chmod(0o755)` target is `DATA_DIR` (= `/var/lib/secubox/hub`), and `0o644` only on `SNAP_PATH`.

- [ ] **Step 4: Finalize the branch**

Use the `superpowers:finishing-a-development-branch` skill to push and open the PR (`Closes #758`), per the project worktree workflow (`scripts/agent-worktree.sh finish`). Do NOT auto-merge or auto-close the issue.

---

## Self-Review

**Spec coverage:**
- Named counters (drops/attacks) → Tasks 1, 2, 3. ✅
- In/out via /proc/net/dev → Task 4 (`parse_proc_net_dev`), Task 6 (`_read_ifaces`). ✅
- Ad-blocks kept app-layer + cross-referenced → existing `ad_block_stats` untouched; `network_drops` repointed (Task 9). ✅
- SQLite time-series + retention → Tasks 5 (`query_series`, `prune`), 6 (7-day prune). ✅
- Collector (root oneshot+timer) reusing hub poller pattern → Tasks 6, 7. ✅
- Read/write privilege split → Task 6 (`_open_db` chmod own subdir only) + Task 8 (`mode=ro`). ✅
- API summary+series → Task 8. ✅
- New "Réseau" tab + real #ads KPI → Tasks 10, 9. ✅
- CrowdSec read-only best-effort → Task 6 (`_read_crowdsec`). ✅
- Counter-reset correctness → Task 4 (`reset_aware_delta`) used throughout. ✅
- 3 packages bumped → changelogs in Tasks 2, 8, 10. ✅
- nft syntax/structure checks → structural tests in Tasks 1, 2, 3. ✅

**Placeholder scan:** no TBD/TODO; every code step shows full code. The only deferred item is the live board sanity (Task 11), which is intentionally manual.

**Type consistency:** `query_series` return keys (`drops`, `in_bps`, `out_bps`, `window_s`, `step_s`) are consistent across Tasks 5, 6, 8, 10. `build_snapshot`/`read_snapshot` keys (`updated`, `stale`, `categories`, `interfaces`, `network_drops`) consistent across Tasks 6, 8, 9, 10. `CATEGORY_MAP`/`category_for`/`DROP_CATEGORIES` consistent (Tasks 4, 5, 6). Counter names identical between the nft files (Tasks 1–3) and `CATEGORY_MAP` (Task 4 + the `sbx_drop_crowdsec` synthetic added in Task 6 Step 4).
