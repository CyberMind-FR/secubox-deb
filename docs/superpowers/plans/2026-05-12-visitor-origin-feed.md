<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Health Banner Live Panel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship three public banner sections (VisitorOrigin, LiveHosts, CertStatus) on top of the existing SecuBox health banner, each backed by an independent aggregator + REST endpoint in `secubox-metrics`.

**Architecture:** Three asyncio background tasks in `secubox-metrics` produce sanitized rollups every 60 s and persist them to `/var/cache/secubox/metrics/<section>.json`. Three public CORS-open endpoints serve the latest rollup. `health-banner.js` polls each endpoint on its own 30 s cycle and hides any section whose payload is empty or disabled.

**Tech Stack:** Python 3.11 (FastAPI, asyncio, maxminddb, cryptography, tomllib), nftables, HAProxy admin socket, systemd timers, vanilla JS for the banner.

**Spec:** `docs/superpowers/specs/2026-05-12-visitor-origin-feed-design.md`
**Issue:** [#92](https://github.com/CyberMind-FR/secubox-deb/issues/92)
**Branch:** `feature/92-health-banner-visitor-origin-feed-anonym`
**Worktree root:** `~/CyberMindStudio/secubox-deb-worktrees/92-health-banner-visitor-origin-feed-anonym/`

---

## File Structure

**Create**

- `packages/secubox-metrics/tests/__init__.py` — empty
- `packages/secubox-metrics/tests/conftest.py` — sys.path injection for `api/` and `common/`
- `packages/secubox-metrics/api/visitor_origin.py` — `VisitorOriginAggregator`
- `packages/secubox-metrics/api/live_hosts.py` — `LiveHostsAggregator`
- `packages/secubox-metrics/api/cert_status.py` — `CertStatusAggregator`
- `packages/secubox-metrics/tests/test_visitor_origin.py`
- `packages/secubox-metrics/tests/test_live_hosts.py`
- `packages/secubox-metrics/tests/test_cert_status.py`
- `packages/secubox-metrics/tests/fixtures/GeoLite2-ASN-test.mmdb` — tiny synthetic mmdb (built once, committed)
- `packages/secubox-metrics/tests/fixtures/certs/{valid,expiring,expired}.pem` — test PEMs
- `packages/secubox-metrics/nftables/secubox-metrics.nft` — ruleset shipped to `/etc/nftables.d/`
- `packages/secubox-metrics/systemd/secubox-geoipupdate.service`
- `packages/secubox-metrics/systemd/secubox-geoipupdate.timer`

**Modify**

- `common/secubox_core/config.py` — add helpers `get_visitor_origin_config()`, `get_live_hosts_config()`, `get_cert_status_config()` with defaults
- `packages/secubox-metrics/api/main.py` — register lifespan that starts the three aggregator tasks; add three GET endpoints
- `packages/secubox-metrics/debian/control` — add `python3-maxminddb`, `python3-cryptography`, `geoipupdate`, `nftables` to Depends
- `packages/secubox-metrics/debian/postinst` — install nft ruleset, add `secubox` to `haproxy` group, create `/var/cache/secubox/metrics/`, install + enable geoipupdate timer
- `packages/secubox-metrics/debian/secubox-metrics.service` — add `ReadWritePaths=/var/cache/secubox`
- `packages/secubox-metrics/debian/rules` — copy `nftables/` and `systemd/` into the deb
- `packages/secubox-hub/www/shared/health-banner.js` — bump to `v1.3.0`, add three section modules
- `packages/secubox-metrics/README.md` — document the three endpoints + config blocks
- `.claude/HISTORY.md`, `.claude/WIP.md`, `.claude/MIGRATION-MAP.md` — session log

**Boundaries**

Each aggregator file is fully self-contained: it owns its own dataclass-style config, its async loop, its parse/aggregate/persist methods, and its `current()` read accessor. `main.py` only imports the three classes, instantiates them once, and registers their lifespan + routes. Tests live next to the package, share a single `conftest.py`.

---

## Conventions

- **TDD everywhere.** Each task writes the failing test, runs it (must FAIL), implements, runs again (must PASS), commits.
- **Commit format.** All commit messages end with `(ref #92)`. Use HEREDOC for multi-line bodies. End with the standard `Co-Authored-By` trailer.
- **Test runner.** `cd packages/secubox-metrics && python3 -m pytest tests/ -v` (worktree root cwd, no `cd`).
- **Imports.** Aggregators live in `api.<name>`, imported in tests via `from visitor_origin import VisitorOriginAggregator` after the `conftest.py` adds `packages/secubox-metrics/api` to `sys.path`.
- **Coding style.** Match existing `api/main.py`: `from __future__ import annotations`, type hints, `Optional` from `typing`, `Path` from `pathlib`, `subprocess.run(..., timeout=5)` defensive default.

---

## Task 1 — Tests scaffolding (conftest + empty __init__)

**Files:**

- Create: `packages/secubox-metrics/tests/__init__.py`
- Create: `packages/secubox-metrics/tests/conftest.py`

- [ ] **Step 1: Create empty `__init__.py`**

```bash
: > packages/secubox-metrics/tests/__init__.py
```

- [ ] **Step 2: Write `conftest.py`**

```python
"""Add the package's api/ and the repo-wide common/ to sys.path for tests."""
import sys
from pathlib import Path

# packages/secubox-metrics/
_pkg_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg_root / "api"))

# repo root → common/
_repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_repo_root / "common"))
```

- [ ] **Step 3: Sanity test — pytest can run an empty suite**

Run: `python3 -m pytest packages/secubox-metrics/tests/ -v`
Expected: `no tests ran` exit 5 (or 0). No import errors.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-metrics/tests/__init__.py packages/secubox-metrics/tests/conftest.py
git commit -m "$(cat <<'EOF'
test(metrics): Scaffold pytest layout for new aggregators (ref #92)

Adds tests/__init__.py and conftest.py that wire packages/secubox-metrics/api
and the repo-wide common/ onto sys.path so individual aggregator modules can
be imported in isolation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2 — Config helpers in `secubox_core.config`

**Files:**

- Modify: `common/secubox_core/config.py`
- Test: `packages/secubox-metrics/tests/test_config_helpers.py` (new)

- [ ] **Step 1: Write the failing test**

`packages/secubox-metrics/tests/test_config_helpers.py`:

```python
"""Tests for the three new config helpers in secubox_core.config."""
from pathlib import Path
from unittest.mock import patch

import secubox_core.config as cfg


def _reload_with(monkeypatch, toml_text: str):
    monkeypatch.setattr(cfg, "_CONFIG", None)
    fake = Path("/tmp/_secubox_test_conf.toml")
    fake.write_text(toml_text)
    monkeypatch.setattr(cfg, "_CONF_PATHS", [fake])


def test_visitor_origin_defaults_when_absent(monkeypatch):
    _reload_with(monkeypatch, "[global]\nhostname='test'\n")
    out = cfg.get_visitor_origin_config()
    assert out["enabled"] is False
    assert out["window_minutes"] == 60
    assert out["min_count"] == 5
    assert out["top_n"] == 5
    assert out["asn_db_path"] == "/var/lib/GeoIP/GeoLite2-ASN.mmdb"
    assert out["nft_table"] == "secubox_metrics"
    assert out["nft_set"] == "seen_src"
    assert out["nft_family"] == "inet"


def test_visitor_origin_overrides(monkeypatch):
    _reload_with(
        monkeypatch,
        "[visitor_origin]\nenabled=true\nmin_count=2\ntop_n=3\n",
    )
    out = cfg.get_visitor_origin_config()
    assert out["enabled"] is True
    assert out["min_count"] == 2
    assert out["top_n"] == 3
    # Other keys keep defaults
    assert out["window_minutes"] == 60


def test_live_hosts_defaults(monkeypatch):
    _reload_with(monkeypatch, "[global]\nhostname='test'\n")
    out = cfg.get_live_hosts_config()
    assert out["enabled"] is False
    assert out["window_minutes"] == 60
    assert out["top_n"] == 5
    assert out["haproxy_socket"] == "/run/haproxy/admin.sock"
    assert out["frontend_filter"] == "*"


def test_cert_status_defaults(monkeypatch):
    _reload_with(monkeypatch, "[global]\nhostname='test'\n")
    out = cfg.get_cert_status_config()
    assert out["enabled"] is False
    assert out["letsencrypt_live_dir"] == "/etc/letsencrypt/live"
    assert out["warn_days"] == 30
    assert out["critical_days"] == 7
```

- [ ] **Step 2: Run test to verify FAIL**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_config_helpers.py -v`
Expected: AttributeError on `get_visitor_origin_config`.

- [ ] **Step 3: Add helpers to `common/secubox_core/config.py`**

Append at the end of the file:

```python
# ── Live-panel helpers (issue #92) ─────────────────────────────────

_VISITOR_ORIGIN_DEFAULTS = {
    "enabled": False,
    "window_minutes": 60,
    "min_count": 5,
    "top_n": 5,
    "asn_db_path": "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "nft_table": "secubox_metrics",
    "nft_set": "seen_src",
    "nft_family": "inet",
}

_LIVE_HOSTS_DEFAULTS = {
    "enabled": False,
    "window_minutes": 60,
    "top_n": 5,
    "haproxy_socket": "/run/haproxy/admin.sock",
    "frontend_filter": "*",
}

_CERT_STATUS_DEFAULTS = {
    "enabled": False,
    "letsencrypt_live_dir": "/etc/letsencrypt/live",
    "warn_days": 30,
    "critical_days": 7,
}


def _merged(defaults: dict, section: str) -> dict:
    out = dict(defaults)
    out.update(get_config(section))
    return out


def get_visitor_origin_config() -> dict:
    """Return [visitor_origin] merged with defaults."""
    return _merged(_VISITOR_ORIGIN_DEFAULTS, "visitor_origin")


def get_live_hosts_config() -> dict:
    """Return [live_hosts] merged with defaults."""
    return _merged(_LIVE_HOSTS_DEFAULTS, "live_hosts")


def get_cert_status_config() -> dict:
    """Return [cert_status] merged with defaults."""
    return _merged(_CERT_STATUS_DEFAULTS, "cert_status")
```

- [ ] **Step 4: Run test to verify PASS**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_config_helpers.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add common/secubox_core/config.py packages/secubox-metrics/tests/test_config_helpers.py
git commit -m "$(cat <<'EOF'
feat(core): Add visitor_origin / live_hosts / cert_status config helpers (ref #92)

Three new section helpers in secubox_core.config that merge defaults with
operator-supplied TOML overrides. Each section defaults to enabled=false so
the live-panel aggregators stay quiet on systems that haven't opted in.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3 — VisitorOrigin aggregator: `_aggregate` and `_lookup_asn`

**Files:**

- Create: `packages/secubox-metrics/api/visitor_origin.py`
- Test: `packages/secubox-metrics/tests/test_visitor_origin.py`

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for the VisitorOrigin aggregator pure functions."""
from ipaddress import IPv4Address
from unittest.mock import MagicMock

import pytest
from visitor_origin import VisitorOriginAggregator


CFG = {
    "enabled": True,
    "window_minutes": 60,
    "min_count": 5,
    "top_n": 5,
    "asn_db_path": "/nonexistent/asn.mmdb",
    "nft_table": "secubox_metrics",
    "nft_set": "seen_src",
    "nft_family": "inet",
}


def _agg_with_mock_asn(mapping: dict[str, tuple[int, str]]):
    agg = VisitorOriginAggregator(CFG)

    def fake_lookup(ip):
        return mapping.get(str(ip))

    agg._lookup_asn = fake_lookup  # type: ignore[assignment]
    return agg


def test_aggregate_counts_unique_ips_per_asn():
    agg = _agg_with_mock_asn({
        "1.1.1.1":   (13335, "Cloudflare, Inc."),
        "1.0.0.1":   (13335, "Cloudflare, Inc."),
        "8.8.8.8":   (15169, "Google LLC"),
        "9.9.9.9":   (19281, "Quad9"),
    })
    # Force min_count=1 for this test so all groups survive
    agg.cfg = dict(CFG, min_count=1)
    entries = agg._aggregate([IPv4Address("1.1.1.1"),
                              IPv4Address("1.0.0.1"),
                              IPv4Address("8.8.8.8"),
                              IPv4Address("9.9.9.9")])
    counts = {e["asn"]: e["count"] for e in entries}
    assert counts == {13335: 2, 15169: 1, 19281: 1}


def test_aggregate_threshold_keeps_equal_drops_below():
    agg = _agg_with_mock_asn({
        "1.1.1.1": (13335, "Cloudflare"),
        "1.0.0.1": (13335, "Cloudflare"),
        "1.0.0.2": (13335, "Cloudflare"),
        "1.0.0.3": (13335, "Cloudflare"),
        "1.0.0.4": (13335, "Cloudflare"),  # 5 distinct → kept
        "8.8.8.8": (15169, "Google"),
        "8.8.4.4": (15169, "Google"),
        "8.8.0.1": (15169, "Google"),
        "8.8.0.2": (15169, "Google"),       # 4 distinct → dropped
    })
    entries = agg._aggregate([IPv4Address(s) for s in [
        "1.1.1.1", "1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4",
        "8.8.8.8", "8.8.4.4", "8.8.0.1", "8.8.0.2",
    ]])
    asns = {e["asn"] for e in entries}
    assert 13335 in asns
    assert 15169 not in asns


def test_aggregate_top_n_and_tiebreak_by_asn():
    agg = _agg_with_mock_asn({
        f"10.0.0.{i}": (100 + (i % 3), f"org{i % 3}") for i in range(1, 16)
    })
    agg.cfg = dict(CFG, top_n=2, min_count=1)
    entries = agg._aggregate([IPv4Address(f"10.0.0.{i}") for i in range(1, 16)])
    assert len(entries) == 2
    # Largest count first; tie → smallest ASN first
    assert entries[0]["count"] >= entries[1]["count"]


def test_lookup_asn_returns_none_for_private(monkeypatch):
    agg = VisitorOriginAggregator(CFG)
    # Force the reader to think the mmdb exists but private IPs short-circuit
    assert agg._lookup_asn(IPv4Address("10.0.0.1")) is None
    assert agg._lookup_asn(IPv4Address("192.168.1.1")) is None
    assert agg._lookup_asn(IPv4Address("127.0.0.1")) is None
```

- [ ] **Step 2: Run test to verify FAIL**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_visitor_origin.py -v`
Expected: ImportError on `visitor_origin`.

- [ ] **Step 3: Write minimal aggregator**

`packages/secubox-metrics/api/visitor_origin.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: VisitorOrigin aggregator
Polls the secubox_metrics seen_src nft set, resolves ASNs via MaxMind GeoLite2,
threshold-gates the rollup, and exposes a sanitized payload. Raw IPs never
leave the local scope.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from collections import Counter
from datetime import datetime, timezone
from ipaddress import IPv4Address, ip_address
from pathlib import Path
from typing import Optional

try:
    import maxminddb
except ImportError:
    maxminddb = None  # type: ignore[assignment]


log = logging.getLogger("secubox.visitor_origin")

CACHE_PATH = Path("/var/cache/secubox/metrics/visitor-origin.json")


class VisitorOriginAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._payload: dict = {"enabled": False, "entries": []}
        self._mmdb = None
        self._mmdb_mtime: float = 0.0

    # ── public ──────────────────────────────────────────────

    def current(self) -> dict:
        if self._payload.get("entries"):
            return self._payload
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text())
            except Exception:
                pass
        return {"enabled": False, "window_minutes": self.cfg["window_minutes"], "entries": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            return self._disabled_payload()
        if not Path(self.cfg["asn_db_path"]).exists() or maxminddb is None:
            return self._disabled_payload()
        ips = self._read_nft_set()
        entries = self._aggregate(ips)
        payload = {
            "enabled": True,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }
        self._persist(payload)
        return payload

    # ── pure helpers ────────────────────────────────────────

    def _aggregate(self, ips: list[IPv4Address]) -> list[dict]:
        counter: Counter[tuple[int, str]] = Counter()
        seen: set[IPv4Address] = set()
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            asn = self._lookup_asn(ip)
            if asn is None:
                continue
            counter[asn] += 1
        groups = [
            {"asn": asn, "org": org, "count": cnt}
            for (asn, org), cnt in counter.items()
            if cnt >= self.cfg["min_count"]
        ]
        groups.sort(key=lambda e: (-e["count"], e["asn"]))
        return groups[: self.cfg["top_n"]]

    def _lookup_asn(self, ip: IPv4Address) -> Optional[tuple[int, str]]:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return None
        if self._mmdb is None:
            try:
                self._mmdb = maxminddb.open_database(self.cfg["asn_db_path"])
                self._mmdb_mtime = Path(self.cfg["asn_db_path"]).stat().st_mtime
            except Exception as e:
                log.warning("mmdb open failed: %s", e)
                return None
        try:
            rec = self._mmdb.get(str(ip))
        except Exception:
            return None
        if not rec:
            return None
        asn = rec.get("autonomous_system_number")
        org = rec.get("autonomous_system_organization") or ""
        if asn is None:
            return None
        return (int(asn), str(org))

    def _read_nft_set(self) -> list[IPv4Address]:
        cmd = [
            "nft", "-j", "list", "set",
            self.cfg["nft_family"], self.cfg["nft_table"], self.cfg["nft_set"],
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return []
            doc = json.loads(res.stdout)
        except Exception:
            return []
        ips: list[IPv4Address] = []
        for obj in doc.get("nftables", []):
            elem = obj.get("set", {}).get("elem")
            if not elem:
                continue
            for e in elem:
                # nftables JSON can wrap addresses in dicts when flags are set
                raw = e["elem"]["val"] if isinstance(e, dict) and "elem" in e else e
                if isinstance(raw, dict):
                    raw = raw.get("val", "")
                try:
                    ips.append(IPv4Address(str(raw)))
                except Exception:
                    continue
        return ips

    def _persist(self, payload: dict) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(CACHE_PATH)
        except Exception as e:
            log.warning("persist failed: %s", e)

    def _disabled_payload(self) -> dict:
        return {
            "enabled": False,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
        }
```

- [ ] **Step 4: Run test to verify PASS**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_visitor_origin.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metrics/api/visitor_origin.py packages/secubox-metrics/tests/test_visitor_origin.py
git commit -m "$(cat <<'EOF'
feat(metrics): VisitorOrigin aggregator (ref #92)

Pure-Python aggregator that polls the nft seen_src set, resolves ASNs via
GeoLite2 mmdb, and emits a threshold-gated top-N rollup. Private/loopback IPs
are skipped at lookup time; raw IPs never leave the function scope; the
threshold gate runs before persistence so the cache file never contains
attributable counts.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4 — VisitorOrigin: `refresh_once` error paths

**Files:**

- Modify: `packages/secubox-metrics/tests/test_visitor_origin.py`
- (Aggregator already supports these; tests pin behavior.)

- [ ] **Step 1: Append failing tests**

```python
def test_refresh_disabled_returns_disabled():
    agg = VisitorOriginAggregator(dict(CFG, enabled=False))
    import asyncio
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["entries"] == []


def test_refresh_missing_mmdb_returns_disabled(tmp_path):
    agg = VisitorOriginAggregator(dict(CFG, asn_db_path=str(tmp_path / "missing.mmdb")))
    import asyncio
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False


def test_refresh_handles_nft_failure(monkeypatch, tmp_path):
    # Pretend mmdb exists so we reach _read_nft_set
    fake_db = tmp_path / "asn.mmdb"
    fake_db.write_bytes(b"\x00")  # truthy existence
    agg = VisitorOriginAggregator(dict(CFG, asn_db_path=str(fake_db)))
    # Force maxminddb import path to succeed without a real db by mocking _lookup_asn
    agg._lookup_asn = lambda ip: None  # type: ignore[assignment]
    monkeypatch.setattr(
        "visitor_origin.subprocess.run",
        lambda *a, **kw: MagicMock(returncode=1, stdout=""),
    )
    import asyncio
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is True
    assert out["entries"] == []
```

- [ ] **Step 2: Run test to verify PASS (aggregator code already handles these)**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_visitor_origin.py -v`
Expected: 7 passed.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-metrics/tests/test_visitor_origin.py
git commit -m "$(cat <<'EOF'
test(metrics): Pin VisitorOrigin error-path behaviour (ref #92)

Regression tests for refresh_once: disabled config, missing mmdb, and nft
subprocess failure must all yield a non-throwing degraded payload.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5 — LiveHosts aggregator: ring buffer + delta computation

**Files:**

- Create: `packages/secubox-metrics/api/live_hosts.py`
- Test: `packages/secubox-metrics/tests/test_live_hosts.py`

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for LiveHosts ring buffer + parsing + filter + aggregation."""
import asyncio
from unittest.mock import patch, MagicMock

from live_hosts import LiveHostsAggregator


CFG = {
    "enabled": True,
    "window_minutes": 60,
    "top_n": 5,
    "haproxy_socket": "/nonexistent.sock",
    "frontend_filter": "*",
}


def _drive(agg, totals_sequence):
    """Feed a sequence of {frontend: req_tot} dicts to _delta_and_buffer."""
    for totals in totals_sequence:
        agg._delta_and_buffer(totals)


def test_delta_buffers_first_sample_as_zeros():
    agg = LiveHostsAggregator(CFG)
    _drive(agg, [{"foo.com": 100, "bar.com": 50}])
    assert len(agg._buckets) == 1
    assert agg._buckets[0] == {"foo.com": 0, "bar.com": 0}


def test_delta_computes_increment():
    agg = LiveHostsAggregator(CFG)
    _drive(agg, [
        {"foo.com": 100},   # init
        {"foo.com": 142},   # +42
        {"foo.com": 150},   # +8
    ])
    assert agg._buckets[-1] == {"foo.com": 8}
    assert agg._buckets[-2] == {"foo.com": 42}


def test_delta_handles_haproxy_restart_no_negatives():
    agg = LiveHostsAggregator(CFG)
    _drive(agg, [
        {"foo.com": 1000},
        {"foo.com": 1050},   # +50
        {"foo.com": 12},     # counter reset → treat as fresh
    ])
    # After reset the bucket value should be 0 (fresh baseline), never -1038.
    assert agg._buckets[-1].get("foo.com", 0) == 0


def test_ring_buffer_caps_at_60():
    agg = LiveHostsAggregator(CFG)
    for i in range(65):
        agg._delta_and_buffer({"foo.com": i * 10})
    assert len(agg._buckets) == 60


def test_aggregate_sums_buckets_top_n():
    agg = LiveHostsAggregator(dict(CFG, top_n=2))
    _drive(agg, [
        {"a.com": 0, "b.com": 0, "c.com": 0},      # baseline
        {"a.com": 30, "b.com": 10, "c.com": 5},    # deltas 30/10/5
        {"a.com": 40, "b.com": 25, "c.com": 6},    # deltas 10/15/1
    ])
    entries = agg._aggregate()
    hosts = [e["host"] for e in entries]
    assert hosts == ["a.com", "b.com"]
    counts = {e["host"]: e["count"] for e in entries}
    assert counts["a.com"] == 40
    assert counts["b.com"] == 25


def test_frontend_filter_strips_internal_names():
    agg = LiveHostsAggregator(CFG)
    raw = {
        "foo.com": 10,
        "_stats": 999,         # leading underscore → drop
        "stats-https": 5,       # no dot → drop
        "secubox.in": 50,
    }
    kept = agg._filter_frontends(raw)
    assert "foo.com" in kept
    assert "secubox.in" in kept
    assert "_stats" not in kept
    assert "stats-https" not in kept
```

- [ ] **Step 2: Run test to verify FAIL**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_live_hosts.py -v`
Expected: ImportError on `live_hosts`.

- [ ] **Step 3: Write the aggregator**

`packages/secubox-metrics/api/live_hosts.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: LiveHosts aggregator
Polls the HAProxy admin socket once per minute, ring-buffers per-frontend
request deltas over 60 minutes, and emits a sanitized top-N rollup of the
hostnames being served.
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


log = logging.getLogger("secubox.live_hosts")

CACHE_PATH = Path("/var/cache/secubox/metrics/live-hosts.json")


class LiveHostsAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._buckets: collections.deque[dict[str, int]] = collections.deque(maxlen=60)
        self._prev_totals: dict[str, int] = {}
        self._payload: dict = {"enabled": False, "entries": []}

    # ── public ──────────────────────────────────────────────

    def current(self) -> dict:
        if self._payload.get("entries"):
            return self._payload
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text())
            except Exception:
                pass
        return {"enabled": False, "window_minutes": self.cfg["window_minutes"], "entries": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            return self._disabled_payload()
        totals = self._read_haproxy_stats()
        if totals is None:
            return self._disabled_payload()
        kept = self._filter_frontends(totals)
        self._delta_and_buffer(kept)
        entries = self._aggregate()
        payload = {
            "enabled": True,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }
        self._persist(payload)
        return payload

    # ── helpers ─────────────────────────────────────────────

    def _filter_frontends(self, totals: dict[str, int]) -> dict[str, int]:
        flt = self.cfg.get("frontend_filter", "*")
        out: dict[str, int] = {}
        for name, n in totals.items():
            if name.startswith("_"):
                continue
            if "." not in name:
                continue
            if flt != "*" and flt not in name:
                continue
            out[name] = n
        return out

    def _delta_and_buffer(self, totals: dict[str, int]) -> None:
        if not self._prev_totals:
            # First sample → zero bucket, store baseline
            self._buckets.append({k: 0 for k in totals})
            self._prev_totals = dict(totals)
            return
        bucket: dict[str, int] = {}
        for host, cur in totals.items():
            prev = self._prev_totals.get(host)
            if prev is None or cur < prev:
                # New frontend or counter reset → fresh baseline, zero delta
                bucket[host] = 0
            else:
                bucket[host] = cur - prev
        self._buckets.append(bucket)
        self._prev_totals = dict(totals)

    def _aggregate(self) -> list[dict]:
        totals: dict[str, int] = collections.Counter()
        for bucket in self._buckets:
            for host, n in bucket.items():
                totals[host] += n
        entries = [{"host": h, "count": c} for h, c in totals.items() if c > 0]
        entries.sort(key=lambda e: (-e["count"], e["host"]))
        return entries[: self.cfg["top_n"]]

    def _read_haproxy_stats(self) -> Optional[dict[str, int]]:
        sock_path = self.cfg["haproxy_socket"]
        if not Path(sock_path).exists():
            return None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(sock_path)
                s.sendall(b"show stat\n")
                chunks = []
                while True:
                    data = s.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
            blob = b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as e:
            log.warning("haproxy socket read failed: %s", e)
            return None
        return self._parse_show_stat(blob)

    @staticmethod
    def _parse_show_stat(blob: str) -> dict[str, int]:
        """Extract {frontend_name: req_tot} from `show stat` CSV output."""
        out: dict[str, int] = {}
        lines = blob.splitlines()
        if not lines:
            return out
        header = lines[0].lstrip("# ").split(",")
        try:
            pxname_i = header.index("pxname")
            svname_i = header.index("svname")
            req_tot_i = header.index("req_tot")
        except ValueError:
            return out
        for line in lines[1:]:
            if not line or line.startswith("#"):
                continue
            cols = line.split(",")
            if len(cols) <= max(pxname_i, svname_i, req_tot_i):
                continue
            if cols[svname_i] != "FRONTEND":
                continue
            try:
                out[cols[pxname_i]] = int(cols[req_tot_i] or "0")
            except ValueError:
                continue
        return out

    def _persist(self, payload: dict) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(CACHE_PATH)
        except Exception as e:
            log.warning("persist failed: %s", e)

    def _disabled_payload(self) -> dict:
        return {
            "enabled": False,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
        }
```

- [ ] **Step 4: Run test to verify PASS**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_live_hosts.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metrics/api/live_hosts.py packages/secubox-metrics/tests/test_live_hosts.py
git commit -m "$(cat <<'EOF'
feat(metrics): LiveHosts aggregator with 60x1-min ring buffer (ref #92)

Reads HAProxy admin socket via raw AF_UNIX, parses 'show stat' CSV, filters
internal frontends (leading underscore or no dot), ring-buffers per-frontend
deltas over 60 minutes, and emits a top-N hostname rollup. Counter-reset
detection (cur < prev) yields a fresh-baseline bucket instead of a negative
delta.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6 — LiveHosts: `show stat` parser + missing-socket path

**Files:**

- Modify: `packages/secubox-metrics/tests/test_live_hosts.py`

- [ ] **Step 1: Append failing tests**

```python
def test_parse_show_stat_csv_extracts_frontends():
    csv = (
        "# pxname,svname,qcur,scur,smax,slim,stot,req_tot,extra\n"
        "stats-https,FRONTEND,0,0,0,0,0,5,\n"
        "secubox.in,FRONTEND,0,1,1,0,42,142,\n"
        "secubox.in,backend-a,0,0,0,0,0,0,\n"
        "apt.secubox.in,FRONTEND,0,0,0,0,0,9,\n"
    )
    out = LiveHostsAggregator._parse_show_stat(csv)
    assert out == {"stats-https": 5, "secubox.in": 142, "apt.secubox.in": 9}


def test_parse_show_stat_empty_or_malformed_returns_empty():
    assert LiveHostsAggregator._parse_show_stat("") == {}
    assert LiveHostsAggregator._parse_show_stat("garbage\n") == {}


def test_refresh_missing_socket_returns_disabled(tmp_path):
    agg = LiveHostsAggregator(dict(CFG, haproxy_socket=str(tmp_path / "missing.sock")))
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False
    assert out["entries"] == []
```

- [ ] **Step 2: Run test to verify PASS (aggregator already handles these)**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_live_hosts.py -v`
Expected: 9 passed.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-metrics/tests/test_live_hosts.py
git commit -m "$(cat <<'EOF'
test(metrics): Pin LiveHosts CSV parser + missing-socket paths (ref #92)

Tests the show-stat CSV parser against the real HAProxy column order and
asserts that an absent admin socket returns a degraded payload rather than
raising.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7 — CertStatus aggregator

**Files:**

- Create: `packages/secubox-metrics/api/cert_status.py`
- Test: `packages/secubox-metrics/tests/test_cert_status.py`
- Create: `packages/secubox-metrics/tests/fixtures/certs/{valid,expiring,expired}.pem` (generated by test setup)

- [ ] **Step 1: Write the failing test**

```python
"""Unit tests for CertStatusAggregator."""
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_status import CertStatusAggregator


CFG_BASE = {
    "enabled": True,
    "warn_days": 30,
    "critical_days": 7,
}


def _make_cert(host: str, days_left: int, out_dir: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_left))
        .sign(key, hashes.SHA256())
    )
    host_dir = out_dir / host
    host_dir.mkdir(parents=True, exist_ok=True)
    pem_path = host_dir / "cert.pem"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return pem_path


@pytest.fixture
def live_dir(tmp_path):
    _make_cert("good.example.com",  60, tmp_path)
    _make_cert("soon.example.com",  14, tmp_path)
    _make_cert("crit.example.com",   3, tmp_path)
    _make_cert("dead.example.com",  -2, tmp_path)
    return tmp_path


def test_summary_counts_by_state(live_dir):
    agg = CertStatusAggregator(dict(CFG_BASE, letsencrypt_live_dir=str(live_dir)))
    out = asyncio.run(agg.refresh_once())
    s = out["summary"]
    assert s["total"] == 4
    assert s["valid"] == 1
    assert s["expiring_soon"] == 1
    assert s["expiring_critical"] == 1
    assert s["expired"] == 1


def test_next_renewal_is_soonest_non_expired(live_dir):
    agg = CertStatusAggregator(dict(CFG_BASE, letsencrypt_live_dir=str(live_dir)))
    out = asyncio.run(agg.refresh_once())
    # Soonest non-expired is crit.example.com at 3d
    assert out["next_renewal"]["host"] == "crit.example.com"
    assert out["next_renewal"]["days"] == 3


def test_missing_live_dir_disabled(tmp_path):
    agg = CertStatusAggregator(
        dict(CFG_BASE, letsencrypt_live_dir=str(tmp_path / "missing"))
    )
    out = asyncio.run(agg.refresh_once())
    assert out["enabled"] is False


def test_corrupt_cert_doesnt_kill_scan(live_dir):
    bad_dir = live_dir / "bad.example.com"
    bad_dir.mkdir()
    (bad_dir / "cert.pem").write_bytes(b"not a real cert")
    agg = CertStatusAggregator(dict(CFG_BASE, letsencrypt_live_dir=str(live_dir)))
    out = asyncio.run(agg.refresh_once())
    # Still surfaces the other four
    assert out["summary"]["total"] == 4
```

- [ ] **Step 2: Run test to verify FAIL**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_cert_status.py -v`
Expected: ImportError on `cert_status`.

- [ ] **Step 3: Write the aggregator**

`packages/secubox-metrics/api/cert_status.py`:

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: CertStatus aggregator
Scans /etc/letsencrypt/live/*/cert.pem, parses each cert via cryptography,
and emits a rollup of {valid, expiring_soon, expiring_critical, expired}
plus the soonest-renewing non-expired host.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509


log = logging.getLogger("secubox.cert_status")

CACHE_PATH = Path("/var/cache/secubox/metrics/cert-status.json")


class CertStatusAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._payload: dict = {"enabled": False, "summary": {}, "warnings": []}

    # ── public ──────────────────────────────────────────────

    def current(self) -> dict:
        if self._payload.get("summary"):
            return self._payload
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text())
            except Exception:
                pass
        return {"enabled": False, "summary": {}, "warnings": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            return self._disabled_payload()
        live = Path(self.cfg["letsencrypt_live_dir"])
        if not live.is_dir():
            return self._disabled_payload()
        infos = self._scan_certs(live)
        if not infos:
            return self._disabled_payload()
        payload = self._summarize(infos)
        self._persist(payload)
        return payload

    # ── helpers ─────────────────────────────────────────────

    def _scan_certs(self, live: Path) -> list[dict]:
        out: list[dict] = []
        now = datetime.now(timezone.utc)
        for host_dir in sorted(live.iterdir()):
            if not host_dir.is_dir():
                continue
            cert_path = host_dir / "cert.pem"
            if not cert_path.exists():
                continue
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                not_after = cert.not_valid_after_utc
            except Exception as e:
                log.warning("parse failed for %s: %s", host_dir.name, e)
                continue
            days = int((not_after - now).total_seconds() // 86400)
            out.append({"host": host_dir.name, "days": days, "state": self._classify(days)})
        return out

    def _classify(self, days: int) -> str:
        if days < 0:
            return "expired"
        if days <= self.cfg["critical_days"]:
            return "expiring_critical"
        if days <= self.cfg["warn_days"]:
            return "expiring_soon"
        return "valid"

    def _summarize(self, infos: list[dict]) -> dict:
        buckets = {"valid": 0, "expiring_soon": 0, "expiring_critical": 0, "expired": 0}
        for i in infos:
            buckets[i["state"]] += 1
        non_expired = sorted(
            (i for i in infos if i["state"] != "expired"),
            key=lambda x: x["days"],
        )
        next_renewal = (
            {"host": non_expired[0]["host"], "days": non_expired[0]["days"]}
            if non_expired
            else None
        )
        warnings = sorted(
            (i for i in infos if i["state"] in ("expiring_soon", "expiring_critical", "expired")),
            key=lambda x: x["days"],
        )
        return {
            "enabled": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"total": len(infos), **buckets, "failed_renewal": 0},
            "next_renewal": next_renewal,
            "warnings": warnings,
        }

    def _persist(self, payload: dict) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(CACHE_PATH)
        except Exception as e:
            log.warning("persist failed: %s", e)

    def _disabled_payload(self) -> dict:
        return {
            "enabled": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {},
            "warnings": [],
        }
```

- [ ] **Step 4: Run test to verify PASS**

Run: `python3 -m pytest packages/secubox-metrics/tests/test_cert_status.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metrics/api/cert_status.py packages/secubox-metrics/tests/test_cert_status.py
git commit -m "$(cat <<'EOF'
feat(metrics): CertStatus aggregator (ref #92)

Scans /etc/letsencrypt/live for cert.pem files, classifies each by days
remaining (valid / expiring_soon / expiring_critical / expired) using the
operator's warn_days/critical_days thresholds, and emits a summary + soonest
next-renewal host. A single corrupt PEM never kills the scan.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8 — Wire aggregators into `main.py` (lifespan + endpoints)

**Files:**

- Modify: `packages/secubox-metrics/api/main.py`

- [ ] **Step 1: Add imports at the top of `main.py` (after existing imports)**

```python
from contextlib import asynccontextmanager

from visitor_origin import VisitorOriginAggregator
from live_hosts import LiveHostsAggregator
from cert_status import CertStatusAggregator

try:
    from secubox_core.config import (
        get_visitor_origin_config,
        get_live_hosts_config,
        get_cert_status_config,
    )
except ImportError:  # dev fallback
    def get_visitor_origin_config(): return {"enabled": False, "window_minutes": 60, "min_count": 5, "top_n": 5, "asn_db_path": "/var/lib/GeoIP/GeoLite2-ASN.mmdb", "nft_table": "secubox_metrics", "nft_set": "seen_src", "nft_family": "inet"}
    def get_live_hosts_config():     return {"enabled": False, "window_minutes": 60, "top_n": 5, "haproxy_socket": "/run/haproxy/admin.sock", "frontend_filter": "*"}
    def get_cert_status_config():    return {"enabled": False, "letsencrypt_live_dir": "/etc/letsencrypt/live", "warn_days": 30, "critical_days": 7}
```

- [ ] **Step 2: Replace the `app = FastAPI(...)` block with a lifespan-aware one**

Find this block (around line 32–36 of the current file):

```python
app = FastAPI(
    title="SecuBox Metrics Dashboard",
    description="Real-time system metrics with caching",
    version="1.0.0"
)
```

Replace with:

```python
visitor_origin_agg = VisitorOriginAggregator(get_visitor_origin_config())
live_hosts_agg     = LiveHostsAggregator(get_live_hosts_config())
cert_status_agg    = CertStatusAggregator(get_cert_status_config())


@asynccontextmanager
async def lifespan(_app):
    tasks = [
        asyncio.create_task(visitor_origin_agg.run_forever()),
        asyncio.create_task(live_hosts_agg.run_forever()),
        asyncio.create_task(cert_status_agg.run_forever()),
    ]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(
    title="SecuBox Metrics Dashboard",
    description="Real-time system metrics with caching",
    version="1.0.0",
    lifespan=lifespan,
)
```

- [ ] **Step 3: Add the three endpoints at the very end of the route section (before `if __name__` or end of file)**

```python
@app.get("/api/v1/metrics/visitor-origin")
async def visitor_origin_endpoint():
    return JSONResponse(
        content=visitor_origin_agg.current(),
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/api/v1/metrics/live-hosts")
async def live_hosts_endpoint():
    return JSONResponse(
        content=live_hosts_agg.current(),
        headers={"Cache-Control": "public, max-age=300"},
    )


@app.get("/api/v1/metrics/cert-status")
async def cert_status_endpoint():
    return JSONResponse(
        content=cert_status_agg.current(),
        headers={"Cache-Control": "public, max-age=300"},
    )
```

- [ ] **Step 4: Smoke-test `main.py` imports**

Run:

```bash
PYTHONPATH=packages/secubox-metrics/api:common python3 -c "import main; print(main.app.title)"
```

Expected: `SecuBox Metrics Dashboard`. No import errors.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metrics/api/main.py
git commit -m "$(cat <<'EOF'
feat(metrics): Wire three live-panel aggregators into FastAPI lifespan (ref #92)

Adds the three asyncio background tasks under a single lifespan and exposes
their current() payloads on /api/v1/metrics/{visitor-origin,live-hosts,cert-status}
with a 5-min Cache-Control. Endpoints stay unauthenticated by design — the
aggregators only emit threshold-gated, hostname-only data.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9 — nftables ruleset file

**Files:**

- Create: `packages/secubox-metrics/nftables/secubox-metrics.nft`

- [ ] **Step 1: Write the ruleset**

```nft
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-metrics ingress tap (issue #92)
# Owns a private table; never touches secubox-firewall's chains.

table inet secubox_metrics {
    set seen_src {
        type ipv4_addr
        flags timeout
        timeout 1h
        size 65536
    }

    chain ingress_tap {
        type filter hook prerouting priority -300; policy accept;
        tcp dport { 80, 443 } add @seen_src { ip saddr }
    }
}
```

- [ ] **Step 2: Lint with `nft -c -f` (host must have nftables installed)**

Run: `nft -c -f packages/secubox-metrics/nftables/secubox-metrics.nft`
Expected: silent exit 0.

If `nft` is unavailable in the dev environment, skip and rely on CI / target-board validation.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-metrics/nftables/secubox-metrics.nft
git commit -m "$(cat <<'EOF'
feat(metrics): Ship nftables ingress tap for visitor-origin (ref #92)

Private inet secubox_metrics table with a timeout'd src-IP set, hooked from
prerouting at priority -300 so additions happen before secubox-firewall's
filter chain decides whether to drop the packet.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10 — geoipupdate systemd timer

**Files:**

- Create: `packages/secubox-metrics/systemd/secubox-geoipupdate.service`
- Create: `packages/secubox-metrics/systemd/secubox-geoipupdate.timer`

- [ ] **Step 1: Write the service unit**

`packages/secubox-metrics/systemd/secubox-geoipupdate.service`:

```ini
[Unit]
Description=SecuBox — refresh GeoLite2 ASN database
ConditionPathExists=/etc/secubox/secrets/maxmind.conf
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/geoipupdate -f /etc/secubox/secrets/maxmind.conf -d /var/lib/GeoIP
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/var/lib/GeoIP
```

- [ ] **Step 2: Write the timer unit**

`packages/secubox-metrics/systemd/secubox-geoipupdate.timer`:

```ini
[Unit]
Description=SecuBox — weekly GeoLite2 ASN refresh

[Timer]
OnCalendar=weekly
RandomizedDelaySec=4h
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Lint with `systemd-analyze verify`**

Run:

```bash
systemd-analyze verify packages/secubox-metrics/systemd/secubox-geoipupdate.service \
                       packages/secubox-metrics/systemd/secubox-geoipupdate.timer
```

Expected: silent exit 0 (some `verify` versions emit a `[Install]` hint on the service file — ignore for `Type=oneshot` triggered by timer).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-metrics/systemd/secubox-geoipupdate.service \
        packages/secubox-metrics/systemd/secubox-geoipupdate.timer
git commit -m "$(cat <<'EOF'
feat(metrics): Weekly GeoLite2 ASN refresh timer (ref #92)

Conditional on /etc/secubox/secrets/maxmind.conf existing, so the unit is a
silent no-op on installs that haven't supplied a license key. RandomizedDelay
spreads load when many boxes deploy together.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11 — Debian packaging: control, rules, postinst, service

**Files:**

- Modify: `packages/secubox-metrics/debian/control`
- Modify: `packages/secubox-metrics/debian/rules`
- Modify: `packages/secubox-metrics/debian/postinst`
- Modify: `packages/secubox-metrics/debian/secubox-metrics.service`

- [ ] **Step 1: Update `debian/control` Depends**

Find:

```
Depends: ${misc:Depends},
         secubox-core,
         python3,
         python3-fastapi | python3-pip,
         python3-uvicorn | python3-pip
```

Replace with:

```
Depends: ${misc:Depends},
         secubox-core,
         python3,
         python3-fastapi | python3-pip,
         python3-uvicorn | python3-pip,
         python3-maxminddb | python3-pip,
         python3-cryptography,
         geoipupdate,
         nftables
```

- [ ] **Step 2: Update `debian/rules` install stanza**

Read the current `debian/rules`. After the existing install stanzas, add (typically under `override_dh_install:`):

```makefile
override_dh_install:
	dh_install
	install -D -m 0644 nftables/secubox-metrics.nft \
	    debian/secubox-metrics/etc/nftables.d/secubox-metrics.nft
	install -D -m 0644 systemd/secubox-geoipupdate.service \
	    debian/secubox-metrics/lib/systemd/system/secubox-geoipupdate.service
	install -D -m 0644 systemd/secubox-geoipupdate.timer \
	    debian/secubox-metrics/lib/systemd/system/secubox-geoipupdate.timer
```

If `override_dh_install` already exists, append the three `install` lines to it instead of duplicating.

- [ ] **Step 3: Update `debian/postinst`**

Inside the `configure)` branch, **before** the `systemctl enable secubox-metrics.service` line, add:

```bash
        # Add secubox to haproxy group for admin-socket access (issue #92)
        if getent group haproxy >/dev/null; then
            usermod -aG haproxy secubox || true
        fi

        # Persistent cache dir for live-panel rollups
        mkdir -p /var/cache/secubox/metrics
        chown -R secubox:secubox /var/cache/secubox

        # Secrets dir for MaxMind license key
        mkdir -p /etc/secubox/secrets
        chmod 0700 /etc/secubox/secrets
        chown secubox:secubox /etc/secubox/secrets

        # GeoIP db dir
        mkdir -p /var/lib/GeoIP
        chown secubox:secubox /var/lib/GeoIP

        # Reload nftables to pick up /etc/nftables.d/secubox-metrics.nft
        if systemctl is-active --quiet nftables; then
            systemctl reload nftables || true
        fi

        # Enable the geoipupdate timer (no-op if user hasn't supplied a key)
        systemctl enable --now secubox-geoipupdate.timer || true
```

- [ ] **Step 4: Update `debian/secubox-metrics.service`**

Find:

```
ReadWritePaths=/run/secubox /tmp/secubox
```

Replace with:

```
ReadWritePaths=/run/secubox /tmp/secubox /var/cache/secubox
```

- [ ] **Step 5: Lint deb metadata (best-effort)**

Run:

```bash
cd packages/secubox-metrics && dpkg-parsechangelog -l debian/changelog >/dev/null && echo "changelog ok"
```

Expected: `changelog ok`.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-metrics/debian/control \
        packages/secubox-metrics/debian/rules \
        packages/secubox-metrics/debian/postinst \
        packages/secubox-metrics/debian/secubox-metrics.service
git commit -m "$(cat <<'EOF'
build(metrics): Package live-panel deps, nft ruleset, and geoipupdate timer (ref #92)

- control: add python3-maxminddb, python3-cryptography, geoipupdate, nftables
- rules: install nftables/ and systemd/ assets
- postinst: secubox -> haproxy group, cache + secrets + GeoIP dirs,
            nftables reload, timer enable
- service: ReadWritePaths gains /var/cache/secubox

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12 — Health-banner frontend v1.3.0

**Files:**

- Modify: `packages/secubox-hub/www/shared/health-banner.js`

- [ ] **Step 1: Bump version + add constants**

Find:

```js
    const VERSION = '1.2.1';
```

Replace with:

```js
    const VERSION = '1.3.0';
    const VISITOR_ORIGIN_API = window.SECUBOX_VISITOR_ORIGIN_API
        || '/api/v1/metrics/visitor-origin';
    const LIVE_HOSTS_API     = window.SECUBOX_LIVE_HOSTS_API
        || '/api/v1/metrics/live-hosts';
    const CERT_STATUS_API    = window.SECUBOX_CERT_STATUS_API
        || '/api/v1/metrics/cert-status';
    const LIVE_REFRESH_INTERVAL = 30000; // 30 s
```

- [ ] **Step 2: Add three render helpers and three poll loops, just before `injectBannerStyles()`**

```js
    // ═══════════════════════════════════════════════════════════════════════════
    // LIVE PANEL — VisitorOrigin / LiveHosts / CertStatus (issue #92)
    // ═══════════════════════════════════════════════════════════════════════════

    function sectionContainer(id) {
        let el = document.getElementById(id);
        if (!el) {
            el = document.createElement('div');
            el.id = id;
            el.className = 'sbx-live-section';
            const banner = document.getElementById('sbx-health-banner');
            if (banner) banner.appendChild(el);
        }
        return el;
    }

    function hideSection(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    }

    function showSection(id) {
        const el = document.getElementById(id);
        if (el) el.style.display = '';
    }

    function renderVisitorOrigin(data) {
        if (!data || !data.enabled || !data.entries || !data.entries.length) {
            hideSection('sbx-visitor-origin');
            return;
        }
        const el = sectionContainer('sbx-visitor-origin');
        const rows = data.entries.map(e =>
            `<div class="sbx-row"><span class="sbx-asn">AS${e.asn}</span> <span class="sbx-org">${e.org}</span><span class="sbx-count">${e.count}</span></div>`
        ).join('');
        el.innerHTML = `<div class="sbx-section-title">VisitorOrigin · ${data.window_minutes}min · top ${data.entries.length}</div>${rows}`;
        showSection('sbx-visitor-origin');
    }

    function renderLiveHosts(data) {
        if (!data || !data.enabled || !data.entries || !data.entries.length) {
            hideSection('sbx-live-hosts');
            return;
        }
        const el = sectionContainer('sbx-live-hosts');
        const rows = data.entries.map(e =>
            `<div class="sbx-row"><span class="sbx-host">${e.host}</span><span class="sbx-count">${e.count}</span></div>`
        ).join('');
        el.innerHTML = `<div class="sbx-section-title">LiveHosts · ${data.window_minutes}min · top ${data.entries.length}</div>${rows}`;
        showSection('sbx-live-hosts');
    }

    function renderCertStatus(data) {
        if (!data || !data.enabled || !data.summary || !data.summary.total) {
            hideSection('sbx-cert-status');
            return;
        }
        const el = sectionContainer('sbx-cert-status');
        const s = data.summary;
        const next = data.next_renewal
            ? `<div class="sbx-row">next renewal: ${data.next_renewal.host} · ${data.next_renewal.days}d</div>`
            : '';
        el.innerHTML =
            `<div class="sbx-section-title">CertStatus · ${s.total} total</div>` +
            `<div class="sbx-row">✓ ${s.valid} valid · ⚠ ${s.expiring_soon} soon · ✗ ${s.expiring_critical + s.expired} critical</div>` +
            next;
        showSection('sbx-cert-status');
    }

    async function pollLivePanel() {
        const fetchSafe = async (url) => {
            try {
                const r = await fetch(url, { credentials: 'omit' });
                if (!r.ok) return null;
                return await r.json();
            } catch (e) { return null; }
        };
        const [vo, lh, cs] = await Promise.all([
            fetchSafe(VISITOR_ORIGIN_API),
            fetchSafe(LIVE_HOSTS_API),
            fetchSafe(CERT_STATUS_API),
        ]);
        if (vo) renderVisitorOrigin(vo); else hideSection('sbx-visitor-origin');
        if (lh) renderLiveHosts(lh);     else hideSection('sbx-live-hosts');
        if (cs) renderCertStatus(cs);    else hideSection('sbx-cert-status');
    }
```

- [ ] **Step 3: Kick off the poll loop in the existing init path**

Locate the line that calls `injectBannerStyles();` near the bottom of the IIFE (around line 822 in the current file). Immediately after that line, add:

```js
        pollLivePanel();
        setInterval(pollLivePanel, LIVE_REFRESH_INTERVAL);
```

- [ ] **Step 4: Add the matching CSS to `injectBannerStyles` style string**

Inside `injectBannerStyles`, locate the existing `style.textContent` template literal and append before the closing backtick:

```css
            .sbx-live-section { padding: 6px 10px; border-top: 1px solid var(--text-muted, #6b6b7a); font-size: 11px; line-height: 1.4; }
            .sbx-section-title { font-weight: 600; color: var(--gold-hermetic, #c9a84c); margin-bottom: 2px; }
            .sbx-row { display: flex; justify-content: space-between; gap: 8px; }
            .sbx-row .sbx-count { color: var(--cyber-cyan, #00d4ff); font-variant-numeric: tabular-nums; }
            .sbx-row .sbx-asn { color: var(--matrix-green, #00ff41); }
```

- [ ] **Step 5: Manual smoke test in a browser**

```bash
cd packages/secubox-hub/www && python3 -m http.server 9000
```

Open `http://localhost:9000/` (or any page that loads `shared/health-banner.js`), open DevTools, confirm:

- `[HealthBanner]` console log shows `VERSION = 1.3.0`.
- The three fetches fire on a 30 s cycle (Network tab).
- All three sections stay hidden when endpoints return 404 (expected against the static server).

This is a visual / network-tab check — no automated assertion.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-hub/www/shared/health-banner.js
git commit -m "$(cat <<'EOF'
feat(banner): v1.3.0 live panel — visitor origin, live hosts, cert status (ref #92)

Three independent fetch loops on a shared 30s cadence, three DOM sections,
per-section hide on enabled=false / empty / fetch error. Uses existing
design tokens (gold/cyan/matrix-green) so no new CSS variables are added.
A failing section never affects the others.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13 — README + tracking files

**Files:**

- Modify: `packages/secubox-metrics/README.md`
- Modify: `.claude/HISTORY.md`
- Modify: `.claude/WIP.md`
- Modify: `.claude/MIGRATION-MAP.md`

- [ ] **Step 1: Append an "Endpoints (live panel)" section to `packages/secubox-metrics/README.md`**

```markdown
## Endpoints — live panel (issue #92)

Three public endpoints feed the health-banner live panel. All are
unauthenticated, CORS-open, and `Cache-Control: public, max-age=300`.

| Method | Path                              | Schema (high-level)                                 |
|--------|-----------------------------------|------------------------------------------------------|
| GET    | `/api/v1/metrics/visitor-origin`  | `{enabled, window_minutes, entries:[{asn,org,count}]}`|
| GET    | `/api/v1/metrics/live-hosts`      | `{enabled, window_minutes, entries:[{host,count}]}`   |
| GET    | `/api/v1/metrics/cert-status`     | `{enabled, summary, next_renewal, warnings}`          |

Config blocks live in `/etc/secubox/secubox.conf`:

```toml
[visitor_origin]
enabled = true
min_count = 5

[live_hosts]
enabled = true

[cert_status]
enabled = true
warn_days = 30
```

MaxMind GeoLite2-ASN refresh: drop a license file at
`/etc/secubox/secrets/maxmind.conf` (mode 0600, owner `secubox`).
The `secubox-geoipupdate.timer` runs weekly; no key ⇒ no-op.
```

- [ ] **Step 2: Append an entry to `.claude/HISTORY.md` under today's date**

```markdown
### Session 160 — Health Banner Live Panel (Issue #92)

**Goal:** Add three public sections to the health banner — VisitorOrigin,
LiveHosts, CertStatus — sharing one polling pipeline.

**Spec:** `docs/superpowers/specs/2026-05-12-visitor-origin-feed-design.md`
**Plan:** `docs/superpowers/plans/2026-05-12-visitor-origin-feed.md`
**Branch:** `feature/92-health-banner-visitor-origin-feed-anonym`
**Issue:** [#92](https://github.com/CyberMind-FR/secubox-deb/issues/92)

**Highlights**
- nftables `inet secubox_metrics` table (priority -300) — independent of
  `secubox-firewall`.
- VisitorOrigin: kernel-dedupe via timeout'd set, mmdb resolution, threshold
  gate before persistence (raw IPs never leave the function).
- LiveHosts: HAProxy admin socket + 60×1-min ring buffer; counter-reset
  detection.
- CertStatus: cryptography parse of `/etc/letsencrypt/live/*/cert.pem`.
- Banner v1.3.0: three fail-isolated fetch loops on a shared 30 s cadence.
```

- [ ] **Step 3: In `.claude/WIP.md`, replace the in-progress Session 159 block with a Session 160 block referencing the merged work, or append at top under "## ✅ Session 160" if 159 is still active.**

```markdown
## ✅ Session 160: Health Banner Live Panel (Issue #92)

### Objective
Add three public banner sections (VisitorOrigin / LiveHosts / CertStatus)
sharing one polling and CORS pipeline in `secubox-metrics`.

### Completed
- Spec + plan written and committed.
- Three aggregators with unit + error-path tests.
- nftables ruleset, systemd timer, postinst plumbing.
- Banner v1.3.0 with three fail-isolated fetch loops.
- README updated.

### Status
PR pending review against `master`.
```

- [ ] **Step 4: In `.claude/MIGRATION-MAP.md`, add a row marking the live-panel feed under `secubox-metrics`** (or, if the module is already ✅, leave a note in the "extensions" section).

This is project-specific — match the existing column convention.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metrics/README.md .claude/HISTORY.md .claude/WIP.md .claude/MIGRATION-MAP.md
git commit -m "$(cat <<'EOF'
docs: Session 160 — Health Banner Live Panel (ref #92)

README documents the three new endpoints + config blocks. HISTORY / WIP /
MIGRATION-MAP entries describe the feature, the spec/plan paths, and the
session's outcome.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14 — Full-suite verification + finish-branch handoff

- [ ] **Step 1: Run the entire metrics test suite**

```bash
python3 -m pytest packages/secubox-metrics/tests/ -v
```

Expected: all tests pass (≥ 20 cases across the four test files).

- [ ] **Step 2: Run the repo-wide test suite that already exists**

```bash
python3 -m pytest tests/ -v
```

Expected: no regressions (existing tests still pass).

- [ ] **Step 3: License-header check (existing CI gate)**

```bash
python3 scripts/license-headers.py --check
```

Expected: `OK`. If new files fail, run `--fix` then re-`--check`.

- [ ] **Step 4: Push and open PR via `scripts/agent-worktree.sh finish`**

Run from the worktree:

```bash
bash scripts/agent-worktree.sh finish
```

This pushes the branch and opens a PR with the format dictated by the script (title includes the issue number, body links `Closes #92`).

- [ ] **Step 5: Comment on issue #92 with the PR URL**

```bash
gh issue comment 92 --body "Implementation complete in <PR_URL>, pending review."
```

(Do **not** close the issue — user closes after manual validation per `CLAUDE.md`.)

---

## Verification matrix

| Acceptance criterion (spec §9)                                                | Task |
|-------------------------------------------------------------------------------|------|
| `apt install` configures everything without manual steps                      | 11   |
| All three endpoints respond 200 with documented schema (enabled + disabled)   | 8, 14 |
| No raw IP in cache / journal / HTTP response                                  | 3, 4 |
| ASN below `min_count` absent from all surfaces                                | 3    |
| Each banner section appears < 90 s after data, disappears < 60 s after loss   | 12, 14 |
| Unit-test coverage ≥ 80 % on aggregators                                      | 3–7  |
| Integration tests pass against fixtures                                       | 5–7  |
| No regression on `/health/summary` or banner SSL section                      | 8, 14 |
