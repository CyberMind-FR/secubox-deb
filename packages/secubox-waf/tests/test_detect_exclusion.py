# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# detect-mode records must never inflate the WAF dashboard's block counters.
from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Make the package importable without an install step
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Stub out secubox_core before importing waf.api — production deps
# (auth, config) aren't needed for these unit tests.
from types import ModuleType

if "secubox_core" not in sys.modules:
    secubox_core = ModuleType("secubox_core")
    auth_mod = ModuleType("secubox_core.auth")
    auth_mod.require_jwt = lambda: None
    config_mod = ModuleType("secubox_core.config")
    config_mod.get_config = lambda *_a, **_k: {}
    secubox_core.auth = auth_mod
    secubox_core.config = config_mod
    sys.modules["secubox_core"] = secubox_core
    sys.modules["secubox_core.auth"] = auth_mod
    sys.modules["secubox_core.config"] = config_mod

# geoip2 may or may not be installed in CI; stub it out.
if "geoip2" not in sys.modules:
    geoip2 = ModuleType("geoip2")
    geoip2_db = ModuleType("geoip2.database")
    geoip2_db.Reader = object
    geoip2_err = ModuleType("geoip2.errors")
    class _AddressNotFoundError(Exception): ...
    geoip2_err.AddressNotFoundError = _AddressNotFoundError
    sys.modules["geoip2"] = geoip2
    sys.modules["geoip2.database"] = geoip2_db
    sys.modules["geoip2.errors"] = geoip2_err

from api import main as waf_main  # noqa: E402
import time


def _write_log(tmp_path, *entries):
    import json as _json
    p = tmp_path / "threats.log"
    p.write_text("\n".join(_json.dumps(e) for e in entries) + "\n")
    return p


def test_detect_records_excluded_from_block_counters(tmp_path, monkeypatch):
    """A detect-mode match is observed, not blocked. Counting it as a block
    would make blocked_24h a lie the instant an operator arms a detect
    category — the whole reason action='detect' exists."""
    today = time.strftime("%Y-%m-%d")
    logp = _write_log(
        tmp_path,
        {"action": "banned", "category": "sqli", "severity": "critical",
         "timestamp": today + "T10:00:00", "client_ip": "203.0.113.1"},
        {"action": "detect", "category": "cve_2024", "severity": "critical",
         "timestamp": today + "T10:00:01", "client_ip": "203.0.113.2"},
        {"action": "detect", "category": "cve_2024", "severity": "critical",
         "timestamp": today + "T10:00:02", "client_ip": "203.0.113.3"},
    )
    monkeypatch.setattr(waf_main, "THREATS_LOG", str(logp))
    monkeypatch.setattr(waf_main, "STATS_DISK_CACHE", str(tmp_path / "cache.json"))

    stats = waf_main._get_threat_stats()

    assert stats["total_threats"] == 1, "detect records leaked into total_threats"
    assert stats["observed_threats"] == 2
    assert "cve_2024" not in stats["by_category"]
    assert stats["by_category"].get("sqli") == 1


def test_detect_only_log_reports_zero_blocked(tmp_path, monkeypatch):
    """A log of pure detect matches must report zero blocks, not N."""
    today = time.strftime("%Y-%m-%d")
    logp = _write_log(
        tmp_path,
        {"action": "detect", "category": "cve_2024", "severity": "high",
         "timestamp": today + "T09:00:00", "client_ip": "203.0.113.9"},
    )
    monkeypatch.setattr(waf_main, "THREATS_LOG", str(logp))
    monkeypatch.setattr(waf_main, "STATS_DISK_CACHE", str(tmp_path / "cache.json"))

    stats = waf_main._get_threat_stats()
    assert stats["total_threats"] == 0
    assert stats["observed_threats"] == 1
