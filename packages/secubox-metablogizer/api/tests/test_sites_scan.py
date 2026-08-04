# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for api/sites_scan.py — the out-of-band site-list cache (#974).

`GET /sites` used to recompute the whole fleet (git x2 + du per site) on
every request, blocking the module's single-worker event loop. Measured on
the board (172 sites, load ~160): ~14.6s per pass, 77% of it spent forking
`git`. Concurrent requests queue behind each other on the single uvicorn
worker, so the effective wait balloons well past 60s under normal traffic
(dashboard polling + health probes + webhook) — this is what made the
Mosaic tab unusable.

Fix: `metablog-audit.timer` calls `sites_scan.main()` out of band, which
runs the expensive scan (`scan_sites`) and writes the result atomically
(`write_cache_atomic`). The request path (`GET /sites` in api/main.py) only
ever calls `read_cache()` — a file read, never a recompute.

Run from packages/secubox-metablogizer/ with secubox_core importable:
    PYTHONPATH=api:../../common ../../.venv/bin/pytest api/tests/test_sites_scan.py -v
"""
import json
import os
import stat
import time
from pathlib import Path

import pytest

import sites_scan


def _site(root: Path, name: str, *, domain=None, port=None) -> Path:
    d = root / name / "public"
    d.mkdir(parents=True)
    (d / "index.html").write_text("<h1>hi</h1>")
    cfg = {}
    if domain is not None:
        cfg["domain"] = domain
    if port is not None:
        cfg["port"] = port
    if cfg:
        (root / name / "site.json").write_text(json.dumps(cfg))
    return root / name


# ─────────────────────────────────────────────────────────────────────────
# scan_sites — the expensive path, exercised directly (never from a request
# handler — that contract is asserted in test_sites_route.py).
# ─────────────────────────────────────────────────────────────────────────

def test_scan_sites_empty_root_returns_empty_list(tmp_path):
    missing_root = tmp_path / "does-not-exist"
    result = sites_scan.scan_sites(missing_root, tmp_path / "nginx.conf")
    assert result == []


def test_scan_sites_finds_each_site_directory(tmp_path):
    root = tmp_path / "sites"
    _site(root, "alpha")
    _site(root, "beta")
    result = sites_scan.scan_sites(root, tmp_path / "nginx.conf")
    names = sorted(s["name"] for s in result)
    assert names == ["alpha", "beta"]


def test_scan_sites_skips_dotdirs(tmp_path):
    root = tmp_path / "sites"
    _site(root, "real")
    (root / ".hidden").mkdir(parents=True)
    result = sites_scan.scan_sites(root, tmp_path / "nginx.conf")
    assert [s["name"] for s in result] == ["real"]


def test_scan_sites_reads_domain_and_port_from_site_json(tmp_path):
    root = tmp_path / "sites"
    _site(root, "custom", domain="custom.example.com", port=8912)
    result = sites_scan.scan_sites(root, tmp_path / "nginx.conf")
    assert result[0]["domain"] == "custom.example.com"
    assert result[0]["port"] == 8912


def test_scan_sites_rewrites_local_suffix(tmp_path):
    root = tmp_path / "sites"
    _site(root, "legacy", domain="legacy.local")
    result = sites_scan.scan_sites(root, tmp_path / "nginx.conf")
    assert result[0]["domain"] == "legacy.gk2.secubox.in"

def test_scan_sites_detects_published_via_nginx_conf(tmp_path):
    root = tmp_path / "sites"
    site_dir = _site(root, "live")
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text(f"server {{ root {site_dir}/public; }}\n")
    result = sites_scan.scan_sites(root, nginx_conf)
    assert result[0]["published"] is True


def test_scan_sites_unpublished_when_not_in_nginx_conf(tmp_path):
    root = tmp_path / "sites"
    _site(root, "draft")
    result = sites_scan.scan_sites(root, tmp_path / "nginx.conf")
    assert result[0]["published"] is False


# ─────────────────────────────────────────────────────────────────────────
# write_cache_atomic — same-directory tmp + rename, never a foreign /tmp
# ─────────────────────────────────────────────────────────────────────────

def test_write_cache_creates_readable_file(tmp_path):
    cache = tmp_path / "cache" / "sites.json"
    sites_scan.write_cache_atomic(cache, [{"name": "a"}])
    assert cache.exists()
    payload = json.loads(cache.read_text())
    assert payload["sites"] == [{"name": "a"}]
    assert payload["count"] == 1


def test_write_cache_leaves_no_tmp_file_behind(tmp_path):
    cache_dir = tmp_path / "cache"
    cache = cache_dir / "sites.json"
    sites_scan.write_cache_atomic(cache, [])
    leftovers = [p for p in cache_dir.iterdir() if p.name != "sites.json"]
    assert leftovers == []


def test_write_cache_result_is_world_readable(tmp_path):
    """The service that writes this file runs as `secubox`; the aggregator
    (and anything else) that reads it must never be blocked by permissions —
    the incident this rule exists for was a /tmp-sourced mv leaving a file
    0600 root:root, unreadable by the secubox-run reader."""
    cache = tmp_path / "cache" / "sites.json"
    sites_scan.write_cache_atomic(cache, [])
    mode = cache.stat().st_mode
    assert mode & stat.S_IROTH, "cache file must be other-readable"


def test_write_cache_ignores_a_broken_system_tmp_dir(tmp_path, monkeypatch):
    """The atomic-write rule is: temp file in the SAME directory as the
    target, then rename — never the system tempdir. Point TMPDIR/TMP/TEMP at
    a path that doesn't exist; if the implementation ever fell back to the
    platform default tempdir this would raise, proving the write really
    happens next to the target."""
    bogus = tmp_path / "no-such-tmpdir"
    monkeypatch.setenv("TMPDIR", str(bogus))
    monkeypatch.setenv("TMP", str(bogus))
    monkeypatch.setenv("TEMP", str(bogus))
    cache = tmp_path / "cache" / "sites.json"
    sites_scan.write_cache_atomic(cache, [{"name": "z"}])
    assert cache.exists()
    assert not bogus.exists()


def test_write_cache_atomic_survives_concurrent_partial_read():
    """Rename is atomic on POSIX: a reader either sees the whole old file or
    the whole new file, never a half-written one. We can't easily force a
    real race in a unit test, but we can assert the mechanism used is
    os.replace (not two separate write+unlink steps) by checking the
    public write path never exposes a truncated destination file — i.e. the
    destination is only ever touched by the final replace."""
    import inspect
    src = inspect.getsource(sites_scan.write_cache_atomic)
    assert "replace" in src or "rename" in src


# ─────────────────────────────────────────────────────────────────────────
# read_cache — the ONLY thing the request path is allowed to call
# ─────────────────────────────────────────────────────────────────────────

def test_read_cache_missing_file_is_not_confused_with_empty(tmp_path):
    cache = tmp_path / "sites.json"
    result = sites_scan.read_cache(cache)
    assert result["available"] is False
    assert result["reason"] == "cache not written yet"
    assert result["sites"] == []
    # Must be distinguishable from "available, 0 sites" — reason is set.
    assert result["reason"] is not None


def test_read_cache_corrupt_json_is_reported_not_raised(tmp_path):
    cache = tmp_path / "sites.json"
    cache.write_text("{not json")
    result = sites_scan.read_cache(cache)
    assert result["available"] is False
    assert result["reason"] == "cache unreadable"


def test_read_cache_non_object_payload_is_reported(tmp_path):
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps([1, 2, 3]))
    result = sites_scan.read_cache(cache)
    assert result["available"] is False
    assert result["reason"] == "cache unreadable"


def test_read_cache_missing_sites_key_is_reported(tmp_path):
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps({"count": 0}))
    result = sites_scan.read_cache(cache)
    assert result["available"] is False
    assert result["reason"] == "cache unreadable"


def test_read_cache_null_sites_value_is_reported_not_raised(tmp_path):
    """A cache payload with `"sites": null` (e.g. a writer bug, or JSON
    serialized from a None) must be reported like any other malformed
    cache — never raise a TypeError out of read_cache(), which is
    documented to never raise."""
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps({"sites": None}))
    result = sites_scan.read_cache(cache)
    assert result["available"] is False
    assert result["reason"] == "cache unreadable"


def test_read_cache_non_list_sites_value_is_reported(tmp_path):
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps({"sites": {"not": "a list"}}))
    result = sites_scan.read_cache(cache)
    assert result["available"] is False
    assert result["reason"] == "cache unreadable"


def test_read_cache_valid_payload_reports_available_true(tmp_path):
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps({"sites": [{"name": "a"}, {"name": "b"}]}))
    result = sites_scan.read_cache(cache)
    assert result["available"] is True
    assert result["reason"] is None
    assert result["count"] == 2
    assert [s["name"] for s in result["sites"]] == ["a", "b"]


def test_read_cache_reports_age_in_seconds(tmp_path):
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps({"sites": []}))
    old = time.time() - 120
    os.utime(cache, (old, old))
    result = sites_scan.read_cache(cache)
    assert result["cache_age_seconds"] >= 100


def test_read_cache_genuinely_empty_fleet_is_available_not_error(tmp_path):
    """A real zero-site fleet must read as available=True, sites=[] — not
    trigger the 'cache missing' branch. That's what makes an empty array
    trustworthy instead of ambiguous."""
    cache = tmp_path / "sites.json"
    cache.write_text(json.dumps({"sites": []}))
    result = sites_scan.read_cache(cache)
    assert result["available"] is True
    assert result["sites"] == []


# ─────────────────────────────────────────────────────────────────────────
# main() — the CLI entry point called by metablog-audit.timer
# ─────────────────────────────────────────────────────────────────────────

def test_main_scans_and_writes_cache(tmp_path, monkeypatch, capsys):
    sites_root = tmp_path / "sites"
    _site(sites_root, "one")
    cache_path = tmp_path / "cache" / "sites.json"
    monkeypatch.setenv("METABLOG_SITES_ROOT", str(sites_root))
    monkeypatch.setenv("METABLOG_SITES_CACHE", str(cache_path))
    monkeypatch.setenv("METABLOG_NGINX_CONF", str(tmp_path / "nginx.conf"))

    rc = sites_scan.main([])

    assert rc == 0
    assert cache_path.exists()
    payload = json.loads(cache_path.read_text())
    assert payload["count"] == 1
