# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for packages/secubox-metablogizer/api/shots.py (#956).

Run from packages/secubox-metablogizer/ with secubox_core importable:
    PYTHONPATH=api:../../common ../../.venv/bin/pytest api/tests/test_shots.py -v
"""
import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

import shots
from secubox_core import screenshots


def _site(sites_root: Path, name: str) -> Path:
    d = sites_root / name
    d.mkdir(parents=True)
    return d


def _png() -> bytes:
    return b"\x89PNG" + b"0" * 60000


# ─────────────────────────────────────────────────────────────────────────
# site_fingerprint
# ─────────────────────────────────────────────────────────────────────────

def test_fingerprint_falls_back_to_mtime_without_git(tmp_path):
    d = _site(tmp_path, "plain")
    assert shots.site_fingerprint(d) == str(int(d.stat().st_mtime))


def test_fingerprint_uses_git_commit_date_when_available(tmp_path, monkeypatch):
    d = _site(tmp_path, "gitsite")
    (d / ".git").mkdir()

    class _Result:
        returncode = 0
        stdout = "2026-01-01T00:00:00+00:00\n"

    monkeypatch.setattr(shots.subprocess, "run", lambda *a, **k: _Result())
    assert shots.site_fingerprint(d) == "2026-01-01T00:00:00+00:00"


def test_fingerprint_falls_back_to_mtime_on_git_timeout(tmp_path, monkeypatch):
    d = _site(tmp_path, "gitsite")
    (d / ".git").mkdir()

    def _boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 5)

    monkeypatch.setattr(shots.subprocess, "run", _boom)
    assert shots.site_fingerprint(d) == str(int(d.stat().st_mtime))


# ─────────────────────────────────────────────────────────────────────────
# site_domain
# ─────────────────────────────────────────────────────────────────────────

def test_domain_defaults_to_name_suffix(tmp_path):
    d = _site(tmp_path, "myblog")
    assert shots.site_domain(d, "myblog") == "myblog.gk2.secubox.in"


def test_domain_reads_site_json(tmp_path):
    d = _site(tmp_path, "custom")
    (d / "site.json").write_text(json.dumps({"domain": "custom.example.com"}))
    assert shots.site_domain(d, "custom") == "custom.example.com"


def test_domain_rewrites_local_suffix(tmp_path):
    d = _site(tmp_path, "legacy")
    (d / "site.json").write_text(json.dumps({"domain": "legacy.local"}))
    assert shots.site_domain(d, "legacy") == "legacy.gk2.secubox.in"


# ─────────────────────────────────────────────────────────────────────────
# pick_next — sélection du prochain site
# ─────────────────────────────────────────────────────────────────────────

def test_pick_next_none_when_no_sites(tmp_path):
    assert shots.pick_next(tmp_path / "sites", tmp_path / "cache") is None


def test_pick_next_prefers_never_captured_over_fresh(tmp_path):
    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    a = _site(sites_root, "a")
    _site(sites_root, "b")
    screenshots.record(cache, "a", _png(), shots.site_fingerprint(a), ok=True)
    # "b" was never captured -> must win over the freshly-captured "a"
    assert shots.pick_next(sites_root, cache) == "b"


def test_pick_next_skips_fresh_sites(tmp_path):
    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    a = _site(sites_root, "a")
    screenshots.record(cache, "a", _png(), shots.site_fingerprint(a), ok=True)
    assert shots.pick_next(sites_root, cache) is None


def test_pick_next_picks_oldest_attempt_first(tmp_path):
    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    _site(sites_root, "a")
    _site(sites_root, "b")
    # Both stale (fingerprint deliberately wrong) but "a" was attempted
    # before "b" -> "a" is the more overdue of the two.
    screenshots.record(cache, "a", None, "stale-fp", ok=False)
    time.sleep(0.01)
    screenshots.record(cache, "b", None, "stale-fp", ok=False)
    assert shots.pick_next(sites_root, cache) == "a"


def test_pick_next_never_recaptures_unrepublished_site(tmp_path):
    """Rule #956: a site already captured and not republished since is never
    recaptured."""
    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    a = _site(sites_root, "a")
    fp1 = shots.site_fingerprint(a)
    screenshots.record(cache, "a", _png(), fp1, ok=True)
    assert shots.pick_next(sites_root, cache) is None

    # Simulate a republish: bump mtime forward so the fingerprint changes.
    future = time.time() + 5
    os.utime(a, (future, future))
    assert shots.site_fingerprint(a) != fp1
    assert shots.pick_next(sites_root, cache) == "a"


# ─────────────────────────────────────────────────────────────────────────
# load_ok — garde de charge
# ─────────────────────────────────────────────────────────────────────────

def test_load_ok_true_under_threshold(monkeypatch):
    monkeypatch.setattr(shots.os, "getloadavg", lambda: (10.0, 5.0, 2.0))
    assert shots.load_ok(40.0) is True


def test_load_ok_false_over_threshold(monkeypatch):
    monkeypatch.setattr(shots.os, "getloadavg", lambda: (87.0, 60.0, 50.0))
    assert shots.load_ok(40.0) is False


def test_load_ok_boundary_is_inclusive(monkeypatch):
    monkeypatch.setattr(shots.os, "getloadavg", lambda: (40.0, 0.0, 0.0))
    assert shots.load_ok(40.0) is True


# ─────────────────────────────────────────────────────────────────────────
# acquire_lock — verrou d'exclusion
# ─────────────────────────────────────────────────────────────────────────

def test_acquire_lock_excludes_second_holder(tmp_path):
    lock_path = tmp_path / "shots" / shots.LOCK_NAME
    first = shots.acquire_lock(lock_path)
    assert first is not None
    try:
        second = shots.acquire_lock(lock_path)
        assert second is None
    finally:
        first.release()


def test_acquire_lock_reacquirable_after_release(tmp_path):
    lock_path = tmp_path / "shots" / shots.LOCK_NAME
    first = shots.acquire_lock(lock_path)
    first.release()
    second = shots.acquire_lock(lock_path)
    assert second is not None
    second.release()


def test_lock_usable_as_context_manager(tmp_path):
    lock_path = tmp_path / "shots" / shots.LOCK_NAME
    with shots.acquire_lock(lock_path) as held:
        assert held is not None
        assert shots.acquire_lock(lock_path) is None
    # released on __exit__
    reacquired = shots.acquire_lock(lock_path)
    assert reacquired is not None
    reacquired.release()


# ─────────────────────────────────────────────────────────────────────────
# capture_site — un échec n'immobilise pas la file
# ─────────────────────────────────────────────────────────────────────────

def test_capture_site_records_failure_without_raising(tmp_path, monkeypatch):
    from secubox_core import shotter

    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    _site(sites_root, "broken")

    async def boom(url, **kw):
        raise shotter.ShotError("rendu vide")

    monkeypatch.setattr(shotter, "capture", boom)

    result = asyncio.run(shots.capture_site(sites_root, cache, "broken"))
    assert result["ok"] is False
    meta = screenshots.read_meta(cache, "broken")
    assert meta["ok"] is False


def test_capture_site_success_records_png(tmp_path, monkeypatch):
    from secubox_core import shotter

    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    _site(sites_root, "good")

    async def fake_capture(url, **kw):
        return _png()

    monkeypatch.setattr(shotter, "capture", fake_capture)

    result = asyncio.run(shots.capture_site(sites_root, cache, "good"))
    assert result["ok"] is True
    assert screenshots.png_path(cache, "good").exists()


def test_failed_capture_falls_behind_untried_site_next_pick(tmp_path, monkeypatch):
    """Rule #956: a failed site is marked attempted and the NEXT run moves on
    to another site — one broken site never freezes the other 171."""
    from secubox_core import shotter

    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    _site(sites_root, "broken")
    _site(sites_root, "untried")

    async def boom(url, **kw):
        raise shotter.ShotError("rendu vide")

    monkeypatch.setattr(shotter, "capture", boom)

    first = shots.pick_next(sites_root, cache)
    assert first == "broken"  # alphabetically first among two never-tried sites
    asyncio.run(shots.capture_site(sites_root, cache, first))

    second = shots.pick_next(sites_root, cache)
    assert second == "untried"


# ─────────────────────────────────────────────────────────────────────────
# main() — orchestration CLI
# ─────────────────────────────────────────────────────────────────────────

def test_main_skips_when_load_high(monkeypatch, capsys):
    monkeypatch.setattr(shots, "load_ok", lambda threshold: False)
    rc = shots.main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["skipped"] == "load-guard"


def test_main_skips_when_locked(tmp_path, monkeypatch, capsys):
    cache = tmp_path / "cache"
    monkeypatch.setenv("METABLOG_SHOTS_CACHE", str(cache))
    monkeypatch.setattr(shots, "load_ok", lambda threshold: True)
    held = shots.acquire_lock(cache / shots.LOCK_NAME)
    try:
        rc = shots.main()
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["skipped"] == "locked"
    finally:
        held.release()


def test_main_skips_when_nothing_to_capture(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("METABLOG_SITES_ROOT", str(tmp_path / "sites"))
    monkeypatch.setenv("METABLOG_SHOTS_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(shots, "load_ok", lambda threshold: True)
    rc = shots.main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["skipped"] == "nothing-to-capture"


def test_main_captures_selected_site(tmp_path, monkeypatch, capsys):
    from secubox_core import shotter

    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    _site(sites_root, "demo")
    monkeypatch.setenv("METABLOG_SITES_ROOT", str(sites_root))
    monkeypatch.setenv("METABLOG_SHOTS_CACHE", str(cache))
    monkeypatch.setattr(shots, "load_ok", lambda threshold: True)

    async def fake_capture(url, **kw):
        return _png()

    monkeypatch.setattr(shotter, "capture", fake_capture)

    rc = shots.main()
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["name"] == "demo"


def test_main_returns_1_when_capture_fails(tmp_path, monkeypatch, capsys):
    from secubox_core import shotter

    sites_root = tmp_path / "sites"
    cache = tmp_path / "cache"
    _site(sites_root, "demo")
    monkeypatch.setenv("METABLOG_SITES_ROOT", str(sites_root))
    monkeypatch.setenv("METABLOG_SHOTS_CACHE", str(cache))
    monkeypatch.setattr(shots, "load_ok", lambda threshold: True)

    async def boom(url, **kw):
        raise shotter.ShotError("rendu vide")

    monkeypatch.setattr(shotter, "capture", boom)

    rc = shots.main()
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
