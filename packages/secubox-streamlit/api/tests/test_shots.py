"""Tests for `api/shots.py` — the capture orchestration layer (#958).

This module is deliberately thin: target resolution is delegated entirely
to `streamlitctl app shot-target` (tested separately in
test_shot_target.py), and the capture mechanics themselves live in
`secubox_core.shotter`/`secubox_core.screenshots` (tested in
common/secubox_core/tests/). What's tested here is the orchestration: does
`main()` skip when it should, capture when it should, and never launch two
captures at once.
"""
import json
import subprocess
from pathlib import Path

import pytest

from api import shots


# ─────────────────────────────────────────────────────────────────────────
# source_fingerprint
# ─────────────────────────────────────────────────────────────────────────

def test_source_fingerprint_format_matches_bash_side(tmp_path):
    """MUST stay "<mtime>:<size>" — `streamlitctl:cmd_app_audit` computes
    the current-side fingerprint with `stat -c '%Y:%s'` to compare against
    what this function records. A format drift here silently breaks the
    "screenshot_stale" flag surfaced to the wall."""
    f = tmp_path / "app.py"
    f.write_text("import streamlit\n")
    import os
    os.utime(f, (1_700_000_000, 1_700_000_000))

    fp = shots.source_fingerprint(f)

    assert fp == f"1700000000:{f.stat().st_size}"


def test_source_fingerprint_missing_file_returns_empty_string(tmp_path):
    fp = shots.source_fingerprint(tmp_path / "does-not-exist.py")
    assert fp == ""


# ─────────────────────────────────────────────────────────────────────────
# resolve_target
# ─────────────────────────────────────────────────────────────────────────

def test_resolve_target_parses_ctl_json(monkeypatch):
    def fake_run(cmd, **kw):
        assert cmd[:2] == ["sudo", "-n"]
        assert cmd[-3:] == ["app", "shot-target", "demo"]
        return subprocess.CompletedProcess(cmd, 0, stdout='{"ok": true, "url": "http://1.2.3.4:8501/", "source": "/srv/streamlit/apps/demo.py"}\n', stderr="")

    monkeypatch.setattr(shots.subprocess, "run", fake_run)
    result = shots.resolve_target("demo")

    assert result["ok"] is True
    assert result["url"] == "http://1.2.3.4:8501/"


def test_resolve_target_survives_ctl_timeout(monkeypatch):
    def fake_run(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 30)

    monkeypatch.setattr(shots.subprocess, "run", fake_run)
    result = shots.resolve_target("demo")

    assert result["ok"] is False
    assert "error" in result


def test_resolve_target_survives_missing_ctl_binary(monkeypatch):
    def fake_run(cmd, **kw):
        raise OSError("no such file")

    monkeypatch.setattr(shots.subprocess, "run", fake_run)
    result = shots.resolve_target("demo")
    assert result["ok"] is False


# ─────────────────────────────────────────────────────────────────────────
# Lock — one capture at a time (#957 §3.4)
# ─────────────────────────────────────────────────────────────────────────

def test_acquire_lock_blocks_a_second_holder(tmp_path):
    lock_path = tmp_path / "shots" / ".lock"
    first = shots.acquire_lock(lock_path)
    assert first is not None

    second = shots.acquire_lock(lock_path)
    assert second is None

    first.release()
    third = shots.acquire_lock(lock_path)
    assert third is not None
    third.release()


# ─────────────────────────────────────────────────────────────────────────
# capture_app — never raises
# ─────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_capture_app_records_success(tmp_path, monkeypatch):
    from secubox_core import shotter, screenshots

    async def fake_capture(url, **kw):
        return b"\x89PNG" + b"0" * 60000

    monkeypatch.setattr(shotter, "capture", fake_capture)
    src = tmp_path / "demo.py"
    src.write_text("import streamlit\n")

    result = await shots.capture_app(tmp_path / "shots", "demo", "http://1.2.3.4:8501/", src)

    assert result["ok"] is True
    assert screenshots.png_path(tmp_path / "shots", "demo").exists()


@pytest.mark.asyncio
async def test_capture_app_records_failure_without_raising(tmp_path, monkeypatch):
    from secubox_core import shotter, screenshots

    async def boom(url, **kw):
        raise shotter.ShotError("rendu vide")

    monkeypatch.setattr(shotter, "capture", boom)
    src = tmp_path / "demo.py"
    src.write_text("import streamlit\n")

    result = await shots.capture_app(tmp_path / "shots", "demo", "http://1.2.3.4:8501/", src)

    assert result["ok"] is False
    assert screenshots.read_meta(tmp_path / "shots", "demo")["ok"] is False


# ─────────────────────────────────────────────────────────────────────────
# main() — the CLI, orchestrating skip/capture decisions
# ─────────────────────────────────────────────────────────────────────────

def _app(tmp_path):
    src = tmp_path / "demo.py"
    src.write_text("import streamlit\n")
    return src


def test_main_never_captures_when_target_not_ok(tmp_path, monkeypatch):
    """Mirrors the invariant pinned in test_shot_target.py: a sleeping (or
    unknown) app must never be captured — here at the orchestration
    level, regardless of what streamlitctl actually said."""
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(shots, "resolve_target", lambda name, ctl=None: {"ok": False, "error": "not running"})

    calls = []

    async def spy_capture_app(*a, **kw):
        calls.append(a)
        return {"ok": True}

    monkeypatch.setattr(shots, "capture_app", spy_capture_app)

    rc = shots.main(["demo"])

    assert calls == []


def test_main_unresolvable_target_is_never_a_silent_success(tmp_path, monkeypatch, capsys):
    """#958: a batch run over 27 apps logged 25 "successes" while only 17
    PNGs existed on disk — an unresolvable target (app not woken yet, not
    found, port unknown, container IP unavailable...) returned exit 0 just
    like a real capture, indistinguishable to a caller checking $? without
    parsing JSON. This must never happen again: an unresolvable target is
    its own outcome, with its own exit code, distinct from both a written
    capture (0) and a rejected one (1) — and distinct in the JSON too, so a
    caller doesn't have to parse free-text "error" strings to tell them
    apart."""
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(shots, "resolve_target", lambda name, ctl=None: {"ok": False, "error": "not running"})

    rc = shots.main(["demo"])

    assert rc != 0
    assert rc not in (shots.EXIT_OK, shots.EXIT_REJECTED), \
        "must be distinguishable from both a written and a rejected capture"
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "target-unavailable"
    assert payload["ok"] is False


def test_main_skips_when_fresh_without_force(tmp_path, monkeypatch):
    from secubox_core import screenshots

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(cache_dir))
    src = _app(tmp_path)
    fingerprint = shots.source_fingerprint(src)
    screenshots.record(cache_dir, "demo", b"\x89PNG" + b"0" * 60000, fingerprint, ok=True)

    monkeypatch.setattr(shots, "resolve_target",
                         lambda name, ctl=None: {"ok": True, "url": "http://1.2.3.4:8501/", "source": str(src)})

    calls = []

    async def spy_capture_app(*a, **kw):
        calls.append(a)
        return {"ok": True}

    monkeypatch.setattr(shots, "capture_app", spy_capture_app)

    rc = shots.main(["demo"])

    assert rc == 0
    assert calls == [], "a fresh screenshot must not be recaptured"


def test_main_force_captures_even_when_fresh(tmp_path, monkeypatch):
    """The manual "recapturer" trigger must ignore staleness entirely."""
    from secubox_core import screenshots

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(cache_dir))
    src = _app(tmp_path)
    fingerprint = shots.source_fingerprint(src)
    screenshots.record(cache_dir, "demo", b"\x89PNG" + b"0" * 60000, fingerprint, ok=True)

    monkeypatch.setattr(shots, "resolve_target",
                         lambda name, ctl=None: {"ok": True, "url": "http://1.2.3.4:8501/", "source": str(src)})

    calls = []

    async def spy_capture_app(*a, **kw):
        calls.append(a)
        return {"ok": True}

    monkeypatch.setattr(shots, "capture_app", spy_capture_app)

    rc = shots.main(["demo", "--force"])

    assert rc == 0
    assert len(calls) == 1


def test_main_captures_when_stale(tmp_path, monkeypatch, capsys):
    from secubox_core import screenshots

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(cache_dir))
    src = _app(tmp_path)
    screenshots.record(cache_dir, "demo", b"\x89PNG" + b"0" * 60000, "stale-fingerprint", ok=True)

    monkeypatch.setattr(shots, "resolve_target",
                         lambda name, ctl=None: {"ok": True, "url": "http://1.2.3.4:8501/", "source": str(src)})

    calls = []

    async def spy_capture_app(*a, **kw):
        calls.append(a)
        return {"ok": True}

    monkeypatch.setattr(shots, "capture_app", spy_capture_app)

    rc = shots.main(["demo"])

    assert rc == shots.EXIT_OK
    assert len(calls) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "written", \
        "a caller must be able to tell a written capture apart from every other outcome without parsing free text"


def test_main_rejected_capture_is_distinguishable_from_target_unavailable(tmp_path, monkeypatch, capsys):
    """#958: a capture that was ATTEMPTED (target resolved fine) but
    rejected by the render/validation pipeline is a different failure mode
    than a target that could never be resolved in the first place — mixing
    them under the same exit code would recreate the exact ambiguity this
    issue is about, just one level down."""
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(tmp_path / "cache"))
    src = _app(tmp_path)

    monkeypatch.setattr(shots, "resolve_target",
                         lambda name, ctl=None: {"ok": True, "url": "http://1.2.3.4:8501/", "source": str(src)})

    async def spy_capture_app(*a, **kw):
        return {"ok": False, "error": "boom"}

    monkeypatch.setattr(shots, "capture_app", spy_capture_app)

    rc = shots.main(["demo"])

    assert rc == shots.EXIT_REJECTED
    assert rc != shots.EXIT_TARGET_UNAVAILABLE
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "rejected"


def test_main_skips_when_another_capture_holds_the_lock(tmp_path, monkeypatch):
    """Serialization invariant (#957 §3.4): two triggers racing (e.g. a
    manual recapture click landing while a lazy wake-capture is already
    running) must never launch two chromiums."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("SECUBOX_STREAMLIT_SHOTS_CACHE", str(cache_dir))
    held = shots.acquire_lock(cache_dir / shots.LOCK_NAME)
    assert held is not None

    calls = []

    def spy_resolve(name, ctl=None):
        calls.append(name)
        return {"ok": True, "url": "http://1.2.3.4:8501/", "source": "/x"}

    monkeypatch.setattr(shots, "resolve_target", spy_resolve)

    rc = shots.main(["demo"])

    assert rc == 0
    assert calls == [], "target resolution (and a fortiori capture) must not run while locked"
    held.release()


def test_main_usage_error_on_missing_name():
    rc = shots.main([])
    assert rc == 2
