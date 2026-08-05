# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Playlist download support for the PeerTube Import tab (#981).

The panel's "Import" tab is what actually executes downloads: it calls
PeerTube's own native HTTP import (POST /videos/imports, one video per call),
NOT secubox-ytsas (a separate module/panel with its own yt-dlp gateway,
uninvolved here). A playlist URL used to either get rejected or silently
yield just its first video. These tests cover: detecting a playlist URL,
surviving one item's failure without aborting the rest, and not
re-downloading an item already completed by a previous run of the same
playlist.
"""
import asyncio
import json

import pytest

from api import main as m


# ─────────────────────────────────────────────────────────── URL heuristic ──

def test_looks_like_playlist_url_true_for_list_param():
    assert m._looks_like_playlist_url(
        "https://www.youtube.com/watch?v=abc123&list=PLxyz") is True


def test_looks_like_playlist_url_true_for_playlist_path():
    assert m._looks_like_playlist_url(
        "https://www.youtube.com/playlist?list=PLxyz") is True


def test_looks_like_playlist_url_false_for_plain_video():
    assert m._looks_like_playlist_url(
        "https://www.youtube.com/watch?v=abc123") is False


def test_looks_like_playlist_url_false_for_empty():
    assert m._looks_like_playlist_url("") is False


# ───────────────────────────────────────────────────── flat-playlist probe ──

def test_is_playlist_result_true_with_entries():
    assert m._is_playlist_result({"entries": [{"id": "a"}, {"id": "b"}]}) is True


def test_is_playlist_result_false_single_video():
    # A lone video probed with --flat-playlist has no "entries" key at all.
    assert m._is_playlist_result({"id": "abc123", "title": "solo video"}) is False


def test_is_playlist_result_false_empty_entries():
    assert m._is_playlist_result({"entries": []}) is False


def test_playlist_entries_extracts_url_title_source_id():
    meta = {"entries": [
        {"id": "vid1", "title": "First", "url": "https://example.com/watch?v=vid1"},
        {"id": "vid2", "title": "Second", "webpage_url": "https://example.com/watch?v=vid2"},
    ]}
    entries = m._playlist_entries(meta)
    assert entries == [
        {"url": "https://example.com/watch?v=vid1", "title": "First", "source_id": "vid1"},
        {"url": "https://example.com/watch?v=vid2", "title": "Second", "source_id": "vid2"},
    ]


def test_playlist_entries_reconstructs_bare_youtube_id():
    # --flat-playlist on a youtube:tab extraction often yields a bare id with
    # no url/webpage_url — reconstruct a canonical watch URL for those.
    meta = {"entries": [{"id": "abc123", "title": "T", "ie_key": "Youtube"}]}
    entries = m._playlist_entries(meta)
    assert entries == [{"url": "https://www.youtube.com/watch?v=abc123",
                         "title": "T", "source_id": "abc123"}]


def test_playlist_entries_skips_unusable_entries():
    meta = {"entries": [{"title": "no id or url"}, None, {"id": "x", "url": "https://e.com/x"}]}
    entries = m._playlist_entries(meta)
    assert entries == [{"url": "https://e.com/x", "title": "x", "source_id": "x"}]


# ─────────────────────────────────────────────── endpoint short-circuit ──

def test_import_playlist_short_circuits_non_playlist_url(monkeypatch):
    """A plain video URL never spends a yt-dlp probe subprocess."""
    monkeypatch.setattr(m, "is_running", lambda: True)

    async def _boom(url):
        raise AssertionError("probe must not run for a non-playlist-looking URL")
    monkeypatch.setattr(m, "_probe_playlist", _boom)

    out = asyncio.run(m.import_playlist(
        m.PlaylistImport(target_url="https://www.youtube.com/watch?v=abc123"),
        user={"sub": "bob"}))
    assert out["success"] is False
    assert out["is_playlist"] is False


def test_import_playlist_reports_when_probe_says_single_video(monkeypatch):
    monkeypatch.setattr(m, "is_running", lambda: True)
    monkeypatch.setattr(m, "get_admin_token", lambda: "tok")

    async def _fake_probe(url):
        return {"id": "abc123", "title": "solo"}
    monkeypatch.setattr(m, "_probe_playlist", _fake_probe)

    out = asyncio.run(m.import_playlist(
        m.PlaylistImport(target_url="https://www.youtube.com/watch?v=abc123&list=RDabc123"),
        user={"sub": "bob"}))
    assert out["success"] is False
    assert out["is_playlist"] is False


def test_import_playlist_queues_job(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "PLAYLIST_JOBS_FILE", tmp_path / "playlist-jobs.json")
    m._playlist_jobs.clear()
    monkeypatch.setattr(m, "is_running", lambda: True)
    monkeypatch.setattr(m, "get_admin_token", lambda: "tok")
    monkeypatch.setattr(m, "default_channel_id", lambda token: 5)

    async def _fake_probe(url):
        return {"title": "My Playlist", "entries": [
            {"id": "v1", "title": "One", "url": "https://e.com/v1"},
            {"id": "v2", "title": "Two", "url": "https://e.com/v2"},
        ]}
    monkeypatch.setattr(m, "_probe_playlist", _fake_probe)

    # Prevent the real background worker from actually running during the test.
    monkeypatch.setattr(m, "_ensure_playlist_worker", lambda: None)
    m._playlist_queue = asyncio.Queue()

    out = asyncio.run(m.import_playlist(
        m.PlaylistImport(target_url="https://www.youtube.com/playlist?list=PL1"),
        user={"sub": "bob"}))
    assert out["success"] is True
    assert out["total"] == 2
    job = m._playlist_jobs[out["job_id"]]
    assert job["channel_id"] == 5
    assert [i["status"] for i in job["items"]] == ["pending", "pending"]


# ───────────────────────────────────────────────── one failure keeps going ──

def test_process_playlist_job_continues_after_item_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "PLAYLIST_JOBS_FILE", tmp_path / "playlist-jobs.json")
    m._playlist_jobs.clear()
    monkeypatch.setattr(m, "get_admin_token", lambda: "tok")

    job_id = "job1"
    m._playlist_jobs[job_id] = {
        "id": job_id, "target_url": "https://e.com/playlist", "title": "P",
        "channel_id": 5, "privacy": 1, "name_prefix": None,
        "created_at": 0, "status": "queued", "current_index": -1,
        "items": [
            {"url": "https://e.com/v1", "title": "One", "source_id": "v1",
             "status": "pending", "video_uuid": None, "import_id": None, "error": None},
            {"url": "https://e.com/v2", "title": "Two", "source_id": "v2",
             "status": "pending", "video_uuid": None, "import_id": None, "error": None},
            {"url": "https://e.com/v3", "title": "Three", "source_id": "v3",
             "status": "pending", "video_uuid": None, "import_id": None, "error": None},
        ],
    }

    calls = []

    async def _fake_submit(target_url, channel_id, privacy, name, token):
        calls.append(target_url)
        if target_url == "https://e.com/v2":
            return {"success": False, "error": "quota exceeded"}
        return {"success": True, "import_id": target_url, "video_uuid": "u-" + target_url}

    async def _fake_await(import_id, token, timeout=None, poll_interval=None):
        return {"terminal": True, "success": True, "label": "success",
                "video_uuid": "u-" + import_id}

    monkeypatch.setattr(m, "_submit_import", _fake_submit)
    monkeypatch.setattr(m, "_await_import_terminal", _fake_await)

    asyncio.run(m._process_playlist_job(job_id))

    job = m._playlist_jobs[job_id]
    statuses = [i["status"] for i in job["items"]]
    assert statuses == ["done", "error", "done"], (
        "one item failing must not abort the rest of the playlist")
    assert job["items"][1]["error"] == "quota exceeded"
    assert job["status"] == "complete"
    # every item was attempted exactly once
    assert calls == ["https://e.com/v1", "https://e.com/v2", "https://e.com/v3"]


def test_process_playlist_job_stops_when_cancelling(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "PLAYLIST_JOBS_FILE", tmp_path / "playlist-jobs.json")
    m._playlist_jobs.clear()
    monkeypatch.setattr(m, "get_admin_token", lambda: "tok")

    job_id = "job2"
    m._playlist_jobs[job_id] = {
        "id": job_id, "target_url": "https://e.com/playlist", "title": "P",
        "channel_id": 5, "privacy": 1, "name_prefix": None,
        "created_at": 0, "status": "cancelling", "current_index": -1,
        "items": [
            {"url": "https://e.com/v1", "title": "One", "source_id": "v1",
             "status": "pending", "video_uuid": None, "import_id": None, "error": None},
        ],
    }

    async def _must_not_run(*a, **kw):
        raise AssertionError("no item should be submitted once cancelling")
    monkeypatch.setattr(m, "_submit_import", _must_not_run)

    asyncio.run(m._process_playlist_job(job_id))
    job = m._playlist_jobs[job_id]
    assert job["status"] == "cancelled"
    assert job["items"][0]["status"] == "pending"


# ───────────────────────────────────────────────────────────── resume ──

def test_carry_forward_done_skips_already_downloaded():
    m._playlist_jobs.clear()
    m._playlist_jobs["prior"] = {
        "id": "prior", "target_url": "https://e.com/playlist",
        "items": [
            {"url": "https://e.com/v1", "title": "One", "source_id": "v1",
             "status": "done", "video_uuid": "uuid-1", "import_id": "imp-1", "error": None},
            {"url": "https://e.com/v2", "title": "Two", "source_id": "v2",
             "status": "error", "video_uuid": None, "import_id": None, "error": "boom"},
        ],
    }
    entries = [
        {"url": "https://e.com/v1", "title": "One", "source_id": "v1"},
        {"url": "https://e.com/v2", "title": "Two", "source_id": "v2"},
        {"url": "https://e.com/v3", "title": "Three", "source_id": "v3"},
    ]
    items = m._carry_forward_done("https://e.com/playlist", entries)
    statuses = {i["source_id"]: i["status"] for i in items}
    assert statuses == {"v1": "done", "v2": "pending", "v3": "pending"}
    v1 = next(i for i in items if i["source_id"] == "v1")
    assert v1["video_uuid"] == "uuid-1"


def test_process_playlist_job_skips_items_already_done(monkeypatch, tmp_path):
    """A relaunch of a partially-fetched playlist must not re-download what a
    previous run already completed for the SAME item (source_id)."""
    monkeypatch.setattr(m, "PLAYLIST_JOBS_FILE", tmp_path / "playlist-jobs.json")
    m._playlist_jobs.clear()
    monkeypatch.setattr(m, "get_admin_token", lambda: "tok")

    job_id = "job3"
    m._playlist_jobs[job_id] = {
        "id": job_id, "target_url": "https://e.com/playlist", "title": "P",
        "channel_id": 5, "privacy": 1, "name_prefix": None,
        "created_at": 0, "status": "queued", "current_index": -1,
        "items": [
            {"url": "https://e.com/v1", "title": "One", "source_id": "v1",
             "status": "done", "video_uuid": "uuid-1", "import_id": "imp-1", "error": None},
            {"url": "https://e.com/v2", "title": "Two", "source_id": "v2",
             "status": "pending", "video_uuid": None, "import_id": None, "error": None},
        ],
    }

    calls = []

    async def _fake_submit(target_url, channel_id, privacy, name, token):
        calls.append(target_url)
        return {"success": True, "import_id": "imp-2", "video_uuid": "uuid-2"}

    async def _fake_await(import_id, token, timeout=None, poll_interval=None):
        return {"terminal": True, "success": True, "label": "success", "video_uuid": "uuid-2"}

    monkeypatch.setattr(m, "_submit_import", _fake_submit)
    monkeypatch.setattr(m, "_await_import_terminal", _fake_await)

    asyncio.run(m._process_playlist_job(job_id))

    assert calls == ["https://e.com/v2"], "the already-done item must not be re-submitted"
    job = m._playlist_jobs[job_id]
    assert job["items"][0]["video_uuid"] == "uuid-1"  # untouched
    assert job["items"][1]["status"] == "done"
    assert job["status"] == "complete"


# ─────────────────────────────────────────────────────────────── cancel ──

def test_cancel_playlist_job_marks_cancelling(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "PLAYLIST_JOBS_FILE", tmp_path / "playlist-jobs.json")
    m._playlist_jobs.clear()
    m._playlist_jobs["j"] = {"id": "j", "status": "running", "items": []}
    out = asyncio.run(m.cancel_playlist_job("j", user={"sub": "bob"}))
    assert out["success"] is True
    assert m._playlist_jobs["j"]["status"] == "cancelling"


def test_cancel_playlist_job_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "PLAYLIST_JOBS_FILE", tmp_path / "playlist-jobs.json")
    m._playlist_jobs.clear()
    out = asyncio.run(m.cancel_playlist_job("nope", user={"sub": "bob"}))
    assert out["success"] is False


# ────────────────────────────────────────────────────────── persistence ──

def test_atomic_write_json_never_touches_tmp_dir(tmp_path, monkeypatch):
    """CLAUDE.md: temp file must be written in the SAME directory, never /tmp."""
    seen_dirs = []
    real_replace = m.os.replace

    def spy_replace(src, dst):
        seen_dirs.append(str(src))
        return real_replace(src, dst)

    monkeypatch.setattr(m.os, "replace", spy_replace)
    target = tmp_path / "sub" / "jobs.json"
    m._atomic_write_json(target, {"a": 1})
    assert target.exists()
    assert json.loads(target.read_text()) == {"a": 1}
    assert len(seen_dirs) == 1
    assert seen_dirs[0].startswith(str(tmp_path / "sub")), \
        "temp file must live in the destination directory, not /tmp"
