# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Test the DPI media-buffer API — list scoping, replay 410-on-evict,
path-traversal-safe id validation, admin/owner gating (ref #812).

Handlers are plain `def` (aggregator-mounted; ref #808) so we call them
directly instead of spinning a TestClient, mirroring the existing dpi tests.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # make api importable
from fastapi import HTTPException  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from api import main as m  # noqa: E402

# Hex-conformant ids/session ids (^[0-9a-f]{8,32}$).
LIVE_ID = "aabbccdd1122"
LIVE_SESSION = "aabbccdd11223344"
EXP_ID = "deadbeefcafe"
EXP_SESSION = "deadbeef99887766"

ADMIN = {"role": "admin", "sub": "root"}
NONADMIN = {"role": "user", "sub": "bob"}


def _seed_buffer(tmp_path):
    """Write a metatag log with one LIVE record (bytes on disk) + one EXPIRED
    record (metatag only), and the live session's object-0.* file."""
    log = tmp_path / "media-buffer.jsonl"
    live = {"id": LIVE_ID, "session_id": LIVE_SESSION, "first_ts": 2,
            "last_ts": 2, "mac_hash": "m1", "host": "cdn.example",
            "url": "https://cdn.example/v.mp4", "direction": "down",
            "kind": "video", "ctype": "video/mp4", "bytes": 5, "segments": 0,
            "truncated": False, "buffer_ref": LIVE_SESSION, "expired": False}
    expired = {"id": EXP_ID, "session_id": EXP_SESSION, "first_ts": 1,
               "last_ts": 1, "mac_hash": "m2", "host": "h2",
               "url": "https://h2/a.mp3", "direction": "down", "kind": "audio",
               "ctype": "audio/mpeg", "bytes": 3, "segments": 0,
               "truncated": False, "buffer_ref": None, "expired": True}
    log.write_text(json.dumps(live) + "\n" + json.dumps(expired) + "\n")
    obj_dir = tmp_path / LIVE_SESSION
    obj_dir.mkdir()
    (obj_dir / "object-0.mp4").write_bytes(b"hello")
    return log


def test_list_admin_sees_all_nonadmin_empty(tmp_path, monkeypatch):
    _seed_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    out = m.media_buffer_list(user=ADMIN)
    assert out["count"] == 2
    assert len(out["items"]) == 2

    # Phase 1: no JWT->persona mapping yet, so a non-admin owns nothing.
    out2 = m.media_buffer_list(user=NONADMIN)
    assert out2["count"] == 0
    assert out2["items"] == []


def test_replay_live_returns_fileresponse(tmp_path, monkeypatch):
    _seed_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    resp = m.media_replay(LIVE_ID, request=None, user=ADMIN)
    assert isinstance(resp, FileResponse)
    assert resp.path.endswith("object-0.mp4")
    assert Path(resp.path).read_bytes() == b"hello"
    assert resp.media_type == "video/mp4"


def test_replay_expired_raises_410(tmp_path, monkeypatch):
    _seed_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    with pytest.raises(HTTPException) as e:
        m.media_replay(EXP_ID, request=None, user=ADMIN)
    assert e.value.status_code == 410


def test_replay_missing_record_raises_410(tmp_path, monkeypatch):
    _seed_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    # well-formed hex id but no such record
    with pytest.raises(HTTPException) as e:
        m.media_replay("ffffffffffff", request=None, user=ADMIN)
    assert e.value.status_code == 410


@pytest.mark.parametrize("bad", ["../etc/passwd", "xyz", "", "AABBCCDD1122",
                                  "a" * 40])
def test_replay_bad_id_raises_400(tmp_path, monkeypatch, bad):
    _seed_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    with pytest.raises(HTTPException) as e:
        m.media_replay(bad, request=None, user=ADMIN)
    assert e.value.status_code == 400


def test_require_admin_or_owner_rejects_nonadmin(tmp_path, monkeypatch):
    # Non-admin has no persona mapping in Phase 1 -> 403 (owner of nothing).
    with pytest.raises(HTTPException) as e:
        m.require_admin_or_owner(user=NONADMIN)
    assert e.value.status_code == 403
    # Admin passes through.
    assert m.require_admin_or_owner(user=ADMIN) == ADMIN


def test_role_derived_from_user_store_when_absent(monkeypatch):
    """When the JWT carries only sub (no role claim), the role is resolved from
    the user store, exactly like secubox-peertube's require_admin."""
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "get_user",
                        lambda sub: {"role": "admin"} if sub == "root" else {"role": "user"})
    assert m._user_is_admin({"sub": "root"}) is True
    assert m._user_is_admin({"sub": "bob"}) is False


def test_thumb_missing_returns_404(tmp_path, monkeypatch):
    _seed_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))
    with pytest.raises(HTTPException) as e:
        m.media_thumb(LIVE_ID, user=ADMIN)
    assert e.value.status_code == 404
    # bad id still 400
    with pytest.raises(HTTPException) as e2:
        m.media_thumb("../x", user=ADMIN)
    assert e2.value.status_code == 400


# ============================================================================
# Phase 2 (#812) — HLS manifest reassembly branch.
# ============================================================================

MANIFEST_ID = "aaaa11112222"
MANIFEST_SESSION = "aaaa1111222233334444"
SEG0_ID = "bbbb11112222"
SEG0_SESSION = "bbbb1111222233334444"
SEG1_ID = "cccc11112222"
SEG1_SESSION = "cccc1111222233334444"
SEG2_EXP_ID = "dddd11112222"
SEG2_EXP_SESSION = "dddd1111222233334444"

MEDIA_PLAYLIST = (
    "#EXTM3U\n"
    "#EXT-X-VERSION:3\n"
    "#EXTINF:10.0,\n"
    "seg0.ts\n"
    "#EXTINF:10.0,\n"
    "seg1.ts\n"
    "#EXTINF:10.0,\n"
    "seg2.ts\n"
    "#EXT-X-ENDLIST\n"
)

MASTER_PLAYLIST = (
    "#EXTM3U\n"
    "#EXT-X-STREAM-INF:BANDWIDTH=1000000\n"
    "variant.m3u8\n"
)

ENCRYPTED_PLAYLIST = (
    "#EXTM3U\n"
    "#EXT-X-VERSION:3\n"
    '#EXT-X-KEY:METHOD=AES-128,URI="key.bin"\n'
    "#EXTINF:10.0,\n"
    "seg0.ts\n"
    "#EXT-X-ENDLIST\n"
)


def _write_object(tmp_path, session_id, filename, content):
    obj_dir = tmp_path / session_id
    obj_dir.mkdir()
    if isinstance(content, str):
        content = content.encode("utf-8")
    (obj_dir / filename).write_bytes(content)


def _hls_record(rec_id, session_id, url, kind="segment", host="h",
                 mac_hash="m1", ctype="video/mp2t", expired=False,
                 buffer_ref=None):
    return {"id": rec_id, "session_id": session_id, "first_ts": 3, "last_ts": 3,
            "mac_hash": mac_hash, "host": host, "url": url, "direction": "down",
            "kind": kind, "ctype": ctype, "bytes": 5, "segments": 0,
            "truncated": False,
            "buffer_ref": buffer_ref if buffer_ref is not None else (None if expired else session_id),
            "expired": expired}


def _seed_hls_buffer(tmp_path, manifest_text=MEDIA_PLAYLIST):
    """Seed a manifest + 2 live matching segments + 1 expired segment whose
    url would otherwise match seg2.ts."""
    log = tmp_path / "media-buffer.jsonl"
    manifest = _hls_record(MANIFEST_ID, MANIFEST_SESSION,
                            "https://h/hls/index.m3u8", kind="manifest",
                            ctype="application/vnd.apple.mpegurl")
    seg0 = _hls_record(SEG0_ID, SEG0_SESSION, "https://h/hls/seg0.ts")
    seg1 = _hls_record(SEG1_ID, SEG1_SESSION, "https://h/hls/seg1.ts")
    seg2_expired = _hls_record(SEG2_EXP_ID, SEG2_EXP_SESSION,
                                "https://h/hls/seg2.ts", expired=True)
    lines = [json.dumps(r) for r in (manifest, seg0, seg1, seg2_expired)]
    log.write_text("\n".join(lines) + "\n")

    _write_object(tmp_path, MANIFEST_SESSION, "object-0.m3u8", manifest_text)
    _write_object(tmp_path, SEG0_SESSION, "object-0.ts", b"seg0-bytes")
    _write_object(tmp_path, SEG1_SESSION, "object-0.ts", b"seg1-bytes")
    # No object written for the expired segment — it's metatag-only.
    return log


def test_manifest_replay_rewrites_live_segments_only(tmp_path, monkeypatch):
    _seed_hls_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    resp = m.media_replay(MANIFEST_ID, request=None, user=ADMIN)
    assert not isinstance(resp, FileResponse)
    assert resp.media_type == "application/vnd.apple.mpegurl"
    body = resp.body.decode("utf-8")

    assert f"/api/v1/dpi/media/replay/{SEG0_ID}" in body
    assert f"/api/v1/dpi/media/replay/{SEG1_ID}" in body
    assert "seg0.ts" not in body
    assert "seg1.ts" not in body
    # Expired segment has no live index entry -> left unchanged.
    assert "seg2.ts" in body

    header = resp.headers.get("x-secubox-media") or resp.headers.get("X-SecuBox-Media")
    assert header is not None
    assert "hls-reassembled" in header
    assert "matched=2" in header
    assert "total=3" in header


def test_manifest_replay_master_playlist_returns_raw_unsupported(tmp_path, monkeypatch):
    _seed_hls_buffer(tmp_path, manifest_text=MASTER_PLAYLIST)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    resp = m.media_replay(MANIFEST_ID, request=None, user=ADMIN)
    assert not isinstance(resp, FileResponse)
    assert resp.media_type == "application/vnd.apple.mpegurl"
    assert resp.body.decode("utf-8") == MASTER_PLAYLIST
    header = resp.headers.get("x-secubox-media") or resp.headers.get("X-SecuBox-Media")
    assert header == "unsupported-variant"


def test_manifest_replay_encrypted_returns_raw_unsupported(tmp_path, monkeypatch):
    _seed_hls_buffer(tmp_path, manifest_text=ENCRYPTED_PLAYLIST)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    resp = m.media_replay(MANIFEST_ID, request=None, user=ADMIN)
    assert not isinstance(resp, FileResponse)
    assert resp.body.decode("utf-8") == ENCRYPTED_PLAYLIST
    header = resp.headers.get("x-secubox-media") or resp.headers.get("X-SecuBox-Media")
    assert header == "unsupported-variant"


def test_segment_kind_replay_still_uses_phase1_fileresponse(tmp_path, monkeypatch):
    _seed_hls_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    resp = m.media_replay(SEG0_ID, request=None, user=ADMIN)
    assert isinstance(resp, FileResponse)
    assert resp.path.endswith("object-0.ts")
    assert Path(resp.path).read_bytes() == b"seg0-bytes"


def test_manifest_replay_phase1_invariants_hold(tmp_path, monkeypatch):
    """Bad id -> 400, expired manifest/segment -> 410 still hold for
    manifest/segment records exactly as for any other kind. The admin/owner
    gate itself (`require_admin_or_owner`) is dependency-injected by FastAPI
    ahead of the handler body — its 403-on-non-admin behavior is kind-agnostic
    and already covered by test_require_admin_or_owner_rejects_nonadmin; it
    applies identically here since the route declares no kind-specific
    override."""
    _seed_hls_buffer(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    with pytest.raises(HTTPException) as e:
        m.media_replay("not-hex!", request=None, user=ADMIN)
    assert e.value.status_code == 400

    with pytest.raises(HTTPException) as e2:
        m.media_replay(SEG2_EXP_ID, request=None, user=ADMIN)
    assert e2.value.status_code == 410

    with pytest.raises(HTTPException) as e3:
        m.require_admin_or_owner(user=NONADMIN)
    assert e3.value.status_code == 403
