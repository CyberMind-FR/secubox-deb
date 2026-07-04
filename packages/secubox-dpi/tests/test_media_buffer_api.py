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
