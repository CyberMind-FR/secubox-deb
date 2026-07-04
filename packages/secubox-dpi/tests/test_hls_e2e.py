# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""End-to-end HLS reassembly test (Phase 2, ref #812).

`test_media_buffer_api.py` already unit-tests the manifest-replay branch in
isolation. This module is the CROSS-LAYER integration check the Phase-1
whole-branch review flagged as missing: it seeds a temp media-buffer that
mimics exactly what the Go tee + janitor write to disk (a metatag JSONL log
+ per-session `object-0.*` files), then drives the REAL `media_replay`
handler through the full chain:

    capture (metatag + object bytes)
      -> join (manifest url + segment urls, same mac_hash/host)
      -> rewrite (secubox_core.hls)
      -> per-segment replay (FileResponse, byte-identical to the capture)
      -> janitor eviction flip (append-only, last-line-wins)

Handlers are plain `def` (aggregator-mounted; ref #808) so we call them
directly, exactly like `test_media_buffer_api.py`.
"""
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # make api importable
from fastapi import HTTPException  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from api import main as m  # noqa: E402

ADMIN = {"role": "admin", "sub": "root"}

# Hex-conformant ids/session ids (^[0-9a-f]{8,32}$) — session_id doubles as
# the on-disk directory name and is itself validated against the same regex
# by `_resolve_object_path`, so both must stay pure hex.
MANIFEST_ID = "e5e5111122223333"
MANIFEST_SESSION = "e5e5111122223333aaaa"
SEG0_ID = "e5e5aaaa11112222"
SEG0_SESSION = "e5e5aaaa11112222bbbb"
SEG1_ID = "e5e5bbbb11112222"
SEG1_SESSION = "e5e5bbbb11112222cccc"
SEG2_ID = "e5e5cccc11112222"
SEG2_SESSION = "e5e5cccc11112222dddd"

HOST = "h"
MAC_HASH = "M"

# A realistic 3-segment VOD media playlist — the exact shape sbxmitm's tee
# would have captured as the manifest's buffer object.
MEDIA_PLAYLIST = (
    "#EXTM3U\n"
    "#EXT-X-VERSION:3\n"
    "#EXT-X-TARGETDURATION:6\n"
    "#EXT-X-PLAYLIST-TYPE:VOD\n"
    "#EXTINF:6.000,\n"
    "seg0.ts\n"
    "#EXTINF:6.000,\n"
    "seg1.ts\n"
    "#EXTINF:6.000,\n"
    "seg2.ts\n"
    "#EXT-X-ENDLIST\n"
)

SEG0_BYTES = b"segment-zero-payload-0123456789"
SEG1_BYTES = b"segment-one-payload-abcdefghij"
SEG2_BYTES = b"segment-two-payload-ZZZZZZZZZZ"

_REPLAY_URL_RE = re.compile(r"/api/v1/dpi/media/replay/([0-9a-f]{8,32})")


def _write_object(tmp_path, session_id, filename, content):
    """Write <tmp_path>/<session_id>/<filename>, mimicking the buffer-object
    layout the Go tee writes under MEDIA_BUFFER_ROOT."""
    obj_dir = tmp_path / session_id
    obj_dir.mkdir(exist_ok=True)
    if isinstance(content, str):
        content = content.encode("utf-8")
    (obj_dir / filename).write_bytes(content)


def _rec(rec_id, session_id, url, kind, ctype, expired=False, buffer_ref=None):
    """Build one metatag-log record, matching the shape sbxmitm/the janitor
    append to media-buffer.jsonl (see secubox_core.media_buffer)."""
    return {
        "id": rec_id, "session_id": session_id, "first_ts": 10, "last_ts": 10,
        "mac_hash": MAC_HASH, "host": HOST, "url": url, "direction": "down",
        "kind": kind, "ctype": ctype, "bytes": len(url), "segments": 0,
        "truncated": False,
        "buffer_ref": buffer_ref if buffer_ref is not None else (None if expired else session_id),
        "expired": expired,
    }


def _seed_full_capture(tmp_path):
    """Seed a temp MEDIA_BUFFER_ROOT with a manifest + 3 live matching
    segments — the state right after capture, before any eviction."""
    log = tmp_path / "media-buffer.jsonl"
    manifest = _rec(MANIFEST_ID, MANIFEST_SESSION, "https://h/hls/index.m3u8",
                     kind="manifest", ctype="application/vnd.apple.mpegurl")
    seg0 = _rec(SEG0_ID, SEG0_SESSION, "https://h/hls/seg0.ts",
                kind="segment", ctype="video/mp2t")
    seg1 = _rec(SEG1_ID, SEG1_SESSION, "https://h/hls/seg1.ts",
                kind="segment", ctype="video/mp2t")
    seg2 = _rec(SEG2_ID, SEG2_SESSION, "https://h/hls/seg2.ts",
                kind="segment", ctype="video/mp2t")
    log.write_text("\n".join(json.dumps(r) for r in (manifest, seg0, seg1, seg2)) + "\n")

    _write_object(tmp_path, MANIFEST_SESSION, "object-0.m3u8", MEDIA_PLAYLIST)
    _write_object(tmp_path, SEG0_SESSION, "object-0.ts", SEG0_BYTES)
    _write_object(tmp_path, SEG1_SESSION, "object-0.ts", SEG1_BYTES)
    _write_object(tmp_path, SEG2_SESSION, "object-0.ts", SEG2_BYTES)
    return log


def _append_janitor_eviction_flip(log_path, rec_id, session_id, url):
    """Append-only eviction flip, exactly as the janitor does: a fresh line
    for the SAME id with expired=true/buffer_ref=null — never rewrites
    history. `_deduped_records` in secubox_core.media_buffer is last-line-wins
    by id, so this is what actually flips the record for every reader."""
    flip = _rec(rec_id, session_id, url, kind="segment", ctype="video/mp2t",
                expired=True, buffer_ref=None)
    with open(log_path, "a") as f:
        f.write(json.dumps(flip) + "\n")


def test_hls_e2e_full_chain_capture_join_rewrite_replay(tmp_path, monkeypatch):
    """Capture -> join -> rewrite -> per-segment replay, all live."""
    _seed_full_capture(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    resp = m.media_replay(MANIFEST_ID, request=None, user=ADMIN)
    assert not isinstance(resp, FileResponse)
    assert resp.media_type == "application/vnd.apple.mpegurl"
    body = resp.body.decode("utf-8")

    header = resp.headers.get("x-secubox-media") or resp.headers.get("X-SecuBox-Media")
    assert header is not None
    assert "hls-reassembled" in header
    assert "matched=3" in header
    assert "total=3" in header

    # Every original segment URI was rewritten — none of the raw names survive.
    assert "seg0.ts" not in body
    assert "seg1.ts" not in body
    assert "seg2.ts" not in body

    rewritten_ids = _REPLAY_URL_RE.findall(body)
    assert rewritten_ids == [SEG0_ID, SEG1_ID, SEG2_ID]

    expected_bytes = {SEG0_ID: SEG0_BYTES, SEG1_ID: SEG1_BYTES, SEG2_ID: SEG2_BYTES}

    # Drive the REAL per-segment replay for every rewritten URL: this proves
    # the whole capture -> metatag -> join -> rewrite -> segment-replay chain,
    # not just that the URL string looks right.
    for seg_id in rewritten_ids:
        seg_resp = m.media_replay(seg_id, request=None, user=ADMIN)
        assert isinstance(seg_resp, FileResponse)
        assert Path(seg_resp.path).read_bytes() == expected_bytes[seg_id]


def test_hls_e2e_eviction_leaves_segment_unrewritten_and_410s(tmp_path, monkeypatch):
    """Janitor evicts seg2 (append-only flip) after capture: re-replaying the
    manifest must leave seg2.ts untouched (no live index entry) while seg0/
    seg1 still rewrite and replay correctly; replaying seg2's id now 410s."""
    log = _seed_full_capture(tmp_path)
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))

    # Sanity: before the flip, all 3 are live (mirrors the previous test).
    resp_before = m.media_replay(MANIFEST_ID, request=None, user=ADMIN)
    assert "seg2.ts" not in resp_before.body.decode("utf-8")

    _append_janitor_eviction_flip(log, SEG2_ID, SEG2_SESSION, "https://h/hls/seg2.ts")

    resp_after = m.media_replay(MANIFEST_ID, request=None, user=ADMIN)
    body_after = resp_after.body.decode("utf-8")
    header_after = (resp_after.headers.get("x-secubox-media")
                    or resp_after.headers.get("X-SecuBox-Media"))
    assert "matched=2" in header_after
    assert "total=3" in header_after

    # seg0/seg1 still rewritten and still replay to their captured bytes.
    assert f"/api/v1/dpi/media/replay/{SEG0_ID}" in body_after
    assert f"/api/v1/dpi/media/replay/{SEG1_ID}" in body_after
    seg0_resp = m.media_replay(SEG0_ID, request=None, user=ADMIN)
    assert Path(seg0_resp.path).read_bytes() == SEG0_BYTES
    seg1_resp = m.media_replay(SEG1_ID, request=None, user=ADMIN)
    assert Path(seg1_resp.path).read_bytes() == SEG1_BYTES

    # seg2 dropped out of the live index -> left UNCHANGED (not rewritten,
    # not in the rewritten playlist's live index) — partial playback, not a
    # broken rewrite.
    assert "seg2.ts" in body_after
    assert f"/api/v1/dpi/media/replay/{SEG2_ID}" not in body_after

    # And replaying seg2's own id directly now 410s (metatag-only, evicted).
    with pytest.raises(HTTPException) as e:
        m.media_replay(SEG2_ID, request=None, user=ADMIN)
    assert e.value.status_code == 410
