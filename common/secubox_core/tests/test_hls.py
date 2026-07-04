# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for secubox_core.hls — HLS media-playlist parser/rewriter."""
from __future__ import annotations

from secubox_core import hls

MEDIA_PLAYLIST = """#EXTM3U
#EXT-X-VERSION:6
#EXT-X-TARGETDURATION:6
#EXT-X-PLAYLIST-TYPE:VOD
#EXT-X-MAP:URI="init.mp4"
#EXTINF:6.006,
seg0.ts
#EXTINF:6.006,
seg1.ts
#EXTINF:6.006,
seg2.ts
#EXT-X-ENDLIST
"""

MASTER_PLAYLIST = """#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=1280000,RESOLUTION=640x360
low/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2560000,RESOLUTION=1280x720
high/index.m3u8
"""

ENCRYPTED_PLAYLIST = """#EXTM3U
#EXT-X-VERSION:6
#EXT-X-KEY:METHOD=AES-128,URI="key.bin",IV=0x0123456789abcdef0123456789abcdef
#EXTINF:6.006,
seg0.ts
#EXT-X-ENDLIST
"""

UNENCRYPTED_KEY_PLAYLIST = """#EXTM3U
#EXT-X-KEY:METHOD=NONE
#EXTINF:6.006,
seg0.ts
#EXT-X-ENDLIST
"""

BASE_URL = "https://h/hls/index.m3u8"


def test_segment_uris_ordered_with_map_first():
    assert hls.segment_uris(MEDIA_PLAYLIST) == [
        "init.mp4", "seg0.ts", "seg1.ts", "seg2.ts",
    ]


def test_segment_uris_no_map():
    text = "#EXTM3U\n#EXTINF:6,\nseg0.ts\n#EXT-X-ENDLIST\n"
    assert hls.segment_uris(text) == ["seg0.ts"]


def test_resolve_relative():
    assert hls.resolve(BASE_URL, "seg0.ts") == "https://h/hls/seg0.ts"


def test_resolve_keeps_query():
    abs_url = hls.resolve(BASE_URL, "https://h/hls/seg0.ts?x=1")
    assert abs_url == "https://h/hls/seg0.ts?x=1"


def test_resolve_normalizes_http_to_https():
    abs_url = hls.resolve(BASE_URL, "http://h/hls/seg0.ts")
    assert abs_url == "https://h/hls/seg0.ts"


def test_rewrite_partial_mapping():
    mapping = {
        "https://h/hls/init.mp4": "/api/v1/dpi/media/replay/aaa",
        "https://h/hls/seg0.ts": "/api/v1/dpi/media/replay/bbb",
    }
    rewritten, matched, total = hls.rewrite(MEDIA_PLAYLIST, mapping, BASE_URL)
    assert matched == 2
    assert total == 4
    assert '#EXT-X-MAP:URI="/api/v1/dpi/media/replay/aaa"' in rewritten
    assert "/api/v1/dpi/media/replay/bbb" in rewritten
    assert "seg1.ts" in rewritten  # unmapped, unchanged
    assert "seg2.ts" in rewritten  # unmapped, unchanged
    assert "seg0.ts" not in rewritten  # mapped, replaced


def test_rewrite_no_matches_leaves_text_shape():
    rewritten, matched, total = hls.rewrite(MEDIA_PLAYLIST, {}, BASE_URL)
    assert matched == 0
    assert total == 4
    assert hls.segment_uris(rewritten) == hls.segment_uris(MEDIA_PLAYLIST)


def test_rewrite_caps_at_max_segments():
    lines = ["#EXTM3U"]
    for i in range(10):
        lines.append("#EXTINF:6,")
        lines.append(f"seg{i}.ts")
    lines.append("#EXT-X-ENDLIST")
    text = "\n".join(lines) + "\n"
    mapping = {f"https://h/hls/seg{i}.ts": f"/r/{i}" for i in range(10)}
    rewritten, matched, total = hls.rewrite(text, mapping, BASE_URL,
                                             max_segments=3)
    assert total == 3
    assert matched == 3
    # Segments beyond the cap are left untouched.
    assert "seg9.ts" in rewritten


def test_is_master_playlist_true():
    assert hls.is_master_playlist(MASTER_PLAYLIST) is True


def test_is_master_playlist_false_on_media_playlist():
    assert hls.is_master_playlist(MEDIA_PLAYLIST) is False


def test_is_encrypted_true():
    assert hls.is_encrypted(ENCRYPTED_PLAYLIST) is True


def test_is_encrypted_false_on_method_none():
    assert hls.is_encrypted(UNENCRYPTED_KEY_PLAYLIST) is False


def test_is_encrypted_false_on_no_key():
    assert hls.is_encrypted(MEDIA_PLAYLIST) is False


def test_fail_safe_empty_string():
    assert hls.is_master_playlist("") is False
    assert hls.is_encrypted("") is False
    assert hls.segment_uris("") == []
    rewritten, matched, total = hls.rewrite("", {}, BASE_URL)
    assert rewritten == ""
    assert matched == 0
    assert total == 0


def test_fail_safe_garbage_input():
    # All non-blank lines are tag lines ("#"-prefixed) — no bare segment
    # URIs — so parsing degrades cleanly to empty results, never raises.
    garbage = '#EXT-X-??? \x00\xff garbled\n#EXT-X-KEY:GARBAGE\n\n'
    assert hls.is_master_playlist(garbage) is False
    assert hls.is_encrypted(garbage) is False
    assert hls.segment_uris(garbage) == []
    rewritten, matched, total = hls.rewrite(garbage, {"x": "y"}, BASE_URL)
    assert rewritten == garbage
    assert matched == 0
    assert total == 0


def test_fail_safe_non_string_types_never_raise():
    assert hls.is_master_playlist(None) is False  # type: ignore[arg-type]
    assert hls.is_encrypted(None) is False  # type: ignore[arg-type]
    assert hls.segment_uris(None) == []  # type: ignore[arg-type]
    rewritten, matched, total = hls.rewrite(None, {}, BASE_URL)  # type: ignore[arg-type]
    assert rewritten == ""
    assert matched == 0
    assert total == 0
    assert hls.resolve(BASE_URL, None) == ""  # type: ignore[arg-type]
