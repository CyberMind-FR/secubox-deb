# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for _media_stats — media-type donut data for the report (ref #785)."""
import json
from secubox_toolbox import api


def _write(tmp_path, records):
    p = tmp_path / "media-catch.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def test_media_stats_shapes_donuts(tmp_path, monkeypatch):
    path = _write(tmp_path, [
        {"client": "aa", "host": "v", "kind": "video", "ctype": "video/mp4", "bytes": 10},
        {"client": "aa", "host": "a", "kind": "audio", "ctype": "audio/mp4", "bytes": 5},
        {"client": "bb", "host": "m", "kind": "manifest", "ctype": "x/y", "bytes": 1},
    ])
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", path)
    out = api._media_stats("aa")
    assert out["me"]["present"] is True
    assert out["all"]["present"] is True
    # donut segments carry pct + cumulative bounds
    seg = out["me"]["kinds"][0]
    assert "pct" in seg and "start" in seg and "end" in seg
    assert sum(s["pct"] for s in out["me"]["kinds"]) in (99, 100, 101)


def test_media_stats_fail_empty(tmp_path, monkeypatch):
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", str(tmp_path / "absent.jsonl"))
    out = api._media_stats("aa")
    assert out["me"]["present"] is False
    assert out["all"]["present"] is False
