# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for the shared media-catch JSONL aggregator (ref #785)."""
import json
from secubox_core import media_catch


def _write(tmp_path, records):
    p = tmp_path / "media-catch.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def test_absent_file_fail_empty(tmp_path):
    out = media_catch.aggregate(path=str(tmp_path / "nope.jsonl"), mac_hash="aa")
    assert out["all"]["present"] is False
    assert out["me"]["present"] is False
    assert out["all"]["kinds"] == [] and out["all"]["top_hosts"] == []


def test_aggregates_all_and_me(tmp_path):
    path = _write(tmp_path, [
        {"client": "aa", "host": "v.example", "kind": "video", "ctype": "video/mp4", "bytes": 1000},
        {"client": "aa", "host": "a.example", "kind": "audio", "ctype": "audio/mp4", "bytes": 500},
        {"client": "bb", "host": "m.example", "kind": "manifest", "ctype": "application/vnd.apple.mpegurl", "bytes": 100},
        {"client": "aa", "host": "v.example", "kind": "video", "ctype": "video/mp4", "bytes": 2000},
        "this-is-a-corrupt-line-not-json",
    ])
    out = media_catch.aggregate(path=path, mac_hash="aa")
    # all: 4 valid records (corrupt line skipped)
    assert out["all"]["present"] is True
    assert out["all"]["flows"] == 4
    assert out["all"]["bytes"] == 3600
    # me (client aa): 3 records
    me = out["me"]
    assert me["present"] is True
    assert me["flows"] == 3
    # kinds sorted by count desc — video (2) before audio (1)
    labels = [k["label"] for k in me["kinds"]]
    assert labels[0] == "video"
    assert {"video", "audio"} <= set(labels)
    # emoji mapped
    kmap = {k["label"]: k["emoji"] for k in me["kinds"]}
    assert kmap["video"] == "📺" and kmap["audio"] == "🎵"
    # ctypes carry counts + generic emoji
    assert any(c["label"] == "video/mp4" and c["count"] == 2 for c in me["ctypes"])
    # top_hosts sorted by bytes desc, carry kind
    assert me["top_hosts"][0]["host"] == "v.example"
    assert me["top_hosts"][0]["bytes"] == 3000
    assert me["top_hosts"][0]["kind"] == "video"


def test_no_mac_hash_me_empty(tmp_path):
    path = _write(tmp_path, [{"client": "aa", "host": "h", "kind": "video", "bytes": 1}])
    out = media_catch.aggregate(path=path)
    assert out["all"]["present"] is True
    assert out["me"]["present"] is False


def test_bounded_tail_read_drops_partial_first_line(tmp_path):
    """Regression test (Fix 1): _tail_lines/aggregate must only read the tail
    `max_bytes` of the file, not the whole thing — and must drop the partial
    first line produced by a mid-line seek.

    20 records, each JSON-encoded to an identical 63-byte line (+1 newline =
    64 bytes/line, 1280 bytes total) so the math is deterministic:
    with max_bytes=200, the read starts at offset size-200=1080, which lands
    56 bytes into record #16's line (a 7-byte partial tail), followed by the
    3 full trailing lines (#17, #18, #19). After dropping the partial first
    line, exactly 3 valid records remain.
    """
    records = [{"client": "aa", "host": f"h{i:03d}", "kind": "video", "bytes": 100}
               for i in range(20)]
    path = _write(tmp_path, records)

    out = media_catch.aggregate(path=path, mac_hash="aa", max_bytes=200)

    # (a) does not raise (implicit — call above completed)
    # (b) only tail records returned — far fewer than the 20 written
    assert out["all"]["present"] is True
    assert out["all"]["flows"] == 3
    assert out["all"]["bytes"] == 300
    hosts = {h["host"] for h in out["all"]["top_hosts"]}
    assert hosts == {"h017", "h018", "h019"}
    # (c) the partial first line from the seek was dropped, not miscounted
    assert "h016" not in hosts


def test_malformed_field_skipped_not_fatal(tmp_path):
    """Regression test: malformed bytes value must not crash aggregate (Finding 1 fix)."""
    path = _write(tmp_path, [
        {"client": "aa", "host": "good", "kind": "video", "bytes": 1000},
        {"client": "aa", "host": "bad", "kind": "video", "bytes": "oops"},  # non-numeric bytes
        {"client": "aa", "host": "good", "kind": "audio", "bytes": 500},
    ])
    # aggregate() must NOT raise; malformed record skipped in _summarize processing
    out = media_catch.aggregate(path=path, mac_hash="aa")
    # All 3 records pass JSON parsing, so flows=3; but malformed one is skipped in aggregation
    # so bytes only count the 2 good records (1000 + 500 = 1500)
    assert out["all"]["present"] is True
    assert out["all"]["flows"] == 3
    assert out["all"]["bytes"] == 1500
    assert out["me"]["flows"] == 3
    assert out["me"]["bytes"] == 1500
