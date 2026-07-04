# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for the shared media-buffer JSONL metatag reader (ref #812)."""
import json

from secubox_core import media_buffer as mb


def _write(tmp_path, records, name="media-buffer.jsonl"):
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return str(p)


def test_read_records_dedup_and_expired(tmp_path):
    p = tmp_path / "media-buffer.jsonl"
    p.write_text(
        '{"id":"a","mac_hash":"m1","first_ts":1,"expired":false,"buffer_ref":"s1"}\n'
        '{"id":"a","mac_hash":"m1","first_ts":1,"expired":true,"buffer_ref":null}\n'
        '{"id":"b","mac_hash":"m2","first_ts":2,"expired":false,"buffer_ref":"s2"}\n'
    )
    recs = mb.read_records(str(p))
    assert len(recs) == 2                       # deduped
    a = mb.record_by_id("a", str(p))
    assert a["expired"] is True                 # last line wins
    assert [r["id"] for r in mb.read_records(str(p), mac_hash="m2")] == ["b"]
    assert mb.read_records(str(tmp_path / "missing.jsonl")) == []   # fail-empty


def test_record_by_id_missing_returns_none(tmp_path):
    path = _write(tmp_path, [
        {"id": "a", "mac_hash": "m1", "first_ts": 1, "expired": False, "buffer_ref": "s1"},
    ])
    assert mb.record_by_id("does-not-exist", path) is None
    assert mb.record_by_id("a", str(tmp_path / "missing.jsonl")) is None


def test_mac_hash_filter_returns_only_matching(tmp_path):
    path = _write(tmp_path, [
        {"id": "a", "mac_hash": "m1", "first_ts": 1, "expired": False, "buffer_ref": "s1"},
        {"id": "b", "mac_hash": "m2", "first_ts": 2, "expired": False, "buffer_ref": "s2"},
        {"id": "c", "mac_hash": "m1", "first_ts": 3, "expired": False, "buffer_ref": "s3"},
    ])
    recs = mb.read_records(path, mac_hash="m1")
    assert {r["id"] for r in recs} == {"a", "c"}


def test_fail_empty_missing_file(tmp_path):
    assert mb.read_records(str(tmp_path / "nope.jsonl")) == []
    assert mb.record_by_id("x", str(tmp_path / "nope.jsonl")) is None


def test_fail_empty_corrupt_and_partial_lines(tmp_path):
    p = tmp_path / "media-buffer.jsonl"
    p.write_text(
        '{"id":"a","mac_hash":"m1","first_ts":1,"expired":false,"buffer_ref":"s1"}\n'
        "this-is-not-json\n"
        '{"id":"b"' + "\n"  # partial/truncated JSON line
        '{"id":"c","mac_hash":"m1","first_ts":3,"expired":false,"buffer_ref":"s3"}\n'
    )
    recs = mb.read_records(str(p))
    ids = {r["id"] for r in recs}
    assert ids == {"a", "c"}


def test_fail_empty_empty_file(tmp_path):
    p = tmp_path / "media-buffer.jsonl"
    p.write_text("")
    assert mb.read_records(str(p)) == []


def test_newest_first_ordering(tmp_path):
    path = _write(tmp_path, [
        {"id": "a", "mac_hash": "m1", "first_ts": 5, "expired": False, "buffer_ref": "s1"},
        {"id": "b", "mac_hash": "m1", "first_ts": 20, "expired": False, "buffer_ref": "s2"},
        {"id": "c", "mac_hash": "m1", "first_ts": 10, "expired": False, "buffer_ref": "s3"},
    ])
    recs = mb.read_records(path)
    assert [r["id"] for r in recs] == ["b", "c", "a"]


def test_max_lines_bounds_result_count(tmp_path):
    records = [
        {"id": str(i), "mac_hash": "m1", "first_ts": i, "expired": False, "buffer_ref": "s"}
        for i in range(10)
    ]
    path = _write(tmp_path, records)
    recs = mb.read_records(path, max_lines=3)
    assert len(recs) == 3
    # tail read keeps the most-recently-appended lines (highest first_ts)
    assert {r["id"] for r in recs} == {"7", "8", "9"}


def test_bounded_tail_read_drops_partial_first_line(tmp_path):
    """Regression test: _tail_lines (copy-pasted from media_catch, ref #785
    Fix 1) must only read the tail `max_bytes` of the file — and must drop
    the partial first line produced by a mid-line seek — for media_buffer's
    own record shape too.

    20 records, each JSON-encoded to an identical 86-byte line (+1 newline =
    87 bytes/line, 1740 bytes total: `id` is zero-padded to a fixed width and
    `first_ts` is offset by 100 so every record has the same digit count,
    keeping every line byte-identical in length so the math is deterministic.
    With max_bytes=200, the read starts at offset size-200=1540, which lands
    61 bytes into record #17's line (a 26-byte partial tail, including its
    trailing newline), followed by the 2 full trailing lines (#18, #19).
    After dropping the partial first line, exactly 2 valid records remain.
    """
    records = [
        {"id": f"r{i:03d}", "mac_hash": "m1", "first_ts": i + 100,
         "expired": False, "buffer_ref": "s"}
        for i in range(20)
    ]
    path = _write(tmp_path, records)

    recs = mb.read_records(path, max_bytes=200, max_lines=2000)

    # (a) does not raise (implicit — call above completed)
    # (b) only tail records returned — far fewer than the 20 written, and no
    #     corrupted/partial record from the seek boundary
    ids = {r["id"] for r in recs}
    assert ids == {"r018", "r019"}
    # (c) the newest records (nearest the tail) survive, newest-first
    assert [r["id"] for r in recs] == ["r019", "r018"]
    # the partial first line from the seek (record #17) was dropped, not
    # miscounted or returned malformed
    assert "r017" not in ids


def test_valid_json_missing_id_or_first_ts(tmp_path):
    """Regression test: a valid-JSON record missing `id` must be excluded
    (can't be deduped/looked up safely — see _deduped_records), while a
    valid-JSON record missing `first_ts` must still be returned and sorted
    as if first_ts=0, without raising (see read_records' `or 0` fallback).
    """
    path = _write(tmp_path, [
        # missing "id" entirely -> skipped by _deduped_records
        {"mac_hash": "m1", "first_ts": 5, "expired": False, "buffer_ref": "missing-id-marker"},
        {"id": "has-first-ts", "mac_hash": "m1", "first_ts": 10, "expired": False, "buffer_ref": "s2"},
        # missing "first_ts" -> sorts as 0, still returned
        {"id": "no-first-ts", "mac_hash": "m1", "expired": False, "buffer_ref": "s3"},
    ])

    recs = mb.read_records(path)  # must not raise

    assert len(recs) == 2  # the id-less record is excluded
    assert {r["id"] for r in recs} == {"has-first-ts", "no-first-ts"}
    # newest-first: the record with first_ts=10 outranks the missing-first_ts
    # record, which is treated as first_ts=0
    assert [r["id"] for r in recs] == ["has-first-ts", "no-first-ts"]
