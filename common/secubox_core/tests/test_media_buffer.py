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
