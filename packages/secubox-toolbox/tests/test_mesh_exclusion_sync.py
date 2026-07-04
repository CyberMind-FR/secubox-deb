# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import mesh_exclusion as mx


def test_union_blobs_dedups_across_nodes():
    blobs = [
        {"node": "gk2", "splice": ["a.com", "b.com"], "bypass": ["(.+\\.)?x\\.com"], "disabled": ["d.com"]},
        {"node": "c3box", "splice": ["b.com", "c.com"], "bypass": [], "disabled": ["e.com"]},
    ]
    u = mx.union_blobs(blobs)
    assert u["splice"] == ["a.com", "b.com", "c.com"]
    assert u["bypass"] == ["(.+\\.)?x\\.com"]
    assert u["disabled"] == ["d.com", "e.com"]


def test_sync_writes_fed_files_only_on_change(tmp_path, monkeypatch):
    monkeypatch.setattr(mx, "FED_SPLICE", tmp_path / "s.txt")
    monkeypatch.setattr(mx, "FED_BYPASS", tmp_path / "b.txt")
    monkeypatch.setattr(mx, "FED_DISABLED", tmp_path / "d.txt")
    monkeypatch.setattr(mx, "pull_blobs", lambda: [
        {"node": "gk2", "splice": ["a.com"], "bypass": [], "disabled": []}])
    r1 = mx.sync()
    assert r1["splice"] == 1 and (tmp_path / "s.txt").read_text() == "a.com\n"
    assert r1["changed"] is True
    r2 = mx.sync()                # same content → no rewrite
    assert r2["changed"] is False


def test_union_blobs_tolerates_malformed_fields():
    # a verified-but-malformed blob (non-list field) must be skipped, not crash
    blobs = [
        {"node": "bad", "splice": 123, "bypass": True, "disabled": None},
        {"node": "ok", "splice": ["a.com"], "bypass": [], "disabled": ["d.com"]},
    ]
    u = mx.union_blobs(blobs)          # must not raise
    assert u["splice"] == ["a.com"]
    assert u["disabled"] == ["d.com"]
    assert u["bypass"] == []
