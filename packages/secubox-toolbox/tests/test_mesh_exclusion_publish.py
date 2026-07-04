# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from secubox_toolbox import mesh_exclusion as mx


def test_local_lists_dedups_and_caps(tmp_path, monkeypatch):
    sp = tmp_path / "splice-learned.txt"; sp.write_text("a.com\na.com\nb.com\n")
    by = tmp_path / "bypass.conf"; by.write_text("(.+\\.)?x\\.com   # c\n(.+\\.)?x\\.com\n")
    di = tmp_path / "disabled.txt"; di.write_text("d.com\n")
    monkeypatch.setattr(mx, "LOCAL_SPLICE", sp)
    monkeypatch.setattr(mx, "LOCAL_BYPASS", by)
    monkeypatch.setattr(mx, "LOCAL_DISABLED", di)
    monkeypatch.setattr(mx, "FED_MAX", 10)
    lists = mx.local_lists()
    assert lists["splice"] == ["a.com", "b.com"]        # deduped, sorted
    assert lists["bypass"] == ["(.+\\.)?x\\.com"]        # inline-comment stripped, deduped
    assert lists["disabled"] == ["d.com"]


def test_build_payload_and_content_hash_stable():
    lists = {"splice": ["a.com"], "bypass": [], "disabled": []}
    p1 = mx.build_payload("gk2", lists)
    p2 = mx.build_payload("gk2", lists)
    assert p1["node"] == "gk2" and p1["splice"] == ["a.com"]
    assert mx.content_hash(p1) == mx.content_hash(p2)    # deterministic
    assert len(mx.content_hash(p1)) == 64                # blake2b-256 hex
