# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox-Deb ToolBoX :: tests for federated mesh-tagged filter entries."""
from secubox_toolbox import api as A


def test_fed_rows_tagged_mesh(tmp_path, monkeypatch):
    fs = tmp_path / "fs"; fs.write_text("fed.example\n")
    monkeypatch.setattr(A, "FED_SPLICE_FILE", fs)
    monkeypatch.setattr(A, "FED_BYPASS_FILE", tmp_path / "nope1")
    monkeypatch.setattr(A, "FED_DISABLED_FILE", tmp_path / "nope2")
    # isolate the other sources to empty
    for name in ("MITM_BYPASS_SEED_FILE", "MITM_BYPASS_FILE", "MITM_BYPASS_DYNAMIC_FILE",
                 "TLS_SPLICE_SEED_FILE", "SPLICE_LEARNED_FILE", "MITM_FILTER_DISABLED_FILE"):
        monkeypatch.setattr(A, name, tmp_path / ("empty_" + name))
    rows = A._load_bypass_tagged()
    fed = [r for r in rows if r["pattern"] == "fed.example"]
    assert fed and fed[0]["source"] == "mesh-splice" and fed[0]["editable"] is False


def test_fed_disabled_pattern_shows_enabled_false(tmp_path, monkeypatch):
    """#806 fix — a pattern disabled elsewhere in the fleet (FED_DISABLED_FILE)
    must union into _load_disabled(), and a mesh-disabled row must render with
    enabled=False even though the LOCAL disabled file is empty."""
    fed_disabled = tmp_path / "fed_disabled.txt"
    fed_disabled.write_text("foo.example\n")
    local_disabled = tmp_path / "local_disabled.txt"  # empty / absent
    monkeypatch.setattr(A, "FED_DISABLED_FILE", fed_disabled)
    monkeypatch.setattr(A, "MITM_FILTER_DISABLED_FILE", local_disabled)

    disabled = A._load_disabled()
    assert "foo.example" in disabled

    # Also surface foo.example as a mesh-disabled row and check enabled=False.
    monkeypatch.setattr(A, "FED_SPLICE_FILE", tmp_path / "nope1")
    monkeypatch.setattr(A, "FED_BYPASS_FILE", tmp_path / "nope2")
    for name in ("MITM_BYPASS_SEED_FILE", "MITM_BYPASS_FILE", "MITM_BYPASS_DYNAMIC_FILE",
                 "TLS_SPLICE_SEED_FILE", "SPLICE_LEARNED_FILE"):
        monkeypatch.setattr(A, name, tmp_path / ("empty_" + name))
    rows = A._load_bypass_tagged()
    row = [r for r in rows if r["pattern"] == "foo.example"]
    assert row and row[0]["source"] == "mesh-disabled" and row[0]["enabled"] is False
