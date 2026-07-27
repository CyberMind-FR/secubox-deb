# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_fleet_store.py
Atomic self.json IO for fleet metrics (T3).
"""
import os

from annuaire import fleet_store

REC = {"node_did": "did:plc:" + "a" * 32, "hostname": "gk2", "cpu_pct": 10.0}


def test_write_then_read_roundtrip(tmp_path):
    path = str(tmp_path / "self.json")
    fleet_store.write(REC, path=path)
    assert fleet_store.read(path=path) == REC


def test_write_is_atomic_via_tmp_replace(tmp_path):
    path = str(tmp_path / "self.json")
    fleet_store.write(REC, path=path)
    # no leftover tmp file after a successful write
    assert not os.path.exists(path + ".tmp")
    assert os.path.exists(path)


def test_read_missing_file_returns_none(tmp_path):
    path = str(tmp_path / "does-not-exist.json")
    assert fleet_store.read(path=path) is None


def test_read_corrupt_json_returns_none(tmp_path):
    path = str(tmp_path / "self.json")
    with open(path, "w") as f:
        f.write("{not valid json")
    assert fleet_store.read(path=path) is None


def test_write_overwrites_existing(tmp_path):
    path = str(tmp_path / "self.json")
    fleet_store.write(REC, path=path)
    other = {**REC, "cpu_pct": 55.0}
    fleet_store.write(other, path=path)
    assert fleet_store.read(path=path) == other


def test_default_path_env_override(monkeypatch, tmp_path):
    override = str(tmp_path / "env-self.json")
    monkeypatch.setenv("FLEET_SELF_PATH", override)
    # Reload semantics: the module-level SELF_PATH is read at import time,
    # so we exercise it by calling write()/read() with the default arg
    # against a fresh import context — assert the constant itself picks up
    # the env at import time via importlib.reload.
    import importlib
    importlib.reload(fleet_store)
    try:
        assert fleet_store.SELF_PATH == override
        fleet_store.write(REC)
        assert fleet_store.read() == REC
    finally:
        importlib.reload(fleet_store)
