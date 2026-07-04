# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.exposure_seed tests — create-time secure-by-default lan seeding (ref #793)."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-vhost"))

from api.exposure_seed import ensure_snippet, _LAN_BLOCK

# Both packages ship an `api` package, so importing secubox-exposure's api.reach
# by dotted path would collide with the already-imported secubox-vhost `api`
# namespace. Load it standalone by file path instead, under a distinct module
# name, to prove byte-for-byte equivalence without a naming collision.
_reach_path = ROOT / "packages" / "secubox-exposure" / "api" / "reach.py"
_spec = importlib.util.spec_from_file_location("exposure_reach_standalone", _reach_path)
_reach_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_reach_mod)
reach_snippet = _reach_mod.reach_snippet


def test_lan_block_byte_matches_exposure_reach_snippet():
    assert _LAN_BLOCK == reach_snippet("lan", False)


def test_ensure_snippet_writes_lan_block_when_absent(tmp_path):
    ok = ensure_snippet("new.example", snippet_dir=tmp_path)
    assert ok is True
    assert (tmp_path / "new.example.conf").read_text() == _LAN_BLOCK


def test_ensure_snippet_is_idempotent_does_not_overwrite_existing(tmp_path):
    (tmp_path / "existing.example.conf").write_text("allow 127.0.0.1;\ndeny all;\n")
    ok = ensure_snippet("existing.example", snippet_dir=tmp_path)
    assert ok is True
    # secubox-exposure is the authoritative editor once a snippet exists — untouched
    assert (tmp_path / "existing.example.conf").read_text() == "allow 127.0.0.1;\ndeny all;\n"


def test_ensure_snippet_returns_false_on_oserror(tmp_path, monkeypatch):
    import api.exposure_seed as es

    def _boom(*a, **kw):
        raise OSError("permission denied")
    monkeypatch.setattr(es.os, "replace", _boom)

    ok = ensure_snippet("blocked.example", snippet_dir=tmp_path)
    assert ok is False
    assert not (tmp_path / "blocked.example.conf").exists()


def test_ensure_snippet_writes_atomically_no_leftover_tmp(tmp_path):
    ensure_snippet("atomic.example", snippet_dir=tmp_path)
    assert not (tmp_path / "atomic.example.conf.tmp").exists()
