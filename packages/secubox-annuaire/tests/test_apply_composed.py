# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys, tomllib; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire.config_apply import apply_composed

def test_apply_composed_writes_merged(tmp_path):
    r = apply_composed("firewall", ['x = 1\n[net]\nb = 1\n', '[net]\nb = 2\n', 'x = 9\n'], str(tmp_path))
    assert r["status"] == "applied"
    doc = tomllib.loads((tmp_path/"firewall.toml").read_text())
    assert doc["x"] == 9 and doc["net"]["b"] == 2

def test_apply_composed_idempotent_skip(tmp_path):
    layers = ['x = 1\n']
    assert apply_composed("s", layers, str(tmp_path))["status"] == "applied"
    assert apply_composed("s", layers, str(tmp_path))["status"] == "skip"

def test_apply_composed_bad_toml_keeps_lastgood(tmp_path):
    apply_composed("s", ['good = 1\n'], str(tmp_path))
    before = (tmp_path/"s.toml").read_text()
    r = apply_composed("s", ['this is = = not toml\n'], str(tmp_path))
    assert r["status"] == "reject"
    assert (tmp_path/"s.toml").read_text() == before   # last-good untouched


# ---------------------------------------------------------------------------
# path traversal via scope — CRITICAL: scope becomes a filename component,
# so a scope that walks out of target_dir must be rejected BEFORE any Path
# is ever built from it.
# ---------------------------------------------------------------------------

def test_apply_composed_rejects_dotdot_scope(tmp_path):
    r = apply_composed("../../../../tmp/pwned", ["x=1\n"], str(tmp_path))
    assert r["status"] == "reject"
    assert r["reason"] == "invalid-scope"
    # nothing escaped tmp_path: no .toml anywhere outside it, and tmp_path
    # itself only ever gets what apply_composed legitimately wrote in other
    # tests in this module (none here) — assert it stayed empty.
    assert list(tmp_path.rglob("*.toml")) == []
    assert not Path("/tmp/pwned.toml").exists()


def test_apply_composed_rejects_slash_scope(tmp_path):
    r = apply_composed("etc/passwd", ["x=1\n"], str(tmp_path))
    assert r["status"] == "reject"
    assert r["reason"] == "invalid-scope"
    assert list(tmp_path.rglob("*.toml")) == []


def test_apply_composed_rejects_absolute_path_scope(tmp_path):
    r = apply_composed("/etc/pwned", ["x=1\n"], str(tmp_path))
    assert r["status"] == "reject"
    assert r["reason"] == "invalid-scope"
    assert not Path("/etc/pwned.toml").exists()
