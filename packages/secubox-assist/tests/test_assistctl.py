# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
import os
import subprocess
import sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-assistctl")
ASSIST = str(Path(__file__).resolve().parent.parent)
ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")


def _env(tmp_path):
    key = tmp_path / "node.key"
    # 32-byte raw Ed25519 as 64 hex
    key.write_text("11" * 32)
    env = dict(os.environ)
    env["ANNUAIRE_KEY_PATH"] = str(key)
    env["ANNUAIRE_JOURNAL"] = str(tmp_path / "journal.db")
    env["ANNUAIRE_LIB"] = ANNUAIRE
    env["ASSIST_LIB"] = ASSIST
    env["PYTHONPATH"] = ANNUAIRE + os.pathsep + ASSIST + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_request_then_list(tmp_path):
    env = _env(tmp_path)
    center = "did:plc:" + "2" * 32
    r = subprocess.run([sys.executable, CTL, "request", center, "--mode",
                        "per-incident", "--scope", "dns", "--duration", "600",
                        "--reason", "help"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out.get("req_id")
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env,
                        capture_output=True, text=True)
    listing = json.loads(r2.stdout)
    assert len(listing["pending"]) == 1


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    center = "did:plc:" + "2" * 32
    r = subprocess.run([sys.executable, CTL, "request", center, "--mode",
                        "standing", "--scope", "dns", "--duration", "600",
                        "--reason", "x"], env=env, capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env,
                        capture_output=True, text=True)
    assert json.loads(r2.stdout)["pending"] == []


def test_request_bad_mode_returns_json_error_not_traceback(tmp_path):
    env = _env(tmp_path)
    center = "did:plc:" + "2" * 32
    r = subprocess.run([sys.executable, CTL, "request", center, "--mode",
                        "bogus-mode", "--scope", "dns", "--duration", "600",
                        "--reason", "help"], env=env, capture_output=True, text=True)
    assert r.returncode != 0
    combined = (r.stdout + r.stderr).strip()
    assert "Traceback" not in combined, combined
    payload = json.loads(r.stderr.strip() or r.stdout.strip())
    assert "error" in payload
