# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-assistctl")
ANN = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
ASSIST = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    key = tmp_path / "node.key"; key.write_text("11" * 32)
    env = dict(os.environ)
    env.update(ANNUAIRE_KEY_PATH=str(key), ANNUAIRE_JOURNAL=str(tmp_path / "j.db"),
               ANNUAIRE_LIB=ANN, ASSIST_LIB=ASSIST,
               PYTHONPATH=os.pathsep.join([ANN, ASSIST, env.get("PYTHONPATH", "")]))
    return env


def test_offer_then_matches_lists(tmp_path):
    env = _env(tmp_path)
    r = subprocess.run([sys.executable, CTL, "offer", "--tags", "lora", "--ttl",
                        "3600"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout).get("offer_id")


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    r = subprocess.run([sys.executable, CTL, "request-open", "--tags", "lora",
                        "--ttl", "600", "--reason", "x"], env=env,
                       capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
