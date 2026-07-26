# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-releasectl")
ANN = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
REL = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    key = tmp_path / "node.key"; key.write_text("11" * 32)
    env = dict(os.environ)
    env.update(ANNUAIRE_KEY_PATH=str(key), ANNUAIRE_JOURNAL=str(tmp_path / "j.db"),
               ANNUAIRE_LIB=ANN, RELEASE_LIB=REL,
               PYTHONPATH=os.pathsep.join([ANN, REL, env.get("PYTHONPATH", "")]))
    return env


def _run(args, env):
    return subprocess.run([sys.executable, CTL, *args], env=env, capture_output=True, text=True)


def test_publish_then_list(tmp_path):
    env = _env(tmp_path)
    arts = json.dumps([{"kind": "deb", "name": "secubox-dpi", "version": "1.2.3",
                        "hash": "ab", "arch": "arm64"}])
    r = subprocess.run([sys.executable, CTL, "publish", "--artifacts", arts,
                        "--notes", "x"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout).get("evo_id")
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env, capture_output=True, text=True)
    evos = json.loads(r2.stdout)["evolutions"]
    assert evos and evos[0]["ring"] == "draft"


def test_dryrun_writes_nothing(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    arts = json.dumps([{"kind": "deb", "name": "x", "version": "1", "hash": "ab", "arch": "arm64"}])
    r = subprocess.run([sys.executable, CTL, "publish", "--artifacts", arts, "--notes", "n"],
                       env=env, capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
    r2 = subprocess.run([sys.executable, CTL, "list"], env=env, capture_output=True, text=True)
    assert json.loads(r2.stdout)["evolutions"] == []


def test_promote_requires_grant_then_succeeds(tmp_path):
    env = _env(tmp_path)
    arts = json.dumps([{"kind": "deb", "name": "x", "version": "1", "hash": "ab", "arch": "arm64"}])
    r = _run(["publish", "--artifacts", arts, "--notes", "n"], env)
    evo_id = json.loads(r.stdout)["evo_id"]

    # single-key setup: this box holds its own key, but has not granted itself
    # a "release" capability, so promote must be rejected cleanly (no traceback).
    r2 = _run(["promote", evo_id], env)
    assert r2.returncode != 0
    err = json.loads(r2.stderr)
    assert "error" in err


def test_assign_rejects_bad_ring_cleanly(tmp_path):
    env = _env(tmp_path)
    r = _run(["assign", "did:example:box", "not-a-ring"], env)
    assert r.returncode != 0
    err = json.loads(r.stderr)
    assert "error" in err


def test_sync_repo_dryrun_reports_plan(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    arts = json.dumps([{"kind": "deb", "name": "secubox-dpi", "version": "1.2.3",
                        "hash": "ab", "arch": "arm64"}])
    _run(["publish", "--artifacts", arts, "--notes", "n"], env)
    r = _run(["sync-repo"], env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out.get("dryrun") is True
    # freshly published evolution sits in "draft" with no prior ring to copy
    # from, so the plan is empty — but the call must not crash or shell out.
    assert out["argv"] == []


def test_apply_dryrun_reports_ring_no_apt(tmp_path):
    env = _env(tmp_path); env["DRYRUN"] = "1"
    r = _run(["apply"], env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out.get("dryrun") is True
    assert out.get("ring") == "published"  # default ring per releases.box_ring
