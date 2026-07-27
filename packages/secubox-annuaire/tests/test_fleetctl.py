# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_fleetctl
Pytest coverage for sbin/sbx-fleetctl (feat/fleet-metrics, Task 4) — exercised
via subprocess, exactly as an operator/timer would invoke it, against a temp
box key + temp fleet_store self.json, mirroring test_centersctl.py's idiom.

Tests:
  - `publish` signs a MetricSnapshot with the box's own node key and writes a
    verify_snapshot()-passing record to FLEET_SELF_PATH.
  - `[metrics] fleet_publish = false` in SECUBOX_CONF -> {"skipped": ...},
    rc0, nothing written.
  - DRYRUN=1 -> prints the plan, writes nothing.
  - a missing box key fails clearly (rc!=0, JSON error) instead of silently
    generating one.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PKG_ROOT = Path(__file__).resolve().parents[1]
CLI = PKG_ROOT / "sbin" / "sbx-fleetctl"

sys.path.insert(0, str(PKG_ROOT))
from annuaire import fleet  # noqa: E402
from annuaire.crypto import did_from_pubkey, generate_keypair, public_from_private  # noqa: E402


def _run(args, env, timeout=20):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture()
def env(tmp_path):
    """Env pointing the CLI at a fresh temp box key + fleet self.json.

    METRICS_CACHE_PATH / ANNUAIRE_DB_PATH are pointed at nonexistent temp
    files so metrics_collect's default readers degrade to safe zero values
    (never touching real board state) -- collect_snapshot is read-only by
    contract, this just keeps the test hermetic.
    """
    box_priv, _box_pub = generate_keypair()
    key_path = tmp_path / "box.key"
    key_path.write_text(box_priv.hex())

    e = os.environ.copy()
    e["ANNUAIRE_LIB"] = str(PKG_ROOT)
    e["ANNUAIRE_KEY_PATH"] = str(key_path)
    e["FLEET_SELF_PATH"] = str(tmp_path / "self.json")
    e["METRICS_CACHE_PATH"] = str(tmp_path / "no-such-cache.json")
    e["ANNUAIRE_DB_PATH"] = str(tmp_path / "no-such-journal.db")
    e["SECUBOX_CONF"] = str(tmp_path / "secubox.conf")  # absent -> fleet_publish defaults True
    e.pop("DRYRUN", None)
    return e


@pytest.fixture()
def box_did(env):
    priv = bytes.fromhex(Path(env["ANNUAIRE_KEY_PATH"]).read_text().strip())
    return did_from_pubkey(public_from_private(priv))


# ---------------------------------------------------------------------------
# publish: happy path
# ---------------------------------------------------------------------------


def test_publish_writes_verified_self_record(env, box_did):
    proc = _run(["publish"], env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["published"] == box_did

    self_path = Path(env["FLEET_SELF_PATH"])
    assert self_path.exists()
    rec = json.loads(self_path.read_text())
    assert rec["node_did"] == box_did
    assert fleet.verify_snapshot(rec) is True


# ---------------------------------------------------------------------------
# fleet_publish = false -> skipped
# ---------------------------------------------------------------------------


def test_fleet_publish_disabled_is_skipped(env):
    Path(env["SECUBOX_CONF"]).write_text("[metrics]\nfleet_publish = false\n")

    proc = _run(["publish"], env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"skipped": "fleet_publish disabled"}
    assert not Path(env["FLEET_SELF_PATH"]).exists()


def test_fleet_publish_true_explicit_still_publishes(env, box_did):
    Path(env["SECUBOX_CONF"]).write_text("[metrics]\nfleet_publish = true\n")

    proc = _run(["publish"], env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["published"] == box_did


# ---------------------------------------------------------------------------
# DRYRUN=1 -> preview only, writes nothing
# ---------------------------------------------------------------------------


def test_dryrun_publish_writes_nothing(env, box_did):
    dry_env = {**env, "DRYRUN": "1"}
    proc = _run(["publish"], dry_env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["dryrun"] is True
    assert out["would"] == "publish"
    assert out["node_did"] == box_did
    assert not Path(env["FLEET_SELF_PATH"]).exists()


# ---------------------------------------------------------------------------
# box key provisioning -- never silently generated
# ---------------------------------------------------------------------------


def test_missing_box_key_fails_clearly(env):
    os.remove(env["ANNUAIRE_KEY_PATH"])

    proc = _run(["publish"], env)
    assert proc.returncode != 0
    err = json.loads(proc.stderr)
    assert "error" in err
    assert "box key" in err["error"]
