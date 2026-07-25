# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_centersctl
Pytest coverage for sbin/sbx-centersctl (Task 7) — the CLI is exercised via
subprocess, exactly as an operator would invoke it, against a temp journal +
temp box key.

Tests:
  - `grant <A> firewall baseline` -> rc0; `list` shows (firewall,baseline)->A.
  - `grant <A> auth baseline` -> rc!=0, stderr JSON {"error":
    "scope-not-delegatable"}; `list` unchanged (nothing was written).
  - `revoke <grant_id>` (captured from grant's stdout JSON) -> rc0; `list` no
    longer shows the grant.
  - `route` does not crash on a journal with just grants (no CONFIG_PUBLISH
    entries -> applied == [], proposals == []).
  - a missing box key fails clearly (rc!=0, JSON error) instead of silently
    generating one — the box key is sovereign identity, never minted here.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PKG_ROOT = Path(__file__).resolve().parents[1]
CLI = PKG_ROOT / "sbin" / "sbx-centersctl"

sys.path.insert(0, str(PKG_ROOT))
from annuaire.crypto import did_from_pubkey, generate_keypair  # noqa: E402


def _run(args, env, timeout=10):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture()
def env(tmp_path):
    """Env pointing the CLI at a fresh temp journal + a generated box key."""
    box_priv, _box_pub = generate_keypair()
    key_path = tmp_path / "box.key"
    key_path.write_text(box_priv.hex())

    e = os.environ.copy()
    e["ANNUAIRE_LIB"] = str(PKG_ROOT)
    e["ANNUAIRE_JOURNAL"] = str(tmp_path / "journal.db")
    e["ANNUAIRE_KEY"] = str(key_path)
    e["CONFIG_TARGET_DIR"] = str(tmp_path / "etc")
    e["CONFIG_LOCAL_DIR"] = str(tmp_path / "config-local")
    return e


@pytest.fixture()
def center_did():
    """A center DID to receive grants (only the did:plc shape matters here)."""
    _priv, pub = generate_keypair()
    return did_from_pubkey(pub)


# ---------------------------------------------------------------------------
# grant + list: happy path
# ---------------------------------------------------------------------------


def test_grant_then_list_shows_it(env, center_did):
    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode == 0, proc.stderr
    granted = json.loads(proc.stdout)
    assert granted["center_did"] == center_did
    assert granted["scope"] == "firewall"
    assert granted["layer"] == "baseline"
    assert granted["grant_id"]

    proc = _run(["list"], env)
    assert proc.returncode == 0, proc.stderr
    matrix = json.loads(proc.stdout)["grants"]
    assert len(matrix) == 1
    assert matrix[0]["scope"] == "firewall"
    assert matrix[0]["layer"] == "baseline"
    assert matrix[0]["center_did"] == center_did


# ---------------------------------------------------------------------------
# grant: rejection (validated before any journal write)
# ---------------------------------------------------------------------------


def test_grant_non_delegatable_scope_rejected(env, center_did):
    proc = _run(["grant", center_did, "auth", "baseline"], env)
    assert proc.returncode != 0
    err = json.loads(proc.stderr)
    assert err["error"] == "scope-not-delegatable"

    proc = _run(["list"], env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["grants"] == []


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


def test_revoke_clears_the_grant(env, center_did):
    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode == 0, proc.stderr
    grant_id = json.loads(proc.stdout)["grant_id"]

    proc = _run(["revoke", grant_id], env)
    assert proc.returncode == 0, proc.stderr
    revoked = json.loads(proc.stdout)
    assert revoked["grant_id"] == grant_id

    proc = _run(["list"], env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["grants"] == []


# ---------------------------------------------------------------------------
# route: must not crash on a grants-only journal
# ---------------------------------------------------------------------------


def test_route_does_not_crash_on_grants_only_journal(env, center_did):
    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode == 0, proc.stderr

    proc = _run(["route"], env)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["applied"] == []
    assert result["proposals"] == []


def test_route_works_without_box_key(env, center_did):
    """route_config's self_did is best-effort — an absent box key must not
    prevent routing (a node may only ever apply centers' delegated config)."""
    _run(["grant", center_did, "firewall", "baseline"], env)
    os.remove(env["ANNUAIRE_KEY"])

    proc = _run(["route"], env)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["applied"] == []
    assert result["proposals"] == []


# ---------------------------------------------------------------------------
# box key provisioning — never silently generated
# ---------------------------------------------------------------------------


def test_missing_box_key_fails_clearly(env, center_did):
    os.remove(env["ANNUAIRE_KEY"])

    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode != 0
    err = json.loads(proc.stderr)
    assert "error" in err
    assert "box key" in err["error"]


# ---------------------------------------------------------------------------
# DRYRUN=1 — grant/revoke/route must preview only, writing nothing
# ---------------------------------------------------------------------------


def test_dryrun_grant_writes_nothing(env, center_did):
    env = {**env, "DRYRUN": "1"}
    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["dryrun"] is True
    assert out["would"] == "grant"
    assert out["scope"] == "firewall"
    assert out["layer"] == "baseline"
    assert out["valid"] is True

    proc = _run(["list"], env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["grants"] == []


def test_dryrun_grant_reports_invalid_without_dying(env, center_did):
    """Even a request that WOULD be rejected previews cleanly (rc0, no journal write)."""
    env = {**env, "DRYRUN": "1"}
    proc = _run(["grant", center_did, "auth", "baseline"], env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["dryrun"] is True
    assert out["valid"] is False
    assert out["reason"] == "scope-not-delegatable"

    proc = _run(["list"], env)
    assert json.loads(proc.stdout)["grants"] == []


def test_dryrun_revoke_writes_nothing(env, center_did):
    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode == 0, proc.stderr
    grant_id = json.loads(proc.stdout)["grant_id"]

    dry_env = {**env, "DRYRUN": "1"}
    proc = _run(["revoke", grant_id], dry_env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["dryrun"] is True
    assert out["would"] == "revoke"
    assert out["grant_id"] == grant_id

    # the real grant is still active — DRYRUN never touched the journal
    proc = _run(["list"], env)
    matrix = json.loads(proc.stdout)["grants"]
    assert len(matrix) == 1
    assert matrix[0]["scope"] == "firewall"


def test_dryrun_route_writes_nothing(env, center_did):
    proc = _run(["grant", center_did, "firewall", "baseline"], env)
    assert proc.returncode == 0, proc.stderr

    dry_env = {**env, "DRYRUN": "1"}
    proc = _run(["route"], dry_env)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["dryrun"] is True
    assert out["would"] == "route"
    assert "firewall" in out["scopes"]

    # nothing was applied to CONFIG_TARGET_DIR
    assert not Path(env["CONFIG_TARGET_DIR"]).exists()
