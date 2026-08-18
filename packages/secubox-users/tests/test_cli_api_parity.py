# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""CLI ↔ API parity: same mutation, same resulting users.json."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from api import engine

ROOT = Path(__file__).resolve().parents[3]
USERSCTL = ROOT / "packages" / "secubox-users" / "sbin" / "usersctl"

VOLATILE = {"created", "last_login", "enrolled_at", "used_at"}


def _strip_volatile(doc: dict) -> dict:
    """Recursively replace volatile fields with a placeholder so they don't cause spurious diffs."""
    def _walk(obj):
        if isinstance(obj, dict):
            return {k: ("<v>" if k in VOLATILE else _walk(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(x) for x in obj]
        return obj
    return _walk(doc)


def _fresh_state(tmp_path: Path) -> Path:
    p = tmp_path / "users.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return p


def _run_cli(state_path: Path, *args: str) -> None:
    env = os.environ.copy()
    env["USERS_FILE"] = str(state_path)
    env["PYTHONPATH"] = str(ROOT / "common") + ":" + str(ROOT / "packages" / "secubox-users")
    r = subprocess.run([sys.executable, str(USERSCTL), *args], env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"usersctl {args} failed: {r.stderr}"


def test_parity_add_disable_enable(tmp_path: Path):
    """add → disable → enable sequence via CLI and via engine should produce identical users.json."""
    via_cli = _fresh_state(tmp_path / "a")
    via_api = _fresh_state(tmp_path / "b")

    # CLI mutation sequence
    _run_cli(via_cli, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    _run_cli(via_cli, "disable", "alice")
    _run_cli(via_cli, "enable", "alice")

    # API (in-process engine) — same sequence
    e = engine.Engine(users_path=via_api)
    e.create_user("alice", email="a@b.c", role="viewer")
    e.disable_user("alice")
    e.enable_user("alice")

    cli_doc = _strip_volatile(json.loads(via_cli.read_text()))
    api_doc = _strip_volatile(json.loads(via_api.read_text()))
    assert cli_doc == api_doc, f"parity diff:\nCLI: {json.dumps(cli_doc, indent=2)}\nAPI: {json.dumps(api_doc, indent=2)}"


def test_parity_multiple_users(tmp_path: Path):
    """Create two users via CLI vs API; final users.json should be identical (modulo timestamps)."""
    via_cli = _fresh_state(tmp_path / "a")
    via_api = _fresh_state(tmp_path / "b")

    _run_cli(via_cli, "add", "alice", "--email", "alice@x.y", "--role", "viewer")
    _run_cli(via_cli, "add", "bob", "--email", "bob@x.y", "--role", "operator")

    e = engine.Engine(users_path=via_api)
    e.create_user("alice", email="alice@x.y", role="viewer")
    e.create_user("bob", email="bob@x.y", role="operator")

    cli_doc = _strip_volatile(json.loads(via_cli.read_text()))
    api_doc = _strip_volatile(json.loads(via_api.read_text()))
    assert cli_doc == api_doc


def test_parity_clear_password_after_set(tmp_path: Path, monkeypatch):
    """Set then clear password: CLI vs API produce same end state (no password, must_change_password=true)."""
    # We need to bypass the interactive getpass prompt. The CLI uses getpass.getpass which
    # falls back to stdin when no TTY is present. Provide a strong password via stdin.

    via_cli = _fresh_state(tmp_path / "a")
    via_api = _fresh_state(tmp_path / "b")

    # First create the user via CLI / API
    _run_cli(via_cli, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    e = engine.Engine(users_path=via_api)
    e.create_user("alice", email="a@b.c", role="viewer")

    # Set strong password
    pw = "StrongPass!42xyz"
    env = os.environ.copy()
    env["USERS_FILE"] = str(via_cli)
    env["PYTHONPATH"] = str(ROOT / "common") + ":" + str(ROOT / "packages" / "secubox-users")
    proc = subprocess.run(
        [sys.executable, str(USERSCTL), "set-password", "alice"],
        env=env, input=f"{pw}\n{pw}\n", capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr

    # Match API side: same set then clear
    e.set_password("alice", pw)

    # Now CLEAR via both
    _run_cli(via_cli, "clear-password", "alice")
    e.clear_password("alice")

    # After clear, password_hash should be None on both sides (set+clear sequence makes the hash
    # value moot for parity — both paths erase it). must_change_password must be True.
    cli_doc = json.loads(via_cli.read_text())
    api_doc = json.loads(via_api.read_text())

    assert cli_doc["users"][0]["password_hash"] is None
    assert api_doc["users"][0]["password_hash"] is None
    assert cli_doc["users"][0]["must_change_password"] is True
    assert api_doc["users"][0]["must_change_password"] is True

    # And the rest of the doc (modulo volatile) should match
    cli_doc_s = _strip_volatile(cli_doc)
    api_doc_s = _strip_volatile(api_doc)
    assert cli_doc_s == api_doc_s
