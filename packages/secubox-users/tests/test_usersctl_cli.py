"""usersctl CLI smoke — same operations the API does, hit the same files."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
USERSCTL = ROOT / "packages" / "secubox-users" / "sbin" / "usersctl"


@pytest.fixture
def env(tmp_path: Path):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return {
        "PATH": os.environ["PATH"],
        "USERS_FILE": str(users),
        "PYTHONPATH": str(ROOT / "common") + ":" + str(ROOT / "packages" / "secubox-users"),
    }


def _run(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(USERSCTL), *args],
        env=env, capture_output=True, text=True,
    )


def test_add_lists_user(env):
    _run(env, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    out = _run(env, "list")
    assert "alice" in out.stdout


def test_disable_flips_enabled(env):
    _run(env, "add", "alice", "--email", "a@b.c", "--role", "viewer")
    _run(env, "disable", "alice")
    doc = json.loads(Path(env["USERS_FILE"]).read_text())
    assert doc["users"][0]["enabled"] is False


def test_help_is_zero_exit(env):
    r = _run(env, "--help")
    assert r.returncode == 0
    assert "usersctl" in r.stdout.lower() or "usage" in r.stdout.lower()
