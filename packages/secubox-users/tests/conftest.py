"""Shared fixtures for secubox-users unit tests."""
import json
import sys
from pathlib import Path

import pytest

# Make both `secubox_core` and the package's own api/ importable.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))


@pytest.fixture
def tmp_users_json(tmp_path: Path) -> Path:
    """Empty v2 users.json (no users yet)."""
    path = tmp_path / "users.json"
    path.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    return path


@pytest.fixture
def tmp_sessions_json(tmp_path: Path) -> Path:
    """Empty sessions.json."""
    path = tmp_path / "sessions.json"
    path.write_text("[]")
    return path
