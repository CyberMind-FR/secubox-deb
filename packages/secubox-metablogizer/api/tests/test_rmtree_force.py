# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for _rmtree_force — must clear Gitea-style read-only .git subtrees."""
import os
import shutil
from pathlib import Path

import pytest

from rmtree import force_remove as _rmtree_force


def _make_locked_git_tree(root: Path) -> Path:
    """Build a fake site dir that mimics a Gitea-cloned layout (0500 .git, 0444 packs)."""
    site = root / "fakesite"
    site.mkdir()
    (site / "site.json").write_text("{}")
    git = site / ".git"
    git.mkdir()
    objects = git / "objects" / "pack"
    objects.mkdir(parents=True)
    pack = objects / "pack-abcd.pack"
    pack.write_bytes(b"\x00" * 32)
    # Lock down: pack file read-only, objects dir read-execute only, .git read-execute only.
    os.chmod(pack, 0o444)
    os.chmod(objects, 0o500)
    os.chmod(git / "objects", 0o500)
    os.chmod(git, 0o500)
    return site


def test_rmtree_force_clears_locked_git_subtree(tmp_path):
    site = _make_locked_git_tree(tmp_path)
    # Sanity check: vanilla rmtree fails on this tree.
    with pytest.raises(PermissionError):
        shutil.rmtree(site)
    # Rebuild (the failed rmtree may have partially mutated state).
    if site.exists():
        # Best-effort cleanup so the test can re-create cleanly.
        for p in site.rglob("*"):
            try:
                os.chmod(p, 0o700)
            except OSError:
                pass
        shutil.rmtree(site)
    site = _make_locked_git_tree(tmp_path)
    _rmtree_force(site)
    assert not site.exists()


def test_rmtree_force_clears_plain_directory(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "a.txt").write_text("a")
    (plain / "sub").mkdir()
    (plain / "sub" / "b.txt").write_text("b")
    _rmtree_force(plain)
    assert not plain.exists()
