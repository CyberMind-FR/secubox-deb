# packages/secubox-metablogizer/api/publish/backup.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Portable per-site backup: a .sbxsite tarball holding either a git bundle of
the site's gitea repo (full history) or a plain content tar, plus manifest.json."""
from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
from pathlib import Path


def export_site(site_dir: Path, manifest: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = site_dir.name
    manifest = dict(manifest)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        has_git = (site_dir / ".git").is_dir()
        manifest["has_git"] = has_git
        if has_git:
            subprocess.run(["git", "-C", str(site_dir), "bundle", "create",
                            str(tdp / "repo.bundle"), "--all"], check=True,
                           capture_output=True)
        else:
            with tarfile.open(tdp / "content.tar", "w") as t:
                t.add(site_dir / "public", arcname="public")
        (tdp / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        art = out_dir / f"{name}.sbxsite"
        with tarfile.open(art, "w:gz") as t:
            for member in ("repo.bundle", "content.tar", "manifest.json"):
                p = tdp / member
                if p.exists():
                    t.add(p, arcname=member)
    return art


def import_site(sbxsite: Path, dest_root: Path) -> dict:
    dest_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        with tarfile.open(sbxsite, "r:gz") as t:
            t.extractall(tdp, filter="data")
        manifest = json.loads((tdp / "manifest.json").read_text())
        name = manifest.get("name")
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise ValueError(f"invalid site name in manifest: {name!r}")
        target = dest_root / name
        if (tdp / "repo.bundle").exists():
            subprocess.run(["git", "clone", "-q", str(tdp / "repo.bundle"), str(target)],
                           check=True, capture_output=True)
        else:
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(tdp / "content.tar", "r") as ct:
                ct.extractall(target, filter="data")
    return manifest
