# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Safe extraction of an uploaded static-site archive into a site docroot."""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path


class ContentError(Exception):
    """Raised when an upload is unsafe (zip-slip / absolute path)."""


def _safe_join(root: Path, member: str) -> Path:
    # Reject absolute paths and any member that escapes root once resolved.
    if member.startswith("/") or member.startswith("\\"):
        raise ContentError(f"absolute path in archive: {member}")
    target = (root / member).resolve()
    if root.resolve() not in (target, *target.parents):
        raise ContentError(f"path escapes docroot: {member}")
    return target


def extract_archive(docroot: Path, data: bytes, filename: str) -> dict:
    docroot.mkdir(parents=True, exist_ok=True)
    name = (filename or "").lower()
    if name.endswith(".zip"):
        # Validate ALL members before writing anything.
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise ContentError(f"not a valid zip archive: {e}")
        with zf as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            targets = [_safe_join(docroot, m.filename) for m in members]
            # Clear previous content (a zip is a fresh publish; history is in gitea).
            for child in docroot.iterdir():
                if child.name == ".git":
                    continue
                shutil.rmtree(child) if child.is_dir() else child.unlink()
            total = 0
            for m, target in zip(members, targets):
                target.parent.mkdir(parents=True, exist_ok=True)
                blob = z.read(m)
                target.write_bytes(blob)
                total += len(blob)
        return {"files": len(members), "bytes": total,
                "index_present": (docroot / "index.html").exists()}

    # Single file: an .html (or anything) becomes index.html unless it has a
    # concrete non-index basename we should preserve.
    if name.endswith(".html") or "." not in Path(name).name:
        dest = docroot / "index.html"
    else:
        dest = _safe_join(docroot, Path(name).name)
    dest.write_bytes(data)
    return {"files": 1, "bytes": len(data), "index_present": (docroot / "index.html").exists()}
