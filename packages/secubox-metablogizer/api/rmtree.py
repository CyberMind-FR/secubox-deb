# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: metablogizer :: rmtree helper
CyberMind — https://cybermind.fr

Sites cloned from Gitea (sub-B of #49) carry a .git subtree whose pack files
are 0444 and whose directories may be 0500. Vanilla `shutil.rmtree` then
trips on `os.open(..., O_RDONLY, dir_fd=topfd)`. `force_remove` chmods the
offending entry to 0700 and retries the failing op.
"""
import os
import shutil
from pathlib import Path


def force_remove(path: Path) -> None:
    """shutil.rmtree, but chmods read-only entries before retry.

    For unlink/rmdir failures the parent directory's mode is the real
    blocker; for opendir failures the entry itself is. Chmod both.
    """
    def _onerror(func, entry, _exc):
        parent = os.path.dirname(entry)
        for target in (parent, entry):
            try:
                os.chmod(target, 0o700)
            except OSError:
                pass
        func(entry)
    shutil.rmtree(path, onerror=_onerror)
