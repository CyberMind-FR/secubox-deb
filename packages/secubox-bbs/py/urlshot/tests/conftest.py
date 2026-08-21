# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Add the package's py/urlshot/ dir to sys.path for tests (`import egress`),
and common/ so `from secubox_core import shotter` resolves to the source
tree — never to a stale system-wide `/usr/lib/python3/dist-packages` copy
that may predate `shotter.py`/`screenshots.py`."""
import sys
from pathlib import Path

# packages/secubox-bbs/py/urlshot/
_pkg_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg_root))

# repo root / common/ (contains secubox_core)
_common = Path(__file__).resolve().parents[5] / "common"
if _common.is_dir():
    sys.path.insert(0, str(_common))
