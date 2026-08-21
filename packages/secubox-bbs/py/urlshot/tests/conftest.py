# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Add the package's py/urlshot/ dir to sys.path for tests (`import egress`)."""
import sys
from pathlib import Path

# packages/secubox-bbs/py/urlshot/
_pkg_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg_root))
