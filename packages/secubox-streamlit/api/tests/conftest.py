# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""pytest conftest — make `api.main` and `secubox_core` importable when
running locally out of the source tree (no system-wide install)."""
import pathlib
import sys

# Add the secubox-streamlit package root so `import api.main` works
PKG_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(PKG_ROOT))

# Add the common/ directory which contains secubox_core
REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
COMMON = REPO_ROOT / "common"
if COMMON.is_dir() and str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
