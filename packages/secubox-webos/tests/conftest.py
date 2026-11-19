# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Add the package's api/ and the repo-wide common/ to sys.path for tests."""
import sys
from pathlib import Path

# packages/secubox-webos/
_pkg_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg_root / "api"))

# repo root → common/
_repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_repo_root / "common"))

# Box en miniature du nom de nœud (#3821, #3824), partagée par les deux fichiers de tests.
from tests.banc_noeud import box  # noqa: E402,F401
