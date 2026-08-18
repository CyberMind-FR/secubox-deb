# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Add the package's api/ and the repo-wide common/ to sys.path for tests."""
import sys
from pathlib import Path

# packages/secubox-metrics/
_pkg_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg_root / "api"))

# repo root → common/
_repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_repo_root / "common"))
