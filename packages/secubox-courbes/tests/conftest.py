# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-courbes : la bibliothèque (lib/) et common/ sur sys.path ; la machine ne s'invite jamais dans un test."""
import sys
from pathlib import Path

_pkg = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_pkg / "lib"))
sys.path.insert(0, str(_pkg))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
