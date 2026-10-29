# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(ICI.parents[1] / "common"))
sys.path.insert(0, str(ICI.parent / "secubox-autoload-agent"))
sys.path.insert(0, str(ICI.parent / "secubox-premier-pas"))


@pytest.fixture(autouse=True)
def _verrou_de_synchronisation(tmp_path, monkeypatch):
    """Le verrou de tunnel-sync et d'exporter-pairs (/run/secubox/autoload-sync.lock en production, #3126) vit dans le dossier de l'essai."""
    monkeypatch.setenv("SECUBOX_AUTOLOAD_VERROU", str(tmp_path / "autoload-sync.lock"))
