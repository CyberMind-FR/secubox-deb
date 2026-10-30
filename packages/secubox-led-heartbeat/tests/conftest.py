# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les fichiers d'état factices des tests appartiennent au compte qui lance pytest."""
import os
import pwd
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "usr" / "lib" / "secubox-led-heartbeat"))


@pytest.fixture(autouse=True)
def _proprietaire_de_test(monkeypatch):
    try:
        import ledcouches
    except ImportError:
        return
    moi = pwd.getpwuid(os.getuid()).pw_name
    monkeypatch.setattr(ledcouches, "PROPRIETAIRES_DEFAUT",
                        list(ledcouches.__dict__.get("PROPRIETAIRES_DEFAUT", [])) + [moi],
                        raising=False)
