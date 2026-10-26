# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-netmodes : le paquet et common/ sur sys.path ; registre des utilisateurs de test.

#3190 : les lectures (/routeur/etat, /reseau/ports, /reseau/carte) servent la version complète au seul ADMINISTRATEUR
RÉEL, jugé par secubox_core.auth.est_admin_reel (#1581) — rôle ET compte actif lus dans le registre, jamais dans le
payload. Un test ne lit jamais le registre de la machine qui le lance : `alice` administratrice, `bob` usager, `carol`
invitée, `dave` administrateur désactivé."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))

REGISTRE = {
    "alice": {"username": "alice", "role": "admin", "enabled": True},
    "bob": {"username": "bob", "role": "user", "enabled": True},
    "carol": {"username": "carol", "role": "guest", "enabled": True},
    "dave": {"username": "dave", "role": "admin", "enabled": False},
}


@pytest.fixture(autouse=True)
def registre(monkeypatch):
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "get_user", lambda sub: REGISTRE.get(sub))
    monkeypatch.setattr(user_store, "is_enabled", lambda sub: bool((REGISTRE.get(sub) or {}).get("enabled")))
    return REGISTRE
