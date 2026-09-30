# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-dpi — harnais des tests (ref #1775)

DEUX CHOSES QUE LE TAMPON MÉDIA LIT HORS DU CODE, et qu'un test ne doit
jamais aller chercher sur la machine qui le lance :

  1. LE REGISTRE DES UTILISATEURS. L'administrateur se reconnaît par
     secubox_core.auth.est_admin_reel (#1581) — rôle ET compte actif lus dans
     users.json, jamais dans une revendication du payload. On fournit un
     registre minimal : `root` administrateur, `bob` simple usager.
  2. LE JOURNAL D'AUDIT. Chaque relecture y écrit une ligne, et la refuse si
     elle ne le peut pas : on le redirige dans un dossier temporaire, au lieu
     de /var/log/secubox/audit.log.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # api importable

REGISTRE = {
    "root": {"username": "root", "role": "admin", "enabled": True},
    "bob": {"username": "bob", "role": "user", "enabled": True},
}


@pytest.fixture(autouse=True)
def registre_et_audit(tmp_path_factory, monkeypatch):
    """Registre d'utilisateurs de test + journal d'audit temporaire. Rend le
    chemin du journal, pour les tests qui le relisent."""
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "get_user", lambda sub: REGISTRE.get(sub))
    monkeypatch.setattr(user_store, "is_enabled",
                        lambda sub: bool((REGISTRE.get(sub) or {}).get("enabled")))
    from api import main as m
    journal = tmp_path_factory.mktemp("audit") / "audit.log"
    # raising=False : la même suite tourne aussi contre une version sans
    # tampon média (contre-épreuve #1775) — elle doit y ÉCHOUER, pas y planter.
    monkeypatch.setattr(m, "AUDIT_LOG", str(journal), raising=False)
    return journal
