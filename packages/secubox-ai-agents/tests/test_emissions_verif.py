# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 3 (#4058) : le vérificateur des émissions est la copie à l'identique de celui de gk2."""
import hashlib

from conftest import PAQUET, RACINE

SOURCE = RACINE / "packages/secubox-waf-ng/composants/waf/api/verif_rapport.py"
COPIE = PAQUET / "emissions/verif_rapport.py"


def _empreinte(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_copie_identique():
    # la copie diverge : on RECOPIE la source de gk2, on ne patche jamais la copie
    assert _empreinte(COPIE) == _empreinte(SOURCE)


def test_verifier_repond():
    from emissions.verif_rapport import Contexte, verifier
    dossier = {"sujet": {"genre": "campagne", "id": "x", "nom": "Essai"}, "chiffres": {"bans_90j": 12},
               "tendances": []}
    r = verifier("La campagne Essai compte 12 bans.", dossier)
    assert isinstance(r["taux_retenues_pct"], int)
    assert Contexte is not None
