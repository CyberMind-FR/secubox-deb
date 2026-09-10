# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: harnais de test — le client est un tableau de bord LAN.

Le parc est passe en LECTURE GARDEE (#1256) : les routes d'affichage exigent
un jeton, ou le mode tableau de bord depuis le LAN. Des dizaines de tests
existants appellent ces routes sans jeton et attendent 200 — ils encodaient
l'ancien contrat, ou la lecture etait publique.

CE MODULE NE DESACTIVE PAS LA GARDE, il place le harnais dans la position du
client legitime : mode arme + requete marquee LAN par nginx. C'est exactement
ce que verra la board quand l'operateur activera le mode. Un test qui veut
verifier le REFUS reste libre de construire sa requete autrement.

CE QU'IL NE MASQUE PAS : `require_jwt` n'est jamais satisfait par le mode
tableau de bord. Une route qui exige un jeton continue de rendre 401 ici —
c'est ce qui laisse `test_detail_requires_jwt_401_without_token` (webos) et
`test_les_deux_routes_webui_exigent_un_jeton` (haproxy) faire leur travail.
"""
from __future__ import annotations

import os


def active_mode_tableau_de_bord() -> None:
    """Arme le mode et fait porter la marque LAN a tout TestClient cree ensuite.

    Le patch porte sur `starlette.testclient.TestClient.__init__` : on ajoute
    l'en-tete par defaut, sans ecraser ce qu'un test passe explicitement.
    Idempotent — plusieurs conftests peuvent l'appeler.
    """
    os.environ.setdefault("SECUBOX_TABLEAU_DE_BORD", "1")

    try:
        from starlette.testclient import TestClient
    except ImportError:  # pas de starlette dans cet environnement : rien a faire
        return

    if getattr(TestClient, "_secubox_lan_patch", False):
        return

    from secubox_core.auth import ENTETE_LAN

    _init = TestClient.__init__

    def __init__(self, *a, **kw):
        entetes = dict(kw.get("headers") or {})
        entetes.setdefault(ENTETE_LAN, "1")
        kw["headers"] = entetes
        _init(self, *a, **kw)

    TestClient.__init__ = __init__
    TestClient._secubox_lan_patch = True
