# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Le collecteur RGPD est-il reellement CABLE ? (#1311)

POURQUOI CE FICHIER EXISTE, A COTE DE test_cookie_audit.py

`test_cookie_audit.py` compte 20 tests et ils passaient tous — pendant que le
collecteur ne tournait pas. Ils construisaient l'objet EUX-MEMES, donc ils
validaient la logique sans jamais constater que personne ne l'appelait.

C'est le trou exact que ces tests-ci bouchent : ils ne verifient pas ce que le
module CALCULE, mais qu'il est INSTANCIE, DEMARRE et EXPOSE. Une suite qui
teste une classe orpheline donne la meme couleur verte qu'une suite qui teste
une fonction vivante, et c'est ainsi qu'un module RGPD a pu dormir un mois
avec une saisine CNIL en cours.
"""

import ast
import io
from pathlib import Path

MAIN = Path(__file__).resolve().parent.parent / "api" / "main.py"


def _source():
    return io.open(MAIN, encoding="utf-8").read()


def test_le_collecteur_est_importe():
    assert "from cookie_audit import CookieAuditAggregator" in _source(), (
        "main.py n'importe pas le collecteur : il ne peut donc pas l'instancier"
    )


def test_le_collecteur_est_instancie():
    """C'est LE defaut d'origine : la classe n'etait construite que dans les tests."""
    s = _source()
    assert "CookieAuditAggregator(" in s, "aucune instanciation en production"
    assert "cookie_audit_agg" in s


def test_le_collecteur_est_demarre_dans_le_lifespan():
    """Instancier ne suffit pas — sans tache, il ne rafraichit jamais rien.

    On verifie la presence de `run_forever` DANS le lifespan, pas ailleurs :
    un objet construit puis oublie produit exactement le meme silence qu'un
    objet absent.
    """
    arbre = ast.parse(_source())
    for n in ast.walk(arbre):
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan":
            corps = ast.dump(n)
            assert "cookie_audit_agg" in corps and "run_forever" in corps, (
                "le collecteur n'est pas demarre dans le lifespan"
            )
            return
    raise AssertionError("aucun lifespan trouve dans main.py")


def test_une_route_expose_le_resultat():
    """Un inventaire que rien ne rend lisible n'existe pas pour l'utilisateur.

    Le guide produit annonce un tableau de bord vie privee ; il lui faut une
    route pour se remplir.
    """
    s = _source()
    assert "/api/v1/metrics/cookie-audit" in s, "aucune route n'expose l'inventaire"
    assert "cookie_audit_agg.current()" in s


def test_la_route_est_gardee():
    """Un inventaire de cookies par vhost dit QUI depose QUOI chez l'exploitant.

    Ce n'est pas une donnee publique : la route doit porter la meme garde que
    ses voisines.
    """
    s = _source()
    i = s.index("/api/v1/metrics/cookie-audit")
    ligne = s[i - 200:i + 200]
    assert "require_lecture" in ligne, "la route n'est pas gardee"


def test_la_configuration_a_un_lecteur():
    """Sans lecteur de section, la config de `secubox.conf` n'atteint jamais
    le collecteur — il tournerait sur ses defauts en ignorant l'exploitant."""
    cfg = Path(__file__).resolve().parents[3] / "common" / "secubox_core" / "config.py"
    if not cfg.is_file():          # arbre partiel : on ne reclame pas ce qu'on ne voit pas
        return
    s = io.open(cfg, encoding="utf-8").read()
    assert "def get_cookie_audit_config" in s
    assert "_COOKIE_AUDIT_DEFAULTS" in s


def test_le_defaut_est_desactive():
    """PAR DEFAUT ETEINT, et c'est un choix.

    Le registre peut peser des centaines de mega-octets ; l'allumer d'office
    sur une carte a 1-2 Go prendrait une decision a la place de l'exploitant.
    """
    cfg = Path(__file__).resolve().parents[3] / "common" / "secubox_core" / "config.py"
    if not cfg.is_file():
        return
    s = io.open(cfg, encoding="utf-8").read()
    i = s.index("_COOKIE_AUDIT_DEFAULTS")
    bloc = s[i:i + 400]
    assert '"enabled": False' in bloc, "le collecteur s'allumerait tout seul"
