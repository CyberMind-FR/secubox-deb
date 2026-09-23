# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Le verdict LAN doit atteindre CHAQUE module servi par le Hall (#1351).

CE QUE CE TEST GARDE, ET POURQUOI IL EXISTE. Le Hall expose ses API une par
une — c'est délibéré : un `include` global ouvrirait ici tout ce qu'un module
déclare ailleurs. Mais une liste tenue à la main diverge, et celle-ci avait
divergé en silence : sur dix-neuf routes, UNE SEULE transmettait le verdict
LAN. Les dix-huit autres ne posaient aucune marque, `require_lecture` exigeait
donc un jeton, et toutes les cartes du Hall recevaient 401 — 6586 refus en une
heure depuis un seul poste, des cartes vides, et rien pour dire pourquoi.

Le remède n'est pas « penser à ajouter la ligne » : c'est que l'oubli échoue.
"""

import re
from pathlib import Path

import pytest

VHOST = Path(__file__).resolve().parents[1] / "nginx" / "hall.vhost.conf"

# Routes qui ne visent PAS une socket de module SecuBox, et qui n'ont donc rien
# à faire du verdict : elles portent leur propre garde, ailleurs.
HORS_SUJET = ("10.100.0.", "nginx_local", "127.0.0.1", "unix:/run/php")


def blocs_location():
    """(en-tête, corps) de chaque bloc `location` du vhost."""
    lignes = VHOST.read_text().split("\n")
    i = 0
    while i < len(lignes):
        m = re.match(r"^(\s*)location\b(.*)\{\s*$", lignes[i])
        if not m:
            i += 1
            continue
        ind, entete, j, corps = m.group(1), m.group(2).strip(), i + 1, []
        while j < len(lignes) and not re.match("^" + ind + r"\}\s*$", lignes[j]):
            corps.append(lignes[j])
            j += 1
        yield entete, "\n".join(corps)
        i = j


def routes_de_module():
    for entete, corps in blocs_location():
        if "proxy_pass" not in corps:
            continue
        if "/run/secubox/" not in corps:
            continue                      # pas une socket de module
        if any(h in corps for h in HORS_SUJET):
            continue
        yield entete, corps


def test_il_y_a_bien_des_routes_a_garder():
    """Un test qui ne trouve rien à vérifier passe pour de mauvaises raisons.
    Si le vhost est réorganisé au point que l'analyse ne reconnaît plus rien,
    mieux vaut le savoir ici que de croire la règle tenue."""
    assert len(list(routes_de_module())) >= 12


@pytest.mark.parametrize("entete, corps", list(routes_de_module()),
                         ids=lambda v: v if isinstance(v, str) and len(v) < 60 else "")
def test_chaque_route_de_module_transmet_le_verdict_lan(entete, corps):
    porte = ("X-SecuBox-LAN" in corps) or ("secubox-proxy.conf" in corps)
    assert porte, (
        f"la route « {entete} » mandate vers une socket SecuBox sans transmettre "
        "le verdict LAN. Le module ne saura pas que la requête vient du réseau "
        "local, `require_lecture` exigera un jeton, et la carte restera vide en "
        "401 sans rien dire. Ajouter :\n"
        "    proxy_set_header X-SecuBox-LAN $lan_client;\n"
        "ou inclure snippets/secubox-proxy.conf si la route s'en accommode "
        "(attention : il pose `Connection \"\"`, incompatible WebSocket)."
    )


def test_la_variable_du_verdict_est_bien_celle_de_nginx():
    """`$lan_client` vient de conf.d/secubox-lan-geo.conf. Écrire une autre
    variable passerait `nginx -t` (une variable inconnue vaut vide) et rendrait
    le verdict TOUJOURS faux — un échec silencieux de plus."""
    texte = VHOST.read_text()
    for m in re.finditer(r"X-SecuBox-LAN\s+(\$\w+)", texte):
        assert m.group(1) == "$lan_client", (
            f"verdict transmis depuis {m.group(1)} : seule $lan_client est "
            "définie par secubox-lan-geo.conf, le reste vaut vide.")


# ── LA GARDE DES SONDES ──────────────────────────────────────────────────────

CARDLETS = VHOST.parent.parent / "www" / "hall" / "cardlets"
HALLJS = VHOST.parent.parent / "www" / "hall"
RULES = VHOST.parent.parent / "debian" / "rules"


def test_toute_carte_qui_sonde_charge_la_garde():
    """Une carte qui interroge une API doit charger `sonde.js` (#1351).

    Sans elle, un refus de lecture est réessayé toutes les deux secondes,
    indéfiniment : 6586 refus en une heure, des journaux noyés, et une vraie
    panne rendue invisible. Douze boucles écrites douze fois ne se corrigent
    pas à la main — c'est le rôle de ce test.
    """
    manquantes = []
    for f in sorted(CARDLETS.glob("*.html")):
        t = f.read_text()
        if "fetch(" in t and "sonde.js" not in t:
            manquantes.append(f.name)
    assert not manquantes, (
        "ces cartes interrogent une API sans la garde des sondes : "
        + ", ".join(manquantes)
        + '\nAjouter <script src="../sonde.js"></script> AVANT leurs propres '
          "scripts — après, la première salve serait déjà partie.")


def test_la_garde_est_chargee_avant_les_scripts_de_la_carte():
    """L'ordre n'est pas cosmétique : `sonde.js` enveloppe `fetch`. Chargée
    après le script qui sonde, elle arriverait trop tard pour la première
    salve — celle-là même qui part au chargement de la carte."""
    for f in sorted(CARDLETS.glob("*.html")):
        t = f.read_text()
        if "sonde.js" not in t:
            continue
        rang = t.index("sonde.js")
        for autre in ("../aide.js", "../slicebar.js"):
            if autre in t:
                assert rang < t.index(autre), (
                    f"{f.name} : sonde.js est chargée après {autre}")


def test_chaque_script_du_hall_est_installe():
    """LA LISTE DE `debian/rules` EST TENUE À LA MAIN, fichier par fichier.
    Un script ajouté sans sa ligne d'installation existe dans le dépôt, passe
    les tests, et MANQUE sur la board : la carte casse chez l'utilisateur et
    nulle part ailleurs. C'est arrivé le même jour au cockpit de gabriel-mood,
    livré avec un répertoire web vide."""
    rules = RULES.read_text()
    oublis = [f.name for f in sorted(HALLJS.glob("*.js")) if f.name not in rules]
    assert not oublis, (
        "scripts présents dans www/hall/ mais jamais installés par debian/rules : "
        + ", ".join(oublis))
