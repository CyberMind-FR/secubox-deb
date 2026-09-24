# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/test_verdict_lan_vhosts.py
"""SecuBox-Deb :: le verdict LAN atteint chaque module (#1354).

`require_lecture` ouvre la lecture au réseau local quand `[tableau_de_bord]`
est armé — mais seulement si nginx MARQUE la requête. La marque est
`X-SecuBox-LAN: $lan_client`, posée par `snippets/secubox-proxy.conf` ou, pour
les blocs qui ne peuvent pas l'inclure, écrite à la main dans le bloc.

POURQUOI UN TEST DE DÉPÔT ET PAS UN TEST PAR PAQUET. L'oubli ne vit pas DANS
un paquet, il vit ENTRE eux : chacun écrit son vhost dans son coin, et la
convention se perd d'un paquet à l'autre. Mesuré le 2026-09-24, avant
correction : **51 routes sans la marque, dans 29 paquets et 32 fichiers**.
Symptôme côté utilisateur : `billets.gk2.secubox.in` rendait 401 en disant que
le mode tableau de bord « est inactif ou la requête n'est pas LAN » — alors
qu'il était actif et que la requête venait bien du LAN.

ET IL NE PRÉSUPPOSE AUCUN CHEMIN. Mon premier balayage ne regardait que
`packages/*/nginx/*.conf` ; il a donc manqué `secubox-billets`, dont le vhost
vit dans `deploy/nginx.conf` — c'est-à-dire le paquet même qui avait déclenché
le rapport. Une convention qu'on croit connaître et qui n'existe pas est pire
qu'une absence de convention : elle fait passer l'audit.

CE QUI N'EST PAS EXIGÉ ICI : que la route soit ouverte. Le verdict ne fait que
TRANSMETTRE une information. Ce qu'un module en fait reste sa décision, et
l'écriture demeure fermée quoi qu'il arrive.
"""
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAQUETS = RACINE / "packages"

# Les répertoires de montage debhelper : ce sont des COPIES de ce qu'on teste
# déjà, et les inclure ferait compter chaque oubli deux fois.
def _est_artefact(p: Path) -> bool:
    parts = p.parts
    for i, x in enumerate(parts):
        if x == "debian" and i + 1 < len(parts) and parts[i + 1].startswith(("secubox-", "gabriel")):
            return True
    return False


def blocs_location(texte: str):
    """(entête, corps) de chaque `location`, y compris la forme sur une ligne."""
    lignes = texte.split("\n")
    i = 0
    while i < len(lignes):
        l = lignes[i]
        m = re.match(r"^(\s*)location\b.*\{", l)
        if not m:
            i += 1
            continue
        if l.count("{") == 1 and l.rstrip().endswith("}"):
            yield l.strip(), l           # tout tient sur la ligne
            i += 1
            continue
        ind, j, corps = m.group(1), i + 1, []
        while j < len(lignes) and not re.match("^" + ind + r"\}\s*$", lignes[j]):
            corps.append(lignes[j])
            j += 1
        yield l.strip(), "\n".join(corps)
        i = j


def routes_de_module():
    """Toute route qui mandate vers une socket de module SecuBox."""
    for f in sorted(PAQUETS.rglob("*.conf")):
        if _est_artefact(f):
            continue
        try:
            texte = f.read_text(errors="replace")
        except OSError:
            continue
        for entete, corps in blocs_location(texte):
            if "proxy_pass" in corps and "/run/secubox/" in corps:
                yield f.relative_to(RACINE), entete, corps


def test_l_inventaire_n_est_pas_vide():
    """Un test qui ne trouve rien à vérifier passe pour de mauvaises raisons.
    Si la disposition des vhosts change au point que l'analyse ne reconnaisse
    plus rien, mieux vaut le savoir ici que de croire la règle tenue."""
    assert len(list(routes_de_module())) >= 150


def test_chaque_route_de_module_transmet_le_verdict_lan():
    manquantes = [
        (str(f), e[:74])
        for f, e, c in routes_de_module()
        if "X-SecuBox-LAN" not in c and "secubox-proxy.conf" not in c
    ]
    assert not manquantes, (
        "ces routes mandatent vers une socket SecuBox sans transmettre le "
        "verdict LAN — le module exigera un jeton même sur le réseau local, et "
        "la page rendra 401 en accusant un réglage qui est pourtant bon :\n"
        + "\n".join(f"  {f} : {e}" for f, e in manquantes)
        + "\n\nAjouter dans le bloc :\n"
          "    proxy_set_header X-SecuBox-LAN $lan_client;\n"
          "ou inclure snippets/secubox-proxy.conf si la route s'en accommode "
          "(il pose `Connection \"\"`, incompatible WebSocket — d'où les blocs "
          "écrits à la main)."
    )


def test_le_verdict_vient_de_la_bonne_variable():
    """`$lan_client` est définie par `conf.d/secubox-lan-geo.conf`. En écrire
    une autre passerait `nginx -t` — une variable inconnue vaut la chaîne
    vide — et rendrait le verdict TOUJOURS faux. L'erreur serait invisible :
    tout continuerait de fonctionner, en refusant tout le monde."""
    fautives = []
    for f, entete, corps in routes_de_module():
        for m in re.finditer(r"X-SecuBox-LAN\s+(\$\w+)", corps):
            if m.group(1) != "$lan_client":
                fautives.append(f"{f} : {entete[:60]} → {m.group(1)}")
    assert not fautives, "verdict transmis depuis une autre variable :\n  " + "\n  ".join(fautives)
