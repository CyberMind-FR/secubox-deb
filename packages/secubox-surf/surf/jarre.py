# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Surf — le bocal à cookies (apprendre une fois, rejouer toujours)
CyberMind — https://cybermind.fr

L'IDEE (§0bis « faux témoins rejoués »). Beaucoup de sites — portails de
consentement, murs anti-bot doux, sessions — refusent le contenu tant qu'un
cookie n'est pas posé. Ce cookie, le navigateur derrière le BiB ne le garde pas
d'une visite à l'autre (contexte tiers, purge), et sur un premier contact il
n'existe pas encore.

On le retient donc CÔTÉ RELAIS, par domaine enregistrable : ce que l'amont pose
(`Set-Cookie`) est appris ici, et REJOUÉ vers l'amont à chaque requête suivante.
Un consentement donné une fois vaut pour toujours ; une session ouverte une fois
se rouvre seule.

DEUX SOURCES D'APPRENTISSAGE :
  - AUTOMATIQUE : les `Set-Cookie` des réponses relayées.
  - MANUELLE (« apprendre une fois ») : l'opérateur colle les cookies d'une
    session réelle — c'est ainsi qu'on franchit un portail qui, sinon, ne pose
    jamais son cookie parce qu'il redirige avant.

CE QUE ÇA N'EST PAS. Ce n'est pas un vol d'identité : ce sont NOS cookies, sur
NOTRE box, pour NOTRE navigation. Rien ne sort de la box. C'est le pendant
serveur du bocal à cookies d'un navigateur ordinaire.
"""

from __future__ import annotations

import json
import threading
from http.cookies import SimpleCookie
from pathlib import Path

# État persistant. Le service tourne en ProtectSystem=strict ; ce chemin est
# ouvert en écriture par `ReadWritePaths` dans l'unité systemd.
CHEMIN = Path("/var/lib/secubox/surf/jarre.json")

_verrou = threading.Lock()
_jarre: dict[str, dict[str, str]] = {}
_charge = False


def _domaine(hote: str) -> str:
    """Le domaine ENREGISTRABLE (les deux derniers labels).

    On regroupe par domaine, pas par hôte : le cookie de consentement posé sur
    `www.bfmtv.com` doit être rejoué vers `gate.bfmtv.com` aussi. Approximation
    volontairement simple — deux labels — suffisante pour le POC ; une vraie
    Public Suffix List distinguerait `co.uk`, mais on ne la traîne pas ici.
    """
    parts = (hote or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hote


def _assure():
    global _charge
    if _charge:
        return
    try:
        _jarre.update(json.loads(CHEMIN.read_text()))
    except (OSError, ValueError):
        pass
    _charge = True


def _sauve():
    try:
        CHEMIN.parent.mkdir(parents=True, exist_ok=True)
        tmp = CHEMIN.with_suffix(".tmp")
        tmp.write_text(json.dumps(_jarre, ensure_ascii=False))
        tmp.replace(CHEMIN)
    except OSError:
        pass


def apprend(hote: str, set_cookies: list[str]):
    """Retient les `Set-Cookie` d'une réponse, pour ce domaine.

    On ne garde que le couple nom=valeur : les attributs (Domain, Path, Expires,
    SameSite) sont ceux du navigateur, pas ceux qu'on rejoue vers l'amont.
    """
    if not set_cookies:
        return
    with _verrou:
        _assure()
        dom = _domaine(hote)
        boc = _jarre.setdefault(dom, {})
        change = False
        for brut in set_cookies:
            try:
                c = SimpleCookie()
                c.load(brut)
                for nom, morceau in c.items():
                    v = morceau.value
                    # Une valeur vidée = suppression demandée par l'amont.
                    if v in ("", "deleted"):
                        if nom in boc:
                            del boc[nom]
                            change = True
                    elif boc.get(nom) != v:
                        boc[nom] = v
                        change = True
            except Exception:  # noqa: BLE001 — un Set-Cookie exotique est ignoré
                continue
        if change:
            _sauve()


def entete(hote: str, cookie_navigateur: str = "") -> str:
    """L'en-tête `Cookie` à envoyer à l'amont : bocal + ce que le navigateur
    présente, le navigateur ayant priorité (il porte la session en cours)."""
    with _verrou:
        _assure()
        boc = dict(_jarre.get(_domaine(hote), {}))
    # Les cookies du navigateur écrasent ceux du bocal, à nom égal.
    if cookie_navigateur:
        try:
            c = SimpleCookie()
            c.load(cookie_navigateur)
            for nom, morceau in c.items():
                boc[nom] = morceau.value
        except Exception:  # noqa: BLE001
            pass
    return "; ".join("%s=%s" % (n, v) for n, v in boc.items())


def pose_manuel(hote: str, cookies: dict[str, str]) -> int:
    """« Apprendre une fois » : l'opérateur seme des cookies pour un domaine."""
    with _verrou:
        _assure()
        boc = _jarre.setdefault(_domaine(hote), {})
        for n, v in cookies.items():
            boc[str(n)] = str(v)
        _sauve()
        return len(boc)


def etat() -> dict[str, int]:
    """Combien de cookies retenus, par domaine — pour l'inspection."""
    with _verrou:
        _assure()
        return {d: len(c) for d, c in _jarre.items()}


def oublie(hote: str) -> bool:
    with _verrou:
        _assure()
        dom = _domaine(hote)
        if dom in _jarre:
            del _jarre[dom]
            _sauve()
            return True
        return False
