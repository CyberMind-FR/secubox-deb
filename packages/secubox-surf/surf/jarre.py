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
# LA JARRE D'ÉTAT (#1235). Pendant du bocal à cookies, pour le storage :
# localStorage / sessionStorage. Les SSO et sessions modernes y rangent des
# jetons, pas seulement dans les cookies ; et sous une origine surf-*, ce
# storage est cloisonné (par origine) ET partitionné (contexte tiers), donc la
# session posée à la vraie origine n'y est jamais. On le retient donc CÔTÉ
# RELAIS, par domaine, et on le RÉINJECTE au chargement (inline, avant les
# scripts du site). Même principe que les cookies : apprendre une fois,
# rejouer toujours — mais pour le storage.
CHEMIN_ETAT = Path("/var/lib/secubox/surf/etat.json")
_MAX_ETAT = 512 * 1024   # garde-fou de taille par domaine

_verrou = threading.Lock()
_jarre: dict[str, dict[str, str]] = {}
_etat: dict[str, dict] = {}
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
    try:
        _etat.update(json.loads(CHEMIN_ETAT.read_text()))
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


def _sauve_etat():
    try:
        CHEMIN_ETAT.parent.mkdir(parents=True, exist_ok=True)
        tmp = CHEMIN_ETAT.with_suffix(".tmp")
        tmp.write_text(json.dumps(_etat, ensure_ascii=False))
        tmp.replace(CHEMIN_ETAT)
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


def apprend_etat(hote: str, local: dict | None, session: dict | None) -> int:
    """Retient le storage d'un hôte, par domaine. Snapshot AUTORITAIRE : l'aire
    fournie remplace celle qu'on avait (le navigateur porte l'état courant).

    Ce sont NOS clés, sur NOTRE box, pour NOTRE navigation — rien ne sort. Un
    garde-fou de taille évite qu'un site nous fasse enfler ; on garde alors
    `local` (souvent les jetons) et on lâche `session` (éphémère par nature)."""
    with _verrou:
        _assure()
        dom = _domaine(hote)
        e = _etat.setdefault(dom, {})
        if isinstance(local, dict):
            e["local"] = {str(k): str(v) for k, v in local.items()}
        if isinstance(session, dict):
            e["session"] = {str(k): str(v) for k, v in session.items()}
        try:
            if len(json.dumps(e)) > _MAX_ETAT:
                e.pop("session", None)
            if len(json.dumps(e)) > _MAX_ETAT:
                e["local"] = {}
        except (TypeError, ValueError):
            pass
        _sauve_etat()
        return len(e.get("local", {})) + len(e.get("session", {}))


def etat_pour(hote: str) -> dict:
    """L'état storage à RÉINJECTER pour cet hôte : {local:{…}, session:{…}}."""
    with _verrou:
        _assure()
        e = _etat.get(_domaine(hote), {})
        return {"local": dict(e.get("local", {})),
                "session": dict(e.get("session", {}))}


def etat() -> dict[str, dict]:
    """Ce qu'on retient par domaine — cookies ET storage — pour l'inspection."""
    with _verrou:
        _assure()
        out: dict[str, dict] = {}
        for d, c in _jarre.items():
            out.setdefault(d, {})["cookies"] = len(c)
        for d, e in _etat.items():
            out.setdefault(d, {})["storage"] = (
                len(e.get("local", {})) + len(e.get("session", {})))
        return out


def oublie(hote: str) -> bool:
    """Purge cookies ET storage d'un domaine — le droit à l'oubli du bocal."""
    with _verrou:
        _assure()
        dom = _domaine(hote)
        trouve = False
        if dom in _jarre:
            del _jarre[dom]
            _sauve()
            trouve = True
        if dom in _etat:
            del _etat[dom]
            _sauve_etat()
            trouve = True
        return trouve
