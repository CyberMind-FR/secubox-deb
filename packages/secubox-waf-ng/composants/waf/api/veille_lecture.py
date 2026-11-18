# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Lectures de la veille V2 (#3720) : flux à curseur du journal des menaces et lectures par la fin des journaux
JSON par ligne. Fonctions pures sur des chemins (aucune route ici) : `main.py` les sert hors de la boucle.

Flux à curseur (`lire_flux`) : position `<inode>:<octet>` du DÉBUT d'une ligne. On ouvre le fichier puis on lit son
inode par `fstat` (jamais un `stat` du chemin suivi d'un `open` : la rotation peut passer entre les deux). Lecture par
`seek`, jamais du fichier entier ; au plus `max_lignes` lignes et `octets_max` octets par réponse ; une ligne n'est
rendue qu'entière (terminée par « \\n »), sauf la fin d'un fichier TOURNÉ, close pour de bon. À inode changé (rotation
par renommage, `delaycompress` : `.1` en clair) : fin de `.1` depuis l'octet, puis le courant depuis 0, sans trou ni
doublon. Inode inconnu (deux rotations ratées) ou fichier raccourci : reprise au début de `.1` puis du courant,
`trou = true`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RE_POSITION = re.compile(r"[0-9]{1,20}:[0-9]{1,15}")
#: Une ligne plus longue est sautée (rendue `ligne: null`, `motif: trop_longue`) : jamais un curseur bloqué.
LIGNE_MAX = 64 * 1024
_BLOC = 64 * 1024


#: Nom du credential systemd (LoadCredential=leurres-hmac:/etc/secubox/secrets/leurres-hmac.key).
CREDENTIAL_LEURRES = "leurres-hmac"
#: Champs de premier niveau qui pourraient porter un dialogue brut (mot de passe compris) : jamais rendus.
CHAMPS_BRUTS = ("message", "ligne", "payload", "brut", "raw", "body", "corps", "donnees", "data")


def cle_leurres() -> Optional[bytes]:
    """La clé locale du HMAC des leurres, depuis `$CREDENTIALS_DIRECTORY` ; None si absente ou trop courte."""
    dossier = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not dossier:
        return None
    try:
        with open(os.path.join(dossier, CREDENTIAL_LEURRES), "rb") as f:
            cle = f.read(4096)
    except OSError:
        return None
    return cle if len(cle) >= 16 else None


def masquer_essais(ligne: Any, cle: Optional[bytes]) -> Any:
    """#3795 : identifiants tentés sur les leurres de service (#3728, `essais` de sbx-authwatch) rendus SANS le mot de
    passe : `mot_de_passe_hmac` (HMAC-SHA256 à clé locale de gk2, hex ; `null` sans clé — jamais le clair, jamais un
    SHA-256 nu, réversible par dictionnaire) et `mot_de_passe_longueur` ; le compte reste. Les champs bruts de premier
    niveau (`CHAMPS_BRUTS`) d'une ligne qui porte des essais sont retirés, et toute chaîne de premier niveau qui
    contient un mot de passe tenté est masquée."""
    if not isinstance(ligne, dict) or "essais" not in ligne:
        return ligne
    essais = ligne.get("essais")
    sortie: List[Dict[str, Any]] = []
    secrets: List[str] = []
    for e in essais if isinstance(essais, list) else []:
        if not isinstance(e, dict):
            continue
        m: Dict[str, Any] = {}
        if isinstance(e.get("compte"), str):
            m["compte"] = e["compte"]
        mdp = e.get("mot_de_passe")
        if isinstance(mdp, str) and mdp:
            secrets.append(mdp)
            octets = mdp.encode("utf-8", "surrogatepass")
            m["mot_de_passe_hmac"] = hmac.new(cle, octets, hashlib.sha256).hexdigest() if cle else None
            m["mot_de_passe_longueur"] = len(mdp)
        sortie.append(m)
    propre: Dict[str, Any] = {}
    for k, val in ligne.items():
        if k == "essais" or k in CHAMPS_BRUTS:
            continue
        if isinstance(val, str) and any(s in val for s in secrets):
            val = "[masqué]"
        propre[k] = val
    propre["essais"] = sortie
    return propre


class PositionInvalide(ValueError):
    """Le curseur ne désigne pas un début de ligne du fichier qu'il nomme."""


def _decoder(brut: bytes) -> Tuple[Optional[dict], Optional[str]]:
    try:
        v = json.loads(brut.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "illisible"
    if not isinstance(v, dict):
        return None, "illisible"
    return v, None


def _lire_depuis(f, inode: int, octet: int, max_lignes: int, octets_max: int, tourne: bool,
                 sortie: List[Dict[str, Any]]) -> Tuple[int, bool, int]:
    """Lit `f` à partir de `octet` (début de ligne) ; ajoute à `sortie`. Rend (octet suivant, fin atteinte, octets
    consommés). `tourne` : fichier qui ne grandira plus (sa fin non terminée est une ligne)."""
    taille = os.fstat(f.fileno()).st_size
    pos, consommes = octet, 0
    f.seek(pos)
    while len(sortie) < max_lignes and pos < taille:
        reste = octets_max - consommes
        if reste <= 0:
            return pos, False, consommes
        brut = f.readline(min(LIGNE_MAX + 1, taille - pos))
        if not brut:
            break
        complete = brut.endswith(b"\n")
        if not complete and len(brut) > LIGNE_MAX:
            # Ligne démesurée : on la saute jusqu'à sa fin, sans la charger.
            saut, termine = len(brut), False
            while True:
                bloc = f.readline(_BLOC)
                if not bloc:
                    break
                saut += len(bloc)
                if bloc.endswith(b"\n"):
                    termine = True
                    break
            if not termine and not tourne:
                return pos, True, consommes   # démesurée ET en cours d'écriture : on attend sa fin
            f.seek(pos + saut)
            sortie.append({"position": f"{inode}:{pos}", "ligne": None, "motif": "trop_longue"})
            pos += saut
            consommes += saut   # les octets sautés comptent dans le plafond de la réponse
            continue
        if not complete and not tourne:
            break   # ligne en cours d'écriture : jamais rendue partielle
        if len(brut) > reste and sortie:
            return pos, False, consommes
        ligne, motif = _decoder(brut.rstrip(b"\n"))
        entree: Dict[str, Any] = {"position": f"{inode}:{pos}", "ligne": ligne}
        if motif:
            entree["motif"] = motif
        sortie.append(entree)
        pos += len(brut)
        consommes += len(brut)
    return pos, pos >= taille, consommes


def _debut_de_ligne(f, octet: int) -> bool:
    if octet == 0:
        return True
    f.seek(octet - 1)
    return f.read(1) == b"\n"


def _ouvrir(chemin: Path):
    try:
        f = open(chemin, "rb")
    except OSError:
        return None, 0
    return f, os.fstat(f.fileno()).st_ino


def lire_flux(courant: Path, depuis: Optional[str], max_lignes: int, octets_max: int) -> Dict[str, Any]:
    """`{"lignes": [{"position", "ligne", ["motif"]}], "suivant", "rotation", "trou"}`. `depuis` absent : début du
    fichier courant. Lève `PositionInvalide` sur un curseur qui ne tombe pas sur un début de ligne."""
    tourne_chemin = courant.with_name(courant.name + ".1")
    f_cour, ino_cour = _ouvrir(courant)
    f_tour, ino_tour = _ouvrir(tourne_chemin)
    try:
        lignes: List[Dict[str, Any]] = []
        rotation = trou = False
        if f_cour is None:
            return {"lignes": [], "suivant": depuis or "0:0", "rotation": False, "trou": False}
        if depuis:
            ino_s, oct_s = depuis.split(":")
            ino, octet = int(ino_s), int(oct_s)
        else:
            ino, octet = ino_cour, 0
        depart_tourne: Optional[int] = None
        if ino == ino_cour:
            taille = os.fstat(f_cour.fileno()).st_size
            if octet > taille:          # raccourci sur place : on reprend au début
                octet, rotation, trou = 0, True, True
            elif not _debut_de_ligne(f_cour, octet):
                raise PositionInvalide("position")
        elif f_tour is not None and ino == ino_tour:
            if octet > os.fstat(f_tour.fileno()).st_size or not _debut_de_ligne(f_tour, octet):
                raise PositionInvalide("position")
            depart_tourne, rotation = octet, True
        else:
            rotation, trou = True, True
            depart_tourne = 0 if f_tour is not None else None
            octet = 0
        consommes = 0
        if depart_tourne is not None:
            pos, fin, consommes = _lire_depuis(f_tour, ino_tour, depart_tourne, max_lignes, octets_max, True, lignes)
            if not fin:
                return {"lignes": lignes, "suivant": f"{ino_tour}:{pos}", "rotation": rotation, "trou": trou}
            octet = 0
        pos, _, _ = _lire_depuis(f_cour, ino_cour, octet, max_lignes, octets_max - consommes, False, lignes)
        return {"lignes": lignes, "suivant": f"{ino_cour}:{pos}", "rotation": rotation, "trou": trou}
    finally:
        for f in (f_cour, f_tour):
            if f is not None:
                f.close()


def lire_fin_jsonl(chemin: Path, garder, arreter, octets_max: int, lignes_max: int) -> Tuple[List[dict], bool]:
    """Les enregistrements (dict) de `chemin` lus par la FIN, dans l'ordre du fichier, au plus `octets_max` octets
    relus et `lignes_max` enregistrements gardés. `garder(r)` : l'enregistrement est rendu ; `arreter(r)` : plus
    besoin de remonter (journal append-only, ordonné à peu près). Rend (enregistrements, complet) — `complet` faux si
    une borne a coupé la remontée."""
    try:
        f = open(chemin, "rb")
    except OSError:
        return [], True
    with f:
        fin = os.fstat(f.fileno()).st_size
        pos, lus, reste = fin, 0, b""
        gardes: List[dict] = []
        premier = True
        while pos > 0:
            n = min(_BLOC, pos, octets_max - lus)
            if n <= 0:
                return list(reversed(gardes)), False
            pos -= n
            f.seek(pos)
            bloc = f.read(n) + reste
            lus += n
            morceaux = bloc.split(b"\n")
            reste = morceaux[0] if pos > 0 else b""
            completes = morceaux[1:] if pos > 0 else morceaux
            if premier:
                # la dernière ligne n'est rendue qu'entière : un morceau final sans « \n » est en cours d'écriture
                completes = completes[:-1]
                premier = False
            for brut in reversed(completes):
                r, _ = _decoder(brut) if brut.strip() else (None, None)
                if r is None:
                    continue
                if arreter(r):
                    return list(reversed(gardes)), True
                if garder(r):
                    gardes.append(r)
                    if len(gardes) >= lignes_max:
                        return list(reversed(gardes)), False
        return list(reversed(gardes)), True
