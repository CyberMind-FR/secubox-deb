# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""« Oublier ce nœud » (#3335) : retire un nœud obsolète du registre des pairs (`peers.json`, donc de la projection
`pairs-enroles.json`) et de l'état wg-mesh (`wg_mesh.json`). Le changement de `wg_mesh.json` déclenche
`secubox-p2p-mesh.path` → `sbx-mesh-up` (root), qui retire le pair de l'interface. Aucun privilège ici, aucune commande `wg`.

Refus : nom invalide, nœud local, pair maître (nom `master`, rôle `master` ou clé de l'ancre), désignation inconnue ou
ambiguë (plusieurs pairs du même nom : désigner par la clé publique), nœud en ligne (poignée de main WireGuard de moins de
`mesh.LIVENESS_MAX_AGE` s) ou mesure des poignées absente, sauf `force` pour ces deux derniers.

Écritures (relecture #3341) : atomiques (temporaire aléatoire, fsync, os.replace) sous le verrou `.etat.lock` du dossier
du maillage, pris aussi par les autres écrivains de `peers.json` et `wg_mesh.json` ; un état présent mais illisible n'est
jamais réécrit (clé privée effacée = maillage coupé)."""
from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

from . import mesh

RE_NOM = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
RE_CLE = re.compile(r"[A-Za-z0-9+/]{43}=")
RESERVES = frozenset({"master"})
VERROU = ".etat.lock"


class Refus(Exception):
    """Oubli refusé : le message est montré à l'administrateur."""


class EtatIllisible(Exception):
    """Un état présent mais illisible : jamais réécrit."""


@contextlib.contextmanager
def verrou(dossier):
    """Verrou exclusif `<dossier>/.etat.lock` (flock) des écrivains de peers.json et wg_mesh.json."""
    fd = os.open(os.path.join(str(dossier), VERROU), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def lire_strict(chemin, defaut):
    """Le JSON de `chemin` ; absent → `defaut` ; présent mais illisible ou pas un objet → EtatIllisible."""
    try:
        texte = Path(chemin).read_text(encoding="utf-8")
    except FileNotFoundError:
        return copy.deepcopy(defaut)
    except OSError as e:
        raise EtatIllisible(f"{chemin} illisible") from e
    try:
        doc = json.loads(texte)
    except ValueError as e:
        raise EtatIllisible(f"{chemin} illisible") from e
    if not isinstance(doc, dict):
        raise EtatIllisible(f"{chemin} de forme inattendue")
    return doc


def ecrire_atomique(chemin, doc, mode: int = 0o600) -> None:
    """Temporaire de nom aléatoire dans le même dossier, mode fixé sur le descripteur, fsync, puis os.replace."""
    chemin = Path(chemin)
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=".oubli-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), mode)
            json.dump(doc, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def oublier(peers_doc, wg_state, nom: str, *, handshakes: Optional[dict], now: float, local: str,
            force: bool = False, cle: Optional[str] = None, empreinte: Optional[str] = None,
            cle_maitre: Optional[str] = None):
    """(peers_doc, wg_state, {"registre": n, "wg": m}) sans le pair désigné ; les entrées d'origine ne sont pas modifiées."""
    if not isinstance(nom, str) or not RE_NOM.fullmatch(nom) or nom in RESERVES or nom == (local or "").lower():
        raise Refus("nom de nœud invalide, local ou réservé")
    if cle is not None and not RE_CLE.fullmatch(cle):
        raise Refus("clé publique invalide")
    peers_doc = copy.deepcopy(peers_doc if isinstance(peers_doc, dict) else {"peers": []})
    wg_state = copy.deepcopy(wg_state if isinstance(wg_state, dict) else {})
    liste = [p for p in peers_doc.get("peers") or [] if isinstance(p, dict)]
    wg = [p for p in wg_state.get("peers") or [] if isinstance(p, dict)]
    cibles_wg = [p for p in wg if p.get("name") == nom and (cle is None or p.get("public_key") == cle)]
    if len(cibles_wg) > 1:
        raise Refus(f"nom ambigu : {len(cibles_wg)} pairs « {nom} », désigner par la clé publique")
    def du_registre(p):
        if p.get("name") != nom:
            return False
        return empreinte is None or p.get("fingerprint") == empreinte
    cibles_reg = [p for p in liste if du_registre(p)]
    if (not cibles_wg and not cibles_reg) or (cle is not None and not cibles_wg):
        raise Refus(f"nœud inconnu : {nom}")      # une clé désignée qui ne correspond à aucun pair wg-mesh : rien
    for p in cibles_wg:
        if p.get("role") == "master" or (cle_maitre and p.get("public_key") == cle_maitre):
            raise Refus(f"{nom} est le maître du maillage : jamais oublié")
    if not force and cibles_wg:
        if handshakes is None:
            raise Refus("mesure des poignées de main indisponible : confirmer l'oubli (force)")
        for p in cibles_wg:
            if mesh.peer_liveness(handshakes, str(p.get("public_key") or ""), now) == "online":
                raise Refus(f"{nom} est en ligne : confirmer l'oubli d'un nœud actif (force)")
    ids = {id(p) for p in cibles_wg}
    peers_doc["peers"] = [p for p in liste if not du_registre(p)]
    wg_state["peers"] = [p for p in wg if id(p) not in ids]
    return peers_doc, wg_state, {"registre": len(cibles_reg), "wg": len(cibles_wg)}
