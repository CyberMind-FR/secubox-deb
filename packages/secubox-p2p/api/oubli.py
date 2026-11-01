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
import threading
import time
from pathlib import Path
from typing import Optional

from . import mesh

RE_NOM = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
RE_CLE = re.compile(r"[A-Za-z0-9+/]{43}=")
RESERVES = frozenset({"master"})
VERROU = ".etat.lock"


class Refus(Exception):
    """Oubli refusé : le message est montré à l'administrateur."""


class VerrouOccupe(Exception):
    """Le verrou est tenu au-delà de l'attente bornée demandée (route publique, #3362 passe 3)."""


class EtatIllisible(Exception):
    """Un état présent mais illisible : jamais réécrit."""


_TENUS = threading.local()


def _cle(dossier) -> str:
    return os.path.realpath(str(dossier))


def tenu(dossier) -> bool:
    """Ce fil tient-il déjà le verrou de `dossier` ?"""
    return getattr(_TENUS, "profondeurs", {}).get(_cle(dossier), 0) > 0


@contextlib.contextmanager
def verrou(dossier, attente: Optional[float] = None):
    """Verrou exclusif `<dossier>/.etat.lock` (flock) des écrivains de peers.json, wg_mesh.json, requests.json et tokens.json.

    RÉENTRANT DANS UN MÊME FIL (#3362, passe 2) : une section critique de lecture-modification-écriture (jonction,
    approbation, oubli) appelle des écrivains (save_json) qui, sous elle, écrivent « déjà sous verrou » au lieu de reprendre
    un flock sur un second descripteur, ce qui bloquerait le fil contre lui-même. Entre fils ou processus : exclusif."""
    cle = _cle(dossier)
    prof = _TENUS.__dict__.setdefault("profondeurs", {})
    if prof.get(cle, 0) > 0:
        prof[cle] += 1
        try:
            yield
        finally:
            prof[cle] -= 1
        return
    fd = os.open(os.path.join(str(dossier), VERROU), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        if os.geteuid() == 0:            # #3362 : créé par root (sbx-mesh-invite), il resterait fermé au service
            st = os.stat(str(dossier))
            os.fchown(fd, st.st_uid, st.st_gid)
        if attente is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:                            # non bloquant, réessai borné : un appelant public ne fige jamais rien
            fin = time.monotonic() + attente
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= fin:
                        raise VerrouOccupe("état du maillage occupé") from None
                    time.sleep(0.05)
        prof[cle] = 1
        try:
            yield
        finally:
            prof[cle] = 0
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


def lire_strict_liste(chemin):
    """#3362 : demandes et jetons de jonction (listes JSON). Absent → [] ; présent mais illisible ou pas une liste →
    EtatIllisible : jamais lu comme vide, donc jamais réécrit vide (load_json avalait l'erreur et rendait [])."""
    try:
        texte = Path(chemin).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as e:
        raise EtatIllisible(f"{chemin} illisible") from e
    try:
        doc = json.loads(texte)
    except ValueError as e:
        raise EtatIllisible(f"{chemin} illisible") from e
    if not isinstance(doc, list):
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


def maj_json(chemin, fn, *, dossier=None, defaut=None, mode: int = 0o600):
    """#3362 (passe 5) : lecture-modification-écriture ATOMIQUE d'un état du maillage. Sous `verrou(dossier)` (réentrant ;
    par défaut le dossier du fichier) : lecture STRICTE (`lire_strict`, ou `lire_strict_liste` si `defaut` est une liste),
    `fn(document)` qui le modifie EN PLACE, puis `ecrire_atomique`. Rend le résultat de `fn`. Une exception de `fn` (refus)
    annule l'écriture ; `fn` rend `SANS_ECRITURE` pour ne rien réécrire."""
    dossier = dossier if dossier is not None else os.path.dirname(str(chemin)) or "."
    with verrou(dossier):
        if isinstance(defaut, list):
            doc = lire_strict_liste(chemin)
        else:
            doc = lire_strict(chemin, defaut if defaut is not None else {})
        res = fn(doc)
        if res is SANS_ECRITURE:
            return None
        ecrire_atomique(chemin, doc, mode)
        return res


class _SansEcriture:
    def __repr__(self):
        return "SANS_ECRITURE"


SANS_ECRITURE = _SansEcriture()


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
    if cle is not None and not cibles_wg:
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
    restants_wg = [p for p in wg if id(p) not in ids]
    ips = sorted({ip for p in cibles_wg for ip in [_ip_pair(p)] if ip})
    cles = [str(p.get("public_key")) for p in cibles_wg if RE_CLE.fullmatch(str(p.get("public_key") or ""))]
    # #3362 : l'adresse d'un pair ciblé désigne aussi son entrée du registre (désignation par clé : l'homonyme garde la sienne).
    ips_restantes = {_ip_pair(p) for p in restants_wg}
    nom_partage = any(p.get("name") == nom for p in restants_wg)
    def du_registre_cible(p):
        if empreinte is not None:
            return du_registre(p)
        if p.get("mesh_ip") and p.get("mesh_ip") in ips:
            return True
        return p.get("name") == nom and not nom_partage and not (p.get("mesh_ip") in ips_restantes and p.get("mesh_ip"))
    retires_reg = [p for p in liste if du_registre_cible(p)]
    if not cibles_wg and not retires_reg:
        raise Refus(f"nœud inconnu : {nom}")
    peers_doc["peers"] = [p for p in liste if not du_registre_cible(p)]
    wg_state["peers"] = restants_wg
    nom_libre = not nom_partage and not any(p.get("name") == nom for p in peers_doc["peers"])
    return peers_doc, wg_state, {"registre": len(retires_reg), "wg": len(cibles_wg), "cles": cles, "ips": ips,
                                 "empreintes": sorted({str(p["fingerprint"]) for p in retires_reg if p.get("fingerprint")}),
                                 "nom_libre": nom_libre}


def _ip_pair(p) -> Optional[str]:
    """Adresse du maillage d'une entrée wg_mesh.json : `mesh_ip`, sinon l'hôte d'un `allowed_ips` en /32."""
    ip = p.get("mesh_ip")
    if isinstance(ip, str) and ip:
        return ip
    ai = str(p.get("allowed_ips") or "").split(",")[0].strip()
    return ai[:-3] if ai.endswith("/32") else None


def oublier_jonctions(demandes, jetons, nom: str, cibles: dict):
    """#3362 : les jonctions du pair oublié. Une demande approuvée qui reste ferait revenir le pair à sa prochaine jonction
    (« Already approved » → `_provision`) et garderait son adresse et son nom : elle part (empreinte ou clé du pair).
    Les jetons qu'il a consommés sont révoqués ; un jeton flash prévu pour son nom aussi, si le nom n'est plus porté.
    Rend (demandes, jetons, {"demandes": n, "jetons": m}) ; les entrées d'origine ne sont pas modifiées."""
    fps = set(cibles.get("empreintes") or [])
    cles = set(cibles.get("cles") or [])
    demandes = copy.deepcopy([d for d in demandes or [] if isinstance(d, dict)])
    jetons = copy.deepcopy([j for j in jetons or [] if isinstance(j, dict)])
    def du_pair(d):
        return (d.get("fingerprint") in fps and d.get("fingerprint")) or (d.get("wg_public_key") in cles and d.get("wg_public_key"))
    partantes = [d for d in demandes if du_pair(d)]
    fps |= {d["fingerprint"] for d in partantes if d.get("fingerprint")}
    n_jetons = 0
    for j in jetons:
        if j.get("status") == "revoked":
            continue
        if (j.get("peer_fp") and j.get("peer_fp") in fps) or (
                cibles.get("nom_libre") and j.get("flash") and j.get("nom_prevu") == nom):
            j["status"] = "revoked"
            n_jetons += 1
    return [d for d in demandes if not du_pair(d)], jetons, {"demandes": len(partantes), "jetons": n_jetons}
