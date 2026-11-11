# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Publication locale et livraison des indices TV (#3666) : le pont entre MirrorNet et le module consommateur.

Dépôt : secubox-ad-guard écrit `indices-publication.json` ({"format": 1, "publier", "recevoir", "contenu"}) ; MirrorNet
en tire l'objet (octets CANONIQUES du contenu, identiques à `dnstv_indices.octets` d'ad-guard, réécrits ici sans
l'importer), le garde comme dépôt de CE nœud, puis écrit `publications.json` pour l'annuaire (qui signe la version, ou
non, selon `publier`). Le fichier d'ad-guard n'est qu'une demande : lu borné, sans suivre de lien, revalidé.

Livraison : pour chaque abonnement Actif de ce nœud à une offre `usage = tv-indices` d'un fournisseur au niveau de
confiance requis, la dernière version non retirée PRÉSENTE ici est recopiée (vérifiée, atomique, 0640) sous
`livraisons/tv-indices/<did-hex32>.json`, et `index.json` dit qui est livré. Ad-guard lit ce dossier sous son compte
(groupe secubox) ; il n'écrit jamais dans le dépôt des objets de MirrorNet.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any, Dict, Optional

from . import config, objets
from .verif import DID

log = logging.getLogger("secubox-mirrornet")

# Chemins surchargeables pour les tests seulement (mêmes règles que config.py).
PARTAGE = Path(os.environ.get("SBX_MIRRORNET_PARTAGE", "/var/lib/secubox-mirrornet-partage"))
PUBLICATIONS = PARTAGE / "publications.json"
LIVRAISON = PARTAGE / "livraisons" / "tv-indices"
SOURCE_TV = Path(os.environ.get("SBX_MIRRORNET_SOURCE_TV", "/var/lib/secubox/ad-guard/dnstv/indices-publication.json"))

JEU = "tv-indices"
TAILLE_MAX = 2 * 1024 * 1024         # fichier d'ad-guard lu, et fichier livré : au plus 2 Mio
PRODUCTEURS_MAX = 64                 # ad-guard n'en lit pas davantage
NOM = re.compile(r"^[a-z0-9-]{1,32}$")
# Schéma du contenu déposé (#3666, revalidé ici : rien d'autre n'est signé) — mêmes bornes qu'ad-guard.
CATEGORIES = ("PUBLICITE", "TRACKING", "TELEMETRIE")
INDICES_MAX = 20000
LEGITIMES_MAX = 5000
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DOMAINE = re.compile(rf"^(?=.{{1,253}}\Z)(?:{_LABEL}\.)+[a-z0-9-]{{2,63}}\Z")
_FICHIER = re.compile(r"^[0-9a-f]{32}\.json$")
_MOTIF: Dict[str, str] = {}          # dernier motif journalisé par sujet : pas un avertissement par passe


def _dire(sujet: str, motif: str) -> None:
    if _MOTIF.get(sujet) != motif:
        _MOTIF[sujet] = motif
        if motif:
            log.warning("mirrornet : %s", motif)


def octets(contenu: Dict[str, Any]) -> bytes:
    """Sérialisation canonique du contenu (doit rester identique à `dnstv_indices.octets` d'ad-guard)."""
    return json.dumps(contenu, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _empreinte(data: bytes) -> str:
    return "b2:" + hashlib.blake2b(data, digest_size=32).hexdigest()


def _lire_borne(chemin: Path, maxi: int = TAILLE_MAX) -> Optional[bytes]:
    """Octets d'un fichier ORDINAIRE (jamais un lien, un tube, un dossier) d'au plus `maxi` octets ; None sinon."""
    fd = -1
    try:
        fd = os.open(str(chemin), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > maxi:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            brut = f.read(maxi + 1)
        return brut if len(brut) <= maxi else None
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _lire_json(chemin: Path, maxi: int = TAILLE_MAX) -> Any:
    brut = _lire_borne(chemin, maxi)
    if brut is None:
        return None
    try:
        return json.loads(brut.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def _ecrire_atomique(chemin: Path, data: bytes) -> None:
    """Temporaire du même dossier (O_EXCL, sans suivre de lien), 0640 explicite (l'unité tourne en UMask=0077), fsync,
    renommage. Toute erreur efface le temporaire."""
    tmp = chemin.parent / f".{chemin.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o640)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _soi(cx: sqlite3.Connection) -> Optional[str]:
    soi = (cx.execute("SELECT soi FROM synchro WHERE id = 1").fetchone() or [None])[0]
    return soi if isinstance(soi, str) and DID.fullmatch(soi) else None


# --- dépôt ---------------------------------------------------------------------------------------------------------

def _contenu_valide(c: Any) -> bool:
    """Contenu publiable : exactement {format: 1, jeu, indices, legitimes} ; `indices` = domaine → PUBLICITE / TRACKING /
    TELEMETRIE (≤ 20 000), `legitimes` = liste de domaines distincts (≤ 5 000), aucun domaine dans les deux."""
    if not isinstance(c, dict) or set(c) != {"format", "jeu", "indices", "legitimes"} or c["format"] != 1 or c["jeu"] != JEU:
        return False
    ind, leg = c["indices"], c["legitimes"]
    if not isinstance(ind, dict) or not isinstance(leg, list) or len(ind) > INDICES_MAX or len(leg) > LEGITIMES_MAX:
        return False
    if not all(isinstance(d, str) and DOMAINE.match(d) and v in CATEGORIES for d, v in ind.items()):
        return False
    if not all(isinstance(d, str) and DOMAINE.match(d) for d in leg) or len(set(leg)) != len(leg):
        return False
    return not (set(leg) & set(ind))


_ABSENTE = object()


def _lire_source(source: Path) -> Any:
    """La publication d'ad-guard ; `_ABSENTE` si le fichier n'existe pas ; None si elle est présente mais invalide."""
    if not os.path.lexists(source):
        _dire("source", "")                     # ad-guard absent ou rien publié : plus de partage (voir deposer)
        return _ABSENTE
    d = _lire_json(source)
    if not (isinstance(d, dict) and d.get("format") == 1 and type(d.get("publier")) is bool
            and type(d.get("recevoir")) is bool and isinstance(d.get("contenu"), dict)
            and d["contenu"].get("jeu") == JEU):
        _dire("source", f"publication des indices TV ignorée ({source.name} : lien, trop gros, illisible ou invalide)")
        return None
    _dire("source", "")
    return d


def deposer(cx: sqlite3.Connection, reglages: Dict[str, Any], source: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Objet tiré de la publication d'ad-guard, gardé comme dépôt de CE nœud, puis demande `publications.json` pour
    l'annuaire (réécrite seulement si elle change). Rend la demande, ou None (source invalide, contenu hors schéma, nœud
    inconnu, objet refusé) — dans ce cas rien n'est écrit. Source ABSENTE (ad-guard retiré) : demande `publier` et
    `recevoir` faux (plus de partage). `publier` faux : aucun objet déposé, la demande garde les interrupteurs avec
    `empreinte` et `taille` nulles."""
    soi = _soi(cx)
    if soi is None:
        return None                              # avant la première synchronisation : on ne sait pas qui on est
    d = _lire_source(Path(source) if source is not None else SOURCE_TV)
    if d is _ABSENTE:
        return _demander({"publier": False, "recevoir": False, "empreinte": None, "taille": None},
                         reglages.get("confiance_min"))
    if d is None:
        return None
    if not d["publier"]:
        return _demander({"publier": False, "recevoir": d["recevoir"], "empreinte": None, "taille": None},
                         reglages.get("confiance_min"))
    if not _contenu_valide(d["contenu"]):
        _dire("depot", "indices TV non déposés : contenu hors schéma (rien n'est signé)")
        return None
    data = octets(d["contenu"])
    if len(data) > TAILLE_MAX:
        return None
    empreinte = _empreinte(data)
    if not objets.present(empreinte):
        try:
            objets.verifier_espace(len(data), int(reglages.get("reserve_mo", 0)))
            objets.ecrire([data], len(data), attendue=empreinte, taille_attendue=len(data))
        except objets.RefusObjet as e:
            _dire("depot", f"indices TV non déposés : {e}")
            return None
    _dire("depot", "")
    objets.noter(cx, empreinte, len(data), soi)
    # Contenu identique à une copie reçue : le dépôt local en reprend la propriété (comme une route de dépôt) — jamais
    # celle d'un objet tenu comme copie d'espace (table copie) : il appartient à son producteur.
    cx.execute("UPDATE objet SET source = ? WHERE empreinte = ? AND source <> ? "
               "AND NOT EXISTS (SELECT 1 FROM copie c WHERE c.empreinte = objet.empreinte)", (soi, empreinte, soi))
    return _demander({"publier": True, "recevoir": d["recevoir"], "empreinte": empreinte, "taille": len(data)},
                     reglages.get("confiance_min"))


def _demander(jeu: Dict[str, Any], confiance_min: Any = None) -> Dict[str, Any]:
    """Écrit `publications.json` (atomique, 0640) seulement si la demande change ; rend la demande.

    `confiance_min` (réglage de MirrorNet, LIMITED par défaut, jamais en dessous) dit à l'annuaire à quels producteurs
    s'abonner : le même seuil que la livraison."""
    if confiance_min not in config.RANG or config.RANG[confiance_min] < config.RANG["LIMITED"]:
        confiance_min = "LIMITED"
    demande = {"format": 1, "confiance_min": confiance_min, "jeux": {JEU: jeu}}
    if _lire_json(PUBLICATIONS) != demande:
        _ecrire_atomique(PUBLICATIONS, json.dumps(demande, sort_keys=True, indent=1).encode("utf-8"))
        log.info("mirrornet : demande de publication des indices TV (publier=%s, recevoir=%s, %s)", jeu["publier"],
                 jeu["recevoir"], (jeu["empreinte"] or "sans objet")[:19])
    return demande


# --- livraison -----------------------------------------------------------------------------------------------------

def _preparer(dossier: Path) -> None:
    """Le paquet crée le dossier (postinst) ; recréé s'il manque, sous un PARTAGE existant. Jamais un lien."""
    for d in (dossier.parent, dossier):
        if os.path.lexists(d):
            continue
        d.mkdir(mode=0o750)
        os.chmod(d, 0o750)
    if dossier.parent.is_symlink() or dossier.is_symlink() or not dossier.is_dir():
        raise NotADirectoryError(f"dossier de livraison invalide : {dossier}")


def _candidats(cx: sqlite3.Connection, soi: Optional[str], seuil: int):
    niveaux = [n for n, r in config.RANG.items() if r >= max(seuil, 1)]      # jamais OBSERVER, jamais REVOKED
    marques = ",".join("?" * len(niveaux))
    return cx.execute(
        "SELECT o.fournisseur_did AS did, n.nom, v.empreinte, v.taille FROM subscription s "
        "JOIN offer o ON o.id = s.offer_id JOIN node n ON n.did = o.fournisseur_did "
        "JOIN dataset_version v ON v.offer_id = o.id JOIN objet x ON x.empreinte = v.empreinte "
        "WHERE s.role = 'abonne' AND o.kind = 'dataset' AND o.usage = ? AND o.etat = 'publiee' "
        "AND v.retiree = 0 AND v.classe <> 'prive' AND o.fournisseur_did <> ? "
        f"AND n.niveau IN ({marques}) "
        "AND (SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id "
        "     ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) = 'Actif' "
        "ORDER BY o.fournisseur_did, v.cree_le DESC, v.numero DESC",
        (JEU, soi or "", *niveaux)).fetchall()


def _copier(empreinte: str, taille: int, cible: Path) -> bool:
    """Recopie l'objet après revérification (taille, BLAKE2b) : un objet altéré sur disque n'est jamais livré."""
    if taille > TAILLE_MAX:
        return False
    try:
        data = _lire_borne(objets.chemin(empreinte), TAILLE_MAX)
    except objets.RefusObjet:
        return False
    if data is None or len(data) != taille or _empreinte(data) != empreinte:
        return False
    _ecrire_atomique(cible, data)
    return True


def _noms(livres: Dict[str, str]) -> Dict[str, str]:
    """Noms uniques et non usurpables pour `index.json` ({did: nom déclaré} → {did: nom livré}).

    Ad-guard range les producteurs par nom ; `node.nom` est déclaré par chaque nœud et n'est pas unique. Un nom non
    conforme devient `box-<8 hex du did>`. Un nom revendiqué par PLUSIEURS dids est suffixé chez TOUS ses revendicateurs
    (`<nom>-<4 hex>`, puis `<nom>-<8 hex>`, puis les 32 hex du did) : aucun nœud n'apparaît sous un nom simple qu'un
    autre revendique aussi. Les niveaux ne font que monter et le dernier est unique par did : la boucle se termine."""
    base = {did: (n if isinstance(n, str) and NOM.fullmatch(n) else f"box-{did[8:16]}") for did, n in livres.items()}
    for did, n in livres.items():
        if base[did] != n:
            _dire("nom:" + did, f"indices de {did[8:20]} : nom de box « {str(n)[:40]} » non conforme, livré en {base[did]}")
    niveau = dict.fromkeys(livres, 0)

    def nom(did: str) -> str:
        b, h = base[did], did[8:]
        return (b, f"{b[:27]}-{h[:4]}", f"{b[:23]}-{h[:8]}", h)[niveau[did]]

    while True:
        par_nom: Dict[str, list] = {}
        for did in livres:
            par_nom.setdefault(nom(did), []).append(did)
        doubles = [ds for ds in par_nom.values() if len(ds) > 1]
        if not doubles:
            return {did: nom(did) for did in livres}
        monte = False
        for ds in doubles:
            _dire("homonymes:" + ",".join(sorted(ds)),
                  f"indices TV : nom « {nom(ds[0])} » revendiqué par {len(ds)} box, suffixé par leur identifiant")
            for did in ds:
                if niveau[did] < 3:
                    niveau[did] += 1
                    monte = True
        if not monte:                         # impossible (32 hex distincts) ; garde contre une boucle sans fin
            return {did: did[8:] for did in livres}


def livrer(cx: sqlite3.Connection, dossier: Optional[Path] = None, confiance_min: Optional[str] = None) -> int:
    """Livre à ad-guard les indices des producteurs écoutés ; rend le nombre de fichiers livrés.

    Ordre : fichiers des producteurs, puis `index.json` (atomique), puis suppression des fichiers qui n'y sont plus —
    un lecteur ne voit jamais un producteur listé sans son fichier."""
    dossier = Path(dossier) if dossier is not None else LIVRAISON
    if confiance_min is None:
        confiance_min = config.reglages()["confiance_min"]
    _preparer(dossier)
    ancien = _lire_json(dossier / "index.json")
    ancien = ancien if isinstance(ancien, dict) else None
    livres: Dict[str, Dict[str, str]] = {}
    for r in _candidats(cx, _soi(cx), config.RANG.get(confiance_min, 1)):
        did, nom, empreinte, taille = r["did"], r["nom"], r["empreinte"], r["taille"]
        if did in livres or not DID.fullmatch(did):
            continue
        if len(livres) >= PRODUCTEURS_MAX:
            _dire("plafond", f"indices TV : plus de {PRODUCTEURS_MAX} producteurs, les suivants ne sont pas livrés")
            break
        cible = dossier / (did[8:] + ".json")
        deja = (ancien or {}).get(did)
        try:
            ok = (isinstance(deja, dict) and deja.get("empreinte") == empreinte and not cible.is_symlink()
                  and cible.is_file() and cible.stat().st_size == taille) or _copier(empreinte, taille, cible)
        except OSError as e:
            log.warning("mirrornet : indices de %s non livrés : %s", did[8:20], e.__class__.__name__)
            ok = False
        if ok:
            livres[did] = {"nom": nom, "empreinte": empreinte}
        # sinon : version suivante (plus ancienne) de ce producteur, si elle est présente
    noms = _noms({did: v["nom"] for did, v in livres.items()})
    for did, v in livres.items():
        v["nom"] = noms[did]
    if ancien != livres:
        _ecrire_atomique(dossier / "index.json", json.dumps(livres, sort_keys=True, indent=1).encode("utf-8"))
        log.info("mirrornet : indices TV livrés pour %s producteur(s)", len(livres))
    gardes = {did[8:] + ".json" for did in livres}
    for p in dossier.iterdir():
        perime = (_FICHIER.fullmatch(p.name) and p.name not in gardes) or (p.name.startswith(".") and p.name.endswith(".tmp"))
        if perime:
            try:
                p.unlink()
            except OSError as e:
                log.warning("mirrornet : livraison périmée %s non effacée : %s", p.name, e.__class__.__name__)
    return len(livres)


def passe(cx: sqlite3.Connection, reglages: Dict[str, Any]) -> Dict[str, Any]:
    """Dépôt puis livraison, à la cadence de la réception ; ne lève jamais (erreurs journalisées)."""
    res: Dict[str, Any] = {}
    erreurs = []
    try:
        res["publication"] = deposer(cx, reglages) is not None
    except Exception as e:  # noqa: BLE001 — la passe de réception continue quoi qu'il arrive
        log.warning("mirrornet : dépôt des indices TV en échec : %s", e)
        erreurs.append(f"dépôt : {e.__class__.__name__}")
    try:
        res["livres"] = livrer(cx, LIVRAISON, reglages.get("confiance_min"))
    except Exception as e:  # noqa: BLE001
        log.warning("mirrornet : livraison des indices TV en échec : %s", e)
        erreurs.append(f"livraison : {e.__class__.__name__}")
    if erreurs:
        res["erreur"] = " ; ".join(erreurs)
    return res
