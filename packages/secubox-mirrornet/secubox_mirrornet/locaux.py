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

Table de jeux (#3723) : le même chemin sert `ip-indices`, les indicateurs d'adresses vérifiés du WAF. Sa publication est
le CONTENU lui-même (`{"format": 1, "jeu": "ip-indices", "indicateurs": [{ip, famille, expire}], "revus": [ip]}`),
écrite par `wafctl` en root dans /var/lib/secubox/waf/ip-indices-publication.json : elle n'est crue que si elle est un
fichier ordinaire de root (`PROPRIETAIRES_IP`), à un seul lien, sans écriture du groupe ni des autres (le dossier
appartient à secubox-waf, le compte du WAF exposé). Présente et valide : publier et recevoir vrais (tout automatique) ;
absente : le jeu sort de `publications.json` (box sans WAF). Livraison sous `livraisons/ip-indices/`, lue par
`secubox-waf-indices` (compte secubox). `tv-indices` est inchangé : mêmes octets, mêmes noms, même demande.
"""
from __future__ import annotations

import hashlib
import ipaddress
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
#: Livraison des indicateurs d'adresses (#3723) ; None : `PARTAGE / livraisons / ip-indices`, calculé à l'appel.
LIVRAISON_IP: Optional[Path] = None
SOURCE_TV = Path(os.environ.get("SBX_MIRRORNET_SOURCE_TV", "/var/lib/secubox/ad-guard/dnstv/indices-publication.json"))
SOURCE_IP = Path(os.environ.get("SBX_MIRRORNET_SOURCE_IP", "/var/lib/secubox/waf/ip-indices-publication.json"))
#: Propriétaires crus de la publication ip-indices : root seul (wafctl), jamais secubox-waf qui tient le dossier.
PROPRIETAIRES_IP: tuple = (0,)

JEU = "tv-indices"
JEU_IP = "ip-indices"
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
# Schéma ip-indices (#3723) : mêmes bornes que wafctl (500 indicateurs) ; `revus` borné de même.
INDICATEURS_MAX = 500
REVUS_MAX = 500
FAMILLE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\Z")
EXPIRE_MAX = 2 ** 41
_DOCUMENTATION = tuple(ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                          "2001:db8::/32"))
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


def _ip_publique(v: Any) -> bool:
    """Adresse IPv4 ou IPv6 écrite sous forme canonique, globale (ou plage de documentation : banc et essais)."""
    if not isinstance(v, str) or len(v) > 39:
        return False
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return False
    if str(a) != v or a.is_multicast:
        return False
    return a.is_global or any(a.version == n.version and a in n for n in _DOCUMENTATION)


def _contenu_valide_ip(c: Any) -> bool:
    """Contenu ip-indices publiable : exactement {format: 1, jeu, indicateurs, revus} ; chaque indicateur exactement
    {ip, famille, expire} (adresse publique canonique, famille `[a-z0-9_-]` de 64 au plus, échéance epoch entière),
    500 au plus, adresses distinctes ; `revus` = adresses publiques canoniques distinctes, 500 au plus."""
    if not isinstance(c, dict) or set(c) != {"format", "jeu", "indicateurs", "revus"}:
        return False
    if type(c["format"]) is not int or c["format"] != 1 or c["jeu"] != JEU_IP:
        return False
    ind, rev = c["indicateurs"], c["revus"]
    if not isinstance(ind, list) or not isinstance(rev, list) or len(ind) > INDICATEURS_MAX or len(rev) > REVUS_MAX:
        return False
    for i in ind:
        if not isinstance(i, dict) or set(i) != {"ip", "famille", "expire"} or not _ip_publique(i["ip"]):
            return False
        if not isinstance(i["famille"], str) or not FAMILLE.match(i["famille"]):
            return False
        if type(i["expire"]) is not int or not 0 < i["expire"] < EXPIRE_MAX:
            return False
    if len({i["ip"] for i in ind}) != len(ind):
        return False
    return all(_ip_publique(r) for r in rev) and len(set(rev)) == len(rev)


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


def _lire_source_ip(source: Path) -> Any:
    """La publication de wafctl (le contenu lui-même), enveloppée comme celle d'ad-guard (publier et recevoir vrais) ;
    `_ABSENTE` si elle n'existe pas ; None si elle est douteuse (lien, pas un fichier ordinaire, propriétaire hors
    `PROPRIETAIRES_IP`, plusieurs liens, écriture du groupe ou des autres, trop grosse) ou illisible."""
    if not os.path.lexists(source):
        _dire("source-ip", "")
        return _ABSENTE
    fd = -1
    d = None
    try:
        fd = os.open(str(source), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        st = os.fstat(fd)
        if (stat.S_ISREG(st.st_mode) and st.st_uid in PROPRIETAIRES_IP and st.st_nlink == 1
                and not st.st_mode & 0o022 and st.st_size <= TAILLE_MAX):
            with os.fdopen(fd, "rb") as f:
                fd = -1
                brut = f.read(TAILLE_MAX + 1)
            if len(brut) <= TAILLE_MAX:
                d = json.loads(brut.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        d = None
    finally:
        if fd >= 0:
            os.close(fd)
    if not (isinstance(d, dict) and d.get("jeu") == JEU_IP):
        _dire("source-ip", f"publication des indicateurs d'adresses ignorée ({source.name} : lien, propriétaire, "
                           "droits, trop grosse, illisible ou invalide)")
        return None
    _dire("source-ip", "")
    return {"format": 1, "publier": True, "recevoir": True, "contenu": d}


def _source_tv() -> Path:
    return SOURCE_TV


def _source_ip() -> Path:
    return SOURCE_IP


def _livraison_tv() -> Path:
    return LIVRAISON


def _livraison_ip() -> Path:
    return LIVRAISON_IP if LIVRAISON_IP is not None else PARTAGE / "livraisons" / JEU_IP


#: Table des jeux (#3723). `retrait` : demande quand la source est ABSENTE — une entrée « plus de partage »
#: (tv-indices, comportement de #3666) ou None (ip-indices : le jeu sort de la demande).
JEUX: Dict[str, Dict[str, Any]] = {
    JEU: {"libelle": "indices TV", "source": _source_tv, "lire": _lire_source, "valide": _contenu_valide,
          "livraison": _livraison_tv,
          "retrait": {"publier": False, "recevoir": False, "empreinte": None, "taille": None}},
    JEU_IP: {"libelle": "indicateurs d'adresses", "source": _source_ip, "lire": _lire_source_ip,
             "valide": _contenu_valide_ip, "livraison": _livraison_ip, "retrait": None},
}


def deposer(cx: sqlite3.Connection, reglages: Dict[str, Any], source: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Objet tiré de la publication d'ad-guard, gardé comme dépôt de CE nœud, puis demande `publications.json` pour
    l'annuaire (réécrite seulement si elle change). Rend la demande, ou None (source invalide, contenu hors schéma, nœud
    inconnu, objet refusé) — dans ce cas rien n'est écrit. Source ABSENTE (ad-guard retiré) : demande `publier` et
    `recevoir` faux (plus de partage). `publier` faux : aucun objet déposé, la demande garde les interrupteurs avec
    `empreinte` et `taille` nulles."""
    return deposer_jeu(cx, reglages, JEU, source)


def deposer_jeu(cx: sqlite3.Connection, reglages: Dict[str, Any], jeu: str,
                source: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """`deposer` pour un jeu de la table (#3723). Source absente : `retrait` du jeu (entrée « plus de partage », ou
    le jeu retiré de la demande)."""
    t = JEUX[jeu]
    soi = _soi(cx)
    if soi is None:
        return None                              # avant la première synchronisation : on ne sait pas qui on est
    d = t["lire"](Path(source) if source is not None else t["source"]())
    if d is _ABSENTE:
        retrait = t["retrait"]
        return _demander(jeu, dict(retrait) if retrait is not None else None, reglages.get("confiance_min"))
    if d is None:
        return None
    if not d["publier"]:
        return _demander(jeu, {"publier": False, "recevoir": d["recevoir"], "empreinte": None, "taille": None},
                         reglages.get("confiance_min"))
    if not t["valide"](d["contenu"]):
        _dire("depot:" + jeu, f"{t['libelle']} non déposés : contenu hors schéma (rien n'est signé)")
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
            _dire("depot:" + jeu, f"{t['libelle']} non déposés : {e}")
            return None
    _dire("depot:" + jeu, "")
    objets.noter(cx, empreinte, len(data), soi)
    # Contenu identique à une copie reçue : le dépôt local en reprend la propriété (comme une route de dépôt) — jamais
    # celle d'un objet tenu comme copie d'espace (table copie) : il appartient à son producteur.
    cx.execute("UPDATE objet SET source = ? WHERE empreinte = ? AND source <> ? "
               "AND NOT EXISTS (SELECT 1 FROM copie c WHERE c.empreinte = objet.empreinte)", (soi, empreinte, soi))
    return _demander(jeu, {"publier": True, "recevoir": d["recevoir"], "empreinte": empreinte, "taille": len(data)},
                     reglages.get("confiance_min"))


def _demander(jeu: str, entree: Optional[Dict[str, Any]], confiance_min: Any = None) -> Optional[Dict[str, Any]]:
    """Écrit `publications.json` (atomique, 0640) seulement si la demande change ; rend la demande.

    Une seule demande pour tous les jeux : l'entrée de `jeu` est posée (ou retirée si `entree` est None), celles des
    AUTRES jeux de la table déjà écrites sont gardées. Retirer un jeu absent n'écrit rien (rend la demande en place,
    ou None s'il n'y en a pas).

    `confiance_min` (réglage de MirrorNet, LIMITED par défaut, jamais en dessous) dit à l'annuaire à quels producteurs
    s'abonner : le même seuil que la livraison."""
    if confiance_min not in config.RANG or config.RANG[confiance_min] < config.RANG["LIMITED"]:
        confiance_min = "LIMITED"
    ancien = _lire_json(PUBLICATIONS)
    jeux: Dict[str, Any] = {}
    if isinstance(ancien, dict) and isinstance(ancien.get("jeux"), dict):
        jeux = {k: v for k, v in ancien["jeux"].items() if k in JEUX and k != jeu and isinstance(v, dict)}
    if entree is None:
        if not (isinstance(ancien, dict) and isinstance(ancien.get("jeux"), dict) and jeu in ancien["jeux"]):
            return ancien if isinstance(ancien, dict) else None
    else:
        jeux[jeu] = entree
    demande = {"format": 1, "confiance_min": confiance_min, "jeux": jeux}
    if ancien != demande:
        _ecrire_atomique(PUBLICATIONS, json.dumps(demande, sort_keys=True, indent=1).encode("utf-8"))
        if entree is None:
            log.info("mirrornet : %s retirés de la demande de publication", JEUX[jeu]["libelle"])
        else:
            log.info("mirrornet : demande de publication des %s (publier=%s, recevoir=%s, %s)", JEUX[jeu]["libelle"],
                     entree["publier"], entree["recevoir"], (entree["empreinte"] or "sans objet")[:19])
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


def _candidats(cx: sqlite3.Connection, soi: Optional[str], seuil: int, jeu: str = JEU):
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
        (jeu, soi or "", *niveaux)).fetchall()


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


def _noms(livres: Dict[str, str], libelle: str = "indices TV") -> Dict[str, str]:
    """Noms uniques et non usurpables pour `index.json` ({did: nom déclaré} → {did: nom livré}).

    Ad-guard range les producteurs par nom ; `node.nom` est déclaré par chaque nœud et n'est pas unique. Un nom non
    conforme devient `box-<8 hex du did>`. Un nom revendiqué par PLUSIEURS dids est suffixé chez TOUS ses revendicateurs
    (`<nom>-<4 hex>`, puis `<nom>-<8 hex>`, puis les 32 hex du did) : aucun nœud n'apparaît sous un nom simple qu'un
    autre revendique aussi. Les niveaux ne font que monter et le dernier est unique par did : la boucle se termine."""
    base = {did: (n if isinstance(n, str) and NOM.fullmatch(n) else f"box-{did[8:16]}") for did, n in livres.items()}
    for did, n in livres.items():
        if base[did] != n:
            _dire("nom:" + did, f"{libelle} de {did[8:20]} : nom de box « {str(n)[:40]} » non conforme, livré en {base[did]}")
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
                  f"{libelle} : nom « {nom(ds[0])} » revendiqué par {len(ds)} box, suffixé par leur identifiant")
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
    return livrer_jeu(cx, JEU, dossier, confiance_min)


def livrer_jeu(cx: sqlite3.Connection, jeu: str, dossier: Optional[Path] = None,
               confiance_min: Optional[str] = None) -> int:
    """`livrer` pour un jeu de la table (#3723) : offres `usage = <jeu>` seulement, dossier du jeu."""
    t = JEUX[jeu]
    libelle = t["libelle"]
    dossier = Path(dossier) if dossier is not None else t["livraison"]()
    if confiance_min is None:
        confiance_min = config.reglages()["confiance_min"]
    _preparer(dossier)
    ancien = _lire_json(dossier / "index.json")
    ancien = ancien if isinstance(ancien, dict) else None
    livres: Dict[str, Dict[str, str]] = {}
    for r in _candidats(cx, _soi(cx), config.RANG.get(confiance_min, 1), jeu):
        did, nom, empreinte, taille = r["did"], r["nom"], r["empreinte"], r["taille"]
        if did in livres or not DID.fullmatch(did):
            continue
        if len(livres) >= PRODUCTEURS_MAX:
            _dire("plafond:" + jeu, f"{libelle} : plus de {PRODUCTEURS_MAX} producteurs, les suivants ne sont pas livrés")
            break
        cible = dossier / (did[8:] + ".json")
        deja = (ancien or {}).get(did)
        try:
            ok = (isinstance(deja, dict) and deja.get("empreinte") == empreinte and not cible.is_symlink()
                  and cible.is_file() and cible.stat().st_size == taille) or _copier(empreinte, taille, cible)
        except OSError as e:
            log.warning("mirrornet : %s de %s non livrés : %s", libelle, did[8:20], e.__class__.__name__)
            ok = False
        if ok:
            livres[did] = {"nom": nom, "empreinte": empreinte}
        # sinon : version suivante (plus ancienne) de ce producteur, si elle est présente
    noms = _noms({did: v["nom"] for did, v in livres.items()}, libelle)
    for did, v in livres.items():
        v["nom"] = noms[did]
    if ancien != livres:
        _ecrire_atomique(dossier / "index.json", json.dumps(livres, sort_keys=True, indent=1).encode("utf-8"))
        log.info("mirrornet : %s livrés pour %s producteur(s)", libelle, len(livres))
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
    """Dépôt puis livraison de chaque jeu, à la cadence de la réception ; ne lève jamais (erreurs journalisées).

    Clés `publication` et `livres` : tv-indices (#3666). `ip_publication` n'apparaît que si la publication du WAF existe
    sur cette box, `ip_livres` que si des indicateurs d'adresses ont été livrés (#3723)."""
    res: Dict[str, Any] = {}
    erreurs = []
    try:
        res["publication"] = deposer(cx, reglages) is not None
    except Exception as e:  # noqa: BLE001 — la passe de réception continue quoi qu'il arrive
        log.warning("mirrornet : dépôt des indices TV en échec : %s", e)
        erreurs.append(f"dépôt : {e.__class__.__name__}")
    try:
        source_ip = os.path.lexists(_source_ip())
        d = deposer_jeu(cx, reglages, JEU_IP)
        if source_ip:
            res["ip_publication"] = d is not None and JEU_IP in d.get("jeux", {})
    except Exception as e:  # noqa: BLE001
        log.warning("mirrornet : dépôt des indicateurs d'adresses en échec : %s", e)
        erreurs.append(f"dépôt ip-indices : {e.__class__.__name__}")
    try:
        res["livres"] = livrer(cx, LIVRAISON, reglages.get("confiance_min"))
    except Exception as e:  # noqa: BLE001
        log.warning("mirrornet : livraison des indices TV en échec : %s", e)
        erreurs.append(f"livraison : {e.__class__.__name__}")
    try:
        n = livrer_jeu(cx, JEU_IP, None, reglages.get("confiance_min"))
        if n or "ip_publication" in res:
            res["ip_livres"] = n
    except Exception as e:  # noqa: BLE001
        log.warning("mirrornet : livraison des indicateurs d'adresses en échec : %s", e)
        erreurs.append(f"livraison ip-indices : {e.__class__.__name__}")
    if erreurs:
        res["erreur"] = " ; ".join(erreurs)
    return res
