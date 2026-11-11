# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: encart « Pubs bloquées récemment » par appareil (#3676).

Pour chaque appareil de SBX TV Privacy : ses requêtes REFUSÉES des dernières 24 h (`dnstv_recents`), regroupées par SERVICE
(`lists/services-pub.txt`, sinon le domaine enregistrable), chaque domaine avec son dernier refus, son nombre et QUI l'a bloqué.

Attribution, dans cet ordre (état actuel des règles et des listes, pas celui de l'instant du refus) :
  1. règle TV Privacy active (essai, confirmée) de CET appareil sur le domaine ou un parent — « indice de <box> » si elle est née
     d'un indice du maillage ; une règle qui ne fait que porter une exception « bloquer » de l'administrateur est dite exception ;
  2. exception « bloquer » de l'administrateur pour cet appareil ;
  3. tri Netflix par insistance (#3226) ; puis, pour un appareil en PROTECT, la liste TV Privacy livrée (sa vue ne voit qu'elle) ;
  4. listes DNS compilées (`/var/lib/secubox-dns-listes/sources`) : adblock (95), adulte (96), filtre web (93) — le domaine ou un
     parent y est une `local-zone` qui bloque, la zone la plus précise d'un fichier décidant ;
  5. sinon « autre ».

Calcul LOURD (listes de 650 000 zones, 42 Mo) : jamais dans une requête. Le moteur auto (`secubox-adguard-auto`, chaque minute)
appelle `rafraichir` qui ne travaille qu'une fois par 10 minutes ; chaque liste est lue EN FLUX, une ligne à la fois, en ne
gardant que les zones des domaines cherchés ; l'attribution par les listes est gardée avec la signature des fichiers et seuls les
domaines nouveaux (ou une liste changée) déclenchent une relecture. Le cache n'est réécrit (atomique, 0640) que s'il change.
La route ne lit QUE ce cache.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from . import dnstv, dnstv_analyse, dnstv_protection, dnstv_regles, dnstv_tri
except ImportError:                                   # lancé hors paquet
    from api import dnstv, dnstv_analyse, dnstv_protection, dnstv_regles, dnstv_tri

FICHIER = "pubs-bloquees.json"                        # le cache lu par la route
FICHIER_LISTES = "pubs-listes.json"                   # attribution par les listes compilées, avec la signature des fichiers
MARQUE = ".pubs-bloquees.passe"                       # horodatage de la dernière passe (mtime) : au plus une toutes les PERIODE_S
FICHIER_SERVICES = "services-pub.txt"
PERIODE_S = 600
FENETRE_S = 86400
DOMAINES_PAR_APPAREIL = 200
APPAREILS_MAX = 50
LECTURE_MAX = 8 * 1024 * 1024
MODE_FICHIER = 0o640
DOSSIER_SOURCES = Path(os.environ.get("SECUBOX_DNS_LISTES_SOURCES", "/var/lib/secubox-dns-listes/sources"))
LISTES = (("adblock", "95-secubox-adblock.conf", "liste adblock"),       # ordre = priorité d'attribution
          ("adulte", "96-secubox-adult.conf", "liste adulte"),
          ("webfilter", "93-secubox-webfilter.conf", "filtre web"))
LIBELLES = {cle: libelle for cle, _, libelle in LISTES}
CATEGORIES_TV = {"advertising": "publicité", "tracking": "pistage", "telemetry": "télémétrie", "social": "réseaux sociaux",
                 "custom": "liste personnelle"}
ETATS_REGLE = {"essai": "essai", "confirme": "confirmée"}


# ── services ──────────────────────────────────────────────────────────────────────────────────────

def charger_services(chemin: Path) -> List[Tuple[str, str]]:
    """Lignes `suffixe  service` (`_` = espace), validées ; plus long suffixe d'abord (ordre stable sinon)."""
    out = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        brut = ligne.split("#", 1)[0].split()
        if len(brut) == 2 and dnstv.valider_domaine(brut[0]) == brut[0].lower():
            out.append((brut[0].lower(), brut[1].replace("_", " ")[:40]))
    return sorted(out, key=lambda x: -len(x[0]))


def service_de(domaine: str, services: List[Tuple[str, str]]) -> str:
    for suffixe, service in services:
        if domaine == suffixe or domaine.endswith("." + suffixe):
            return service
    return dnstv_analyse.racine(domaine)


def parents(domaine: str) -> List[str]:
    """Le domaine puis chacun de ses parents, du plus précis au plus large (une `local-zone` couvre tout son sous-arbre)."""
    p = domaine.split(".")
    return [".".join(p[i:]) for i in range(len(p))]


# ── listes compilées : lecture en flux ───────────────────────────────────────────────────────────

def _ouvrir_liste(chemin: Path):
    """Ouverture en lecture d'une liste (jamais un lien symbolique) ; itérée ligne à ligne, jamais chargée en entier."""
    fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW)
    return os.fdopen(fd, "r", encoding="utf-8", errors="replace")


def zones(chemin: Path, candidats: set) -> Dict[str, bool]:
    """Zones de `chemin` présentes dans `candidats` -> vrai si une de leurs occurrences BLOQUE (`always_nxdomain`…), faux si elles ne
    sont que transparentes. `local-zone-override` (exemption par adresse) n'est pas une zone. Mémoire : les seules correspondances."""
    out: Dict[str, bool] = {}
    with _ouvrir_liste(chemin) as h:
        for ligne in h:
            i = ligne.find("local-zone:")
            if i < 0:
                continue
            a = ligne.find('"', i)
            b = ligne.find('"', a + 1) if a >= 0 else -1
            if b < 0:
                continue
            zone = ligne[a + 1:b].rstrip(".").lower()
            if zone not in candidats:
                continue
            action = ligne[b + 1:].split()
            out[zone] = out.get(zone, False) or bool(action and action[0] in dnstv.ACTIONS_BLOQUANTES)
    return out


def _nom_errno(e: OSError) -> str:
    return errno.errorcode.get(e.errno or 0, type(e).__name__)


def _signature(dossier: Path, erreurs: List[str]) -> Dict[str, Optional[List[int]]]:
    """Signature (mtime, taille) de chaque liste ; absente = None (liste non installée, normal). Une liste présente mais
    inaccessible (droits du dossier…) vaut aussi None et s'ajoute à `erreurs`."""
    sig: Dict[str, Optional[List[int]]] = {}
    for _, nom, _ in LISTES:
        try:
            st = os.stat(dossier / nom)
            sig[nom] = [st.st_mtime_ns, st.st_size]
        except FileNotFoundError:
            sig[nom] = None
        except OSError as e:
            sig[nom] = None
            erreurs.append(f"{nom}: {_nom_errno(e)}")
    return sig


def attribuer_listes(domaines: Iterable[str], cache: dict, dossier: Optional[Path] = None) -> Tuple[Dict[str, str], dict]:
    """{domaine: clé de la première liste qui le bloque, "" sinon} et le nouveau cache. Les listes ne sont relues que pour les
    domaines absents du cache, ou pour tous si un fichier a changé (signature mtime + taille) ; chaque fichier une fois au plus.
    Une liste présente mais illisible est journalisée (stderr, une ligne par passe, errno) et le cache porte `listes_lisibles: false` :
    ses blocages s'afficheraient sinon « autre » sans explication."""
    dossier = dossier or DOSSIER_SOURCES
    voulus = set(domaines)
    erreurs: List[str] = []
    sig = _signature(dossier, erreurs)
    connus = dict(cache.get("domaines") or {}) if isinstance(cache, dict) and cache.get("fichiers") == sig else {}
    nouveaux = voulus - set(connus)
    if nouveaux:
        candidats = {p for d in nouveaux for p in parents(d)}
        par_liste = {}
        for cle, nom, _ in LISTES:
            try:
                par_liste[cle] = zones(dossier / nom, candidats) if sig[nom] is not None else {}
            except OSError as e:                             # illisible (droits, lien) : rien n'en vient, et sa signature
                par_liste[cle], sig[nom] = {}, None          # vide forcera une relecture complète dès qu'elle redevient lisible
                erreurs.append(f"{nom}: {_nom_errno(e)}")
        for d in nouveaux:
            connus[d] = ""
            for cle, _, _ in LISTES:
                z = par_liste[cle]
                decide = next((z[p] for p in parents(d) if p in z), False)     # la zone la plus précise du fichier décide
                if decide:
                    connus[d] = cle
                    break
    if erreurs:
        print("pubs bloquées : listes compilées illisibles (" + ", ".join(erreurs) + ")", file=sys.stderr)
    garde = {d: connus[d] for d in sorted(voulus)}
    return dict(garde), {"version": 1, "fichiers": sig, "domaines": garde, "listes_lisibles": not erreurs}


# ── attribution ───────────────────────────────────────────────────────────────────────────────────

def _index_regles(regles) -> Dict[Tuple[str, str], dict]:
    return {(r["appareil"], r["domaine"]): r for r in regles.liste() if r["etat"] in ETATS_REGLE}


def _index_exceptions(exceptions: list) -> set:
    return {(e["appareil"], e["domaine"]) for e in exceptions if e["type"] == "bloquer"}


def source_avant_listes(slug: str, domaine: str, mode: str, categorie: str, regles: dict, exceptions: set,
                        tri: set) -> Optional[Tuple[str, str]]:
    """Étapes 1 à 3 (règle, indice, exception, tri, liste TV en PROTECT) ; None : à chercher dans les listes compilées."""
    ps = parents(domaine)
    r = next((regles[(slug, p)] for p in ps if (slug, p) in regles), None)
    if r is not None:
        if (slug, r["domaine"]) in exceptions:
            return "exception", "exception de l'administrateur"
        if r.get("indice"):
            return "indice", "indice de " + ", ".join(r["indice"])
        return "regle", f"règle TV Privacy ({ETATS_REGLE[r['etat']]})"
    if any((slug, p) in exceptions for p in ps):
        return "exception", "exception de l'administrateur"
    if mode == "auto" and slug in tri and (domaine == dnstv_tri.ZONE or domaine.endswith("." + dnstv_tri.ZONE)):
        return "tri", "tri Netflix"
    if mode == "block" and categorie:
        return "liste-tv", f"liste TV Privacy ({CATEGORIES_TV.get(categorie, categorie)})"
    return None


def construire(lignes: List[dict], etat: dict, regles, exceptions: list, services: List[Tuple[str, str]], cache_listes: dict,
               maintenant: int, dossier_sources: Optional[Path] = None) -> Tuple[dict, dict]:
    """Contenu du cache et nouveau cache des listes. `lignes` : `Magasin.bloques` (adresse, domaine, nombre, dernier refus)."""
    par_ip = {c["ip"]: c for c in etat.get("clients", [])}
    tri = set(dnstv_tri.reglage(etat).get("appareils") or [])
    appareils: Dict[str, Dict[str, dict]] = {}
    for x in lignes:
        c = par_ip.get(x["client"])
        if c is None:
            continue
        slug = dnstv._slug(c["nom"])
        d = appareils.setdefault(slug, {}).setdefault(x["domaine"], {"domaine": x["domaine"], "dernier_ts": 0, "nombre": 0,
                                                                       "mode": c["mode"], "categorie": ""})
        d["nombre"] += int(x["nombre"])
        if x["dernier_ts"] > d["dernier_ts"]:
            d.update(dernier_ts=int(x["dernier_ts"]), mode=c["mode"], categorie=x.get("categorie") or "")
    # plafonds : les appareils au refus le plus récent, puis leurs domaines les plus récents
    recence = sorted(appareils, key=lambda s: (-max(v["dernier_ts"] for v in appareils[s].values()), s))[:APPAREILS_MAX]
    retenus = {s: sorted(appareils[s].values(), key=lambda v: (-v["dernier_ts"], v["domaine"]))[:DOMAINES_PAR_APPAREIL] for s in recence}
    ix_r, ix_e = _index_regles(regles), _index_exceptions(exceptions)
    for s, doms in retenus.items():
        for v in doms:
            v["_src"] = source_avant_listes(s, v["domaine"], v["mode"], v["categorie"], ix_r, ix_e, tri)
    a_chercher = {v["domaine"] for doms in retenus.values() for v in doms if v["_src"] is None}
    attr, cache_listes = attribuer_listes(a_chercher, cache_listes, dossier_sources)
    sortie: Dict[str, list] = {}
    for s, doms in retenus.items():
        groupes: Dict[str, dict] = {}
        for v in doms:
            src = v["_src"] or ((attr[v["domaine"]], LIBELLES[attr[v["domaine"]]]) if attr.get(v["domaine"]) else ("autre", "autre"))
            nom = service_de(v["domaine"], services)
            g = groupes.setdefault(nom, {"service": nom, "nombre": 0, "dernier_ts": 0, "domaines": []})
            g["nombre"] += v["nombre"]
            g["dernier_ts"] = max(g["dernier_ts"], v["dernier_ts"])
            g["domaines"].append({"domaine": v["domaine"], "dernier_ts": v["dernier_ts"], "nombre": v["nombre"], "source": src[0], "detail": src[1]})
        sortie[s] = sorted(groupes.values(), key=lambda g: (-g["dernier_ts"], g["service"]))
    return {"version": 1, "maj": int(maintenant), "fenetre_s": FENETRE_S, "listes_lisibles": bool(cache_listes.get("listes_lisibles", True)),
            "appareils": sortie}, cache_listes


# ── fichiers ──────────────────────────────────────────────────────────────────────────────────────

def _lire_json(chemin: Path):
    """JSON borné, jamais par un lien symbolique ni autre chose qu'un fichier ordinaire (une FIFO ne bloque jamais : O_NONBLOCK
    puis refus) ; None si absent ou illisible."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return json.loads(h.read(LECTURE_MAX))
    except (OSError, ValueError):
        return None


def _ecrire_si_change(chemin: Path, contenu: dict, ignorer: Tuple[str, ...] = ()) -> bool:
    """Écriture atomique (temporaire du même dossier, 0640, rename) seulement si le contenu change, `ignorer` mis à part."""
    ancien = _lire_json(chemin)
    if isinstance(ancien, dict) and {k: v for k, v in ancien.items() if k not in ignorer} == {k: v for k, v in contenu.items() if k not in ignorer}:
        return False
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix="." + chemin.stem + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            os.fchmod(h.fileno(), MODE_FICHIER)
            json.dump(contenu, h, ensure_ascii=False, separators=(",", ":"))
            h.flush()
            os.fsync(h.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True


def rafraichir(maintenant: int, dossier: Optional[Path] = None, force: bool = False) -> bool:
    """Une passe (moteur auto) : rien si la précédente a moins de PERIODE_S (sauf `force`). Rend vrai si la passe a eu lieu.
    Règles ou exceptions illisibles : lève (le moteur journalise) et RIEN n'est écrit — jamais une attribution fausse."""
    d = dossier or dnstv.DOSSIER_ETAT
    marque = d / MARQUE
    if not force:
        try:
            if 0 <= maintenant - os.lstat(marque).st_mtime < PERIODE_S:
                return False
        except FileNotFoundError:
            pass
    d.mkdir(parents=True, exist_ok=True)
    # Marque posée AVANT le calcul (une passe qui échoue n'est pas refaite chaque minute), par descripteur : jamais à travers un lien
    # symbolique (O_NOFOLLOW → ELOOP, la passe s'arrête), jamais bloquée par une FIFO (O_NONBLOCK).
    fd = os.open(marque, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, MODE_FICHIER)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "marque des pubs bloquées : pas un fichier ordinaire")
        os.utime(fd, (maintenant, maintenant))
    finally:
        os.close(fd)
    etat, erreur = dnstv.lire_etat(d)
    if erreur:
        raise dnstv.ErreurTV(erreur)
    regles = dnstv_regles.charger(d)
    exceptions = dnstv_protection.charger_exceptions(d)
    f = dnstv.DOSSIER_LISTES / FICHIER_SERVICES
    services = charger_services(f) if f.is_file() else []
    lignes = dnstv.Magasin(d / "dnstv.db").bloques(maintenant - FENETRE_S)
    cache = _lire_json(d / FICHIER_LISTES)
    contenu, cache = construire(lignes, etat, regles, exceptions, services, cache if isinstance(cache, dict) else {}, maintenant)
    _ecrire_si_change(d / FICHIER_LISTES, cache)
    _ecrire_si_change(d / FICHIER, contenu, ignorer=("maj",))
    return True


def vue(slug: str, dossier: Optional[Path] = None) -> dict:
    """Lecture SEULE du cache pour un appareil : {maj (dernier contenu), verifie (dernière passe), services}."""
    d = dossier or dnstv.DOSSIER_ETAT
    doc = _lire_json(d / FICHIER)
    try:
        verifie: Optional[int] = int(os.lstat(d / MARQUE).st_mtime)
    except OSError:
        verifie = None
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("appareils"), dict):
        return {"maj": None, "verifie": verifie, "fenetre_s": FENETRE_S, "listes_lisibles": True, "services": []}
    services = doc["appareils"].get(slug)
    return {"maj": doc.get("maj"), "verifie": verifie, "fenetre_s": FENETRE_S, "listes_lisibles": doc.get("listes_lisibles") is not False,
            "services": services if isinstance(services, list) else []}

