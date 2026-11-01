# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: SBX TV PRIVACY lot 3 (#3374) — cache de classification DÉCOUPÉ et analyseur côté serveur.

Le moteur AUTO écrivait un JSON unique (16 Mo sur gk2), relu en entier à chaque appel et perdu au-delà de 16 Mio. Il écrit
désormais une base SQLite (`classification-cache.db`, 0640, remplacée atomiquement) : chaque lecture est une requête bornée
(filtres, agrégats, `LIMIT/OFFSET`), jamais le jeu complet en mémoire ni dans le navigateur.

Tous les paramètres viennent de listes fermées ou sont bornés ici (`ErreurAnalyse`, message sûr à montrer) ; le SQL n'est fait
que de fragments constants et de paramètres liés.
"""
from __future__ import annotations

import collections
import contextlib
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:
    from . import dnstv, dnstv_taxonomie
except ImportError:                                   # lancé hors paquet
    from api import dnstv, dnstv_taxonomie

FICHIER = "classification-cache.db"
ANCIEN_JSON = "classification-cache.json"
MODE_FICHIER = 0o640
FENETRES = {"1h": 3600, "24h": 86400, "7j": 7 * 86400, "30j": 30 * 86400}
FENETRES_SOUS_UN_JOUR = ("1h", "24h")                 # « nouveaux » n'y est pas calculé : la première vue est au jour UTC (I3)
TEMPORAIRE_AGE_S = 600
DECISIONS = ("bloque", "autorise", "candidat", "protege")
AGREGATS = ("domaine", "racine", "categorie", "appareil", "aucun")
LIMITE_MAX = 200
MACS_MAX = 8
EXPORT_MAX = 50000
AGREGATS_MAX = 50
Q_RE = re.compile(r"^[a-z0-9.-]{1,64}$")

SCHEMA = """
CREATE TABLE lignes (domaine TEXT NOT NULL, racine TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', nom TEXT NOT NULL DEFAULT '',
    ips TEXT NOT NULL DEFAULT '[]', categorie TEXT NOT NULL, source TEXT NOT NULL, confiance INTEGER NOT NULL, ancienne TEXT,
    protegee INTEGER NOT NULL, requetes INTEGER NOT NULL, bloquees INTEGER NOT NULL, derniere INTEGER NOT NULL DEFAULT 0,
    precision TEXT, premiere INTEGER NOT NULL DEFAULT 0, regle TEXT NOT NULL DEFAULT '');
CREATE INDEX lignes_derniere ON lignes(derniere);
CREATE INDEX lignes_mac ON lignes(mac);
CREATE TABLE meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
"""


class ErreurAnalyse(ValueError):
    """Paramètre refusé ; le message est sûr à montrer."""


def racine(domaine: str) -> str:
    """Domaine racine approché (eTLD+1) : deux dernières étiquettes, trois si les deux dernières sont un suffixe public connu."""
    p = str(domaine).split(".")
    n = 3 if len(p) >= 3 and ".".join(p[-2:]) in dnstv_taxonomie.SUFFIXES_PUBLICS else 2
    return ".".join(p[-n:])


# ── écriture (moteur AUTO) ───────────────────────────────────────────────────────────────────────────

def _regles_par_couple(etat: Optional[dict], regles: Iterable[dict]) -> Dict[tuple, str]:
    macs = dnstv_taxonomie.macs_par_appareil(etat or {})
    out = {}
    for r in regles or []:
        for mac in macs.get(r.get("appareil"), [""]):
            out[(mac, r.get("domaine"))] = r.get("etat", "")
    return out


def ecrire_cache(lignes: List[dict], maintenant: int, dossier: Optional[Path] = None, etat: Optional[dict] = None,
                 regles: Iterable[dict] = ()) -> None:
    """Écrit le cache (SQLite) dans un fichier temporaire du même dossier puis le remplace atomiquement ; supprime l'ancien JSON."""
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    noms = {c.get("mac"): c.get("nom", "") for c in (etat or {}).get("clients", []) if c.get("mac")}
    couples = _regles_par_couple(etat, regles)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".classification-cache.")
    os.close(fd)
    try:
        cx = sqlite3.connect(tmp)
        try:
            cx.executescript(SCHEMA)
            cx.executemany("INSERT INTO lignes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                (e["domaine"], racine(e["domaine"]), e.get("mac") or "", noms.get(e.get("mac"), ""), json.dumps(e.get("ips") or []),
                 e.get("categorie", "INCONNU"), e.get("source", ""), int(e.get("confiance") or 0), e.get("ancienne"),
                 1 if e.get("protegee") else 0, int(e.get("requetes") or 0), int(e.get("bloquees") or 0),
                 int(e.get("derniere_observation") or 0), e.get("precision"),
                 int(e.get("premiere_observation") or e.get("derniere_observation") or 0),
                 couples.get((e.get("mac") or "", e["domaine"]), ""))
                for e in lignes if isinstance(e, dict) and e.get("domaine")))
            cx.execute("INSERT INTO meta VALUES ('genere', ?)", (str(int(maintenant)),))
            cx.commit()
        finally:
            cx.close()
        os.chmod(tmp, MODE_FICHIER)
        os.replace(tmp, d / FICHIER)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    with contextlib.suppress(OSError):
        (d / ANCIEN_JSON).unlink()


def menage(dossier: Optional[Path] = None, maintenant: Optional[float] = None) -> None:
    """Supprime l'ancien cache JSON (jusqu'à 16 Mo) et les fichiers temporaires SQLite orphelins de plus de 10 min (un moteur tué
    pendant l'écriture). Appelé par le moteur à CHAQUE passage, même inactif. Aucune erreur ne remonte."""
    import time as _t
    d = dossier or dnstv.DOSSIER_ETAT
    limite = (maintenant if maintenant is not None else _t.time()) - TEMPORAIRE_AGE_S
    with contextlib.suppress(OSError):
        (d / ANCIEN_JSON).unlink()
    try:
        candidats = list(d.glob(".classification-cache.*"))
    except OSError:
        return
    for f in candidats:
        with contextlib.suppress(OSError):
            if not f.is_symlink() and f.is_file() and f.stat().st_mtime < limite:
                f.unlink()


# ── lecture (API) ────────────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _ouvrir(dossier: Optional[Path]):
    """Connexion en LECTURE SEULE ; None si le cache est absent, un lien symbolique ou illisible."""
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER
    if f.is_symlink() or not f.is_file():
        yield None
        return
    try:
        cx = sqlite3.connect(f"file:{f}?mode=ro", uri=True, timeout=5)
        cx.execute("SELECT 1 FROM meta LIMIT 1")
    except sqlite3.Error:
        yield None
        return
    try:
        yield cx
    finally:
        cx.close()


def genere(dossier: Optional[Path] = None) -> Optional[int]:
    """Horodatage du cache, sans le lire ; None s'il n'y en a pas."""
    with _ouvrir(dossier) as cx:
        if cx is None:
            return None
        r = cx.execute("SELECT valeur FROM meta WHERE cle='genere'").fetchone()
        return int(r[0]) if r else None


COLONNES = "domaine, mac, nom, ips, categorie, source, confiance, ancienne, protegee, requetes, bloquees, derniere, precision, premiere, regle"


def _ligne(r) -> dict:
    (domaine, mac, nom, ips, cat, src, conf, anc, prot, req, bloq, der, prec, prem, regle) = r
    return {"domaine": domaine, "mac": mac or None, "nom": nom or None, "ips": json.loads(ips or "[]"), "categorie": cat, "source": src,
            "confiance": conf, "ancienne": anc, "protegee": bool(prot), "requetes": req, "bloquees": bloq,
            "derniere_observation": der or None, "precision": prec, "premiere_observation": prem or None, "regle": regle or None}


def toutes(dossier: Optional[Path] = None) -> Optional[dict]:
    """Compatibilité (lot 2, tests) : le cache entier sous la forme `{version, genere, domaines}`. L'API ne s'en sert pas."""
    g = genere(dossier)
    if g is None:
        return None
    with _ouvrir(dossier) as cx:
        if cx is None:
            return None
        try:
            lignes = [_ligne(r) for r in cx.execute(f"SELECT {COLONNES} FROM lignes ORDER BY derniere DESC, domaine, mac")]
        except sqlite3.Error:
            return None
    return {"version": 1, "genere": g, "domaines": lignes}


def _liste(valeurs, admises, nom: str, maximum: int) -> List[str]:
    v = list(valeurs or [])
    if len(v) > maximum:
        raise ErreurAnalyse(f"{nom} : {maximum} valeurs au plus")
    for x in v:
        if x not in admises:
            raise ErreurAnalyse(f"{nom} inconnu(e)")
    return list(dict.fromkeys(v))


def _entier(v, nom: str, bas: int, haut: int) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not bas <= v <= haut:
        raise ErreurAnalyse(f"{nom} : entier de {bas} à {haut} attendu")
    return v


def filtre(fenetre: str = "30j", macs=(), categories=(), decisions=(), sources=(), confiance_min: int = 0, confiance_max: int = 100,
           q: Optional[str] = None, domaine_exact: Optional[str] = None, racine_exacte: Optional[str] = None,
           maintenant: int = 0) -> tuple:
    """(clause WHERE, paramètres) après validation stricte de chaque filtre. Les filtres se combinent par ET ; les valeurs d'un même
    filtre par OU."""
    if fenetre not in FENETRES:
        raise ErreurAnalyse("fenêtre inconnue (1h, 24h, 7j, 30j)")
    if len(list(macs or [])) > MACS_MAX:
        raise ErreurAnalyse(f"appareils : {MACS_MAX} au plus")
    ms = []
    for m in macs or []:
        m2 = m.strip().lower() if isinstance(m, str) else ""
        if not dnstv.MAC_RE.match(m2):
            raise ErreurAnalyse("MAC invalide")
        ms.append(m2)
    cats = _liste(categories, dnstv_taxonomie.CATEGORIES, "catégorie", len(dnstv_taxonomie.CATEGORIES))
    decs = _liste(decisions, DECISIONS, "décision", len(DECISIONS))
    srcs = _liste(sources, dnstv_taxonomie.SOURCES + (dnstv_taxonomie.SOURCE_AUCUNE,), "source", 6)
    cmin, cmax = _entier(confiance_min, "confiance_min", 0, 100), _entier(confiance_max, "confiance_max", 0, 100)
    # 30 j (la rétention) : aussi les lignes jamais observées (domaines des règles, corrections manuelles), comme au lot 2.
    fen = "(derniere >= ? OR derniere = 0)" if fenetre == "30j" else "derniere >= ?"
    w, a = [fen, "confiance BETWEEN ? AND ?"], [int(maintenant) - FENETRES[fenetre], cmin, cmax]
    if ms:
        w.append("mac IN (%s)" % ",".join("?" * len(ms)))
        a += ms
    if cats:
        w.append("categorie IN (%s)" % ",".join("?" * len(cats)))
        a += cats
    if srcs:
        w.append("source IN (%s)" % ",".join("?" * len(srcs)))
        a += srcs
    if decs:
        f = {"bloque": "bloquees > 0", "autorise": "requetes > bloquees", "candidat": "regle = 'candidat'", "protege": "protegee = 1"}
        w.append("(" + " OR ".join(f[x] for x in decs) + ")")
    if q is not None and q != "":
        if not isinstance(q, str) or not Q_RE.match(q):
            raise ErreurAnalyse("recherche : 64 caractères au plus parmi a-z 0-9 . -")
        w.append("instr(domaine, ?) > 0")
        a.append(q)
    for val, col in ((domaine_exact, "domaine"), (racine_exacte, "racine")):
        if val:
            if dnstv.valider_domaine(val) != val:
                raise ErreurAnalyse("domaine invalide")
            w.append(f"{col} = ?")
            a.append(val)
    return " AND ".join(w), a


CLES_AGREGAT = {"domaine": "domaine", "racine": "racine", "categorie": "categorie", "appareil": "mac"}


def _groupes(cx, cle: str, where: str, a: list, limite: int) -> List[dict]:
    col = CLES_AGREGAT[cle]
    out = []
    for k, nom, n, dn, req, bloq in cx.execute(
            f"SELECT {col}, MAX(nom), COUNT(*), COUNT(DISTINCT domaine), SUM(requetes), SUM(bloquees) FROM lignes WHERE {where} "
            f"GROUP BY {col} ORDER BY SUM(requetes) DESC, {col} LIMIT ?", a + [limite]):
        x = {"cle": k or None, "lignes": n, "domaines": dn, "requetes": req or 0, "bloquees": bloq or 0,
             "part_bloquee": round((bloq or 0) / req, 4) if req else 0.0}
        if cle == "appareil":
            x["nom"] = nom or None
        out.append(x)
    return out


def analyser(dossier: Optional[Path] = None, fenetre: str = "30j", macs=(), categories=(), decisions=(), sources=(),
             confiance_min: int = 0, confiance_max: int = 100, q: Optional[str] = None, domaine_exact: Optional[str] = None,
             racine_exacte: Optional[str] = None, agreger: str = "racine", decalage: int = 0, limite: int = 25,
             maintenant: int = 0) -> dict:
    """Métriques, agrégats et une page de lignes pour les filtres donnés, calculés en SQL sur le cache. Cache absent : `cache: false`."""
    if agreger not in AGREGATS:
        raise ErreurAnalyse("agrégation inconnue (domaine, racine, categorie, appareil, aucun)")
    _entier(limite, "limite", 1, LIMITE_MAX)
    _entier(decalage, "décalage", 0, 10_000_000)
    where, a = filtre(fenetre, macs, categories, decisions, sources, confiance_min, confiance_max, q, domaine_exact, racine_exacte,
                      maintenant)
    vide = {"cache": False, "genere": None, "total": 0, "decalage": decalage, "limite": limite, "lignes": [], "agregats": [],
            "agreger": agreger, "fenetre": fenetre,
            "metriques": {"domaines": 0, "requetes": 0, "bloquees": 0, "part_bloquee": 0.0, "par_categorie": {}, "top_domaines": [],
                          "top_appareils": [], "nouveaux": None if fenetre in FENETRES_SOUS_UN_JOUR else 0}}
    g = genere(dossier)
    if g is None:
        return vide
    try:
        return _analyser(dossier, g, where, a, fenetre, agreger, decalage, limite, maintenant) or vide
    except sqlite3.Error:
        return vide                                               # cache corrompu ou d'un autre schéma : comme absent, jamais une 500


def _analyser(dossier, g, where, a, fenetre, agreger, decalage, limite, maintenant) -> Optional[dict]:
    with _ouvrir(dossier) as cx:
        if cx is None:
            return None
        total, dn, req, bloq = cx.execute(f"SELECT COUNT(*), COUNT(DISTINCT domaine), COALESCE(SUM(requetes),0), COALESCE(SUM(bloquees),0) "
                                          f"FROM lignes WHERE {where}", a).fetchone()
        par_cat = {c: {"domaines": n, "requetes": r or 0} for c, n, r in cx.execute(
            f"SELECT categorie, COUNT(DISTINCT domaine), SUM(requetes) FROM lignes WHERE {where} GROUP BY categorie", a)}
        # I3 : la première vue est au JOUR (UTC) ; sous un jour, « nouveau » serait faux : non calculé (None).
        nouveaux = None if fenetre in FENETRES_SOUS_UN_JOUR else cx.execute(
            f"SELECT COUNT(DISTINCT domaine) FROM lignes WHERE {where} AND premiere >= ?", a + [int(maintenant) - FENETRES[fenetre]]).fetchone()[0]
        metriques = {"domaines": dn, "requetes": req, "bloquees": bloq, "part_bloquee": round(bloq / req, 4) if req else 0.0,
                     "par_categorie": par_cat, "top_domaines": _groupes(cx, "domaine", where, a, 5),
                     "top_appareils": _groupes(cx, "appareil", where, a, 5), "nouveaux": nouveaux}
        agregats = [] if agreger == "aucun" else _groupes(cx, agreger, where, a, AGREGATS_MAX)
        lignes = [_ligne(r) for r in cx.execute(f"SELECT {COLONNES} FROM lignes WHERE {where} "
                                                 "ORDER BY derniere DESC, domaine, mac LIMIT ? OFFSET ?", a + [limite, decalage])]
    return {"cache": True, "genere": g, "total": total, "decalage": decalage, "limite": limite, "lignes": lignes, "agregats": agregats,
            "agreger": agreger, "fenetre": fenetre, "metriques": metriques}


def selection(dossier: Optional[Path] = None, limite: int = EXPORT_MAX, maintenant: int = 0, **filtres) -> tuple:
    """(lignes filtrées, `limite` au plus ; total ; horodatage du cache ou None). Sert aux routes du lot 2 et à l'export CSV."""
    where, a = filtre(maintenant=maintenant, **filtres)
    g = genere(dossier)
    with _ouvrir(dossier) as cx:
        if cx is None or g is None:
            return [], 0, None
        try:
            total = cx.execute(f"SELECT COUNT(*) FROM lignes WHERE {where}", a).fetchone()[0]
            lignes = [_ligne(r) for r in cx.execute(f"SELECT {COLONNES} FROM lignes WHERE {where} ORDER BY derniere DESC, domaine, mac LIMIT ?",
                                                     a + [max(1, min(int(limite), EXPORT_MAX))])]
        except sqlite3.Error:
            return [], 0, None
    return lignes, total, g


# ── événements récents agrégés (vue générale) ────────────────────────────────────────────────────────

GROUPES_MAX = 200
HEURES = (1, 24)


def evenements_agreges(magasin: "dnstv.Magasin", heures: int, maintenant: int, noms: Dict[str, str], detail: bool = False) -> dict:
    """Requêtes récentes (`dnstv_recents`) regroupées par appareil × domaine réel (suffixe `.home` rattaché) : occurrences, premier et
    dernier horodatage, décision dominante, nouveauté (domaine jamais vu de cet appareil avant le jour de début de fenêtre).
    Tri : groupes avec blocage, puis nouveautés, puis les plus fréquents. `detail` : lignes de chaque groupe (administrateur)."""
    if heures not in HEURES:
        raise ErreurAnalyse("heures : 1 ou 24")
    depuis = int(maintenant) - heures * 3600
    groupes: Dict[tuple, dict] = {}
    for e in magasin.recents(None, depuis, 20000):
        dom = dnstv.domaine_reel(e["domaine"])
        g = groupes.setdefault((e["client"], dom), {"client": e["client"], "appareil": noms.get(e["client"], e["client"]), "domaine": dom,
                                                    "occurrences": 0, "premier": e["ts"], "dernier": e["ts"], "_dec": collections.Counter(),
                                                    "_l": []})
        g["occurrences"] += 1
        g["premier"], g["dernier"] = min(g["premier"], e["ts"]), max(g["dernier"], e["ts"])
        g["_dec"][e["decision"]] += 1
        if detail:
            g["_l"].append({"ts": e["ts"], "domaine": e["domaine"], "decision": e["decision"]})
    deja = set()
    jour = dnstv._jour(depuis)
    paires = list(groupes)
    with contextlib.closing(magasin._cx()) as cx:
        for i in range(0, len(paires), 400):
            lot = paires[i:i + 400]
            doms = sorted({d for _, d in lot} | {d + "." + s for _, d in lot for s in dnstv.SUFFIXES_RECHERCHE})
            for c, d in cx.execute("SELECT DISTINCT client, domaine FROM dnstv_counts WHERE jour < ? AND domaine IN (%s)" % ",".join("?" * len(doms)),
                                   [jour] + doms):
                deja.add((c, dnstv.domaine_reel(d)))
    out = []
    for cle, g in groupes.items():
        dec = g.pop("_dec")
        lignes = g.pop("_l")
        g["decision"] = dec.most_common(1)[0][0]
        g["bloquees"] = dec.get("BLOCKED", 0)
        g["erreurs"] = dec.get("UPSTREAM_ERROR", 0)
        g["nouveau"] = cle not in deja
        if detail:
            g["lignes"] = sorted(lignes, key=lambda x: -x["ts"])[:100]
        out.append(g)
    out.sort(key=lambda g: (g["bloquees"] == 0, not g["nouveau"], -g["occurrences"], -g["dernier"]))
    return {"heures": heures, "groupes": out[:GROUPES_MAX], "total": len(out)}
