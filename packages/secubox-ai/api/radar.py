# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Radar et chaîne d'attaque de la console (#3811), portés du POC gk0 (relais.py, 2026-11-13 → 11-18). Lecture seule.

- Tendances par pays (`pays_tendances`) : aujourd'hui (relevé de `menaces.py`), hier et J-7 à la même heure, série
  7 jours et journée heure par heure, lues sur les échantillons de 15 min que la VEILLE écrit dans veille.db
  (`pays_echantillons`, migration 0004). Rien n'est extrapolé : sans échantillon à ±15 min, null.
- Séries 1 h / 3 h (`series_menaces`) : écarts entre instantanés réels du relevé (2 min, gardés 3 h), par tranche de
  10 min ; jamais d'interpolation.
- Chaîne d'attaque : dossiers d'attaquant de la veille (#3795), étapes repérage → essais → exploitation → persistance
  avec leurs règles, le nombre de preuves, leurs heures et la première preuve de chaque étape (événement réel).

Stats lourdes (PERF-CACHE) : tendances et chaîne sont calculées par une tâche de fond (60 s, fil séparé, veille.db
ouverte en LECTURE SEULE), jamais par requête ; les routes rendent le dernier calcul. Aucun chiffre ne vient du modèle.
"""
import asyncio
import datetime as dt
import json
import logging
import re
import sqlite3
import time
from collections import Counter
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from secubox_core.auth import require_jwt

from api import menaces, reglages
from veille import decisions, riposte
from veille.correlation import _COLS, _evt

log = logging.getLogger("secubox.ai.radar")

PAS_S, TOL_S = 900, 900
PERIODE_S = 60
FENETRE_CHAINE_S = 86400
LIMITE_CHAINE = 12
LIMITE_CAMPAGNES = 5
LIGNES_MAX = 3000
ORDRE = ("reperage", "essais", "exploitation", "persistance")
ECHELLE = ("info", "low", "medium", "high", "critical")
SERIES_CATEGORIES = ("sasl_failed", "scanners", "robots", "unrouted")
SERIES_TRANCHE = 600

CACHE: dict = {"pays": None, "chaine": None, "quand": 0.0}
_BOUCLE: list = []


def _reinitialiser() -> None:
    CACHE.update(pays=None, chaine=None, quand=0.0)


def _nombre(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def chemin_veille():
    return reglages.etat_dir() / "veille.db"


def _ouvrir_lecture():
    """veille.db en lecture seule (la veille est le seul écrivain) ; absente ou illisible : None."""
    chemin = chemin_veille()
    if not chemin.is_file():
        return None
    try:
        db = sqlite3.connect(chemin.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        db.execute("PRAGMA busy_timeout = 5000")
        db.execute("PRAGMA query_only = ON")
        return db
    except sqlite3.Error as e:
        log.warning("radar : veille.db illisible (%s)", type(e).__name__)
        return None


# ---- Tendances par pays (POC `pays_tendances`) ----
def _json(x):
    try:
        v = json.loads(x) if isinstance(x, str) else None
    except ValueError:
        return None
    return {str(k): n for k, n in v.items() if _nombre(n)} if isinstance(v, dict) else None


def lire_echantillons(db, maintenant: float) -> list:
    try:
        lignes = db.execute("SELECT quand, alertes_json, tot_alertes, bans_json, tot_bans FROM pays_echantillons "
                            "WHERE quand >= ? AND quand <= ? ORDER BY quand", (int(maintenant) - 8 * 86400,
                                                                              int(maintenant) + TOL_S)).fetchall()
    except sqlite3.Error as e:          # migration 0004 pas encore appliquée par la veille
        log.warning("radar : échantillons par pays illisibles (%s)", type(e).__name__)
        return []
    return [{"quand": q, "alertes": _json(a), "tot_alertes": ta if _nombre(ta) else None,
             "bans": _json(b), "tot_bans": tb if _nombre(tb) else None} for q, a, ta, b, tb in lignes]


def _proche(echs: list, t: float, cle: str):
    """Échantillon le plus proche de t (±15 min) portant la clé `cle`, sinon None."""
    best = None
    for x in echs:
        if x.get(cle) is None or abs(x["quand"] - t) > TOL_S:
            continue
        if best is None or abs(x["quand"] - t) < abs(best["quand"] - t):
            best = x
    return best


def _decale(maintenant: float, jours: int) -> float:
    """Même heure LOCALE, `jours` jours plus tôt (sûr aux changements d'heure)."""
    d = dt.datetime.fromtimestamp(maintenant).astimezone()
    return (d.replace(tzinfo=None) - dt.timedelta(days=jours)).astimezone().timestamp()


def pays_tendances(echs: list, maintenant: float, alertes_auj: dict, bans_auj: dict, tot_alertes, tot_bans) -> dict:
    out = {"echantillons": len(echs), "depuis": echs[0]["quand"] if echs else None, "colonnes": {}}
    for col, cle, tcle, auj, tot in (("alertes", "alertes", "tot_alertes", alertes_auj, tot_alertes),
                                     ("bans", "bans", "tot_bans", bans_auj, tot_bans)):
        refs = {j: _proche(echs, _decale(maintenant, j), cle) for j in range(1, 8)}
        pays = {}
        for cc, v in auj.items():
            # Pays absent du top 5 d'un échantillon : null + drapeau « hors top 5 » (jamais 0 inventé).
            serie = [(refs[j][cle].get(cc) if refs[j] else None) for j in range(6, 0, -1)] + [v]
            hors = [bool(refs[j]) and cc not in refs[j][cle] for j in range(6, 0, -1)] + [False]
            pays[cc] = {"auj": v, "hier": serie[5], "hier_hors": hors[5],
                        "j7": refs[7][cle].get(cc) if refs[7] else None, "j7_hors": bool(refs[7]) and cc not in refs[7][cle],
                        "serie7": serie, "serie7_hors": hors}
        jours = {}
        for nom, decal in (("auj", 0), ("hier", 1), ("j7", 7)):
            base = dt.datetime.fromtimestamp(_decale(maintenant, decal)).replace(hour=0, minute=0, second=0, microsecond=0)
            pts = []
            for h in range(24):
                t = base.replace(hour=h).astimezone().timestamp()
                if t > maintenant + TOL_S:
                    pts.append(None)
                    continue
                x = _proche(echs, t, tcle)
                pts.append(x[tcle] if x else None)
            jours[nom] = pts
        n = dt.datetime.fromtimestamp(maintenant)
        jours["maintenant"] = {"h": round(n.hour + n.minute / 60, 3), "valeur": tot}
        out["colonnes"][col] = {"pays": pays, "jour": jours, "hier_dispo": refs[1] is not None,
                                "j7_dispo": refs[7] is not None}
    return out


def _aujourdhui(r: dict | None) -> tuple:
    """(alertes par pays, bans par pays, total alertes, total bans) du relevé courant ; source en erreur : vide/None."""
    if not r:
        return {}, {}, None, None
    erreurs = r.get("erreurs") or []
    stats_ok, bans_ok = "/waf/stats" not in erreurs, "/waf/bans" not in erreurs
    jour = (r.get("chiffres") or {}).get("menaces_jour")
    al = dict(r.get("_pays_alertes") or {}) if stats_ok else {}
    bp = {k: v for k, v in (r.get("bans_par_pays") or {}).items() if _nombre(v)} if bans_ok else {}
    return al, bp, jour if stats_ok and _nombre(jour) else None, (r.get("chiffres") or {}).get("bans_actifs") if bans_ok else None


# ---- Chaîne d'attaque (dossiers de la veille, #3795) ----
def _rang(g) -> int:
    return ECHELLE.index(g) if g in ECHELLE else 0


def _enchainees(etapes: list) -> int:
    """Étapes successives (même règle que veille.dossiers.Dossier.enchainees)."""
    n, dernier = 0, ""
    for e in etapes:
        if str(e.get("debut") or "") >= dernier:
            n, dernier = n + 1, str(e.get("debut") or "")
    return n


def _etapes(brut) -> list:
    try:
        v = json.loads(brut or "[]")
    except ValueError:
        return []
    return [e for e in v if isinstance(e, dict) and e.get("etape") in ORDRE] if isinstance(v, list) else []


def _outils(brut) -> list:
    try:
        v = json.loads(brut or "[]")
    except ValueError:
        return []
    out = []
    for a in v if isinstance(v, list) else []:
        if isinstance(a, dict) and isinstance(a.get("outil"), str):
            out.append({"outil": a["outil"][:64], "confiance": a.get("confiance") if isinstance(a.get("confiance"), str) else None,
                        "traits": len(a.get("traits_concordants") or []) if a["outil"] != "inconnu"
                        else len(a.get("traits_observes") or [])})
    return out


def _preuve(db, eid):
    x = db.execute("SELECT horodatage, source, famille, sous_famille, service, vhost FROM evenements WHERE id = ?",
                   (eid,)).fetchone()
    if not x:
        return None
    return {"horodatage": x[0], "source": x[1], "famille": x[2], "sous_famille": x[3], "service": x[4], "vhost": x[5]}


def _resume_etapes(db, etapes: list) -> list:
    out = []
    for e in etapes:
        preuves = [p for p in e.get("preuves") or [] if isinstance(p, str)]
        out.append({"etape": e["etape"], "regles": [str(r) for r in e.get("regles") or []][:6], "preuves": len(preuves),
                    "debut": e.get("debut"), "fin": e.get("fin"), "exemple": _preuve(db, preuves[0]) if preuves else None})
    return out


def chaine(db, maintenant: float, fenetre_s: int = FENETRE_CHAINE_S, limite: int = LIMITE_CHAINE) -> dict:
    depuis = dt.datetime.fromtimestamp(maintenant - fenetre_s, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        lignes = db.execute("SELECT id, cle, type, gravite, etapes_json, outils_json, premiere_vue, derniere_vue FROM dossiers "
                            "WHERE derniere_vue >= ? ORDER BY derniere_vue DESC LIMIT ?", (depuis, LIGNES_MAX)).fetchall()
    except sqlite3.Error as e:
        log.warning("radar : dossiers illisibles (%s)", type(e).__name__)
        return {"disponible": False, "fenetre_s": fenetre_s, "raison": "dossiers de la veille illisibles"}
    acteurs, campagnes, entonnoir = [], [], Counter()
    for did, cle, type_, grav, ej, oj, prem, der in lignes:
        etapes = _etapes(ej)
        if type_ == "campagne":
            campagnes.append((did, cle, grav, etapes, prem, der))
            continue
        for e in etapes:
            entonnoir[e["etape"]] += 1
        acteurs.append((did, cle, grav, etapes, oj, prem, der))
    acteurs.sort(key=lambda a: (_enchainees(a[3]), len(a[3]), _rang(a[2]), a[6]), reverse=True)
    liste = []
    for did, cle, grav, etapes, oj, prem, der in acteurs[:limite]:
        adresses = [ip for (ip,) in db.execute(
            "SELECT DISTINCT e.ip_src FROM dossier_evenements d JOIN evenements e ON e.id = d.evenement_id "
            "WHERE d.dossier_id = ? AND e.ip_src IS NOT NULL ORDER BY e.ip_src LIMIT 6", (did,))]
        liste.append({"cle": cle, "gravite": grav, "premiere_vue": prem, "derniere_vue": der, "adresses": adresses,
                      "enchainees": _enchainees(etapes), "etapes": _resume_etapes(db, etapes), "outils": _outils(oj)})
    camp = []
    for did, cle, grav, etapes, prem, der in campagnes:
        membres = db.execute("SELECT COUNT(*), MIN(regle) FROM dossier_membres WHERE campagne_id = ?", (did,)).fetchone()
        camp.append({"cle": cle, "gravite": grav, "membres": membres[0], "regle": membres[1], "premiere_vue": prem,
                     "derniere_vue": der, "etapes": [e["etape"] for e in etapes]})
    camp.sort(key=lambda c: (c["membres"], c["derniere_vue"]), reverse=True)
    return {"disponible": True, "fenetre_s": fenetre_s, "acteurs": len(acteurs), "campagnes_total": len(campagnes),
            "entonnoir": {e: entonnoir.get(e, 0) for e in ORDRE},
            "enchainees_2": sum(1 for a in acteurs if _enchainees(a[3]) >= 2),
            "dossiers": liste, "campagnes": camp[:LIMITE_CAMPAGNES], "tronque": len(lignes) >= LIGNES_MAX}


# ---- Calcul de fond ----
def calculer(r: dict | None, maintenant: float) -> tuple:
    """(tendances, chaîne) depuis veille.db en lecture seule. Exécuté HORS de la boucle (asyncio.to_thread)."""
    al, bp, ta, tb = _aujourdhui(r)
    db = _ouvrir_lecture()
    if db is None:
        return (pays_tendances([], maintenant, al, bp, ta, tb),
                {"disponible": False, "fenetre_s": FENETRE_CHAINE_S, "raison": "veille.db absente (veille arrêtée ?)"})
    try:
        return pays_tendances(lire_echantillons(db, maintenant), maintenant, al, bp, ta, tb), chaine(db, maintenant)
    finally:
        db.close()


async def rafraichir() -> None:
    r = menaces._cache.get("releve")
    maintenant = time.time()
    p, c = await asyncio.to_thread(calculer, r, maintenant)
    CACHE.update(pays=p, chaine=c, quand=maintenant)


async def _boucle() -> None:
    while True:
        try:
            await rafraichir()
        except (sqlite3.Error, OSError, ValueError, KeyError, TypeError) as e:
            log.warning("radar : calcul de fond en échec (%s)", type(e).__name__)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - la boucle ne doit jamais mourir en silence (cache figé)
            log.exception("radar : erreur inattendue du calcul de fond")
        await asyncio.sleep(PERIODE_S)


def demarrer() -> None:
    if not _BOUCLE:
        _BOUCLE.append(asyncio.create_task(_boucle()))


async def arreter() -> None:
    boucles = list(_BOUCLE)
    _BOUCLE.clear()
    for b in boucles:
        b.cancel()
    await asyncio.gather(*boucles, return_exceptions=True)


# ---- Séries 1 h / 3 h (POC `series_menaces`) ----
def instantane_complet(x) -> bool:
    """Un instantané n'entre dans les séries que s'il est entier : jamais de valeur devinée."""
    try:
        return (_nombre(x["quand"]) and isinstance(x["menaces_jour"], int) and isinstance(x["bans"], int)
                and isinstance(x["categories"], dict) and bool(x["categories"]))
    except (KeyError, TypeError):
        return False


def _valeur_categorie(categories: dict, nom: str):
    """gk2 préfixe certaines catégories (auth_smtp:sasl_failed) : on retient le suffixe. None si absente."""
    v = [n for k, n in categories.items() if (k == nom or k.endswith(":" + nom)) and _nombre(n)]
    return sum(v) if v else None


def series_menaces(instantanes, maintenant: float, fenetre_s: int) -> dict:
    """Écart entre deux instantanés complets consécutifs, rangé dans la tranche du plus récent ; instantané incomplet
    ou écart négatif (remise à zéro) ignorés, rien d'interpolé : une tranche sans écart vaut null."""
    debut = maintenant - fenetre_s
    bons = sorted((x for x in instantanes if instantane_complet(x) and x["quand"] <= maintenant), key=lambda x: x["quand"])
    t0, t1 = int(debut // SERIES_TRANCHE), int(maintenant // SERIES_TRANCHE)
    cases = {t: {c: None for c in SERIES_CATEGORIES} for t in range(t0, t1 + 1)}
    for a, b in zip(bons, bons[1:]):
        t = int(b["quand"] // SERIES_TRANCHE)
        if b["quand"] < debut or t not in cases or b["menaces_jour"] < a["menaces_jour"]:
            continue
        for c in SERIES_CATEGORIES:
            d = (_valeur_categorie(b["categories"], c) or 0) - (_valeur_categorie(a["categories"], c) or 0)
            if d < 0:
                continue
            cases[t][c] = (cases[t][c] or 0) + d
    presentes = [c for c in SERIES_CATEGORIES
                 if any(_valeur_categorie(x["categories"], c) is not None for x in bons if x["quand"] >= debut)]
    return {"fenetre": "1h" if fenetre_s <= 3600 else "3h", "tranche_s": SERIES_TRANCHE,
            "tranches": [t * SERIES_TRANCHE for t in sorted(cases)],
            "categories": {c: [cases[t][c] for t in sorted(cases)] for c in presentes},
            "bans": [{"quand": x["quand"], "bans": x["bans"]} for x in bons if x["quand"] >= debut]}


# ---- Routes (lecture seule, administration : même garde que /menaces/*) ----
routeur = APIRouter(prefix="", dependencies=[Depends(require_jwt)])


def _attente(nom: str) -> dict:
    return {"pret": False, "raison": "premier calcul de fond en cours", "calcule": None, nom: None}


@routeur.get("/menaces/pays")
async def menaces_pays():
    if CACHE["pays"] is None:
        return _attente("pays_tendances")
    return {"pret": True, "calcule": CACHE["quand"], "pays_tendances": CACHE["pays"]}


@routeur.get("/menaces/chaine")
async def menaces_chaine():
    if CACHE["chaine"] is None:
        return _attente("chaine")
    return {"pret": True, "calcule": CACHE["quand"], "chaine": CACHE["chaine"]}


@routeur.get("/menaces/series")
async def menaces_series(fenetre: str = "3h"):
    if fenetre not in ("1h", "3h"):
        raise HTTPException(400, "fenetre : 1h ou 3h")
    r = menaces._cache.get("releve") or {}
    s = series_menaces(list(menaces.INSTANTANES), time.time(), 3600 if fenetre == "1h" else 3 * 3600)
    c, ev, p = r.get("chiffres") or {}, r.get("evolution_1h") or {}, r.get("posture") or {}
    s["tuiles"] = {"alertes_jour": c.get("menaces_jour"), "bans_actifs": c.get("bans_actifs"), "campagnes": c.get("campagnes"),
                   "attaquants": c.get("attaquants_campagnes"), "posture_score": p.get("score"), "posture_nom": p.get("name"),
                   "evolution": ev if ev.get("disponible") else {"disponible": False}}
    s["blocs"] = (r.get("blocs") or [])[:6]
    s["quand"] = r.get("quand")
    return s


# ---- Dossier d'attaquant (#3724, onglet Dossier) : lecture seule de veille.db, rien du modèle ne fait un chiffre ----
NIVEAUX = ("observer", "contenir", "usager")
LIMITE_CHRONO = 300
LIMITE_ADRESSES = 50
LIMITE_GESTES = 100
TEXTE_MAX = 200
_RE_CURSEUR_D = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\|([A-Za-z0-9-]{1,64})$")
_COLONNES_D = ("id", "cle", "type", "gravite", "niveau", "niveau_depuis", "premiere_vue", "derniere_vue")
_COLONNES_ACTION_D = ("id", "etat", "code_http", "motif", "id_gk2", "fin_gk2", "envoyee_le", "repondue_le", "effet",
                      "constatee_le")


def _veille_indisponible():
    return HTTPException(503, detail={"motif": "veille_indisponible"})


def _lire_veille(fonction):
    """`fonction(db)` sur veille.db en LECTURE SEULE, hors de la boucle ; 503 si la base manque ou n'est pas migrée."""
    def faire():
        db = _ouvrir_lecture()
        if db is None:
            raise _veille_indisponible()
        try:
            return fonction(db)
        except sqlite3.OperationalError:
            raise _veille_indisponible() from None
        finally:
            db.close()
    return asyncio.to_thread(faire)


def _texte(v, n=TEXTE_MAX):
    return v[:n] if isinstance(v, str) else None


def _charger(brut, defaut):
    try:
        v = json.loads(brut) if isinstance(brut, str) else defaut
    except ValueError:
        return defaut
    return v if isinstance(v, type(defaut)) else defaut


@routeur.get("/dossiers")
async def dossiers_liste(curseur: Optional[str] = None, limite: int = Query(100, ge=1, le=500),
                         niveau: Optional[str] = None):
    """Dossiers d'attaquant, du plus récemment vu au plus ancien ; curseur opaque `derniere_vue|id`."""
    if niveau is not None and niveau not in NIVEAUX:
        raise HTTPException(422, detail={"motif": "niveau"})
    c = None
    if curseur is not None:
        m = _RE_CURSEUR_D.fullmatch(curseur)
        if not m:
            raise HTTPException(422, detail={"motif": "curseur"})
        c = (m.group(1), m.group(2))

    def lire(db):
        sql, args = f"SELECT {', '.join(_COLONNES_D)} FROM dossiers WHERE 1 = 1", []
        if niveau:
            sql += " AND niveau = ?"
            args.append(niveau)
        if c:
            sql += " AND (derniere_vue < ? OR (derniere_vue = ? AND id < ?))"
            args += [c[0], c[0], c[1]]
        sql += " ORDER BY derniere_vue DESC, id DESC LIMIT ?"
        lignes = [dict(zip(_COLONNES_D, r)) for r in db.execute(sql, (*args, limite + 1)).fetchall()]
        suite = None
        if len(lignes) > limite:
            lignes = lignes[:limite]
            suite = f"{lignes[-1]['derniere_vue']}|{lignes[-1]['id']}"
        return {"dossiers": lignes, "curseur": suite}
    return await _lire_veille(lire)


def _chronologie(db, did, etapes):
    etape_de = {}
    for e in etapes:
        for i in e.get("preuves") or []:
            if isinstance(i, str):
                etape_de.setdefault(i, e["etape"])
    total = db.execute("SELECT COUNT(*) FROM dossier_evenements WHERE dossier_id = ?", (did,)).fetchone()[0]
    cols = ", ".join("e." + x.strip() for x in _COLS.split(","))
    lignes = db.execute(f"SELECT {cols}, e.message FROM dossier_evenements d JOIN evenements e ON e.id = d.evenement_id "
                        "WHERE d.dossier_id = ? ORDER BY e.horodatage DESC, e.id DESC LIMIT ?",
                        (did, LIMITE_CHRONO)).fetchall()
    out = []
    for x in reversed(lignes):
        e = _evt(x[:11])
        out.append({"id": e.id, "horodatage": e.horodatage, "couche": riposte.couche(e), "source": e.source,
                    "famille": e.famille, "sous_famille": e.sous_famille, "service": e.service, "vhost": e.vhost,
                    "gravite": e.gravite, "message": _texte(x[11]), "etape": etape_de.get(e.id)})
    return out, total


def _outils_detail(brut):
    out = []
    for a in _charger(brut, [])[:8]:
        if not isinstance(a, dict) or not isinstance(a.get("outil"), str):
            continue
        traits = a.get("traits_concordants") if a["outil"] != "inconnu" else a.get("traits_observes")
        vus = []
        for t in (traits if isinstance(traits, list) else [])[:12]:
            if isinstance(t, dict):
                vus.append({k: _texte(t.get(k), 64) for k in ("type", "couche", "source", "valeur", "groupe")
                            if isinstance(t.get(k), str)})
            elif isinstance(t, str):
                vus.append({"type": _texte(t, 64)})
        out.append({"outil": a["outil"][:64], "confiance": _texte(a.get("confiance"), 32),
                    "version": _texte(a.get("version"), 32), "traits": vus})
    return out


def _historique_niveau(db, did):
    out = []
    for h, brut in db.execute("SELECT horodatage, details_json FROM audit_chaine WHERE operation = 'riposte_niveau' "
                              "AND objet = ? ORDER BY id DESC LIMIT 20", (did,)).fetchall():
        d = _charger(brut, {})
        out.append({"horodatage": h, "de": d.get("de"), "vers": d.get("vers"), "cible": d.get("cible")})
    return list(reversed(out))


def _gestes(db, did, maintenant):
    props = db.execute("SELECT id, geste, cible, duree_s, mode, etat, reference, cree_le, maj_le, motif FROM propositions "
                       "WHERE dossier_id = ? ORDER BY cree_le DESC, id DESC LIMIT ?", (did, LIMITE_GESTES)).fetchall()
    out = []
    for pid, geste, cible, duree, mode, etat, ref, cree, maj, motif in reversed(props):
        a = db.execute(f"SELECT {', '.join(_COLONNES_ACTION_D)} FROM actions WHERE proposition_id = ?",
                       (pid,)).fetchone()
        action = dict(zip(_COLONNES_ACTION_D, a)) if a else None
        defaire = {"possible": False, "action_id": None, "raison": None}
        cible_aid = None
        if geste == "prolonger" and ref:
            r = db.execute("SELECT id FROM actions WHERE proposition_id = ?", (ref,)).fetchone()
            cible_aid = r[0] if r else None
        elif action:
            cible_aid = action["id"]
        if geste == "unban":
            defaire["raison"] = "levee"
        elif cible_aid is None:
            defaire["raison"] = "non_envoyee"
        else:
            _, _, raison = decisions.cible_levee(db, cible_aid, maintenant)
            defaire = {"possible": raison is None, "action_id": cible_aid if raison is None else None,
                       "raison": raison}
        out.append({"proposition": {"id": pid, "geste": geste, "cible": cible, "duree_s": duree, "mode": mode,
                                    "etat": etat, "reference": ref, "cree_le": cree, "maj_le": maj,
                                    "motif": _texte(motif)},
                    "action": action, "defaire": defaire})
    return out


def _analyse(db, did):
    r = db.execute("SELECT id, etat, version_prompt, moteur, resume, lecture, preuves_json, manques_json, motif, "
                   "cree_le, duree_ms FROM analyses WHERE dossier_id = ? ORDER BY cree_le DESC, rowid DESC LIMIT 1",
                   (did,)).fetchone()
    if r is None:
        return None
    aid, etat, vp, moteur, resume, lecture, preuves, manques, motif, cree, duree = r
    return {"id": aid, "etat": etat, "version_prompt": _texte(vp, 64), "moteur": _texte(moteur, 64),
            "resume": _texte(resume, 4000), "lecture": _texte(lecture, 4000) if etat == "valide" else None,
            "preuves": len(_charger(preuves, [])) if etat == "valide" else None,
            "manques": [_texte(m) for m in _charger(manques, []) if isinstance(m, str)][:12],
            "motif": _texte(motif), "cree_le": cree, "duree_ms": duree if _nombre(duree) else None}


def detail_dossier(db, did, maintenant=None):
    maintenant = maintenant or dt.datetime.now(dt.timezone.utc)
    r = db.execute(f"SELECT {', '.join(_COLONNES_D)}, etapes_json, outils_json, signaux_json FROM dossiers "
                   "WHERE id = ?", (did,)).fetchone()
    if r is None:
        raise HTTPException(404, detail={"motif": "inconnu"})
    dossier = dict(zip(_COLONNES_D, r[:8]))
    brutes = _charger(r[8], [])
    etapes = [e for e in brutes if isinstance(e, dict) and e.get("etape") in ORDRE]
    adresses = [ip for (ip,) in db.execute(
        "SELECT DISTINCT e.ip_src FROM dossier_evenements d JOIN evenements e ON e.id = d.evenement_id "
        "WHERE d.dossier_id = ? AND e.ip_src IS NOT NULL ORDER BY e.ip_src LIMIT ?", (did, LIMITE_ADRESSES + 1))]
    blocs = [b for (b,) in db.execute(
        "SELECT DISTINCT e.bloc24 FROM dossier_evenements d JOIN evenements e ON e.id = d.evenement_id "
        "WHERE d.dossier_id = ? AND e.bloc24 IS NOT NULL ORDER BY e.bloc24 LIMIT 6", (did,))]
    total = db.execute("SELECT COUNT(DISTINCT e.ip_src) FROM dossier_evenements d JOIN evenements e "
                       "ON e.id = d.evenement_id WHERE d.dossier_id = ? AND e.ip_src IS NOT NULL", (did,)).fetchone()[0]
    dossier.update(adresses=adresses[:LIMITE_ADRESSES], adresses_total=total, blocs=blocs)
    chrono, n_chrono = _chronologie(db, did, etapes)
    par = {e["etape"]: e for e in etapes}
    vue_etapes = []
    for nom in ORDRE:
        e = par.get(nom)
        vue_etapes.append({"etape": nom, "atteinte": e is not None, "debut": e.get("debut") if e else None,
                           "fin": e.get("fin") if e else None,
                           "preuves": len([p for p in e.get("preuves") or [] if isinstance(p, str)]) if e else None,
                           "regles": [str(x)[:64] for x in e.get("regles") or []][:6] if e else []})
    sig = _charger(r[10], {})
    seuils = sig.pop("seuils", None)
    sig.pop("plancher", None)
    try:
        en_attente = bool(db.execute("SELECT 1 FROM redescentes WHERE dossier_id = ? AND appliquee_le IS NULL",
                                     (did,)).fetchone())
    except sqlite3.OperationalError:           # migration 0009 pas encore appliquée par la veille
        en_attente = False
    en_file = bool(db.execute("SELECT 1 FROM travaux WHERE genre = 'analyser' AND objet_id = ? AND etat IN "
                              "('attente', 'en_cours')", (did,)).fetchone())
    return {"dossier": dossier, "chronologie": chrono, "chronologie_total": n_chrono,
            "chronologie_tronquee": n_chrono > len(chrono), "etapes": vue_etapes, "outils": _outils_detail(r[9]),
            "niveau": {"niveau": dossier["niveau"], "depuis": dossier["niveau_depuis"], "signaux": sig,
                       "seuils": seuils if isinstance(seuils, dict) else None,
                       "historique": _historique_niveau(db, did), "redescente_en_attente": en_attente},
            "analyse": _analyse(db, did), "analyse_en_file": en_file, "gestes": _gestes(db, did, maintenant)}


@routeur.get("/dossiers/{did}")
async def dossier_detail(did: str):
    """Vue complète d'un dossier : chronologie multicouche (preuves réelles, couche et étape calculées par le code),
    étapes, outils et traits, niveau avec ses signaux et son historique, dernière analyse et son état, gestes avec
    la réponse de gk2 et l'effet mesuré (null : à mesurer, jamais inventé)."""
    return await _lire_veille(lambda db: detail_dossier(db, did))
