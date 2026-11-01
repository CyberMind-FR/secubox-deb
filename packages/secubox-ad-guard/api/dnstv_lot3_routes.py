# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes `/adblock-tv/protection/*` du lot 3 SBX TV PRIVACY (#3374).

Gardes : lecture d'une donnée par appareil `require_lecture_nominative` (administrateur réel ou porteur délégué du pilotage) ;
écriture et export `require_jwt` ; SEULE exception, la route lambda « Ça ne marche plus ? Je débloque » (`/protection/usager/*`),
en `require_personne` et bornée (pause minutée ou retour en observation ; jamais de durcissement, de liste ni d'historique).
Ce routeur est inclus dans celui de `dnstv_routes` (préfixe `/adblock-tv`).
"""
from __future__ import annotations

import collections
import copy
import csv
import io
import json
import logging
import threading
import time
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

try:
    from . import dnstv, dnstv_analyse, dnstv_appareils, dnstv_journal, dnstv_protection, dnstv_regles
    from . import dnstv_routes as _r
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_analyse, dnstv_appareils, dnstv_journal, dnstv_protection, dnstv_regles
    from api import dnstv_routes as _r

from secubox_core.auth import require_jwt, require_personne

router = APIRouter(tags=["adblock-tv-protection"])
logger = logging.getLogger("secubox.ad-guard.tv-privacy")


def est_admin_reel(p) -> bool:
    """Administrateur réel (délégué à `dnstv_routes`, que les tests surchargent)."""
    return bool(_r.est_admin_reel(p))


def _admin(lecteur) -> bool:
    return isinstance(lecteur, dict) and not lecteur.get("tableau_de_bord") and est_admin_reel(lecteur)


# ── analyseur ────────────────────────────────────────────────────────────────────────────────────────

def _pour_lecteur(e: dict) -> dict:
    """Vue d'un lecteur qui n'est pas administrateur réel (porteur délégué) : MAC tronquée, sans adresses, observation au jour."""
    d = {k: v for k, v in e.items() if k not in ("ips", "precision")}
    d["mac"] = dnstv_appareils.mac_courte(e["mac"]) if e.get("mac") else None
    for k in ("derniere_observation", "premiere_observation"):
        d[k] = dnstv._jour(e[k]) if e.get(k) else None
    return d


def _filtres(fenetre, mac, categorie, decision, source, confiance_min, confiance_max, q, domaine, racine) -> dict:
    return {"fenetre": fenetre, "macs": mac or [], "categories": categorie or [], "decisions": decision or [], "sources": source or [],
            "confiance_min": confiance_min, "confiance_max": confiance_max, "q": q, "domaine_exact": domaine, "racine_exacte": racine}


def _params(fenetre: str = "30j", mac: Optional[List[str]] = Query(None), categorie: Optional[List[str]] = Query(None),
            decision: Optional[List[str]] = Query(None), source: Optional[List[str]] = Query(None), confiance_min: int = 0,
            confiance_max: int = 100, q: Optional[str] = Query(None, max_length=64), domaine: Optional[str] = Query(None, max_length=253),
            racine: Optional[str] = Query(None, max_length=253)) -> dict:
    for liste in (mac, categorie, decision, source):
        if liste and len(liste) > 10:
            raise HTTPException(422, "10 valeurs au plus par filtre")
    return _filtres(fenetre, mac, categorie, decision, source, confiance_min, confiance_max, q, domaine, racine)


@router.get("/protection/analyse")
def analyse(f: dict = Depends(_params), agreger: str = "racine", decalage: int = 0, limite: int = 25,
            lecteur=Depends(_r.require_lecture_nominative)):
    """Analyseur côté serveur : métriques, agrégats (domaine, racine, catégorie, appareil) et une page de lignes (25 par défaut,
    200 au plus), filtres combinables. Lu dans le cache découpé du moteur AUTO ; aucun calcul lourd ni jeu complet dans la réponse."""
    try:
        res = dnstv_analyse.analyser(agreger=agreger, decalage=decalage, limite=limite, maintenant=int(time.time()), **f)
    except dnstv_analyse.ErreurAnalyse as e:
        raise HTTPException(422, str(e)) from None
    if not _admin(lecteur):
        res["lignes"] = [_pour_lecteur(x) for x in res["lignes"]]
        for g in (res["agregats"] if agreger == "appareil" else []) + res["metriques"]["top_appareils"]:
            g["cle"] = dnstv_appareils.mac_courte(g["cle"]) if g.get("cle") else None
    res["admin"] = _admin(lecteur)
    res["categories"] = list(dnstv_analyse.dnstv_taxonomie.CATEGORIES)
    res["protegees"] = sorted(dnstv_analyse.dnstv_taxonomie.PROTEGEES)
    res["decisions"], res["fenetres"], res["agregations"] = list(dnstv_analyse.DECISIONS), list(dnstv_analyse.FENETRES), list(dnstv_analyse.AGREGATS)
    res["sources"] = list(dnstv_analyse.dnstv_taxonomie.SOURCES) + [dnstv_analyse.dnstv_taxonomie.SOURCE_AUCUNE]
    return res


def _cellule(v) -> str:
    """Cellule CSV neutralisée : une valeur qui commence par = + - @ (formule de tableur) est préfixée d'une apostrophe."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/protection/analyse.csv", dependencies=[Depends(require_jwt)])
def analyse_csv(f: dict = Depends(_params)):
    """Export CSV du résultat filtré (50 000 lignes au plus) : administrateur seulement."""
    try:
        lignes, _total, _g = dnstv_analyse.selection(maintenant=int(time.time()), **f)
    except dnstv_analyse.ErreurAnalyse as e:
        raise HTTPException(422, str(e)) from None
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["domaine", "appareil", "mac", "categorie", "source", "confiance", "requetes", "bloquees", "derniere", "premiere", "regle", "protegee"])
    for x in lignes:
        w.writerow([_cellule(v) for v in (x["domaine"], x.get("nom"), x.get("mac"), x["categorie"], x["source"], x["confiance"], x["requetes"],
                                          x["bloquees"], x.get("derniere_observation"), x.get("premiere_observation"), x.get("regle"), x["protegee"])])
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="tv-privacy-analyse.csv"'})


# ── événements récents agrégés ───────────────────────────────────────────────────────────────────────

def _noms_par_ip() -> dict:
    etat, _ = dnstv.lire_etat()
    return {c["ip"]: c["nom"] for c in etat.get("clients", [])}


@router.get("/protection/evenements")
def evenements(heures: int = 1, detail: bool = False, lecteur=Depends(_r.require_lecture_nominative)):
    """Requêtes récentes AGRÉGÉES par appareil × domaine réel (1 h ou 24 h) ; `detail=1` (administrateur) ajoute les lignes."""
    if detail and not _admin(lecteur):
        raise HTTPException(403, "détail ligne à ligne : administrateur requis")
    try:
        res = dnstv_analyse.evenements_agreges(_r._magasin(), heures, int(time.time()), _noms_par_ip(), detail=detail)
    except dnstv_analyse.ErreurAnalyse as e:
        raise HTTPException(422, str(e)) from None
    if not _admin(lecteur):
        res["groupes"] = [_groupe_pour_lecteur(g) for g in res["groupes"]]
    return res


def _groupe_pour_lecteur(g: dict) -> dict:
    """Groupe d'événements pour un lecteur qui n'est pas administrateur réel (porteur délégué) : sans l'adresse du client, sans lignes ;
    l'appareil est son NOM, ou « appareil inconnu » si seul l'adresse le désigne (#3374, constat S1)."""
    d = {k: v for k, v in g.items() if k not in ("client", "lignes")}
    if d.get("appareil") == g.get("client"):
        d["appareil"] = "appareil inconnu"
    return d


def _entree_pour_lecteur(e: dict) -> dict:
    """Entrée de journal pour un lecteur qui n'est pas administrateur réel : sans motif (il peut nommer l'acteur)."""
    return {k: v for k, v in e.items() if k != "motif"}




# ── retour en un geste, pause minutée, exceptions, journal (administrateur) ─────────────────────────

class AppareilIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    appareil: Optional[str] = Field(default=None, max_length=40)       # None : tous les appareils du périmètre


class PauseIn(AppareilIn):
    minutes: int


class ExceptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    appareil: str = Field(min_length=1, max_length=40)
    domaine: str = Field(min_length=3, max_length=253)
    type: str = Field(max_length=10)
    actif: bool = True


def _mac_de(etat: dict, nom: str) -> Optional[str]:
    return next((c["mac"] for c in etat.get("clients", []) if c["nom"] == nom and c.get("mac")), None)


def _journaliser(entrees: list) -> None:
    """Le journal ne doit jamais faire échouer un geste déjà appliqué : une erreur est seulement tracée."""
    try:
        dnstv_journal.ajouter(entrees)
    except (OSError, ValueError) as e:
        logger.warning("journal des décisions non écrit : %s", type(e).__name__)


def _audit(acteur: str, origine: str, geste: str, cibles: list, minutes: Optional[int] = None, domaine: Optional[str] = None,
           type_: Optional[str] = None) -> None:
    """Décision de sécurité dans audit.log (geste, périmètre, origine, acteur) par le verbe root borné `audit-protection` ; un échec
    rend 502 et le geste est refusé : jamais de décision non tracée."""
    _r._ctl_entree("audit-protection", json.dumps({"acteur": acteur, "origine": origine, "geste": geste, "cibles": sorted(cibles)[:64],
                                                   "minutes": minutes, "domaine": domaine, "type": type_}))


def _geste(geste, action: str, origine: str, motif: str, acteur: str = "inconnu", minutes: Optional[int] = None) -> tuple:
    """Applique `geste(etat, pauses)` sous le verrou des règles : audit (audit.log) AVANT toute écriture, puis état et pauses, puis
    `apply` au contrôleur root ; en cas d'échec, état et pauses reviennent à leur version précédente. Journalise."""
    with _r._verrou():
        etat, ancien = _r._etat_et_copie()
        try:
            pauses = dnstv_protection.charger_pauses()
        except dnstv_protection.ErreurProtection as e:
            raise HTTPException(409, str(e)) from None
        anciennes = copy.deepcopy(pauses)
        try:
            touches = geste(etat, pauses)
        except dnstv_protection.ErreurProtection as e:
            raise HTTPException(404 if "inconnu" in str(e) else 422, str(e)) from None
        if not touches:
            return [], None, pauses
        _audit(acteur, origine, action, touches, minutes)
        try:
            dnstv.ecrire_etat(etat)
            dnstv_protection.ecrire_pauses(pauses)
        except (dnstv.ErreurTV, dnstv_protection.ErreurProtection) as e:
            dnstv.ecrire_etat(ancien)
            raise HTTPException(422, str(e)) from None
        try:
            application = _r._ctl("apply")
        except HTTPException:
            dnstv.ecrire_etat(ancien)
            dnstv_protection.ecrire_pauses(anciennes)
            raise
        maintenant = int(time.time())
        _journaliser([dnstv_journal.entree(maintenant, n, _mac_de(etat, n), "", "", action, origine, motif) for n in touches])
    return touches, application, pauses


def _cible(appareil: Optional[str]):
    return None if appareil is None else [appareil]


@router.post("/protection/observe")
def tout_en_observe(corps: AppareilIn, jeton=Depends(require_jwt)):
    """Retour en un geste : l'appareil (ou tous) repasse en OBSERVE, sans échéance ; sa pause éventuelle est oubliée."""
    touches, app, _ = _geste(lambda e, p: dnstv_protection.passer_en_observe(e, p, _cible(corps.appareil)), "observe", "admin", "retour en OBSERVE",
                             _r._acteur(jeton))
    return {"appareils": touches, "application": app}


@router.post("/protection/pause")
def pause(corps: PauseIn, jeton=Depends(require_jwt)):
    """Pause minutée (15, 60 ou 240 min) : les appareils protégés passent en OBSERVE, reprise automatique à l'échéance."""
    if corps.minutes not in dnstv_protection.DUREES_MIN:
        raise HTTPException(422, "durée de pause : 15 min, 1 h, 4 h ou 24 h")
    maintenant = int(time.time())
    touches, app, _ = _geste(lambda e, p: dnstv_protection.mettre_en_pause(e, p, _cible(corps.appareil), corps.minutes, maintenant, "admin"),
                             "pause", "admin", dnstv_protection.duree_lisible(corps.minutes), _r._acteur(jeton), corps.minutes)
    return {"appareils": touches, "jusqu_a": maintenant + corps.minutes * 60, "application": app}


@router.post("/protection/reprendre")
def reprendre(corps: AppareilIn, jeton=Depends(require_jwt)):
    """Reprise immédiate de la protection des appareils en pause (modes d'avant)."""
    touches, app, _ = _geste(lambda e, p: dnstv_protection.reprendre(e, p, _cible(corps.appareil), int(time.time())),
                             "reprise", "admin", "reprise manuelle", _r._acteur(jeton))
    return {"appareils": touches, "application": app}


@router.get("/protection/exceptions")
def exceptions(lecteur=Depends(_r.require_lecture_nominative)):
    """Vue unifiée des exceptions appareil × domaine (lot 3), des autorisations au puits et des suspects jugés légitimes."""
    try:
        ex = dnstv_protection.charger_exceptions()
    except dnstv_protection.ErreurProtection as e:
        raise HTTPException(409, str(e)) from None
    v = dnstv_protection.vue_exceptions(ex, _r._etat(), _r._ignores())
    if not _admin(lecteur):
        for e in v["exceptions"]:
            e["mac"] = dnstv_appareils.mac_courte(e["mac"]) if e.get("mac") else ""
    return v


@router.post("/protection/exceptions")
def exception_poser(corps: ExceptionIn, jeton=Depends(require_jwt)):
    """Pose ou retire une exception (`autoriser` : liste blanche ; `bloquer` : liste noire) pour UN appareil et UN domaine."""
    with _r._verrou():
        etat, ancien_etat = _r._etat_et_copie()
        regles, ancien_regles = _r._regles(), _r._regles()
        avant = regles.liste()
        try:
            ex = dnstv_protection.charger_exceptions()
            nouv = dnstv_protection.poser_exception(ex, etat, regles, corps.appareil, corps.domaine, corps.type, corps.actif, int(time.time()))
        except dnstv_protection.ErreurProtection as e:
            raise HTTPException(404 if "inconnu" in str(e) else 422, str(e)) from None
        except dnstv_regles.ErreurRegle as e:
            raise HTTPException(422, str(e)) from None
        _audit(_r._acteur(jeton), "admin", "exception", [corps.appareil], None, dnstv.valider_domaine(corps.domaine),
               corps.type if corps.actif else corps.type + "-retire")
        dnstv_regles.ecrire(regles)
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            dnstv_regles.ecrire(ancien_regles)
            raise HTTPException(422, str(e)) from None
        application = _r._appliquer_ou_annuler_tout(ancien_etat, ancien_regles)
        dnstv_protection.ecrire_exceptions(nouv)
        d = dnstv.valider_domaine(corps.domaine)
        _journaliser(dnstv_journal.depuis_regles(avant, regles.liste(), etat)
                     + [dnstv_journal.entree(int(time.time()), corps.appareil, _mac_de(etat, corps.appareil), d, "", "exception", "admin",
                                             f"{corps.type} {'posée' if corps.actif else 'retirée'}")])
    return {"exceptions": len(nouv), "application": application}


JOURNAL_HEURES = (1, 24, 168, 720)


@router.get("/protection/journal")
def journal(heures: int = 24, detail: bool = False, lecteur=Depends(_r.require_lecture_nominative)):
    """Journal des décisions, AGRÉGÉ par défaut (appareil × domaine × action) ; `detail=1` (administrateur) : lignes, 500 au plus."""
    if heures not in JOURNAL_HEURES:
        raise HTTPException(422, "heures : 1, 24, 168 ou 720")
    if detail and not _admin(lecteur):
        raise HTTPException(403, "détail ligne à ligne : administrateur requis")
    lignes = dnstv_journal.lire(depuis=int(time.time()) - heures * 3600)
    out = {"heures": heures, "total": len(lignes), "agregats": dnstv_journal.agreger(lignes)[:200]}
    if detail:
        out["lignes"] = lignes[:500]
    return out


@router.get("/protection/journal.csv", dependencies=[Depends(require_jwt)])
def journal_csv():
    """Export CSV du journal des décisions (les deux générations), MAC tronquée."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["horodatage", "appareil", "mac", "domaine", "categorie", "action", "origine", "motif"])
    for e in dnstv_journal.lire():
        w.writerow([_cellule(v) for v in (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(e["ts"])), e.get("appareil"), e.get("mac"),
                                          e.get("domaine"), e.get("categorie"), e["action"], e.get("origine"), e.get("motif"))])
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="tv-privacy-journal.csv"'})


@router.get("/protection/diagnostic")
def diagnostic(lecteur=Depends(_r.require_lecture_nominative)):
    """Diagnostic : erreurs DNS récentes (24 h, agrégées), exceptions et autorisations, pauses en cours, derniers retours arrière."""
    etat = _r._etat()
    ev = dnstv_analyse.evenements_agreges(_r._magasin(), 24, int(time.time()), _noms_par_ip())
    try:
        pauses = dnstv_protection.charger_pauses()
    except dnstv_protection.ErreurProtection:
        pauses = []
    retours = [e for e in dnstv_journal.lire(depuis=int(time.time()) - 7 * 86400)
               if e["action"] in ("retrait", "rejet", "observe", "pause", "reprise", "deblocage")][:30]
    admin = _admin(lecteur)
    erreurs = [g for g in ev["groupes"] if g.get("erreurs")][:50]
    if not admin:
        erreurs = [_groupe_pour_lecteur(g) for g in erreurs]
        retours = [_entree_pour_lecteur(e) for e in retours]
    return {"erreurs_dns": erreurs,
            "exceptions": exceptions(lecteur)["exceptions"],
            "pauses": [{"appareil": p["appareil"], "fin": p["fin"], "origine": p["origine"]} for p in pauses],
            "retours_arriere": retours,
            "modes": [{"nom": c["nom"], "mode": c["mode"], "mode_nom": dnstv.nom_mode(c["mode"])} for c in etat.get("clients", [])],
            "message": dnstv_protection.MESSAGE_HONNETE}


# ── route LAMBDA « Ça ne marche plus ? Je débloque » ─────────────────────────────────────────────────
# Garde `require_personne` (AGENTS.md : garde d'usager posée EXPLICITEMENT) : une personne admise (profil user ou plus). Refusés :
# le tableau de bord anonyme (aucune session), l'invité, la session plafonnée, le jeton à portée et le porteur délégué du pilotage.
# Bornée : un seul geste, une PAUSE de 24 h au plus avec reprise automatique (décision du propriétaire), jamais de durcissement, de liste de
# domaines ni d'historique ; la liste des TV ne donne que leur NOM. Débit limité.

DEBIT_FENETRE_S = 600
DEBIT_PAR_PORTEUR = 5
DEBIT_BOX = 20
_DEBIT: dict = {}
_DEBIT_VERROU = threading.Lock()


def _debit(sub: str, maintenant: float, compter: bool = True) -> None:
    """5 gestes par porteur et 20 pour la box sur 10 minutes ; 429 au-delà. `compter=False` vérifie seulement : un geste refusé
    (404, 409, 422) n'est pas décompté, seul un geste appliqué l'est."""
    with _DEBIT_VERROU:
        for cle, plafond in ((sub, DEBIT_PAR_PORTEUR), ("*", DEBIT_BOX)):
            q = _DEBIT.setdefault(cle, collections.deque())
            while q and maintenant - q[0] > DEBIT_FENETRE_S:
                q.popleft()
            if len(q) >= plafond:
                raise HTTPException(429, "trop de demandes : réessayer dans quelques minutes")
        if not compter:
            return
        for cle in (sub, "*"):
            _DEBIT[cle].append(maintenant)
        if len(_DEBIT) > 1000:                                          # mémoire bornée
            for k in [k for k, q in _DEBIT.items() if k != "*" and not q]:
                del _DEBIT[k]


class UsagerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tv: str = Field(min_length=1, max_length=40)                       # identifiant d'une TV (liste minimale) ou « toutes »
    geste: Literal["pause"]                                           # S3 (décision du propriétaire) : l'usager ne fait qu'une PAUSE
    minutes: int                                                      # 15, 60, 240 ou 1440 (24 h au plus), reprise automatique


def _tv_du_perimetre(etat: dict) -> dict:
    """slug -> nom des appareils du périmètre (mode ≠ off)."""
    return {dnstv._slug(c["nom"]): c["nom"] for c in etat.get("clients", []) if c["mode"] != "off"}


@router.get("/protection/usager/tv")
def usager_tv(personne=Depends(require_personne)):
    """Liste MINIMALE des TV pour choisir : identifiant, nom, protégée ou non, fin de pause. Ni MAC, ni adresse, ni domaine."""
    etat, erreur = dnstv.lire_etat()
    if erreur:
        raise HTTPException(409, "état illisible")
    try:
        pauses = {p["appareil"]: p["fin"] for p in dnstv_protection.charger_pauses()}
    except dnstv_protection.ErreurProtection:
        pauses = {}
    tv = []
    for slug, nom in sorted(_tv_du_perimetre(etat).items(), key=lambda x: x[1]):
        modes = [c["mode"] for c in etat["clients"] if c["nom"] == nom]
        tv.append({"id": slug, "nom": nom, "protege": any(m in dnstv_protection.MODES_PROTEGES for m in modes), "pause_jusqu_a": pauses.get(nom)})
    return {"tv": tv, "durees": list(dnstv_protection.DUREES_MIN), "message": dnstv_protection.MESSAGE_HONNETE}


@router.post("/protection/usager/debloquer")
def usager_debloquer(corps: UsagerIn, personne=Depends(require_personne)):
    """« Ça ne marche plus ? Je débloque » : PAUSE minutée (24 h au plus, reprise automatique) d'UNE TV ou de toutes. Le retour en
    observation sans échéance reste réservé à l'administrateur. Audité (audit-protection), journalisé (origine usager), appliqué."""
    if corps.minutes not in dnstv_protection.DUREES_MIN:
        raise HTTPException(422, "durée de pause : 15 min, 1 h, 4 h ou 24 h")
    sub = str(personne.get("sub") or "") if isinstance(personne, dict) else ""
    if not sub:
        raise HTTPException(403, "session sans identité : geste refusé")
    etat, erreur = dnstv.lire_etat()
    if erreur:
        raise HTTPException(409, "état illisible")
    perimetre = _tv_du_perimetre(etat)
    if corps.tv == "toutes":
        noms, libelle = sorted(perimetre.values()), "toutes les TV"
    elif corps.tv in perimetre:
        noms, libelle = [perimetre[corps.tv]], perimetre[corps.tv]
    else:
        raise HTTPException(404, "TV inconnue")
    _debit(sub, time.monotonic(), compter=False)
    acteur = _r._acteur(personne)
    maintenant = int(time.time())
    _geste(lambda e, p: dnstv_protection.mettre_en_pause(e, p, noms, corps.minutes, maintenant, "usager"), "pause", "usager",
           f"{dnstv_protection.duree_lisible(corps.minutes)} par {acteur}", acteur, corps.minutes)
    _debit(sub, time.monotonic())                                     # décompté seulement une fois le geste appliqué
    message = f"protection en pause pour {libelle} pendant {dnstv_protection.duree_lisible(corps.minutes)}"
    jusqu_a = maintenant + corps.minutes * 60
    logger.info("déblocage usager (%s) : pause %s min %s", acteur, corps.minutes, corps.tv)
    return {"message": message, "jusqu_a": jusqu_a, "rappel": dnstv_protection.MESSAGE_HONNETE}
