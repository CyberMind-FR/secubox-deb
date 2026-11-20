# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Façade SADE en lecture seule (mode OBSERVE) : /defense/* au-dessus du substrat actord, WAF, threatmesh (#3839).

Aucune écriture, aucune action. Chaque réponse porte `sources` : l'état de lecture de chaque source, pour qu'une
source muette se voie au lieu de se confondre avec « zéro menace » (les compteurs valent alors `None`, jamais 0).

Confidentialité (#2201/#2274) : une adresse d'acteur ne sort QUE pour un administrateur réel (`require_jwt`).
Tout autre lecteur reçoit la vue réduite d'actord et des cibles masquées ; les adresses ne sont même pas copiées
dans sa réponse. Les identifiants de l'appelant (Authorization, Cookie) sont retransmis tels quels au WAF et à
threatmesh : la façade ne forge ni ne conserve aucun jeton.

Contrat de `sources.<x>.ok` : True ou False quand la route a consulté la source, `None` quand elle ne l'a pas
consultée (seule `/status` lit les trois). Un front ne doit pas traiter `None` comme une panne : c'est « non lu ».

Compteurs : `menaces_suivies` = acteurs connus d'actord (aucune fenêtre de 24 h n'existe dans /actors, qui ne porte que
« HH:MM »), compté avant toute troncature ; `evenements_24h` = somme de `activite_24h` de /overview.
"""
import asyncio
import hashlib
import re
import sqlite3
import threading
from collections import OrderedDict
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from secubox_core.auth import require_jwt, require_lecture

from . import defense_etat, echelle, substrat

router = APIRouter(tags=["defense"])

TTL_S = 15.0          # durée du cache par route
TAMPON_S = 120.0      # un relevé complet de moins de 120 s n'est pas écrasé par un relevé dégradé (#3011)
MENACES_MAX = 200
CACHE_MAX = 256       # entrées au plus : la clé contient un condensat des identifiants de l'appelant

_CACHE: "OrderedDict[Any, Dict[str, Any]]" = OrderedDict()
_ID_ACTEUR = re.compile(r"^ACT-\d{1,9}$")  # forme des identifiants d'actord (RELEVE.md)
_VERROU = threading.Lock()
_SOURCES = ("actord", "waf", "threatmesh")


# ── identité de l'appelant ────────────────────────────────────────────────────────────────────────

async def _est_admin(request: Request) -> bool:
    """Vrai seulement si l'appelant passe `require_jwt` (administrateur réel). Aucun cryptage ici : on rejoue la garde."""
    creds = None
    brut = request.headers.get("authorization", "")
    if brut.lower().startswith("bearer ") and brut[7:].strip():
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=brut[7:].strip())
    try:
        await require_jwt(request, creds)
        return True
    except HTTPException:
        return False
    except Exception:  # noqa: BLE001 — dans le doute, vue réduite
        return False


def _entetes_appelant(request: Request) -> Dict[str, str]:
    """Les seuls identifiants retransmis au WAF et à threatmesh (jamais à actord, qui n'en a pas l'usage)."""
    e = {}
    for nom in ("Authorization", "Cookie"):
        v = request.headers.get(nom.lower())
        if v:
            e[nom] = v
    return e


# ── cache à double tampon ─────────────────────────────────────────────────────────────────────────

def _servi(cle: Tuple, calcul: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    """Sert depuis le cache (15 s) ; un relevé dégradé n'écrase pas un relevé complet de moins de 120 s."""
    maintenant = time.time()
    with _VERROU:
        e = _CACHE.get(cle)
        if e is not None and maintenant < e["retry_at"]:
            return e["payload"]
    payload = calcul()
    complet = all(v["ok"] is not False for v in payload["sources"].values())
    with _VERROU:
        e = _CACHE.get(cle)
        if not complet and e is not None and e["complet"] and maintenant - e["complet_a"] < TAMPON_S:
            e["retry_at"] = maintenant + TTL_S
            return e["payload"]
        _CACHE.pop(cle, None)
        while len(_CACHE) >= CACHE_MAX:
            _CACHE.popitem(last=False)  # évince la plus ancienne, jamais tout le cache
        _CACHE[cle] = {"payload": payload, "complet": complet, "complet_a": maintenant if complet else None,
                       "retry_at": maintenant + TTL_S}
        return payload


def _cle(route: str, admin: bool, entetes: Dict[str, str]) -> Tuple:
    h = hashlib.sha256(("\0".join(f"{k}={v}" for k, v in sorted(entetes.items()))).encode()).hexdigest()
    return (route, admin, h)


# ── lecture du substrat ───────────────────────────────────────────────────────────────────────────

def _sources(lues: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """`ok` vaut True/False pour une source lue, None pour une source que la route n'a pas consultée."""
    out = {}
    for s in _SOURCES:
        r = lues.get(s)
        out[s] = {"ok": None, "erreur": "non consultée"} if r is None else {"ok": r["ok"], "erreur": r["erreur"]}
    return out


def _agreger(lectures: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Une source lue plusieurs fois est ok si toutes ses lectures le sont (la première erreur est gardée)."""
    return lectures[0] if len(lectures) == 1 else next((r for r in lectures if not r["ok"]), lectures[0])


def _lire_actord(admin: bool, chemin: str) -> Dict[str, Any]:
    """La vue complète (cibles) n'est demandée que pour un administrateur réel."""
    entetes = {"X-Sbx-Vue": "complete"} if admin and chemin == "/actors" else None
    return substrat.lire("actord", chemin, entetes=entetes)


def _liste(r: Dict[str, Any], cle: Optional[str] = None) -> list:
    d = r["donnees"] if r["ok"] else None
    if cle is not None and isinstance(d, dict):
        d = d.get(cle)
    return d if isinstance(d, list) else []


def _iso(ts: Any) -> Optional[str]:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return ts if isinstance(ts, str) and ts else None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _contexte(admin: bool, entetes: Dict[str, str], actord=("/actors", "/proposals"), waf=("/bans/history",),
              mesh=()) -> Dict[str, Any]:
    """Lit les chemins demandés ; rend `{"lues": {source: lecture}, "<source><chemin>": lecture}`."""
    brut: Dict[str, Dict[str, Any]] = {}
    par_source: Dict[str, List[Dict[str, Any]]] = {}
    for chemin in actord:
        r = _lire_actord(admin, chemin)
        brut["actord" + chemin] = r
        par_source.setdefault("actord", []).append(r)
    for chemin in waf:
        r = substrat.lire("waf", chemin, entetes=entetes)
        brut["waf" + chemin] = r
        par_source.setdefault("waf", []).append(r)
    for chemin in mesh:
        r = substrat.lire("threatmesh", chemin, entetes=entetes)
        brut["threatmesh" + chemin] = r
        par_source.setdefault("threatmesh", []).append(r)
    brut["lues"] = {s: _agreger(v) for s, v in par_source.items()}
    return brut


# ── construction des menaces ──────────────────────────────────────────────────────────────────────

def _score(a: Dict[str, Any]) -> Optional[int]:
    s = a.get("priority")
    return s if echelle.bande(s) != "inconnu" else None


def _historique_par_ip(ctx: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    h = ctx.get("waf/bans/history")
    d = h["donnees"] if h and h["ok"] and isinstance(h["donnees"], dict) else {}
    return {t["ip"]: t for t in d.get("tracked", []) if isinstance(t, dict) and isinstance(t.get("ip"), str)}


def _ips_par_acteur(ctx: Dict[str, Any]) -> Dict[str, List[str]]:
    """Adresses par acteur (seule source : /proposals). Usage interne : n'atteint la réponse que pour un admin."""
    out: Dict[str, List[str]] = {}
    for p in _liste(ctx.get("actord/proposals", {"ok": False, "donnees": None}), "propositions"):
        if isinstance(p, dict) and isinstance(p.get("actor"), str):
            out[p["actor"]] = [i for i in p.get("ips", []) if isinstance(i, str)]
    return out


def _menace(a: Dict[str, Any], admin: bool, ips: Dict[str, List[str]], hist: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    sc = _score(a)
    b = echelle.bande(sc)
    adrs = ips.get(a.get("id"), [])
    comptes = [hist[i]["count"] for i in adrs if i in hist and isinstance(hist[i].get("count"), int)]
    tags = a.get("tags") if isinstance(a.get("tags"), list) else []
    return {
        "id": a.get("id"),
        # source : adresses pour l'administrateur seulement ; sinon l'identifiant (le nom d'acteur est toujours vide)
        "source": ", ".join(adrs) if admin and adrs else (a.get("name") or a.get("id")),
        "score": sc,
        "bande": b,
        "phase": echelle.phase(b),
        "couches": [t[0] for t in tags if isinstance(t, (list, tuple)) and t and isinstance(t[0], str)],
        "tentatives": sum(comptes) if comptes else None,
        "vu": a.get("last"),
    }


def _menaces(ctx: Dict[str, Any], admin: bool, borne: bool = False) -> List[Dict[str, Any]]:
    """Menaces triées par score décroissant. `borne` tronque à MENACES_MAX (affichage seulement, jamais les compteurs)."""
    ips, hist = _ips_par_acteur(ctx), _historique_par_ip(ctx)
    acteurs = [a for a in _liste(ctx["actord/actors"]) if isinstance(a, dict) and isinstance(a.get("id"), str)]
    m = [_menace(a, admin, ips, hist) for a in acteurs]
    m.sort(key=lambda x: (x["score"] is None, -(x["score"] or 0)))
    return m[:MENACES_MAX] if borne else m


# ── routes ────────────────────────────────────────────────────────────────────────────────────────

@router.get("/status", dependencies=[Depends(require_lecture)])
async def status(request: Request, admin: bool = Depends(_est_admin)):
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes, actord=("/actors", "/proposals", "/overview"), waf=("/bans",),
                        mesh=("/status",))
        src = _sources(ctx["lues"])
        out: Dict[str, Any] = {"mode": None, "menaces_suivies": None, "evenements_24h": None, "blocages_actifs": None, "a_valider": None,
                               "score_max": None, "bande_max": None, "sources": src}
        if src["actord"]["ok"]:
            m = _menaces(ctx, admin)
            scores = [x["score"] for x in m if x["score"] is not None]
            out["menaces_suivies"] = len(m)
            act = (ctx["actord/overview"]["donnees"] or {}).get("activite_24h") if ctx["actord/overview"]["ok"] and \
                isinstance(ctx["actord/overview"]["donnees"], dict) else None
            if isinstance(act, list) and all(isinstance(n, int) and not isinstance(n, bool) for n in act):
                out["evenements_24h"] = sum(act)
            out["a_valider"] = sum(1 for x in m if echelle.exige_validation(x["bande"]))
            if scores:
                out["score_max"] = max(scores)
                out["bande_max"] = echelle.bande(max(scores))
        if src["waf"]["ok"]:
            d = ctx["waf/bans"]["donnees"]
            out["blocages_actifs"] = len(_liste(ctx["waf/bans"], "bans")) if isinstance(d, dict) else None
        return out

    rep = await asyncio.to_thread(_servi, _cle("status", admin, entetes), calcul)
    # le mode se lit en direct, jamais depuis le cache : un changement se voit tout de suite
    return {**rep, **await asyncio.to_thread(_mode_vivant)}


@router.get("/threats", dependencies=[Depends(require_lecture)])
async def threats(request: Request, admin: bool = Depends(_est_admin)):
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes)
        return {"menaces": _menaces(ctx, admin, borne=True), "sources": _sources(ctx["lues"])}

    return await asyncio.to_thread(_servi, _cle("threats", admin, entetes), calcul)


@router.get("/threats/{menace_id}", dependencies=[Depends(require_lecture)])
async def threat(menace_id: str, request: Request, admin: bool = Depends(_est_admin)):
    if not _ID_ACTEUR.match(menace_id):  # clé de cache contrôlée par l'appelant : forme validée avant tout
        raise HTTPException(status_code=404, detail="menace inconnue")
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes)
        src = _sources(ctx["lues"])
        # Les erreurs voyagent dans la charge (`_erreur`) pour passer par le double tampon : un relevé complet
        # récent est servi à la place d'un 503.
        if not src["actord"]["ok"]:
            return {"_erreur": (503, "actord injoignable"), "sources": src}
        trouvee = next((x for x in _menaces(ctx, admin) if x["id"] == menace_id), None)
        if trouvee is None:
            return {"_erreur": (404, "menace inconnue"), "sources": src}
        chrono = []
        for p in _liste(ctx["actord/proposals"], "propositions"):
            if isinstance(p, dict) and p.get("actor") == menace_id:
                chrono.append({"ts": _iso((ctx["actord/proposals"]["donnees"] or {}).get("genere_le")),
                               "capteur": "actord", "libelle": p.get("raison") or f"proposition {p.get('mode')}"})
                hist = _historique_par_ip(ctx)
                for ip in p.get("ips", []):
                    t = hist.get(ip)
                    if not t:
                        continue
                    cats = t.get("top_categories") or []
                    cat = cats[0].get("category") if cats and isinstance(cats[0], dict) else None
                    # le libellé ne cite jamais l'adresse : la chronologie est la même pour tous les lecteurs
                    lib = f"{t.get('count')} événements, gravité {t.get('severity_max')}" + (f", {cat}" if cat else "")
                    chrono.append({"ts": t.get("last_seen"), "capteur": "waf", "libelle": lib})
        chrono.sort(key=lambda c: str(c["ts"] or ""))
        return {**trouvee, "chronologie": chrono, "sources": src}

    rep_ = await asyncio.to_thread(_servi, _cle("threat:" + menace_id, admin, entetes), calcul)
    if "_erreur" in rep_:
        raise HTTPException(status_code=rep_["_erreur"][0], detail=rep_["_erreur"][1])
    return rep_


@router.get("/actions", dependencies=[Depends(require_lecture)])
async def actions(request: Request, admin: bool = Depends(_est_admin)):
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes, actord=(), waf=("/bans", "/bans/history"))
        src = _sources(ctx["lues"])
        out: List[Dict[str, Any]] = []
        vus = set()
        masque = {}

        def cible(ip):
            # non-administrateur : adresse masquée, numérotée pour distinguer les lignes sans rien révéler
            return ip if admin else masque.setdefault(ip, f"cible-{len(masque) + 1}")

        for b in _liste(ctx["waf/bans"], "bans"):
            if not isinstance(b, dict) or not isinstance(b.get("ip"), str):
                continue
            vus.add(b["ip"])
            out.append({"ts": b.get("created_at") or None, "cible": cible(b["ip"]), "geste": b.get("type") or "ban",
                        "origine": b.get("origin"), "ttl_s": b.get("expires_in"), "etat": "actif"})
        for ip, t in _historique_par_ip(ctx).items():
            if ip in vus:
                continue
            out.append({"ts": t.get("last_seen"), "cible": cible(ip), "geste": "vu", "origine": "sbxwaf",
                        "ttl_s": None, "etat": "historique"})
        return {"actions": out, "sources": src}

    return await asyncio.to_thread(_servi, _cle("actions", admin, entetes), calcul)


@router.get("/mesh", dependencies=[Depends(require_lecture)])
async def mesh(request: Request, admin: bool = Depends(_est_admin)):
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes, actord=(), waf=(), mesh=("/status", "/peers"))
        src = _sources(ctx["lues"])
        st = ctx["threatmesh/status"]["donnees"] if ctx["threatmesh/status"]["ok"] else None
        noeuds: List[Dict[str, Any]] = []
        if isinstance(st, dict):
            recus = st.get("mesh") if isinstance(st.get("mesh"), dict) else {}
            noeuds.append({"nom": st.get("node"), "soi": True, "emis": None,
                           "recus": st.get("mesh_total") if isinstance(st.get("mesh_total"), int) else None,
                           "etat": "actif"})
            for p in _liste(ctx["threatmesh/peers"], "peers"):
                nom = (p.get("name") or p.get("id")) if isinstance(p, dict) else None
                if not nom:
                    continue  # jamais `address` : adresse de pair
                n = recus.get(f"mesh:{nom}")
                noeuds.append({"nom": nom, "soi": False, "emis": None, "recus": n if isinstance(n, int) else None,
                               "etat": "actif" if isinstance(n, int) and n > 0 else "silencieux"})
        return {"noeuds": noeuds, "sources": src}

    return await asyncio.to_thread(_servi, _cle("mesh", admin, entetes), calcul)


@router.get("/incidents", dependencies=[Depends(require_lecture)])
async def incidents(request: Request, jours: int = Query(7, ge=1, le=90), admin: bool = Depends(_est_admin)):
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes, actord=("/overview", "/proposals"), waf=("/bans",))
        src = _sources(ctx["lues"])
        propose = _ips_par_acteur(ctx)
        bannies = {b.get("ip") for b in _liste(ctx["waf/bans"], "bans") if isinstance(b, dict)}
        # « bloqué » seulement si une adresse de l'acteur est dans les bans ACTIFS du WAF ; une proposition
        # d'actord (shadow ou non) n'est qu'« proposé ».
        bloques = {a for a, ips in propose.items() if bannies & set(ips)}
        depuis = time.time() - jours * 86400
        out = []
        for e in _liste(ctx["actord/overview"], "recents"):
            if not isinstance(e, dict):
                continue
            ts = e.get("ts")
            if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts < depuis:
                continue
            sc = e.get("score") if echelle.bande(e.get("score")) != "inconnu" else None
            b = echelle.bande(sc)
            out.append({"ts": _iso(ts), "titre": f"{e.get('acteur')} : {e.get('type')} ({e.get('module')})",
                        "score": sc, "bande": b,
                        "issue": "bloqué" if e.get("acteur") in bloques
                        else "proposé" if e.get("acteur") in propose else "observé"})
        return {"incidents": out, "sources": src}

    return await asyncio.to_thread(_servi, _cle(f"incidents:{jours}", admin, entetes), calcul)


# ── mode et politique ─────────────────────────────────────────────────────────────────────────────

def _mode_vivant() -> Dict[str, Any]:
    """Mode en direct ; base indisponible : `observe` (défaut sûr) et `etat_base: indisponible`."""
    try:
        return {"mode": defense_etat.mode_courant()}
    except defense_etat.EtatIndisponible:
        return {"mode": "observe", "etat_base": "indisponible"}


@router.get("/policies", dependencies=[Depends(require_lecture)])
async def policies():
    def lire():
        out = {**_mode_vivant(), "modes_ouverts": list(defense_etat.MODES_OUVERTS),
               "bandes": [{"seuil": s, "nom": n} for s, n in echelle.BANDES_DEFAUT],
               "seuils": {}, "liste_blanche": []}
        if "etat_base" not in out:
            try:
                out["seuils"], out["liste_blanche"] = defense_etat.seuils(), defense_etat.liste_blanche()
            except (sqlite3.Error, OSError):
                out["etat_base"] = "indisponible"
        return out
    return await asyncio.to_thread(lire)


@router.post("/mode")
async def changer_mode(corps: Dict[str, Any], payload: Dict[str, Any] = Depends(require_jwt)):
    valeur = corps.get("mode") if isinstance(corps, dict) else None
    if not isinstance(valeur, str) or valeur not in defense_etat.MODES:
        raise HTTPException(status_code=400, detail="mode inconnu")
    par = str((payload or {}).get("sub") or "inconnu")
    try:
        await asyncio.to_thread(defense_etat.changer_mode, valeur, par)
    except defense_etat.AuditIndisponible:
        return JSONResponse(status_code=503, content={"error": "audit indisponible : mode inchangé",
                                                      "cause": "audit_indisponible"})
    except defense_etat.EtatIndisponible:
        return JSONResponse(status_code=503, content={"error": "base d'état indisponible",
                                                      "cause": "base_indisponible"})
    except PermissionError:
        return JSONResponse(status_code=409, content={"error": "ce mode attend les gestes de réaction, non livrés",
                                                      "cause": "gestes_non_livres"})
    return {"mode": valeur}
