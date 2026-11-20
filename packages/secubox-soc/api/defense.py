# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Façade SADE : /defense/* au-dessus du substrat actord, WAF, threatmesh (#3839).

Lecture seule partout, sauf deux écritures réservées à un administrateur réel (`require_jwt`) : le mode
(`POST /mode`) et la file d'approbation REACTIVE (`POST /approve`, `POST /refuse`), seul chemin qui pose un ban
réel (un `POST /ban` du WAF par adresse, au nom de l'administrateur, audité ici avant et après). Chaque réponse porte `sources` : l'état de lecture de chaque source, pour qu'une
source muette se voie au lieu de se confondre avec « zéro menace » (les compteurs valent alors `None`, jamais 0).

Confidentialité (#2201/#2274) : une adresse d'acteur ne sort QUE pour un administrateur réel (`require_jwt`).
Tout autre lecteur reçoit la vue réduite d'actord et des cibles masquées ; les adresses ne sont même pas copiées
dans sa réponse. Les identifiants de l'appelant (Authorization, Cookie) sont retransmis tels quels au WAF et à
threatmesh : la façade ne forge ni ne conserve aucun jeton.

Contrat de `sources.<x>.ok` : True ou False quand la route a consulté la source, `None` quand elle ne l'a pas
consultée (seule `/status` lit les trois). Un front ne doit pas traiter `None` comme une panne : c'est « non lu ».

Compteurs : `menaces_suivies` = acteurs connus d'actord (aucune fenêtre de 24 h n'existe dans /actors, qui ne porte que
« HH:MM »), compté avant toute troncature ; `evenements_24h` = somme de `activite_24h` de /overview, qui ne couvre
que les ECHANTILLON_ACTORD derniers événements d'actord : `evenements_24h_plafonne` vaut True quand l'échantillon est
plein (ou de taille inconnue) et le chiffre n'est alors qu'un minimum ; `a_valider` = propositions d'actord en attente
de décision (même règle que /proposals) ; `blocages_actifs` = bans que le WAF dit appliqués (`application.ok`),
`blocages_enregistres` = bans inscrits au WAF, appliqués ou non.
"""
import asyncio
import hashlib
import ipaddress
import re
import socket
import sqlite3
import struct
import threading
from collections import OrderedDict
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from secubox_core.auth import (
    ENTETE_LAN,
    SESSION_COOKIE,
    _validate_token,
    est_admin_reel,
    mode_tableau_de_bord_actif,
    require_jwt,
    require_lecture,
)

from . import defense_etat, echelle, sade_auto, substrat

router = APIRouter(tags=["defense"])

TTL_S = 15.0          # durée du cache par route
TAMPON_S = 900.0      # un relevé complet de moins de 15 min n'est pas écrasé par un relevé dégradé (#3011) ; il porte
                      # son heure (`releve_a`) et la page l'affiche « RELEVÉ DU HH:MM » : jamais présenté comme direct
DELAI_LECTURE_S = 20.0  # lecture d'une source : /bans/history prend 1 à 3 s sur gk2 chargé, 3 s coupaient (20/11)
MENACES_MAX = 200
CACHE_MAX = 256       # entrées au plus : la clé contient un condensat des identifiants de l'appelant

_CACHE: "OrderedDict[Any, Dict[str, Any]]" = OrderedDict()
_ID_ACTEUR = re.compile(r"^ACT-\d{1,9}$")  # forme des identifiants d'actord (RELEVE.md)
_VERROU = threading.Lock()
_SOURCES = ("actord", "waf", "threatmesh")
ECHANTILLON_ACTORD = 5000  # `apercuEchantillon` (cmd/sbx-actord/overview.go) : derniers événements examinés par /overview


# ── identité de l'appelant ────────────────────────────────────────────────────────────────────────

async def _est_admin(request: Request) -> bool:
    """Vrai seulement si l'appelant passe `require_jwt` (administrateur réel). Aucun cryptage ici.

    Sonde silencieuse d'abord : un jeton de session valide dont le compte n'est pas administrateur réel est refusé SANS
    rejouer `require_jwt` (qui journalise un WARNING « administration refusée » à chaque lecture). Tout le reste (jeton
    invalide, porteur de pilotage, administrateur) passe par `require_jwt` comme avant : la garde elle-même n'est pas
    affaiblie, elle n'est seulement plus appelée pour un refus déjà certain."""
    creds = None
    brut = request.headers.get("authorization", "")
    if brut.lower().startswith("bearer ") and brut[7:].strip():
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=brut[7:].strip())
    try:
        jetons = ([creds.credentials] if creds is not None else []) + [t for t in [request.cookies.get(SESSION_COOKIE)] if t]
        for jeton in jetons:  # même ordre que `require_session` : porteur puis cookie, le premier valide l'emporte
            payload = _validate_token(jeton)
            if payload is not None:
                if not est_admin_reel(payload):
                    return False
                break
    except Exception:  # noqa: BLE001 — sonde seulement : en cas de doute, la garde réelle tranche
        pass
    try:
        await require_jwt(request, creds)
        return True
    except HTTPException:
        return False
    except Exception:  # noqa: BLE001 — dans le doute, vue réduite
        return False


def _entetes_appelant(request: Request) -> Dict[str, str]:
    """Les seuls identifiants retransmis au WAF et à threatmesh (jamais à actord, qui n'en a pas l'usage).

    Mode tableau de bord (LAN sans jeton) : le verdict LAN posé par nginx (`X-SecuBox-LAN: 1`) est retransmis
    pour les LECTURES, et seulement quand le mode est actif sur la box — sans lui, le WAF répondait 401 et les
    cartes blocages/actions restaient vides depuis le LAN (constaté sur gk2, 20/11). Le WAF applique ensuite sa
    propre règle de tableau de bord. Aucune exposition nouvelle : ses sockets acceptent déjà cet en-tête de tout
    processus local. Le ban (`POST /ban`) n'utilise pas cette fonction : il exige toujours le porteur admin.
    """
    e = {}
    for nom in ("Authorization", "Cookie"):
        v = request.headers.get(nom.lower())
        if v:
            e[nom] = v
    if request.headers.get(ENTETE_LAN.lower(), "").strip() == "1" and mode_tableau_de_bord_actif():
        e[ENTETE_LAN] = "1"
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
    payload["releve_a"] = _iso(maintenant)
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
    """La vue complète de `/actors` (cibles) n'est demandée que pour un administrateur réel. `/proposals` n'existe
    QUE dans la vue complète (404 sinon, RELEVE.md) : on la demande pour tous, ses adresses ne servent qu'en interne
    et n'atteignent que la réponse d'un administrateur."""
    entetes = {"X-Sbx-Vue": "complete"} if chemin == "/proposals" or (admin and chemin == "/actors") else None
    return substrat.lire("actord", chemin, entetes=entetes, delai=DELAI_LECTURE_S)


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
        r = substrat.lire("waf", chemin, entetes=entetes, delai=DELAI_LECTURE_S)
        brut["waf" + chemin] = r
        par_source.setdefault("waf", []).append(r)
    for chemin in mesh:
        r = substrat.lire("threatmesh", chemin, entetes=entetes, delai=DELAI_LECTURE_S)
        brut["threatmesh" + chemin] = r
        par_source.setdefault("threatmesh", []).append(r)
    brut["lues"] = {s: _agreger(v) for s, v in par_source.items()}
    return brut


def _nom_hote() -> Optional[str]:
    try:
        n = socket.gethostname().split(".")[0]
    except OSError:
        return None
    return n if re.fullmatch(r"[A-Za-z0-9-]{1,63}", n or "") else None


def _type_lisible(t: Any) -> Any:
    """actord marque d'un « ? » final un outil deviné (« client-automatise? ») : « client-automatise (probable) »."""
    if isinstance(t, str) and t.endswith("?") and t.rstrip("?"):
        return t.rstrip("?") + " (probable)"
    return t


def _meme_incident(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return (a["titre"], (a["ts"] or "")[:16], a["bande"], a["issue"], a["score"]) == \
        (b["titre"], (b["ts"] or "")[:16], b["bande"], b["issue"], b["score"])


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

def _a_valider(r: Dict[str, Any]) -> Optional[int]:
    """Propositions d'actord en attente de décision : même source et même règle que GET /proposals (état de la dernière
    génération par empreinte ; absent = en attente). None si la base d'état est illisible : jamais un zéro inventé."""
    try:
        etats = defense_etat.etats_decisions()
    except defense_etat.EtatIndisponible:
        return None
    return sum(1 for p in _propositions(r) if etats.get(p["empreinte"], "en_attente") == "en_attente")


@router.get("/status", dependencies=[Depends(require_lecture)])
async def status(request: Request, admin: bool = Depends(_est_admin)):
    entetes = _entetes_appelant(request)

    def calcul():
        ctx = _contexte(admin, entetes, actord=("/actors", "/proposals", "/overview"), waf=("/bans",),
                        mesh=("/status",))
        src = _sources(ctx["lues"])
        out: Dict[str, Any] = {"mode": None, "menaces_suivies": None, "evenements_24h": None, "evenements_24h_plafonne": False,
                               "blocages_actifs": None, "blocages_enregistres": None, "blocages_application": None,
                               "a_valider": None, "score_max": None, "bande_max": None, "sources": src}
        if src["actord"]["ok"]:
            m = _menaces(ctx, admin)
            scores = [x["score"] for x in m if x["score"] is not None]
            out["menaces_suivies"] = len(m)
            ov = ctx["actord/overview"]["donnees"] if ctx["actord/overview"]["ok"] and \
                isinstance(ctx["actord/overview"]["donnees"], dict) else {}
            act = ov.get("activite_24h")
            if isinstance(act, list) and all(isinstance(n, int) and not isinstance(n, bool) for n in act):
                out["evenements_24h"] = sum(act)
                ech = ov.get("echantillon")
                # échantillon plein, ou de taille inconnue (ancien actord, même plafond) : jamais présenté comme exact
                out["evenements_24h_plafonne"] = not (isinstance(ech, int) and not isinstance(ech, bool)
                                                      and ech < ECHANTILLON_ACTORD)
            out["a_valider"] = _a_valider(ctx["actord/proposals"])
            if scores:
                out["score_max"] = max(scores)
                out["bande_max"] = echelle.bande(max(scores))
        if src["waf"]["ok"]:
            d = ctx["waf/bans"]["donnees"]
            if isinstance(d, dict):
                n = len(_liste(ctx["waf/bans"], "bans"))
                app = d.get("application") if isinstance(d.get("application"), dict) else {}
                out["blocages_enregistres"] = n
                out["blocages_application"] = app.get("etat") if isinstance(app.get("etat"), str) else None
                # appliqués = la table nft du WAF les porte : `application.ok` vrai. Faux : rien n'est appliqué (0) ;
                # champ absent : on ne sait pas (None, jamais un 0 inventé).
                out["blocages_actifs"] = n if app.get("ok") is True else (0 if app.get("ok") is False else None)
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
        masque: Dict[str, str] = {}
        for p in _liste(ctx["actord/proposals"], "propositions"):
            if isinstance(p, dict) and p.get("actor") == menace_id:
                lib = p.get("raison") if isinstance(p.get("raison"), str) and p.get("raison") else f"proposition {p.get('mode')}"
                # vue complète d'actord : un non-administrateur ne reçoit jamais une adresse, même dans un texte libre
                chrono.append({"ts": _iso((ctx["actord/proposals"]["donnees"] or {}).get("genere_le")),
                               "capteur": "actord", "libelle": lib if admin else _masquer(lib, masque)})
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
            # le nom d'hôte de la box, pas l'identifiant technique de threatmesh (« sb-b3f6… » vu sur gk2, 20/11)
            noeuds.append({"nom": _nom_hote() or st.get("node"), "identifiant": st.get("node"), "soi": True, "emis": None,
                           "recus": st.get("mesh_total") if isinstance(st.get("mesh_total"), int) else None,
                           "etat": "actif"})
            for p in _liste(ctx["threatmesh/peers"], "peers"):
                nom = (p.get("name") or p.get("id")) if isinstance(p, dict) else None
                if not nom:
                    continue  # jamais `address` : adresse de pair
                n = recus.get(f"mesh:{nom}")
                noeuds.append({"nom": nom, "soi": False, "emis": None, "recus": n if isinstance(n, int) else None,
                               "etat": "actif" if isinstance(n, int) and n > 0 else "silencieux"})
        # threatmesh ≥ 1.2.0 ne partage plus d'indicateurs non signés (#3450) : des pairs tous silencieux sont attendus
        pairs = [n for n in noeuds if not n["soi"]]
        return {"noeuds": noeuds, "pairs_silencieux": bool(pairs) and all(n["etat"] == "silencieux" for n in pairs),
                "sources": src}

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
        out: List[Dict[str, Any]] = []
        for e in _liste(ctx["actord/overview"], "recents"):
            if not isinstance(e, dict):
                continue
            ts = e.get("ts")
            if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts < depuis:
                continue
            sc = e.get("score") if echelle.bande(e.get("score")) != "inconnu" else None
            b = echelle.bande(sc)
            inc = {"ts": _iso(ts), "titre": f"{e.get('acteur')} : {_type_lisible(e.get('type'))} ({e.get('module')})",
                   "score": sc, "bande": b,
                   "issue": "bloqué" if e.get("acteur") in bloques
                   else "proposé" if e.get("acteur") in propose else "observé", "n": 1}
            # actord émet un événement par requête : deux lignes identiques dans la même minute n'en font qu'une (×n)
            if out and _meme_incident(out[-1], inc):
                out[-1]["n"] += 1
                continue
            out.append(inc)
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
async def policies(admin: bool = Depends(_est_admin)):
    def lire():
        out = {**_mode_vivant(), "modes_ouverts": list(defense_etat.MODES_OUVERTS),
               "bandes": [{"seuil": s, "nom": n} for s, n in echelle.BANDES_DEFAUT],
               "seuils": {}, "liste_blanche": []}
        if "etat_base" not in out:
            try:
                out["seuils"], out["liste_blanche"] = defense_etat.seuils(), defense_etat.liste_blanche()
                try:
                    bans: Optional[int] = defense_etat.bans_auto_depuis(sade_auto.FENETRE_PLAFOND_S)
                except defense_etat.EtatIndisponible:
                    bans = None  # jamais un zéro inventé
                try:
                    _v, depuis, par = defense_etat.mode_detail()
                except defense_etat.EtatIndisponible:
                    depuis, par = None, None
                # auteur du dernier changement de mode : la page dit « retour en OBSERVE par le plafond » quand c'est
                # l'exécuteur ; le nom d'un opérateur humain ne sort que pour un administrateur
                if not admin and par != sade_auto.OPERATEUR:
                    par = None
                # `bans_derniere_heure` : ADRESSES réclamées par l'exécuteur sur l'heure glissante, quel que soit l'état
                # de la décision (la page écrit « Décisions automatiques ») ; c'est le compte du plafond
                out["auto"] = {"plafond_heure": sade_auto.PLAFOND_HEURE, "bans_derniere_heure": bans,
                               "score": [sade_auto.SCORE_MIN, sade_auto.SCORE_MAX],
                               "ttl_max_s": sade_auto.TTL_AUTO_MAX_S, "adresses_max": sade_auto.ADRESSES_AUTO_MAX,
                               "mode_par": par, "mode_depuis": depuis}
                if not admin:  # un lecteur ne voit que l'amorçage système, jamais les ajouts ni leur auteur
                    out["liste_blanche"] = [{k: e[k] for k in ("cidr", "motif", "ts", "supprimable")}
                                            for e in out["liste_blanche"] if not e["supprimable"]]
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



# ── liste blanche : ajout et retrait par un administrateur réel (#3839) ─────────────────────────────
_CAUSES_LB = {"cidr_illisible": "réseau illisible ou non admis", "cidr_trop_large": "réseau trop large (au plus /24 en IPv4, /48 en IPv6)",
              "motif_invalide": "motif requis (1 à 80 caractères)", "deja_presente": "réseau déjà en liste blanche",
              "liste_pleine": "liste blanche pleine"}


async def _geste_liste_blanche(fn, *args) -> JSONResponse:
    try:
        cidr = await asyncio.to_thread(fn, *args)
    except defense_etat.AuditIndisponible:
        return JSONResponse(status_code=503, content={"error": "audit indisponible : rien changé", "cause": "audit_indisponible"})
    except defense_etat.EtatIndisponible:
        return JSONResponse(status_code=503, content={"error": "base d'état indisponible", "cause": "base_indisponible"})
    except ValueError as e:
        c = str(e) if str(e) in _CAUSES_LB else "corps"
        return JSONResponse(status_code=409 if c in ("deja_presente", "liste_pleine") else 400,
                            content={"error": _CAUSES_LB.get(c, "requête invalide"), "cause": c})
    except KeyError:
        return JSONResponse(status_code=404, content={"error": "réseau absent de la liste blanche", "cause": "absente"})
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "entrée système non supprimable", "cause": "entree_amorcee"})
    with _VERROU:
        _CACHE.clear()
    return JSONResponse(status_code=200, content={"cidr": cidr})


@router.post("/liste-blanche")
async def ajouter_liste_blanche(corps: Dict[str, Any], payload: Dict[str, Any] = Depends(require_jwt)):
    corps = corps if isinstance(corps, dict) else {}
    return await _geste_liste_blanche(defense_etat.ajouter_liste_blanche, corps.get("cidr"), corps.get("motif"),
                                      str((payload or {}).get("sub") or "inconnu"))


@router.post("/liste-blanche/retirer")
async def retirer_liste_blanche(corps: Dict[str, Any], payload: Dict[str, Any] = Depends(require_jwt)):
    corps = corps if isinstance(corps, dict) else {}
    return await _geste_liste_blanche(defense_etat.retirer_liste_blanche, corps.get("cidr"),
                                      str((payload or {}).get("sub") or "inconnu"))

# ── file d'approbation (REACTIVE) ─────────────────────────────────────────────────────────────────
#
# Identité d'une décision : l'EMPREINTE de la proposition = sha256(geste | adresses normalisées triées | ttl_s), jamais
# l'identifiant d'acteur (ACT-NNNN est renuméroté à chaque redémarrage d'actord). L'administrateur approuve une
# empreinte : celle qu'il a vue (rendue par GET /proposals, à lui seul). Le serveur la recalcule sur la proposition
# COURANTE d'actord ; aucune correspondance → 409 `proposition_changee`, rien n'est fait.
#
# Ordre des contrôles, identique en simulation : corps → mode → proposition relue chez actord (même empreinte) →
# [approbation] geste exécutable → adresses (présentes, ≤ 32) → durée représentable → liste blanche (toutes les
# adresses, échec fermé) → porteur → décision non tranchée. Le geste réel réclame ensuite la décision (`en_cours`,
# mode relu, audit fsync, dans UNE transaction) AVANT tout appel au WAF ; jamais d'appel si l'audit a échoué.

_EMPREINTE = re.compile(r"^[0-9a-f]{64}$")
_GESTES = {"DENY": "ban", "QUARANTINE": "quarantaine"}  # mode d'actord → geste SADE
GESTES_EXECUTABLES = ("ban",)                            # seul geste livré : un POST /ban du WAF par adresse
ROUTES_PROC = "/proc/net/route"                          # passerelles IPv4 (les IPv6 sont lien-local, déjà refusées)
# Le WAF borne `wafctl` à 15 s (subprocess timeout), plus sudo et uvicorn : la façade attend nettement plus, pour qu'un
# succès lent ne soit jamais audité comme un échec. Sur expiration malgré tout, l'issue est « incertain ».
DELAI_WAF_S = 30.0
ADRESSES_MAX = 32                                        # un sudo wafctl séquentiel par adresse
TTL_MAX_S = 9_999_999                                    # au-delà, « <n>s » n'est plus accepté par wafctl

# Jamais bannissables, quelle que soit la liste blanche en base (qui en amorce déjà la plupart). Les plages de
# documentation (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) ne sont pas routées : elles restent admises
# pour les jeux d'essai.
_INTERDITS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2002::/16",
    "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
))
_IP_TEXTE = re.compile(r"[0-9a-fA-F:.]{2,}")


_IPV4_ENFOUIE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _masquer(texte: str, masque: Dict[str, str]) -> str:
    """Remplace toute adresse d'un texte libre par `cible-N` (même numérotation que les cibles masquées)."""
    def sub(m):
        v = m.group(0)
        # on jette la ponctuation de bord (« : » ou « . » de fin) puis on valide par ipaddress
        for cand in dict.fromkeys((v, v.rstrip(".:"), v.rstrip("."), v.rstrip(":"), v.strip(".:"))):
            try:
                ipaddress.ip_address(cand)
            except ValueError:
                continue
            cle = cand
            return masque.setdefault(cle, f"cible-{len(masque) + 1}") + v[len(cand):]
        # « 1.2.3.4:8080 », « a1.2.3.4 » : une IPv4 enfouie dans le jeton est masquée ; « 09:47:00 » reste intact
        def ipv4(n):
            try:
                ipaddress.IPv4Address(n.group(0))
            except ValueError:
                return n.group(0)
            return masque.setdefault(n.group(0), f"cible-{len(masque) + 1}")
        return _IPV4_ENFOUIE.sub(ipv4, v)
    return _IP_TEXTE.sub(sub, texte)


def _geste(mode: Any) -> str:
    if not isinstance(mode, str) or not mode:
        return "inconnu"
    g = _GESTES.get(mode.upper(), mode.lower())
    return g if re.fullmatch(r"[a-z_]{1,32}", g) else "inconnu"


def _normaliser(a: str) -> str:
    """Forme canonique d'une adresse pour l'empreinte (IPv4 sous IPv6 déballée) ; texte inchangé si illisible."""
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return a
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.compressed


def empreinte(geste: str, ips: List[str], ttl_s: Optional[int]) -> str:
    """sha256(geste | adresses normalisées triées | ttl_s) en hexadécimal : l'identité d'une décision."""
    brut = f"{geste}|{','.join(sorted(_normaliser(a) for a in ips))}|{ttl_s if ttl_s else ''}"
    return hashlib.sha256(brut.encode("utf-8")).hexdigest()


def _propositions(r: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Propositions d'actord normalisées, une par empreinte. Une adresse qui n'est pas une chaîne est gardée sous forme
    textuelle : elle échouera au contrôle d'adresse (échec fermé), jamais silencieusement retirée."""
    out, vus = [], set()
    for p in _liste(r, "propositions"):
        if not isinstance(p, dict) or not isinstance(p.get("actor"), str) or not _ID_ACTEUR.match(p["actor"]):
            continue
        g = _geste(p.get("mode"))
        ips = p.get("ips") if isinstance(p.get("ips"), list) else []
        ips = [i if isinstance(i, str) else repr(i) for i in ips]
        ttl = p.get("ttl_s")
        ttl = ttl if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl > 0 else None
        e = empreinte(g, ips, ttl)
        if e in vus:
            continue
        vus.add(e)
        sc = p.get("priorite") if echelle.bande(p.get("priorite")) != "inconnu" else None
        out.append({"id": f"{p['actor']}:{g}", "empreinte": e, "menace_id": p["actor"], "geste": g, "ips": ips,
                    "score": sc, "bande": echelle.bande(sc),
                    "motif": p.get("raison") if isinstance(p.get("raison"), str) else None, "ttl_s": ttl})
    return out


def _lire_propositions() -> Dict[str, Any]:
    return substrat.lire("actord", "/proposals", entetes={"X-Sbx-Vue": "complete"})


def _reseau(texte: Any) -> Optional[Any]:
    """Réseau d'une adresse ou d'un CIDR, ou d'un point d'accès « hôte:port » / « [v6]:port » ; None si illisible."""
    if not isinstance(texte, str) or not texte.strip():
        return None
    t = texte.strip()
    if t.startswith("[") and "]" in t:
        t = t[1:t.index("]")]
    elif t.count(":") == 1:
        t = t.split(":")[0]
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None


def _adresse_interdite(texte: str, proteges: List[Any]) -> bool:
    """Vrai si `texte` n'est pas une adresse unicast publique, ou tombe dans un réseau protégé (IPv4 et IPv6)."""
    try:
        ip = ipaddress.ip_address(texte)
    except ValueError:
        return True  # CIDR, nom, vide, espace parasite : jamais bannissable par ce geste
    if ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
        return True
    if ip.version == 6 and (ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None
                            or ip.is_site_local or getattr(ip, "scope_id", None)):
        return True
    return any(n.version == ip.version and ip in n for n in _INTERDITS + tuple(proteges))


def _passerelles() -> List[Any]:
    out = []
    try:
        with open(ROUTES_PROC, encoding="ascii") as f:
            lignes = f.read().splitlines()[1:]
    except (OSError, UnicodeDecodeError):
        return out
    for ligne in lignes:
        c = ligne.split()
        if len(c) > 2 and c[2] != "00000000":
            try:
                out.append(ipaddress.ip_network(socket.inet_ntoa(struct.pack("<I", int(c[2], 16)))))
            except (ValueError, struct.error, OSError):
                continue
    return out


def _pairs(entetes: Dict[str, str]) -> Tuple[List[Any], bool]:
    """Adresses des pairs du maillage (threatmesh /peers) et si la liste a pu être lue. Non lue : l'approbation
    continue (la garde du WAF reste le dernier rempart), mais la réponse et l'audit le disent."""
    r = substrat.lire("threatmesh", "/peers", entetes=entetes)
    out = []
    for p in _liste(r, "peers"):
        if isinstance(p, dict):
            for champ in ("address", "endpoint", "ip"):
                n = _reseau(p.get(champ))
                if n is not None:
                    out.append(n)
    return out, bool(r.get("ok"))


def _proteges(entetes: Dict[str, str], appelant: List[str]) -> Tuple[List[Any], List[str], bool]:
    """(réseaux protégés, entrées de liste blanche illisibles, pairs lus). Protégés : liste blanche en base +
    passerelles + pairs du maillage + adresses de l'administrateur. Lève `EtatIndisponible` si la base ne se lit pas."""
    try:
        lb = defense_etat.liste_blanche()
    except (sqlite3.Error, OSError) as e:
        raise defense_etat.EtatIndisponible(e.__class__.__name__) from e
    nets, illisibles = [], []
    for e in lb:
        n = _reseau(e.get("cidr"))
        if n is None:
            illisibles.append(str(e.get("cidr")))
        else:
            nets.append(n)
    pairs, pairs_lus = _pairs(entetes)
    nets += _passerelles() + pairs
    nets += [n for n in (_reseau(a) for a in appelant) if n is not None]
    return nets, illisibles, pairs_lus


_sain = defense_etat.champ_sain


def _champs(p: Dict[str, Any], par: str, duree: Optional[str]) -> str:
    return (f"empreinte={p['empreinte']} acteur={_sain(p['menace_id'], 16)} adresses={_sain(','.join(p['ips']), 1024)} "
            f"geste={_sain(p['geste'], 32)} duree={duree or 'defaut_waf'} "
            f"score={p['score'] if p['score'] is not None else 'inconnu'} operateur={defense_etat._operateur_sain(par)}")


def _non(code: int, cause: str, message: str, **extra) -> Tuple[int, Dict[str, Any]]:
    return code, {"error": message, "cause": cause, **extra}


def _traiter(action: str, emp: str, simuler: bool, par: str, porteur: Optional[str], entetes: Dict[str, str],
             appelant: List[str]) -> Tuple[int, Dict[str, Any]]:
    """Approuve ou refuse la proposition d'empreinte `emp`. Rend (code HTTP, corps). Synchrone : appelé dans un fil."""
    p: Optional[Dict[str, Any]] = None
    duree: Optional[str] = None
    pairs_note = ""          # « pairs_maillage=… » dans l'audit, une fois la liste blanche évaluée
    pairs_extra: Dict[str, Any] = {}

    def bloque(code, cause, message, note="", **extra):
        # en simulation, la ligne d'audit EST le résultat : obligatoire ; sinon trace d'un geste empêché, au mieux
        champs = (_champs(p, par, duree) if p
                  else f"empreinte={_sain(emp, 64)} operateur={defense_etat._operateur_sain(par)}")
        suffixe = (f" {note}" if note else "") + pairs_note
        try:
            defense_etat.ecrire_audit(f"sade-simule operation={action} verdict={cause} {champs}{suffixe}" if simuler
                                      else f"sade-{action}-refus cause={cause} {champs}{suffixe}")
        except defense_etat.AuditIndisponible:
            if simuler:
                return _non(503, "audit_indisponible", "audit indisponible : simulation non tracée")
        return _non(code, cause, message, **extra, **pairs_extra)

    try:
        mode = defense_etat.mode_courant()
    except defense_etat.EtatIndisponible:
        return _non(503, "base_indisponible", "base d'état indisponible")
    if mode not in ("reactive", "active"):
        return bloque(409, "mode", f"mode {mode} : la file d'approbation n'agit qu'en REACTIVE ou ACTIVE")
    r = _lire_propositions()
    if not r["ok"]:
        return bloque(503, "actord_indisponible", f"actord injoignable ({r['erreur']}) : proposition non relue")
    p = next((x for x in _propositions(r) if x["empreinte"] == emp), None)
    if p is None:
        return bloque(409, "proposition_changee",
                      "la proposition affichée n'existe plus telle quelle chez actord (adresses, durée ou geste changés, "
                      "ou expirée) : rechargez la file")
    duree = f"{p['ttl_s']}s" if p["ttl_s"] else None
    if action == "approuve":
        if p["geste"] not in GESTES_EXECUTABLES:
            return bloque(409, "gestes_non_livres", f"geste « {p['geste']} » non livré : seul le ban est exécutable")
        if not p["ips"]:
            return bloque(409, "sans_adresse", "proposition sans adresse : rien à bannir")
        if len(p["ips"]) > ADRESSES_MAX:
            return bloque(409, "trop_d_adresses", f"{len(p['ips'])} adresses : au plus {ADRESSES_MAX} par approbation")
        if p["ttl_s"] and p["ttl_s"] > TTL_MAX_S:
            return bloque(409, "duree_invalide", f"durée {p['ttl_s']} s non représentable par le WAF")
        try:
            proteges, illisibles, pairs_lus = _proteges(entetes, appelant)
        except defense_etat.EtatIndisponible:
            return _non(503, "base_indisponible", "liste blanche illisible : aucun geste")
        pairs_note = f" pairs_maillage={'verifies' if pairs_lus else 'non_verifies'}"
        if not pairs_lus:
            pairs_extra = {"pairs_maillage": "non_verifies"}
        if illisibles:
            return bloque(403, "liste_blanche", "entrée de liste blanche illisible : aucun geste tant qu'elle n'est pas corrigée",
                          note=f"motif=liste_blanche_illisible entrees={_sain(','.join(illisibles), 256)}",
                          entrees_illisibles=illisibles)
        refusees = [ip for ip in p["ips"] if _adresse_interdite(ip, proteges)]
        if refusees:
            return bloque(403, "liste_blanche", "adresse protégée ou non publique : proposition entière refusée",
                          adresses_refusees=refusees)
        if not porteur:
            return bloque(409, "porteur_requis", "jeton porteur requis : le WAF refuse une écriture par cookie seul")
    try:
        etat = defense_etat.decision(emp)["etat"]
    except defense_etat.EtatIndisponible:
        return _non(503, "base_indisponible", "base d'état indisponible")
    if etat != "en_attente":
        return bloque(409, "deja_traitee", f"décision déjà {etat}", etat=etat)

    if simuler:
        try:
            defense_etat.ecrire_audit(f"sade-simule operation={action} verdict=ok {_champs(p, par, duree)}{pairs_note}")
        except defense_etat.AuditIndisponible:
            return _non(503, "audit_indisponible", "audit indisponible : simulation non tracée")
        quoi = (f"ban de {len(p['ips'])} adresse(s) pour {duree or 'la durée par défaut du WAF'}"
                if action == "approuve" else "refus")
        return 200, {"etat": "simule", "resultat": f"simulation : {quoi} possible, rien n'a été appliqué", **pairs_extra}

    try:
        gen = defense_etat.reclamer(emp, p["menace_id"], p["geste"], ",".join(p["ips"]), p["score"], p["ttl_s"], par,
                                    "refuse" if action == "refuse" else "en_cours",
                                    f"sade-{'refuse' if action == 'refuse' else 'approuve-demande'} "
                                    f"{_champs(p, par, duree)}{pairs_note}",
                                    modes=("reactive", "active"))
    except defense_etat.ModeRefuse as e:
        return _non(409, "mode", f"mode {e} : la file d'approbation n'agit qu'en REACTIVE ou ACTIVE")
    except defense_etat.DejaTraitee as e:
        return _non(409, "deja_traitee", f"décision déjà {e}", etat=str(e))
    except defense_etat.AuditIndisponible:
        return _non(503, "audit_indisponible", "audit indisponible : aucun geste")
    except defense_etat.EtatIndisponible:
        return _non(503, "base_indisponible", "base d'état indisponible")
    if action == "refuse":
        return 200, {"etat": "refuse", "resultat": "proposition refusée"}

    # Geste réel : la décision est réclamée et la demande auditée. Un POST /ban par adresse, arrêt au premier échec.
    bannies: List[str] = []
    echec: Optional[Tuple[str, str]] = None
    for ip in p["ips"]:
        corps: Dict[str, Any] = {"ip": ip, "reason": f"SADE {p['menace_id']} approuvé par {defense_etat._operateur_sain(par)}"}
        if duree:
            corps["duration"] = duree
        rep = substrat.ecrire("waf", "/ban", corps, entetes={"Authorization": porteur}, delai=DELAI_WAF_S)
        d = rep.get("donnees")
        if rep.get("ok") and isinstance(d, dict) and d.get("success") is True:
            bannies.append(ip)
            continue
        echec = (ip, rep.get("erreur") or "réponse du WAF sans succès")
        break
    if echec is None:
        issue = "applique"
    elif echec[1] == "délai":
        issue = "incertain"  # le WAF a peut-être posé le ban après notre délai : un nouvel essai est idempotent
    else:
        issue = "partiel" if bannies else "echec"
    resultat = (f"{len(bannies)} adresse(s) bannie(s) pour {duree or 'la durée par défaut du WAF'}" if echec is None
                else f"échec du WAF sur {echec[0]} : {echec[1]} ; déjà bannies : {', '.join(bannies) or 'aucune'}")
    avertissements = []
    try:
        defense_etat.conclure(emp, gen, "applique" if echec is None else "en_attente", resultat,
                              getattr(gen, "demande_ts", None))
    except defense_etat.EtatIndisponible:
        # la ligne reste `en_cours` : plus aucun geste sans reprise explicite (jamais deux bans en parallèle)
        avertissements.append("décision non close en base : elle reste « en cours » (reprise possible plus tard)")
    try:
        defense_etat.ecrire_audit(f"sade-approuve-resultat issue={issue} generation={gen} "
                                  f"bannies={_sain(','.join(bannies) or 'aucune', 1024)} "
                                  + (f"echec={_sain(echec[0], 64)} erreur={_sain(echec[1], 200)} " if echec else "")
                                  + _champs(p, par, duree) + pairs_note)
    except defense_etat.AuditIndisponible:
        avertissements.append("audit du résultat indisponible")
    with _VERROU:
        _CACHE.clear()  # les bans actifs ont changé : la façade relit au prochain appel
    extra = {**({"avertissements": avertissements} if avertissements else {}), **pairs_extra}
    if echec is None:
        return 200, {"etat": "applique", "resultat": resultat, "bannies": bannies, **extra}
    return _non(502, "waf", f"WAF : {echec[1]}", etat="en_attente", issue=issue, resultat=resultat, bannies=bannies,
                echec=echec[0], **extra)


def _porteur(request: Request) -> Optional[str]:
    brut = request.headers.get("authorization", "")
    if brut[:7].lower() == "bearer " and brut[7:].strip():
        return "Bearer " + brut[7:].strip()
    return None


def _adresses_appelant(request: Request) -> List[str]:
    """Adresses vues de l'administrateur (nginx pose X-Real-IP / X-Forwarded-For) : on ne le bannit jamais lui-même.
    Un en-tête forgé ne peut qu'ajouter des refus (échec fermé), jamais en retirer."""
    out = []
    for nom in ("x-real-ip", "x-forwarded-for"):
        out += [a.strip() for a in request.headers.get(nom, "").split(",") if a.strip()][:16]
    if request.client and request.client.host:
        out.append(request.client.host)
    return out


def _empreinte_du_corps(corps: Any) -> Optional[str]:
    e = corps.get("empreinte") if isinstance(corps, dict) else None
    return e if isinstance(e, str) and _EMPREINTE.match(e) else None


async def _action(action: str, corps: Any, request: Request, payload: Dict[str, Any]) -> JSONResponse:
    emp = _empreinte_du_corps(corps)
    simuler = corps.get("simuler", False) if isinstance(corps, dict) else False
    if emp is None or not isinstance(simuler, bool):
        return JSONResponse(status_code=400, content={"error": "corps attendu : {\"empreinte\": <64 hex>, \"simuler\": bool}",
                                                      "cause": "corps"})
    par = str((payload or {}).get("sub") or "inconnu")
    code, rep = await asyncio.to_thread(_traiter, action, emp, simuler, par, _porteur(request),
                                        _entetes_appelant(request), _adresses_appelant(request))
    if not simuler:
        with _VERROU:
            _CACHE.clear()  # la file d'approbation a changé : « À valider » se relit au prochain appel
    return JSONResponse(status_code=code, content=rep)


@router.post("/approve")
async def approuver(corps: Dict[str, Any], request: Request, payload: Dict[str, Any] = Depends(require_jwt)):
    return await _action("approuve", corps, request, payload)


@router.post("/refuse")
async def refuser(corps: Dict[str, Any], request: Request, payload: Dict[str, Any] = Depends(require_jwt)):
    return await _action("refuse", corps, request, payload)


@router.post("/reprendre")
async def reprendre(corps: Dict[str, Any], payload: Dict[str, Any] = Depends(require_jwt)):
    """Débloque une décision restée `en_cours` (processus interrompu pendant les appels au WAF) : retour `en_attente`
    seulement si la demande est plus vieille que le délai maximal de ses appels au WAF + 60 s."""
    emp = _empreinte_du_corps(corps)
    if emp is None:
        return JSONResponse(status_code=400, content={"error": "corps attendu : {\"empreinte\": <64 hex>}", "cause": "corps"})
    par = str((payload or {}).get("sub") or "inconnu")
    try:
        r = await asyncio.to_thread(defense_etat.reprendre, emp, par, DELAI_WAF_S)
    except defense_etat.PasBloquee as e:
        return JSONResponse(status_code=409, content={"error": f"décision non bloquée : {e}", "cause": "pas_bloquee"})
    except defense_etat.AuditIndisponible:
        return JSONResponse(status_code=503, content={"error": "audit indisponible : rien n'est repris",
                                                      "cause": "audit_indisponible"})
    except defense_etat.EtatIndisponible:
        return JSONResponse(status_code=503, content={"error": "base d'état indisponible", "cause": "base_indisponible"})
    with _VERROU:
        _CACHE.clear()
    return {"etat": "en_attente", "resultat": f"décision reprise (demande vieille de {r['age_s']} s) : à nouveau en attente"}


@router.get("/proposals", dependencies=[Depends(require_lecture)])
async def proposals(admin: bool = Depends(_est_admin)):
    """Propositions d'actord et état de la décision de chacune (par empreinte, dernière génération). Adresses et
    empreinte : administrateur seulement (`cible-N` sinon ; l'empreinte d'une IPv4 se retrouve par force brute).
    Jamais en cache : l'état d'une décision doit se voir dès qu'il change."""
    def calcul():
        r = _lire_propositions()
        # `admin` : la page n'affiche les boutons qu'à un administrateur réel (le POST reste gardé par require_jwt)
        out: Dict[str, Any] = {**_mode_vivant(), "admin": admin, "shadow": None, "genere_le": None, "propositions": [],
                               "sources": _sources({"actord": r})}
        if not r["ok"]:
            return out
        d = r["donnees"] if isinstance(r["donnees"], dict) else {}
        out["shadow"] = d.get("shadow") if isinstance(d.get("shadow"), bool) else None
        out["genere_le"] = _iso(d.get("genere_le"))
        try:
            etats: Optional[Dict[str, str]] = defense_etat.etats_decisions()
            auteurs = defense_etat.auteurs_decisions()
        except defense_etat.EtatIndisponible:
            etats, auteurs, out["etat_base"] = None, {}, "indisponible"
        masque: Dict[str, str] = {}
        for p in _propositions(r):
            if admin:
                cible, motif = ", ".join(p["ips"]), p["motif"]
            else:
                cible = ", ".join(masque.setdefault(ip, f"cible-{len(masque) + 1}") for ip in p["ips"])
                motif = _masquer(p["motif"], masque) if p["motif"] else None
            ligne = {
                "id": p["id"], "menace_id": p["menace_id"], "cible": cible, "geste": p["geste"], "score": p["score"],
                "bande": p["bande"], "motif": motif, "validation_humaine": echelle.exige_validation(p["bande"]),
                "etat": etats.get(p["empreinte"], "en_attente") if etats is not None else None,
                "ttl_s": p["ttl_s"], "executable": p["geste"] in GESTES_EXECUTABLES}
            if auteurs.get(p["empreinte"]) == sade_auto.OPERATEUR:
                ligne["auto"] = True  # seul le fait « automatique » sort, jamais le nom d'un opérateur humain
            if admin:
                ligne["empreinte"] = p["empreinte"]
            out["propositions"].append(ligne)
        return out
    return await asyncio.to_thread(calcul)
