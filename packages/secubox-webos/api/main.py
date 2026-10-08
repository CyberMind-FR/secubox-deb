# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — API registre normalisé (P1)."""
import asyncio
import json
import time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

# LE HALL EST LA COUCHE D'USAGER (#1581) : ses routes demandent une session,
# pas l'administration ; ce qu'il relaie à un module, ce module le juge.
from secubox_core.auth import require_session, require_personne, create_token, domaine_box
from secubox_core.health import systemd_batch
from api.models import Service
from api import registry, flags, cardlets, actions, aide, hotes
from secubox_core.auth import require_lecture

_cache: dict = {"services": [], "computed_at": None}
_flags: dict = flags.load_flags()
_CACHE_FILE = Path("/var/cache/secubox/webos/services.json")


def _live_sockets(sock_dir: str = "/run/secubox") -> frozenset:
    """Ids joignables via socket (agrégateur ou daemon propre) — signal de santé."""
    try:
        return frozenset(p.stem for p in Path(sock_dir).glob("*.sock"))
    except Exception:
        return frozenset()


def _recompute() -> bool:
    """Read menu/health/exposure sources and refresh `_cache` in place.

    Rend False, SANS toucher au registre, quand le menu du hub est absent ou
    vide : un registre vidé fait retomber le Hall sur sa maquette.
    """
    menu = registry.load_menu_cache()
    if not menu.get("categories"):
        return False
    health = systemd_batch()
    expo = registry.load_exposure_cache()
    svcs = registry.normalize_services(menu, health, expo, sockets=_live_sockets())
    _cache["services"] = [s.model_dump() for s in svcs]
    _cache["computed_at"] = time.time()
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(_cache))
    except Exception:
        pass
    return True


async def _refresh_loop() -> None:
    while True:
        try:
            if not _recompute():
                # Menu absent : on réveille le hub (hors boucle d'événements).
                await asyncio.to_thread(registry.reveille_hub)
        except Exception:
            pass
        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _flags
    _flags = flags.load_flags()
    if _CACHE_FILE.exists():
        try:
            _cache.update(json.loads(_CACHE_FILE.read_text()))
        except Exception:
            pass
    _charge_broadcast()   # #1224 : reprendre le flux courant apres redemarrage
    _charge_hist()        # #1360 : historique global des broadcasts + likes
    if _broadcast.get("actif"):   # le flux courant entre dans l'historique global
        _hist_ajoute(_broadcast)
    task = asyncio.create_task(_refresh_loop())
    t_hotes = asyncio.create_task(hotes.boucle(domaine_box))   # #1670
    yield
    task.cancel()
    t_hotes.cancel()


app = FastAPI(title="SecuBox WebOS", root_path="/api/v1/webos", lifespan=lifespan)
public_router = APIRouter(prefix="/public")
router = APIRouter()


def _enabled() -> bool:
    return bool(_flags.get("enabled"))


_PUBLIC_FIELDS = ("id", "name", "description", "category", "icon", "installed", "active")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@public_router.get("/services")
async def public_services():
    """Minimal, unauthenticated projection — never leaks urls/latency/reach."""
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    out = []
    for s in _cache["services"]:
        row = {k: s[k] for k in _PUBLIC_FIELDS if k in s}
        row["health"] = {"state": (s.get("health") or {}).get("state", "unknown")}
        # `path` (relatif, non sensible) : nécessaire pour construire l'URL de la
        # webui admin embarquée (admin.gk2.secubox.in<path>) côté Hall (#1175).
        row["path"] = (s.get("urls") or {}).get("path") or ("/" + s["id"] + "/")
        out.append(row)
    return {"services": out, "computed_at": _cache["computed_at"]}


# ── DIFFUSION PARTAGEE — le Broadcaster (#1224, MVP a/overlay) ───────────────
# UN flux courant propose au parc : une URL (YouTube via le BiB/ytsas pour
# l'instant), posee par un utilisateur, vue par TOUS dans l'overlay « 📡 direct »
# du Hall. C'est l'inverse du BiB (un-vers-plusieurs). Etat en memoire + fichier
# (survit au redemarrage). NO-RETENTION : on ne garde que le POINTEUR, jamais le
# media. GET public (tout le parc regarde). POSER ou AIMER une diffusion est
# reserve aux PERSONNES (require_personne, #1608) : pas un visiteur, pas un
# appareil invite. L'URL passe par une liste blanche et le debit est borne.
_BROADCAST_FILE = Path("/var/cache/secubox/webos/broadcast.json")
_broadcast: dict = {"actif": False}


def _charge_broadcast() -> None:
    global _broadcast
    try:
        _broadcast = json.loads(_BROADCAST_FILE.read_text())
    except (OSError, ValueError):
        _broadcast = {"actif": False}


def _sauve_broadcast() -> None:
    try:
        _BROADCAST_FILE.parent.mkdir(parents=True, exist_ok=True)
        _BROADCAST_FILE.write_text(json.dumps(_broadcast))
    except OSError:
        pass


# HISTORIQUE GLOBAL DES BROADCASTS + LIKES (#1360). Chaque diffusion posee est
# ajoutee a une liste bornee, partagee par TOUT le parc (contrairement a
# l'historique perso, en localStorage cote navigateur). Un like par url. Meme
# modele NO-RETENTION : on ne garde que le pointeur (url + titre), jamais le media.
_HIST_FILE = Path("/var/cache/secubox/webos/broadcast_hist.json")
_hist: list = []


def _charge_hist() -> None:
    global _hist
    try:
        _hist = json.loads(_HIST_FILE.read_text())
    except (OSError, ValueError):
        _hist = []


def _sauve_hist() -> None:
    try:
        _HIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        _HIST_FILE.write_text(json.dumps(_hist[:80]))
    except OSError:
        pass


def _hist_ajoute(b: dict) -> None:
    global _hist
    url = (b or {}).get("url", "")
    if not url:
        return
    for h in _hist:
        if h.get("url") == url:
            h["ts"] = b.get("ts")
            h["titre"] = b.get("titre") or h.get("titre")
            h["par"] = b.get("par") or h.get("par")
            _hist.remove(h)
            _hist.insert(0, h)
            _sauve_hist()
            return
    _hist.insert(0, {"url": url, "titre": b.get("titre", ""), "par": b.get("par", ""),
                     "ts": b.get("ts"), "likes": 0})
    del _hist[80:]
    _sauve_hist()


# LISTE BLANCHE DES URL DIFFUSABLES (#1608) : chemins de MEME ORIGINE (le flux
# souverain /api/v1/ytsas/stream/<id>, #1237), noms https du domaine de la box,
# et les lecteurs YouTube que le BiB sait relayer. Rien d'autre.
_HOTES_EXTERNES = frozenset({"www.youtube.com", "youtube.com", "m.youtube.com",
                             "youtu.be", "www.youtube-nocookie.com"})


def _url_diffusable(url: str) -> bool:
    from urllib.parse import urlsplit
    if url.startswith("/") and not url.startswith("//") and "\\" not in url:
        return True
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        return False
    h = u.hostname.lower().rstrip(".")
    dom = (domaine_box() or "").lower()
    return h in _HOTES_EXTERNES or bool(dom) and (h == dom or h.endswith("." + dom))


# DEBIT : quelques gestes par minute et par personne suffisent a l'usage.
_DEBIT: dict = {}


def _debit_ok(qui: str, geste: str, maxi: int, fenetre: float = 60.0) -> bool:
    maint = time.time()
    cle = (qui, geste)
    t = [x for x in _DEBIT.get(cle, []) if maint - x < fenetre]
    if len(t) >= maxi:
        _DEBIT[cle] = t
        return False
    t.append(maint)
    _DEBIT[cle] = t
    return True


_AIME: dict = {}     # url -> personnes qui l'ont aimee (memoire, un ♥ par personne)


@public_router.get("/broadcast")
async def get_broadcast():
    """Le flux courant du parc, ou {actif:false} si rien ne diffuse."""
    return _broadcast


@public_router.post("/broadcast")
async def set_broadcast(payload: dict, qui: dict = Depends(require_personne)):
    """Poser (ou couper) le flux courant. `url` vide = on coupe la diffusion."""
    global _broadcast
    url = str((payload or {}).get("url", "")).strip()
    if not _debit_ok(str(qui.get("sub")), "diffuse", 10):
        return JSONResponse({"detail": "Trop de diffusions, réessayez dans une minute"}, status_code=429)
    if url and not _url_diffusable(url):
        return JSONResponse({"detail": "Adresse non diffusable"}, status_code=422)
    if not url:
        _broadcast = {"actif": False}
    else:
        # POS + TS (#1237) : position de lecture du broadcaster au moment ou il
        # diffuse. Le direct s'y resynchronise : live = pos + (now - ts).
        try:
            pos = float(payload.get("pos", 0) or 0)
        except (TypeError, ValueError):
            pos = 0.0
        _broadcast = {
            "actif": True, "url": url[:2000],
            "titre": str(payload.get("titre", ""))[:200],
            "par": str(payload.get("par", ""))[:80],
            "pos": max(0.0, pos), "ts": time.time(),
        }
    if _broadcast.get("actif"):
        _hist_ajoute(_broadcast)
    _sauve_broadcast()
    return _broadcast


@public_router.get("/broadcasts")
async def get_broadcasts():
    """Historique GLOBAL des broadcasts du parc (récents + tops par likes)."""
    recents = _hist[:24]
    tops = sorted((h for h in _hist if h.get("likes", 0) > 0),
                  key=lambda h: h.get("likes", 0), reverse=True)[:12]
    return {"recents": recents, "tops": tops, "total": len(_hist)}


@public_router.post("/broadcast/like")
async def like_broadcast(payload: dict, qui: dict = Depends(require_personne)):
    """Un ♥ sur un broadcast de l'historique (par url), un par personne."""
    url = str((payload or {}).get("url", "")).strip()
    sub = str(qui.get("sub"))
    if not _debit_ok(sub, "aime", 30):
        return JSONResponse({"detail": "Trop de gestes, réessayez dans une minute"}, status_code=429)
    for h in _hist:
        if h.get("url") == url:
            deja = _AIME.setdefault(url, set())
            if sub in deja:
                return {"url": url, "likes": int(h.get("likes", 0))}
            deja.add(sub)
            h["likes"] = int(h.get("likes", 0)) + 1
            _sauve_hist()
            return {"url": url, "likes": h["likes"]}
    return {"url": url, "likes": 0}


_rc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/radio")
async def cardlet_radio():
    """Cardlet Radio (now-playing) — lue côté serveur via radio.sock, cache 5 s."""
    now = time.time()
    if _rc["d"] and now - _rc["t"] < 5:
        return _rc["d"]
    # radio_cardlet_safe fait de l'I/O socket BLOQUANTE : hors du thread, elle
    # gèle la boucle uvicorn (single-worker) → 502 sur tout le module (#1175).
    d = await asyncio.to_thread(cardlets.radio_cardlet_safe)
    _rc["d"], _rc["t"] = d, now
    return d


# Cardlets DISPONIBLES (#1231). Le Hall demandait ses cardlets par une liste
# ecrite en dur dans sa page : chaque nouveau cardlet obligeait a la modifier.
# Il decouvre desormais ce qui existe. Ajouter un cardlet = une entree ici, et
# l'accueil s'en saisit sans qu'on y touche.
CARDLETS_DISPONIBLES = ["radio", "waf", "podcaster"]


# ── AIDE DES CARTES (#1664) ─────────────────────────────────────────────────
# Une source (api/aide_cartes.json) pour la bulle ❓, la vue Aide et ZIA/Lexie.
# Les chiffres sont lus EN VISITEUR (voir api/aide.py) : l'aide ne montre rien
# qu'un visiteur ne puisse déjà lire ; les métriques `session` sont complétées
# par le Hall avec les droits de la personne.
_aide_lecteur: "aide.Lecteur | None" = None


def _aide():
    global _aide_lecteur
    if _aide_lecteur is None:
        _aide_lecteur = aide.Lecteur(domaine_box())
    return _aide_lecteur


def _etat_service(sid: str) -> str:
    for s in _cache["services"]:
        if s.get("id") == sid:
            return (s.get("health") or {}).get("state", "unknown")
    return ""


@public_router.get("/aide/cartes")
async def aide_cartes():
    """Toutes les cartes : rôle, usage, métriques déclarées (sans valeurs)."""
    return {"cartes": [aide.publique(c) for c in aide.charger().values()]}


@public_router.get("/aide/trouver")
async def aide_trouver(q: str = ""):
    """La carte que désigne une phrase (« à quoi sert la carte Radio ? »),
    avec sa phrase parlée — l'unique logique de reconnaissance, pour ZIA."""
    c = aide.trouver(aide.charger(), q[:200])
    if not c:
        return {"carte": None}
    return {"carte": await aide_carte(c["id"])}


@public_router.get("/aide/cartes/{cid}")
async def aide_carte(cid: str):
    """Une carte, ses chiffres vivants (vus d'un visiteur) et sa phrase."""
    c = aide.charger().get(cid)
    if not c:
        return JSONResponse({"detail": "carte inconnue"}, status_code=404)
    m = await _aide().metriques(c)
    out = aide.publique(c)
    for decl, vive in zip(out["metriques"], m):
        decl["valeur"] = vive["valeur"]
    out["etat"] = _etat_service(c.get("service") or "") if c.get("service") else ""
    out["phrase"] = aide.phrase(c, m)
    return out


# ── HÔTES LOCAUX (#1670) ────────────────────────────────────────────────────
# Chargé AVANT domaine.js par le Hall : la liste des noms que cette box sert
# vraiment. Une carte vise le service local s'il y figure, celui de la box de
# référence sinon. Script (et non JSON) : la page le lit sans requête bloquante.
# LES NOMS QUE CETTE BOX SERT POUR SON DOMAINE (#1682). Lus par le relais du
# maillage pour exposer le nœud par défaut : server_name exacts du domaine de la
# box et « x.* » ramenés à ce domaine. Sans vérification de joignabilité (c'est
# précisément ce que le relais va établir) ; rien d'autre que des noms.
@public_router.get("/noms")
async def noms_de_la_box():
    dom = (domaine_box() or "").lower()
    return {"domaine": dom, "noeud": hotes.nom_noeud(),
            "noms": hotes.candidats(hotes.lire_sites(), dom)}


@public_router.get("/hotes.js")
async def hotes_js():
    corps = ("window.SBX_HOTES_LOCAUX=" + json.dumps(hotes.locaux()) + ";\n"
             # Le nom de CE nœud pour la barre d'état (#1680) — jamais « gk2 » en dur.
             "window.SBX_NOEUD=" + json.dumps(hotes.nom_noeud()) + ";\n")
    return Response(corps, media_type="application/javascript",
                    headers={"Cache-Control": "max-age=120"})


@public_router.get("/cardlets")
async def cardlets_index():
    """Liste des cardlets servis, pour que l'accueil les decouvre."""
    return {"cardlets": CARDLETS_DISPONIBLES, "count": len(CARDLETS_DISPONIBLES)}


_wc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/waf")
async def cardlet_waf(request: Request):
    """Cardlet WAF (posture) — lue côté serveur via waf.sock, cache 20 s (#1228).

    Les adresses de l'activité récente ne sont rendues qu'à une session
    reconnue ; un visiteur voit pays, catégorie et action (#1608)."""
    d = await _cardlet_waf_cache()
    if _session_reconnue(request):
        return d
    return {**d, "recent": [{k: v for k, v in r.items() if k != "ip"}
                            for r in (d.get("recent") or [])]}


def _session_reconnue(request: Request) -> bool:
    from secubox_core import auth as _a
    jetons = [request.cookies.get(_a.SESSION_COOKIE) or ""]
    z = request.headers.get("authorization", "")
    if z.lower().startswith("bearer "):
        jetons.append(z[7:].strip())
    return any(j and _a._validate_token(j) for j in jetons)


async def _cardlet_waf_cache():
    """Posture WAF, cache 20 s.

    Cache PLUS LONG que celui de la Radio : un now-playing change de titre en
    trois minutes, une posture de pare-feu bouge en dizaines de minutes.
    Interroger trois points d'entrée toutes les cinq secondes chargerait la box
    pour montrer le même chiffre — c'est exactement le travers qu'on vient de
    corriger ailleurs (#1210).
    """
    now = time.time()
    if _wc["d"] and now - _wc["t"] < 20:
        return _wc["d"]
    # Comme la Radio : l'I/O socket est BLOQUANTE, elle gèlerait la boucle
    # uvicorn mono-ouvrier et rendrait 502 tout le module (#1175).
    d = await asyncio.to_thread(cardlets.waf_cardlet_safe)
    _wc["d"], _wc["t"] = d, now
    return d


# ── « QUI FRAPPE ? » — caractérisation d'attaquants (#1240) ──────────────────
# La carte Pare-feu dit « suis-je couvert ». Celle-ci dit « QUI frappe, et
# comment » : elle lit la synthèse de campagnes produite par sbxwaf --correlate
# (secubox-waf-campaigns.timer -> campaigns.json, world-readable), enrichie de la
# lecture « negative space » (recon / sondes haute-valeur). Lecture seule ; on ne
# recopie pas la logique du WAF, on affiche ce qu'il a déjà corrélé.
_WAF_CAMPAIGNS = Path("/var/cache/secubox/waf/campaigns.json")
_qf = {"d": None, "t": 0.0}


def _lire_qui_frappe() -> dict:
    """Résume campaigns.json pour la carte. Toute panne -> carte vide, jamais 500."""
    try:
        raw = json.loads(_WAF_CAMPAIGNS.read_text())
    except Exception:
        return {"ok": False, "attaquants": 0, "campagnes_total": 0,
                "haute_valeur": 0, "campagnes": []}
    camps = raw.get("campagnes") or []
    # On met en TÊTE ce qui vise des secrets (haute valeur), pas le plus bruyant :
    # un balayage de 10 000 sondes sans valeur intéresse moins qu'une campagne de
    # 12 IP qui cherche des `.env`. À valeur égale, le volume départage.
    top = sorted(camps, key=lambda c: (int(c.get("haute_valeur", 0) or 0),
                                       int(c.get("sondes", 0) or 0)), reverse=True)[:5]

    def norm(c: dict) -> dict:
        return {
            "signature": (c.get("signature") or "")[:8],
            "outil": c.get("outil") or "",
            "attaquants": len(c.get("attaquants") or []),
            "sondes": int(c.get("sondes", 0) or 0),
            "haute_valeur": int(c.get("haute_valeur", 0) or 0),
            # #1243 : la sequence de sondes = empreinte de workflow (couche analyse).
            "sequence": (c.get("exemple_sequence") or [])[:8],
        }

    return {
        "ok": True,
        "attaquants": int(raw.get("attaquants", 0) or 0),
        "campagnes_total": len(camps),
        "haute_valeur": sum(int(c.get("haute_valeur", 0) or 0) for c in camps),
        "campagnes": [norm(c) for c in top],
    }


@public_router.get("/waf/qui-frappe")
async def waf_qui_frappe():
    """Caractérisation d'attaquants — MÊME sous-couche que la carte Pare-feu
    (#1240). Lecture SERVEUR de campaigns.json (agrégat de posture : compteurs de
    campagnes, pas de donnée nominative), sans jeton navigateur — car l'état
    « connecté » du Hall n'est pas un JWT en localStorage, et exiger un Bearer
    affichait « Session requise » à un utilisateur pourtant connecté. La carte
    reste masquée pour un invité (data-auth) ; ce endpoint ne fait que la remplir
    quand elle est visible, exactement comme /public/cardlets/waf."""
    now = time.time()
    if _qf["d"] and now - _qf["t"] < 30:
        return _qf["d"]
    d = await asyncio.to_thread(_lire_qui_frappe)
    _qf["d"], _qf["t"] = d, now
    return d


_pc = {"d": None, "t": 0.0}


@public_router.get("/cardlets/podcaster")
async def cardlet_podcaster():
    """Cardlet Podcaster (bibliothèque) — lue via podcaster.sock, cache 30 s.

    Cache le plus long des trois : un épisode arrive toutes les heures au mieux.
    Interroger plus souvent afficherait le même titre en chargeant la box.
    """
    now = time.time()
    if _pc["d"] and now - _pc["t"] < 30:
        return _pc["d"]
    d = await asyncio.to_thread(cardlets.podcaster_cardlet_safe)
    _pc["d"], _pc["t"] = d, now
    return d


_mbbs = {"d": None, "t": 0.0}


@public_router.get("/menu/bbs")
async def menu_bbs():
    """Sous-menu BBS (rubriques) — « navbar embarquée » lue via bbs.sock, cache 30 s."""
    now = time.time()
    if _mbbs["d"] and now - _mbbs["t"] < 30:
        return _mbbs["d"]
    d = await asyncio.to_thread(cardlets.bbs_menu_safe)
    _mbbs["d"], _mbbs["t"] = d, now
    return d


@router.get("/services")
async def services(user=Depends(require_session)):
    """Full registry — JWT-gated."""
    if not _enabled():
        return {"services": [], "computed_at": _cache["computed_at"]}
    return {"services": _cache["services"], "computed_at": _cache["computed_at"]}


# ── DÉLÉGATION D'ACCÈS (#1288) ─────────────────────────────────────────────
#
# Deux routes PUBLIQUES, et elles le sont a dessein : une carte doit pouvoir
# demander si elle a un acces, et en deposer la demande. Ni l'une ni l'autre ne
# revele quoi que ce soit — la premiere rend deux booleens, la seconde inscrit
# une ligne dans une file bornee. Tout ce qui accorde, lit ou pose un secret est
# derriere le jeton.

# AUCUNE DE CES ROUTES N'EST PUBLIQUE, ET C'EST UNE CORRECTION (#1289).
#
# La premiere version exposait l'etat et le depot de demande sans jeton. C'etait
# un trou : le Hall est joignable sur le reseau local sans se connecter, donc
# n'importe qui pouvait deposer des demandes — et, une fois un acces accorde,
# n'importe qui aurait lu les donnees deleguees a travers la carte.
#
# UN AVATAR RASSEMBLE PLUSIEURS IDENTITES : encore faut-il savoir de QUEL
# avatar il s'agit. Un profil annonce par la page serait declaratif — il suffit
# de pretendre etre quelqu'un d'autre. La personne vient donc du JETON, seul
# endroit ou elle est prouvee. Sans jeton, pas d'identite, donc rien a voir et
# rien a demander : la carte affiche « connectez-vous », ce qui est la verite.

_QUI_OK = "abcdefghijklmnopqrstuvwxyz0123456789._-"


def _qui_sur(sub: str) -> str:
    """Un `sub` assaini : il sert de nom de dossier dans le coffre, et un
    identifiant venu d'un jeton reste un identifiant venu du réseau."""
    q = "".join(c for c in str(sub or "").lower() if c in _QUI_OK)[:64]
    return q or "_"


def _qui(user) -> str:
    """La clé du coffre : la PERSONNE (#1562), plus l'appareil.

    Rangé par `sub` (sbx-…, gk2), le coffre d'une personne à deux appareils
    était deux coffres vides, quand l'Identity Manager crée ses comptes — et
    y pose désormais ses accès — par personne. Session sans personne
    (appareil non rattaché, compte système seul) : l'ancienne clé, inchangée.
    Au premier passage d'un appareil, son ancien coffre est REPRIS dans celui
    de la personne (déplacé, jamais écrasé)."""
    user = user or {}
    ancien = _qui_sur(user.get("sub"))
    try:
        from secubox_core.capacites import personne_du_porteur  # noqa: PLC0415
        from secubox_core import coffre  # noqa: PLC0415
        per = personne_du_porteur(user)
        cle = coffre.cle_personne(per["user_uuid"]) if per else None
    except Exception:  # noqa: BLE001 — jamais une panne du coffre pour une clé
        cle = None
    if not cle:
        return ancien
    if ancien != "_":
        coffre.reprend(ancien, cle)
    return cle


def _etiquette(compte: str) -> str:
    """Ce qu'on AFFICHE pour ce porteur — distinct de ce qui l'IDENTIFIE.

    `qui_sur()` assainit le `sub` pour en faire une clé de fichier sûre ; ce
    n'est pas un nom, et l'afficher tel quel donnait « sbx-3704f0234ea3 » dans
    la barre du Hall. Un appareil a pourtant un nom : celui que son porteur a
    déclaré à l'admission, et que l'administrateur a lu pour décider.

    Ce nom N'IDENTIFIE RIEN — il vient d'un formulaire ouvert, deux appareils
    peuvent déclarer le même. C'est précisément pour ça qu'il est cantonné à
    l'affichage, et que le compte, lui, dérive de la clé.
    """
    try:
        from secubox_core import appareils
        a = appareils.get(compte)
        if a and a.get("nom"):
            return str(a["nom"])[:60]
    except Exception:
        pass
    return compte


def _etiquette_porteur(user) -> str:
    """L'étiquette de la SESSION, jamais celle de la clé du coffre.

    Depuis le coffre par personne (#1562), `qui` vaut « p-<uuid> » : l'afficher
    montrait cet identifiant dans la barre du Hall au lieu de « gek » — ni
    perdu ni usurpé, mais illisible et inquiétant. La personne s'affiche par
    son pseudo ; sans personne, l'appareil par son nom, comme avant."""
    user = user or {}
    try:
        from secubox_core.capacites import personne_du_porteur  # noqa: PLC0415
        per = personne_du_porteur(user)
        if per and per.get("pseudo"):
            return str(per["pseudo"])[:60]
    except Exception:  # noqa: BLE001 — une étiquette ne tombe jamais en panne
        pass
    return _etiquette(_qui_sur(user.get("sub")))


# ── ACTIONS DES MODULES (#1314) ────────────────────────────────────────────
#
# SOUS JETON, ET SOUS LISTE CLOSE. L'API d'administration repond `400` et non
# `401` a un POST sans jeton : elle n'est pas authentifiee, et la relayer telle
# quelle ouvrirait l'ajout de torrents a tout le reseau local, sur un Hall
# joignable sans se connecter. L'autorisation est donc la NOTRE.

def _porteur(request: Request) -> str:
    """Le jeton brut presente par l'appelant, s'il y en a un.

    `require_session` rend la CHARGE du jeton, pas le jeton : pour le relayer a un
    module qui protege ses propres routes, il faut la chaine d'origine.
    """
    a = request.headers.get("authorization") or ""
    return a[7:].strip() if a[:7].lower() == "bearer " else ""


# ── LE DEPOT PUBLIC ────────────────────────────────────────────────────────
#
# CES DEUX ROUTES NE SONT PAS PROTEGEES PAR JWT, ET C'EST LE POINT.
# Deposer un fichier a la box ne demande aucun compte : c'est la raison d'etre
# de cet espace, et le service l'expose deja publiquement sur son domaine. Les
# proteger ici reviendrait a offrir dans la carte une chose plus fermee que ce
# que le service offre a tout le monde — sans rien fermer, puisque l'autre
# porte reste ouverte.
#
# Ce qu'on ne perd pas au passage : l'adresse d'origine, transmise au service
# pour que son limiteur de debit continue de compter par machine.
#
# DECLAREES AVANT LA ROUTE GENERIQUE : `/actions/{module}/{action}` les
# capturerait, FastAPI retenant la premiere qui correspond.
@router.get("/depot/reglages", dependencies=[Depends(require_lecture)])
async def depot_reglages():
    """Les plafonds du depot, avant l'envoi."""
    return await actions.reglages_depot()


@router.post("/depot")
async def depot_public(request: Request):
    """Relayer un depot vers le service, en flux."""
    code, corps = await actions.relaie_depot(request)
    return JSONResponse(status_code=code, content=corps)


@router.get("/actions/{module}/{action}")
async def action_lecture(module: str, action: str, request: Request,
                         user=Depends(require_session)):
    """Les actions de LECTURE — une liste, un historique, un etat."""
    return await actions.agir(module, action, None, _porteur(request))


# LECTURE PUBLIQUE DES MEDIAS PARTAGES DU PARC (#1237). Le depot, ytsas et
# torrent sont des medias PARTAGES : leur liste/etat se voient sans session
# (cardlets pleins meme en invite). AGIR (POST) reste protege par la session.
# Whitelist stricte : aucun autre module n'est expose sans auth.
_LECTURE_PUBLIQUE = {"droplet", "ytsas", "torrent"}


@public_router.get("/actions/{module}/{action}")
async def action_lecture_publique(module: str, action: str, request: Request):
    """Liste/etat sans session pour les modules media partages du parc."""
    if module not in _LECTURE_PUBLIQUE:
        return JSONResponse({"detail": "auth requise"}, status_code=401)
    return await actions.agir(module, action, None, _porteur(request))


@router.post("/actions/{module}/{action}")
async def action_ecriture(module: str, action: str, request: Request,
                          corps: dict | None = None,
                          user=Depends(require_session)):
    """Les actions qui MODIFIENT. Le corps n'est lu que pour les champs que
    l'action declare : ce qui n'est pas nomme n'est pas transmis."""
    return await actions.agir(module, action, corps or {}, _porteur(request))


# ── PASSAGE DE JETON ENTRE DEUX DOMAINES (#1305) ───────────────────────────
#
# Le temoin de session porte `.gk2.secubox.in` : sur hall.gk2.net, le
# navigateur ne l'envoie JAMAIS. Ce n'est pas un reglage rate — c'est la regle
# qui empeche un site de poser des temoins valables pour un autre, et aucun
# reglage ne la contourne.
#
# On passe donc un JETON, pas un temoin. Cette route est appelee depuis le
# domaine SecuBox, ou la session VAUT : elle frappe un jeton court au nom de la
# personne deja authentifiee, que la page de relais renverra dans le FRAGMENT
# de l'URL de retour.
#
# LE FRAGMENT ET RIEN D'AUTRE. Ce qui suit `#` ne part pas au serveur : ni dans
# les journaux d'acces, ni dans le `Referer`, ni dans un cache de proxy. Un
# jeton dans la requete finirait dans les trois.

# Une heure. Assez pour ouvrir une session de travail, trop peu pour qu'un
# jeton oublie dans un historique serve encore demain.
DUREE_JETON = 3600


@router.post("/jeton")
async def frappe_jeton(user=Depends(require_session)):
    """Un jeton court, pour la personne DEJA authentifiee ici.

    ON REJOUE LA MEME SESSION, ON N'EN CREE PAS UNE AUTRE (#1306).
    La validation exige qu'un `jti` nomme une session VIVANTE du magasin :
    frapper un jeton avec un jti neuf produisait un jeton toujours refuse —
    « Token invalide ou expire » — et rendait le relais inutile.

    On reprend donc le jti de la session presentee. Trois consequences, toutes
    souhaitables : le jeton relaye est la MEME session vue d'un autre domaine ;
    se deconnecter le tue partout d'un coup ; et l'on n'ajoute aucune session a
    revoquer, donc aucune surface de plus.
    """
    sub = (user or {}).get("sub")
    jti = (user or {}).get("jti")
    if not sub or not jti:
        return {"ok": False, "detail": "session sans identite exploitable"}
    return {"ok": True, "jeton": create_token(sub, expires_in=DUREE_JETON, jti=jti),
            "expire_dans": DUREE_JETON}


@router.get("/session")
async def session_courante(user=Depends(require_session)):
    """Qui est connecté, et sous quel nom on l'affiche.

    Le Hall SONDE sa session ici : une route protégée qui répond 200 est la
    seule preuve qui vaille. Elle remplace `GET /acces`, qui rendait aussi les
    accès délégués (retirés, #1857) — l'identité est celle de l'Identity
    Manager (secubox-sbxid)."""
    return {"qui": _qui(user), "etiquette": _etiquette_porteur(user)}


@router.get("/sbxos/manifeste")
async def sbxos_manifeste(request: Request):
    """Manifeste de session de SBXOS (#1610) : rôle, LAN, domaine, Espaces,
    modules et capacités, calculés par la box selon l'appelant."""
    from api import sbxos_manifeste as sm
    from secubox_core.auth import domaine_box
    lan = request.headers.get("X-SecuBox-LAN", "").strip() == "1"
    dom = domaine_box() or (request.headers.get("host", "").split(":")[0])
    try:
        corps = sm.construire(sm.role_de(request), lan, dom)
    except (OSError, ValueError) as e:
        return JSONResponse({"detail": f"manifeste indisponible : {e.__class__.__name__}"},
                            status_code=503, headers={"Cache-Control": "no-store"})
    return JSONResponse(corps, headers={"Cache-Control": "private, no-store", "Vary": "Cookie"})


app.include_router(public_router)
app.include_router(router)
