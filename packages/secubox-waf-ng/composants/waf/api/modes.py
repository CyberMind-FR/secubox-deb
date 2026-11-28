# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Page Modes du WAF (#3741) : mode de chaque catégorie, touches sur 7 jours, leurres de service, hôtes PHP.

L'API tourne sous `secubox` et ne lit ni n'écrit /etc/secubox/waf (0750 root) : tout passe par deux commandes
root à lignes sudoers EXACTES, l'entrée en JSON sur STDIN :

- `secubox-cvectl waf-modes lister|appliquer` (secubox-security-posture) : écriture de waf-rules.json par
  `leurres.ecrire_regles` (verrou, copie de retour, validation, relecture, rollback, audit) ;
- `wafctl leurres-modes lister|ecrire` : leurres-modes.json (relu à chaud par sbx-authwatch) ;
- `wafctl php-sites lister|ecrire|detecter` (#3974) : sites PHP détectés et exceptions, qui calculent php_hotes de
  vhost_profiles.json (relu à chaud par sbxwaf). `GET /php-hotes` reste en lecture (ancienne vue).

Codes des commandes : 0 → 200, 2 → 422, 3 → 409, 4 → 404, autre ou délai → 503 `ctl`. Toute écriture réussie
est auditée avec `lever=True` : un changement fait dont l'audit manque rend 500, jamais caché.
"""
from __future__ import annotations

import asyncio
import contextlib
import gzip
import ipaddress
import json
import time
import logging
import os
import re
import subprocess
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from glob import glob
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from secubox_core.auth import require_jwt, require_lecture

log = logging.getLogger("secubox.waf.modes")

router = APIRouter()

CVECTL = "/usr/sbin/secubox-cvectl"
WAFCTL = "/usr/sbin/wafctl"
_SUDO = ["sudo", "-n"]
_DELAI_S = 30
_STATUTS = {2: 422, 3: 409, 4: 404}

STATS7J_CACHE = Path("/var/lib/secubox/waf/stats7j-categories.json")
STATS7J_TTL = 900                     # s : période de la tâche de fond (main._warm_loop)
MAILLAGE = ipaddress.ip_network("10.10.0.0/24")
#: RFC 1918 + ULA (pas `is_private`, qui compte aussi les plages de documentation).
PRIVES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
LEURRES = (("rdp", 3389), ("vnc", 5900), ("telnet", 23), ("smb", 445), ("mysql", 3306), ("postgres", 5432),
           ("redis", 6379), ("mongodb", 27017), ("elasticsearch", 9200), ("mssql", 1433),
           ("submission", 587), ("imap", 143), ("pop3", 110))      # messagerie (#3924)
#: Leurres de messagerie : « observer » tant que « bannir » n'est pas écrit (miroir de BannitMail d'authwatch).
LEURRES_MAIL = frozenset({"submission", "imap", "pop3"})
#: Messagerie sans capture (#3924) : sbx-authwatch y observe toujours, sans réglage possible.
LEURRES_FIXES = (("smtp", 25), ("smtps", 465), ("imaps", 993), ("pop3s", 995))
_HOTE = re.compile(r"^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$")
_EXPLICITE = re.compile(r"^\^[a-z0-9_-]+(\\\.[a-z0-9_-]+)+\$$")

#: Branchements de main.py : audit(action, detail, user, lever=…), journal des menaces, liste blanche, repli.
_config: Dict[str, Any] = {}
_verrou_stats = threading.Lock()


def configurer(*, audit: Callable[..., None], journal: str, liste_blanche: Callable[[], List[str]],
               regles_livrees: str) -> None:
    _config.update(audit=audit, journal=journal, liste_blanche=liste_blanche, regles_livrees=regles_livrees)


# ── commandes root ────────────────────────────────────────────────────────

def _executer(argv: List[str], entree: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=entree, capture_output=True, timeout=_DELAI_S, check=False)


def _ctl(argv: List[str], entree: Optional[dict] = None) -> dict:
    """Lance la commande (sudo -n), rend sa sortie JSON ou lève l'HTTPException de son code."""
    try:
        r = _executer(_SUDO + argv, json.dumps(entree or {}).encode() if entree is not None else b"")
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("modes : %s injoignable (%s)", argv[1:3], type(e).__name__)
        raise HTTPException(503, detail={"motif": "ctl"}) from None
    try:
        sortie = json.loads((r.stdout or b"").decode("utf-8", "replace").strip().splitlines()[-1])
    except (ValueError, IndexError):
        sortie = None
    if r.returncode in _STATUTS:
        erreur = str((sortie or {}).get("erreur") or "")[:200] if isinstance(sortie, dict) else ""
        raise HTTPException(_STATUTS[r.returncode], detail={"motif": "refus", "erreur": erreur})
    if r.returncode != 0 or not isinstance(sortie, dict):
        raise HTTPException(503, detail={"motif": "ctl"})
    return sortie


def _acteur(user: dict) -> str:
    return re.sub(r"[^A-Za-z0-9_.@-]", "_", str((user or {}).get("sub") or "admin"))[:64] or "admin"


def _auditer(action: str, detail: str, user: dict) -> None:
    """INTENTION, avant l'écriture : si elle n'est pas écrite, rien n'est fait (500)."""
    try:
        _config["audit"](action, detail, user, lever=True)
    except OSError:
        raise HTTPException(500, detail={"motif": "audit"}) from None


def _auditer_issue(action: str, detail: str, user: dict) -> None:
    """ISSUE, après l'écriture : l'intention est déjà tracée, un échec ici est journalisé sans défaire."""
    try:
        _config["audit"](action, detail, user, lever=True)
    except OSError as e:
        log.warning("modes : issue de %s non auditée : %s", action, e)


def _ecrire(argv: List[str], entree: dict, action: str, detail: str, user: dict) -> dict:
    """Écriture tracée : intention auditée, commande, puis issue (ok ou refus) auditée."""
    _auditer(action, "intention " + detail, user)
    try:
        sortie = _ctl(argv, entree)
    except HTTPException as e:
        _auditer_issue(action, f"refus {e.status_code} {detail}", user)
        raise
    _auditer_issue(action, "ok " + detail, user)
    return sortie


# ── catégories ────────────────────────────────────────────────────────────

def _resume_livre(chemin: str) -> Dict[str, dict]:
    """Repli quand cvectl ne répond pas : la copie livrée (pas forcément l'état de la box : `source: paquet`)."""
    try:
        cats = json.loads(Path(chemin).read_text(encoding="utf-8")).get("categories") or {}
    except (OSError, ValueError) as e:
        log.warning("modes : règles livrées illisibles : %s", e)
        return {}
    out = {}
    for nom, c in cats.items():
        if not isinstance(c, dict):
            continue
        st = c.get("structural")
        out[nom] = {"name": c.get("name", nom), "severity": c.get("severity", "medium"),
                    "enabled": c.get("enabled", True) is not False,
                    "mode": c.get("mode") if c.get("mode") in ("detect", "escalate", "block") else "block",
                    "ban_seuil": c.get("ban_seuil"), "ban_duree": c.get("ban_duree"),
                    "motifs": len([p for p in c.get("patterns") or [] if isinstance(p, dict) and p.get("pattern")]),
                    "structurels": len(st) if isinstance(st, list) else 0,
                    "verrouille": bool(c.get("generated"))}
    return out


def lire_categories() -> dict:
    try:
        cats, source = _ctl([CVECTL, "waf-modes", "lister", "--json"])["categories"], "box"
    except (HTTPException, KeyError):
        cats, source = _resume_livre(_config.get("regles_livrees", "")), "paquet"
    for c in cats.values():
        c["rules_count"] = int(c.get("motifs") or 0) + int(c.get("structurels") or 0)
    return {"categories": cats, "total_rules": sum(c["rules_count"] for c in cats.values() if c.get("enabled")),
            "source": source}


# #4034 — double tampon : la page reçoit TOUT DE SUITE le dernier relevé complet ; s'il a plus de CAT_FRAIS s, un fil
# le recalcule en arrière-plan (un seul à la fois). Sous forte charge, `cvectl waf-modes lister` dépassait 30 s et la
# page restait vide. Une écriture (bascule de mode) invalide le relevé : la lecture suivante attend le calcul.
CAT_FRAIS = 30.0
_cat = {"releve": None, "quand": 0.0, "calcul": False}
_cat_verrou = threading.Lock()


def _recalculer_categories() -> dict:
    try:
        r = lire_categories()
    finally:
        with _cat_verrou:
            _cat["calcul"] = False
    if r.get("source") == "box" or _cat["releve"] is None:   # un repli « paquet » n'écrase jamais un relevé de la box
        with _cat_verrou:
            _cat["releve"], _cat["quand"] = r, time.monotonic()
    return r


def categories_tampon() -> dict:
    with _cat_verrou:
        releve, age, calcul = _cat["releve"], time.monotonic() - _cat["quand"], _cat["calcul"]
        if releve is not None and age >= CAT_FRAIS and not calcul:
            _cat["calcul"] = True
            threading.Thread(target=_recalculer_categories, name="waf-categories", daemon=True).start()
        elif releve is None:
            _cat["calcul"] = True
    if releve is None:
        return {**_recalculer_categories(), "age_s": 0}
    return {**releve, "age_s": int(age)}


def _invalider_categories() -> None:
    with _cat_verrou:
        _cat["releve"], _cat["quand"] = None, 0.0


@router.get("/categories", dependencies=[Depends(require_lecture)])
async def categories():
    """Catégories : mode, seuil et durée de ban, motifs + structurels (vrai total), verrouillage. Dernier relevé
    servi aussitôt (`age_s`), rafraîchi en arrière-plan (#4034)."""
    return await asyncio.to_thread(categories_tampon)


class Changement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    categorie: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,95}$")
    mode: Literal["detect", "escalate", "block"]
    ban_seuil: Optional[int] = Field(default=None, ge=1, le=10)
    ban_duree: Optional[Literal["4h", "24h", "168h"]] = None


class Lot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    changements: List[Changement] = Field(min_length=1, max_length=40)


class UnMode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["detect", "escalate", "block"]
    ban_seuil: Optional[int] = Field(default=None, ge=1, le=10)
    ban_duree: Optional[Literal["4h", "24h", "168h"]] = None


def _appliquer(lot: List[Changement], user: dict) -> dict:
    entree = {"acteur": _acteur(user), "changements": [c.model_dump(exclude_none=True) for c in lot]}
    detail = " ".join(f"{c.categorie}={c.mode}" + (f"/{c.ban_seuil}" if c.ban_seuil else "")
                      + (f"/{c.ban_duree}" if c.ban_duree else "") for c in lot)
    try:
        return _ecrire([CVECTL, "waf-modes", "appliquer", "--apply", "--json"], entree, "waf-modes", detail, user)
    finally:
        _invalider_categories()


@router.post("/categories/modes")
def categories_modes(lot: Lot, user: dict = Depends(require_jwt)):
    """Bascule un LOT (bouton « Appliquer ») ; catégories générées : 409 (mode fixé)."""
    return _appliquer(lot.changements, user)


@router.post("/category/{categorie}/mode")
def category_mode(categorie: str, corps: UnMode, user: dict = Depends(require_jwt)):
    try:
        ch = Changement(categorie=categorie, **corps.model_dump())
    except ValueError:
        raise HTTPException(422, detail={"motif": "categorie"}) from None
    return _appliquer([ch], user)


# ── touches sur 7 jours ───────────────────────────────────────────────────

def _local(ip: str, blanche: set) -> bool:
    """LAN ou maillage (sbxwaf écrit « local » pour toute adresse privée), RFC1918/ULA, liste blanche."""
    if ip == "local" or ip in blanche:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a in MAILLAGE or a.is_loopback or any(a in n for n in PRIVES if n.version == a.version)


def _ouvrir(chemin: str):
    return gzip.open(chemin, "rt", errors="replace") if chemin.endswith(".gz") else open(
        chemin, encoding="utf-8", errors="replace")


def calculer_stats7j(chemins: List[str], maintenant: datetime, blanche: set) -> dict:
    debut = maintenant - timedelta(days=7)
    cats: Dict[str, dict] = {}
    lus = 0
    for chemin in chemins:
        try:
            f = _ouvrir(chemin)
        except OSError as e:
            log.warning("stats7j : %s illisible : %s", chemin, e)
            continue
        lus += 1
        with f:
            for ligne in f:
                try:
                    e = json.loads(ligne)
                    quand = datetime.fromisoformat(str(e["timestamp"]).replace("Z", "+00:00"))
                except (ValueError, KeyError, TypeError):
                    continue
                if quand.tzinfo is None:
                    quand = quand.replace(tzinfo=timezone.utc)
                cat = e.get("category")
                if quand < debut or not isinstance(cat, str) or not cat:
                    continue
                c = cats.setdefault(cat, {"touches": 0, "faux_positifs_estimes": 0, "par_action": {}, "par_jour": [0] * 7})
                c["touches"] += 1
                # #3980 : mini-série de la page Modes, calculée dans la même passe (index 0 = le plus ancien jour)
                c["par_jour"][min(6, max(0, (quand - debut).days))] += 1
                if _local(str(e.get("client_ip") or ""), blanche):
                    c["faux_positifs_estimes"] += 1
                a = str(e.get("action") or "?")[:20]
                c["par_action"][a] = c["par_action"].get(a, 0) + 1
    return {"genere_le": maintenant.isoformat(), "fenetre_jours": 7,
            "categories": cats if lus else None,       # journal absent : null, jamais 0 inventé
            "robots_verifies": None,
            "note": "faux positifs estimés = touches venant du LAN ou du maillage (« local »), d'adresses "
                    "privées ou de la liste blanche ; les robots vérifiés ne sont pas écrits au journal"}


def rafraichir_stats7j() -> None:
    """Appelé par la tâche de fond de main.py (toutes les STATS7J_TTL s) : calcul puis écriture atomique du cache."""
    with _verrou_stats:
        journal = _config.get("journal", "")
        blanche = {x.strip() for x in (_config.get("liste_blanche") or (lambda: []))() if x.strip()}
        data = calculer_stats7j(sorted(glob(journal + "*")), datetime.now(timezone.utc), blanche)
        STATS7J_CACHE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=STATS7J_CACHE.parent, prefix=".stats7j.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, STATS7J_CACHE)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise


def stats7j() -> dict:
    """Lecture SEULE du cache : la requête ne balaie jamais le journal."""
    try:
        return json.loads(STATS7J_CACHE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"categories": None, "robots_verifies": None, "etat": "calcul en cours"}
    except (OSError, ValueError) as e:
        log.warning("stats7j : cache illisible : %s", e)
        return {"categories": None, "robots_verifies": None, "etat": "calcul en cours"}


@router.get("/categories/stats7j", dependencies=[Depends(require_lecture)])
async def categories_stats7j():
    return await asyncio.to_thread(stats7j)


# ── leurres de service ────────────────────────────────────────────────────

class ModesLeurres(BaseModel):
    model_config = ConfigDict(extra="forbid")
    modes: Dict[Literal[tuple(n for n, _ in LEURRES)], Literal["observer", "bannir"]]  # type: ignore[valid-type]


def _leurres(modes: dict) -> dict:
    return {"leurres": [{"service": n, "port": p, "mode": modes.get(n, "observer" if n in LEURRES_MAIL else "bannir")} for n, p in LEURRES]
            + [{"service": n, "port": p, "mode": "observer", "fixe": True} for n, p in LEURRES_FIXES]}


@router.get("/leurres-service/modes", dependencies=[Depends(require_lecture)])
def leurres_modes():
    """Mode de chaque leurre (absent = bannir, comportement d'origine ; messagerie : absent = observer)."""
    return _leurres(_ctl([WAFCTL, "leurres-modes", "lister"]).get("modes") or {})


@router.post("/leurres-service/modes")
def leurres_modes_ecrire(corps: ModesLeurres, user: dict = Depends(require_jwt)):
    detail = " ".join(f"{k}={v}" for k, v in sorted(corps.modes.items()))
    sortie = _ecrire([WAFCTL, "leurres-modes", "ecrire"], {"acteur": _acteur(user), "modes": dict(corps.modes)},
                     "waf-leurres-modes", detail, user)
    return _leurres(sortie.get("modes") or {})


# ── hôtes PHP ─────────────────────────────────────────────────────────────

def _hotes(etat: dict) -> dict:
    """Vhosts connus, « conteneur PHP » (oui si son service est déclaré PHP, sinon inconnu), couvert, explicite."""
    profils = etat.get("profils_vhosts") or {}
    php_services = set(etat.get("php_services") or [])
    motifs = [m for m in etat.get("php_hotes") or [] if isinstance(m, str)]
    compiles = []
    for m in motifs:
        try:
            compiles.append(re.compile(m))
        except re.error:
            continue
    explicites = {m[1:-1].replace("\\.", ".") for m in motifs if _EXPLICITE.fullmatch(m)}
    vhosts = etat.get("vhosts")
    noms = sorted(set(vhosts or []) | set(profils) | explicites)
    out = []
    for h in noms:
        service = profils.get(h)
        par_service = service in php_services
        out.append({"hote": h, "service": service, "conteneur_php": "oui" if par_service else "inconnu",
                    "couvert": par_service or any(r.search(h) for r in compiles),
                    "explicite": h in explicites})
    return {"hotes": out, "motifs": motifs, "tous": "^.*$" in motifs, "routes_lisibles": vhosts is not None}


@router.get("/php-hotes", dependencies=[Depends(require_lecture)])
def php_hotes():
    return _hotes(_ctl([WAFCTL, "php-hotes", "lister"]))


# ── sites PHP détectés (#3974) ────────────────────────────────────────────

def _sites(etat: dict) -> dict:
    """Vue de la page : sites PHP détectés (preuve, dates), exceptions, compte des autres sites servis.

    Jamais la liste brute : seuls les sites SERVIS (haproxy-routes.json) comptent ; adresses et noms non servis
    n'apparaissent pas (une exception ancienne non servie est rendue marquée `servi: false`)."""
    e = etat.get("etat") or {}
    routes = etat.get("routes")
    servis = set(routes or [])
    explicites = set(etat.get("explicites") or [])
    profils = etat.get("profils_vhosts") or {}
    services = set(etat.get("php_services") or [])
    gardes = [m for m in etat.get("php_hotes") or [] if isinstance(m, str) and not _EXPLICITE.fullmatch(m)]
    compiles = []
    for m in gardes:
        if m == TOUS:              # « tout couvrir » hérité : signalé à part, il ne fait pas d'un site un site PHP
            continue
        with contextlib.suppress(re.error):
            compiles.append((m, re.compile(m)))

    def couvert(h: str) -> Optional[str]:
        if profils.get(h) in services:
            return "service"
        if h in explicites:
            return "site"
        return next(("motif" for _, r in compiles if r.search(h)), None)

    detectes = []
    for h, d in sorted((e.get("detectes") or {}).items()):
        if routes is not None and h not in servis:
            continue
        d = d if isinstance(d, dict) else {}
        detectes.append({"hote": h, "type": d.get("type"), "preuve": d.get("preuve"), "premiere": d.get("premiere"),
                         "derniere": d.get("derniere"), "exclu": h in (e.get("exclure") or {}), "couvert": couvert(h)})
    def exc(nom: str) -> List[dict]:
        return [{"hote": h, "le": (v or {}).get("le"), "par": (v or {}).get("par"),
                 "servi": routes is None or h in servis, "couvert": couvert(h)}
                for h, v in sorted((e.get(nom) or {}).items())]
    php = {d["hote"] for d in detectes} | set(e.get("forcer") or {})
    autres = [h for h in sorted(servis) if h not in php and not couvert(h)]
    return {"detectes": detectes, "forcer": exc("forcer"), "exclure": exc("exclure"),
            "autres": len(autres), "servis": sorted(servis), "routes_lisibles": routes is not None,
            "derniere_detection": e.get("derniere_detection"), "migre": bool(etat.get("present")),
            "suspendu": bool(e.get("retabli")), "suspendu_le": (e.get("retabli") or {}).get("le"),
            "tout_couvrir_herite": TOUS in gardes, "motifs_livres": [m for m in gardes if m != TOUS]}


TOUS = "^.*$"


@router.get("/php-sites", dependencies=[Depends(require_lecture)])
def php_sites():
    return _sites(_ctl([WAFCTL, "php-sites", "lister"]))


class ExceptionsPHP(BaseModel):
    model_config = ConfigDict(extra="forbid")
    forcer: Optional[List[str]] = Field(default=None, max_length=200)
    exclure: Optional[List[str]] = Field(default=None, max_length=200)
    retirer_tout_couvrir: Optional[bool] = None
    reactiver: Optional[bool] = None      # lève la suspension posée par « wafctl php-sites retablir »


def _noms(v: Optional[List[str]]) -> Optional[List[str]]:
    if v is None:
        return None
    noms = sorted({h.strip().lower() for h in v})
    if any(not _HOTE.fullmatch(h) for h in noms):
        raise HTTPException(422, detail={"motif": "hote"})
    return noms


@router.post("/php-sites")
def php_sites_ecrire(corps: ExceptionsPHP, user: dict = Depends(require_jwt)):
    """Exceptions de l'administrateur (listes complètes) et retrait de l'ancien « tout couvrir ». La couverture des
    sites détectés n'est jamais écrite ici : wafctl la recalcule."""
    forcer, exclure = _noms(corps.forcer), _noms(corps.exclure)
    if forcer is None and exclure is None and not corps.retirer_tout_couvrir and not corps.reactiver:
        raise HTTPException(422, detail={"motif": "vide"})
    entree: dict = {"acteur": _acteur(user)}
    detail = []
    if forcer is not None:
        entree["forcer"] = forcer
        detail.append("forcer " + (",".join(forcer) or "aucun"))
    if exclure is not None:
        entree["exclure"] = exclure
        detail.append("exclure " + (",".join(exclure) or "aucun"))
    if corps.retirer_tout_couvrir:
        entree["retirer_tout_couvrir"] = True
        detail.append("tout couvrir hérité retiré")
    if corps.reactiver:
        entree["reactiver"] = True
        detail.append("détection réactivée")
    return _sites(_ecrire([WAFCTL, "php-sites", "ecrire"], entree, "waf-php-sites", " ; ".join(detail), user))


def detecter_sites() -> dict:
    """Relance de la détection (tâche de fond horaire, ou bouton). wafctl audite lui-même tout changement."""
    return _ctl([WAFCTL, "php-sites", "detecter"], {})


@router.post("/php-sites/detecter")
def php_sites_detecter(user: dict = Depends(require_jwt)):
    _auditer("waf-php-sites", "detecter demandé", user)
    d = detecter_sites()
    return {**_sites(_ctl([WAFCTL, "php-sites", "lister"])), "nouveaux": d.get("nouveaux") or []}
