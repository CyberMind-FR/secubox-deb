# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Page Modes du WAF (#3741) : mode de chaque catégorie, touches sur 7 jours, leurres de service, hôtes PHP.

L'API tourne sous `secubox` et ne lit ni n'écrit /etc/secubox/waf (0750 root) : tout passe par deux commandes
root à lignes sudoers EXACTES, l'entrée en JSON sur STDIN :

- `secubox-cvectl waf-modes lister|appliquer` (secubox-security-posture) : écriture de waf-rules.json par
  `leurres.ecrire_regles` (verrou, copie de retour, validation, relecture, rollback, audit) ;
- `wafctl leurres-modes|php-hotes lister|ecrire` : leurres-modes.json (relu à chaud par sbx-authwatch) et
  php_hotes de vhost_profiles.json (relu à chaud par sbxwaf).

Codes des commandes : 0 → 200, 2 → 422, 3 → 409, 4 → 404, autre ou délai → 503 `ctl`. Toute écriture réussie
est auditée avec `lever=True` : un changement fait dont l'audit manque rend 500, jamais caché.
"""
from __future__ import annotations

import asyncio
import contextlib
import gzip
import ipaddress
import json
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
           ("redis", 6379), ("mongodb", 27017), ("elasticsearch", 9200), ("mssql", 1433))
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


@router.get("/categories", dependencies=[Depends(require_lecture)])
async def categories():
    """Catégories : mode, seuil et durée de ban, motifs + structurels (vrai total), verrouillage."""
    return await asyncio.to_thread(lire_categories)


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
    return _ecrire([CVECTL, "waf-modes", "appliquer", "--apply", "--json"], entree, "waf-modes", detail, user)


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
                c = cats.setdefault(cat, {"touches": 0, "faux_positifs_estimes": 0, "par_action": {}})
                c["touches"] += 1
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
    return {"leurres": [{"service": n, "port": p, "mode": modes.get(n, "bannir")} for n, p in LEURRES]}


@router.get("/leurres-service/modes", dependencies=[Depends(require_lecture)])
def leurres_modes():
    """Mode de chaque leurre (absent = bannir, comportement d'origine)."""
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


class HotesPHP(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hotes: Optional[List[str]] = Field(default=None, max_length=200)
    tous: Optional[bool] = None       # « Tout couvrir » : motif ^.*$, vhosts futurs compris


@router.post("/php-hotes")
def php_hotes_ecrire(corps: HotesPHP, user: dict = Depends(require_jwt)):
    """Liste EXPLICITE des hôtes cochés (motifs ^nom\\.domaine$) ; les autres motifs restent. Jamais de cochage
    automatique : seule cette route, sur geste de l'administrateur, écrit."""
    if corps.hotes is None and corps.tous is None:
        raise HTTPException(422, detail={"motif": "vide"})
    entree: dict = {"acteur": _acteur(user)}
    detail = []
    if corps.hotes is not None:
        hotes = sorted({h.strip().lower() for h in corps.hotes})
        if any(not _HOTE.fullmatch(h) for h in hotes):
            raise HTTPException(422, detail={"motif": "hote"})
        entree["hotes"] = hotes
        detail.append("explicites " + (",".join(hotes) or "aucun"))
    if corps.tous is not None:
        entree["tous"] = corps.tous
        detail.append("tous " + ("oui" if corps.tous else "non"))
    _ecrire([WAFCTL, "php-hotes", "ecrire"], entree, "waf-php-hotes", " ; ".join(detail), user)
    return _hotes(_ctl([WAFCTL, "php-hotes", "lister"]))
