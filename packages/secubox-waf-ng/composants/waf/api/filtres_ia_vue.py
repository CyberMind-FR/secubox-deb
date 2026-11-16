# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Onglet « Filtres IA » du WAF (#3748) : filtres de l'IA en vigueur, touches, bans, recoupement avec les leurres.

Ce que gk2 sait, et rien d'autre : les vulnérabilités connues et les candidats conçus vivent sur le relais (gk0) et
ne sont pas lisibles ici — la page les affiche « — ». Sources lues par la tâche de fond (toutes les CACHE_TTL s,
jamais sur le chemin d'une requête) puis écrites en cache par remplacement atomique :

- filtres en vigueur : `sudo -n secubox-cvectl filtres-ia lister --json` (waf-rules.json est 0750 root) ;
- touches : journal des menaces de sbxwaf (`rule_id` = id du filtre, catégories `ia_filtres_*`), 24 h et 7 j ;
- bans actifs : ensemble nft du WAF (cache chaud de main.py) ;
- leurres : mémoire des leurres de service (#3734), adresses vues sur 30 jours ;
- écartés : lignes `leurre_filtres-ia-appliquer` / `rejet` du journal d'audit (cvectl les y écrit).

Retrait (`POST /filtres-ia/{id}/retirer`, administrateur réel) : `secubox-cvectl filtres-ia retirer --apply`, acteur =
l'administrateur ; intention auditée AVANT (500 si elle ne s'écrit pas, rien n'est fait), issue auditée après.
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
from typing import Any, Callable, Dict, Iterable, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from secubox_core.auth import require_jwt, require_lecture

log = logging.getLogger("secubox.waf.filtres_ia_vue")

router = APIRouter(prefix="/filtres-ia")

CVECTL = "/usr/sbin/secubox-cvectl"
_SUDO = ["sudo", "-n"]
_DELAI_S = 60
_STATUTS = {2: 422, 3: 409, 4: 404}
_RE_ID = re.compile(r"ia-[a-z0-9._-]{1,93}")
_RE_ID_AUDIT = re.compile(r"(ia-[a-z0-9._-]{1,93}):")
CATEGORIES = {"ia_filtres_critique": "critique", "ia_filtres_haute": "haute", "ia_filtres_moyenne": "moyenne"}

CACHE = Path("/var/lib/secubox/waf/filtres-ia.json")
CACHE_TTL = 300                       # s : période de la tâche de fond (main._warm_loop)
AUDIT_LOG = Path("/var/log/secubox/audit.log")
AUDIT_FIN = 16 << 20                  # octets lus à la fin du journal d'audit (écartés)
RADAR_MAX = 300
MAILLAGE = ipaddress.ip_network("10.10.0.0/24")
PRIVES = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))

#: Branchements de main.py : audit, journal des menaces, bans actifs, leurres par adresse, liste blanche.
_config: Dict[str, Any] = {}
_verrou = threading.Lock()


def configurer(*, audit: Callable[..., None], journal: str, bans: Callable[[], List[dict]],
               leurres: Callable[[], Dict[str, List[str]]], liste_blanche: Callable[[], List[str]]) -> None:
    _config.update(audit=audit, journal=journal, bans=bans, leurres=leurres, liste_blanche=liste_blanche)


# ── commande root ─────────────────────────────────────────────────────────

def _executer(argv: List[str], entree: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=entree, capture_output=True, timeout=_DELAI_S, check=False)


def _ctl(verbe: str, entree: Optional[dict]) -> dict:
    argv = _SUDO + [CVECTL, "filtres-ia", verbe] + (["--apply"] if verbe != "lister" else []) + ["--json"]
    try:
        r = _executer(argv, json.dumps(entree).encode() if entree is not None else b"")
    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("filtres-ia : cvectl %s injoignable (%s)", verbe, type(e).__name__)
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


# ── agrégation ────────────────────────────────────────────────────────────

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


def lire_touches(chemins: Iterable[str], maintenant: datetime) -> Optional[List[dict]]:
    """Touches des filtres de l'IA sur 7 jours (None : aucun journal lisible, jamais une liste vide inventée)."""
    debut = maintenant - timedelta(days=7)
    touches, lus = [], 0
    for chemin in chemins:
        try:
            f = _ouvrir(chemin)
        except OSError as e:
            log.warning("filtres-ia : %s illisible : %s", chemin, e)
            continue
        lus += 1
        with f:
            for ligne in f:
                if "ia_filtres_" not in ligne:
                    continue
                try:
                    e = json.loads(ligne)
                    quand = datetime.fromisoformat(str(e["timestamp"]).replace("Z", "+00:00"))
                except (ValueError, KeyError, TypeError):
                    continue
                if quand.tzinfo is None:
                    quand = quand.replace(tzinfo=timezone.utc)
                if quand < debut or e.get("category") not in CATEGORIES:
                    continue
                touches.append({"ts": quand, "id": str(e.get("rule_id") or ""), "categorie": e["category"],
                                "ip": str(e.get("client_ip") or ""), "action": str(e.get("action") or "?")[:20]})
    return touches if lus else None


def lire_ecartes(chemin: Path, appliques: set) -> Optional[dict]:
    """Candidats refusés par gk2 (audit de cvectl), hors ceux appliqués depuis. None : audit illisible."""
    try:
        with open(chemin, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - AUDIT_FIN))
            brut = f.read().decode("utf-8", "replace")
    except OSError as e:
        log.warning("filtres-ia : audit illisible : %s", e)
        return None
    raisons: Dict[str, str] = {}
    for ligne in brut.splitlines():
        if "filtres-ia-appliquer" not in ligne or '"rejet"' not in ligne:
            continue
        try:
            e = json.loads(ligne)
        except ValueError:
            continue
        if e.get("action") != "leurre_filtres-ia-appliquer" or e.get("result") != "rejet":
            continue
        detail = str(e.get("detail") or "")
        pos = [(m.start(), m.group(1)) for m in _RE_ID_AUDIT.finditer(detail)]
        for i, (debut, fid) in enumerate(pos):
            fin = pos[i + 1][0] if i + 1 < len(pos) else len(detail)
            raisons[fid] = detail[debut + len(fid) + 1:fin].strip().rstrip(",").strip()[:80]
    par_raison: Dict[str, int] = {}
    for fid, r in raisons.items():
        if fid not in appliques:
            par_raison[r or "?"] = par_raison.get(r or "?", 0) + 1
    return {"total": sum(par_raison.values()),
            "par_raison": dict(sorted(par_raison.items(), key=lambda kv: -kv[1])[:8])}


def agreger(filtres: Optional[List[dict]], touches: Optional[List[dict]], bans: Optional[set],
            leurres: Optional[Dict[str, List[str]]], ecartes: Optional[dict], blanche: set,
            maintenant: datetime) -> dict:
    """Tout ce que la page montre. Une source absente donne null (affiché « — »), jamais 0."""
    il_y_a_24h = maintenant - timedelta(hours=24)
    par_id: Dict[str, dict] = {}
    for f in filtres or []:
        fid = f.get("id")
        if not isinstance(fid, str):
            continue
        par_id[fid] = {"id": fid, "cve": f.get("cve"), "produit": f.get("produit"), "famille": f.get("famille"),
                       "gravite": f.get("gravite") or CATEGORIES.get(f.get("categorie") or ""),
                       "categorie": f.get("categorie"), "motif": str(f.get("pattern") or "")[:200],
                       "kev": f.get("kev") if isinstance(f.get("kev"), bool) else None,
                       "epss": f.get("epss") if isinstance(f.get("epss"), (int, float)) else None,
                       "touches_24h": 0 if touches is not None else None,
                       "touches_7j": 0 if touches is not None else None,
                       "adresses_24h": 0 if touches is not None else None,
                       "bannies": 0 if (touches is not None and bans is not None) else None,
                       "faux_positifs": 0 if touches is not None else None, "leurres": [], "derniere": None}
    ips_f: Dict[str, set] = {}
    ips_24h: Dict[str, set] = {}
    ia_ips: Dict[str, dict] = {}            # adresse -> touches 24 h, dernière, ids
    t24 = fp24 = 0
    for t in touches or []:
        f = par_id.get(t["id"])
        loc = _local(t["ip"], blanche)
        if f is not None:
            f["touches_7j"] += 1
            ips_f.setdefault(t["id"], set()).add(t["ip"])
            if f["derniere"] is None or t["ts"].isoformat() > f["derniere"]:
                f["derniere"] = t["ts"].isoformat()
        if t["ts"] < il_y_a_24h:
            continue
        t24 += 1
        fp24 += loc
        if f is not None:
            f["touches_24h"] += 1
            f["faux_positifs"] += loc
            ips_24h.setdefault(t["id"], set()).add(t["ip"])
        if not loc:
            a = ia_ips.setdefault(t["ip"], {"touches": 0, "ids": set(), "derniere": t["ts"]})
            a["touches"] += 1
            a["ids"].add(t["id"])
            a["derniere"] = max(a["derniere"], t["ts"])
    for fid, f in par_id.items():
        if touches is None:
            continue
        f["adresses_24h"] = len(ips_24h.get(fid, ()))
        ips = ips_f.get(fid, set())
        if bans is not None:
            f["bannies"] = len(ips & bans)
        if leurres is not None:
            f["leurres"] = sorted({s for ip in ips for s in leurres.get(ip, ())})
    touches_7j_ips = {t["ip"] for t in touches or [] if not _local(t["ip"], blanche)}
    bannis_ia = (touches_7j_ips & bans) if (touches is not None and bans is not None) else None
    communs: Optional[Dict[str, int]] = None
    if touches is not None and leurres is not None:
        communs = {}
        for ip in touches_7j_ips:
            for s in leurres.get(ip, ()):
                communs[s] = communs.get(s, 0) + 1
    radar = None
    if touches is not None or leurres is not None:
        points: Dict[str, dict] = {}
        for ip, a in ia_ips.items():
            points[ip] = {"ip": ip, "ia": True, "touches": a["touches"], "filtres": len(a["ids"]), "leurres": [],
                          "banni": None if bans is None else ip in bans}
        for ip, services in (leurres or {}).items():
            if ip == "local":
                continue
            if ip in points:
                points[ip]["leurres"] = list(services)
            elif ip in touches_7j_ips or len(points) < RADAR_MAX:
                points[ip] = {"ip": ip, "ia": False, "touches": 0, "filtres": 0, "leurres": list(services),
                              "banni": None if bans is None else ip in bans}
        radar = sorted(points.values(), key=lambda p: (-(p["ia"] and bool(p["leurres"])), -p["touches"]))[:RADAR_MAX]
    filtres_l = sorted(par_id.values(), key=lambda f: (-(f["faux_positifs"] or 0), -(f["touches_24h"] or 0),
                                                       -(f["touches_7j"] or 0), f["id"]))
    par_gravite = None
    if filtres is not None:
        par_gravite = {g: sum(1 for f in filtres_l if f["gravite"] == g) for g in ("critique", "haute", "moyenne")}
    kevs = [f["kev"] for f in filtres_l if f["kev"] is not None]
    return {
        "genere_le": maintenant.isoformat(),
        "filtres": filtres_l if filtres is not None else None,
        "resume": {
            "actifs": len(filtres_l) if filtres is not None else None,
            "par_gravite": par_gravite,
            "kev": sum(kevs) if kevs else None,          # gk2 ne garde pas toujours KEV : null plutôt que 0
            "ecartes": ecartes,
            "touches_24h": t24 if touches is not None else None,
            "filtres_touches_24h": (sum(1 for f in filtres_l if f["touches_24h"]) if touches is not None
                                    and filtres is not None else None),
            "faux_positifs_24h": fp24 if touches is not None else None,
            "bans_actifs": len(bannis_ia) if bannis_ia is not None else None,
            "bans_aussi_leurre": (len({ip for ip in bannis_ia if ip in (leurres or {})})
                                  if bannis_ia is not None and leurres is not None else None),
            # Relais gk0 : non lisibles depuis gk2.
            "vulnerabilites_connues": None, "candidats_relais": None,
        },
        "leurres_communs": communs,
        "radar": radar,
    }


def _bans_actuels() -> Optional[set]:
    try:
        return {str(b["ip"]) for b in _config["bans"]() if isinstance(b, dict) and b.get("ip")}
    except Exception as e:  # noqa: BLE001 — nft muet : état inconnu (« — »), jamais « non banni »
        log.warning("filtres-ia : bans illisibles : %s", e)
        return None


def _leurres_actuels() -> Optional[Dict[str, List[str]]]:
    try:
        return _config["leurres"]()
    except Exception as e:  # noqa: BLE001 — mémoire des leurres indisponible : « — »
        log.warning("filtres-ia : mémoire des leurres illisible : %s", e)
        return None


def _ecrire_cache(data: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=CACHE.parent, prefix=".filtres-ia.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, CACHE)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def rafraichir() -> None:
    """Appelé par la tâche de fond de main.py (toutes les CACHE_TTL s) : calcul puis écriture atomique du cache."""
    with _verrou:
        maintenant = datetime.now(timezone.utc)
        try:
            filtres = _ctl("lister", None).get("filtres")
            filtres = filtres if isinstance(filtres, list) else None
        except HTTPException:
            filtres = None
        touches = lire_touches(sorted(glob(_config.get("journal", "") + "*")), maintenant)
        blanche = {x.strip() for x in (_config.get("liste_blanche") or (lambda: []))() if x.strip()}
        ecartes = lire_ecartes(AUDIT_LOG, {f.get("id") for f in filtres or []})
        _ecrire_cache(agreger(filtres, touches, _bans_actuels(), _leurres_actuels(), ecartes, blanche, maintenant))


def lire_cache() -> dict:
    """Lecture SEULE du cache : une requête ne balaie jamais le journal."""
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as e:
        log.warning("filtres-ia : cache illisible : %s", e)
    return {"etat": "calcul en cours", "genere_le": None, "filtres": None, "resume": None,
            "leurres_communs": None, "radar": None}


@router.get("/resume", dependencies=[Depends(require_lecture)])
async def resume() -> Dict[str, Any]:
    c = await asyncio.to_thread(lire_cache)
    return {k: c.get(k) for k in ("etat", "genere_le", "resume", "leurres_communs")}


@router.get("/touches", dependencies=[Depends(require_lecture)])
async def touches() -> Dict[str, Any]:
    c = await asyncio.to_thread(lire_cache)
    return {"etat": c.get("etat"), "genere_le": c.get("genere_le"), "filtres": c.get("filtres")}


@router.get("/radar", dependencies=[Depends(require_lecture)])
async def radar() -> Dict[str, Any]:
    c = await asyncio.to_thread(lire_cache)
    return {"etat": c.get("etat"), "genere_le": c.get("genere_le"), "points": c.get("radar")}


def _acteur(user: dict) -> str:
    return re.sub(r"[^A-Za-z0-9_.@-]", "_", str((user or {}).get("sub") or "admin"))[:64] or "admin"


def _oublier(fid: str) -> None:
    """Le filtre retiré quitte le cache tout de suite (le prochain tour de fond recalcule le reste)."""
    with _verrou:
        c = lire_cache()
        if isinstance(c.get("filtres"), list):
            c["filtres"] = [f for f in c["filtres"] if f.get("id") != fid]
            if isinstance(c.get("resume"), dict) and c["resume"].get("actifs") is not None:
                c["resume"]["actifs"] = len(c["filtres"])
            try:
                _ecrire_cache(c)
            except OSError as e:
                log.warning("filtres-ia : cache non mis à jour après retrait : %s", e)


@router.post("/{fid}/retirer")
def retirer(fid: str, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    if not _RE_ID.fullmatch(fid):
        raise HTTPException(422, detail={"motif": "id"})
    try:
        _config["audit"]("waf-filtres-ia-retirer", f"intention {fid}", user, lever=True)
    except OSError:
        raise HTTPException(500, detail={"motif": "audit"}) from None
    try:
        sortie = _ctl("retirer", {"acteur": _acteur(user), "id": fid})
    except HTTPException as e:
        with contextlib.suppress(OSError):
            _config["audit"]("waf-filtres-ia-retirer", f"refus {e.status_code} {fid}", user, lever=True)
        raise
    try:
        _config["audit"]("waf-filtres-ia-retirer", f"ok {fid}", user, lever=True)
    except OSError as e:
        log.warning("filtres-ia : issue du retrait non auditée : %s", e)
    _oublier(fid)
    return sortie
