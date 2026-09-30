# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-dpi — sbxdpi (nDPI) socket + tc mirred DPI dual-stream

Enhanced features:
- Traffic history tracking with time-series stats
- Bandwidth quotas per app/device with enforcement
- Scheduled traffic reports
- Alert thresholds with webhook notifications
- Application fingerprint database
- Traffic anomaly detection
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from secubox_core.auth import require_lecture
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import subprocess, json, socket, time, threading, asyncio
from pathlib import Path
import httpx

app = FastAPI(title="secubox-dpi", version="2.0.0", root_path="/api/v1/dpi")

# Phase 2b/2c (#488/#490) : ingest mitm DPI events + nDPI-style classification
from secubox_core.mitm_ingest import mount_ingest_routes  # noqa: E402
from secubox_core.classifiers import host_app as _host_app  # noqa: E402


def _dpi_enrich(event: dict) -> dict:
    """Phase 2c enrichment : classify host/SNI -> {app, category, emoji}.

    Future Phase 3 : query the nDPI daemon socket for live classification.
    """
    host = event.get("host") or event.get("sni") or ""
    if not host:
        return event
    cls = _host_app.classify_host(host)
    event["enriched"] = {
        "app": cls["app"],
        "category": cls["category"],
        "emoji": cls["emoji"],
        "source": "secubox-dpi/host_app",
        "method": "pattern-match",
    }
    return event


mount_ingest_routes(
    app,
    endpoint_path="/classify",
    db_path="/var/lib/secubox/dpi/mitm-ingest.db",
    kind="dpi",
    enrich_hook=_dpi_enrich,
)

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}


# Vivacité du moteur R3 : le collector réécrit state.json à chaque fenêtre de
# capture (~60 s). Au-delà de ce seuil sans fenêtre, le moteur est « idle ».
ENGINE_ALIVE_S = 180


@app.get("/exfil", dependencies=[Depends(require_lecture)])
def exfil_state():
    """#687 Phase 2 — état d'exfiltration cloud par terminal, produit par le
    collector Go (secubox-dpi-flowcap → secubox-dpi-collector). Fail-empty :
    le tableau de bord ne tombe jamais en erreur avant la première fenêtre.

    LA LISTE DES TERMINAUX VIENT DU CUMUL (cumulative.json) — l'ensemble des
    terminaux observés sur la période — et PAS de state.json, qui n'est que la
    fenêtre courante et se vide dès que le tunnel wg-toolbox est au repos (la
    page affichait alors « aucun terminal sur R3 » malgré un historique réel).
    On superpose les `active_flows` de state.json pour que la vue live bouge,
    plus un bloc `engine` (vivacité) que lit updateEngine() de la page.

    `def` et non `async def` : lectures de fichiers bloquantes (100–200 Ko),
    exécutées hors de la boucle partagée de l'agrégateur (ref #808)."""
    base = {"generated_at": 0, "devices": [], "alerts": [], "alert_count": 0,
            "top_apps": [], "top_protocols": [], "active_flows": []}
    try:
        if COLLECTOR_CUMUL.exists():
            base.update(json.loads(COLLECTOR_CUMUL.read_text()))
    except Exception as e:  # pragma: no cover — cumul illisible : fail-empty
        base["error"] = str(e)
    live_ts = 0
    try:
        if COLLECTOR_STATE.exists():
            st = json.loads(COLLECTOR_STATE.read_text())
            base["active_flows"] = st.get("active_flows", []) or []
            live_ts = st.get("generated_at", 0) or 0
    except Exception:
        pass
    if not base.get("devices"):
        base["note"] = "no devices observed yet (or wg-toolbox idle since first capture)"
    # Vivacité du moteur R3 déduite de l'âge de la dernière fenêtre : sans
    # privilège (l'API tourne en `secubox`), sans interroger systemd.
    age = max(0, int(time.time() - live_ts)) if live_ts else None
    base["engine"] = {
        "name": "ndpiReader · R3 exfil",
        "service": "secubox-dpi-flowcap",
        "alive": bool(age is not None and age < ENGINE_ALIVE_S),
        "last_window_s": age,
    }
    return base


@app.get("/history", dependencies=[Depends(require_lecture)])
def exfil_history(device: str = "", days: int = 14):
    """#720 — per-device DAILY timeline from the collector history.json. Without
    ?device, returns board-wide daily totals. Fail-empty."""
    import json as _json
    from pathlib import Path as _P
    p = _P("/var/lib/secubox/dpi/history.json")
    try:
        rows = _json.loads(p.read_text()) if p.exists() else []
    except Exception as e:  # pragma: no cover
        return {"device": device, "days": [], "error": str(e)}
    if device:
        per = [r for r in rows if r.get("device") == device]
        return {"device": device, "days": per[-days:]}
    # board-wide: sum per day
    by_day: dict = {}
    for r in rows:
        d = by_day.setdefault(r.get("day"), {
            "day": r.get("day"), "flows": 0, "up_bytes": 0, "down_bytes": 0,
            "alerts": 0, "devices": 0})
        d["flows"] += int(r.get("flows", 0) or 0)
        d["up_bytes"] += int(r.get("up_bytes", 0) or 0)
        d["down_bytes"] += int(r.get("down_bytes", 0) or 0)
        d["alerts"] += int(r.get("alerts", 0) or 0)
        d["devices"] += 1
    days_sorted = sorted(by_day.values(), key=lambda x: x["day"] or "")
    return {"device": "", "days": days_sorted[-days:]}


@app.get("/media_types", dependencies=[Depends(require_lecture)])
def media_types():
    """#785 — répartition des types MIME captés par le media-catcher R4 de
    sbxmitm (/run/secubox/media-catch.jsonl), agrégée pour toute la board.
    Distinct de la catégorie de service « media » (SNI). Lecture gardée comme
    /exfil, fail-empty. `def` : lecture bornée du journal, hors boucle (#808)."""
    try:
        from secubox_core import media_catch
        agg = media_catch.aggregate(path=media_catch.MEDIA_CATCH_PATH)
        view = agg.get("all") or {}
        return {"present": bool(view.get("present")),
                "flows": view.get("flows", 0), "bytes": view.get("bytes", 0),
                "kinds": view.get("kinds", []), "ctypes": view.get("ctypes", []),
                "top_hosts": view.get("top_hosts", [])}
    except Exception as e:  # pragma: no cover — fail-empty
        return {"present": False, "flows": 0, "bytes": 0,
                "kinds": [], "ctypes": [], "top_hosts": [], "error": str(e)}


# ── RÈGLES D'ENRICHISSEMENT DPI (#DPI-sémantique) — écriture JWT ─────────────
# Le learner (sbxdpi, GET) PROPOSE ; l'ACCEPT est un acte HUMAIN, écrit ici sous
# JWT dans /etc/secubox/dpi/rules.json — que sbxdpi recharge à chaud (mtime,
# internal/reload). sbxdpi ne s'écrit jamais lui-même (GET only). Séparation
# lecture (LAN, sbxdpi) / écriture (JWT, ici) conforme au reste du DPI.
DPI_RULES_FILE = Path("/etc/secubox/dpi/rules.json")
DPI_IGNORE_FILE = Path("/etc/secubox/dpi/learn-ignore.txt")


class _RuleMatch(BaseModel):
    domain_suffix: List[str] = Field(default_factory=list)
    ndpi: List[str] = Field(default_factory=list)
    port: List[int] = Field(default_factory=list)


class _RuleIn(BaseModel):
    id: str
    application: Optional[str] = None
    usage: Optional[str] = None
    content: Optional[str] = None
    infra: Optional[str] = None
    infra_role: Optional[str] = None
    confidence: int = 50
    match: _RuleMatch


def _dpi_load_ruleset() -> dict:
    try:
        return json.loads(DPI_RULES_FILE.read_text())
    except Exception:
        return {"_meta": {"version": "0.0.0"}, "rules": []}


def _dpi_save_ruleset(rs: dict) -> None:
    DPI_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = DPI_RULES_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rs, ensure_ascii=False, indent=2))
    tmp.replace(DPI_RULES_FILE)  # swap atomique — sbxdpi ne voit jamais un demi-fichier


@app.get("/rules")
def dpi_rules(user=Depends(require_jwt)):
    """Règles d'enrichissement DPI actives (rules.json)."""
    return _dpi_load_ruleset()


@app.post("/rules/accept")
def dpi_rules_accept(rule: _RuleIn, user=Depends(require_jwt)):
    """ACCEPT : matérialise une suggestion du learner en règle. Garde-fous : au
    moins un signal de match, id unique. sbxdpi recharge à chaud."""
    m = rule.match
    if not (m.domain_suffix or m.ndpi or m.port):
        raise HTTPException(400, "règle sans signal de match (domain_suffix/ndpi/port)")
    rs = _dpi_load_ruleset()
    rules = rs.setdefault("rules", [])
    if any(r.get("id") == rule.id for r in rules):
        raise HTTPException(409, f"règle {rule.id!r} déjà présente")
    rules.append(rule.dict(exclude_none=True))
    rs.setdefault("_meta", {})["updated"] = datetime.utcnow().strftime("%Y-%m-%d")
    _dpi_save_ruleset(rs)
    return {"ok": True, "id": rule.id, "count": len(rules)}


@app.post("/rules/ignore")
def dpi_rules_ignore(domain: str, user=Depends(require_jwt)):
    """IGNORE : note un domaine à ne plus suggérer (learn-ignore.txt)."""
    d = (domain or "").strip().lower()
    if not d:
        raise HTTPException(400, "domaine vide")
    DPI_IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with DPI_IGNORE_FILE.open("a") as f:
        f.write(d + "\n")
    return {"ok": True, "ignored": d}


# ── PONT vers sbxdpi (moteur d'enrichissement live, lecture LAN) ─────────────
# L'admin (sous JWT) doit voir suggestions/usage/sessions calculées par sbxdpi,
# qui n'écoute qu'en LAN sur dpi-live.sock. On les PROXIFIE ici, sous JWT, en
# fail-empty si le socket dort (sbxdpi est dark tant que le cutover nDPI n'est
# pas fait). Unifie les deux surfaces DPI (collector + sbxdpi) derrière l'admin.
DPI_LIVE_SOCK = "/run/secubox/dpi-live.sock"


async def _sbxdpi_get(path: str, default):
    try:
        transport = httpx.AsyncHTTPTransport(uds=DPI_LIVE_SOCK)
        async with httpx.AsyncClient(transport=transport, timeout=3.0) as cli:
            r = await cli.get("http://sbxdpi" + path)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return default


# ── DÉRIVATION DEPUIS LE COLLECTOR (#DPI-sémantique) ─────────────────────────
# sbxdpi est dark (feed ZMQ rejeté #722/#723) ; MAIS le collector produit déjà
# des données RÉELLES riches dans cumulative.json : par device, by_category +
# une liste `services` (dst hostname, bytes, flows, service/category). On dérive
# usage/sessions/suggestions de LÀ, en réutilisant les règles rules.json (même
# logique host→usage que l'enrichisseur Go). Repli quand sbxdpi répond vide.
COLLECTOR_CUMUL = Path("/var/lib/secubox/dpi/cumulative.json")
# Fenêtre live du collector (active_flows + generated_at) — lue par /exfil.
COLLECTOR_STATE = Path("/var/lib/secubox/dpi/state.json")
# collector category → famille d'usage (vocabulaire des règles)
_CAT_MAP = {
    "media": "streaming", "game": "gaming", "gaming": "gaming",
    "cloud": "cloud", "filehost": "cloud", "messaging": "social",
    "social": "social", "ai": "ai", "adult": "adult",
}
_rules_cache: list = []
_rules_mtime: float = -1.0


def _dpi_rules() -> list:
    global _rules_cache, _rules_mtime
    try:
        mt = DPI_RULES_FILE.stat().st_mtime
    except OSError:
        return []
    if mt != _rules_mtime:
        _rules_mtime = mt
        try:
            _rules_cache = json.loads(DPI_RULES_FILE.read_text()).get("rules", [])
        except Exception:
            _rules_cache = []
    return _rules_cache


def _host_suffix(host: str, suffix: str) -> bool:
    host = (host or "").strip().lower()
    suffix = (suffix or "").strip().lower()
    return bool(host) and bool(suffix) and (host == suffix or host.endswith("." + suffix))


def _classify(host: str) -> dict:
    """Mirroir host-only de l'enrichisseur Go : meilleure règle par domain_suffix."""
    best = {}
    for r in _dpi_rules():
        ds = (r.get("match") or {}).get("domain_suffix") or []
        if any(_host_suffix(host, s) for s in ds):
            if not best or r.get("confidence", 0) >= best.get("confidence", 0):
                best = r
    return best


_TWO_LVL = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp", "co.nz", "com.br", "com.cn"}


def _registrable(host: str) -> str:
    host = (host or "").strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _TWO_LVL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _collector_devices() -> list:
    try:
        return json.loads(COLLECTOR_CUMUL.read_text()).get("devices", [])
    except Exception:
        return []


# Première partie : nos propres vhosts (clés de haproxy-routes.json) — comme
# l'exemption first-party de sbxdpi. On ne SUGGÈRE jamais une règle pour nous.
BOX_ROUTES = Path("/etc/secubox/waf/haproxy-routes.json")
_box_cache: set = set()
_box_mtime: float = -1.0


def _box_domains() -> set:
    global _box_cache, _box_mtime
    try:
        mt = BOX_ROUTES.stat().st_mtime
    except OSError:
        return _box_cache
    if mt != _box_mtime:
        _box_mtime = mt
        try:
            _box_cache = {str(k).strip().lower() for k in json.loads(BOX_ROUTES.read_text()).keys()}
        except Exception:
            _box_cache = set()
    return _box_cache


def _is_box(host: str) -> bool:
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in _box_domains())


def _valid_host(host: str) -> bool:
    """Écarte les dst qui ne sont pas des hostnames (IP, fragments d'UA…)."""
    h = (host or "").strip().lower()
    if not h or " " in h or "." not in h:
        return False
    if h.replace(".", "").replace("-", "").isdigit():  # IPv4-ish
        return False
    tld = h.rsplit(".", 1)[-1]
    return tld.isalpha() and len(tld) >= 2


def _rank(m: dict, total: int) -> list:
    out = [{"name": k, "flows": v["flows"], "bytes": v["bytes"],
            "pct": (v["bytes"] / total * 100) if total else 0.0,
            "confidence": v["confidence"]} for k, v in m.items() if k]
    out.sort(key=lambda x: (-x["bytes"], -x["flows"]))
    return out


def _bump(m: dict, key: str, b: int, f: int, conf: int):
    if not key:
        return
    a = m.setdefault(key, {"bytes": 0, "flows": 0, "confidence": 0})
    a["bytes"] += b
    a["flows"] += f
    a["confidence"] = max(a["confidence"], conf)


# ── Dérivations collector (sync, partagées JWT + public aggregate) ───────────
# Le même calcul sert (a) l'admin sous JWT et (b) le relais Hall en lecture
# aggregate/no-PII (routeur /pub, sans JWT — cf. hall.vhost.conf #1360).
def _derive_usage() -> dict:
    usages, providers, apps = {}, {}, {}
    unknown, total = [], 0
    for dev in _collector_devices():
        for s in dev.get("services", []):
            host = s.get("dst", "")
            b = int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
            fl = int(s.get("flows", 0) or 0)
            total += b
            en = _classify(host)
            usage = en.get("usage") or _CAT_MAP.get(s.get("category", ""), "")
            infra = en.get("infra") or s.get("service") or s.get("cloud") or ""
            app = en.get("application") or s.get("service") or ""
            conf = en.get("confidence", 0) or (60 if s.get("service") else 0)
            if not usage and not app:
                unknown.append({"name": host, "flows": fl, "bytes": b, "pct": 0.0})
                continue
            _bump(usages, usage, b, fl, conf)
            _bump(providers, infra, b, fl, conf)
            _bump(apps, app, b, fl, conf)
    unknown.sort(key=lambda x: -x["bytes"])
    return {"usages": _rank(usages, total), "providers": _rank(providers, total),
            "applications": _rank(apps, total), "unknown": unknown[:60]}


def _derive_suggestions() -> list:
    groups: dict = {}
    for dev in _collector_devices():
        for s in dev.get("services", []):
            host = s.get("dst", "")
            # inconnu = ni règle, ni label collector (service/category), et un
            # vrai hostname tiers (pas IP, pas nous). C'est ça qu'on propose.
            if (_classify(host) or s.get("service") or s.get("category")
                    or not _valid_host(host) or _is_box(host)):
                continue
            dom = _registrable(host)
            g = groups.setdefault(dom, {"subs": 0, "flows": 0, "bytes": 0, "ex": []})
            g["subs"] += 1
            g["flows"] += int(s.get("flows", 0) or 0)
            g["bytes"] += int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
            if len(g["ex"]) < 3:
                g["ex"].append(host)
    out = []
    for dom, g in groups.items():
        conf = min(95, max(20, 30 + (g["subs"] - 1) * 15 + (25 if g["bytes"] >= 1 << 30 else 10 if g["bytes"] >= 1 << 20 else 0)))
        out.append({"domain": dom, "subdomains": g["subs"], "flows": g["flows"], "bytes": g["bytes"],
                    "confidence": conf, "examples": g["ex"],
                    "reason": f"{g['subs']} sous-domaine(s) non classifié(s), {formatBytesPy(g['bytes'])}",
                    "proposed_rule": {"id": "learn-" + dom, "usage": "", "confidence": conf,
                                      "match": {"domain_suffix": [dom]}}})
    out.sort(key=lambda x: -x["bytes"])
    return out[:40]


def _derive_sessions() -> list:
    by: dict = {}
    for dev in _collector_devices():
        did = dev.get("device", "")
        fs, ls = dev.get("first_seen", 0), dev.get("last_seen", 0)
        for s in dev.get("services", []):
            host = s.get("dst", "")
            en = _classify(host)
            usage = en.get("usage") or _CAT_MAP.get(s.get("category", ""), "")
            if not usage:
                continue
            k = (did, usage)
            a = by.get(k)
            if a is None:
                a = {"device": did, "usage": usage, "application": en.get("application") or s.get("service") or "",
                     "infra": en.get("infra") or s.get("service") or "", "start": fs, "last": ls,
                     "flows": 0, "bytes": 0, "hosts": [], "confidence": 0}
                by[k] = a
            a["flows"] += int(s.get("flows", 0) or 0)
            a["bytes"] += int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
            a["confidence"] = max(a["confidence"], en.get("confidence", 0) or (60 if s.get("service") else 0))
            if host and host not in a["hosts"] and len(a["hosts"]) < 6:
                a["hosts"].append(host)
            if not a["application"] and (en.get("application") or s.get("service")):
                a["application"] = en.get("application") or s.get("service")
    out = list(by.values())
    out.sort(key=lambda x: -x["bytes"])
    return out[:200]


# Table d'alias éditable : {hash_device: "Nom lisible"}. Optionnelle, versionnable,
# CSPN-clean (explicite, pas de reverse du hash). L'opérateur nomme ses terminaux ;
# à défaut, l'UI retombe sur le hash court. Rechargée à chaud (mtime).
DEVICE_NAMES = Path("/etc/secubox/dpi/device-names.json")
_names_cache: dict = {}
_names_mtime: float = -1.0


def _device_names() -> dict:
    global _names_cache, _names_mtime
    try:
        mt = DEVICE_NAMES.stat().st_mtime
    except OSError:
        return _names_cache
    if mt != _names_mtime:
        _names_mtime = mt
        try:
            d = json.loads(DEVICE_NAMES.read_text())
            _names_cache = ({str(k): str(v) for k, v in d.items() if not str(k).startswith("__")}
                            if isinstance(d, dict) else {})
        except Exception:
            _names_cache = {}
    return _names_cache


# Nom lisible d'un terminal, dans l'ordre de priorité :
#   1. table d'alias manuelle /etc/secubox/dpi/device-names.json (surcharge op.)
#   2. `name`/`label` émis par le collector dans cumulative.json (s'il l'ajoute :
#      il a l'accès légitime à wg-peers.json — la FastAPI, elle, tourne en
#      `secubox` sans accès au dir toolbox 0750, et on NE casse PAS cette
#      séparation CSPN pour lire un nom).
# À défaut, l'UI retombe sur le hash court.
def _client_name(did: str, dev: dict) -> str:
    return (_device_names().get(did)
            or dev.get("name") or dev.get("label") or "")


def _derive_clients() -> list:
    """Détail par TERMINAL (device) : volume ↑/↓, familles d'usage, top
    destinations, nombre de sessions d'usage, alertes. Dérivé du collector —
    c'est la vue « clients » enrichie de la cardlet DPI (mêmes cards que l'admin)."""
    out = []
    for dev in _collector_devices():
        did = dev.get("device", "")
        up = int(dev.get("up_bytes", 0) or 0)
        down = int(dev.get("down_bytes", 0) or 0)
        tot = up + down
        usages, dsts, fams, countries = {}, {}, set(), {}
        for s in dev.get("services", []) or []:
            b = int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
            en = _classify(s.get("dst", ""))
            u = en.get("usage") or _CAT_MAP.get(s.get("category", ""), "")
            if u:
                usages[u] = usages.get(u, 0) + b
                fams.add(u)
            host = s.get("dst", "")
            if host:
                d = dsts.setdefault(host, {"host": host, "bytes": 0,
                                          "service": s.get("service") or en.get("application") or ""})
                d["bytes"] += b
            # Pays du terminal : géo de ses destinations IP publiques.
            if _is_ip(host):
                try:
                    priv = _ipaddr.ip_address(host).is_private
                except ValueError:
                    priv = True
                if not priv:
                    cc = _country_of(host)
                    if cc:
                        a = countries.setdefault(cc[0], {"cc": cc[0], "flag": _flag(cc[0]),
                                                         "name": cc[1], "bytes": 0})
                        a["bytes"] += b
        ulist = sorted(({"name": k, "bytes": v, "pct": (v / tot * 100) if tot else 0.0}
                        for k, v in usages.items() if k), key=lambda x: -x["bytes"])
        dlist = sorted(dsts.values(), key=lambda x: -x["bytes"])[:8]
        clist = sorted(countries.values(), key=lambda x: -x["bytes"])[:6]
        out.append({"device": did, "name": _client_name(did, dev),
                    "up_bytes": up, "down_bytes": down, "bytes": tot,
                    "flows": int(dev.get("flows", 0) or 0),
                    "first_seen": dev.get("first_seen", 0), "last_seen": dev.get("last_seen", 0),
                    "usages": ulist, "top_dst": dlist, "countries": clist,
                    "sessions": len(fams), "alerts": len(dev.get("alerts", []) or [])})
    out.sort(key=lambda x: -x["bytes"])
    return out


_RISK_SEV = {"exfil_volume": "high", "beaconing": "medium",
             "new_cloud": "medium", "unclassified_external": "low"}


def _derive_stats() -> dict:
    """Compteurs agrégés (protocoles/apps/catégories/talkers/risques) dérivés du
    collector, dans la forme que la cardlet du Hall attend de sbxdpi. Aggregate,
    sans PII (destinations publiques + hash device)."""
    protos, apps, cats, talkers, risks = {}, {}, {}, {}, {}
    total_bytes = total_flows = 0
    for dev in _collector_devices():
        for c, b in (dev.get("by_category") or {}).items():
            cats[c] = cats.get(c, 0) + int(b or 0)
        for a in (dev.get("alerts") or []):
            k = a.get("kind") or "alert"
            risks[k] = risks.get(k, 0) + 1
        for s in dev.get("services", []):
            b = int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
            fl = int(s.get("flows", 0) or 0)
            total_bytes += b
            total_flows += fl
            proto = (s.get("proto") or "Unknown").split(".")[0]
            protos[proto] = protos.get(proto, 0) + b
            app = s.get("service") or _classify(s.get("dst", "")).get("application") or ""
            if app:
                apps[app] = apps.get(app, 0) + b
            dst = s.get("dst", "")
            if dst:
                talkers[dst] = talkers.get(dst, 0) + b

    def pctlist(m: dict, tot: int, n: int) -> list:
        out = [{"name": k, "bytes": v, "pct": (v / tot * 100) if tot else 0.0}
               for k, v in m.items() if k]
        out.sort(key=lambda x: -x["bytes"])
        return out[:n]
    return {
        "connected": True,
        "total_flows": total_flows, "total_bytes": total_bytes,
        "updated_at": int(time.time()),
        "protocols": pctlist(protos, total_bytes, 40),
        "apps": pctlist(apps, total_bytes, 40),
        "categories": pctlist(cats, sum(cats.values()), 40),
        "talkers": pctlist(talkers, total_bytes, 40),
        "risks": [{"name": k, "severity": _RISK_SEV.get(k, "low"), "count": v}
                  for k, v in sorted(risks.items(), key=lambda x: -x[1])],
    }


@app.get("/usage")
async def dpi_usage(user=Depends(require_jwt)):
    """Vue usage enrichie. sbxdpi si vivant, sinon dérivée du collector (réel)."""
    live = await _sbxdpi_get("/api/v1/dpi/usage", {})
    if live and (live.get("usages") or live.get("unknown")):
        return live
    return _derive_usage()


@app.get("/suggestions")
async def dpi_suggestions(user=Depends(require_jwt)):
    """Suggestions du learner : sbxdpi si vivant, sinon dérivées du collector."""
    live = await _sbxdpi_get("/api/v1/dpi/suggestions", [])
    return live or _derive_suggestions()


@app.get("/sessions")
async def dpi_sessions(user=Depends(require_jwt)):
    """Sessions d'usage : sbxdpi si vivant, sinon dérivées du collector (par
    device + usage), avec durée = first_seen→last_seen du device."""
    live = await _sbxdpi_get("/api/v1/dpi/sessions", [])
    return live or _derive_sessions()


@app.get("/clients")
async def dpi_clients(user=Depends(require_jwt)):
    """Détail par terminal (device) — vue clients enrichie."""
    live = await _sbxdpi_get("/api/v1/dpi/clients", [])
    return live or _derive_clients()


# ── Pays (géo des destinations) ─────────────────────────────────────────────
# Dérivé des IP de destination RÉELLES du collector (services[].dst quand c'est
# une IP publique) via GeoLite2-Country. Additif, lecture seule, agrégé par pays
# — pas de PII (destinations publiques). Base MaxMind déjà présente sur la box.
import ipaddress as _ipaddr  # noqa: E402

_GEO_PATHS = ("/var/lib/GeoIP/GeoLite2-Country.mmdb",
              "/usr/share/GeoIP/GeoLite2-Country.mmdb")
_geo_reader = None
_geo_tried = False


def _geo():
    global _geo_reader, _geo_tried
    if _geo_tried:
        return _geo_reader
    _geo_tried = True
    try:
        import geoip2.database
        for p in _GEO_PATHS:
            if Path(p).exists():
                _geo_reader = geoip2.database.Reader(p)
                break
    except Exception:
        _geo_reader = None
    return _geo_reader


def _is_ip(s: str) -> bool:
    try:
        _ipaddr.ip_address((s or "").strip())
        return True
    except ValueError:
        return False


def _country_of(ip: str):
    r = _geo()
    if not r:
        return None
    try:
        c = r.country(ip)
        iso = (c.country.iso_code or "").upper()
        if not iso:
            return None
        return iso, (c.country.names.get("fr") or c.country.name or iso)
    except Exception:
        return None


def _flag(iso: str) -> str:
    iso = (iso or "").upper()
    if len(iso) != 2 or not iso.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in iso)


def _derive_countries() -> list:
    by: dict = {}
    total = 0
    for dev in _collector_devices():
        did = dev.get("device", "")
        for s in dev.get("services", []):
            dst = (s.get("dst") or "").strip()
            if not _is_ip(dst):
                continue
            try:  # IP privée/loopback = trafic interne, pas un pays.
                if _ipaddr.ip_address(dst).is_private:
                    continue
            except ValueError:
                continue
            cc = _country_of(dst)
            if not cc:
                continue
            iso, name = cc
            b = int(s.get("up_bytes", 0) or 0) + int(s.get("down_bytes", 0) or 0)
            fl = int(s.get("flows", 0) or 0)
            total += b
            a = by.get(iso)
            if a is None:
                a = {"cc": iso, "flag": _flag(iso), "name": name,
                     "bytes": 0, "flows": 0, "hosts": set(), "devices": set()}
                by[iso] = a
            a["bytes"] += b
            a["flows"] += fl
            a["hosts"].add(dst)
            if did:
                a["devices"].add(did)
    out = [{"cc": a["cc"], "flag": a["flag"], "name": a["name"],
            "bytes": a["bytes"], "flows": a["flows"],
            "hosts": len(a["hosts"]), "devices": len(a["devices"]),
            "pct": (a["bytes"] / total * 100) if total else 0.0} for a in by.values()]
    out.sort(key=lambda x: (-x["bytes"], -x["flows"]))
    return out


@app.get("/countries")
async def dpi_countries(user=Depends(require_jwt)):
    """Top pays des destinations (géo des IP réelles du collector). Additif."""
    live = await _sbxdpi_get("/api/v1/dpi/countries", [])
    return live or _derive_countries()


# ── Relais public agrégé pour le Hall (/pub, SANS JWT) ───────────────────────
# Même posture que le socket sbxdpi (hall.vhost.conf #1360) : lecture seule,
# GET, compteurs AGRÉGÉS et non nominatifs — pas de PII. Le Hall relaie
# /api/v1/dpi/<x> vers /pub/<x>. Les écritures (/rules/accept…) ne sont PAS ici
# et restent derrière le JWT du portail. Distinct des routes JWT : un client du
# Hall ne peut atteindre que ces cinq lectures agrégées.
pub = APIRouter(prefix="/pub")


@pub.get("/stats", dependencies=[Depends(require_lecture)])
def pub_stats():
    return _derive_stats()


@pub.get("/usage", dependencies=[Depends(require_lecture)])
def pub_usage():
    return _derive_usage()


@pub.get("/suggestions", dependencies=[Depends(require_lecture)])
def pub_suggestions():
    return _derive_suggestions()


@pub.get("/sessions", dependencies=[Depends(require_lecture)])
def pub_sessions():
    return _derive_sessions()


@pub.get("/clients", dependencies=[Depends(require_lecture)])
def pub_clients():
    return _derive_clients()


@pub.get("/countries", dependencies=[Depends(require_lecture)])
def pub_countries():
    return _derive_countries()


app.include_router(pub)


def formatBytesPy(o: int) -> str:
    o = int(o or 0)
    for unit, div in (("Go", 1 << 30), ("Mo", 1 << 20), ("Ko", 1 << 10)):
        if o >= div:
            return f"{o/div:.1f} {unit}"
    return f"{o} o"


app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("dpi")

# Configuration paths
# Les endpoints legacy lisent le moteur LIVE sbxdpi (nDPI 5.x → nDPIsrvd →
# sbxdpi) via sa socket HTTP unix.
DPI_LIVE_SOCK = "/run/secubox/dpi-live.sock"
DATA_DIR = Path("/var/lib/secubox/dpi")
HISTORY_FILE = DATA_DIR / "traffic_history.json"
QUOTAS_FILE = DATA_DIR / "quotas.json"
ALERTS_FILE = DATA_DIR / "alert_config.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Stats collection interval (seconds)
STATS_INTERVAL = 60
MAX_HISTORY_ENTRIES = 1440  # 24 hours at 1-minute intervals


# ============================================================================
# Tampon média — liste / relecture / vignette (ref #812, #814, #815)
#
# Lit le journal de métatags du tampon média de sbxmitm et sert la relecture
# d'une capture. Chaque handler est un `def` : ce module est monté DANS
# l'agrégateur, un `async def` bloquant figerait la boucle partagée (ref #808) ;
# FastAPI exécute les `def` dans un pool de threads. Le chemin de l'objet se
# DÉDUIT du session_id de l'ENREGISTREMENT sous MEDIA_BUFFER_ROOT, jamais d'une
# entrée client, et son realpath est vérifié dans la racine (défense en
# profondeur contre la traversée).
#
# CONTRÔLE D'ACCÈS. Une capture, c'est le trafic d'un usager : seul un
# administrateur réel la relit — ou, plus tard, son propriétaire (phase 3).
# Chaque relecture est écrite dans audit.log AVANT d'être servie, et si la
# ligne ne peut pas s'écrire la relecture est refusée : pas de lecture sans
# trace.
#
# LES OCTETS SERVIS VIENNENT DU TRAFIC CAPTURÉ, donc d'un tiers — leur
# Content-Type aussi. Servis tels quels depuis l'origine d'administration, un
# « text/html » capturé s'exécuterait avec la session de l'admin qui clique
# « Play ». Seuls les types audio/vidéo/HLS passent ; le reste part en
# application/octet-stream, avec nosniff.
# ============================================================================
import os  # noqa: E402
import re  # noqa: E402
import glob  # noqa: E402
from datetime import timezone  # noqa: E402
from fastapi import Request, Response  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from secubox_core import media_buffer  # noqa: E402
from secubox_core import hls  # noqa: E402
from secubox_core.auth import est_admin_reel, adresse_client  # noqa: E402

MEDIA_BUFFER_ROOT = "/data/secubox/media-buffer"
AUDIT_LOG = "/var/log/secubox/audit.log"
# \Z (et non $) : $ accepte un « \n » final, qui passerait la garde.
_REC_ID_RE = re.compile(r"^[0-9a-f]{8,32}\Z")
# Types servis tels quels : ceux qu'un navigateur ne peut PAS exécuter.
_CTYPES_MEDIA = ("video/", "audio/")
_CTYPES_HLS = {"application/vnd.apple.mpegurl", "application/x-mpegurl"}
_ENTETES_MEDIA = {"X-Content-Type-Options": "nosniff"}


def _media_log_path() -> str:
    """Chemin du JSONL de métatags, dérivé de MEDIA_BUFFER_ROOT (remplacé
    dans les tests)."""
    return os.path.join(MEDIA_BUFFER_ROOT, "media-buffer.jsonl")


def _user_is_admin(user) -> bool:
    """Le porteur est-il un ADMINISTRATEUR RÉEL ?

    Délègue à secubox_core.auth.est_admin_reel (#1581), le prédicat même de
    `require_jwt` : un compte utilisateur actif, de rôle « admin » dans le
    registre — jamais une session d'appareil (sbx-…), jamais une session
    plafonnée sous admin. Le rôle se lit dans le REGISTRE, pas dans une
    revendication `role` portée par le payload : le raccourci d'origine (#812)
    qui la croyait sur parole est retiré."""
    if not isinstance(user, dict):
        return False
    return est_admin_reel(user)


def require_admin_or_owner(user=Depends(require_jwt)):
    """Garde de relecture/vignette : administrateur — ou, un jour, propriétaire.

    Aucune correspondance session → persona (mac_hash) n'existe encore : un
    non-admin n'est propriétaire de rien, il est refusé (403). `require_jwt`
    exige déjà un administrateur réel (#1581) ; ce second contrôle, porté par
    la garde elle-même, tient même si la dépendance amont s'assouplissait.

    # TODO(phase3) : n'admettre un non-admin que si le mac_hash de
    # l'enregistrement demandé est celui de sa persona.
    """
    if _user_is_admin(user):
        return user
    raise HTTPException(status_code=403, detail="Réservé aux administrateurs de la box")


def _resolve_object_path(rec: dict) -> Optional[str]:
    """Objet du tampon sur disque pour un enregistrement, sans traversée.

    L'objet vit en <MEDIA_BUFFER_ROOT>/<session_id>/object-0.* — session_id
    est validé contre l'expression hexadécimale, et le realpath obtenu doit
    rester sous MEDIA_BUFFER_ROOT. None si l'id est malformé, si le fichier a
    disparu ou si la résolution sort de la racine.
    """
    session_id = (rec or {}).get("session_id")
    if not session_id or not _REC_ID_RE.match(str(session_id)):
        return None
    root = os.path.realpath(MEDIA_BUFFER_ROOT)
    session_dir = os.path.realpath(os.path.join(root, session_id))
    if session_dir != root and not session_dir.startswith(root + os.sep):
        return None
    for cand in sorted(glob.glob(os.path.join(session_dir, "object-0.*"))):
        real = os.path.realpath(cand)
        if (real == root or real.startswith(root + os.sep)) and os.path.isfile(real):
            return real
    return None


_CTYPE_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*\Z")


def _ctype_sur(ctype) -> str:
    """Content-Type à servir pour une capture : son type principal (sans
    paramètres) s'il est audio/vidéo/HLS et bien formé, sinon
    application/octet-stream — le navigateur télécharge, n'exécute rien. Ni
    paramètre ni caractère libre ne remonte jusqu'à l'en-tête de réponse."""
    principal = str(ctype or "").split(";", 1)[0].strip().lower()
    if _CTYPE_RE.match(principal) and (principal.startswith(_CTYPES_MEDIA)
                                       or principal in _CTYPES_HLS):
        return principal
    return "application/octet-stream"


_AUDIT_HORS_CHAMP_RE = re.compile(r"[^\x21-\x7e]")


def _audit_champ(valeur) -> str:
    """Un champ de ligne d'audit : ni espace, ni caractère de contrôle, borné.
    `host` vient du trafic capturé : un « \\n » y forgerait une seconde ligne
    dans le journal."""
    s = _AUDIT_HORS_CHAMP_RE.sub("_", "" if valeur is None else str(valeur))
    return s[:256] or "-"


def _audit_replay(sub, rec_id: str, host: str, ip: str) -> bool:
    """Ajoute UNE ligne d'audit (horodatage RFC 3339) pour une relecture.

    Rend False si la ligne n'a pas pu être écrite : l'appelant refuse alors
    de servir. `os.open` en O_APPEND, pas de réécriture du journal."""
    ts = datetime.now(timezone.utc).isoformat()
    line = (f"{ts} media-replay sub={_audit_champ(sub)} rec_id={_audit_champ(rec_id)} "
            f"host={_audit_champ(host)} ip={_audit_champ(ip)}\n").encode("utf-8", "replace")
    try:
        fd = os.open(AUDIT_LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            return os.write(fd, line) == len(line)
        finally:
            os.close(fd)
    except OSError as e:
        log.error("dpi media : audit.log non inscriptible (%s) — relecture %s refusée",
                  e, rec_id)
        return False


# ============================================================================
# Phase 2 (#812) — réassemblage des manifestes HLS.
#
# Les segments sont des objets ordinaires du tampon (kind="segment"), servis
# tels quels par GET /media/replay/{id}. Quand l'enregistrement demandé est un
# manifeste, media_replay() analyse la playlist stockée (secubox_core.hls) et
# réécrit chaque URI de segment vers l'URL de relecture du segment capturé
# correspondant — une jointure PURE, à la lecture, par URL absolue ; jamais un
# état de session partagé entre requêtes.
# ============================================================================
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_SEGMENT_INDEX = 5000
MAX_MANIFEST_SEGMENTS = 5000


def _segment_index(mac_hash: Optional[str], host: Optional[str]) -> Dict[str, str]:
    """Associe l'`url` absolue d'un segment capturé à l'`id` de son
    enregistrement.

    Limité au MÊME mac_hash + host que le manifeste relu (jamais de jointure
    entre personas ou hôtes) ; seuls les `kind=="segment"` vivants (non
    expirés) comptent. Borné à MAX_SEGMENT_INDEX entrées pour qu'une session
    pathologique ne fasse pas exploser la jointure. Fail-empty : {}.
    """
    try:
        records = media_buffer.read_records(mac_hash=mac_hash, path=_media_log_path())
    except Exception:
        return {}
    out: Dict[str, str] = {}
    try:
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("kind") != "segment":
                continue
            if rec.get("expired"):
                continue
            if rec.get("host") != host:
                continue
            url = rec.get("url")
            seg_id = rec.get("id")
            if not url or not seg_id:
                continue
            out[url] = seg_id
            if len(out) >= MAX_SEGMENT_INDEX:
                log.warning("dpi media : index de segments pour %s plafonné à %d",
                            host, MAX_SEGMENT_INDEX)
                break
    except Exception:
        return out
    return out


def _replay_manifest(rec: dict, path: str) -> Optional[Response]:
    """Relecture d'un manifeste : analyse la playlist capturée et réécrit les
    URI de segments vers les URL de relecture des segments capturés.

    Les playlists maîtres/multivariantes (ABR) et chiffrées (#EXT-X-KEY) sont
    hors périmètre de la phase 2 : le manifeste brut est rendu inchangé avec
    l'en-tête `X-SecuBox-Media: unsupported-variant`, plutôt qu'une réécriture
    cassée.

    Sûr en cas d'échec : toute erreur de lecture/analyse rend None, et
    l'appelant retombe sur le FileResponse brut de la phase 1 — cette branche
    ne doit JAMAIS produire un 500.
    """
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            log.warning("dpi media : manifeste %s tronqué à %d octets",
                        rec.get("id") or rec.get("url") or "?", MAX_MANIFEST_BYTES)
            raw = raw[:MAX_MANIFEST_BYTES]
        text = raw.decode("utf-8", errors="replace")

        if hls.is_master_playlist(text) or hls.is_encrypted(text):
            return Response(content=text, media_type="application/vnd.apple.mpegurl",
                            headers={**_ENTETES_MEDIA,
                                     "X-SecuBox-Media": "unsupported-variant"})

        mapping = {
            seg_url: f"/api/v1/dpi/media/replay/{seg_id}"
            for seg_url, seg_id in _segment_index(rec.get("mac_hash"), rec.get("host")).items()
        }
        rewritten, matched, total = hls.rewrite(
            text, mapping, rec.get("url") or "", max_segments=MAX_MANIFEST_SEGMENTS
        )
        if total >= MAX_MANIFEST_SEGMENTS:
            log.warning("dpi media : réécriture plafonnée à %d segments (total=%d matched=%d)",
                        MAX_MANIFEST_SEGMENTS, total, matched)
        return Response(
            content=rewritten,
            media_type="application/vnd.apple.mpegurl",
            headers={**_ENTETES_MEDIA,
                     "X-SecuBox-Media": f"hls-reassembled; matched={matched}; total={total}"},
        )
    except Exception:
        return None


class QuotaType(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class QuotaAction(str, Enum):
    ALERT = "alert"
    THROTTLE = "throttle"
    BLOCK = "block"


class BandwidthQuota(BaseModel):
    target: str  # app name, MAC address, or "all"
    target_type: str = "app"  # app, device, category
    quota_bytes: int = Field(ge=0)
    quota_type: QuotaType = QuotaType.DAILY
    action: QuotaAction = QuotaAction.ALERT
    throttle_kbps: int = 0  # If action is throttle
    enabled: bool = True
    current_usage: int = 0
    last_reset: Optional[str] = None


class AlertThreshold(BaseModel):
    name: str
    metric: str  # bandwidth_total, bandwidth_app, new_device, suspicious_app
    threshold: float
    comparison: str = "gt"  # gt, lt, eq
    enabled: bool = True
    cooldown_minutes: int = 15
    last_triggered: Optional[str] = None


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = ["quota_exceeded", "alert_triggered", "anomaly_detected"]
    enabled: bool = True
    secret: Optional[str] = None


class TrafficStats(BaseModel):
    timestamp: str
    rx_bytes: int
    tx_bytes: int
    total_bytes: int
    flows_active: int
    top_apps: List[Dict[str, Any]]
    top_devices: List[Dict[str, Any]]


# ============================================================================
# Traffic History Management
# ============================================================================

_traffic_history: List[Dict] = []
_history_lock = threading.Lock()


def load_traffic_history() -> List[Dict]:
    """Load traffic history from file."""
    global _traffic_history
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                _traffic_history = json.load(f)
        except Exception:
            _traffic_history = []
    return _traffic_history


def save_traffic_history():
    """Save traffic history to file."""
    with _history_lock:
        # Keep only recent entries
        history = _traffic_history[-MAX_HISTORY_ENTRIES:]
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(history, f)
        except Exception:
            pass


def add_traffic_stats(stats: TrafficStats):
    """Add traffic stats to history."""
    global _traffic_history
    with _history_lock:
        _traffic_history.append(stats.dict())
        if len(_traffic_history) > MAX_HISTORY_ENTRIES:
            _traffic_history = _traffic_history[-MAX_HISTORY_ENTRIES:]


# ============================================================================
# Quota Management
# ============================================================================

def load_quotas() -> Dict[str, BandwidthQuota]:
    """Load bandwidth quotas."""
    if QUOTAS_FILE.exists():
        try:
            with open(QUOTAS_FILE) as f:
                data = json.load(f)
                return {k: BandwidthQuota(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_quotas(quotas: Dict[str, BandwidthQuota]):
    """Save bandwidth quotas."""
    try:
        with open(QUOTAS_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in quotas.items()}, f, indent=2)
    except Exception:
        pass


def check_quotas(app_traffic: Dict[str, int], device_traffic: Dict[str, int]):
    """Check traffic against quotas and trigger actions."""
    quotas = load_quotas()
    alerts = []

    for name, quota in quotas.items():
        if not quota.enabled:
            continue

        usage = 0
        if quota.target_type == "app" and quota.target in app_traffic:
            usage = app_traffic[quota.target]
        elif quota.target_type == "device" and quota.target in device_traffic:
            usage = device_traffic[quota.target]
        elif quota.target == "all":
            usage = sum(app_traffic.values())

        quota.current_usage = usage

        if usage >= quota.quota_bytes:
            alerts.append({
                "quota_name": name,
                "target": quota.target,
                "usage": usage,
                "limit": quota.quota_bytes,
                "action": quota.action.value
            })

            # Apply action
            if quota.action == QuotaAction.THROTTLE and quota.throttle_kbps > 0:
                # Apply tc throttling (would need implementation)
                pass
            elif quota.action == QuotaAction.BLOCK:
                # Add to block rules (would need implementation)
                pass

    save_quotas(quotas)
    return alerts


# ============================================================================
# Alert Management
# ============================================================================

def load_alert_config() -> Dict[str, AlertThreshold]:
    """Load alert thresholds."""
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE) as f:
                data = json.load(f)
                return {k: AlertThreshold(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_alert_config(alerts: Dict[str, AlertThreshold]):
    """Save alert thresholds."""
    try:
        with open(ALERTS_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in alerts.items()}, f, indent=2)
    except Exception:
        pass


# ============================================================================
# Webhook Notifications
# ============================================================================

def load_webhooks() -> List[WebhookConfig]:
    """Load webhook configurations."""
    if WEBHOOKS_FILE.exists():
        try:
            with open(WEBHOOKS_FILE) as f:
                return [WebhookConfig(**wh) for wh in json.load(f)]
        except Exception:
            pass
    return []


def save_webhooks(webhooks: List[WebhookConfig]):
    """Save webhook configurations."""
    try:
        with open(WEBHOOKS_FILE, 'w') as f:
            json.dump([wh.dict() for wh in webhooks], f, indent=2)
    except Exception:
        pass


async def send_webhook(event: str, data: Dict[str, Any]):
    """Send webhook notification."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if not wh.enabled or event not in wh.events:
            continue

        payload = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": data
        }

        try:
            headers = {"Content-Type": "application/json"}
            if wh.secret:
                import hashlib, hmac
                sig = hmac.new(wh.secret.encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = sig

            async with httpx.AsyncClient() as client:
                await client.post(wh.url, json=payload, headers=headers, timeout=5.0)
        except Exception:
            pass

async def _sbxdpi_get(path: str):
    """Lit un endpoint de sbxdpi (moteur nDPI LIVE) via dpi-live.sock.

    Classification live. Fail-empty si la socket dort (sbxdpi dark avant
    cutover complet)."""
    if not Path(DPI_LIVE_SOCK).exists():
        return {"error": "sbxdpi socket unavailable"}
    try:
        transport = httpx.AsyncHTTPTransport(uds=DPI_LIVE_SOCK)
        async with httpx.AsyncClient(transport=transport, timeout=5.0) as cli:
            r = await cli.get("http://sbxdpi/api/v1/dpi/" + path)
            return r.json()
    except Exception as e:
        log.warning("sbxdpi query error: %s", e)
        return {"error": str(e)}

def _legacy_dpi_query(cmd: dict) -> dict:
    """SHIM de dépréciation : les endpoints legacy profonds (dns_queries,
    ssl_fingerprints, flow-by-id…) qui n'ont pas encore d'équivalent sbxdpi
    renvoient une erreur claire. Les surfaces clés (status/flows/applications/
    devices/risks/talkers) sont, elles, re-branchées sur sbxdpi (_sbxdpi_get).
    À migrer au fil de l'eau."""
    return {"error": "endpoint legacy sans moteur — nDPI (sbxdpi). à migrer.",
            "retired": True}

def _setup_mirred(iface: str, mirror_if: str = "ifb0") -> dict:
    """Configure tc mirred + ifb0 pour DPI dual-stream."""
    cmds = [
        ["ip", "link", "add", mirror_if, "type", "ifb"],
        ["ip", "link", "set", mirror_if, "up"],
        ["tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"],
        ["tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect",
         "dev", mirror_if],
        ["tc", "qdisc", "add", "dev", iface, "handle", "1:", "prio"],
        ["tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "mirror",
         "dev", mirror_if],
    ]
    results = []
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": " ".join(cmd[-3:]), "ok": r.returncode == 0,
                        "err": r.stderr.strip()[:100] if r.returncode != 0 else ""})
    return {"steps": results, "interface": iface, "mirror": mirror_if}


@router.get("/media/buffer")
def media_buffer_list(user=Depends(require_jwt)):
    """Captures du tampon média. L'administrateur les voit toutes ; un
    non-admin n'en voit aucune tant que la correspondance persona n'existe
    pas. `def` : lecture bornée, hors boucle (#808). Fail-empty."""
    if _user_is_admin(user):
        items = media_buffer.read_records(path=_media_log_path())
    else:
        # TODO(phase3) : limiter au mac_hash de la persona de l'appelant.
        # D'ici là, un non-admin n'est propriétaire de rien.
        items = []
    return {"items": items, "count": len(items)}


@router.get("/media/replay/{rec_id}")
def media_replay(rec_id: str, request: Request = None,
                 user=Depends(require_admin_or_owner)):
    """Sert les octets d'une capture — administrateur/propriétaire, audité.

    410 dès que le janitor a évincé les octets (métatag seul). Le chemin de
    l'objet se déduit du session_id de l'ENREGISTREMENT sous
    MEDIA_BUFFER_ROOT — jamais de `rec_id`, validé en plus contre une
    expression hexadécimale stricte. 503 si la ligne d'audit ne peut pas
    s'écrire : aucune relecture ne part sans trace.

    Phase 2 (#812) : pour un manifeste HLS capturé (kind=="manifest"), la
    réponse est la playlist RÉÉCRITE dont les URI de segments pointent vers
    les relectures des segments capturés (voir `_replay_manifest`). Tout autre
    kind (video/audio/file/segment) garde le FileResponse de la phase 1.
    """
    if not _REC_ID_RE.match(rec_id or ""):
        raise HTTPException(status_code=400, detail="invalid record id")
    rec = media_buffer.record_by_id(rec_id, path=_media_log_path())
    if not rec or rec.get("expired") or rec.get("buffer_ref") is None:
        raise HTTPException(status_code=410, detail="media evicted — metatag only")
    path = _resolve_object_path(rec)
    if not path:
        raise HTTPException(status_code=410, detail="media evicted — metatag only")
    sub = user.get("sub") if isinstance(user, dict) else None
    ip = ""
    try:
        if request is not None:
            ip = adresse_client(request)   # depuis la droite de XFF (#1753)
    except Exception:
        ip = ""
    # Une seule ligne par relecture, écrite AVANT d'envoyer quoi que ce soit —
    # quelle que soit la branche (manifeste réécrit ou objet brut).
    if not _audit_replay(sub, rec_id, rec.get("host") or "", ip):
        raise HTTPException(status_code=503,
                            detail="journal d'audit indisponible — relecture refusée")

    if rec.get("kind") == "manifest":
        manifest_resp = _replay_manifest(rec, path)
        if manifest_resp is not None:
            return manifest_resp
        # Sûr en cas d'échec : une erreur de lecture/analyse du manifeste
        # retombe sur le FileResponse brut ci-dessous — jamais un 500.

    return FileResponse(path, media_type=_ctype_sur(rec.get("ctype")),
                        headers=dict(_ENTETES_MEDIA))


@router.get("/media/thumb/{rec_id}")
def media_thumb(rec_id: str, user=Depends(require_admin_or_owner)):
    """Sert <session>/thumb.jpg d'une capture. Aucune génération de vignette
    pour l'instant : 404 tant qu'il n'en existe pas. Même validation stricte
    de l'id et même résolution sans traversée que la relecture."""
    if not _REC_ID_RE.match(rec_id or ""):
        raise HTTPException(status_code=400, detail="invalid record id")
    rec = media_buffer.record_by_id(rec_id, path=_media_log_path())
    session_id = (rec or {}).get("session_id")
    if rec and session_id and _REC_ID_RE.match(str(session_id)):
        root = os.path.realpath(MEDIA_BUFFER_ROOT)
        thumb = os.path.realpath(os.path.join(root, session_id, "thumb.jpg"))
        if (thumb == root or thumb.startswith(root + os.sep)) and os.path.isfile(thumb):
            return FileResponse(thumb, media_type="image/jpeg", headers=dict(_ENTETES_MEDIA))
    raise HTTPException(status_code=404, detail="no thumbnail (Phase 2)")


@router.get("/status")
async def status(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    h = await _sbxdpi_get("health")
    connected = bool(isinstance(h, dict) and h.get("connected"))
    return {"running": connected, "mode": cfg.get("mode", "inline"),
            "engine": "ndpi", "interface": cfg.get("interface", "eth2"),
            "connected": connected,
            "total_flows": h.get("total_flows") if isinstance(h, dict) else None,
            "total_bytes": h.get("total_bytes") if isinstance(h, dict) else None,
            "filtered": h.get("filtered") if isinstance(h, dict) else None}

# Endpoints legacy re-branchés sur sbxdpi (nDPI live). Formes sbxdpi :
#   top_apps/top_protocols/top_categories → [{name,flows,bytes,pct}]
#   talkers → [{name:"src → dst",flows,bytes,pct}] ; risks → [{name,count,severity}]
@router.get("/flows")
async def flows(user=Depends(require_jwt)):
    return await _sbxdpi_get("stats")

@router.get("/applications")
async def applications(user=Depends(require_jwt)):
    return await _sbxdpi_get("top_apps")

@router.get("/devices")
async def devices(user=Depends(require_jwt)):
    return await _sbxdpi_get("talkers")

@router.get("/risks")
async def risks(user=Depends(require_jwt)):
    return await _sbxdpi_get("risks")

@router.get("/talkers")
async def talkers(user=Depends(require_jwt)):
    return await _sbxdpi_get("talkers")

@router.post("/setup_mirred")
async def setup_mirred(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    return _setup_mirred(cfg.get("interface","eth0"), cfg.get("mirror_if","ifb0"))


@router.get("/apps")
async def apps(user=Depends(require_jwt)):
    """Liste des applications détectées."""
    return _legacy_dpi_query({"type": "get_applications"})


@router.get("/protocols")
async def protocols(user=Depends(require_jwt)):
    """Protocoles détectés."""
    return _legacy_dpi_query({"type": "get_protocols"})


@router.get("/categories")
async def categories(user=Depends(require_jwt)):
    """Catégories d'applications."""
    return [
        {"id": "streaming", "name": "Streaming", "apps": ["netflix", "youtube", "twitch"]},
        {"id": "social", "name": "Réseaux sociaux", "apps": ["facebook", "instagram", "tiktok"]},
        {"id": "gaming", "name": "Jeux", "apps": ["steam", "xbox", "playstation"]},
        {"id": "productivity", "name": "Productivité", "apps": ["office365", "google_drive", "zoom"]},
        {"id": "p2p", "name": "P2P/Torrent", "apps": ["bittorrent", "emule"]},
    ]


@router.get("/top_apps")
async def top_apps(limit: int = 10, user=Depends(require_jwt)):
    """Top applications par trafic."""
    flows = _legacy_dpi_query({"type": "get_flows"})
    if "error" in flows:
        return []
    # Aggregate by app
    app_traffic = {}
    for f in flows.get("flows", []):
        app = f.get("detected_application_name", "unknown")
        app_traffic[app] = app_traffic.get(app, 0) + f.get("bytes", 0)
    sorted_apps = sorted(app_traffic.items(), key=lambda x: -x[1])[:limit]
    return [{"app": a, "bytes": b} for a, b in sorted_apps]


@router.get("/top_protocols")
async def top_protocols(limit: int = 10, user=Depends(require_jwt)):
    """Top protocoles par trafic."""
    flows = _legacy_dpi_query({"type": "get_flows"})
    if "error" in flows:
        return []
    proto_traffic = {}
    for f in flows.get("flows", []):
        proto = f.get("detected_protocol_name", "unknown")
        proto_traffic[proto] = proto_traffic.get(proto, 0) + f.get("bytes", 0)
    sorted_protos = sorted(proto_traffic.items(), key=lambda x: -x[1])[:limit]
    return [{"protocol": p, "bytes": b} for p, b in sorted_protos]


@router.get("/bandwidth_by_app")
async def bandwidth_by_app(user=Depends(require_jwt)):
    """Bande passante par application."""
    return await top_apps(20, user)


@router.get("/bandwidth_by_device")
async def bandwidth_by_device(user=Depends(require_jwt)):
    """Bande passante par appareil."""
    flows = _legacy_dpi_query({"type": "get_flows"})
    if "error" in flows:
        return []
    device_traffic = {}
    for f in flows.get("flows", []):
        mac = f.get("local_mac", "unknown")
        device_traffic[mac] = device_traffic.get(mac, 0) + f.get("bytes", 0)
    sorted_devs = sorted(device_traffic.items(), key=lambda x: -x[1])[:20]
    return [{"mac": d, "bytes": b} for d, b in sorted_devs]


@router.get("/active_flows")
async def active_flows(user=Depends(require_jwt)):
    """Flux actifs."""
    return _legacy_dpi_query({"type": "get_flows"})


@router.get("/flow_details")
async def flow_details(flow_id: str, user=Depends(require_jwt)):
    """Détails d'un flux."""
    return _legacy_dpi_query({"type": "get_flow", "flow_id": flow_id})


@router.get("/device_flows")
async def device_flows(mac: str, user=Depends(require_jwt)):
    """Flux d'un appareil."""
    flows = _legacy_dpi_query({"type": "get_flows"})
    if "error" in flows:
        return []
    return [f for f in flows.get("flows", []) if f.get("local_mac") == mac]


@router.get("/realtime")
def realtime(user=Depends(require_jwt)):
    """Statistiques temps réel."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    stats_path = Path(f"/sys/class/net/{iface}/statistics")
    if not stats_path.exists():
        return {"error": "Interface not found"}
    return {
        "rx_bytes": int((stats_path / "rx_bytes").read_text().strip()),
        "tx_bytes": int((stats_path / "tx_bytes").read_text().strip()),
        "rx_packets": int((stats_path / "rx_packets").read_text().strip()),
        "tx_packets": int((stats_path / "tx_packets").read_text().strip()),
    }


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    """Statistiques DPI."""
    return _legacy_dpi_query({"type": "get_stats"})


from pydantic import BaseModel


class BlockRuleRequest(BaseModel):
    app_or_category: str
    action: str = "block"  # block, limit, mark
    limit_kbps: int = 0


@router.get("/block_rules")
def block_rules(user=Depends(require_jwt)):
    """Règles de blocage."""
    rules_file = Path("/etc/secubox/dpi-rules.json")
    if rules_file.exists():
        return json.loads(rules_file.read_text())
    return []


@router.post("/add_block_rule")
def add_block_rule(req: BlockRuleRequest, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/dpi-rules.json")
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    rules = json.loads(rules_file.read_text()) if rules_file.exists() else []
    rules.append(req.model_dump())
    rules_file.write_text(json.dumps(rules, indent=2))
    log.info("DPI rule added: %s", req.app_or_category)
    return {"success": True}


@router.post("/delete_block_rule")
def delete_block_rule(app_or_category: str, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/dpi-rules.json")
    if rules_file.exists():
        rules = json.loads(rules_file.read_text())
        rules = [r for r in rules if r.get("app_or_category") != app_or_category]
        rules_file.write_text(json.dumps(rules, indent=2))
    return {"success": True}


@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    """Alertes DPI."""
    return _legacy_dpi_query({"type": "get_alerts"})


@router.get("/dns_queries")
async def dns_queries(limit: int = 100, user=Depends(require_jwt)):
    """Requêtes DNS interceptées."""
    return _legacy_dpi_query({"type": "get_dns_queries", "limit": limit})


@router.get("/ssl_flows")
async def ssl_flows(user=Depends(require_jwt)):
    """Flux SSL/TLS."""
    flows = _legacy_dpi_query({"type": "get_flows"})
    if "error" in flows:
        return []
    return [f for f in flows.get("flows", []) if f.get("ssl", {}).get("enabled")]


@router.get("/ssl_fingerprints")
async def ssl_fingerprints(user=Depends(require_jwt)):
    """Empreintes JA3/JA3S."""
    return _legacy_dpi_query({"type": "get_ssl_fingerprints"})


class DpiSettingsRequest(BaseModel):
    interface: str = "eth0"
    mirror_if: str = "ifb0"
    mode: str = "inline"  # inline, passive, mirror
    enabled: bool = True


@router.get("/settings")
async def settings(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    return {
        "interface": cfg.get("interface", "eth0"),
        "mirror_if": cfg.get("mirror_if", "ifb0"),
        "mode": cfg.get("mode", "inline"),
        "enabled": cfg.get("enabled", True),
    }


@router.post("/save_settings")
async def save_settings(req: DpiSettingsRequest, user=Depends(require_jwt)):
    settings_file = Path("/etc/secubox/dpi.json")
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps(req.model_dump(), indent=2))
    log.info("DPI settings saved")
    return {"success": True}


@router.post("/restart")
def restart(user=Depends(require_jwt)):
    """Contrôle de service DPI legacy retiré (moteur nDPI/sbxdpi géré ailleurs)."""
    return {"success": False, "retired": True}


@router.post("/start")
def start(user=Depends(require_jwt)):
    return {"success": False, "retired": True}


@router.post("/stop")
def stop(user=Depends(require_jwt)):
    return {"success": False, "retired": True}


@router.get("/logs")
def logs(lines: int = 100, user=Depends(require_jwt)):
    return {"lines": []}


@router.get("/interface_list")
def interface_list(user=Depends(require_jwt)):
    """Liste des interfaces."""
    r = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(r.stdout)
        return [l.get("ifname") for l in links if l.get("ifname") != "lo"]
    except Exception:
        return []


@router.get("/tc_status")
def tc_status(user=Depends(require_jwt)):
    """État tc mirred."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    qdisc = subprocess.run(["tc", "qdisc", "show", "dev", iface],
                           capture_output=True, text=True)
    filters = subprocess.run(["tc", "filter", "show", "dev", iface, "parent", "ffff:"],
                             capture_output=True, text=True)
    return {
        "qdisc": qdisc.stdout,
        "filters": filters.stdout,
        "active": "mirred" in filters.stdout,
    }


@router.post("/remove_mirred")
def remove_mirred(user=Depends(require_jwt)):
    """Supprimer la configuration mirred."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    mirror_if = cfg.get("mirror_if", "ifb0")
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "ingress"], capture_output=True)
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    subprocess.run(["ip", "link", "del", mirror_if], capture_output=True)
    return {"success": True}


@router.get("/export_flows")
async def export_flows(format: str = "json", user=Depends(require_jwt)):
    """Exporter les flux."""
    flows = _legacy_dpi_query({"type": "get_flows"})
    if format == "csv":
        lines = ["timestamp,src_ip,dst_ip,app,protocol,bytes"]
        for f in flows.get("flows", []):
            lines.append(f"{f.get('timestamp')},{f.get('local_ip')},{f.get('other_ip')},"
                        f"{f.get('detected_application_name')},{f.get('detected_protocol_name')},"
                        f"{f.get('bytes')}")
        return {"format": "csv", "data": "\n".join(lines)}
    return flows


@router.get("/health")
async def health():
    return {"status": "ok", "module": "dpi", "version": "2.0.0"}


# ============================================================================
# Traffic History Endpoints
# ============================================================================

@router.get("/history")
async def get_traffic_history(
    hours: int = 24,
    resolution: str = "1m",
    user=Depends(require_jwt)
):
    """Get traffic history."""
    history = load_traffic_history()

    # Filter by time
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    history = [h for h in history if h.get("timestamp", "") >= cutoff]

    return {
        "history": history,
        "count": len(history),
        "hours": hours
    }


@router.get("/history/summary")
async def get_history_summary(hours: int = 24, user=Depends(require_jwt)):
    """Get traffic history summary."""
    history = load_traffic_history()

    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    history = [h for h in history if h.get("timestamp", "") >= cutoff]

    if not history:
        return {"error": "No data available"}

    total_rx = sum(h.get("rx_bytes", 0) for h in history)
    total_tx = sum(h.get("tx_bytes", 0) for h in history)
    avg_flows = sum(h.get("flows_active", 0) for h in history) / len(history)

    # Aggregate top apps
    app_totals = defaultdict(int)
    for h in history:
        for app in h.get("top_apps", []):
            app_totals[app.get("app", "unknown")] += app.get("bytes", 0)

    top_apps = sorted(app_totals.items(), key=lambda x: -x[1])[:10]

    return {
        "period_hours": hours,
        "total_rx_bytes": total_rx,
        "total_tx_bytes": total_tx,
        "total_bytes": total_rx + total_tx,
        "avg_active_flows": round(avg_flows, 1),
        "top_apps": [{"app": a, "bytes": b} for a, b in top_apps],
        "data_points": len(history)
    }


@router.post("/history/clear")
async def clear_traffic_history(user=Depends(require_jwt)):
    """Clear traffic history."""
    global _traffic_history
    with _history_lock:
        _traffic_history = []
    save_traffic_history()
    return {"status": "cleared"}


# ============================================================================
# Quota Endpoints
# ============================================================================

@router.get("/quotas")
async def list_quotas(user=Depends(require_jwt)):
    """List bandwidth quotas."""
    quotas = load_quotas()
    return {"quotas": {k: v.dict() for k, v in quotas.items()}}


@router.put("/quotas/{quota_name}")
async def set_quota(quota_name: str, quota: BandwidthQuota, user=Depends(require_jwt)):
    """Create or update a bandwidth quota."""
    quotas = load_quotas()
    quotas[quota_name] = quota
    save_quotas(quotas)
    return {"status": "updated", "quota": quota.dict()}


@router.delete("/quotas/{quota_name}")
async def delete_quota(quota_name: str, user=Depends(require_jwt)):
    """Delete a bandwidth quota."""
    quotas = load_quotas()
    if quota_name not in quotas:
        raise HTTPException(status_code=404, detail="Quota not found")
    del quotas[quota_name]
    save_quotas(quotas)
    return {"status": "deleted"}


@router.post("/quotas/{quota_name}/reset")
async def reset_quota(quota_name: str, user=Depends(require_jwt)):
    """Reset quota usage counter."""
    quotas = load_quotas()
    if quota_name not in quotas:
        raise HTTPException(status_code=404, detail="Quota not found")
    quotas[quota_name].current_usage = 0
    quotas[quota_name].last_reset = datetime.utcnow().isoformat() + "Z"
    save_quotas(quotas)
    return {"status": "reset"}


@router.get("/quotas/status")
async def quota_status(user=Depends(require_jwt)):
    """Get current quota usage status."""
    quotas = load_quotas()
    status = []

    for name, quota in quotas.items():
        percent = (quota.current_usage / quota.quota_bytes * 100) if quota.quota_bytes > 0 else 0
        status.append({
            "name": name,
            "target": quota.target,
            "usage": quota.current_usage,
            "limit": quota.quota_bytes,
            "percent": round(percent, 1),
            "exceeded": quota.current_usage >= quota.quota_bytes,
            "action": quota.action.value
        })

    return {"quotas": status}


# ============================================================================
# Alert Endpoints
# ============================================================================

@router.get("/alerts/config")
async def list_alert_thresholds(user=Depends(require_jwt)):
    """List alert thresholds."""
    alerts = load_alert_config()
    return {"alerts": {k: v.dict() for k, v in alerts.items()}}


@router.put("/alerts/config/{alert_name}")
async def set_alert_threshold(alert_name: str, alert: AlertThreshold, user=Depends(require_jwt)):
    """Create or update an alert threshold."""
    alerts = load_alert_config()
    alert.name = alert_name
    alerts[alert_name] = alert
    save_alert_config(alerts)
    return {"status": "updated", "alert": alert.dict()}


@router.delete("/alerts/config/{alert_name}")
async def delete_alert_threshold(alert_name: str, user=Depends(require_jwt)):
    """Delete an alert threshold."""
    alerts = load_alert_config()
    if alert_name not in alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    del alerts[alert_name]
    save_alert_config(alerts)
    return {"status": "deleted"}


# ============================================================================
# Webhook Endpoints
# ============================================================================

@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    webhooks = load_webhooks()
    return {"webhooks": [wh.dict() for wh in webhooks]}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    """Add a webhook."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if wh.url == webhook.url:
            raise HTTPException(status_code=409, detail="Webhook URL already exists")

    webhooks.append(webhook)
    save_webhooks(webhooks)
    return {"status": "added"}


@router.delete("/webhooks")
async def delete_webhook(url: str, user=Depends(require_jwt)):
    """Delete a webhook by URL."""
    webhooks = load_webhooks()
    original_len = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.url != url]

    if len(webhooks) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    save_webhooks(webhooks)
    return {"status": "deleted"}


@router.post("/webhooks/test")
async def test_webhook(url: str, user=Depends(require_jwt)):
    """Test a webhook."""
    await send_webhook("test", {"message": "Test event from SecuBox DPI"})
    return {"status": "sent"}


# ============================================================================
# Traffic Anomaly Detection
# ============================================================================

@router.get("/anomalies")
async def detect_anomalies(user=Depends(require_jwt)):
    """Detect traffic anomalies based on historical patterns."""
    history = load_traffic_history()

    if len(history) < 60:  # Need at least 1 hour of data
        return {"anomalies": [], "message": "Insufficient data for anomaly detection"}

    # Calculate baseline (average of last 24 hours)
    recent = history[-60:]  # Last hour
    historical = history[:-60] if len(history) > 60 else history

    if not historical:
        return {"anomalies": [], "message": "Insufficient historical data"}

    avg_bytes = sum(h.get("total_bytes", 0) for h in historical) / len(historical)
    avg_flows = sum(h.get("flows_active", 0) for h in historical) / len(historical)

    recent_bytes = sum(h.get("total_bytes", 0) for h in recent) / len(recent) if recent else 0
    recent_flows = sum(h.get("flows_active", 0) for h in recent) / len(recent) if recent else 0

    anomalies = []

    # Check for significant deviations (>200% or <50% of average)
    if avg_bytes > 0:
        bytes_ratio = recent_bytes / avg_bytes
        if bytes_ratio > 2:
            anomalies.append({
                "type": "high_bandwidth",
                "severity": "warning" if bytes_ratio < 3 else "critical",
                "message": f"Bandwidth {bytes_ratio:.1f}x higher than average",
                "current": recent_bytes,
                "average": avg_bytes
            })
        elif bytes_ratio < 0.5:
            anomalies.append({
                "type": "low_bandwidth",
                "severity": "info",
                "message": f"Bandwidth {bytes_ratio:.1f}x lower than average",
                "current": recent_bytes,
                "average": avg_bytes
            })

    if avg_flows > 0:
        flows_ratio = recent_flows / avg_flows
        if flows_ratio > 2:
            anomalies.append({
                "type": "high_connections",
                "severity": "warning" if flows_ratio < 3 else "critical",
                "message": f"Active flows {flows_ratio:.1f}x higher than average",
                "current": recent_flows,
                "average": avg_flows
            })

    return {"anomalies": anomalies, "baseline_hours": len(historical) / 60}


# ============================================================================
# Background Stats Collection
# ============================================================================

_stats_task: Optional[asyncio.Task] = None


async def collect_stats_periodically():
    """Background task to collect traffic stats."""
    while True:
        try:
            await asyncio.sleep(STATS_INTERVAL)

            # Get current stats
            cfg = get_config("dpi")
            iface = cfg.get("interface", "eth0")
            stats_path = Path(f"/sys/class/net/{iface}/statistics")

            if not stats_path.exists():
                continue

            rx_bytes = int((stats_path / "rx_bytes").read_text().strip())
            tx_bytes = int((stats_path / "tx_bytes").read_text().strip())

            # Get flows and calculate top apps/devices
            flows = _legacy_dpi_query({"type": "get_flows"})

            app_traffic = defaultdict(int)
            device_traffic = defaultdict(int)

            for f in flows.get("flows", []):
                app = f.get("detected_application_name", "unknown")
                mac = f.get("local_mac", "unknown")
                bytes_count = f.get("bytes", 0)
                app_traffic[app] += bytes_count
                device_traffic[mac] += bytes_count

            top_apps = sorted(app_traffic.items(), key=lambda x: -x[1])[:10]
            top_devices = sorted(device_traffic.items(), key=lambda x: -x[1])[:10]

            stats = TrafficStats(
                timestamp=datetime.utcnow().isoformat() + "Z",
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
                total_bytes=rx_bytes + tx_bytes,
                flows_active=len(flows.get("flows", [])),
                top_apps=[{"app": a, "bytes": b} for a, b in top_apps],
                top_devices=[{"mac": m, "bytes": b} for m, b in top_devices]
            )

            add_traffic_stats(stats)

            # Check quotas
            quota_alerts = check_quotas(dict(app_traffic), dict(device_traffic))
            for alert in quota_alerts:
                await send_webhook("quota_exceeded", alert)

            # Save periodically (every 5 minutes)
            if len(_traffic_history) % 5 == 0:
                save_traffic_history()

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error(f"Stats collection error: {e}")


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global _stats_task
    load_traffic_history()
    _stats_task = asyncio.create_task(collect_stats_periodically())
    log.info("DPI module started with traffic monitoring")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global _stats_task
    if _stats_task:
        _stats_task.cancel()
        try:
            await _stats_task
        except asyncio.CancelledError:
            pass
    save_traffic_history()
    log.info("DPI module stopped")


app.include_router(router)
