# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox WAF - Web Application Firewall

Mitmproxy-based threat detection with CrowdSec integration.
300+ rules across 14+ categories (SQLi, XSS, RCE, VoIP, router botnets, etc.)
"""
import asyncio
import os
import json
import re
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config
import geoip2.database
import geoip2.errors

# Paths
RULES_PATH = "/usr/share/secubox/waf/waf-rules.json"
# Threat log — the WAF dashboard's sole data source. The Go engine (sbxwaf,
# #744) writes to the sandboxed leaf dir /var/log/secubox/waf/waf-threats.log;
# the legacy Python mitmproxy WAF used the shared-parent path. Prefer the Go
# engine's path, fall back to the legacy one, and honour SECUBOX_WAF_THREATS_LOG.
THREATS_LOG = os.environ.get("SECUBOX_WAF_THREATS_LOG") or next(
    (p for p in ("/var/log/secubox/waf/waf-threats.log",
                 "/var/log/secubox/waf-threats.log") if Path(p).exists()),
    "/var/log/secubox/waf/waf-threats.log",
)
STATS_CACHE = "/tmp/secubox/waf-stats.json"

# ── historique des menaces (#1062) : tendances multi-jours depuis les logs
# TOURNÉS (gzip compris), agrégat de fond servi par /history. Scan complet et
# coûteux → jamais sur le chemin requête : cache disque, TTL 1 h, recalcul en
# thread (comme /stats). L'import tolère les deux contextes de montage.
import glob as _glob
try:
    from api.historique import agreger_historique as _agreger_historique, bucket_ip
except ImportError:  # standalone (WorkingDirectory=…/waf)
    from historique import agreger_historique as _agreger_historique, bucket_ip

HISTORY_CACHE = "/var/lib/secubox/waf/waf-history.json"
_history_lock = threading.Lock()


def _history_cached(max_age: int = 3600) -> dict:
    """Historique agrégé, servi depuis un cache disque (1 h). Recalcule sous
    verrou si périmé, en balayant waf-threats.log* (courant + tournés)."""
    p = Path(HISTORY_CACHE)

    def _frais():
        try:
            return p.exists() and (time.time() - p.stat().st_mtime) < max_age
        except OSError:
            return False

    if _frais():
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            pass
    with _history_lock:
        if _frais():
            try:
                return json.loads(p.read_text())
            except (OSError, ValueError):
                pass
        data = _agreger_historique(sorted(_glob.glob(THREATS_LOG + "*")))
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data))
        except OSError:
            pass
        return data

# Phase 7+ (#509) — disk-persisted counters + log byte position for
# the double-buffered cache.  Survives aggregator restart, populated
# incrementally by the warm refresh loop.
STATS_DISK_CACHE = "/var/lib/secubox/waf/stats-disk-cache.json"
# Table nft ou sbxwaf tient ses bannissements (#1218) — source de verite
# depuis que CrowdSec est retire du chemin de blocage.
WAF_NFT_TABLE = "secubox"

# Runtime state
_compiled_patterns: Dict[str, List[dict]] = {}
_category_stats: Dict[str, dict] = {}
_request_counts: Dict[str, List[float]] = defaultdict(list)


# ═══════════════════════════════════════════════════════════════════════
# Warm Cache — background refresher per CLAUDE.md § Performance Patterns
#
# The threat log on a busy production board reaches 200 k+ JSONL entries
# (≈50 MB). Computing /stats means a full scan + GeoIP lookups, which
# takes ~6 s of CPU on the Marvell ARM target. The old design ran that
# scan on the request path (lazy read-through cache, 30 s TTL); once the
# log grew past ~50 k entries the scan started taking longer than the
# TTL itself, the cache never warmed, every request blocked the event
# loop, and the dashboard saw HAProxy 504s and rendered empty.
#
# New design: a single background asyncio task refreshes ALL expensive
# state every WAF_WARM_INTERVAL seconds OFF the request path. Endpoints
# return module-level dicts — O(1), no I/O. The first refresh happens at
# startup; until it completes, endpoints either serve a "loading"
# placeholder or compute synchronously (cold-start fallback).
#
# Per operator directive: "les cache double buffer ne doivent pas tomber
# et permettre juste d'aller plus vite... un echec de cron et de cache
# doit forcer le cron et faire du realtime".
# ═══════════════════════════════════════════════════════════════════════

WAF_WARM_INTERVAL = 30  # seconds between background refreshes
WAF_ALERTS_TAIL_BYTES = 512 * 1024  # how much of the log tail to keep hot

_warm_lock = threading.Lock()
_warm: Dict[str, Any] = {
    "stats": None,           # full dashboard stats dict
    "alerts_raw": None,      # list of latest threat entries (up to 500)
    "bans": None,            # CrowdSec decisions, flattened
    "last_refresh": 0.0,
    "refresh_count": 0,
    "refresh_duration_ms": 0,
}


# Back-compat shim so legacy call sites that still reference `stats_cache`
# (notably write-side endpoints that invalidate after a state change) keep
# working without an exception. Reads always return None so callers fall
# through to the warm cache; writes are absorbed silently. Remove once
# all references have been audited.
class _StatsCacheShim:
    def get(self, *_a, **_kw): return None
    def set(self, *_a, **_kw): pass
    def invalidate(self, *_a, **_kw): pass


stats_cache = _StatsCacheShim()


def _cfg():
    cfg = get_config("waf")
    return {
        "enabled": cfg.get("enabled", True) if cfg else True,
        "autoban_enabled": cfg.get("autoban_enabled", True) if cfg else True,
        "ban_duration": cfg.get("ban_duration", "4h") if cfg else "4h",
        "min_severity": cfg.get("min_severity", "high") if cfg else "high",
        "sensitivity": cfg.get("sensitivity", "moderate") if cfg else "moderate",
        "rate_limit": cfg.get("rate_limit", 100) if cfg else 100,
        "rate_window": cfg.get("rate_window", 60) if cfg else 60,
        "whitelist": cfg.get("whitelist", "127.0.0.1,192.168.255.1") if cfg else "127.0.0.1",
    }


def _load_rules():
    """Load and compile WAF rules from JSON."""
    global _compiled_patterns, _category_stats

    rules_file = Path(RULES_PATH)
    if not rules_file.exists():
        # Try local config path
        rules_file = Path("/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-waf/config/waf-rules.json")
        if not rules_file.exists():
            return

    try:
        data = json.loads(rules_file.read_text())
        categories = data.get("categories", {})

        _compiled_patterns.clear()
        _category_stats.clear()

        for cat_id, cat_data in categories.items():
            if not cat_data.get("enabled", True):
                continue

            patterns = []
            for rule in cat_data.get("patterns", []):
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                    patterns.append({
                        "id": rule["id"],
                        "regex": compiled,
                        "desc": rule.get("desc", ""),
                        "cve": rule.get("cve"),
                    })
                except re.error:
                    pass  # Skip invalid patterns

            _compiled_patterns[cat_id] = patterns
            _category_stats[cat_id] = {
                "name": cat_data.get("name", cat_id),
                "severity": cat_data.get("severity", "medium"),
                "owasp": cat_data.get("owasp"),
                "rules_count": len(patterns),
                "enabled": True,
            }
    except Exception:
        pass


# Load rules on startup
_load_rules()


def _check_request(path: str, query: str = "", body: str = "", headers: dict = None) -> Optional[dict]:
    """Check request against WAF rules."""
    if not _cfg()["enabled"]:
        return None

    # Combine all inputs for scanning
    scan_text = f"{path} {query} {body}".lower()

    for cat_id, patterns in _compiled_patterns.items():
        for pattern in patterns:
            if pattern["regex"].search(scan_text):
                return {
                    "matched": True,
                    "category": cat_id,
                    "rule_id": pattern["id"],
                    "description": pattern["desc"],
                    "severity": _category_stats.get(cat_id, {}).get("severity", "medium"),
                    "cve": pattern.get("cve"),
                }

    return None


def _check_rate_limit(ip: str) -> dict:
    """Check if IP exceeds rate limit."""
    cfg = _cfg()
    window = cfg["rate_window"]
    max_requests = cfg["rate_limit"]

    now = datetime.now().timestamp()
    cutoff = now - window

    # Clean old entries
    _request_counts[ip] = [t for t in _request_counts[ip] if t > cutoff]
    _request_counts[ip].append(now)

    count = len(_request_counts[ip])
    return {
        "is_limited": count > max_requests,
        "count": count,
        "limit": max_requests,
        "window": window,
    }


def _log_threat(ip: str, threat: dict, request_path: str):
    """Log threat to file."""
    log_dir = Path(THREATS_LOG).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",  # UTC with Z suffix
        "ip": ip,
        "path": request_path,
        "category": threat.get("category"),
        "rule_id": threat.get("rule_id"),
        "severity": threat.get("severity"),
        "description": threat.get("description"),
    }

    with open(THREATS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _should_autoban(threat: dict) -> bool:
    """Determine if threat should trigger auto-ban."""
    cfg = _cfg()
    if not cfg["autoban_enabled"]:
        return False

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threat_severity = severity_order.get(threat.get("severity", "low"), 1)
    min_severity = severity_order.get(cfg["min_severity"], 3)

    return threat_severity >= min_severity


def _ban_ip(ip: str, duration: str = "4h", reason: str = "WAF auto-ban") -> tuple:
    """Bannit une adresse dans l'ensemble nft du WAF (#1225).

    Cette fonction passait par `cscli decisions add` et AVALAIT l'echec
    (`except: pass`). Depuis le retrait de CrowdSec (#1210) la commande ne
    faisait plus rien : le bouton « Ban » du tableau de bord annoncait un succes
    sans que rien ne soit banni. Elle ecrit desormais dans l'ensemble que la
    chaine waf_drop consulte — le seul endroit qui bloque vraiment — par le
    verbe `wafctl ban`, qui valide l'adresse et refuse le prive.

    Rend (succes, message). L'appelant DOIT propager l'echec : un bouton qui
    ment est pire qu'un bouton absent.
    """
    _ = reason  # le motif vit dans le journal de menaces, pas dans le set nft
    try:
        r = subprocess.run(["sudo", "-n", "/usr/sbin/wafctl", "ban", ip, duration],
                           capture_output=True, text=True, timeout=15)
    except Exception as e:
        return False, f"wafctl injoignable : {e}"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "échec sans message").strip()
    return True, (r.stdout or "").strip()


def _unban_ip(ip: str) -> tuple:
    """Retire une adresse de l'ensemble nft. Rend (succes, message)."""
    try:
        r = subprocess.run(["sudo", "-n", "/usr/sbin/wafctl", "unban", ip],
                           capture_output=True, text=True, timeout=15)
    except Exception as e:
        return False, f"wafctl injoignable : {e}"
    if r.returncode != 0:
        return False, (r.stderr or r.stdout or "échec sans message").strip()
    return True, (r.stdout or "").strip()

def _raison_du_ban(ip: str, cache: dict) -> str:
    """Motif du bannissement, lu dans le journal de menaces.

    Le set nft ne porte que l'adresse et son echeance — c'est un pare-feu, pas
    une archive. Le « pourquoi » vit dans le journal : on y prend la derniere
    ligne `banned` de cette adresse. Sans elle, on le dit plutot que d'inventer.
    """
    return cache.get(ip) or "waf"


def _raisons_recentes(limite: int = 4000) -> dict:
    """Derniere categorie ayant valu un bannissement, par adresse."""
    out: Dict[str, str] = {}
    try:
        lignes = _read_log_tail(Path(THREATS_LOG))
    except Exception:
        return out
    for ligne in lignes[-limite:]:
        try:
            d = json.loads(ligne)
        except (ValueError, TypeError):
            continue
        if d.get("action") != "banned":
            continue
        ip = d.get("client_ip")
        if ip and ip != "local":
            out[ip] = d.get("category") or "waf"
    return out


def _get_bans() -> List[dict]:
    """Bannissements ACTIFS, lus dans l'ensemble nft du WAF (#1221).

    Cette fonction interrogeait CrowdSec. Depuis que le WAF applique lui-meme
    (#1218) et que CrowdSec est retire (#1210), `cscli` ne rend plus rien : le
    tableau de bord affichait « 0 ban actif » pendant que le pare-feu en tenait
    quatre-vingts. La source de verite est desormais l'ensemble nft, celui-la
    meme que la chaine waf_drop consulte — on lit donc ce qui BLOQUE vraiment,
    et non ce qu'un tiers a enregistre.

    L'echeance vient de nft (`expires`), le motif du journal de menaces, le pays
    de la base GeoIP. Rien n'est invente : un champ inconnu reste vide.
    """
    bans: List[dict] = []
    raisons = _raisons_recentes()
    reader = _get_geoip_reader()
    maintenant = int(time.time())

    for ensemble in ("waf_ban", "waf_ban6"):
        try:
            r = subprocess.run(
                ["sudo", "-n", "nft", "-j", "list", "set", "inet", WAF_NFT_TABLE, ensemble],
                capture_output=True, text=True, timeout=10)
            if r.returncode != 0 or not r.stdout:
                continue
            doc = json.loads(r.stdout)
        except Exception:
            continue

        for bloc in doc.get("nftables", []):
            jeu = bloc.get("set")
            if not jeu:
                continue
            for elem in jeu.get("elem", []) or []:
                e = elem.get("elem") if isinstance(elem, dict) else None
                if isinstance(e, dict):
                    ip, expire = e.get("val"), e.get("expires")
                else:
                    ip, expire = elem, None
                if not isinstance(ip, str):
                    continue
                categorie = _raison_du_ban(ip, raisons)
                bans.append({
                    "ip": ip,
                    "value": ip,
                    "scenario": categorie,
                    "reason": categorie,
                    "duration": f"{int(expire)}s" if isinstance(expire, int) else "",
                    "expires_in": int(expire) if isinstance(expire, int) else None,
                    "type": "ban",
                    "origin": "sbxwaf",
                    "id": None,
                    "created_at": "",
                    "country": _lookup_country(ip, reader),
                    "asn": "",
                    "asn_org": "",
                })
    bans.sort(key=lambda b: b.get("expires_in") or 0, reverse=True)
    _ = maintenant
    return bans


def _load_stats_disk_cache() -> dict:
    """Load the persisted counter state + last-read byte position.

    Schema : {byte_position: int, counters: {...}, ip_countries: {...},
              today_iso: 'YYYY-MM-DD', threats_today: int,
              last_updated: int}

    Counters are full-history accumulators ; `threats_today` is reset
    at the day rollover.
    """
    p = Path(STATS_DISK_CACHE)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save_stats_disk_cache(state: dict) -> None:
    try:
        p = Path(STATS_DISK_CACHE)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write : tmp → rename so a half-written file never
        # corrupts the cache on the next load.
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(p)
    except Exception:
        pass


# Classification par ORIGINE et par TYPE (#1221).
#
# Le journal de menaces melange desormais deux producteurs : sbxwaf, qui ne voit
# que le HTTP, et sbx-authwatch, qui couvre ce que le HTTP ne montre pas — SSH,
# SMTP, IMAP et les leurres de service. Sans distinction, le tableau de bord
# affiche un total qui ne dit plus de quelle surface vient la menace.
#
# L'origine se lit dans `tool`, que authwatch renseigne ; le type se deduit du
# prefixe de categorie. On ne devine rien : une categorie inconnue reste
# rangee sous « http », qui est le cas historique.
_TYPES_AUTHWATCH = {
    "auth_ssh:": "ssh",
    "auth_smtp:": "smtp",
    "auth_imap:": "imap",
    "leurre:": "leurre",
}


def _origine_et_type(entry: dict) -> tuple:
    """Rend (origine, type) pour une ligne du journal de menaces."""
    cat = str(entry.get("category") or "")
    for prefixe, typ in _TYPES_AUTHWATCH.items():
        if cat.startswith(prefixe):
            return "authwatch", typ
    if str(entry.get("tool") or "") == "authwatch":
        return "authwatch", "autre"
    return "waf", "http"


def _get_threat_stats() -> dict:
    """Get threat statistics from log with GeoIP country lookup.

    Phase 7+ (#509) — double-buffered cache : the first call after a
    cold start does ONE full-log pass and persists counters + the byte
    position to disk.  Subsequent calls only read the new tail since
    the last position.  Log rotation / truncation is detected via the
    file shrinking ; counters are reset cleanly.
    """
    state = _load_stats_disk_cache()
    today = datetime.now().date().isoformat()

    # Reset accumulators if the day has rolled over.
    if state.get("today_iso") != today:
        state["today_iso"] = today
        state["threats_today"] = 0
        state["observed_today"] = 0   # detect-mode matches seen today (not blocked)

    counters = state.get("counters", {})
    by_category = defaultdict(int, counters.get("by_category", {}))
    by_severity = defaultdict(int, counters.get("by_severity", {}))
    top_ips = defaultdict(int, counters.get("top_ips", {}))
    top_countries = defaultdict(int, counters.get("top_countries", {}))
    top_vhosts = defaultdict(int, counters.get("top_vhosts", {}))
    # Noms demandés que la box NE SERT PAS (#1219). Le moteur répond 421 et
    # journalise `host_anomaly:*` ; ces requêtes sont volontairement exclues des
    # statistiques de visite (elles n'atteignent aucun backend), si bien que
    # rien ne les totalisait nulle part. Or la liste est parlante : entre le
    # balayage, elle révèle les vhosts qui MANQUENT — un nom legacy encore
    # référencé ailleurs, un service jamais publié.
    noms_non_routes = defaultdict(int, counters.get("noms_non_routes", {}))
    # #1221 : d'ou vient la menace, et sur quelle surface.
    par_origine = defaultdict(int, counters.get("par_origine", {}))
    par_type = defaultdict(int, counters.get("par_type", {}))
    # Ce qui etait VISE sur les surfaces hors HTTP (#1221). Un compte inexistant
    # tente depuis des centaines de sources en dit plus long qu'un total : c'est
    # la que se lit le ciblage.
    # EFFICACITE par categorie (#1224) : ce qui a ete BLOQUE contre ce qui n'a
    # ete qu'observe. Une categorie qui detecte beaucoup et ne bloque jamais
    # n'est pas une protection, c'est un compteur — et rien ne le disait.
    efficacite = defaultdict(lambda: defaultdict(int))
    for _cat, _actions in (counters.get("efficacite") or {}).items():
        for _a, _n in (_actions or {}).items():
            efficacite[_cat][_a] = int(_n or 0)
    comptes_vises = defaultdict(int, counters.get("comptes_vises", {}))
    leurres_touches = defaultdict(int, counters.get("leurres_touches", {}))
    total_threats = counters.get("total_threats", 0)
    threats_today = state.get("threats_today", 0)
    # detect-mode matches: seen and logged but NOT blocked — kept apart from the
    # block counters so blocked_24h stays truthful. Persisted like the rest
    # because the reader is incremental (byte_position) and would otherwise
    # only count the newest lines.
    observed_threats = counters.get("observed_threats", 0)
    observed_today = state.get("observed_today", 0)
    ip_countries: Dict[str, str] = dict(state.get("ip_countries", {}))

    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        # Return whatever's cached.
        return _finalize_stats(
            total_threats, threats_today, by_category, by_severity,
            top_ips, top_countries, top_vhosts, ip_countries,
            observed_threats, observed_today, noms_non_routes,
            par_origine, par_type, comptes_vises, leurres_touches, efficacite,
        )

    geoip_reader = _get_geoip_reader()
    try:
        size_now = log_path.stat().st_size
        byte_position = state.get("byte_position", 0)

        # Reprise unique à l'arrivée d'un compteur (#1219). Le lecteur est
        # incrémental : un compteur ajouté après coup ne verrait QUE les lignes
        # à venir et afficherait une liste vide pendant des jours, alors que
        # l'historique est déjà sur le disque. On relit donc le journal en
        # entier, une fois — et on repart de zéro pour TOUS les compteurs, faute
        # de quoi les anciens seraient comptés deux fois.
        if ("noms_non_routes" not in counters or "par_origine" not in counters
                or "comptes_vises" not in counters
                or "efficacite" not in counters):
            by_category.clear(); by_severity.clear(); top_ips.clear()
            top_countries.clear(); top_vhosts.clear(); noms_non_routes.clear()
            par_origine.clear(); par_type.clear()
            comptes_vises.clear(); leurres_touches.clear(); efficacite.clear()
            ip_countries.clear()
            total_threats = 0
            observed_threats = 0
            byte_position = 0

        # Log rotation / truncation : the file shrank since last read.
        # Drop accumulators ; we'll rebuild from the new (smaller) file.
        if size_now < byte_position:
            by_category.clear(); by_severity.clear(); top_ips.clear()
            top_countries.clear(); top_vhosts.clear(); noms_non_routes.clear()
            total_threats = 0
            threats_today = 0
            observed_threats = 0
            observed_today = 0
            byte_position = 0
            ip_countries.clear()

        if size_now > byte_position:
            with open(log_path) as f:
                f.seek(byte_position)
                for line in f:
                    try:
                        entry = json.loads(line.strip())

                        # A "detect" record was MATCHED but let through — the
                        # request was NOT blocked. Counting it as a block would
                        # conflate "blocked" with "would have blocked" and make
                        # blocked_24h a lie the moment an operator arms a detect
                        # category. It gets its own observed-only counter.
                        if entry.get("action") == "detect":
                            observed_threats += 1
                            if entry.get("timestamp", "").startswith(today):
                                observed_today += 1
                            continue

                        total_threats += 1

                        if entry.get("timestamp", "").startswith(today):
                            threats_today += 1

                        by_category[entry.get("category", "unknown")] += 1
                        by_severity[entry.get("severity", "unknown")] += 1

                        ip = entry.get("client_ip") or entry.get("ip", "unknown")
                        top_ips[ip] += 1

                        if ip not in ip_countries:
                            ip_countries[ip] = _lookup_country(ip, geoip_reader)
                        top_countries[ip_countries[ip]] += 1

                        vhost = entry.get("host") or entry.get("vhost", "unknown")
                        top_vhosts[vhost] += 1

                        # Un Host non routé : on garde le NOM demandé, pas la
                        # classe — c'est le nom qui dit s'il manque un vhost.
                        _act = str(entry.get("action") or "inconnu")
                        efficacite[str(entry.get("category") or "inconnu")][_act] += 1

                        _orig, _typ = _origine_et_type(entry)
                        par_origine[_orig] += 1
                        par_type[_typ] += 1
                        if _typ in ("ssh", "smtp", "imap"):
                            # authwatch porte le compte vise dans `path`.
                            _cible = str(entry.get("path") or "").strip()
                            if _cible:
                                comptes_vises[_cible] += 1
                        elif _typ == "leurre":
                            _svc = str(entry.get("host") or "").strip()
                            if _svc:
                                leurres_touches[_svc] += 1

                        if str(entry.get("category", "")).startswith("host_anomaly"):
                            if vhost and vhost != "unknown":
                                noms_non_routes[vhost] += 1
                    except json.JSONDecodeError:
                        pass
                byte_position = f.tell()
    except Exception:
        pass

    # Cap the ip_countries dict so it doesn't grow without bound.
    # Top-1000 most recently seen IPs is plenty for the dashboard.
    if len(ip_countries) > 1200:
        ip_countries = dict(
            sorted(ip_countries.items(), key=lambda kv: -top_ips.get(kv[0], 0))[:1000]
        )

    # Persist before returning so the next call starts from here.
    _save_stats_disk_cache({
        "today_iso": today,
        "threats_today": threats_today,
        "observed_today": observed_today,
        "byte_position": byte_position,
        "counters": {
            "total_threats": total_threats,
            "observed_threats": observed_threats,
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "top_ips": dict(top_ips),
            "top_countries": dict(top_countries),
            "top_vhosts": dict(top_vhosts),
            "noms_non_routes": dict(noms_non_routes),
            "par_origine": dict(par_origine),
            "par_type": dict(par_type),
            "comptes_vises": dict(comptes_vises),
            "leurres_touches": dict(leurres_touches),
            "efficacite": {c: dict(a) for c, a in efficacite.items()},
        },
        "ip_countries": ip_countries,
        "last_updated": int(time.time()),
    })

    return _finalize_stats(
        total_threats, threats_today, by_category, by_severity,
        top_ips, top_countries, top_vhosts, ip_countries,
        observed_threats, observed_today, noms_non_routes,
        par_origine, par_type, comptes_vises, leurres_touches, efficacite,
    )


def _finalize_stats(
    total_threats: int, threats_today: int,
    by_category, by_severity, top_ips, top_countries, top_vhosts,
    ip_countries: dict,
    observed_threats: int = 0, observed_today: int = 0,
    noms_non_routes=None, par_origine=None, par_type=None,
    comptes_vises=None, leurres_touches=None, efficacite=None,
) -> dict:
    """Shape the dashboard-friendly result : top-10 lists + plain dicts."""
    top_ips_sorted = sorted(top_ips.items(), key=lambda x: -x[1])[:10]
    return {
        "total_threats": total_threats,
        "threats_today": threats_today,
        # detect-mode: matched but let through. Separate from the block counts.
        "observed_threats": observed_threats,
        "observed_today": observed_today,
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "top_ips": {ip: count for ip, count in top_ips_sorted},
        "top_ips_countries": {
            ip: ip_countries.get(ip, "??") for ip, _ in top_ips_sorted
        },
        "top_countries": dict(
            sorted(top_countries.items(), key=lambda x: -x[1])[:10]
        ),
        "top_vhosts": dict(
            sorted(top_vhosts.items(), key=lambda x: -x[1])[:10]
        ),
        # Liste de pays : 25 et non 10. Un top-10 est un aperçu ; pour juger
        # d'où vient le trafic il faut voir la traîne.
        "pays": dict(
            sorted(top_countries.items(), key=lambda x: -x[1])[:25]
        ),
        "noms_non_routes": dict(
            sorted((noms_non_routes or {}).items(), key=lambda x: -x[1])[:40]
        ),
        "noms_non_routes_total": sum((noms_non_routes or {}).values()),
        "noms_non_routes_distincts": len(noms_non_routes or {}),
        "par_origine": dict(par_origine or {}),
        "par_type": dict(par_type or {}),
        "comptes_vises": dict(
            sorted((comptes_vises or {}).items(), key=lambda x: -x[1])[:20]
        ),
        "leurres_touches": dict(
            sorted((leurres_touches or {}).items(), key=lambda x: -x[1])[:15]
        ),
        # Trie par volume : les categories les plus sollicitees d'abord, ce
        # sont celles dont l'efficacite compte le plus.
        "efficacite": dict(
            sorted(
                ((c, dict(a)) for c, a in (efficacite or {}).items()),
                key=lambda x: -sum(x[1].values()),
            )[:20]
        ),
    }


# ───────────────────────────────────────────────────────────────────────
# Warm-cache helpers (called only from the background refresher)
# ───────────────────────────────────────────────────────────────────────

def _read_log_tail(path: Path, max_bytes: int = WAF_ALERTS_TAIL_BYTES) -> List[str]:
    """Return up to max_bytes-worth of complete trailing lines without
    loading the full file. Threat-log entries are JSON one-liners of
    ~200-400 bytes each, so 512 KB ≈ 1.5-2.5 k entries — enough for any
    realistic dashboard view."""
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, max_bytes)
            f.seek(-chunk, 2)
            data = f.read().decode("utf-8", errors="ignore")
    except Exception:
        return []
    lines = data.split("\n")
    # If we landed mid-line, the first split fragment is partial.
    if chunk < size:
        lines = lines[1:]
    return [ln for ln in lines if ln.strip()]


def _decorate_dashboard_stats(stats: dict) -> dict:
    """Mirror of the legacy /stats endpoint's post-processing — adds the
    dashboard-friendly fields the React widget expects."""
    cfg = _cfg()
    stats["running"] = cfg["enabled"]
    stats["version"] = "1.2.0"
    stats["rules_loaded"] = sum(len(p) for p in _compiled_patterns.values())
    stats["blocked_today"] = stats.get("threats_today", 0)
    stats["blocked_24h"] = stats.get("total_threats", 0)

    cats = stats.get("by_category", {})
    stats["categories_list"] = [
        {"name": cat, "count": count}
        for cat, count in sorted(cats.items(), key=lambda x: -x[1])[:8]
    ]
    countries = stats.get("top_countries", {})
    stats["top_countries"] = [
        {"country": c, "count": cnt}
        for c, cnt in sorted(countries.items(), key=lambda x: -x[1])[:5]
    ]
    vhosts = stats.get("top_vhosts", {})
    stats["top_vhosts"] = [
        {"vhost": v, "count": cnt}
        for v, cnt in sorted(vhosts.items(), key=lambda x: -x[1])[:5]
    ]

    # Last threat — tail-read up to 2 KB, take the last complete line.
    log_path = Path(THREATS_LOG)
    if log_path.exists():
        try:
            tail = _read_log_tail(log_path, max_bytes=4096)
            if tail:
                last = json.loads(tail[-1])
                ts = last.get("timestamp", "")
                time_ago = "recently"
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        diff = datetime.now(dt.tzinfo) - dt
                        mins = int(diff.total_seconds() / 60)
                        if mins < 1:
                            time_ago = "just now"
                        elif mins < 60:
                            time_ago = f"{mins}m ago"
                        else:
                            time_ago = f"{mins // 60}h ago"
                    except Exception:
                        pass
                stats["last_threat"] = {
                    "ip": last.get("ip") or last.get("client_ip", "unknown"),
                    "type": last.get("category", "attack"),
                    "vhost": last.get("host") or last.get("vhost"),
                    "time_ago": time_ago,
                }
        except Exception:
            pass

    return stats


def _read_alerts_raw() -> List[dict]:
    """Read up to ~500 most recent threat entries from the log tail."""
    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        return []
    parsed: List[dict] = []
    for line in _read_log_tail(log_path):
        try:
            entry = json.loads(line)
            entry["client_ip"] = entry.get("client_ip") or entry.get("ip", "unknown")
            parsed.append(entry)
        except json.JSONDecodeError:
            continue
    # Newest first.
    return list(reversed(parsed))[:500]


_SEV_CRIT = ("probing", "exploit", "cve", "rce", "sqli", "xss", "lfi", "rfi",
             "backdoor", "log4j", "shellshock", "webshell")
_SEV_HIGH = ("bruteforce", "-bf", "bf-", "scan", "crawl", "enum", "scanner", "flood")


def _alert_severity(scenario: str) -> str:
    """CrowdSec alerts carry no severity field — derive one from the scenario so
    the dashboard donut has a meaningful distribution."""
    s = (scenario or "").lower()
    if any(k in s for k in _SEV_CRIT):
        return "critical"
    if any(k in s for k in _SEV_HIGH):
        return "high"
    return "medium"


def _get_crowdsec_alerts() -> List[dict]:
    """Recent CrowdSec alerts — the REAL detection layer. The inline mitmproxy WAF
    log (THREATS_LOG) is normally empty because CrowdSec + the firewall bouncer do
    the detection/blocking, so the threat cards must read alerts here (same source
    the bans already use). Newest first; best-effort (empty on any cscli failure)."""
    try:
        result = subprocess.run(
            ["sudo", "cscli", "alerts", "list", "-o", "json"],
            capture_output=True, text=True, timeout=15)
        if result.returncode != 0 or not result.stdout:
            return []
        raw = json.loads(result.stdout) or []
    except Exception:
        return []
    out: List[dict] = []
    for a in raw:
        decs = a.get("decisions") or []
        scenario = a.get("scenario") or (decs[0].get("scenario") if decs else "") or ""
        src = a.get("source") or {}
        ip = src.get("ip") or src.get("value") or (decs[0].get("value") if decs else "") or ""
        country = src.get("cn") or ""
        if not country:
            for ev in (a.get("events") or [])[:1]:
                for m in ev.get("meta") or []:
                    if m.get("key") == "IsoCode":
                        country = m.get("value", "")
        out.append({
            "id": a.get("id"),
            "timestamp": a.get("created_at") or a.get("start_at") or "",
            "ip": ip, "client_ip": ip,
            "scenario": scenario,
            "category": scenario.split("/")[-1] if scenario else "attack",
            "severity": _alert_severity(scenario),
            "country": country,
            "vhost": "",
            "count": a.get("events_count", 1),
        })
    return out


def _protected_vhost_count() -> int:
    """Number of vhosts protected by the WAF = the HAProxy→mitmproxy route map."""
    for p in ("/srv/mitmproxy/haproxy-routes.json", "/srv/mitmproxy-in/haproxy-routes.json"):
        try:
            d = json.loads(Path(p).read_text())
            if isinstance(d, dict) and d:
                return len(d)
        except Exception:
            pass
    return 0


def _overlay_crowdsec_stats(stats: dict, alerts: List[dict]) -> None:
    """Fold CrowdSec alert counts into the (usually-empty) inline-log stats so the
    Threats/Blocked cards + severity/category donuts reflect real activity."""
    now = datetime.now(timezone.utc)
    today = 0
    by_sev = defaultdict(int, stats.get("by_severity") or {})
    by_cat = defaultdict(int, stats.get("by_category") or {})
    # top_countries may already have been decorated into a list of
    # {"country","count"} dicts (the overlay can run after _decorate_dashboard_stats);
    # accept either shape so we never crash the warm refresh and lose the WAF stats.
    _tc = stats.get("top_countries") or {}
    if isinstance(_tc, list):
        _tc = {d.get("country", "??"): int(d.get("count", 0) or 0) for d in _tc}
    by_country = defaultdict(int, _tc)
    for a in alerts:
        by_sev[a["severity"]] += 1
        by_cat[a["category"]] += 1
        if a.get("country"):
            by_country[a["country"]] += 1
        ts = a.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if (now - dt) <= timedelta(hours=24):
                today += 1
        except Exception:
            today += 1  # unparseable ts → treat as recent
    stats["total_threats"] = stats.get("total_threats", 0) + len(alerts)
    stats["threats_today"] = stats.get("threats_today", 0) + today
    stats["blocked_24h"] = stats["total_threats"]
    stats["blocked_today"] = stats["threats_today"]
    stats["by_severity"] = dict(by_sev)
    stats["by_category"] = dict(by_cat)
    stats["top_countries"] = [{"country": c, "count": n}
                              for c, n in sorted(by_country.items(), key=lambda x: -int(x[1] or 0))[:5]]
    if alerts:
        a0 = alerts[0]
        ago = "recently"
        try:
            dt = datetime.fromisoformat(a0["timestamp"].replace("Z", "+00:00"))
            mins = int((now - dt).total_seconds() / 60)
            ago = "just now" if mins < 1 else (f"{mins}m ago" if mins < 60 else f"{mins // 60}h ago")
        except Exception:
            pass
        stats["last_threat"] = {"ip": a0["ip"], "type": a0["category"],
                                "vhost": a0.get("vhost"), "time_ago": ago}


def _refresh_warm_caches() -> dict:
    """Compute every expensive piece of state ONCE. Called from the
    background loop via asyncio.to_thread so the event loop stays free."""
    t0 = time.time()
    new_stats = _decorate_dashboard_stats(_get_threat_stats())
    new_alerts = _read_alerts_raw()
    try:
        new_bans = _get_bans()
    except Exception:
        new_bans = []
    # CrowdSec is the authoritative detection layer; overlay its alerts so the
    # threat cards/donuts aren't stuck at 0 when the inline mitmproxy log is empty.
    try:
        cs_alerts = _get_crowdsec_alerts()
    except Exception:
        cs_alerts = []
    # The Go sbxwaf engine (#744) now writes a RICH threat log, so the WAF stats
    # are real and fresh. Only fall back to the CrowdSec overlay when the engine
    # produced NOTHING (engine down / log unreadable) — otherwise the overlay's
    # older, coarser CrowdSec scenarios would clobber the engine's fresh
    # categories AND push a stale "1h ago" entry to the live attack banner.
    engine_has_data = (new_stats.get("total_threats", 0) or 0) > 0 or bool(new_alerts)
    if cs_alerts and not engine_has_data:
        # Defensive: a CrowdSec-overlay failure must NEVER abort the refresh and
        # leave the warm cache frozen — the WAF top_ips/top_vhosts/tracked-attacker
        # data (the dashboard's per-IP/vhost panels) lives in new_stats and must
        # survive even if the optional CrowdSec donut overlay throws.
        try:
            _overlay_crowdsec_stats(new_stats, cs_alerts)
        except Exception:
            pass
        if not new_alerts:
            new_alerts = cs_alerts  # feed the live feed / threat list too
    new_stats["vhosts_count"] = _protected_vhost_count()
    duration_ms = int((time.time() - t0) * 1000)

    with _warm_lock:
        _warm["stats"] = new_stats
        _warm["alerts_raw"] = new_alerts
        _warm["bans"] = new_bans
        _warm["last_refresh"] = time.time()
        _warm["refresh_count"] += 1
        _warm["refresh_duration_ms"] = duration_ms
    return {
        "duration_ms": duration_ms,
        "alerts": len(new_alerts),
        "bans": len(new_bans),
    }


async def _warm_loop():
    """Background refresher. Survives individual failures so a single
    bad log line / cscli outage can't kill the loop."""
    # Stagger the very first refresh by 1 s so uvicorn finishes binding
    # before we burn CPU on the initial full scan.
    await asyncio.sleep(1)
    while True:
        try:
            await asyncio.to_thread(_refresh_warm_caches)
        except Exception:
            # Swallow — next tick will retry. Logging would spam.
            pass
        await asyncio.sleep(WAF_WARM_INTERVAL)


@asynccontextmanager
async def _lifespan(_app):
    task = asyncio.create_task(_warm_loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


app = FastAPI(title="SecuBox WAF", lifespan=_lifespan)


# === Public Endpoints ===

@app.get("/history")
async def waf_history():
    """Tendances des menaces par jour + top attaquants persistants, sur toute la
    fenêtre de rétention des logs (courant + tournés). Cache disque 1 h."""
    return await asyncio.to_thread(_history_cached)


CAMPAIGNS_FILE = "/var/cache/secubox/waf/campaigns.json"


@app.get("/campaigns")
async def waf_campaigns():
    """Campagnes d'attaque corrélées (#1070 phase D) : attaquants regroupés par
    MÊME workflow (même jeu de sondes, même outil), à travers le temps et les IP.
    Produit par le timer secubox-waf-campaigns (corrélateur Go de sbxwaf) ; on lit
    ici son instantané JSON. Absent → vue vide (corrélateur pas encore passé)."""
    try:
        data = json.loads(Path(CAMPAIGNS_FILE).read_text())
    except (OSError, ValueError):
        return {"available": False, "attaquants": 0, "campagnes": []}
    camps = data.get("campagnes", [])[:20]
    for c in camps:
        c["exemple_sequence"] = c.get("exemple_sequence", [])[:12]
        c["nb_attaquants"] = len(c.get("attaquants", []))
    return {"available": True, "attaquants": data.get("attaquants", 0), "campagnes": camps}


@app.get("/status")
async def status():
    """WAF status (public)."""
    cfg = _cfg()
    total_rules = sum(len(p) for p in _compiled_patterns.values())
    active_categories = len(_compiled_patterns)

    return {
        "module": "waf",
        "enabled": cfg["enabled"],
        "autoban_enabled": cfg["autoban_enabled"],
        "total_rules": total_rules,
        "active_categories": active_categories,
        "sensitivity": cfg["sensitivity"],
    }


# === Protected Endpoints ===

@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Detailed WAF info."""
    cfg = _cfg()
    return {
        "config": cfg,
        "rules_path": RULES_PATH,
        "threats_log": THREATS_LOG,
    }


@app.get("/detections")
async def get_detections():
    """Detections COMPORTEMENTALES, celles qui ne tiennent pas dans un fichier
    de motifs (#1222).

    Le panneau listait les 18 categories de waf-rules.json et rien d'autre. Or
    plusieurs protections ne reposent sur aucun motif : elles jugent un
    comportement — un hote qu'on ne sert pas, un robot qui s'annonce, une
    authentification qui echoue, une connexion a un service inexistant. Elles
    protegeaient sans figurer nulle part.

    L'etat rendu est MESURE, jamais suppose : on lit le fichier de profils, on
    interroge systemd, on compte les ports reellement en ecoute. Une detection
    dont on ne peut pas etablir l'etat est rendue « inconnue » plutot
    qu'affichee active.
    """
    detections = []

    # ── Hotes non routes ──────────────────────────────────────────────────
    detections.append({
        "id": "host_anomaly",
        "nom": "Hôtes non routés",
        "emoji": "🚪",
        "resume": "Un navigateur n'envoie jamais un nom qu'on ne publie pas",
        "classes": ["hôte vide", "IP littérale", "nom généré (DGA)", "nom non servi"],
        "actif": _unite_active("secubox-waf-ng"),
        "detail": "4 classes, du signal certain au gradué",
    })

    # ── Anti-robots par vhost ─────────────────────────────────────────────
    coches = []
    try:
        profils = json.loads(Path("/etc/secubox/waf/vhost_profiles.json").read_text())
        coches = [str(v) for v in (profils.get("anti_robots") or [])]
    except (OSError, ValueError, AttributeError):
        coches = []
    detections.append({
        "id": "robots",
        "nom": "Anti-robots",
        "emoji": "🤖",
        "resume": "48 robots nommés ; robots.txt reste servi",
        "classes": coches,
        "actif": bool(coches),
        "detail": (f"{len(coches)} vhost(s) coché(s)" if coches
                   else "aucun vhost coché — la case est dans le panneau Vhost"),
    })

    # ── authwatch : journaux hors HTTP ────────────────────────────────────
    aw = _unite_active("secubox-authwatch")
    detections.append({
        "id": "authwatch_journaux",
        "nom": "Authentification SSH / SMTP / IMAP",
        "emoji": "🔑",
        "resume": "Ce que le HTTP ne montre pas : sbxwaf est derrière HAProxy",
        "classes": ["SSH", "SMTP (postfix)", "IMAP/POP3 (dovecot)"],
        "actif": aw,
        "detail": ("compte inexistant → banni au premier essai ; compte réel → patient"
                   if aw else "service sbx-authwatch arrêté"),
    })

    # ── Leurres de service ────────────────────────────────────────────────
    ports = _ports_leurres()
    detections.append({
        "id": "leurres",
        "nom": "Leurres de service",
        "emoji": "🕳️",
        "resume": "Personne ne se connecte à un service qu'on n'offre pas",
        "classes": ports,
        "actif": bool(ports),
        "detail": (f"{len(ports)} port(s) en écoute, bannissement au premier contact"
                   if ports else "aucun leurre en écoute"),
    })

    return {"detections": detections, "count": len(detections)}


def _unite_active(unite: str) -> bool:
    """Etat REEL d'une unite systemd. Une erreur rend False : on n'affiche pas
    « actif » sur une supposition."""
    try:
        r = subprocess.run(["systemctl", "is-active", unite],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


# Ports leurres declares par defaut dans sbx-authwatch. Sert de reference quand
# l'unite ne les enumere pas explicitement (« --leurres defaut »).
_LEURRES_DEFAUT = ["23", "445", "1433", "3306", "3389", "5432", "5900", "6379", "9200", "27017"]


def _ports_leurres() -> List[str]:
    """Ports leurres REELLEMENT en ecoute.

    On n'identifie PAS le processus : l'API tourne sous `secubox` et `ss -lntp`
    ne lui montre pas les noms de processus des autres comptes — le premier
    essai affichait donc « aucun leurre » pendant que neuf ports ecoutaient. On
    croise donc deux choses accessibles sans privilege : les ports que l'unite
    declare, et les ports effectivement en ecoute (`ss -lnt`, sans -p).
    """
    if not _unite_active("secubox-authwatch"):
        return []

    candidats = list(_LEURRES_DEFAUT)
    try:
        r = subprocess.run(["systemctl", "show", "secubox-authwatch", "-p", "ExecStart"],
                           capture_output=True, text=True, timeout=5)
        ligne = r.stdout or ""
        if "--leurres" in ligne:
            apres = ligne.split("--leurres", 1)[1].strip()
            spec = apres.split()[0] if apres.split() else ""
            if spec and spec != "defaut":
                explicites = []
                for part in spec.split(","):
                    port = part.split(":")[0].strip()
                    if port.isdigit():
                        explicites.append(port)
                if explicites:
                    candidats = explicites
    except Exception:
        pass

    try:
        r = subprocess.run(["ss", "-lnt"], capture_output=True, text=True, timeout=5)
        ecoute = r.stdout if r.returncode == 0 else ""
    except Exception:
        return []

    ouverts = set()
    for ligne in ecoute.splitlines()[1:]:
        champs = ligne.split()
        if len(champs) < 4:
            continue
        adresse = champs[3]
        if ":" in adresse:
            ouverts.add(adresse.rsplit(":", 1)[-1])

    # Un port declare ET en ecoute n'est pas forcement un LEURRE : sur gk2, le
    # 445 est tenu par samba et authwatch a echoue a s'y lier. Le compte de
    # service appartient au groupe systemd-journal : on lit donc les echecs de
    # liaison du service et on les retire, plutot que d'annoncer une protection
    # qui n'existe pas.
    echoues = set()
    try:
        r = subprocess.run(
            ["journalctl", "-u", "secubox-authwatch", "--since", "-1h",
             "--no-pager", "-o", "cat"],
            capture_output=True, text=True, timeout=8)
        for ligne in (r.stdout or "").splitlines():
            if "address already in use" not in ligne:
                continue
            marque = "port "
            if marque in ligne:
                port = ligne.split(marque, 1)[1].split(")", 1)[0].strip()
                if port.isdigit():
                    echoues.add(port)
    except Exception:
        pass

    return [p for p in candidats if p in ouverts and p not in echoues]


@app.get("/categories")
async def get_categories():
    """List all WAF categories with stats (public)."""
    return {
        "categories": _category_stats,
        "total_rules": sum(c["rules_count"] for c in _category_stats.values()),
    }


@app.get("/rules", dependencies=[Depends(require_jwt)])
async def get_rules():
    """Get all WAF rules by category."""
    rules = {}
    for cat_id, patterns in _compiled_patterns.items():
        rules[cat_id] = [
            {"id": p["id"], "pattern": p["regex"].pattern, "desc": p["desc"], "cve": p.get("cve")}
            for p in patterns
        ]
    return {"rules": rules}


@app.get("/rules/{category}", dependencies=[Depends(require_jwt)])
async def get_category_rules(category: str):
    """Get rules for a specific category."""
    if category not in _compiled_patterns:
        raise HTTPException(404, f"Category not found: {category}")

    patterns = _compiled_patterns[category]
    return {
        "category": category,
        "info": _category_stats.get(category, {}),
        "rules": [
            {"id": p["id"], "pattern": p["regex"].pattern, "desc": p["desc"], "cve": p.get("cve")}
            for p in patterns
        ]
    }


class ToggleCategoryRequest(BaseModel):
    enabled: bool


@app.post("/category/{category}/toggle", dependencies=[Depends(require_jwt)])
async def toggle_category(category: str, req: ToggleCategoryRequest):
    """Enable or disable a WAF category."""
    if category not in _category_stats:
        raise HTTPException(404, f"Category not found: {category}")

    # Update in-memory state
    if req.enabled:
        _load_rules()  # Reload to re-enable
    else:
        _compiled_patterns.pop(category, None)
        if category in _category_stats:
            _category_stats[category]["enabled"] = False

    return {"success": True, "category": category, "enabled": req.enabled}


def _empty_stats_skeleton() -> dict:
    """Minimal shape returned when the warm cache hasn't refreshed yet
    (first second after boot, or refresh task crashed). Keeps the
    dashboard from rendering `undefined`-laden cards."""
    return {
        "total_threats": 0, "threats_today": 0,
        "by_category": {}, "by_severity": {},
        "top_ips": {}, "top_ips_countries": {},
        "top_countries": [], "top_vhosts": [], "categories_list": [],
        "running": _cfg()["enabled"],
        "version": "1.2.0",
        "rules_loaded": sum(len(p) for p in _compiled_patterns.values()),
        "blocked_today": 0, "blocked_24h": 0,
        "loading": True,
    }


VISITS_STATS = os.environ.get(
    "SECUBOX_WAF_VISITS_STATS", "/var/log/secubox/waf/visits-stats.json")


@app.get("/visits")
async def get_visits():
    """Non-attacker visit statistics (#747) — the WAF sees ALL inbound traffic,
    so this is real 'who actually visited' data: total requests, client-type /
    OS / per-vhost / status breakdowns, plus the busiest client IPs geo-mapped to
    countries here (the engine ships only the IPs; the API holds the GeoIP DB).
    Public, served straight from the engine's periodic JSON snapshot."""
    try:
        snap = json.loads(Path(VISITS_STATS).read_text())
    except (OSError, ValueError):
        return {"available": False, "total": 0, "by_client_type": {}, "by_os": {},
                "by_status": {}, "by_vhost": {}, "top_countries": {}, "top_ips": {}}
    reader = _get_geoip_reader()
    top_ips = snap.get("top_ips") or {}
    by_country: Dict[str, int] = defaultdict(int)
    for ip, n in top_ips.items():
        pays = _lookup_country(ip, reader)
        # Le LAN n'est pas une origine geographique (#1221). Il pesait 37 182
        # sur 37 700 : la carte affichait une seule barre et les vrais pays
        # etaient invisibles. On l'ecarte de la repartition — le total general
        # le compte toujours, c'est la LECTURE PAR PAYS qu'il rendait inutile.
        if pays in ("LAN", "??", "", None):
            continue
        by_country[pays] += int(n or 0)
    return {
        "available": True,
        "total": int(snap.get("total", 0)),
        "by_client_type": snap.get("by_client_type") or {},
        "by_os": snap.get("by_os") or {},
        "by_status": snap.get("by_status") or {},
        "by_vhost": dict(sorted((snap.get("by_vhost") or {}).items(),
                                key=lambda kv: -int(kv[1] or 0))[:10]),
        "top_countries": dict(sorted(by_country.items(),
                                     key=lambda kv: -kv[1])[:10]),
        "top_ips": dict(sorted(top_ips.items(),
                               key=lambda kv: -int(kv[1] or 0))[:10]),
        "updated_unix": int(snap.get("updated_unix", 0)),
    }


@app.get("/stats")
async def get_stats():
    """Threat statistics for the dashboard (public).

    Always served from the warm cache populated by `_warm_loop()` every
    WAF_WARM_INTERVAL seconds. If the very first refresh hasn't completed
    yet, fall back to a synchronous compute so the dashboard isn't blank
    on cold-start."""
    with _warm_lock:
        cached = _warm["stats"]
        last_refresh = _warm["last_refresh"]
    if cached is not None:
        out = dict(cached)
        out["cache_last_run"] = last_refresh
        out["source"] = "warm-cache"
        return out

    # Cold start: warm task hasn't completed yet. Compute once on this
    # request thread so the dashboard sees real data immediately, then
    # the background loop takes over.
    stats = await asyncio.to_thread(
        lambda: _decorate_dashboard_stats(_get_threat_stats())
    )
    stats["source"] = "cold-start"
    return stats


def _slice_alerts(alerts: List[dict], limit: int, aggregate: bool) -> dict:
    """Slice and optionally aggregate the warm alerts list."""
    if not aggregate:
        return {"alerts": alerts[:limit], "aggregated": False}

    # Le lecteur GeoIP est ouvert UNE fois pour tout le lot : chaque appel a
    # _get_geoip_reader ouvrirait sinon la base par adresse agregee.
    _geo = _get_geoip_reader()
    with _warm_lock:
        _bans_chauds = _warm.get("bans")
    _deja_bannies = {b.get("ip") for b in (_bans_chauds or []) if b.get("ip")}
    ip_groups: Dict[str, dict] = defaultdict(
        lambda: {"alerts": [], "count": 0, "categories": set(), "severities": set()}
    )
    for alert in alerts:
        ip = alert.get("client_ip", "unknown")
        ip_groups[ip]["alerts"].append(alert)
        ip_groups[ip]["count"] += 1
        _cat = alert.get("category") or ""
        if _cat:
            ip_groups[ip]["categories"].add(_cat)
        ip_groups[ip]["severities"].add(alert.get("severity", ""))
        if "first_seen" not in ip_groups[ip]:
            ip_groups[ip]["first_seen"] = alert.get("timestamp")
        ip_groups[ip]["last_seen"] = alert.get("timestamp")

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    aggregated = []
    for ip, data in sorted(ip_groups.items(), key=lambda x: x[1]["count"], reverse=True)[:limit]:
        max_sev = max(data["severities"], key=lambda s: sev_order.get(s, 0), default="low")
        # Le pays manquait a la forme agregee : la colonne du panneau affichait
        # un globe generique sur chaque ligne. On le resout ici, une fois par
        # adresse — la base GeoIP est deja ouverte pour le reste.
        aggregated.append({
            # Deja banni ? Le tableau proposait « Ban » sur des adresses que le
            # pare-feu ecartait deja : un bouton sans effet, et une lecture
            # fausse de l'etat.
            "currently_banned": ip in _deja_bannies,
            "country": _lookup_country(ip, _geo) if ip and ip != "local" else "",
            "client_ip": ip,
            "count": data["count"],
            "categories": list(data["categories"]),
            "max_severity": max_sev,
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "latest_alert": data["alerts"][0] if data["alerts"] else None,
        })
    return {"alerts": aggregated, "aggregated": True}


@app.get("/alerts")
async def get_alerts(limit: int = 50, aggregate: bool = False):
    """Recent threat alerts, sliced/aggregated from the warm cache."""
    with _warm_lock:
        raw = _warm["alerts_raw"]
    if raw is None:
        # Cold start — tail-read once.
        raw = await asyncio.to_thread(_read_alerts_raw)
    return _slice_alerts(raw or [], limit, aggregate)


@app.get("/bans")
async def get_bans():
    """Active IP bans from CrowdSec. Read from warm cache; the
    underlying `cscli` call is too slow (5-15 s) to run on the request
    path. Cold start falls through to a synchronous fetch."""
    with _warm_lock:
        bans = _warm["bans"]
    if bans is None:
        bans = await asyncio.to_thread(_get_bans)
    return {"bans": bans, "total": len(bans)}


def _aggregate_threats(hours: int, limit: int) -> List[dict]:
    """Walk waf-threats.log and aggregate per-IP within the last N hours.

    Returns the top `limit` source IPs ordered by hit count. Each entry
    carries first-seen / last-seen / top categories / max severity so the
    UI can show 'silence but track' status even after the CrowdSec ban
    expired (active ban set in `currently_banned`)."""
    log_path = Path(THREATS_LOG)
    if not log_path.exists():
        return []

    cutoff = datetime.utcnow() - timedelta(hours=hours)
    cutoff_iso = cutoff.isoformat() + "Z"

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    by_ip: dict = {}

    # Reading the whole log keeps the request simple ; threats.log is rotated
    # by logrotate so this stays bounded. For very large logs we tail by size.
    raw_lines = _read_log_tail(log_path, max_bytes=8 * 1024 * 1024)
    for raw in raw_lines:
        try:
            e = json.loads(raw)
        except Exception:
            continue
        ts = e.get("timestamp", "")
        if ts < cutoff_iso:
            continue
        # mitm WAF writes the source IP as "client_ip" ; the in-process WAF
        # writes it as "ip". Accept both so this works no matter which path
        # produced the entry.
        ip = e.get("client_ip") or e.get("ip")
        if not ip:
            continue
        # Trafic interne (loopback/privé) fondu sous « local » : ce n'est pas
        # un attaquant, il ne doit pas trôner dans le top (cf. sbxwaf #1163).
        ip = bucket_ip(ip)
        rec = by_ip.setdefault(ip, {
            "ip": ip,
            "count": 0,
            "first_seen": ts,
            "last_seen": ts,
            "categories": {},
            "severity_max": "low",
            "sample_path": e.get("path", ""),
        })
        rec["count"] += 1
        if ts < rec["first_seen"]:
            rec["first_seen"] = ts
        if ts > rec["last_seen"]:
            rec["last_seen"] = ts
            rec["sample_path"] = e.get("path", "")
        cat = e.get("category") or "unknown"
        rec["categories"][cat] = rec["categories"].get(cat, 0) + 1
        sev = e.get("severity") or "low"
        if sev_rank.get(sev, 0) > sev_rank.get(rec["severity_max"], 0):
            rec["severity_max"] = sev

    # Cross-reference active CrowdSec bans so the UI can mark "currently
    # silenced (drop) vs only tracked".
    active = set()
    with _warm_lock:
        bans = _warm.get("bans")
    if bans:
        active = {b.get("ip") for b in bans if b.get("ip")}

    out = []
    for rec in by_ip.values():
        cats = sorted(rec["categories"].items(), key=lambda kv: kv[1], reverse=True)
        rec["top_categories"] = [{"category": c, "count": n} for c, n in cats[:3]]
        rec["currently_banned"] = rec["ip"] in active
        del rec["categories"]
        out.append(rec)
    out.sort(key=lambda r: r["count"], reverse=True)
    return out[:limit]


@app.get("/bans/history")
async def get_bans_history(hours: int = 24, limit: int = 100):
    """Tracked attackers — IPs we have threat-logged in the window.

    Surfaces every source IP that hit a WAF rule even AFTER its CrowdSec
    decision expires. Lets the operator audit "who was silenced and is
    still being silenced" vs "who was silenced and may slip back in".
    `currently_banned=True` means there is an active nft drop right now.
    """
    if hours < 1 or hours > 24 * 31:
        hours = 24
    if limit < 1 or limit > 1000:
        limit = 100
    rows = await asyncio.to_thread(_aggregate_threats, hours, limit)
    return {
        "window_hours": hours,
        "total_ips": len(rows),
        "tracked": rows,
    }


class BanRequest(BaseModel):
    ip: str
    duration: str = "4h"
    reason: str = "Manual WAF ban"


@app.post("/ban", dependencies=[Depends(require_jwt)])
async def ban_ip(req: BanRequest):
    """Bannit manuellement une adresse. L'echec est PROPAGE : un bouton qui
    annonce un succes sans rien faire est pire qu'un bouton absent."""
    ok, message = _ban_ip(req.ip, req.duration, req.reason)
    if not ok:
        raise HTTPException(500, f"bannissement refusé : {message}")
    stats_cache.invalidate()
    with _warm_lock:
        _warm["bans"] = None  # forcer la relecture de l'ensemble nft
    return {"success": True, "ip": req.ip, "duration": req.duration, "message": message}


@app.post("/unban/{ip}", dependencies=[Depends(require_jwt)])
async def unban_ip(ip: str):
    """Retire un bannissement. L'echec est propage."""
    ok, message = _unban_ip(ip)
    if not ok:
        raise HTTPException(500, f"levée du ban refusée : {message}")
    stats_cache.invalidate()
    with _warm_lock:
        _warm["bans"] = None
    return {"success": True, "ip": ip, "message": message}


class CheckRequest(BaseModel):
    path: str
    query: str = ""
    body: str = ""
    headers: dict = None
    ip: str = None


@app.post("/check", dependencies=[Depends(require_jwt)])
async def check_threat(req: CheckRequest):
    """Check a request for threats (for HAProxy integration)."""
    # Rate limit check
    if req.ip:
        rate_result = _check_rate_limit(req.ip)
        if rate_result["is_limited"]:
            return {
                "blocked": True,
                "reason": "rate_limit",
                "details": rate_result,
            }

    # WAF pattern check
    threat = _check_request(req.path, req.query, req.body, req.headers)

    if threat:
        if req.ip:
            _log_threat(req.ip, threat, req.path)

            cfg = _cfg()
            whitelist = cfg["whitelist"].split(",")
            if req.ip not in whitelist and _should_autoban(threat):
                _ban_ip(req.ip, cfg["ban_duration"], f"WAF: {threat['rule_id']}")
                threat["auto_banned"] = True

        return {"blocked": True, "reason": "waf_match", "threat": threat}

    return {"blocked": False}


@app.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_rules():
    """Reload WAF rules from file."""
    _load_rules()
    stats_cache.invalidate()  # rules changed → cached stats stale
    total_rules = sum(len(p) for p in _compiled_patterns.values())
    return {
        "success": True,
        "categories": len(_compiled_patterns),
        "rules": total_rules,
    }


class AutobanConfig(BaseModel):
    enabled: bool = None
    ban_duration: str = None
    min_severity: str = None
    sensitivity: str = None


@app.post("/autoban/config", dependencies=[Depends(require_jwt)])
async def update_autoban_config(req: AutobanConfig):
    """Update auto-ban configuration."""
    # In production, this would update the TOML config file
    return {"success": True, "config": req.dict(exclude_none=True)}


# ── Health & Auto-Repair ──────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Layer 1: Basic health check."""
    rules_loaded = len(_compiled_patterns) > 0
    log_writable = os.access(Path(THREATS_LOG).parent, os.W_OK) if Path(THREATS_LOG).parent.exists() else False

    status = "ok" if rules_loaded and log_writable else "degraded"
    rules_count = sum(len(p) for p in _compiled_patterns.values())
    return {
        "status": status,
        "healthy": status == "ok",
        "module": "waf",
        "version": "1.2.0",
        "dev_stage": "production",
        "enabled": "enabled",
        "message": f"WAF active ({rules_count} rules)" if status == "ok" else "WAF degraded",
        "checks": {
            "rules_loaded": rules_loaded,
            "rules_count": rules_count,
            "log_writable": log_writable,
            "categories": len(_compiled_patterns)
        }
    }


@app.get("/doctor")
async def doctor_check():
    """Layer 2: Doctor health - can we self-repair?"""
    issues = []
    can_repair = True

    # Check rules file
    rules_path = Path(RULES_PATH)
    if not rules_path.exists():
        issues.append({"type": "rules_missing", "repairable": True})
    elif len(_compiled_patterns) == 0:
        issues.append({"type": "rules_not_loaded", "repairable": True})

    # Check log directory
    log_dir = Path(THREATS_LOG).parent
    if not log_dir.exists():
        issues.append({"type": "log_dir_missing", "repairable": True})
    elif not os.access(log_dir, os.W_OK):
        issues.append({"type": "log_not_writable", "repairable": True})

    # Check mitmproxy routes (for WAF integration)
    routes_file = Path("/data/mitmproxy-waf/data/routes.json")
    if not routes_file.exists():
        routes_file = Path("/data/mitmproxy/routes.json")
    if not routes_file.exists():
        issues.append({"type": "routes_missing", "repairable": False})
        can_repair = False

    return {
        "healthy": len(issues) == 0,
        "issues": issues,
        "can_repair": can_repair,
        "repair_endpoint": "/repair"
    }


@app.post("/repair", dependencies=[Depends(require_jwt)])
async def repair_waf():
    """Auto-repair WAF: reload rules, fix logs, sync routes."""
    repairs = []

    # 1. Ensure log directory
    log_dir = Path(THREATS_LOG).parent
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True)
        repairs.append({"action": "create_log_dir", "status": "ok"})

    # Fix log permissions
    if log_dir.exists():
        try:
            os.chmod(log_dir, 0o755)
            log_file = Path(THREATS_LOG)
            if log_file.exists():
                os.chmod(log_file, 0o666)
            repairs.append({"action": "fix_log_perms", "status": "ok"})
        except Exception as e:
            repairs.append({"action": "fix_log_perms", "status": "error", "message": str(e)})

    # 2. Reload rules
    try:
        _load_rules()
        total = sum(len(p) for p in _compiled_patterns.values())
        repairs.append({"action": "reload_rules", "status": "ok", "rules": total})
    except Exception as e:
        repairs.append({"action": "reload_rules", "status": "error", "message": str(e)})

    # 3. Clear expired bans (via mitmproxy if available)
    # This would be done via the mitmproxy addon

    # 4. Verify mitmproxy connection
    routes_file = Path("/data/mitmproxy-waf/data/routes.json")
    if not routes_file.exists():
        routes_file = Path("/data/mitmproxy/routes.json")
    if routes_file.exists():
        try:
            routes = json.loads(routes_file.read_text())
            repairs.append({"action": "check_routes", "status": "ok", "routes": len(routes)})
        except Exception as e:
            repairs.append({"action": "check_routes", "status": "error", "message": str(e)})
    else:
        repairs.append({"action": "check_routes", "status": "warning", "message": "routes.json not found"})

    return {
        "success": all(r["status"] in ("ok", "warning") for r in repairs),
        "repairs": repairs
    }


@app.get("/whitelist", dependencies=[Depends(require_jwt)])
async def get_whitelist():
    """Get whitelisted IPs."""
    cfg = _cfg()
    return {"whitelist": cfg["whitelist"].split(",")}


class WhitelistRequest(BaseModel):
    ip: str
    action: str  # "add" or "remove"


@app.post("/whitelist", dependencies=[Depends(require_jwt)])
async def update_whitelist(req: WhitelistRequest):
    """Add or remove IP from whitelist."""
    # In production, this would update the TOML config file
    return {"success": True, "ip": req.ip, "action": req.action}

# GeoIP lookup with caching
import urllib.request
import ssl

_geoip_cache = {}

# GeoIP database reader (local MaxMind database)
_geoip_reader = None
_geoip_cache = {}
GEOIP_DB_PATH = "/var/lib/secubox/geoip/GeoLite2-Country.mmdb"

def _get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None:
        try:
            _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception:
            pass
    return _geoip_reader


def _lookup_country(ip: str, reader=None) -> str:
    """Lookup country code for IP address."""
    if ip in _geoip_cache:
        return _geoip_cache[ip]

    # Skip private/local IPs
    if ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "unknown")):
        _geoip_cache[ip] = "LAN"
        return "LAN"

    if reader is None:
        reader = _get_geoip_reader()

    if reader:
        try:
            response = reader.country(ip)
            country = response.country.iso_code or "??"
            _geoip_cache[ip] = country
            return country
        except geoip2.errors.AddressNotFoundError:
            _geoip_cache[ip] = "??"
            return "??"
        except Exception:
            pass

    _geoip_cache[ip] = "??"
    return "??"


@app.get("/geoip/{ip}")
async def get_geoip(ip: str):
    """Lookup country code for IP address using local MaxMind database."""
    if ip in _geoip_cache:
        return {"ip": ip, "country": _geoip_cache[ip]}
    
    # Skip private IPs
    if ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.")):
        _geoip_cache[ip] = "LAN"
        return {"ip": ip, "country": "LAN"}
    
    # Try local database
    reader = _get_geoip_reader()
    if reader:
        try:
            response = reader.country(ip)
            country = response.country.iso_code or ""
            if country:
                _geoip_cache[ip] = country
                return {"ip": ip, "country": country}
        except Exception:
            pass
    
    return {"ip": ip, "country": ""}
