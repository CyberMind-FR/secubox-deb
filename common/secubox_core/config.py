# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
secubox_core.config — Chargeur de configuration TOML
=====================================================
Lit /etc/secubox/secubox.conf (TOML).
Fallback : ./secubox.conf.example (dev).
"""
from __future__ import annotations
import os
import subprocess
from functools import lru_cache
from pathlib import Path

try:
    import tomllib          # stdlib Python 3.11+
except ImportError:
    import tomli as tomllib  # pip install tomli pour Python 3.10

# Chemins de recherche (ordre de priorité)
_CONF_PATHS = [
    Path("/etc/secubox/secubox.conf"),
    Path(__file__).parents[4] / "secubox.conf.example",
]

_CONFIG: dict | None = None


def _load() -> dict:
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG

    for p in _CONF_PATHS:
        if p.exists():
            with open(p, "rb") as f:
                _CONFIG = tomllib.load(f)
            return _CONFIG

    # Config minimale par défaut (dev sans fichier)
    _CONFIG = {
        "global": {"hostname": "secubox", "timezone": "Europe/Paris", "board": "unknown"},
        "api":    {"socket_dir": "/tmp/secubox", "jwt_secret": os.environ.get("SECUBOX_JWT_SECRET", "dev-secret")},
        "auth":   {"users": {"admin": {"password": "secubox"}}},
        "dpi":    {"mode": "inline", "engine": "ndpid", "interface": "eth0", "mirror_if": "ifb0"},
        "wireguard": {"interface": "wg0", "listen_port": 51820},
    }
    return _CONFIG


def get_config(section: str = "") -> dict:
    """
    Retourne la section demandée, ou la config complète si section="".

    Exemple :
        cfg = get_config("wireguard")
        port = cfg["listen_port"]
    """
    cfg = _load()
    if not section:
        return cfg
    return cfg.get(section, {})


def reload_config() -> None:
    """Force le rechargement du fichier de config (post-modification)."""
    global _CONFIG
    _CONFIG = None
    _load()


# ── Informations board ─────────────────────────────────────────────

def get_board_info() -> dict:
    """
    Retourne les infos hardware du board courant.
    Lit /proc/device-tree/model (DTS node name sur ARM).
    """
    model = "unknown"
    model_path = Path("/proc/device-tree/model")
    if model_path.exists():
        model = model_path.read_text(errors="replace").strip().rstrip("\x00")

    # Uptime
    try:
        uptime_sec = float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        uptime_sec = 0.0

    # CPU / RAM
    cpu_count = os.cpu_count() or 1
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":")
            mem[k.strip()] = int(v.strip().split()[0])  # kB
    except Exception:
        pass

    return {
        "model":        model,
        "board":        get_config("global").get("board", "unknown"),
        "hostname":     get_config("global").get("hostname", "secubox"),
        "uptime_sec":   int(uptime_sec),
        "cpu_count":    cpu_count,
        "mem_total_mb": mem.get("MemTotal", 0) // 1024,
        "mem_free_mb":  mem.get("MemAvailable", 0) // 1024,
    }


# ── Live-panel helpers (issue #92) ─────────────────────────────────

_VISITOR_ORIGIN_DEFAULTS = {
    "enabled": False,
    "window_minutes": 60,
    "min_count": 5,
    "top_n": 5,
    "asn_db_path": "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
    "nft_table": "secubox_metrics",
    "nft_set": "seen_src",
    "nft_family": "inet",
}

_LIVE_HOSTS_DEFAULTS = {
    "enabled": False,
    "window_minutes": 60,
    "top_n": 5,
    "haproxy_socket": "/run/haproxy/admin.sock",
    "frontend_filter": "*",
}

_CERT_STATUS_DEFAULTS = {
    "enabled": False,
    "letsencrypt_live_dir": "/etc/letsencrypt/live",
    "warn_days": 30,
    "critical_days": 7,
}


_COOKIE_AUDIT_DEFAULTS = {
    # ENABLED=False PAR DEFAUT, et c'est volontaire. Ce collecteur lit un
    # registre d'audit de cookies qui peut peser des centaines de mega-octets ;
    # l'allumer d'office sur une carte a 1-2 Go serait une decision prise a la
    # place de l'exploitant. `secubox.conf` l'active explicitement la ou il sert.
    "enabled": False,
    "ledger_path": "/var/log/secubox/cookie-audit/server.jsonl",
    "ingest_dir": "/var/lib/secubox/cookie-audit/ingest",
    "max_ingest_age_hours": 24,
}

# SOCLE RGPD DU CLASSIFIEUR (#159). Efface par la fusion 7ebe27403a et restaure
# (#1777, ref #1748) : sans lui, `classifier` restait vide et CHAQUE cookie
# tombait en « unclassified » — un _ga ou un _fbp n'etait plus reconnu comme
# traceur, et un jeton CSRF pose en JS passait pour une violation. Surcharge par
# [cookie_audit.classifier] dans /etc/secubox/secubox.conf. Categories
# evaluees dans l'ordre (strictly_necessary > functional > analytics >
# marketing), la premiere qui correspond l'emporte.
_COOKIE_CLASSIFIER_DEFAULTS = {
    "strictly_necessary": [
        r"^PHPSESSID$",
        r"^sess(ion)?id$",
        r"^csrftoken$",
        r"^XSRF-TOKEN$",
        r"^_csrf$",
        r"^cart$",
        r"^remember_token$",
        r"^secubox_session$",
    ],
    "functional": [
        r"^lang$",
        r"^locale$",
        r"^theme$",
        r"^cookie[_-]?consent$",
        r"^euconsent",
    ],
    "analytics": [
        r"^_ga",
        r"^_gid$",
        r"^_gat",
        r"^_pk_",
        r"^_hjid$",
        r"^_hjSession",
        r"^_clck$",
        r"^_clsk$",
        r"^_matomo",
    ],
    "marketing": [
        r"^_fbp$",
        r"^_fbc$",
        r"^__utm",
        r"^_gcl_",
        r"^_uet",
        r"^IDE$",
        r"^MUID$",
        r"^NID$",
    ],
}


def _merged(defaults: dict, section: str) -> dict:
    out = dict(defaults)
    out.update(get_config(section))
    return out


def get_visitor_origin_config() -> dict:
    """Return [visitor_origin] merged with defaults."""
    return _merged(_VISITOR_ORIGIN_DEFAULTS, "visitor_origin")


def get_live_hosts_config() -> dict:
    """Return [live_hosts] merged with defaults."""
    return _merged(_LIVE_HOSTS_DEFAULTS, "live_hosts")


def get_cert_status_config() -> dict:
    """Return [cert_status] merged with defaults."""
    return _merged(_CERT_STATUS_DEFAULTS, "cert_status")


def get_cookie_audit_config() -> dict:
    """Return [cookie_audit] merged with defaults.

    MANQUANT JUSQU'ICI (#1311). Le module `cookie_audit` existait, testE (20
    tests) et configurE dans `secubox.conf` — mais aucun lecteur ne rendait sa
    section, aucun code ne l'instanciait, et son agregateur n'etait jamais
    demarre. 170 Mo de registre s'accumulaient sans jamais etre reconcilies,
    alors que c'est la brique RGPD / ePrivacy du produit.

    Chaque categorie du classifieur est l'UNION des motifs de l'exploitant et
    du socle integre : on peut etendre la base RGPD, jamais la perdre en
    silence. ``classifier_override = true`` dans ``[cookie_audit]`` desactive
    la fusion et n'applique que les motifs de l'exploitant.
    """
    cfg = _merged(_COOKIE_AUDIT_DEFAULTS, "cookie_audit")
    operator_cls = (get_config("cookie_audit") or {}).get("classifier") or {}
    override = bool(cfg.get("classifier_override", False))
    merged_cls: dict = {}
    for cat, base in _COOKIE_CLASSIFIER_DEFAULTS.items():
        op = operator_cls.get(cat, []) or []
        if override:
            merged_cls[cat] = list(op)
        else:
            seen = set()
            out = []
            for pat in list(op) + list(base):
                if pat not in seen:
                    out.append(pat)
                    seen.add(pat)
            merged_cls[cat] = out
    cfg["classifier"] = merged_cls
    return cfg
