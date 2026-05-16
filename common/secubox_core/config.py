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
        "crowdsec": {"lapi_url": "http://127.0.0.1:8080", "lapi_key": ""},
        "dpi":    {"mode": "inline", "engine": "netifyd", "interface": "eth0", "mirror_if": "ifb0"},
        "wireguard": {"interface": "wg0", "listen_port": 51820},
    }
    return _CONFIG


def get_config(section: str = "") -> dict:
    """
    Retourne la section demandée, ou la config complète si section="".

    Exemple :
        cfg = get_config("crowdsec")
        url = cfg["lapi_url"]
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

# Cookie audit (RGPD / ePrivacy, issue #156). See packages/secubox-metrics
# for the aggregator and packages/secubox-mitmproxy/addons/cookie_audit.py
# for the server-side ledger producer.
_COOKIE_AUDIT_DEFAULTS = {
    "enabled": False,
    "ledger_path": "/var/log/secubox/cookie-audit/server.jsonl",
    "ingest_dir": "/var/lib/secubox/cookie-audit/ingest",
    "max_ingest_age_hours": 24,
}

# Built-in classifier patterns. Override with [cookie_audit.classifier] in
# /etc/secubox/secubox.conf. Categories evaluated in order
# (strictly_necessary > functional > analytics > marketing), first match wins.
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
    """Return [cookie_audit] merged with defaults, including classifier rules.

    Each classifier category is the union of operator-provided patterns and
    the built-in defaults — admins can extend but never silently drop the
    RGPD baseline. Set ``classifier_override = true`` in
    ``[cookie_audit]`` to disable the merge and use operator patterns only.
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
