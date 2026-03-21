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
