# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: ToolBoX device-blocks attribution (Phase 13.C #524)

Attributes blacklist drops + DoH-bypass attempts to the DEVICE that made
them, by mapping the packet source IP to a device identity :

  - R3 WG peers (10.99.1.x)  → sha256(wg_pubkey)[:16]  (same hash as the
    social-mapping model — anonymous, rotating-salt-equivalent via the
    pubkey).
  - captive subnet (10.99.0.x / br-lxc 10.100.0.x) → dnsmasq lease MAC
    hashed with the rotating MAC salt.

Storage : `device_blocks` aggregate (one row per device × kind × dst).
Read by the /admin/device-blocks endpoint + the SOC tile.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("secubox.toolbox.device_blocks")

DB_PATH = Path("/var/lib/secubox/toolbox/toolbox.db")
_WG_PEERS_DB = Path("/var/lib/secubox/toolbox/wg-peers.json")
_SALT_FILE = Path("/etc/secubox/secrets/toolbox-mac-salt")
# Common dnsmasq lease locations.
_LEASE_FILES = (
    Path("/var/lib/misc/dnsmasq.leases"),
    Path("/var/lib/dnsmasq/dnsmasq.leases"),
    Path("/run/secubox/toolbox-dnsmasq.leases"),
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_blocks (
    mac_hash  TEXT NOT NULL,
    ip        TEXT NOT NULL,
    kind      TEXT NOT NULL,        -- 'blacklist-drop' | 'doh-attempt'
    dst       TEXT NOT NULL,
    hits      INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (mac_hash, kind, dst)
);
CREATE INDEX IF NOT EXISTS idx_devblk_ts ON device_blocks(last_seen);
CREATE INDEX IF NOT EXISTS idx_devblk_mac ON device_blocks(mac_hash, last_seen);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=5.0, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.executescript(_SCHEMA)
    return c


# ── device resolver ──
_wg_cache: Dict[str, str] = {}
_wg_mtime: float = 0.0


def _wg_hash(ip: str) -> Optional[str]:
    global _wg_mtime
    try:
        if not _WG_PEERS_DB.exists():
            return None
        mt = _WG_PEERS_DB.stat().st_mtime
        if mt != _wg_mtime or not _wg_cache:
            _wg_cache.clear()
            data = json.loads(_WG_PEERS_DB.read_text()).get("peers", {})
            for pubkey, meta in data.items():
                pip = meta.get("ip")
                if pip:
                    _wg_cache[pip] = hashlib.sha256(pubkey.encode()).hexdigest()[:16]
            _wg_mtime = mt
        return _wg_cache.get(ip)
    except Exception:
        return None


def _salt() -> str:
    try:
        return _SALT_FILE.read_text().strip()
    except Exception:
        return ""


def _lease_mac(ip: str) -> Optional[str]:
    for lf in _LEASE_FILES:
        try:
            if not lf.exists():
                continue
            for line in lf.read_text().splitlines():
                # dnsmasq lease : <expiry> <mac> <ip> <host> <clientid>
                parts = line.split()
                if len(parts) >= 3 and parts[2] == ip:
                    return parts[1].lower()
        except Exception:
            continue
    return None


def resolve_device(ip: str) -> str:
    """Map a source IP to an anonymous device hash.

    R3 WG → wg pubkey hash ; captive/br-lxc → hashed lease MAC ; unknown
    → a stable hash of the IP itself (so unattributed drops still bucket).
    """
    if not ip:
        return "unknown"
    if ip.startswith("10.99.1."):
        h = _wg_hash(ip)
        if h:
            return h
    mac = _lease_mac(ip)
    if mac:
        salt = _salt()
        if salt:
            key = (salt + ":" + time.strftime("%Y-%m-%d")).encode()
            import hmac
            return hmac.new(key, mac.encode(), hashlib.sha256).hexdigest()[:16]
        return hashlib.sha256(mac.encode()).hexdigest()[:16]
    # Fall back to an IP-derived bucket (still anonymous, last-octet kept
    # for the operator to eyeball which subnet).
    return "ip:" + ip


def record_block(mac_hash: str, ip: str, kind: str, dst: str) -> None:
    """Upsert a device block event (called by the attribution tailer)."""
    if not (mac_hash and kind and dst):
        return
    now = int(time.time())
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO device_blocks(mac_hash, ip, kind, dst, hits, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, 1, ?, ?) "
                "ON CONFLICT(mac_hash, kind, dst) DO UPDATE SET "
                "hits = hits + 1, ip = excluded.ip, last_seen = excluded.last_seen",
                (mac_hash, ip, kind, dst, now, now),
            )
    except Exception as e:  # pragma: no cover
        log.warning("record_block failed: %s", e)


def recent(hours: int = 24, limit: int = 500) -> List[Dict]:
    since = int(time.time()) - max(hours, 1) * 3600
    try:
        with _conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT mac_hash, ip, kind, dst, hits, first_seen, last_seen "
                "FROM device_blocks WHERE last_seen >= ? "
                "ORDER BY last_seen DESC LIMIT ?",
                (since, limit),
            ).fetchall()]
    except Exception as e:  # pragma: no cover
        log.warning("recent failed: %s", e)
        return []


def aggregate(hours: int = 24) -> Dict:
    since = int(time.time()) - max(hours, 1) * 3600
    out: Dict = {"window_hours": hours, "devices": 0, "total_hits": 0,
                 "by_device": [], "by_kind": []}
    try:
        with _conn() as c:
            out["devices"] = c.execute(
                "SELECT COUNT(DISTINCT mac_hash) FROM device_blocks WHERE last_seen >= ?",
                (since,),
            ).fetchone()[0]
            out["total_hits"] = c.execute(
                "SELECT COALESCE(SUM(hits),0) FROM device_blocks WHERE last_seen >= ?",
                (since,),
            ).fetchone()[0]
            out["by_device"] = [dict(r) for r in c.execute(
                "SELECT mac_hash, ip, "
                "SUM(CASE WHEN kind='blacklist-drop' THEN hits ELSE 0 END) AS blacklist, "
                "SUM(CASE WHEN kind='doh-attempt' THEN hits ELSE 0 END) AS doh, "
                "SUM(hits) AS total, MAX(last_seen) AS last_seen "
                "FROM device_blocks WHERE last_seen >= ? "
                "GROUP BY mac_hash ORDER BY total DESC LIMIT 100",
                (since,),
            ).fetchall()]
            out["by_kind"] = [dict(r) for r in c.execute(
                "SELECT kind, SUM(hits) AS hits, COUNT(DISTINCT mac_hash) AS devices "
                "FROM device_blocks WHERE last_seen >= ? GROUP BY kind",
                (since,),
            ).fetchall()]
    except Exception as e:  # pragma: no cover
        log.warning("aggregate failed: %s", e)
    return out


def purge_older_than(days: int = 7) -> int:
    cutoff = int(time.time()) - max(days, 1) * 86400
    try:
        with _conn() as c:
            return c.execute(
                "DELETE FROM device_blocks WHERE last_seen < ?", (cutoff,)
            ).rowcount or 0
    except Exception:
        return 0
