# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — canonical SQLite device store (#817 Task 1).

Consolidates the four legacy device inventories (nac, mac-guard,
device-intel, iot-guard) into a single normalized `devices` table, keyed
by a canonicalized MAC address. Pure stdlib (`sqlite3`, `json`, `re`) —
no FastAPI, no secubox_core import — so it can be unit tested in
isolation and reused by discovery/collector/enrich modules.

Import of this module MUST have no side effects: no directory creation,
no DB connection opened at import time. `DeviceStore(db_path)` is the
only thing that touches disk.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time

logger = logging.getLogger("secubox.nac.store")

_HEX_RE = re.compile(r"[0-9a-fA-F]")

# Enrichment columns: a later upsert with a NULL value must never wipe a
# previously stored non-null value here. Always-overwrite columns (ip,
# last_seen, source) are handled separately in the SQL below.
_BEST_VALUE_COLUMNS = (
    "hostname",
    "oui_vendor",
    "is_router",
    "is_openwrt",
    "is_secubox",
    "model",
    "luci_version",
    "device_type",
    "risk_level",
    "risk_score",
    "zone",
    "allow_state",
    "quarantined",
    "parental_profile",
    "tags",
    "notes",
    "group_id",
    "plane",
    "provenance",
    "geo_cc",
    "geo_asn",
)

_ALWAYS_SET_COLUMNS = ("ip", "last_seen", "source")

# `first_seen` is set-once: the FIRST value ever recorded wins, so it is
# handled separately from the generic best-value columns (which let a
# later non-null incoming value win). Here the *existing* stored value
# wins whenever a row already exists; the incoming value is only used to
# seed a brand-new row.
_FIRST_SEEN_COLUMN = "first_seen"

_ALL_UPSERT_COLUMNS = _BEST_VALUE_COLUMNS + _ALWAYS_SET_COLUMNS + (_FIRST_SEEN_COLUMN,)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
  oui_vendor TEXT,
  is_router INTEGER DEFAULT 0, is_openwrt INTEGER DEFAULT 0, is_secubox INTEGER DEFAULT 0,
  model TEXT, luci_version TEXT,
  device_type TEXT DEFAULT 'unknown', risk_level TEXT DEFAULT 'unknown', risk_score INTEGER DEFAULT 50,
  zone TEXT, allow_state TEXT DEFAULT 'unknown', quarantined INTEGER DEFAULT 0, parental_profile TEXT,
  first_seen INTEGER, last_seen INTEGER, source TEXT,
  tags TEXT, notes TEXT, group_id TEXT,
  plane TEXT, provenance TEXT, geo_cc TEXT, geo_asn TEXT
);
CREATE INDEX IF NOT EXISTS idx_dev_last ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_dev_zone ON devices(zone);
CREATE INDEX IF NOT EXISTS idx_dev_type ON devices(device_type);
CREATE TABLE IF NOT EXISTS device_history(id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ts INTEGER, event TEXT, detail TEXT);
"""


def canon_mac(s: str) -> str:
    """Canonicalize a MAC address to lowercase, colon-separated form.

    Accepts `AA:BB:CC:DD:EE:FF`, `aabb.ccdd.eeff` (Cisco dot form),
    `aa-bb-cc-dd-ee-ff`, and bare `aabbccddeeff`. Returns "" if the input
    does not reduce to exactly 12 hex characters.
    """
    if not s:
        return ""
    hexonly = "".join(ch for ch in s if _HEX_RE.match(ch))
    if len(hexonly) != 12:
        return ""
    hexonly = hexonly.lower()
    return ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))


class DeviceStore:
    """Canonical device inventory backed by SQLite (WAL mode)."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        return dict(row)

    def upsert(self, dev: dict) -> None:
        """Insert or best-value-merge a device dict keyed by `mac` (already canon).

        Enrichment columns (`_BEST_VALUE_COLUMNS`) use COALESCE(excluded, stored)
        so a later sighting with missing fields never wipes previously learned
        data. `ip`/`last_seen`/`source` are always overwritten with the
        incoming value (or kept if the incoming value is falsy/None, via
        COALESCE too, since a sighting always carries at least last_seen/ip).
        `first_seen` is set-once: the existing stored value always wins over
        the incoming one, so it can never be pushed forward (or backward) by
        a later sighting — it only gets set on first insert.
        """
        mac = dev.get("mac")
        if not mac:
            raise ValueError("upsert requires a canon 'mac' key")

        cols = ["mac"] + list(_ALL_UPSERT_COLUMNS)
        values = [mac] + [dev.get(c) for c in _ALL_UPSERT_COLUMNS]
        placeholders = ", ".join("?" for _ in cols)
        col_list = ", ".join(cols)

        set_clauses = []
        for c in _BEST_VALUE_COLUMNS:
            set_clauses.append(f"{c} = COALESCE(excluded.{c}, devices.{c})")
        for c in _ALWAYS_SET_COLUMNS:
            set_clauses.append(f"{c} = COALESCE(excluded.{c}, devices.{c})")
        set_clauses.append(
            f"{_FIRST_SEEN_COLUMN} = COALESCE(devices.{_FIRST_SEEN_COLUMN}, excluded.{_FIRST_SEEN_COLUMN})"
        )
        set_sql = ", ".join(set_clauses)

        sql = (
            f"INSERT INTO devices ({col_list}) VALUES ({placeholders}) "
            f"ON CONFLICT(mac) DO UPDATE SET {set_sql}"
        )
        self._conn.execute(sql, values)
        self._conn.commit()

    def get(self, mac: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        return self._row_to_dict(row)

    def list(self, *, zone=None, device_type=None, risk_min=None, limit=1000) -> list:
        clauses = []
        params: list = []
        if zone is not None:
            clauses.append("zone = ?")
            params.append(zone)
        if device_type is not None:
            clauses.append("device_type = ?")
            params.append(device_type)
        if risk_min is not None:
            clauses.append("risk_score >= ?")
            params.append(risk_min)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        sql = (
            f"SELECT * FROM devices {where} "
            f"ORDER BY last_seen DESC LIMIT ?"
        )
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM devices").fetchone()
        return int(row["n"])

    def record_event(self, mac: str, event: str, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO device_history (mac, ts, event, detail) VALUES (?, ?, ?, ?)",
            (mac, int(time.time()), event, detail),
        )
        self._conn.commit()

    def history(self, mac: str | None = None, limit: int = 200) -> list:
        if mac is not None:
            rows = self._conn.execute(
                "SELECT * FROM device_history WHERE mac = ? ORDER BY ts DESC LIMIT ?",
                (mac, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM device_history ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def _to_epoch(v) -> int | None:
    """Best-effort conversion of a legacy timestamp (ISO string, epoch int/float,
    or already-int) to an integer epoch. Returns None if unparseable."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        try:
            return int(float(v))
        except ValueError:
            pass
        try:
            import datetime as _dt
            return int(_dt.datetime.fromisoformat(v).timestamp())
        except ValueError:
            return None
    return None


def _migrate_macguard(store: DeviceStore, path: str) -> int:
    """mac-guard `devices.json`: dict keyed by MAC (uppercase), fields
    `vendor`, `hostname`, `ip`, `first_seen`, `last_seen`."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    n = 0
    for raw_mac, info in data.items():
        mac = canon_mac(raw_mac)
        if not mac:
            continue
        store.upsert({
            "mac": mac,
            "ip": info.get("ip"),
            "hostname": info.get("hostname"),
            "oui_vendor": info.get("vendor"),
            "first_seen": _to_epoch(info.get("first_seen")),
            "last_seen": _to_epoch(info.get("last_seen")),
            "source": "mac-guard",
        })
        n += 1
    return n


def _bool_to_int(v) -> int | None:
    return None if v is None else int(bool(v))


def _migrate_deviceintel(store: DeviceStore, path: str) -> int:
    """device-intel `devices.json`: dict keyed by MAC (uppercase), fields
    `is_openwrt`, `is_secubox`, `model`, `luci_version`, `is_router`."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    n = 0
    for raw_mac, info in data.items():
        mac = canon_mac(raw_mac)
        if not mac:
            continue
        store.upsert({
            "mac": mac,
            "ip": info.get("ip"),
            "hostname": info.get("hostname"),
            "is_router": _bool_to_int(info.get("is_router")),
            "is_openwrt": _bool_to_int(info.get("is_openwrt")),
            "is_secubox": _bool_to_int(info.get("is_secubox")),
            "model": info.get("model"),
            "luci_version": info.get("luci_version"),
            "source": "device-intel",
        })
        n += 1
    return n


def _migrate_iotguard(store: DeviceStore, path: str) -> int:
    """iot-guard SQLite `devices` table: `mac_address` (lowercase),
    `ip`, `hostname`, `device_type`, `risk_score`."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"iot-guard db not found: {path}")
    # Open read-only: sqlite3.connect() on a plain path creates an empty
    # file if it doesn't exist, and we must never leave stray junk on
    # disk when iot-guard was never installed on this board.
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
        rows = conn.execute("SELECT * FROM devices").fetchall()
    finally:
        conn.close()
    n = 0
    for row in rows:
        d = dict(row)
        mac = canon_mac(d.get("mac_address", ""))
        if not mac:
            continue
        store.upsert({
            "mac": mac,
            "ip": d.get("ip"),
            "hostname": d.get("hostname") if "hostname" in cols else None,
            "device_type": d.get("device_type"),
            "risk_score": d.get("risk_score"),
            "source": "iot-guard",
        })
        n += 1
    return n


def migrate_legacy(store: DeviceStore, *, macguard_json, deviceintel_json, iot_db) -> dict:
    """Idempotent import of the three retired legacy device stores.

    Each source is independently best-effort: a missing file, corrupt
    JSON, or malformed SQLite DB is logged and skipped — never raises.
    Re-running is a no-op because `upsert` merges by `mac` (primary key).
    """
    imported = 0
    skipped = 0

    for label, fn, path in (
        ("mac-guard", _migrate_macguard, macguard_json),
        ("device-intel", _migrate_deviceintel, deviceintel_json),
        ("iot-guard", _migrate_iotguard, iot_db),
    ):
        try:
            imported += fn(store, path)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, must never abort boot
            logger.warning("migrate_legacy: skipping %s source (%s): %s", label, path, exc)
            skipped += 1

    return {"imported": imported, "skipped": skipped}
