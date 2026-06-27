# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: secubox-hub network-stats (#758).

Shared by the root collector (write path: collect_once/main) and the FastAPI
app (read path: read_snapshot/query_series). Pure functions are unit-tested;
the privileged collect path is integration-tested with monkeypatched sources.
"""
from __future__ import annotations
import json
import sqlite3
import subprocess
import time
from pathlib import Path

DB_PATH = Path("/var/lib/secubox/hub/netstats.db")
SNAP_PATH = Path("/var/lib/secubox/hub/netstats.json")
DATA_DIR = DB_PATH.parent
STALE_AFTER_S = 120  # snapshot older than this is flagged stale

# counter-name → category. Named counters live in the owning packages' tables.
CATEGORY_MAP = {
    "sbx_drop_blacklist_v4": "blacklist", "sbx_drop_blacklist_v6": "blacklist",
    "sbx_drop_quarantine_v4": "quarantine", "sbx_drop_quarantine_v6": "quarantine",
    "sbx_doh_detect_v4": "doh", "sbx_doh_detect_v6": "doh",
    "sbx_drop_wafrl": "waf_ratelimit",
    "sbx_drop_input_policy": "input_policy",
    "sbx_drop_crowdsec": "crowdsec",
}
# Categories that count toward "network_drops" (doh is detect-only, excluded).
DROP_CATEGORIES = {"blacklist", "quarantine", "waf_ratelimit", "input_policy", "crowdsec"}


def category_for(name: str) -> str | None:
    return CATEGORY_MAP.get(name)


def parse_proc_net_dev(text: str) -> dict[str, dict]:
    """Parse /proc/net/dev → {iface: {rx_bytes,rx_packets,tx_bytes,tx_packets}}.
    Skips the two header lines and the loopback interface.
    """
    out: dict[str, dict] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "lo" or not name:
            continue
        f = rest.split()
        if len(f) < 16:
            continue
        out[name] = {
            "rx_bytes": int(f[0]), "rx_packets": int(f[1]),
            "tx_bytes": int(f[8]), "tx_packets": int(f[9]),
        }
    return out


def parse_nft_counters_json(data: dict) -> dict[str, dict]:
    """Parse `nft -j list counters` (or list table) → {name: {packets,bytes}}."""
    out: dict[str, dict] = {}
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict) and "name" in c:
            out[c["name"]] = {
                "packets": int(c.get("packets", 0) or 0),
                "bytes": int(c.get("bytes", 0) or 0),
            }
    return out


def reset_aware_delta(prev: int, cur: int) -> int:
    """Monotonic-counter delta that tolerates resets (nft reload → cur < prev)."""
    if cur < prev:
        return cur
    return cur - prev


# ---------------------------------------------------------------------------
# SQLite store (Task 5)
# ---------------------------------------------------------------------------

def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS counter_samples (
            ts INTEGER NOT NULL, name TEXT NOT NULL,
            packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
            PRIMARY KEY (ts, name)
        );
        CREATE TABLE IF NOT EXISTS iface_samples (
            ts INTEGER NOT NULL, iface TEXT NOT NULL,
            rx_bytes INTEGER NOT NULL, rx_packets INTEGER NOT NULL,
            tx_bytes INTEGER NOT NULL, tx_packets INTEGER NOT NULL,
            PRIMARY KEY (ts, iface)
        );
        CREATE INDEX IF NOT EXISTS idx_counter_ts ON counter_samples(ts);
        CREATE INDEX IF NOT EXISTS idx_iface_ts ON iface_samples(ts);
        """
    )
    conn.commit()


def insert_sample(conn: sqlite3.Connection, ts: int, counters: dict, ifaces: dict) -> None:
    for name, v in counters.items():
        conn.execute(
            "INSERT OR REPLACE INTO counter_samples(ts,name,packets,bytes) VALUES(?,?,?,?)",
            (ts, name, int(v.get("packets", 0)), int(v.get("bytes", 0))),
        )
    for iface, v in ifaces.items():
        conn.execute(
            "INSERT OR REPLACE INTO iface_samples(ts,iface,rx_bytes,rx_packets,tx_bytes,tx_packets) "
            "VALUES(?,?,?,?,?,?)",
            (ts, iface, int(v["rx_bytes"]), int(v["rx_packets"]),
             int(v["tx_bytes"]), int(v["tx_packets"])),
        )
    conn.commit()


def _bucket(ts: int, step_s: int) -> int:
    return ts - (ts % step_s)


def query_series(conn: sqlite3.Connection, window_s: int, step_s: int) -> dict:
    """Reset-aware deltas/rates bucketed to step_s over the last window_s.
    Rates are attributed to the bucket of the later sample in each pair.
    """
    now_row = conn.execute("SELECT MAX(ts) FROM counter_samples").fetchone()
    max_ts_c = now_row[0] if now_row and now_row[0] is not None else None
    now_row2 = conn.execute("SELECT MAX(ts) FROM iface_samples").fetchone()
    max_ts_i = now_row2[0] if now_row2 and now_row2[0] is not None else None
    max_ts = max(t for t in (max_ts_c, max_ts_i) if t is not None) if any(t is not None for t in (max_ts_c, max_ts_i)) else 0
    floor = max_ts - window_s

    drops: dict[str, dict[int, int]] = {}
    rows = conn.execute(
        "SELECT ts,name,packets FROM counter_samples WHERE ts>=? ORDER BY name,ts",
        (floor - step_s,),
    ).fetchall()
    prev: dict[str, tuple[int, int]] = {}
    for ts, name, pk in rows:
        cat = category_for(name)
        if cat is None:
            continue
        if name in prev:
            d = reset_aware_delta(prev[name][1], pk)
            b = _bucket(ts, step_s)
            if b >= _bucket(floor, step_s):
                drops.setdefault(cat, {}).setdefault(b, 0)
                drops[cat][b] += d
        prev[name] = (ts, pk)

    in_bps: dict[str, dict[int, int]] = {}
    out_bps: dict[str, dict[int, int]] = {}
    irows = conn.execute(
        "SELECT ts,iface,rx_bytes,tx_bytes FROM iface_samples WHERE ts>=? ORDER BY iface,ts",
        (floor - step_s,),
    ).fetchall()
    iprev: dict[str, tuple[int, int, int]] = {}
    for ts, iface, rx, tx in irows:
        if iface in iprev:
            pts, prx, ptx = iprev[iface]
            dt = ts - pts
            if dt > 0:
                b = _bucket(ts, step_s)
                if b >= _bucket(floor, step_s):
                    in_bps.setdefault(iface, {})[b] = reset_aware_delta(prx, rx) * 8 // dt
                    out_bps.setdefault(iface, {})[b] = reset_aware_delta(ptx, tx) * 8 // dt
        iprev[iface] = (ts, rx, tx)

    def _flatten(d: dict[str, dict[int, int]]) -> dict[str, list]:
        return {k: [[b, v[b]] for b in sorted(v)] for k, v in d.items()}

    return {
        "window_s": window_s, "step_s": step_s,
        "drops": _flatten(drops), "in_bps": _flatten(in_bps), "out_bps": _flatten(out_bps),
    }


def prune(conn: sqlite3.Connection, keep_s: int) -> None:
    for tbl in ("counter_samples", "iface_samples"):
        row = conn.execute(f"SELECT MAX(ts) FROM {tbl}").fetchone()
        if row and row[0] is not None:
            conn.execute(f"DELETE FROM {tbl} WHERE ts < ?", (row[0] - keep_s,))
    conn.commit()


# ---------------------------------------------------------------------------
# Snapshot builder + privileged collector (Task 6)
# ---------------------------------------------------------------------------

def build_snapshot(conn: sqlite3.Connection, now: int) -> dict:
    """Latest cumulative per category + instantaneous rates vs the previous
    sample. network_drops = sum of DROP_CATEGORIES packet counts (doh excluded).
    """
    cats: dict[str, dict] = {}
    # latest cumulative per counter-name → fold into categories
    rows = conn.execute(
        "SELECT name, packets, bytes, ts FROM counter_samples "
        "WHERE ts=(SELECT MAX(ts) FROM counter_samples)"
    ).fetchall()
    for name, pk, by, _ts in rows:
        cat = category_for(name)
        if cat is None:
            continue
        c = cats.setdefault(cat, {"packets": 0, "bytes": 0})
        c["packets"] += int(pk)
        c["bytes"] += int(by)
    ser = query_series(conn, window_s=120, step_s=30)
    for cat, pts in ser["drops"].items():
        if pts:
            cats.setdefault(cat, {"packets": 0, "bytes": 0})["pps"] = pts[-1][1] / 30.0

    ifaces: dict[str, dict] = {}
    irow = conn.execute(
        "SELECT iface, rx_bytes, tx_bytes FROM iface_samples "
        "WHERE ts=(SELECT MAX(ts) FROM iface_samples)"
    ).fetchall()
    for iface, rx, tx in irow:
        ifaces[iface] = {"rx_bytes": int(rx), "tx_bytes": int(tx)}
    for iface, pts in ser["in_bps"].items():
        if pts:
            ifaces.setdefault(iface, {})["rx_bps"] = pts[-1][1]
    for iface, pts in ser["out_bps"].items():
        if pts:
            ifaces.setdefault(iface, {})["tx_bps"] = pts[-1][1]

    network_drops = sum(
        cats.get(cat, {}).get("packets", 0) for cat in DROP_CATEGORIES
    )
    return {
        "updated": now,
        "stale": False,
        "categories": cats,
        "interfaces": ifaces,
        "network_drops": int(network_drops),
    }


def read_snapshot() -> dict:
    """Read the latest snapshot (API path). Flags stale by `updated` age."""
    try:
        d = json.loads(SNAP_PATH.read_text())
    except Exception:
        return {"updated": 0, "stale": True, "categories": {}, "interfaces": {}, "network_drops": 0}
    age = max(0, int(time.time()) - int(d.get("updated", 0)))
    d["stale"] = age > STALE_AFTER_S
    return d


def _run_nft_json(args: list[str]) -> dict:
    try:
        r = subprocess.run(["/usr/sbin/nft", "-j", "list"] + args,
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return json.loads(r.stdout or "{}")
    except Exception:
        pass
    return {}


def _read_nft_counters() -> dict:
    return parse_nft_counters_json(_run_nft_json(["counters"]))


def _read_crowdsec() -> dict:
    """Best-effort: sum the externally-managed inet crowdsec table counters
    into a single synthetic counter mapped to the 'crowdsec' category.
    """
    data = _run_nft_json(["table", "inet", "crowdsec"])
    total = 0
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict):
            total += int(c.get("packets", 0) or 0)
        rule = item.get("rule")
        if isinstance(rule, dict):
            for ex in rule.get("expr", []):
                cc = ex.get("counter")
                if isinstance(cc, dict):
                    total += int(cc.get("packets", 0) or 0)
    if total:
        # synthetic name so category_for resolves to 'crowdsec'
        return {"sbx_drop_crowdsec": {"packets": total, "bytes": 0}}
    return {}


def _read_ifaces() -> dict:
    try:
        return parse_proc_net_dev(Path("/proc/net/dev").read_text())
    except Exception:
        return {}


def _open_db(conn: sqlite3.Connection | None):
    if conn is not None:
        return conn, False
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        DATA_DIR.chmod(0o755)  # our subdir only — NEVER the /var/lib/secubox parent
    except Exception:
        pass
    c = sqlite3.connect(str(DB_PATH))
    init_db(c)
    return c, True


def collect_once(now: int | None = None, conn: sqlite3.Connection | None = None) -> dict:
    if now is None:
        now = int(time.time())
    c, owns = _open_db(conn)
    try:
        counters = dict(_read_nft_counters())
        counters.update(_read_crowdsec())
        ifaces = _read_ifaces()
        insert_sample(c, now, counters, ifaces)
        prune(c, keep_s=7 * 86400)
        snap = build_snapshot(c, now)
        try:
            SNAP_PATH.write_text(json.dumps(snap))
            SNAP_PATH.chmod(0o644)
        except Exception:
            pass
        return snap
    finally:
        if owns:
            c.close()


def main() -> None:
    collect_once()


if __name__ == "__main__":
    main()
