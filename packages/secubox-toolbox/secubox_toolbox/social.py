# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: ToolBoX Social Mapping store

Phase 11.A (#505, parent #502) — per-device cross-cookie tracker
correlation engine. Captures Set-Cookie + Cookie headers from each
3rd-party flow during a consented R2 / R3 session, normalizes the
identifiers (NEVER persists raw cookie values), and folds raw edges
into per-peer node + link aggregates every 5 minutes.

Schema (3 tables):
  - social_edges : raw event log, retention 7 d (configurable).
  - social_nodes : per-peer per-tracker aggregate (hits, first/last
    seen, list of sites the tracker connected this peer to).
  - social_links : per-peer per-site-pair aggregate (which trackers
    were shared, JA4 collision flag, last seen).

Identifier discipline (NON-negotiable, doctrine):
  - client_mac_hash is computed from the existing rotating-salt MAC
    hash (mac.py). 24 h rotation makes the graph unreachable past TTL.
  - cookie_id_hash = sha256(tracker_domain || cookie_name || cookie_value)[:16].
    Raw values are NEVER persisted.
  - Session/CSRF/auth cookie names are stripped via the deny-list
    (default constant + TOML override).

See also: utiq.py for the same fire-and-forget executor pattern.
"""
from __future__ import annotations

import concurrent.futures as _futures
import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

log = logging.getLogger("secubox.toolbox.social.store")

DB_PATH = Path("/var/lib/secubox/toolbox/toolbox.db")

# Cookie names whose presence on a flow is NEVER recorded as a tracker
# identifier. Phase 11.A ships a conservative default ; operators can
# extend via [social_graph.deny_cookies] in toolbox.toml.
_DEFAULT_DENY_COOKIES: Set[str] = {
    # session
    "phpsessid", "jsessionid", "asp.net_sessionid", "ci_session",
    "express.sid", "connect.sid", "sails.sid", "django_session",
    "laravel_session", "flask_session", "session", "sessionid",
    # csrf
    "_csrf", "_csrf_token", "xsrf-token", "csrftoken", "csrf",
    "x-csrf-token", "anti-csrf-token",
    # auth (1st-party)
    "auth", "auth_token", "access_token", "refresh_token", "bearer",
    "remember_token", "remember_me", "_oauth2_proxy",
    # cloudflare / consent / locale (low signal)
    "__cf_bm", "cf_clearance", "consent", "cookieconsent_status",
    "locale", "lang", "language", "_locale",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS social_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    client_mac_hash TEXT    NOT NULL,
    src_site        TEXT    NOT NULL,
    tracker_domain  TEXT    NOT NULL,
    cookie_id_hash  TEXT    NOT NULL,
    ja4_hash        TEXT,
    -- Phase 11.C (#508) — consent state at the moment the edge was
    -- recorded.  Computed by the addon based on whether a consent
    -- platform cookie (OneTrust/Didomi/Quantcast/Sourcepoint) has
    -- already been observed for this peer × site pair.
    consent_state   TEXT    NOT NULL DEFAULT 'none_seen'
);
CREATE INDEX IF NOT EXISTS idx_social_edges_mac_ts
    ON social_edges(client_mac_hash, ts);
CREATE INDEX IF NOT EXISTS idx_social_edges_tracker_ts
    ON social_edges(tracker_domain, ts);

CREATE TABLE IF NOT EXISTS social_nodes (
    client_mac_hash TEXT NOT NULL,
    tracker_domain  TEXT NOT NULL,
    hits            INTEGER NOT NULL DEFAULT 0,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    sites_jsonl     TEXT NOT NULL DEFAULT '[]',
    -- Phase 11.C (#508) — GeoIP-derived metadata populated at fold
    -- time so reads + PDF rendering don't have to do per-row mmdb
    -- lookups.  eu_inside is 1 when country_iso ∈ EU/EEA whitelist.
    country_iso     TEXT,
    asn_org         TEXT,
    eu_inside       INTEGER NOT NULL DEFAULT 1,
    -- Number of edges recorded against this (peer, tracker) BEFORE a
    -- consent cookie was observed.  >0 = legal-grade evidence of
    -- tracker firing before consent (RGPD art. 6.1.a + 7).
    pre_consent_hits INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (client_mac_hash, tracker_domain)
);

CREATE TABLE IF NOT EXISTS social_links (
    client_mac_hash       TEXT NOT NULL,
    site_a                TEXT NOT NULL,
    site_b                TEXT NOT NULL,
    shared_trackers_jsonl TEXT NOT NULL DEFAULT '[]',
    ja4_match             INTEGER NOT NULL DEFAULT 0,
    last_seen             INTEGER NOT NULL,
    PRIMARY KEY (client_mac_hash, site_a, site_b)
);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=5.0, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.executescript(_SCHEMA)
    _migrate_phase11c(c)
    return c


# ───── Phase 11.C migrations — additive columns on pre-existing tables ─────
# CREATE TABLE IF NOT EXISTS skips creation if the table already exists, so
# the new columns won't auto-appear on a 2.6.0 → 2.6.2 upgrade.  Idempotent
# ALTERs : we probe the column list first to skip the duplicate-column
# error case (which would raise on every connection otherwise).
_PHASE11C_MIGRATIONS = (
    ("social_edges",  "consent_state",    "TEXT NOT NULL DEFAULT 'none_seen'"),
    ("social_nodes",  "country_iso",      "TEXT"),
    ("social_nodes",  "asn_org",          "TEXT"),
    ("social_nodes",  "eu_inside",        "INTEGER NOT NULL DEFAULT 1"),
    ("social_nodes",  "pre_consent_hits", "INTEGER NOT NULL DEFAULT 0"),
)


def _migrate_phase11c(c: sqlite3.Connection) -> None:
    try:
        for table, col, decl in _PHASE11C_MIGRATIONS:
            existing = {
                r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if col not in existing:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    except Exception as e:  # pragma: no cover
        log.warning("Phase 11.C migration failed: %s", e)


# ───── EU / EEA whitelist (RGPD scope, art. 45 + Schengen extension) ─────
# Codes are ISO 3166-1 alpha-2.  Source : EU member state list + EFTA
# (NO, IS, LI) + UK (adequacy decision in force as of writing).  The
# Phase C "extra_eu" flag is set when GeoIP says the tracker's country
# ISO is NOT in this set.
_EU_EEA_ISO: frozenset = frozenset({
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR",
    "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL",
    "PT", "RO", "SE", "SI", "SK",      # 27 EU
    "IS", "LI", "NO",                  # EFTA / EEA
    "GB",                              # UK adequacy decision
})


def is_eu_iso(iso: str | None) -> bool:
    return bool(iso) and (iso or "").upper() in _EU_EEA_ISO


# Lightweight cache around the existing `geo` module so the fold loop
# doesn't pay the lookup cost per repeated tracker_domain.  Bounded to
# 4096 entries (well above any realistic distinct tracker count seen
# in a 7d retention window).
import functools as _functools


@_functools.lru_cache(maxsize=4096)
def _geo_for(host: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (country_iso, asn_org) for a tracker host.

    Best-effort.  Falls back to (None, None) when the GeoIP module isn't
    importable (worker hasn't installed the mmdb yet) or when the host
    is a raw IP and the underlying lookup misses.
    """
    try:
        from secubox_toolbox import geo as _g  # type: ignore
        info = _g.lookup(host) or {}
        iso = (info.get("country_iso") or "").upper() or None
        asn = (info.get("asn_org") or "")[:64] or None
        return iso, asn
    except Exception:
        return None, None


def cookie_id_hash(tracker_domain: str, cookie_name: str, cookie_value: str) -> str:
    """Stable short hash for an observed tracker identifier.

    Never round-trippable to the raw value (truncated SHA-256).
    """
    h = hashlib.sha256()
    h.update((tracker_domain or "").lower().encode("utf-8", "replace"))
    h.update(b"\x00")
    h.update((cookie_name or "").lower().encode("utf-8", "replace"))
    h.update(b"\x00")
    h.update((cookie_value or "").encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def is_deny_listed(cookie_name: str, extra_deny: Optional[Iterable[str]] = None) -> bool:
    name = (cookie_name or "").strip().lower()
    if not name:
        return True
    if name in _DEFAULT_DENY_COOKIES:
        return True
    if extra_deny:
        if name in {x.lower() for x in extra_deny}:
            return True
    return False


# Phase 11.A — fire-and-forget SQLite writes (same pattern as
# utiq.py + local_store.py). The mitmproxy asyncio loop never blocks
# on _conn() open + INSERT + fsync. Bounded queue depth via the
# single-worker executor.
_executor = _futures.ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="sbx_social_write"
)


def _record_edge_sync(
    client_mac_hash: str,
    src_site: str,
    tracker_domain: str,
    cookie_id_hash_val: str,
    ja4_hash: Optional[str],
    consent_state: str,
) -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO social_edges(ts, client_mac_hash, src_site, "
                "tracker_domain, cookie_id_hash, ja4_hash, consent_state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    int(time.time()),
                    client_mac_hash,
                    src_site,
                    tracker_domain,
                    cookie_id_hash_val,
                    ja4_hash,
                    consent_state or "none_seen",
                ),
            )
    except Exception as e:  # pragma: no cover — best-effort
        log.warning("record_edge failed: %s", e)


def record_edge(
    *,
    client_mac_hash: str,
    src_site: str,
    tracker_domain: str,
    cookie_id_hash_val: str,
    ja4_hash: Optional[str] = None,
    consent_state: str = "none_seen",
) -> None:
    """Submit one edge off-thread. Best-effort, never raises into the
    addon, never blocks the mitmproxy asyncio loop.

    `consent_state` is one of {none_seen, pre_consent, post_consent} as
    computed by the addon based on the per-peer × per-site consent
    cookie observation log (Phase 11.C).
    """
    if not (client_mac_hash and src_site and tracker_domain and cookie_id_hash_val):
        return
    try:
        _executor.submit(
            _record_edge_sync,
            client_mac_hash,
            src_site,
            tracker_domain,
            cookie_id_hash_val,
            ja4_hash,
            consent_state,
        )
    except RuntimeError:
        # Executor shut down (interpreter teardown) — silent drop.
        pass


def fold_recent(window_seconds: int = 300) -> Tuple[int, int]:
    """Fold raw edges from the last `window_seconds` into the node + link
    aggregate tables. Returns (nodes_touched, links_touched).

    Called by the FastAPI startup background task every 5 min. Cheap
    even with thousands of edges per fold because everything is on
    the indexed (client_mac_hash, ts) column.
    """
    since = int(time.time()) - max(window_seconds, 60)
    nodes_touched = 0
    links_touched = 0
    try:
        with _conn() as c:
            edges = c.execute(
                "SELECT client_mac_hash, src_site, tracker_domain, "
                "cookie_id_hash, ja4_hash, ts, consent_state "
                "FROM social_edges WHERE ts >= ?",
                (since,),
            ).fetchall()

            # Aggregate per (mac, tracker_domain) → nodes
            per_node: Dict[Tuple[str, str], Dict] = {}
            # Aggregate per (mac, site_a, site_b) → links
            per_link: Dict[Tuple[str, str, str], Dict] = {}
            # Index per (mac, site) → set(tracker_domain) for cross-site
            per_site_trackers: Dict[Tuple[str, str], Set[str]] = {}
            # JA4 hashes seen per (mac, site)
            per_site_ja4: Dict[Tuple[str, str], Set[str]] = {}

            for e in edges:
                mac = e["client_mac_hash"]
                site = e["src_site"]
                trk = e["tracker_domain"]
                ja4 = e["ja4_hash"]
                ts = e["ts"]

                # Per-node accumulator
                key_n = (mac, trk)
                n = per_node.setdefault(
                    key_n,
                    {
                        "hits": 0,
                        "first_seen": ts,
                        "last_seen": ts,
                        "sites": set(),
                        "pre_consent_hits": 0,
                    },
                )
                n["hits"] += 1
                n["first_seen"] = min(n["first_seen"], ts)
                n["last_seen"] = max(n["last_seen"], ts)
                n["sites"].add(site)
                if e["consent_state"] == "pre_consent":
                    n["pre_consent_hits"] += 1

                # Per-site tracker index (for link fold below)
                per_site_trackers.setdefault((mac, site), set()).add(trk)
                if ja4:
                    per_site_ja4.setdefault((mac, site), set()).add(ja4)

            # Persist nodes
            for (mac, trk), n in per_node.items():
                # Merge into existing row if present
                # Phase 11.C : enrich with GeoIP at fold time so reads
                # + PDF rendering never block on mmdb lookups.
                country_iso, asn_org = _geo_for(trk)
                eu_inside = 1 if is_eu_iso(country_iso) else 0
                cur = c.execute(
                    "SELECT hits, first_seen, sites_jsonl, pre_consent_hits "
                    "FROM social_nodes "
                    "WHERE client_mac_hash = ? AND tracker_domain = ?",
                    (mac, trk),
                ).fetchone()
                if cur:
                    hits = cur["hits"] + n["hits"]
                    first = min(cur["first_seen"], n["first_seen"])
                    try:
                        existing_sites = set(json.loads(cur["sites_jsonl"]))
                    except Exception:
                        existing_sites = set()
                    sites = sorted(existing_sites | n["sites"])
                    pre = (cur["pre_consent_hits"] or 0) + n["pre_consent_hits"]
                    c.execute(
                        "UPDATE social_nodes SET hits = ?, first_seen = ?, "
                        "last_seen = ?, sites_jsonl = ?, country_iso = ?, "
                        "asn_org = ?, eu_inside = ?, pre_consent_hits = ? "
                        "WHERE client_mac_hash = ? AND tracker_domain = ?",
                        (hits, first, n["last_seen"], json.dumps(sites),
                         country_iso, asn_org, eu_inside, pre, mac, trk),
                    )
                else:
                    c.execute(
                        "INSERT INTO social_nodes(client_mac_hash, "
                        "tracker_domain, hits, first_seen, last_seen, "
                        "sites_jsonl, country_iso, asn_org, eu_inside, "
                        "pre_consent_hits) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            mac,
                            trk,
                            n["hits"],
                            n["first_seen"],
                            n["last_seen"],
                            json.dumps(sorted(n["sites"])),
                            country_iso,
                            asn_org,
                            eu_inside,
                            n["pre_consent_hits"],
                        ),
                    )
                nodes_touched += 1

            # Derive links : for each (mac, trk) node, the sites form
            # a clique connected by this tracker. Stamp each pair.
            for (mac, trk), n in per_node.items():
                sites = sorted(n["sites"])
                if len(sites) < 2:
                    continue
                for i, a in enumerate(sites):
                    for b in sites[i + 1 :]:
                        key_l = (mac, a, b)
                        l = per_link.setdefault(
                            key_l,
                            {
                                "shared": set(),
                                "ja4_match": False,
                                "last_seen": n["last_seen"],
                            },
                        )
                        l["shared"].add(trk)
                        l["last_seen"] = max(l["last_seen"], n["last_seen"])
                        # JA4 collision : same JA4 seen on both sites
                        ja4_a = per_site_ja4.get((mac, a), set())
                        ja4_b = per_site_ja4.get((mac, b), set())
                        if ja4_a & ja4_b:
                            l["ja4_match"] = True

            for (mac, a, b), l in per_link.items():
                cur = c.execute(
                    "SELECT shared_trackers_jsonl, ja4_match FROM social_links "
                    "WHERE client_mac_hash = ? AND site_a = ? AND site_b = ?",
                    (mac, a, b),
                ).fetchone()
                if cur:
                    try:
                        existing = set(json.loads(cur["shared_trackers_jsonl"]))
                    except Exception:
                        existing = set()
                    shared = sorted(existing | l["shared"])
                    ja4m = 1 if (cur["ja4_match"] or l["ja4_match"]) else 0
                    c.execute(
                        "UPDATE social_links SET shared_trackers_jsonl = ?, "
                        "ja4_match = ?, last_seen = ? "
                        "WHERE client_mac_hash = ? AND site_a = ? AND site_b = ?",
                        (json.dumps(shared), ja4m, l["last_seen"], mac, a, b),
                    )
                else:
                    c.execute(
                        "INSERT INTO social_links(client_mac_hash, site_a, "
                        "site_b, shared_trackers_jsonl, ja4_match, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            mac,
                            a,
                            b,
                            json.dumps(sorted(l["shared"])),
                            1 if l["ja4_match"] else 0,
                            l["last_seen"],
                        ),
                    )
                links_touched += 1
    except Exception as e:  # pragma: no cover
        log.warning("fold_recent failed: %s", e)
    return nodes_touched, links_touched


def fetch_graph(mac_hash: str, since_seconds: int = 86400) -> Dict:
    """Return the per-client graph JSON contract.

    {nodes:[{id,domain,family,hits,sites_count}],
     edges:[{src,dst,reuse_count,shared_trackers[],ja4_match}],
     stats:{total_trackers,total_sites,first_seen,last_seen}}
    """
    since = int(time.time()) - max(since_seconds, 3600)
    out: Dict = {"nodes": [], "edges": [], "stats": {}}
    if not mac_hash:
        return out
    try:
        with _conn() as c:
            # Nodes : trackers active in window
            for r in c.execute(
                "SELECT tracker_domain, hits, first_seen, last_seen, sites_jsonl "
                "FROM social_nodes WHERE client_mac_hash = ? AND last_seen >= ? "
                "ORDER BY hits DESC LIMIT 500",
                (mac_hash, since),
            ).fetchall():
                try:
                    sites = json.loads(r["sites_jsonl"])
                except Exception:
                    sites = []
                out["nodes"].append(
                    {
                        "id": r["tracker_domain"],
                        "domain": r["tracker_domain"],
                        "hits": r["hits"],
                        "sites_count": len(sites),
                        "sites": sites,
                        "first_seen": r["first_seen"],
                        "last_seen": r["last_seen"],
                    }
                )

            # Edges : site-pairs sharing trackers in window
            for r in c.execute(
                "SELECT site_a, site_b, shared_trackers_jsonl, ja4_match, last_seen "
                "FROM social_links WHERE client_mac_hash = ? AND last_seen >= ? "
                "ORDER BY last_seen DESC LIMIT 1000",
                (mac_hash, since),
            ).fetchall():
                try:
                    shared = json.loads(r["shared_trackers_jsonl"])
                except Exception:
                    shared = []
                out["edges"].append(
                    {
                        "src": r["site_a"],
                        "dst": r["site_b"],
                        "reuse_count": len(shared),
                        "shared_trackers": shared,
                        "ja4_match": bool(r["ja4_match"]),
                        "last_seen": r["last_seen"],
                    }
                )

            stats_row = c.execute(
                "SELECT COUNT(DISTINCT tracker_domain) AS total_trackers, "
                "MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
                "FROM social_nodes WHERE client_mac_hash = ? AND last_seen >= ?",
                (mac_hash, since),
            ).fetchone()
            sites_count = len(
                {
                    s
                    for n in out["nodes"]
                    for s in n["sites"]
                }
            )
            out["stats"] = {
                "total_trackers": (stats_row["total_trackers"] or 0) if stats_row else 0,
                "total_sites": sites_count,
                "first_seen": stats_row["first_seen"] if stats_row else None,
                "last_seen": stats_row["last_seen"] if stats_row else None,
            }
    except Exception as e:  # pragma: no cover
        log.warning("fetch_graph failed: %s", e)
    return out


def wipe_mac(mac_hash: str) -> int:
    """Delete every row for a given peer across the 3 tables.

    Used by the RGPD art. 17 endpoint. Returns total rows deleted.
    """
    if not mac_hash:
        return 0
    total = 0
    try:
        with _conn() as c:
            for table in ("social_edges", "social_nodes", "social_links"):
                cur = c.execute(
                    f"DELETE FROM {table} WHERE client_mac_hash = ?", (mac_hash,)
                )
                total += cur.rowcount or 0
    except Exception as e:  # pragma: no cover
        log.warning("wipe_mac failed: %s", e)
    return total


def aggregate(hours: int = 24) -> Dict:
    """Operator dashboard KPI tiles + tracker-family histogram +
    anonymized client table. JWT-gated in the API layer.
    """
    if hours < 1 or hours > 24 * 31:
        hours = 24
    since = int(time.time()) - hours * 3600
    out: Dict = {
        "window_hours": hours,
        "active_clients": 0,
        "total_trackers_seen": 0,
        "extra_eu_trackers": 0,  # Phase C will populate this
        "by_tracker_domain": [],
        "by_client": [],
    }
    try:
        with _conn() as c:
            out["active_clients"] = c.execute(
                "SELECT COUNT(DISTINCT client_mac_hash) FROM social_edges "
                "WHERE ts >= ?",
                (since,),
            ).fetchone()[0]
            out["total_trackers_seen"] = c.execute(
                "SELECT COUNT(DISTINCT tracker_domain) FROM social_edges "
                "WHERE ts >= ?",
                (since,),
            ).fetchone()[0]
            out["by_tracker_domain"] = [
                dict(r)
                for r in c.execute(
                    "SELECT tracker_domain, COUNT(*) AS hits, "
                    "COUNT(DISTINCT client_mac_hash) AS clients "
                    "FROM social_edges WHERE ts >= ? "
                    "GROUP BY tracker_domain ORDER BY hits DESC LIMIT 50",
                    (since,),
                ).fetchall()
            ]
            out["by_client"] = [
                dict(r)
                for r in c.execute(
                    "SELECT client_mac_hash, COUNT(DISTINCT src_site) AS sites, "
                    "COUNT(DISTINCT tracker_domain) AS trackers, "
                    "MAX(ts) AS last_seen "
                    "FROM social_edges WHERE ts >= ? "
                    "GROUP BY client_mac_hash ORDER BY last_seen DESC LIMIT 100",
                    (since,),
                ).fetchall()
            ]
    except Exception as e:  # pragma: no cover
        log.warning("aggregate failed: %s", e)
    return out


def evidence(mac_hash: str, since_seconds: int = 86400) -> Dict:
    """Phase 11.C evidence helper — returns the legal-grade slice
    consumed by the bilingual PDF report.

    Two evidence buckets, both fact-only (no interpretation) :
      - ``pre_consent`` : (tracker_domain, sites, pre_consent_hits,
        country_iso, asn_org).  Trackers that fired BEFORE a consent
        cookie was observed for that peer × site.  Direct RGPD art. 7
        + art. 6.1.a evidence.
      - ``extra_eu``    : (tracker_domain, country_iso, asn_org,
        sites).  Trackers resolving to non-EU/EEA countries.  Note :
        we report the fact, not SCC absence (we can't prove a
        negative).  RGPD art. 44+ evidence.
    """
    since = int(time.time()) - max(since_seconds, 3600)
    out: Dict = {"pre_consent": [], "extra_eu": []}
    if not mac_hash:
        return out
    try:
        with _conn() as c:
            for r in c.execute(
                "SELECT tracker_domain, hits, pre_consent_hits, sites_jsonl, "
                "country_iso, asn_org, last_seen "
                "FROM social_nodes "
                "WHERE client_mac_hash = ? AND last_seen >= ? "
                "AND pre_consent_hits > 0 "
                "ORDER BY pre_consent_hits DESC, hits DESC LIMIT 100",
                (mac_hash, since),
            ).fetchall():
                try:
                    sites = json.loads(r["sites_jsonl"])
                except Exception:
                    sites = []
                out["pre_consent"].append({
                    "tracker_domain": r["tracker_domain"],
                    "hits": r["hits"],
                    "pre_consent_hits": r["pre_consent_hits"],
                    "sites": sites,
                    "country_iso": r["country_iso"],
                    "asn_org": r["asn_org"],
                    "last_seen": r["last_seen"],
                })
            for r in c.execute(
                "SELECT tracker_domain, hits, sites_jsonl, country_iso, "
                "asn_org, last_seen "
                "FROM social_nodes "
                "WHERE client_mac_hash = ? AND last_seen >= ? "
                "AND eu_inside = 0 AND country_iso IS NOT NULL "
                "ORDER BY hits DESC LIMIT 100",
                (mac_hash, since),
            ).fetchall():
                try:
                    sites = json.loads(r["sites_jsonl"])
                except Exception:
                    sites = []
                out["extra_eu"].append({
                    "tracker_domain": r["tracker_domain"],
                    "hits": r["hits"],
                    "sites": sites,
                    "country_iso": r["country_iso"],
                    "asn_org": r["asn_org"],
                    "last_seen": r["last_seen"],
                })
    except Exception as e:  # pragma: no cover
        log.warning("evidence query failed: %s", e)
    return out


def purge_older_than(days: int = 7) -> int:
    """Drop raw edges older than `days`. The aggregate node/link tables
    stay : they represent the durable fold. Operator-side wipe goes
    through wipe_mac().
    """
    cutoff = int(time.time()) - max(days, 1) * 86400
    try:
        with _conn() as c:
            cur = c.execute("DELETE FROM social_edges WHERE ts < ?", (cutoff,))
            return cur.rowcount or 0
    except Exception as e:  # pragma: no cover
        log.warning("purge_older_than failed: %s", e)
        return 0
