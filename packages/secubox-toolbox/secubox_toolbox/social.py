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
import re
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

-- Phase 12.A (#515) — host-stable CDN/edge metadata, mac-independent.
-- Phase 12.B (#516) adds antibot_vendor.  Phase 12.C (#518) adds
-- opgrade_vendor + opgrade_category (operator-grade / state-adjacent).
CREATE TABLE IF NOT EXISTS social_host_meta (
    tracker_domain   TEXT PRIMARY KEY,
    cdn_vendor       TEXT,
    cache_status     TEXT,
    antibot_vendor   TEXT,
    opgrade_vendor   TEXT,
    opgrade_category TEXT,
    last_seen        INTEGER NOT NULL
);

-- Phase 12.B (#516) — per-client "challenged your humanity" log.
CREATE TABLE IF NOT EXISTS social_antibot (
    client_mac_hash TEXT NOT NULL,
    src_site        TEXT NOT NULL,
    antibot_vendor  TEXT NOT NULL,
    hits            INTEGER NOT NULL DEFAULT 0,
    last_seen       INTEGER NOT NULL,
    PRIMARY KEY (client_mac_hash, src_site, antibot_vendor)
);

-- Phase 12.C (#518) — per-client operator-grade / state-adjacent log.
CREATE TABLE IF NOT EXISTS social_opgrade (
    client_mac_hash TEXT NOT NULL,
    src_site        TEXT NOT NULL,
    opgrade_vendor  TEXT NOT NULL,
    category        TEXT NOT NULL,
    hits            INTEGER NOT NULL DEFAULT 0,
    last_seen       INTEGER NOT NULL,
    PRIMARY KEY (client_mac_hash, src_site, opgrade_vendor)
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
    # Phase 12.B (#516) — anti-bot vendor column on the host-meta table
    # (created by 12.A ; additive on a 2.6.3/2.6.4 → upgrade).
    ("social_host_meta", "antibot_vendor", "TEXT"),
    # Phase 12.C (#518) — operator-grade / state-adjacent columns.
    ("social_host_meta", "opgrade_vendor", "TEXT"),
    ("social_host_meta", "opgrade_category", "TEXT"),
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
    # #642 — never record IP-literal "trackers" (no SNI/hostname = the client's
    # own traffic to gk2 service IPs etc.); they're noise the domain views filter.
    if _is_ip(tracker_domain):
        return
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


def _record_host_cdn_sync(domain: str, cdn_vendor: Optional[str],
                          cache_status: Optional[str]) -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO social_host_meta(tracker_domain, cdn_vendor, "
                "cache_status, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(tracker_domain) DO UPDATE SET "
                "cdn_vendor=COALESCE(excluded.cdn_vendor, cdn_vendor), "
                "cache_status=COALESCE(excluded.cache_status, cache_status), "
                "last_seen=excluded.last_seen",
                (domain, cdn_vendor, cache_status, int(time.time())),
            )
    except Exception as e:  # pragma: no cover
        log.warning("record_host_cdn failed: %s", e)


def record_host_cdn(*, domain: str, cdn_vendor: Optional[str] = None,
                    cache_status: Optional[str] = None) -> None:
    """Phase 12.A (#515) — upsert host-stable CDN metadata off-thread.
    Best-effort, host-keyed (mac-independent)."""
    if not domain or not (cdn_vendor or cache_status):
        return
    try:
        _executor.submit(_record_host_cdn_sync, domain, cdn_vendor, cache_status)
    except RuntimeError:
        pass


# ── Phase 12.B (#516) — anti-bot / "prove you're human" recording ──

def _record_host_antibot_sync(domain: str, vendor: str) -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO social_host_meta(tracker_domain, antibot_vendor, "
                "last_seen) VALUES (?, ?, ?) "
                "ON CONFLICT(tracker_domain) DO UPDATE SET "
                "antibot_vendor=excluded.antibot_vendor, "
                "last_seen=excluded.last_seen",
                (domain, vendor, int(time.time())),
            )
    except Exception as e:  # pragma: no cover
        log.warning("record_host_antibot failed: %s", e)


def record_host_antibot(*, domain: str, antibot_vendor: str) -> None:
    """Upsert the host-stable anti-bot vendor fronting `domain`."""
    if not (domain and antibot_vendor):
        return
    try:
        _executor.submit(_record_host_antibot_sync, domain, antibot_vendor)
    except RuntimeError:
        pass


def _record_antibot_challenge_sync(mac_hash: str, src_site: str, vendor: str) -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO social_antibot(client_mac_hash, src_site, "
                "antibot_vendor, hits, last_seen) VALUES (?, ?, ?, 1, ?) "
                "ON CONFLICT(client_mac_hash, src_site, antibot_vendor) DO UPDATE "
                "SET hits = hits + 1, last_seen = excluded.last_seen",
                (mac_hash, src_site, vendor, int(time.time())),
            )
    except Exception as e:  # pragma: no cover
        log.warning("record_antibot_challenge failed: %s", e)


def record_antibot_challenge(*, client_mac_hash: str, src_site: str,
                             antibot_vendor: str) -> None:
    """Record a per-client "this site challenged your humanity" event."""
    if not (client_mac_hash and src_site and antibot_vendor):
        return
    try:
        _executor.submit(_record_antibot_challenge_sync, client_mac_hash,
                         src_site, antibot_vendor)
    except RuntimeError:
        pass


def antibot_for_client(mac_hash: str, since_seconds: int = 86400) -> List[Dict]:
    """Per-client anti-bot challenge list for the graph alert tile."""
    since = int(time.time()) - max(since_seconds, 3600)
    out: List[Dict] = []
    if not mac_hash:
        return out
    try:
        with _conn() as c:
            for r in c.execute(
                "SELECT src_site, antibot_vendor, hits, last_seen "
                "FROM social_antibot WHERE client_mac_hash = ? AND last_seen >= ? "
                "ORDER BY last_seen DESC LIMIT 100",
                (mac_hash, since),
            ).fetchall():
                out.append(dict(r))
    except Exception as e:  # pragma: no cover
        log.warning("antibot_for_client failed: %s", e)
    return out


# ── Phase 12.C (#518) — operator-grade / state-adjacent recording ──

def _record_host_opgrade_sync(domain, vendor, category) -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO social_host_meta(tracker_domain, opgrade_vendor, "
                "opgrade_category, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(tracker_domain) DO UPDATE SET "
                "opgrade_vendor=excluded.opgrade_vendor, "
                "opgrade_category=excluded.opgrade_category, "
                "last_seen=excluded.last_seen",
                (domain, vendor, category, int(time.time())),
            )
    except Exception as e:  # pragma: no cover
        log.warning("record_host_opgrade failed: %s", e)


def record_host_opgrade(*, domain: str, opgrade_vendor: str,
                        opgrade_category: Optional[str] = None) -> None:
    if not (domain and opgrade_vendor):
        return
    try:
        _executor.submit(_record_host_opgrade_sync, domain, opgrade_vendor,
                         opgrade_category)
    except RuntimeError:
        pass


def _record_opgrade_event_sync(mac_hash, src_site, vendor, category) -> None:
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO social_opgrade(client_mac_hash, src_site, "
                "opgrade_vendor, category, hits, last_seen) "
                "VALUES (?, ?, ?, ?, 1, ?) "
                "ON CONFLICT(client_mac_hash, src_site, opgrade_vendor) DO UPDATE "
                "SET hits = hits + 1, category = excluded.category, "
                "last_seen = excluded.last_seen",
                (mac_hash, src_site, vendor, category, int(time.time())),
            )
    except Exception as e:  # pragma: no cover
        log.warning("record_opgrade_event failed: %s", e)


def record_opgrade_event(*, client_mac_hash: str, src_site: str,
                         opgrade_vendor: str, category: str) -> None:
    if not (client_mac_hash and src_site and opgrade_vendor):
        return
    try:
        _executor.submit(_record_opgrade_event_sync, client_mac_hash,
                         src_site, opgrade_vendor, category or "")
    except RuntimeError:
        pass


def opgrade_for_client(mac_hash: str, since_seconds: int = 86400) -> List[Dict]:
    """Per-client operator-grade / state-adjacent list for the alert tile
    + the PDF evidence section."""
    since = int(time.time()) - max(since_seconds, 3600)
    out: List[Dict] = []
    if not mac_hash:
        return out
    try:
        with _conn() as c:
            for r in c.execute(
                "SELECT src_site, opgrade_vendor, category, hits, last_seen "
                "FROM social_opgrade WHERE client_mac_hash = ? AND last_seen >= ? "
                "ORDER BY last_seen DESC LIMIT 100",
                (mac_hash, since),
            ).fetchall():
                out.append(dict(r))
    except Exception as e:  # pragma: no cover
        log.warning("opgrade_for_client failed: %s", e)
    return out


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


# eTLD+1 rollup (#549). Mirror of the addon's _registrable_domain so the
# graph can group trackers under their registrable parent (all
# *.doubleclick.net → doubleclick.net) without a publicsuffix dependency.
_MULTI_LABEL_TLDS = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk",
    "co.jp", "ne.jp", "ac.jp",
    "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.hk", "com.tw", "com.mx",
}


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip(host: str) -> bool:
    """True for an IPv4/IPv6 literal (to keep IPs out of domain views)."""
    h = host or ""
    return bool(_IP_RE.match(h)) or ":" in h


def _registrable_domain(host: str) -> str:
    """Cheap eTLD+1 : www.lemonde.fr → lemonde.fr ; a.b.example.co.uk →
    example.co.uk. Raw IPs and single-label hosts pass through."""
    h = (host or "").lower().strip(".")
    if not h or h.replace(".", "").replace(":", "").isdigit():
        return h
    parts = h.split(".")
    if len(parts) < 2:
        return h
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_LABEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# ── geography helpers (#553) : flag + continent rollup, no IP/ASN ──
def _flag_emoji(iso2: Optional[str]) -> str:
    """ISO-3166 alpha-2 → flag emoji (regional indicator pair). '' if unknown."""
    if not iso2 or len(iso2) != 2 or not iso2.isalpha():
        return ""
    base = 0x1F1E6
    return "".join(chr(base + (ord(ch) - ord("A"))) for ch in iso2.upper())


# Compact ISO-3166 alpha-2 → continent map (covers the countries a French
# civic kiosk realistically surfaces ; unknowns fall back to "Autre").
_CONTINENT = {
    # Europe
    "FR": "Europe", "DE": "Europe", "GB": "Europe", "UK": "Europe", "IE": "Europe",
    "NL": "Europe", "BE": "Europe", "LU": "Europe", "ES": "Europe", "PT": "Europe",
    "IT": "Europe", "CH": "Europe", "AT": "Europe", "SE": "Europe", "NO": "Europe",
    "FI": "Europe", "DK": "Europe", "PL": "Europe", "CZ": "Europe", "RO": "Europe",
    "BG": "Europe", "GR": "Europe", "HU": "Europe", "SK": "Europe", "HR": "Europe",
    "RS": "Europe", "UA": "Europe", "RU": "Europe", "IS": "Europe", "EE": "Europe",
    "LV": "Europe", "LT": "Europe", "SI": "Europe",
    # Americas
    "US": "Amériques", "CA": "Amériques", "MX": "Amériques", "BR": "Amériques",
    "AR": "Amériques", "CL": "Amériques", "CO": "Amériques", "PE": "Amériques",
    # Asia
    "CN": "Asie", "JP": "Asie", "KR": "Asie", "IN": "Asie", "SG": "Asie",
    "HK": "Asie", "TW": "Asie", "TH": "Asie", "ID": "Asie", "VN": "Asie",
    "IL": "Asie", "TR": "Asie", "AE": "Asie", "SA": "Asie",
    # Africa
    "ZA": "Afrique", "EG": "Afrique", "MA": "Afrique", "DZ": "Afrique",
    "TN": "Afrique", "NG": "Afrique", "KE": "Afrique", "SN": "Afrique",
    # Oceania
    "AU": "Océanie", "NZ": "Océanie",
}


def _continent_of(iso2: Optional[str]) -> str:
    if not iso2:
        return "Inconnu"
    return _CONTINENT.get(iso2.upper(), "Autre")


def _tracker_tier(opgrade, antibot, cdn) -> str:
    """Severity tier used for the donut breakdown (highest wins)."""
    if opgrade:
        return "opgrade"
    if antibot:
        return "antibot"
    if cdn:
        return "cdn"
    return "other"


def fetch_graph(mac_hash: str, since_seconds: int = 86400) -> Dict:
    """Return the per-client graph JSON contract.

    {nodes:[{id,domain,family,hits,sites_count}],
     edges:[{src,dst,reuse_count,shared_trackers[],ja4_match}],
     stats:{total_trackers,total_sites,first_seen,last_seen},
     by_domain:[...], targets:[...], history:[...]}   # additive (#549)
    """
    since = int(time.time()) - max(since_seconds, 3600)
    out: Dict = {"nodes": [], "edges": [], "stats": {}}
    if not mac_hash:
        return out
    try:
        with _conn() as c:
            # Nodes : trackers active in window.  Phase 12.A — LEFT JOIN
            # the host-stable CDN metadata so the d3 view + node detail
            # can colour/label by edge-network vendor.
            for r in c.execute(
                "SELECT n.tracker_domain, n.hits, n.first_seen, n.last_seen, "
                "n.sites_jsonl, n.country_iso, m.cdn_vendor, m.cache_status, "
                "m.antibot_vendor, m.opgrade_vendor, m.opgrade_category "
                "FROM social_nodes n "
                "LEFT JOIN social_host_meta m ON m.tracker_domain = n.tracker_domain "
                "WHERE n.client_mac_hash = ? AND n.last_seen >= ? "
                "ORDER BY n.hits DESC LIMIT 500",
                (mac_hash, since),
            ).fetchall():
                try:
                    sites = json.loads(r["sites_jsonl"])
                except Exception:
                    sites = []
                cc = (r["country_iso"] or "").upper() or None
                out["nodes"].append(
                    {
                        "id": r["tracker_domain"],
                        "domain": r["tracker_domain"],
                        "hits": r["hits"],
                        "sites_count": len(sites),
                        "sites": sites,
                        "first_seen": r["first_seen"],
                        "last_seen": r["last_seen"],
                        "country_iso": cc,
                        "country_flag": _flag_emoji(cc),
                        "continent": _continent_of(cc),
                        "tier": _tracker_tier(r["opgrade_vendor"], r["antibot_vendor"],
                                              r["cdn_vendor"]),
                        "cdn_vendor": r["cdn_vendor"],
                        "cache_status": r["cache_status"],
                        "antibot_vendor": r["antibot_vendor"],
                        "opgrade_vendor": r["opgrade_vendor"],
                        "opgrade_category": r["opgrade_category"],
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
            # Phase 12.B — per-client anti-bot challenges for the alert tile.
            antibot = antibot_for_client(mac_hash, since_seconds=since_seconds)
            out["antibot"] = antibot
            # Phase 12.C — operator-grade / state-adjacent surfaces.
            opgrade = opgrade_for_client(mac_hash, since_seconds=since_seconds)
            out["opgrade"] = opgrade
            # ── #549 additive aggregations (read-time, no schema change) ──
            # (a) by_domain : roll trackers up under registrable parent.
            _dom: Dict[str, dict] = {}
            for n in out["nodes"]:
                parent = _registrable_domain(n["domain"])
                d = _dom.setdefault(parent, {
                    "domain": parent, "tracker_count": 0, "hits": 0,
                    "_trackers": set(), "_sites": set(), "_vendors": set(),
                    "last_seen": 0,
                })
                d["_trackers"].add(n["domain"])
                d["hits"] += n["hits"] or 0
                d["_sites"].update(n["sites"])
                d["last_seen"] = max(d["last_seen"], n["last_seen"] or 0)
                for v in (n.get("cdn_vendor"), n.get("antibot_vendor"),
                          n.get("opgrade_vendor")):
                    if v:
                        d["_vendors"].add(v)
            by_domain = []
            for d in _dom.values():
                by_domain.append({
                    "domain": d["domain"],
                    "tracker_count": len(d["_trackers"]),
                    "trackers": sorted(d["_trackers"])[:30],
                    "hits": d["hits"],
                    "sites_count": len(d["_sites"]),
                    "sites": sorted(d["_sites"])[:20],
                    "vendors": sorted(d["_vendors"]),
                    "last_seen": d["last_seen"],
                })
            by_domain.sort(key=lambda x: (-x["hits"], -x["tracker_count"]))
            out["by_domain"] = by_domain

            # (b) targets : invert sites→trackers (who watches each page).
            _tgt: Dict[str, dict] = {}
            for n in out["nodes"]:
                for s in n["sites"]:
                    t = _tgt.setdefault(s, {
                        "site": s, "hits": 0,
                        "_trackers": set(), "_domains": set(),
                    })
                    t["_trackers"].add(n["domain"])
                    t["_domains"].add(_registrable_domain(n["domain"]))
                    t["hits"] += n["hits"] or 0
            targets = []
            for t in _tgt.values():
                targets.append({
                    "site": t["site"],
                    "tracker_count": len(t["_trackers"]),
                    "trackers": sorted(t["_trackers"])[:30],
                    "parent_domains": sorted(t["_domains"]),
                    "hits": t["hits"],
                })
            targets.sort(key=lambda x: (-x["tracker_count"], -x["hits"]))
            out["targets"] = targets

            # (c) history : per-(UTC)day timeline from the raw edge log.
            history = []
            for r in c.execute(
                "SELECT (ts/86400) AS day_epoch, COUNT(*) AS hits, "
                "COUNT(DISTINCT tracker_domain) AS trackers, "
                "COUNT(DISTINCT src_site) AS sites "
                "FROM social_edges WHERE client_mac_hash = ? AND ts >= ? "
                "GROUP BY day_epoch ORDER BY day_epoch",
                (mac_hash, since),
            ).fetchall():
                history.append({
                    "day": int(r["day_epoch"]) * 86400,
                    "hits": r["hits"],
                    "trackers": r["trackers"],
                    "sites": r["sites"],
                })
            out["history"] = history

            # (d) #553 geography + tier rollups for the donut-bubble view.
            _TIERS = ("opgrade", "antibot", "cdn", "other")
            tier_tot = {t: 0 for t in _TIERS}
            _ctry: Dict[str, dict] = {}
            _cont: Dict[str, dict] = {}
            for n in out["nodes"]:
                tier = n["tier"]; hits = n["hits"] or 0
                tier_tot[tier] += hits
                cc = n["country_iso"] or "??"
                ct = _ctry.setdefault(cc, {
                    "country_iso": None if cc == "??" else cc,
                    "flag": n["country_flag"], "continent": n["continent"],
                    "tracker_count": 0, "hits": 0,
                    "tiers": {t: 0 for t in _TIERS}, "_sites": set(),
                })
                ct["tracker_count"] += 1; ct["hits"] += hits
                ct["tiers"][tier] += hits; ct["_sites"].update(n["sites"])
                co = _cont.setdefault(n["continent"], {
                    "continent": n["continent"], "country_count_set": set(),
                    "tracker_count": 0, "hits": 0, "tiers": {t: 0 for t in _TIERS},
                })
                co["country_count_set"].add(cc)
                co["tracker_count"] += 1; co["hits"] += hits
                co["tiers"][tier] += hits
            by_country = sorted(
                ({"country_iso": v["country_iso"], "flag": v["flag"],
                  "continent": v["continent"], "tracker_count": v["tracker_count"],
                  "hits": v["hits"], "sites_count": len(v["_sites"]),
                  "tiers": v["tiers"]} for v in _ctry.values()),
                key=lambda x: -x["hits"])
            by_continent = sorted(
                ({"continent": v["continent"],
                  "country_count": len(v["country_count_set"]),
                  "tracker_count": v["tracker_count"], "hits": v["hits"],
                  "tiers": v["tiers"]} for v in _cont.values()),
                key=lambda x: -x["hits"])
            out["by_country"] = by_country
            out["by_continent"] = by_continent
            out["by_tier"] = tier_tot

            out["stats"] = {
                "total_trackers": (stats_row["total_trackers"] or 0) if stats_row else 0,
                "total_sites": sites_count,
                "total_domains": len(by_domain),
                "total_countries": len([c for c in by_country if c["country_iso"]]),
                "total_continents": len([c for c in by_continent if c["continent"] not in ("Inconnu",)]),
                "first_seen": stats_row["first_seen"] if stats_row else None,
                "last_seen": stats_row["last_seen"] if stats_row else None,
                "antibot_sites": len({a["src_site"] for a in antibot}),
                "antibot_vendors": sorted({a["antibot_vendor"] for a in antibot}),
                "opgrade_sites": len({o["src_site"] for o in opgrade}),
                "opgrade_vendors": sorted({o["opgrade_vendor"] for o in opgrade}),
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
            for table in ("social_edges", "social_nodes", "social_links",
                          "social_antibot", "social_opgrade"):
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
        "by_cdn": [],  # Phase 12.A
        "by_antibot": [],  # Phase 12.B
        "antibot_clients": 0,  # Phase 12.B
        "by_opgrade": [],  # Phase 12.C
        "opgrade_clients": 0,  # Phase 12.C
    }
    try:
        with _conn() as c:
            out["active_clients"] = c.execute(
                "SELECT COUNT(DISTINCT client_mac_hash) FROM social_edges "
                "WHERE ts >= ?",
                (since,),
            ).fetchone()[0]
            # #593 — fold to registrable domain + drop IP literals (the raw
            # column otherwise surfaces IPs, incl. the cabine's own WAN IP,
            # as the top "tracker"). Over-fetch, fold in Python, top 50.
            _byd: dict = {}
            for r in c.execute(
                "SELECT tracker_domain, COUNT(*) AS hits, "
                "COUNT(DISTINCT client_mac_hash) AS clients "
                "FROM social_edges WHERE ts >= ? "
                "GROUP BY tracker_domain ORDER BY hits DESC LIMIT 400",
                (since,),
            ).fetchall():
                td = r["tracker_domain"] or ""
                if not td or _is_ip(td):
                    continue
                dom = _registrable_domain(td)
                e = _byd.setdefault(dom, {"tracker_domain": dom, "hits": 0,
                                         "clients": 0})
                e["hits"] += r["hits"]
                e["clients"] = max(e["clients"], r["clients"])
            out["by_tracker_domain"] = sorted(
                _byd.values(), key=lambda x: -x["hits"])[:50]
            # #642 — KPI = distinct non-IP registrable trackers (matches the
            # table's universe; was a raw COUNT that surfaced IP literals).
            out["total_trackers_seen"] = len(_byd)
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
            # Phase 12.A — CDN/edge-network breakdown over the trackers
            # seen in the window (host-stable metadata, mac-independent).
            out["by_cdn"] = [
                dict(r)
                for r in c.execute(
                    "SELECT m.cdn_vendor, COUNT(DISTINCT m.tracker_domain) AS hosts "
                    "FROM social_host_meta m "
                    "WHERE m.cdn_vendor IS NOT NULL AND m.last_seen >= ? "
                    "AND m.tracker_domain IN ("
                    "  SELECT DISTINCT tracker_domain FROM social_edges WHERE ts >= ?) "
                    "GROUP BY m.cdn_vendor ORDER BY hosts DESC LIMIT 25",
                    (since, since),
                ).fetchall()
            ]
            # Phase 12.B — anti-bot / "prove you're human" breakdown.
            out["by_antibot"] = [
                dict(r)
                for r in c.execute(
                    "SELECT antibot_vendor, "
                    "COUNT(DISTINCT src_site) AS sites, "
                    "COUNT(DISTINCT client_mac_hash) AS clients, "
                    "SUM(hits) AS challenges "
                    "FROM social_antibot WHERE last_seen >= ? "
                    "GROUP BY antibot_vendor ORDER BY challenges DESC LIMIT 25",
                    (since,),
                ).fetchall()
            ]
            out["antibot_clients"] = c.execute(
                "SELECT COUNT(DISTINCT client_mac_hash) FROM social_antibot "
                "WHERE last_seen >= ?",
                (since,),
            ).fetchone()[0]
            # Phase 12.C — operator-grade / state-adjacent breakdown.
            out["by_opgrade"] = [
                dict(r)
                for r in c.execute(
                    "SELECT opgrade_vendor, category, "
                    "COUNT(DISTINCT src_site) AS sites, "
                    "COUNT(DISTINCT client_mac_hash) AS clients, "
                    "SUM(hits) AS events "
                    "FROM social_opgrade WHERE last_seen >= ? "
                    "GROUP BY opgrade_vendor ORDER BY events DESC LIMIT 25",
                    (since,),
                ).fetchall()
            ]
            out["opgrade_clients"] = c.execute(
                "SELECT COUNT(DISTINCT client_mac_hash) FROM social_opgrade "
                "WHERE last_seen >= ?",
                (since,),
            ).fetchone()[0]
    except Exception as e:  # pragma: no cover
        log.warning("aggregate failed: %s", e)
    return out


def _xsite_detail_from_conn(conn, since: int, top_n: int) -> list:
    """Pure cross-site tracker detail over a social_edges connection.

    A (tracker_domain, cookie_id_hash) pair is cross-site when its cookie id is
    observed on >= 2 DISTINCT valid src_sites (src_site not in '', 'null') within
    the window (ts >= since). For every such pair, aggregate per REGISTRABLE
    tracker domain (IP literals dropped). Ranked by client_count, then
    site_count, then domain; capped to top_n.
    """
    rows = conn.execute(
        "SELECT ts, client_mac_hash, src_site, tracker_domain, "
        "       cookie_id_hash, consent_state "
        "FROM social_edges "
        "WHERE ts >= ? "
        "  AND cookie_id_hash IS NOT NULL AND cookie_id_hash <> '' "
        "  AND src_site NOT IN ('', 'null') "
        "LIMIT 50000",
        (since,),
    ).fetchall()

    # Pass 1: which (raw tracker_domain, cookie_id_hash) pairs are cross-site.
    sites_per_pair: dict = {}
    for r in rows:
        key = (r["tracker_domain"], r["cookie_id_hash"])
        sites_per_pair.setdefault(key, set()).add(r["src_site"])
    xsite_pairs = {k for k, s in sites_per_pair.items() if len(s) >= 2}
    if not xsite_pairs:
        return []

    # Pass 2: aggregate the cross-site rows per registrable tracker domain.
    agg: dict = {}
    for r in rows:
        if (r["tracker_domain"], r["cookie_id_hash"]) not in xsite_pairs:
            continue
        dom = _registrable_domain(r["tracker_domain"])
        if not dom or _is_ip(dom):
            continue
        e = agg.setdefault(dom, {
            "tracker_domain": dom, "sites": set(), "clients": set(),
            "cookies": set(), "pre_consent_hits": 0, "last_seen": 0,
        })
        e["sites"].add(r["src_site"])
        e["clients"].add(r["client_mac_hash"])
        e["cookies"].add(r["cookie_id_hash"])
        if r["consent_state"] == "pre_consent":
            e["pre_consent_hits"] += 1
        if r["ts"] > e["last_seen"]:
            e["last_seen"] = r["ts"]

    out = [{
        "tracker_domain": e["tracker_domain"],
        "sites": sorted(e["sites"]),
        "site_count": len(e["sites"]),
        "client_count": len(e["clients"]),
        "cookie_count": len(e["cookies"]),
        "pre_consent_hits": e["pre_consent_hits"],
        "last_seen": e["last_seen"],
    } for e in agg.values()]
    out.sort(key=lambda t: (-t["client_count"], -t["site_count"],
                            t["tracker_domain"]))
    return out[:max(0, top_n)]


def cookie_xsite_detail(hours: int = 24, top_n: int = 50) -> Dict:
    """Operator view of cross-site tracker cookies over social_edges.

    Mirrors aggregate()'s envelope shape. JWT-gated in the API layer.
    """
    if hours < 1 or hours > 24 * 31:
        hours = 24
    if top_n < 1 or top_n > 500:
        top_n = 50
    now = int(time.time())
    since = now - hours * 3600
    out: Dict = {"window_hours": hours, "generated_at": now, "trackers": []}
    try:
        with _conn() as c:
            out["trackers"] = _xsite_detail_from_conn(c, since, top_n)
    except sqlite3.Error as e:
        log.warning("cookie_xsite_detail: DB error, returning empty: %s", e)
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
