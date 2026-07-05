# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — WAN presence collector (Project B, #820, Task 3).

`collect_wan(store, geo_enrich, ...)` turns sbxwaf's threat-log
(`/var/log/secubox/waf-threats.log`, JSONL — one object per line, see
`packages/secubox-toolbox-ng/cmd/sbxwaf/threatlog.go`'s `logEntry`:
`{timestamp, client_ip, host, method, path, category, severity, rule_id,
action, user_agent}`) into `wan:<ip>` rows in a `PresenceStore`.

Bounded tail-read: only the last `max_bytes` of the log are ever read off
disk (mirrors `common/secubox_core/media_catch.py`'s `_tail_lines` — a
seek-from-end, then drop the (possibly partial) first line of the read),
further capped to the last `max_lines` decoded lines. Never loads the whole
file — the threat-log can grow large on a busy board.

`classify_ua(ua)` ports sbxwaf's `classifyUA` keyword logic
(`packages/secubox-toolbox-ng/cmd/sbxwaf/visitstats.go`) — the client-type
half only (the Go function also derives an OS bucket; that OS detection is
kept here ONLY as an internal helper to resolve the "mobile OS UA without a
browser marker" -> `mobile-app` branch, matching the Go source's order:
crawler markers first (checked before bot/browser because crawler UAs often
also carry "Mozilla"), then bot markers, then the mobile-app heuristic,
then a bare "mozilla" substring -> browser, else "other").

Dedup choice: within a single `collect_wan()` call, ONE presence row is
upserted PER DISTINCT `client_ip` — not once per log line. When a line
repeats an IP, the LAST occurrence in tail order wins for that row's
host/UA/category/timestamp (later log lines are more recent sightings).
This means `PresenceStore.hits` increments by exactly one per collect
cycle per IP (not per threat-log hit) — `hits` therefore tracks "how many
collect cycles this IP was seen in", consistent with how the other planes'
collectors are expected to call `upsert()` once per identity per cycle.
Per-line hit volume (if ever needed) belongs in `extra`/a future
aggregate, not in `hits`.

Fail-safe throughout: a missing/unreadable log, a malformed JSON line, a
line missing `client_ip`, or a raising `geo_enrich` all degrade quietly
(skip the line / fall back to an "unknown" origin) — `collect_wan` itself
NEVER raises, returning 0 when nothing could be collected.

Pure stdlib + `api.presence.geo`/`api.presence.store`. No I/O at import
time — only `collect_wan()` touches the filesystem.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime

from . import geo as _geo
from .store import pid

DEFAULT_THREAT_LOG = "/var/log/secubox/waf-threats.log"
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_LINES = 5000

# UA substrings -> "crawler" (mirrors classifyUA's first switch: bot/spider/
# slurp/crawl all map to the Go function's "crawler" clientType).
_CRAWLER_MARKERS = ("bot", "spider", "slurp", "crawl")

# UA substrings -> "bot" (scripted / non-browser HTTP clients).
_BOT_MARKERS = (
    "curl", "wget", "python", "go-http", "okhttp", "java/", "libwww", "scanner",
)

# Markers used only to resolve the mobile-app heuristic below.
_ANDROID_MARKER = "android"
_IOS_MARKERS = ("iphone", "ipad", "ios ")
_MOBILE_BROWSER_MARKERS = ("mobile safari", "version/")


def classify_ua(ua: str) -> str:
    """Classify a raw User-Agent into `bot`/`crawler`/`mobile-app`/`browser`/`other`.

    Ports `classifyUA`'s client-type branch (sbxwaf `visitstats.go`) keyword
    for keyword, same branch order. Never raises — a `None`/empty/non-string
    UA yields `"other"`.
    """
    if not ua or not isinstance(ua, str):
        return "other"
    low = ua.lower()
    if not low:
        return "other"

    if any(marker in low for marker in _CRAWLER_MARKERS):
        return "crawler"
    if any(marker in low for marker in _BOT_MARKERS):
        return "bot"

    is_mobile_os = _ANDROID_MARKER in low or any(m in low for m in _IOS_MARKERS)
    if is_mobile_os and not any(m in low for m in _MOBILE_BROWSER_MARKERS):
        return "mobile-app"

    if "mozilla" in low:
        return "browser"
    return "other"


def _tail_lines(path: str, max_bytes: int, max_lines: int) -> list[str]:
    """Return up to the last `max_lines` decoded lines, best-effort.

    Only the tail `max_bytes` of the file are ever read off disk (mirrors
    `common/secubox_core/media_catch.py`'s `_tail_lines`). If the seek lands
    mid-line, the (possibly partial) first line of the read is dropped.
    Fail-safe: a missing/unreadable file returns `[]`, never raises.
    """
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size > max_bytes:
                f.seek(size - max_bytes)
                raw = f.read()
                parts = raw.splitlines()
                parts = parts[1:]
            else:
                f.seek(0)
                raw = f.read()
                parts = raw.splitlines()
    except OSError:
        return []

    if len(parts) > max_lines:
        parts = parts[-max_lines:]

    out: list[str] = []
    for b in parts:
        if not b:
            continue
        try:
            out.append(b.decode("utf-8"))
        except UnicodeDecodeError:
            continue
    return out


def _parse_ts(ts) -> int:
    """Best-effort RFC 3339 timestamp -> epoch seconds. Falls back to now()."""
    if isinstance(ts, str) and ts:
        try:
            return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
        except ValueError:
            pass
    return int(time.time())


def collect_wan(
    store,
    geo_enrich=None,
    *,
    threat_log: str = DEFAULT_THREAT_LOG,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
) -> int:
    """Collect WAN presences from the sbxwaf threat-log into `store`.

    Returns the number of distinct `client_ip`s upserted. Fail-safe: a
    missing/unreadable log, malformed lines, or a raising `geo_enrich` never
    raise out of this function — worst case it returns 0.
    """
    enrich = geo_enrich if geo_enrich is not None else _geo.enrich_origin

    lines = _tail_lines(threat_log, max_bytes, max_lines)
    if not lines:
        return 0

    # Dedup per distinct client_ip — last occurrence in tail order wins the
    # row's host/UA/category/timestamp (see module docstring "Dedup choice").
    by_ip: dict = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        ip = rec.get("client_ip")
        if not ip or not isinstance(ip, str):
            continue
        by_ip[ip] = rec

    for ip, rec in by_ip.items():
        ua = rec.get("user_agent") or ""
        client_type = classify_ua(ua)

        try:
            origin = enrich(ip, "wan")
        except Exception:
            origin = {"geo_cc": None, "geo_asn": None, "geo_org": None, "provenance": "unknown"}
        if not isinstance(origin, dict):
            origin = {"geo_cc": None, "geo_asn": None, "geo_org": None, "provenance": "unknown"}

        last_seen = _parse_ts(rec.get("timestamp"))
        extra = json.dumps({
            "host": rec.get("host"),
            "ua": ua[:200],
            "category": rec.get("category"),
        })

        try:
            store.upsert({
                "id": pid("wan", ip),
                "plane": "wan",
                "identity": ip,
                "client_type": client_type,
                "last_seen": last_seen,
                "geo_cc": origin.get("geo_cc"),
                "geo_asn": origin.get("geo_asn"),
                "geo_org": origin.get("geo_org"),
                "provenance": origin.get("provenance"),
                "extra": extra,
            })
        except Exception:
            # Fail-safe: a single bad upsert must not abort the collect.
            continue

    return len(by_ip)
