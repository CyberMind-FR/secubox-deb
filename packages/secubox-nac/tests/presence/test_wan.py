# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `presence.wan.collect_wan`/`classify_ua`
(Project B, Task 3, #820).
"""

import json

BOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
MOBILE_APP_UA = "MyCoolApp/3.2 (Linux; Android 13; SM-G991B)"


def _line(ip, ua, host="example.com", category="scan", ts="2026-07-04T12:00:00Z"):
    return json.dumps({
        "timestamp": ts,
        "client_ip": ip,
        "host": host,
        "method": "GET",
        "path": "/",
        "category": category,
        "severity": "medium",
        "rule_id": "R1",
        "action": "block",
        "user_agent": ua,
    })


def test_classify_ua():
    from api.presence.wan import classify_ua

    assert classify_ua(BOT_UA) == "crawler"
    assert classify_ua(MOBILE_APP_UA) == "mobile-app"
    assert classify_ua(BROWSER_UA) == "browser"
    assert classify_ua("") == "other"
    assert classify_ua(None) == "other"


def _fake_geo_enrich(ip, plane):
    if ip == "1.1.1.1":
        return {"geo_cc": "US", "geo_asn": "AS13335", "geo_org": "Cloudflare", "provenance": "geo"}
    return {"geo_cc": None, "geo_asn": None, "geo_org": None, "provenance": "private"}


def test_collect_wan(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.wan import collect_wan

    log = tmp_path / "waf-threats.log"
    log.write_text(
        _line("1.1.1.1", BOT_UA) + "\n" +
        _line("10.0.0.5", BROWSER_UA) + "\n"
    )

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_wan(store, _fake_geo_enrich, threat_log=str(log))

    assert n == 2
    rows = store.list(plane="wan")
    assert len(rows) == 2

    by_identity = {r["identity"]: r for r in rows}
    bot_row = by_identity["1.1.1.1"]
    assert bot_row["client_type"] == "crawler"
    assert bot_row["geo_cc"] == "US"
    assert bot_row["geo_asn"] == "AS13335"
    assert bot_row["provenance"] == "geo"
    # #820 whole-branch fix M3: first_seen must be populated on insert.
    assert bot_row["first_seen"] is not None
    extra = json.loads(bot_row["extra"])
    assert extra["host"] == "example.com"
    assert extra["category"] == "scan"

    browser_row = by_identity["10.0.0.5"]
    assert browser_row["client_type"] == "browser"
    assert browser_row["provenance"] == "private"
    assert not browser_row["geo_cc"]


def test_collect_wan_first_seen_set_once(tmp_path):
    """#820 whole-branch fix M3: `first_seen` is populated on the initial
    upsert and must NOT move forward on a later re-sighting of the same
    IP (the store's set-once COALESCE semantics)."""
    from api.presence.store import PresenceStore
    from api.presence.wan import collect_wan

    log = tmp_path / "waf-threats.log"
    log.write_text(_line("1.1.1.1", BOT_UA, ts="2026-07-04T12:00:00Z"))

    store = PresenceStore(str(tmp_path / "devices.db"))
    collect_wan(store, _fake_geo_enrich, threat_log=str(log))
    row1 = store.get("wan:1.1.1.1")
    assert row1["first_seen"] is not None
    first_seen = row1["first_seen"]

    log.write_text(_line("1.1.1.1", BOT_UA, ts="2026-07-04T13:00:00Z"))
    collect_wan(store, _fake_geo_enrich, threat_log=str(log))
    row2 = store.get("wan:1.1.1.1")
    assert row2["first_seen"] == first_seen
    assert row2["last_seen"] > first_seen


def test_collect_wan_missing_log(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.wan import collect_wan

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_wan(store, _fake_geo_enrich, threat_log=str(tmp_path / "does-not-exist.log"))

    assert n == 0
    assert store.count() == 0


def test_collect_wan_bad_lines(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.wan import collect_wan

    log = tmp_path / "waf-threats.log"
    log.write_text(
        _line("2.2.2.2", BROWSER_UA) + "\n" +
        "not valid json at all {{{\n" +
        "\n" +
        json.dumps({"no_client_ip_field": True}) + "\n" +
        _line("3.3.3.3", BOT_UA) + "\n"
    )

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_wan(store, _fake_geo_enrich, threat_log=str(log))

    assert n == 2
    identities = {r["identity"] for r in store.list(plane="wan")}
    assert identities == {"2.2.2.2", "3.3.3.3"}


def test_bounded_tail(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.wan import collect_wan

    log = tmp_path / "waf-threats.log"
    # Head: a batch of "old" IPs that must be pushed out of the bounded tail.
    old_lines = [_line(f"10.1.0.{i}", BROWSER_UA) for i in range(1, 50)]
    tail_lines = [_line("9.9.9.9", BOT_UA), _line("8.8.8.8", BROWSER_UA)]
    content = "\n".join(old_lines + tail_lines) + "\n"
    log.write_text(content)

    # Small enough to force a mid-file seek that lands inside the old block,
    # keeping only (part of) the tail — including the two tail IPs.
    small_max_bytes = len(("\n".join(tail_lines) + "\n").encode("utf-8")) + 10

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_wan(
        store, _fake_geo_enrich, threat_log=str(log), max_bytes=small_max_bytes,
    )

    identities = {r["identity"] for r in store.list(plane="wan")}
    # No crash, and the surviving IPs are a subset confined to the tail
    # (the old 10.1.0.x IPs must NOT all be present).
    assert n == len(identities)
    assert n >= 1
    assert "10.1.0.1" not in identities
    assert "9.9.9.9" in identities or "8.8.8.8" in identities
