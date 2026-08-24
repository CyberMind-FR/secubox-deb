# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — normalize_services (api.registry)."""
from api.registry import normalize_services, HEALTH_MAP

MENU = {"categories": [{"items": [
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "🔥", "path": "/waf/",
     "description": "", "installed": True, "active": True,
     "domain": "waf.gk2.secubox.in"},
    {"id": "radio", "name": "Radio", "category": "mind", "icon": "🎧", "path": "/radio/",
     "installed": True, "active": True, "same_origin": True},
]}]}
HEALTH = {"waf": {"status": "ok", "msg": "Running"},
          "radio": {"status": "error", "msg": "Failed"}}
EXPO = {"waf.gk2.secubox.in": {"reach": "wan", "latency_ms": 12.5}}


def test_health_mapping_and_join():
    svcs = {s.id: s for s in normalize_services(MENU, HEALTH, EXPO)}
    assert svcs["waf"].health.state == "online"
    assert svcs["waf"].urls.lan == "https://waf.gk2.secubox.in"
    assert svcs["waf"].urls.wan == "https://waf.gk2.secubox.in"   # reach=wan
    assert svcs["waf"].routing.mode == "wan"
    assert svcs["waf"].health.latency_ms == 12.5
    # radio: offline, same-origin (pas d'URL), latence absente
    assert svcs["radio"].health.state == "offline"
    assert svcs["radio"].urls.lan is None
    assert svcs["radio"].urls.wan is None
    assert svcs["radio"].health.latency_ms is None
    assert svcs["radio"].routing.available is False   # offline


def test_unknown_when_health_absent():
    svcs = {s.id: s for s in normalize_services(MENU, {}, None)}
    assert svcs["waf"].health.state == "unknown"
    assert svcs["waf"].urls.wan is None               # pas d'expo ⇒ pas de wan
