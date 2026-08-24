# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.models import Service


def test_service_defaults():
    s = Service(id="waf", name="WAF", category="wall",
                urls={"path": "/waf/"}, routing={}, health={}, auth={})
    assert s.health.state == "unknown"
    assert s.health.latency_ms is None
    assert s.routing.mode == "unknown"
    assert s.cardlet is None
    assert s.capabilities == []
    assert s.urls.path == "/waf/"
