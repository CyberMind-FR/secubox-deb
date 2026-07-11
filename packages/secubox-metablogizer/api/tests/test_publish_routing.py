# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from publish.routing import merge_route, apply_route


def test_merge_route_sets_host_backend():
    out = merge_route({"a.gk2.secubox.in": ["192.168.1.200", 8900]},
                      "zem.gk2.secubox.in", "192.168.1.200", 8900)
    assert out["zem.gk2.secubox.in"] == ["192.168.1.200", 8900]
    assert "a.gk2.secubox.in" in out  # additive


def test_merge_route_is_idempotent():
    base = {}
    once = merge_route(base, "z.gk2.secubox.in", "192.168.1.200", 8900)
    twice = merge_route(once, "z.gk2.secubox.in", "192.168.1.200", 8900)
    assert once == twice


def test_apply_route_calls_vhost_then_waf():
    calls = []
    def runner(verb, *args):
        calls.append((verb, args))
        return {"ok": True, "detail": "x"}
    res = apply_route("zem.gk2.secubox.in", 8900, runner=runner)
    assert calls == [("vhost-add", ("zem.gk2.secubox.in",)),
                     ("waf-route", ("zem.gk2.secubox.in", "8900"))]
    assert res["route_ok"] is True


def test_apply_route_reports_failure():
    def runner(verb, *args):
        return {"ok": verb == "vhost-add", "detail": "boom" if verb == "waf-route" else "ok"}
    res = apply_route("zem.gk2.secubox.in", 8900, runner=runner)
    assert res["route_ok"] is False
