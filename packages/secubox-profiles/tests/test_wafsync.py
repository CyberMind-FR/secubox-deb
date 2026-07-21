# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests génération liste on-demand-vhosts (sbxwaf wake trigger)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations


def test_ondemand_vhosts_selects_sleepable_portals():
    from api.wafsync import ondemand_vhosts
    from api.manifest import Manifest
    def m(mid, lc, dom):
        return Manifest(id=mid, category="infra", runtime="native", exposure="public",
                        units=(f"{mid}.service",), portal_domain=dom, lifecycle=lc)
    ms = {"a": m("a","on-demand","a.gk2"), "b": m("b","always-on","b.gk2"),
          "c": m("c","eager","c.gk2"), "d": m("d","on-demand",None)}
    assert ondemand_vhosts(ms) == ["a.gk2", "c.gk2"]   # sorted; b=always-on, d=no portal

def test_write_ondemand_atomic(tmp_path):
    from api.wafsync import write_ondemand
    from api.manifest import Manifest
    import json
    ms = {"a": Manifest(id="a", category="infra", runtime="native", exposure="public",
          units=("a.service",), portal_domain="a.gk2", lifecycle="on-demand")}
    out = tmp_path / "on-demand-vhosts.json"
    assert write_ondemand(manifests=ms, out_path=out) == ["a.gk2"]
    assert json.loads(out.read_text()) == ["a.gk2"]
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_ondemand_output_is_world_readable(tmp_path):
    """sbxwaf runs as a different unprivileged user (secubox-waf) than
    secubox-profiles (secubox). tempfile.mkstemp() defaults to 0600
    owner-only — without an explicit chmod, sbxwaf can never read this
    PUBLIC vhost list and the wake trigger is silently inert (#896 review,
    Fix 1)."""
    import stat

    from api.wafsync import write_ondemand
    from api.manifest import Manifest
    ms = {"a": Manifest(id="a", category="infra", runtime="native", exposure="public",
          units=("a.service",), portal_domain="a.gk2", lifecycle="on-demand")}
    out = tmp_path / "on-demand-vhosts.json"
    write_ondemand(manifests=ms, out_path=out)
    mode = stat.S_IMODE(out.stat().st_mode)
    assert oct(mode) == "0o644"
