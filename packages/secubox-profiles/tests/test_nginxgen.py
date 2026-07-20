# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests génération snippets nginx @waker
CyberMind — https://cybermind.fr
"""
from __future__ import annotations


def test_render_only_for_sleepable_portal(tmp_path):
    from api.nginxgen import render_snippet
    from api.manifest import Manifest
    on_demand = Manifest(id="d", category="infra", runtime="native", exposure="public",
                         units=("d.service",), portal_domain="d.gk2", lifecycle="on-demand")
    always = Manifest(id="a", category="infra", runtime="native", exposure="public",
                      units=("a.service",), portal_domain="a.gk2", lifecycle="always-on")
    noportal = Manifest(id="n", category="infra", runtime="native", exposure="lan",
                        units=("n.service",), lifecycle="on-demand")
    assert render_snippet(on_demand) is not None and "@waker" in render_snippet(on_demand)
    assert render_snippet(always) is None
    assert render_snippet(noportal) is None


def test_sync_writes_and_prunes(tmp_path):
    from api.nginxgen import sync_snippets
    from api.manifest import Manifest
    out = tmp_path / "snips"; out.mkdir()
    (out / "stale.gk2.waker.conf").write_text("old")   # should be pruned
    manifests = {"d": Manifest(id="d", category="infra", runtime="native", exposure="public",
                 units=("d.service",), portal_domain="d.gk2", lifecycle="on-demand")}
    written = sync_snippets(manifests=manifests, out_dir=out)
    assert written == ["d.gk2"]
    assert (out / "d.gk2.waker.conf").exists()
    assert not (out / "stale.gk2.waker.conf").exists()
