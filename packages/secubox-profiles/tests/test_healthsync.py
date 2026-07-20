# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests génération liste sleepable-modules (health monitor)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations


def test_sleepable_module_ids_selects_eager_and_on_demand():
    from api.healthsync import sleepable_module_ids
    from api.manifest import Manifest
    def m(mid, lc, protected=False):
        return Manifest(id=mid, category="infra", runtime="native", exposure="lan",
                        units=(f"{mid}.service",), lifecycle=lc, protected=protected)
    ms = {
        "a": m("a", "on-demand"),
        "b": m("b", "always-on"),
        "c": m("c", "eager"),
        "d": m("d", "manual"),
        "e": m("e", "on-demand", protected=True),  # protected wins -> always-on
    }
    assert sleepable_module_ids(ms) == ["a", "c"]  # sorted; b/d/e excluded


def test_write_sleepable_atomic(tmp_path):
    from api.healthsync import write_sleepable
    from api.manifest import Manifest
    import json
    ms = {"a": Manifest(id="a", category="infra", runtime="native", exposure="lan",
          units=("a.service",), lifecycle="on-demand")}
    out = tmp_path / "sleepable-modules.json"
    assert write_sleepable(manifests=ms, out_path=out) == ["a"]
    assert json.loads(out.read_text()) == ["a"]
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_sleepable_prunes_nothing_but_overwrites(tmp_path):
    from api.healthsync import write_sleepable
    from api.manifest import Manifest
    import json
    out = tmp_path / "sleepable-modules.json"
    out.write_text(json.dumps(["stale"]))
    ms = {"b": Manifest(id="b", category="infra", runtime="native", exposure="lan",
          units=("b.service",), lifecycle="eager")}
    write_sleepable(manifests=ms, out_path=out)
    assert json.loads(out.read_text()) == ["b"]
