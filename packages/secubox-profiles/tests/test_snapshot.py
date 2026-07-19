# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.diff import START, STOP, Change
from api.manifest import Manifest
from api.observe import Actual
from api.snapshot import capture, read


def _m(mid, portal=None):
    return Manifest(id=mid, category="infra", runtime="lxc", exposure="lan",
                    units=(f"secubox-{mid}.service",), lxc=mid, portal_domain=portal)


def test_capture_records_prestate_and_portal_value(tmp_path):
    manifests = {"lyrion": _m("lyrion", portal="lyrion.gk2.secubox.in")}
    actuals = {"lyrion": Actual(enabled=True, active=True, lxc_running=True, portal_routed=True)}
    plan = [Change("lyrion", STOP, "", 50)]
    snap = capture(plan, manifests, actuals, now="2026-07-19T10:00:00Z",
                   routes={"lyrion.gk2.secubox.in": ["127.0.0.1", 9000]}, root=tmp_path)
    assert snap["modules"]["lyrion"]["on"] is True
    assert snap["modules"]["lyrion"]["route"] == ["127.0.0.1", 9000]
    assert (tmp_path / "R1.json").exists()
    assert read("R1", root=tmp_path)["modules"]["lyrion"]["on"] is True


def test_rotation_shifts_r1_to_r2(tmp_path):
    manifests = {"x": _m("x")}
    actuals = {"x": Actual(lxc_running=True)}
    plan = [Change("x", STOP, "", 50)]
    capture(plan, manifests, actuals, now="t1", routes={}, root=tmp_path)
    capture(plan, manifests, actuals, now="t2", routes={}, root=tmp_path)
    assert read("R1", root=tmp_path)["ts"] == "t2"
    assert read("R2", root=tmp_path)["ts"] == "t1"


def test_capture_only_planned_modules(tmp_path):
    manifests = {"x": _m("x"), "y": _m("y")}
    actuals = {"x": Actual(lxc_running=True), "y": Actual(lxc_running=True)}
    plan = [Change("x", STOP, "", 50)]  # only x
    snap = capture(plan, manifests, actuals, now="t", routes={}, root=tmp_path)
    assert set(snap["modules"]) == {"x"}
