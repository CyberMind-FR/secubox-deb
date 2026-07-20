# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests secubox-wakectl (wake un module via l'actionneur)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations


def test_wake_refuses_manual_and_unknown(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="manual"\n')
    r = wake("demo", root=root, run=lambda a: (0, ""),
             observe=lambda m: Actual(enabled=False, active=False), now="t")
    assert r["status"] == "refused"
    r2 = wake("ghost", root=root, run=lambda a: (0, ""),
              observe=lambda m: Actual(enabled=False, active=False), now="t")
    assert r2["status"] == "refused"


def test_wake_already_up_is_noop(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n')
    r = wake("demo", root=root, run=lambda a: (0, ""),
             observe=lambda m: Actual(enabled=True, active=True), now="t")
    assert r["status"] == "already-up"


def test_wake_starts_a_down_on_demand_module(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    calls = []
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n')
    # observe: down first (so plan_changes plans a START), then up (wait_state converges)
    seq = iter([Actual(enabled=False, active=False)] + [Actual(enabled=True, active=True)] * 5)
    def obs(m):
        return next(seq)
    def run(a):
        calls.append(a); return 0, ""
    r = wake("demo", root=root, run=run, observe=obs, now="t")
    assert r["status"] == "woken"
    assert any(c[:2] == ["systemctl", "enable"] for c in calls)


def test_wake_dry_run_reports_planned_not_failed(tmp_path):
    from api.wake import wake
    from api.observe import Actual
    root = tmp_path
    (root / "modules.d").mkdir()
    (root / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n')
    r = wake("demo", root=root, run=lambda a: (0, ""),
              observe=lambda m: Actual(enabled=False, active=False), now="t",
              apply=False)
    assert r["status"] == "planned"


def test_main_requires_root(monkeypatch):
    import api.wake as w
    monkeypatch.setattr(w, "_running_as_root", lambda: False)
    assert w.main(["wake", "demo"]) == 1


def test_main_refused_exit_3(monkeypatch, tmp_path, capsys):
    import api.wake as w
    monkeypatch.setattr(w, "_running_as_root", lambda: True)
    monkeypatch.setattr(w, "wake", lambda *a, **k: {"status": "refused", "module": "demo", "reason": "manual"})
    rc = w.main(["--root", str(tmp_path), "wake", "demo", "--json"])
    out = capsys.readouterr().out
    import json as _j
    assert rc == 3 and _j.loads(out)["status"] == "refused"


def test_main_woken_exit_0(monkeypatch, tmp_path):
    import api.wake as w
    monkeypatch.setattr(w, "_running_as_root", lambda: True)
    monkeypatch.setattr(w, "wake", lambda *a, **k: {"status": "woken", "module": "demo"})
    assert w.main(["--root", str(tmp_path), "wake", "demo"]) == 0
