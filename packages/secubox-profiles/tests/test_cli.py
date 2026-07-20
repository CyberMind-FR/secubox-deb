# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

import pytest

from api.cli import main

MANIFEST = """
id       = "lyrion"
category = "media"
runtime  = "native"
exposure = "lan"
units    = ["secubox-lyrion.service"]
priority = 30
"""


@pytest.fixture()
def root(tmp_path):
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "lyrion.toml").write_text(MANIFEST)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "media.toml").write_text(
        'name = "media"\nlabel = "🎬 Média"\non = ["lyrion"]\n')
    return tmp_path


def test_status_json_lists_modules(root, capsys, monkeypatch):
    monkeypatch.setattr("api.cli._observe_all",
                        lambda ms, routes: {"lyrion": __import__(
                            "api.observe", fromlist=["Actual"]).Actual(
                                enabled=True, active=True, rss_kb=1024)})
    rc = main(["--root", str(root), "status", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["modules"][0]["id"] == "lyrion"
    assert out["modules"][0]["on"] is True
    assert out["modules"][0]["category"] == "media"


def test_diff_reports_no_change_when_converged(root, capsys, monkeypatch):
    monkeypatch.setattr("api.cli._observe_all",
                        lambda ms, routes: {"lyrion": __import__(
                            "api.observe", fromlist=["Actual"]).Actual(
                                enabled=True, active=True)})
    rc = main(["--root", str(root), "diff", "--profile", "media", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["changes"] == []


def test_diff_reports_stop_for_module_absent_from_profile(root, capsys, monkeypatch):
    (root / "profiles" / "vide.toml").write_text('name = "vide"\nlabel = "v"\non = []\n')
    monkeypatch.setattr("api.cli._observe_all",
                        lambda ms, routes: {"lyrion": __import__(
                            "api.observe", fromlist=["Actual"]).Actual(
                                enabled=True, active=True)})
    rc = main(["--root", str(root), "diff", "--profile", "vide", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["changes"] == [{"id": "lyrion", "action": "stop", "priority": 30,
                               "reason": "absent du profil 'vide'"}]


def test_diff_unknown_profile_errors(root, capsys):
    rc = main(["--root", str(root), "diff", "--profile", "fantome", "--json"])
    assert rc == 2


def test_apply_requires_root(tmp_path, monkeypatch):
    import api.cli as cli
    monkeypatch.setattr(cli, "_running_as_root", lambda: False)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    assert cli.main(["--root", str(root), "apply", "--yes"]) == 1


def test_apply_dry_run_default_acts_on_nothing(tmp_path, monkeypatch, capsys):
    import api.cli as cli
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "lyrion.toml").write_text(
        'id="lyrion"\ncategory="infra"\nruntime="lxc"\nexposure="lan"\n'
        'units=["secubox-lyrion.service"]\nlxc="lyrion"\nprotected=false\n')
    # observe: lyrion currently on; no profile → desired off → plan = stop lyrion
    # (currently-on is is_on(), which reads enabled+active — NOT lxc_running;
    # the brief's original Actual(lxc_running=True) would resolve to "off"
    # already and produce an empty plan, defeating the point of this test —
    # fixed here to Actual(enabled=True, active=True).)
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"lyrion": __import__("api.observe", fromlist=["Actual"]).Actual(enabled=True, active=True)})
    called = {"n": 0}
    import api.apply as ap
    real = ap.apply_plan
    def spy(*a, **k):
        called["n"] += 1
        assert k.get("apply") is False   # dry-run
        return real(*a, **k)
    monkeypatch.setattr(ap, "apply_plan", spy)
    rc = cli.main(["--root", str(root), "apply"])  # no --yes → dry-run
    assert rc == 0 and called["n"] == 1


def test_apply_only_filters_plan(tmp_path, monkeypatch):
    # --only restricts the plan; a plan with x and y, --only x → only x acted.
    import api.cli as cli
    import api.apply as ap
    from api.apply import ApplyReport
    from api.observe import Actual

    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    for mid in ("x", "y"):
        (root / "modules.d" / f"{mid}.toml").write_text(
            f'id="{mid}"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
            f'units=["secubox-{mid}.service"]\nprotected=false\n')
    # both currently on; no active profile → desired off for both → plan
    # would stop BOTH x and y before any --only filtering.
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {mid: Actual(enabled=True, active=True) for mid in mans})

    captured = {}

    def spy(plan, *a, **k):
        captured["ids"] = {c.id for c in plan}
        return ApplyReport(status="planned", changed=[c.id for c in plan])

    monkeypatch.setattr(ap, "apply_plan", spy)
    rc = cli.main(["--root", str(root), "apply", "--only", "x"])  # dry-run
    assert rc == 0
    assert captured["ids"] == {"x"}


def test_apply_json_emits_report(tmp_path, monkeypatch, capsys):
    import api.apply as ap
    import api.cli as cli
    from api.apply import ApplyReport
    from api.observe import Actual

    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "x.toml").write_text(
        'id="x"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["x.service"]\nprotected=false\n')
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"x": Actual(enabled=True, active=True)})
    monkeypatch.setattr(ap, "apply_plan",
                        lambda *a, **k: ApplyReport(status="applied", changed=["x"]))
    rc = cli.main(["--root", str(root), "apply", "--yes", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["status"] == "applied" and out["changed"] == ["x"]


def test_rollback_requires_root(tmp_path, monkeypatch):
    import api.cli as cli
    monkeypatch.setattr(cli, "_running_as_root", lambda: False)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    assert cli.main(["--root", str(root), "rollback", "--yes"]) == 1


def test_rollback_dry_run_default_acts_on_nothing(tmp_path, monkeypatch):
    # Root-gated wiring check for `rollback` — mirrors the `apply` dry-run
    # test above. Not in the brief verbatim (which only specified the apply
    # tests): added because `_cmd_rollback` called the bare name
    # `rollback_to`, which was never imported anywhere in cli.py — a
    # guaranteed NameError on the very first real `rollback --yes`, with zero
    # test coverage catching it. Fixed in cli.py (apply.rollback_to, same
    # attribute-access pattern as apply.apply_plan, for the same monkeypatch
    # reason) and covered here so a regression back to the bare name fails
    # loudly instead of only at runtime in production.
    import api.apply as ap
    import api.cli as cli
    from api.apply import ApplyReport

    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    monkeypatch.setattr(cli, "read_snapshot",
                        lambda target, root: {"ts": "2026-07-19T00:00:00Z", "modules": {}})

    called = {"n": 0}

    def spy(*a, **k):
        called["n"] += 1
        assert k.get("apply") is False   # dry-run
        return ApplyReport(status="planned", changed=[])

    monkeypatch.setattr(ap, "rollback_to", spy)
    rc = cli.main(["--root", str(root), "rollback"])  # no --yes → dry-run
    assert rc == 0 and called["n"] == 1


def test_rollback_json_emits_report(tmp_path, monkeypatch, capsys):
    # Mirrors test_apply_json_emits_report for `rollback --json` — the
    # report dict must also carry "target" (the apply report itself has no
    # notion of which snapshot was targeted).
    import api.apply as ap
    import api.cli as cli
    from api.apply import ApplyReport

    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    monkeypatch.setattr(cli, "read_snapshot",
                        lambda target, root: {"ts": "2026-07-19T00:00:00Z", "modules": {}})
    monkeypatch.setattr(ap, "rollback_to",
                        lambda *a, **k: ApplyReport(status="applied", changed=["x"]))
    rc = cli.main(["--root", str(root), "rollback", "--target", "R2", "--yes", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["status"] == "applied" and out["changed"] == ["x"] and out["target"] == "R2"


def test_scan_survives_unreadable_routes_file(root, capsys, monkeypatch):
    # load_routes() renvoie None quand le fichier de routes est présent mais
    # illisible/corrompu (indéterminable, distinct de "aucune route"). scan
    # doit rester lecture seule et ne pas planter dans ce cas plutôt que de
    # propager le None jusqu'à `for r in sorted(routes)` — mais il ne doit
    # PAS non plus retomber silencieusement sur "aucune route" : ça dégrade
    # exposure (public -> lan/internal) pour tout module routé sans que
    # l'opérateur ne le sache, et un manifeste écrit fait ensuite autorité
    # (scan n'écrase pas sans --force). L'opérateur doit être prévenu.
    monkeypatch.setattr("api.cli.load_routes", lambda: None)
    monkeypatch.setattr("api.cli._running_as_root", lambda: True)
    monkeypatch.setattr("api.cli._run", lambda argv: (
        (0, "secubox-lyrion.service enabled\n") if argv[0:2] == ["systemctl", "list-unit-files"]
        else (0, "")))
    rc = main(["--root", str(root), "scan"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "illisible" in err or "corrompu" in err
    assert "exposure" in err.lower()


def test_scan_stays_silent_when_routes_file_genuinely_absent(root, capsys, monkeypatch):
    # Fichier absent = aucune route, c'est le cas normal (box sans WAF routé).
    # Aucun avertissement ne doit être émis dans ce cas — sinon l'opérateur
    # ne peut plus distinguer "rien à signaler" de "attention, dégradé".
    monkeypatch.setattr("api.cli.load_routes", lambda: set())
    monkeypatch.setattr("api.cli._running_as_root", lambda: True)
    monkeypatch.setattr("api.cli._run", lambda argv: (
        (0, "secubox-lyrion.service enabled\n") if argv[0:2] == ["systemctl", "list-unit-files"]
        else (0, "")))
    rc = main(["--root", str(root), "scan"])
    err = capsys.readouterr().err
    assert rc == 0
    assert err == ""


def test_scan_aborts_when_lxc_ls_did_not_execute(root, capsys, monkeypatch):
    # rc=None (OSError/timeout) sur lxc-ls est indéterminé, PAS "aucun
    # conteneur". Sur une box avec des conteneurs LXC, retomber sur out=""
    # dériverait silencieusement tous les modules LXC en runtime="native"
    # dans un manifeste qui fait ensuite autorité — c'est le C2 du review.
    # scan doit refuser d'écrire plutôt que de produire cet inventaire faux.
    monkeypatch.setattr("api.cli._running_as_root", lambda: True)

    def fake_run(argv):
        if argv[0:2] == ["systemctl", "list-unit-files"]:
            return 0, "secubox-lyrion.service enabled\n"
        if argv[0] == "lxc-ls":
            return None, ""  # n'a pas pu s'exécuter
        return 0, ""

    monkeypatch.setattr("api.cli._run", fake_run)
    rc = main(["--root", str(root), "scan"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "lxc-ls" in err
    mod_dir = root / "modules.d"
    # Aucun nouveau manifeste dérivé n'a été écrit sur cette découverte ratée
    # (le seul fichier présent est celui déjà posé par la fixture `root`).
    assert sorted(p.name for p in mod_dir.glob("*.toml")) == ["lyrion.toml"]


def test_scan_handles_genuinely_empty_lxc_ls_without_false_alarm(root, capsys, monkeypatch):
    # rc=0 et sortie vide, en root, c'est le cas normal d'une box sans
    # conteneur LXC — ne doit PAS être traité comme une erreur.
    monkeypatch.setattr("api.cli._running_as_root", lambda: True)
    monkeypatch.setattr("api.cli._run", lambda argv: (
        (0, "secubox-lyrion.service enabled\n") if argv[0:2] == ["systemctl", "list-unit-files"]
        else (0, "")))
    rc = main(["--root", str(root), "scan", "--force"])
    err = capsys.readouterr().err
    assert rc == 0
    assert "lxc-ls" not in err
    from api.manifest import load_manifest
    m = load_manifest(root / "modules.d" / "lyrion.toml")
    assert m.runtime == "native"


def test_export_pkglist_from_tmp_root(tmp_path, monkeypatch, capsys):
    import api.cli as cli
    import api.export as export
    root = tmp_path / "etc-secubox"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "waf.toml").write_text(
        'id="waf"\ncategory="security"\nruntime="native"\nexposure="lan"\n'
        'units=["secubox-waf.service"]\nprotected=false\n')
    (root / "modules.d" / "auth.toml").write_text(
        'id="auth"\ncategory="security"\nruntime="native"\nexposure="lan"\n'
        'units=["secubox-auth.service"]\nprotected=true\n')
    (root / "profiles" / "p.toml").write_text('name="p"\non=["waf"]\n')

    def fake_run(argv):
        if argv[:2] == ["dpkg", "-S"]:
            if "secubox-waf.service" in argv[2]:
                return 0, "secubox-waf: " + argv[2] + "\n"
            if "secubox-auth.service" in argv[2]:
                return 0, "secubox-auth: " + argv[2] + "\n"
            return 1, ""
        return None, ""
    monkeypatch.setattr(export, "_run", fake_run)

    rc = cli.main(["--root", str(root), "export", "p", "--format", "pkglist"])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["secubox-auth", "secubox-waf"]   # protected auth + listed waf


def test_export_unknown_profile_errors(tmp_path):
    import api.cli as cli
    root = tmp_path / "etc-secubox"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    assert cli.main(["--root", str(root), "export", "nope"]) == 2  # StateError -> rc 2


def test_scan_refuses_when_not_root(root, capsys, monkeypatch):
    # lxc-ls non-root répond rc=0 avec une sortie vide, indistinguable d'une
    # box sans conteneur : sur les 24 conteneurs de cette box, ça dériverait
    # silencieusement tout en runtime="native". scan doit refuser plutôt que
    # d'écrire un inventaire qu'il sait potentiellement faux.
    monkeypatch.setattr("api.cli._running_as_root", lambda: False)
    monkeypatch.setattr("api.cli._run", lambda argv: (
        (0, "secubox-lyrion.service enabled\n") if argv[0:2] == ["systemctl", "list-unit-files"]
        else (0, "")))
    rc = main(["--root", str(root), "scan"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "root" in err.lower()


def test_apply_passes_route_value_dict_not_set_derived_empty_dict(tmp_path, monkeypatch):
    # Regression for the routes-set-discarded-as-{} bug (Phase 3a review
    # finding 1): load_routes() returns a set of domain NAMES (used by
    # _observe_all for portal_routed membership) — it never carried the
    # [host, port] VALUE. _cmd_apply used to derive routes_map from that same
    # set (`routes if isinstance(routes, dict) else {}`), which is always {}
    # on the real board, so snapshot.capture recorded route=None for every
    # portal module and rollback could never restore it. _cmd_apply must
    # instead pass load_route_values()'s dict (domain -> [host, port]) as
    # apply_plan's routes= kwarg.
    import api.cli as cli
    import api.apply as ap
    from api.apply import ApplyReport
    from api.observe import Actual

    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "lyrion.toml").write_text(
        'id="lyrion"\ncategory="media"\nruntime="native"\nexposure="public"\n'
        'units=["secubox-lyrion.service"]\nprotected=false\n'
        '[portal]\ndomain="lyrion.gk2.secubox.in"\n')
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"lyrion": Actual(enabled=True, active=True)})
    # load_routes() (the SET, used above only to observe portal_routed) still
    # reports the domain as routed; load_route_values() (the DICT, used for
    # apply_plan's snapshot) carries the real [host, port] — the two must not
    # be conflated.
    monkeypatch.setattr(cli, "load_routes", lambda: {"lyrion.gk2.secubox.in"})
    monkeypatch.setattr(cli, "load_route_values",
                        lambda: {"lyrion.gk2.secubox.in": ["127.0.0.1", 9000]})

    captured = {}

    def spy(plan, *a, **k):
        captured["routes"] = k.get("routes")
        return ApplyReport(status="planned", changed=[c.id for c in plan])

    monkeypatch.setattr(ap, "apply_plan", spy)
    rc = cli.main(["--root", str(root), "apply"])  # dry-run, no --yes needed to reach apply_plan
    assert rc == 0
    assert captured["routes"] == {"lyrion.gk2.secubox.in": ["127.0.0.1", 9000]}


def test_main_maps_valueerror_to_rc2_not_traceback(tmp_path, monkeypatch):
    # Phase 3a review finding 2: json.JSONDecodeError is a ValueError, not an
    # OSError — a corrupt routes/snapshot JSON hit during the apply pipeline
    # (e.g. snapshot.capture's json.loads) must surface as a clean rc 2 with
    # a stderr message, never an uncaught traceback on the board.
    import api.cli as cli
    import api.apply as apply_mod
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "x.toml").write_text(
        'id="x"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["x.service"]\nprotected=false\n')
    from api.observe import Actual
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"x": Actual(enabled=True, active=True)})

    def boom(*a, **k):
        raise ValueError("Expecting value: line 1 column 1 (char 0)")
    monkeypatch.setattr(apply_mod, "apply_plan", boom)
    assert cli.main(["--root", str(root), "apply", "--yes"]) == 2


def test_apply_error_maps_to_rc3_not_traceback(tmp_path, monkeypatch):
    # apply_plan's belt-and-suspenders ApplyError (STOP of a protected module)
    # must surface as a clean rc 3, never an uncaught traceback on the board.
    import api.cli as cli
    import api.apply as apply_mod
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "x.toml").write_text(
        'id="x"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
        'units=["x.service"]\nprotected=false\n')
    from api.observe import Actual
    monkeypatch.setattr(cli, "_observe_all",
                        lambda mans, routes: {"x": Actual(enabled=True, active=True)})

    def boom(*a, **k):
        raise apply_mod.ApplyError("x est protégé — un STOP est refusé")
    monkeypatch.setattr(apply_mod, "apply_plan", boom)
    assert cli.main(["--root", str(root), "apply", "--yes"]) == 3


def test_run_distinguishes_timeout_from_could_not_run(monkeypatch):
    # cli._run must return the actuate.TIMED_OUT sentinel on a subprocess
    # timeout (the command RAN, still working) and None only on OSError
    # (the command could not run at all) — the actuator relies on this
    # distinction to fast-fail only on genuine could-not-run.
    import subprocess

    import api.cli as cli
    from api.actuate import TIMED_OUT

    def raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)
    monkeypatch.setattr(cli.subprocess, "run", raise_timeout)
    assert cli._run(["whatever"]) == (TIMED_OUT, "")

    def raise_oserror(*a, **k):
        raise OSError("no such binary")
    monkeypatch.setattr(cli.subprocess, "run", raise_oserror)
    assert cli._run(["whatever"]) == (None, "")


# --- set-lifecycle (niveau d'éveil, webui->ctl) -----------------------------

_LC_MANIFEST = (
    'id        = "yacy"\n'
    'category  = "infra"\n'
    'runtime   = "native"\n'
    'exposure  = "public"\n'
    'units     = ["secubox-yacy.service"]\n'
    'portal    = { domain = "yacy.gk2.secubox.in" }\n'
    'priority  = 50\n'
    'lifecycle = "always-on"\n'
)


@pytest.fixture()
def lc_root(tmp_path, monkeypatch):
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "yacy.toml").write_text(_LC_MANIFEST)
    (tmp_path / "profiles").mkdir()
    monkeypatch.setattr("api.cli._running_as_root", lambda: True)
    return tmp_path


def test_set_lifecycle_writes_manifest_and_resyncs(lc_root, capsys):
    rc = main(["--root", str(lc_root), "set-lifecycle", "yacy",
               "--lifecycle", "on-demand", "--wake-class", "urgent", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["status"] == "set"
    assert out["lifecycle"] == "on-demand" and out["wake_class"] == "urgent"
    assert out["effective_lifecycle"] == "on-demand"
    # manifest actually edited
    from api.manifest import load_manifest
    m = load_manifest(lc_root / "modules.d" / "yacy.toml")
    assert m.lifecycle == "on-demand" and m.wake_class == "urgent"
    # resynced: yacy now an on-demand vhost + sleepable
    assert out["ondemand_vhosts"] == ["yacy.gk2.secubox.in"]
    assert out["sleepable"] == ["yacy"]
    import json as _j
    assert _j.loads((lc_root / "waf" / "on-demand-vhosts.json").read_text())
    assert "yacy" in _j.loads((lc_root / "health" / "sleepable-modules.json").read_text())


def test_set_lifecycle_to_always_on_clears_sleepable(lc_root, capsys):
    # first make it on-demand
    main(["--root", str(lc_root), "set-lifecycle", "yacy",
          "--lifecycle", "on-demand", "--wake-class", "normal", "--json"])
    capsys.readouterr()
    # then back to always-on: no longer on-demand / sleepable
    rc = main(["--root", str(lc_root), "set-lifecycle", "yacy",
               "--lifecycle", "always-on", "--wake-class", "normal", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["ondemand_vhosts"] == [] and out["sleepable"] == []


def test_set_lifecycle_unknown_module_refused(lc_root, capsys):
    rc = main(["--root", str(lc_root), "set-lifecycle", "ghost",
               "--lifecycle", "on-demand", "--wake-class", "normal", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 3 and out["status"] == "refused" and out["reason"] == "unknown"


def test_set_lifecycle_requires_root(lc_root, capsys, monkeypatch):
    monkeypatch.setattr("api.cli._running_as_root", lambda: False)
    rc = main(["--root", str(lc_root), "set-lifecycle", "yacy",
               "--lifecycle", "on-demand", "--wake-class", "normal", "--json"])
    assert rc == 1


def test_set_lifecycle_rejects_bad_enum_via_argparse(lc_root):
    # argparse choices= is the hard gate: invalid value exits (SystemExit) before
    # any manifest write.
    with pytest.raises(SystemExit):
        main(["--root", str(lc_root), "set-lifecycle", "yacy",
              "--lifecycle", "turbo", "--wake-class", "normal", "--json"])


def test_set_lifecycle_protected_module_refused(lc_root, capsys):
    (lc_root / "modules.d" / "auth.toml").write_text(
        'id="auth"\ncategory="security"\nruntime="native"\nexposure="lan"\n'
        'units=["secubox-auth.service"]\nlifecycle="always-on"\n')
    rc = main(["--root", str(lc_root), "set-lifecycle", "auth",
               "--lifecycle", "on-demand", "--wake-class", "normal", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 3 and out["status"] == "refused" and out["reason"] == "protected"
    # manifest NOT rewritten
    assert 'lifecycle="always-on"' in (lc_root / "modules.d" / "auth.toml").read_text()
