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


def test_apply_is_not_a_command_in_phase_1(root):
    # Garde-fou : Phase 1 est en lecture seule. Si `apply` apparaît ici, c'est
    # que quelqu'un a court-circuité la Phase 3.
    with pytest.raises(SystemExit):
        main(["--root", str(root), "apply"])


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
