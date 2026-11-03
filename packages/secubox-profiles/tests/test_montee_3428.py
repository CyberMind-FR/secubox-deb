# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3428 : `apply --profile isp|full --yes` sur une box lite installe d'abord le méta-paquet par apt (sans délai, audité) ;
sans réseau, rien ne change et le code RC_DIFFERE le dit."""
import inspect
import json

import api.cli as cli
import api.montee as montee


class FauxApt:
    def __init__(self, installe=False, rc_update=0, rc_install=0, rc_dl=0):
        self.vues, self.installe, self.rc_update, self.rc_install, self.rc_dl = [], installe, rc_update, rc_install, rc_dl

    def __call__(self, argv):
        self.vues.append(argv)
        if argv[0] == "dpkg-query":
            return (0, "ii ") if self.installe else (1, "")
        if argv[:2] == ["apt-get", "update"]:
            return self.rc_update, "Err:1 https://apt.secubox.in trixie InRelease\n  Temporary failure resolving" if self.rc_update else ""
        if argv[:2] == ["apt-get", "install"]:
            return (self.rc_dl if "--download-only" in argv else self.rc_install), ""
        return 0, ""


def _audit(p):
    return [json.loads(ln)["event"] for ln in p.read_text().splitlines()] if p.exists() else []


def test_box_lite_vers_isp_installe_le_meta_paquet_par_apt(tmp_path):
    apt, journal = FauxApt(), tmp_path / "audit.log"
    rc, msg, neuf = montee.installer("isp", run=apt, audit_path=journal)
    assert rc == 0 and neuf and "secubox-isp" in msg
    assert apt.vues[1] == ["apt-get", "update", "-q"]
    assert apt.vues[2] == ["apt-get", "install", "-y", "-q", "--download-only", "secubox-isp"]   # télécharger d'abord
    assert apt.vues[3][:4] == ["apt-get", "install", "-y", "-q"] and apt.vues[3][-1] == "secubox-isp"
    assert _audit(journal) == ["profile_upgrade_start", "profile_upgrade_done"]


def test_full_aussi_et_deja_installe_ne_relance_pas_apt(tmp_path):
    apt = FauxApt(installe=True)
    assert montee.installer("full", run=apt, audit_path=tmp_path / "a")[:2] == (0, "secubox-full déjà installé")
    assert all(v[0] == "dpkg-query" for v in apt.vues)
    assert _audit(tmp_path / "a") == ["profile_upgrade_skip"]


def test_profil_sans_meta_paquet_n_appelle_pas_apt(tmp_path):
    apt = FauxApt()
    rc, _, neuf = montee.installer("media-lab", run=apt, audit_path=tmp_path / "a")
    assert rc == 0 and not neuf and apt.vues == []


def test_sans_reseau_message_clair_rien_change(tmp_path):
    apt, journal = FauxApt(rc_update=100), tmp_path / "audit.log"
    rc, msg, neuf = montee.installer("isp", run=apt, audit_path=journal)
    assert rc == montee.RC_DIFFERE and not neuf
    assert "Rien n'a été changé" in msg and "apply --profile isp --yes" in msg
    assert not any(v[:2] == ["apt-get", "install"] for v in apt.vues)
    assert _audit(journal) == ["profile_upgrade_start", "profile_upgrade_failed"]


def test_jamais_de_timeout_sur_apt():
    assert "timeout=" not in inspect.getsource(montee)


def _racine(tmp_path):
    root = tmp_path / "etc"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir()
    (root / "profiles" / "isp.toml").write_text('name = "isp"\nlabel = "ISP"\non = []\n')
    return root


def test_apply_yes_installe_puis_scanne_puis_applique(tmp_path, monkeypatch):
    root, ordre = _racine(tmp_path), []
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    monkeypatch.setattr(montee, "installer", lambda p: ordre.append(("apt", p)) or (0, "secubox-isp installé par apt", True))
    monkeypatch.setattr(cli, "_cmd_scan", lambda a: ordre.append(("scan", a.force)) or 0)
    monkeypatch.setattr(cli, "_observe_all", lambda m, routes: {})
    import api.apply as ap
    monkeypatch.setattr(ap, "apply_plan", lambda *a, **k: ordre.append(("apply", k["apply"])) or ap.ApplyReport(status="applied"))
    monkeypatch.setattr(cli.front_web, "appliquer", lambda p, run: {"ok": True})
    cli.main(["--root", str(root), "apply", "--profile", "isp", "--yes"])
    assert ordre[:3] == [("apt", "isp"), ("scan", False), ("apply", True)]


def test_apply_sans_reseau_rend_differe_sans_appliquer(tmp_path, monkeypatch, capsys):
    root = _racine(tmp_path)
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    monkeypatch.setattr(montee, "installer", lambda p: (montee.RC_DIFFERE, "secubox-isp n'a pas pu être installé", False))
    import api.apply as ap
    monkeypatch.setattr(ap, "apply_plan", lambda *a, **k: (_ for _ in ()).throw(AssertionError("apply appelé")))
    assert cli.main(["--root", str(root), "apply", "--profile", "isp", "--yes"]) == montee.RC_DIFFERE
    assert "pas pu être installé" in capsys.readouterr().err


def test_dry_run_annonce_l_installation_sans_rien_installer(tmp_path, monkeypatch, capsys):
    root = _racine(tmp_path)
    monkeypatch.setattr(cli, "_running_as_root", lambda: True)
    monkeypatch.setattr(montee, "est_installe", lambda p, run=None: False)
    monkeypatch.setattr(montee, "installer", lambda p: (_ for _ in ()).throw(AssertionError("apt en dry-run")))
    monkeypatch.setattr(cli, "_observe_all", lambda m, routes: {})
    assert cli.main(["--root", str(root), "apply", "--profile", "isp"]) == 0
    assert "secubox-isp absent" in capsys.readouterr().out


def test_telechargement_impossible_rien_change(tmp_path):
    apt = FauxApt(rc_dl=100)
    rc, msg, _ = montee.installer("full", run=apt, audit_path=tmp_path / "a")
    assert rc == montee.RC_DIFFERE and "Rien n'a été changé" in msg
    assert not any(v[:2] == ["apt-get", "install"] and "--download-only" not in v for v in apt.vues)


def test_echec_pendant_l_installation_est_un_echec_pas_un_report(tmp_path):
    apt = FauxApt(rc_install=100)
    rc, msg, _ = montee.installer("isp", run=apt, audit_path=tmp_path / "a")
    assert rc == montee.RC_ECHEC != montee.RC_DIFFERE and "Rien n'a été changé" not in msg and "dpkg --audit" in msg
