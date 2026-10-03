# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import importlib.machinery
import importlib.util
import json
import os
import stat
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_regles as R

ETAT = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"},
                                   {"ip": "2a01:e0a::1", "nom": "TV banc", "mode": "auto"},
                                   {"ip": "192.168.1.9", "nom": "Autre", "mode": "observe"}]}


def test_mode_auto_accepte():
    assert dnstv.valider_etat(ETAT)["clients"][0]["mode"] == "auto"


def test_rendu_une_vue_par_appareil_auto_avec_ses_seules_regles():
    out = dnstv.rendre_unbound(ETAT, {"ads.example.com": "advertising"}, {"tv-banc": ["videos-pub.ftv-publicite.fr", "c.2mdn.net"]})
    assert "access-control-view: 192.168.1.95/32 sbx-tv-auto-tv-banc" in out
    assert "access-control-view: 2a01:e0a::1/128 sbx-tv-auto-tv-banc" in out
    bloc = out.split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]
    assert 'local-zone: "videos-pub.ftv-publicite.fr." always_nxdomain' in bloc
    assert 'local-zone: "c.2mdn.net." always_nxdomain' in bloc
    assert 'local-zone: "." transparent' in bloc
    assert "ads.example.com" not in bloc                      # en auto, la table du mode block ne s'applique pas


def test_rendu_sans_regle_la_vue_auto_est_transparente():
    out = dnstv.rendre_unbound(ETAT, {}, None)
    bloc = out.split('name: "sbx-tv-auto-tv-banc"')[1]
    assert "always_nxdomain" not in bloc.split("view:")[0] and 'local-zone: "." transparent' in bloc


def test_domaine_hostile_dans_les_regles_refuse_au_rendu():
    with pytest.raises(dnstv.ErreurTV):
        dnstv.rendre_unbound(ETAT, {}, {"tv-banc": ['a"; server: reboot']})


def test_magasin_evenements_et_jours_vus(tmp_path):
    m = dnstv.Magasin(tmp_path / "x.db")
    t = int(time.time())
    e1 = dnstv.Evenement(t - 90000, "192.168.1.95", "k7.ftven.fr", "A", "NOERROR", "ALLOWED")
    e2 = dnstv.Evenement(t - 5, "192.168.1.95", "k7.ftven.fr", "A", "NOERROR", "ALLOWED")
    m.ajouter([(e1, ""), (e2, "")])
    ev = m.evenements(["192.168.1.95"], t - 100)
    assert [x["domaine"] for x in ev] == ["k7.ftven.fr"] and ev[0]["decision"] == "ALLOWED"
    assert m.jours_vus(["192.168.1.95"], "9999-01-01")["k7.ftven.fr"] == 2


# ── contrôleur root : commande regles-appliquer ──────────────────────────────

def charger_ctl(monkeypatch, tmp_path, control_script):
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_ETAT", str(tmp_path))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_UNBOUND", str(tmp_path / "94.conf"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_CHECKCONF", str(tmp_path / "checkconf"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_CONTROL", str(control_script))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_APPLIQUE", str(tmp_path / "applique.json"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_SANS_ROOT", "1")
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", tmp_path / "listes")
    monkeypatch.setattr(dnstv, "CONF_UNBOUND", tmp_path / "94.conf")
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-tv"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_ctl", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_tv_ctl", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def faux(tmp_path, nom, code=0):
    p = tmp_path / nom
    p.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/{nom}.log\nexit {code}\n')
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def preparer(tmp_path, regles):
    dnstv.ecrire_etat(ETAT, tmp_path)
    R.ecrire(regles, tmp_path)


def regles_essai(*domaines):
    r = R.Regles()
    for d in domaines:
        rid = r.proposer("tv-banc", d, 50, "faible", 1_800_000_000)["id"]
        r.transiter(rid, "essai", "admin", "", 1_800_000_000)
    return r


def test_application_a_chaud_ajoute_sans_recharger(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()                                            # état initial : écrit le drop-in, recharge (vue nouvelle)
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    assert mod.regles_appliquer() == 0
    journal = (tmp_path / "unbound-control.log").read_text()
    assert "view_local_zone sbx-tv-auto-tv-banc b.example.com. always_nxdomain" in journal
    assert "reload" not in journal                              # aucune coupure du DNS
    assert 'local-zone: "b.example.com." always_nxdomain' in (tmp_path / "94.conf").read_text()   # persisté pour le prochain démarrage


def test_retrait_a_chaud(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    mod.appliquer()
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.regles_appliquer()
    assert "view_local_zone_remove sbx-tv-auto-tv-banc b.example.com." in (tmp_path / "unbound-control.log").read_text()


def test_echec_a_chaud_repli_rechargement(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = tmp_path / "unbound-control"
    ctl.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/unbound-control.log\ncase "$1" in view_local_zone*) exit 1;; esac\nexit 0\n')
    ctl.chmod(0o755)
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    assert mod.regles_appliquer() == 0
    assert "reload" in (tmp_path / "unbound-control.log").read_text().splitlines()[-1]


def test_regles_lien_symbolique_refuse_rien_ne_change(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    dnstv.ecrire_etat(ETAT, tmp_path)
    (tmp_path / "ailleurs.json").write_text(json.dumps({"version": 1, "regles": []}))
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "regles.json")
    with pytest.raises(SystemExit):
        mod.regles_appliquer()
    assert not (tmp_path / "unbound-control.log").exists()
