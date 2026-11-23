# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3527 / #3516 : la liste des services de l'administration ne montre que les services présents, chacun avec un état lisible
(une tâche de minuterie ou un service coupé par le profil n'est jamais « arrêté »)."""
import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

PAQUETS = Path(__file__).resolve().parents[2]
ADMIN = PAQUETS / "secubox-system" / "composants" / "admin"
sys.path.insert(0, str(PAQUETS.parent / "common"))

UNITES = """\
secubox-actord.service not-found inactive dead secubox-actord.service
secubox-waf-ng.service loaded active running WAF
secubox-maj.service loaded inactive dead Mise a jour
secubox-firstboot.service loaded inactive dead Premier demarrage
secubox-netmodes.service loaded inactive dead Modes reseau
secubox-coupe.service masked inactive dead secubox-coupe.service
secubox-panne.service loaded failed failed Panne
secubox-arret.service loaded inactive dead Arrete
secubox-oneshot.service loaded active exited Passe
secubox-group@g1.service loaded active running Groupe
secubox-dep.service loaded inactive dead Dependance
"""
FICHIERS = """\
secubox-waf-ng.service enabled enabled
secubox-maj.service static -
secubox-firstboot.service enabled enabled
secubox-netmodes.service disabled enabled
secubox-coupe.service masked enabled
secubox-panne.service enabled enabled
secubox-arret.service enabled enabled
secubox-oneshot.service enabled enabled
secubox-group@.service disabled enabled
secubox-dep.service indirect enabled
"""
TRIGGERS = "Triggers=secubox-maj.service\n\nTriggers=secubox-firstboot.service secubox-autre.socket\n"


@pytest.fixture(scope="module")
def admin():
    spec = importlib.util.spec_from_file_location("api_admin_3527", ADMIN / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    with mock.patch.object(Path, "mkdir", lambda *a, **k: None):
        spec.loader.exec_module(m)
    return m


def test_absents_retires_et_etats_lisibles(admin):
    par = {s["name"]: s for s in admin.classer_services(UNITES, FICHIERS, TRIGGERS)}
    assert "secubox-actord" not in par                                  # not-found : paquet absent, App Store
    assert {k: v["etat"] for k, v in par.items()} == {
        "secubox-waf-ng": "actif", "secubox-maj": "a_la_demande", "secubox-firstboot": "a_la_demande",
        "secubox-netmodes": "desactive", "secubox-coupe": "desactive", "secubox-panne": "echec", "secubox-arret": "arrete",
        "secubox-oneshot": "termine", "secubox-group@g1": "actif", "secubox-dep": "a_la_demande"}
    assert par["secubox-waf-ng"]["is_running"] and not par["secubox-maj"]["is_running"]
    assert par["secubox-netmodes"]["fichier"] == "disabled" and par["secubox-group@g1"]["fichier"] == "disabled"


def test_sorties_vides_ou_illisibles(admin):
    assert admin.classer_services("", "", "") == []
    assert admin.classer_services("ligne courte\n\n", "x", "Triggers=") == []
    # Sans fichier d'unité connu, un service inactif est dit arrêté (jamais une donnée inventée).
    assert admin.classer_services("secubox-x.service loaded inactive dead X\n", "", "")[0]["etat"] == "arrete"


def test_taches_ponctuelles_et_conditions_non_remplies(admin):
    u = ("secubox-premier-pas.service loaded inactive dead P\nsecubox-rpi-dsi-boot.service loaded inactive dead D\n"
         "secubox-vrai.service loaded inactive dead V\n")
    f = "secubox-premier-pas.service enabled enabled\nsecubox-rpi-dsi-boot.service enabled enabled\nsecubox-vrai.service enabled enabled\n"
    show = ("Id=secubox-premier-pas.service\nType=oneshot\nConditionResult=yes\n\n"
            "Id=secubox-rpi-dsi-boot.service\nType=simple\nConditionResult=no\n\n"
            "Id=secubox-vrai.service\nType=simple\nConditionResult=yes\n")
    par = {s["name"]: s["etat"] for s in admin.classer_services(u, f, "", show)}
    assert par == {"secubox-premier-pas": "a_la_demande", "secubox-rpi-dsi-boot": "a_la_demande", "secubox-vrai": "arrete"}


def test_route_appelle_systemctl_sans_shell(admin, monkeypatch):
    appels = []

    def run(argv, *a, **k):
        appels.append(argv)
        import subprocess
        sortie = {"list-units": UNITES, "list-unit-files": FICHIERS, "show": TRIGGERS}[argv[1]]
        if argv[1] == "show" and "Type" in argv:
            sortie = "Id=secubox-arret.service\nType=simple\nConditionResult=yes\n"
        if argv[1] == "list-units" and "--type=timer,path" in argv:
            sortie = "secubox-maj.timer loaded active waiting X\nsecubox-firstboot.path loaded active waiting Y\n"
        return subprocess.CompletedProcess(argv, 0, sortie, "")
    monkeypatch.setattr(admin.subprocess, "run", run)
    noms = {s["name"]: s["etat"] for s in admin._get_services_status()}
    assert noms["secubox-maj"] == "a_la_demande" and "secubox-actord" not in noms
    assert noms["secubox-arret"] == "arrete"
    show = [a for a in appels if a[1] == "show"][0]
    assert show[:5] == ["systemctl", "show", "-p", "Triggers", "--"] and "secubox-maj.timer" in show
    assert all(isinstance(a, list) for a in appels)


def test_page_rend_les_etats():
    src = (ADMIN / "www" / "admin" / "index.html").read_text()
    for t in ("À LA DEMANDE", "DÉSACTIVÉ", "TERMINÉ", "attendus"):
        assert t in src
