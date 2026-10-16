# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2773 — NAC : les conteneurs LXC de TOUS les dossiers de conteneurs ont un nom.

CONSTAT (gk2, 2026-10-16) : l'inventaire (#2445) ne lisait que /var/lib/lxc ; mqtt (.110), zigbee (.111), peertube (.120), photoprism (.130) et ytsas (.180)
vivent dans /data/lxc, adresse écrite en dur dans leur config, et la page affichait « Conteneur sans nom ». (`lxc-ls` n'est pas une option : le service root est
confiné sans droit d'entrer dans un espace de noms.)"""
import json
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

SBIN = Path(__file__).resolve().parents[1] / "sbin" / "secubox-nac-lxc-names"
_spec = spec_from_loader("lxcnoms", SourceFileLoader("lxcnoms", str(SBIN)))
L = module_from_spec(_spec)
_spec.loader.exec_module(L)


def conteneur(racine: Path, nom: str, texte: str):
    d = racine / nom
    d.mkdir(parents=True)
    (d / "config").write_text(texte)


@pytest.fixture
def deux_racines(tmp_path):
    a, b = tmp_path / "var-lib-lxc", tmp_path / "data-lxc"
    conteneur(a, "mail", "lxc.net.0.ipv4.address = 10.100.0.10/24\nlxc.net.0.hwaddr = 00:16:3E:AA:BB:CC\n")
    conteneur(b, "mqtt", "lxc.uts.name = mqtt\nlxc.net.0.ipv4.address = 10.100.0.110/24\n")
    conteneur(b, "zigbee", "lxc.net.0.ipv4.address = 10.100.0.111/24\n")
    conteneur(b, "peertube", "lxc.net.0.ipv4.address = 10.100.0.120/24\n")
    return a, b


def test_les_deux_dossiers_sont_inventories(deux_racines):
    a, b = deux_racines
    r = L.inventaire([str(a), str(b)])
    assert r["ips"] == {"10.100.0.10": "mail", "10.100.0.110": "mqtt", "10.100.0.111": "zigbee", "10.100.0.120": "peertube"}
    assert r["macs"] == {"00:16:3e:aa:bb:cc": "mail"}


def test_un_seul_dossier_en_chaine_reste_accepte(deux_racines):
    a, _ = deux_racines
    assert L.inventaire(str(a))["ips"] == {"10.100.0.10": "mail"}


def test_un_dossier_absent_ou_illisible_n_empeche_pas_l_autre(deux_racines, tmp_path):
    _, b = deux_racines
    r = L.inventaire([str(tmp_path / "n-existe-pas"), str(b)])
    assert r["ips"]["10.100.0.110"] == "mqtt"


def test_la_premiere_declaration_d_une_adresse_l_emporte(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    conteneur(a, "premier", "lxc.net.0.ipv4.address = 10.100.0.50/24\n")
    conteneur(b, "second", "lxc.net.0.ipv4.address = 10.100.0.50/24\n")
    assert L.inventaire([str(a), str(b)])["ips"]["10.100.0.50"] == "premier"


def test_un_nom_invalide_est_ignore(tmp_path):
    a = tmp_path / "a"
    conteneur(a, "ok", "lxc.net.0.ipv4.address = 10.100.0.60/24\n")
    conteneur(a, "mauvais", "lxc.uts.name = ../etc\nlxc.net.0.ipv4.address = 10.100.0.61/24\n")
    ips = L.inventaire([str(a)])["ips"]
    assert ips == {"10.100.0.60": "ok"} or ips.get("10.100.0.61") in (None, "mauvais")


def test_les_dossiers_par_defaut_sont_les_deux_emplacements_du_parc():
    assert L.DOSSIERS == ["/var/lib/lxc", "/data/lxc"]


def test_la_variable_d_environnement_accepte_plusieurs_dossiers(monkeypatch):
    monkeypatch.setenv("SBX_LXC_DIR", "/x/un:/x/deux")
    assert L.dossiers_depuis_env() == ["/x/un", "/x/deux"]
    monkeypatch.delenv("SBX_LXC_DIR")
    assert L.dossiers_depuis_env() == ["/var/lib/lxc", "/data/lxc"]


def test_le_fichier_ecrit_ne_contient_que_noms_et_adresses(deux_racines, tmp_path):
    a, b = deux_racines
    sortie = tmp_path / "conteneurs.json"
    L.ecrire(L.inventaire([str(a), str(b)]), str(sortie))
    d = json.loads(sortie.read_text())
    assert set(d) == {"ips", "macs"} and d["ips"]["10.100.0.110"] == "mqtt"
    assert oct(sortie.stat().st_mode & 0o777) == "0o644"


def test_le_service_peut_lire_les_deux_dossiers_et_le_script_est_livre():
    compile(SBIN.read_text(), str(SBIN), "exec")
    unite = (SBIN.parents[1] / "debian" / "secubox-nac-lxc-names.service").read_text()
    assert "ReadOnlyPaths=/var/lib/lxc /data/lxc" in unite, "le bac à sable laisse déjà lire les deux"
    assert "secubox-nac-lxc-names" in (SBIN.parents[1] / "debian" / "rules").read_text()
