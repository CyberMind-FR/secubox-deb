# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374) : passage DPI du moteur — état affichable, cibles, garde de charge, suspension du forçage si la lecture casse."""
import json

import pytest

from api import dnstv, dnstv_contournement as C, dnstv_dpi as D

MAC = "aa:bb:cc:00:00:01"
NOW = 1_800_000_000


class Rep:
    def __init__(self, rc=0, out=""):
        self.returncode, self.stdout, self.stderr = rc, out, ""


@pytest.fixture
def dossier(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}, tmp_path)
    return tmp_path


def lancer(dossier, appels, charge=(0.5, 0.5, 0.5), now=NOW, sbx=None):
    def executer(verbe):
        appels.append(verbe)
        return Rep(0, "") if verbe != "conntrack-dump" else Rep(0, "")
    return D.moteur(now, executer, voisins={}, charge=lambda: charge, cpus=4, sbxdpi_chemin=dossier / "absent.json")


def test_passage_ecrit_l_etat_et_demande_les_cibles_toutes_les_5_minutes(dossier):
    appels = []
    r = lancer(dossier, appels)
    e = json.loads((dossier / D.FICHIER_ETAT).read_text())
    assert e["appareils"][0]["couverture"] == "dns" and e["sources"]["sbxdpi"] == "absent"
    assert "dpi-cibles" in appels and "conntrack-dump" in appels and r["ok"]
    appels.clear()
    lancer(dossier, appels, now=NOW + 60)
    assert "dpi-cibles" not in appels
    lancer(dossier, appels, now=NOW + 301)
    assert "dpi-cibles" in appels


def test_garde_de_charge_arrete_nDPId_apres_10_minutes_puis_attend_la_reprise_manuelle(dossier):
    appels = []
    for k in range(0, 11):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k)
    assert appels.count("ndpid-arreter") == 1
    e = json.loads((dossier / D.FICHIER_ETAT).read_text())
    assert e["charge"]["pause"] == NOW + 600
    lancer(dossier, appels, charge=(0.1, 0.1, 0.1), now=NOW + 1200)
    assert json.loads((dossier / D.FICHIER_ETAT).read_text())["charge"]["pause"] == NOW + 600     # reprise manuelle seulement
    D.reprendre_manuellement(lambda verbe: appels.append(verbe) or Rep())
    assert "ndpid-reprendre" in appels and json.loads((dossier / D.FICHIER_ETAT).read_text())["charge"]["pause"] is None


def test_charge_breve_n_arrete_rien(dossier):
    appels = []
    lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW)
    lancer(dossier, appels, charge=(0.1, 0.1, 0.1), now=NOW + 60)
    for k in range(2, 11):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k)
    assert "ndpid-arreter" not in appels


def test_lecture_cassee_suspend_le_forcage_de_l_appareil():
    etat = {"clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}
    ch = [{"appareil": "tv-salon", "domaine": "x.example", "de": "essai", "vers": "retire", "motif": "contenu habituel plus demandé"},
          {"appareil": "tv-salon", "domaine": "y.example", "de": "essai", "vers": "retire", "motif": "rafale de refus"}]
    assert C.a_suspendre(ch, etat) == [MAC]
    assert C.a_suspendre(ch[1:], etat) == []


def _module_auto():
    import importlib.machinery
    import importlib.util
    from pathlib import Path
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_auto_lot4", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_tv_auto_lot4", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_moteur_ecrit_la_suspension_et_survit_a_un_passage_dpi_en_echec(dossier):
    m = _module_auto()
    etat, _ = dnstv.lire_etat()
    ch = [{"appareil": "tv-salon", "domaine": "x.example", "de": "essai", "vers": "retire", "motif": "contenu habituel plus demandé"}]
    assert m.suspendre_forcage(ch, etat, NOW)
    assert C.lire_suspensions((dossier / C.FICHIER_SUSPENSIONS).read_text(), NOW + 10) == {MAC}
    m.rafraichir_dpi(NOW, voisins=lambda: {}, executer=lambda v: (_ for _ in ()).throw(OSError("panne")))   # jamais d'exception
