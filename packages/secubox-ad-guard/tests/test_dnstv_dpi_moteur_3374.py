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


def lancer(dossier, appels, charge=(0.5, 0.5, 0.5), now=NOW, sbx=None, cpu=None, rc_arret=0, pendant=None):
    """`cpu` : usage cumulé du cgroup de nDPId en µs (None = illisible) ; `pendant` : action jouée au milieu du passage."""
    def executer(verbe):
        appels.append(verbe)
        if verbe == "conntrack-dump" and pendant:
            pendant()
        return Rep(rc_arret if verbe == "ndpid-arreter" else 0, "")
    return D.moteur(now, executer, voisins={}, charge=lambda: charge, cpus=4, sbxdpi_chemin=dossier / "absent.json",
                    cpu_ndpid=(lambda: cpu(now)) if cpu else (lambda: None))


def ndpid_occupe(now):                                   # 50 % d'un cœur
    return (now - NOW) * 500_000


def ndpid_calme(now):                                    # 5 % d'un cœur
    return (now - NOW) * 50_000


def charge_etat(dossier):
    return json.loads((dossier / D.FICHIER_ETAT).read_text())["charge"]


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


def test_garde_de_charge_arrete_nDPId_apres_5_minutes_puis_attend_la_reprise_manuelle(dossier):
    appels = []
    for k in range(0, 5):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe)
    assert "ndpid-arreter" not in appels                                     # 4 min : un pic, pas un arrêt
    for k in range(5, 11):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe)
    assert appels.count("ndpid-arreter") == 1
    c = charge_etat(dossier)
    assert c["etat"] == "arrete" and c["depuis"] == NOW + 300
    lancer(dossier, appels, charge=(0.1, 0.1, 0.1), now=NOW + 1200, cpu=ndpid_occupe)
    assert charge_etat(dossier)["etat"] == "arrete"                          # reprise manuelle seulement
    D.reprendre_manuellement(lambda verbe: appels.append(verbe) or Rep())
    assert "ndpid-reprendre" in appels and charge_etat(dossier)["etat"] == "normal"


def test_charge_breve_n_arrete_rien(dossier):
    appels = []
    lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW, cpu=ndpid_occupe)
    lancer(dossier, appels, charge=(0.1, 0.1, 0.1), now=NOW + 60, cpu=ndpid_occupe)
    for k in range(2, 6):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe)
    assert "ndpid-arreter" not in appels


def test_nDPId_peu_gourmand_on_signale_sans_arreter(dossier):
    appels = []
    for k in range(0, 8):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_calme)
    assert "ndpid-arreter" not in appels
    c = charge_etat(dossier)
    assert c["etat"] == "haute" and "nDPId non en cause" in c["signal"]


def test_arret_refuse_par_root_n_affiche_pas_de_pause(dossier):
    appels = []
    for k in range(0, 7):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe, rc_arret=2)
    assert "ndpid-arreter" in appels and charge_etat(dossier)["etat"] != "arrete"


def test_reprise_pendant_un_passage_n_est_pas_ecrasee_et_la_garde_se_rearme(dossier):
    appels = []
    for k in range(0, 6):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe)
    assert charge_etat(dossier)["etat"] == "arrete"
    lancer(dossier, appels, charge=(0.1, 0.1, 0.1), now=NOW + 600, cpu=ndpid_occupe,
           pendant=lambda: D.reprendre_manuellement(lambda v: Rep()))
    assert charge_etat(dossier)["etat"] == "normal"                          # la reprise tombée au milieu du passage tient
    n = appels.count("ndpid-arreter")
    for k in range(11, 18):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe)
    assert appels.count("ndpid-arreter") == n + 1                            # garde réarmée


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


def test_suspension_ecrite_par_mkstemp_jamais_par_un_nom_previsible(dossier, tmp_path):
    m = _module_auto()
    cible = tmp_path / "ailleurs.txt"
    cible.write_text("intact")
    (dossier / ("." + C.FICHIER_SUSPENSIONS + ".tmp")).symlink_to(cible)       # piège sur l'ancien nom fixe
    etat, _ = dnstv.lire_etat()
    ch = [{"appareil": "tv-salon", "domaine": "x.example", "de": "essai", "vers": "retire", "motif": "contenu habituel plus demandé"}]
    assert m.suspendre_forcage(ch, etat, NOW)
    assert cible.read_text() == "intact"


def test_journal_impossible_le_dit_sur_stderr(dossier, monkeypatch, capsys):
    m = _module_auto()
    monkeypatch.setattr(m.dnstv_journal, "ajouter", lambda *a: (_ for _ in ()).throw(OSError("disque plein")))
    etat, _ = dnstv.lire_etat()
    ch = [{"appareil": "tv-salon", "domaine": "x.example", "de": "essai", "vers": "retire", "motif": "contenu habituel plus demandé"}]
    m.suspendre_forcage(ch, etat, NOW)
    assert "journal" in capsys.readouterr().err


def test_conntrack_indisponible_n_est_pas_ok(dossier):
    def executer(verbe):
        return Rep(4, "") if verbe == "conntrack-dump" else Rep(0, "")
    D.moteur(NOW, executer, voisins={}, charge=lambda: (0.1, 0.1, 0.1), cpus=4, sbxdpi_chemin=dossier / "absent.json",
             cpu_ndpid=lambda: None)
    assert json.loads((dossier / D.FICHIER_ETAT).read_text())["sources"]["conntrack"] == "indisponible"
