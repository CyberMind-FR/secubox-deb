# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3774 : onglet « Filtrages automatiques » — lecture, réglage d'un filtrage, retour aux réglages par défaut."""
import pytest
from fastapi import HTTPException

from api import dnstv, dnstv_auto, dnstv_routes as RT


@pytest.fixture
def etat_tv(monkeypatch, tmp_path):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv_auto, "TOML", tmp_path / "absent.toml")
    appels = []
    monkeypatch.setattr(RT, "_ctl", lambda a: appels.append(a) or {"ok": True})
    dnstv.ecrire_etat({"actif": True, "ajout_auto": True, "auto_essai": True,
                       "clients": [{"ip": "192.168.1.95", "nom": "TV 4e95", "mode": "auto"}]}, tmp_path)
    return appels


def test_lecture_tout_actif_par_defaut(etat_tv):
    f = RT.filtrages_lire(lecteur=None)
    assert all(f["filtrages"].values()) and set(f["filtrages"]) == set(RT.FILTRAGES)


def test_couper_un_filtrage_de_la_page_prime_sur_le_toml(etat_tv):
    r = RT.filtrage_regler(RT.FiltrageIn(cle="declencheurs_pub", actif=False))
    assert r["filtrages"]["declencheurs_pub"] is False and etat_tv == ["regles-appliquer"]
    assert dnstv_auto.reglage_depuis(dnstv.lire_etat()[0]).declencheurs_pub is False


def test_tri_des_nouvelles_tv_coupe_n_est_pas_pose(etat_tv):
    RT.filtrage_regler(RT.FiltrageIn(cle="tri_nouvelles", actif=False))
    etat = dnstv.lire_etat()[0]
    assert dnstv.politique_auto(etat) is False or "tv-4e95" not in (etat.get("tri_netflix") or {}).get("appareils", [])


def test_retour_aux_defauts_pose_tout_et_le_tri(etat_tv):
    RT.filtrage_regler(RT.FiltrageIn(cle="indices", actif=False))
    RT.filtrage_regler(RT.FiltrageIn(cle="tri_nouvelles", actif=False))
    r = RT.filtrages_defaut()
    assert all(r["filtrages"].values()) and r["tri_netflix"] == ["tv-4e95"] and etat_tv[-1] == "apply"


def test_echec_du_controleur_rend_l_etat_d_avant(etat_tv, monkeypatch):
    def refus(a):
        raise HTTPException(502, "refus")
    monkeypatch.setattr(RT, "_ctl", refus)
    with pytest.raises(HTTPException):
        RT.filtrage_regler(RT.FiltrageIn(cle="auto_essai", actif=False))
    assert dnstv.lire_etat()[0]["auto_essai"] is True


def test_cle_inconnue_refusee():
    with pytest.raises(ValueError):
        RT.FiltrageIn(cle="actif", actif=False)          # TV Privacy ne se désactive pas par cette voie (#3674)


def test_filtrages_invalides_refuses_par_l_etat(tmp_path):
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat({"actif": True, "clients": [], "filtrages": {"inconnu": True}})
