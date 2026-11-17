# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3785 : pubs RTL9+ (OQEE) dans le profil de base, posées aux TV en mode auto (la garde de catégorie les accepte)."""
from api import dnstv, dnstv_profil as P, dnstv_regles as R

RTL9 = ("vizchoice.viznet.tv", "ads-canalplus.akamaized.net")


def test_profil_de_base_contient_rtl9():
    assert set(RTL9) <= set(P.graine())


def test_migration_pose_rtl9_aux_tv_auto(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(P, "charger_agrege", lambda dossier=None: {})
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV 4e95", "mode": "auto"}]}, tmp_path)
    assert P.migrer_graine(tmp_path, 1000) is True
    assert set(RTL9) <= set(R.charger(tmp_path).actives("tv-4e95"))
