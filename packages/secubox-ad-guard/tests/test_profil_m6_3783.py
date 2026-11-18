# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3783 : pubs M6+ dans le profil de base, et migration des TV déjà en mode auto à chaque nouveau profil."""
from api import dnstv, dnstv_profil as P, dnstv_regles as R

M6 = ("7cbf2.v.fwmrm.net", "ads.stickyadstv.com", "2mdn.net", "smartclip.net", "adform.net", "realytics.net", "everesttech.net",
      "ups.analytics.yahoo.com")


def test_profil_de_base_contient_m6():
    g = set(P.graine())
    assert set(M6) <= g


def _monde(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(P, "charger_agrege", lambda dossier=None: {})
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV 4e95", "mode": "auto"},
                                                  {"ip": "192.168.1.9", "nom": "PC", "mode": "off"}]}, tmp_path)


def test_migration_equipe_les_tv_auto_une_fois(tmp_path, monkeypatch):
    _monde(tmp_path, monkeypatch)
    assert P.migrer_graine(tmp_path, 1000) is True
    actives = set(R.charger(tmp_path).actives("tv-4e95"))
    assert set(M6) <= actives and not R.charger(tmp_path).actives("pc")
    assert P.migrer_graine(tmp_path, 2000) is False                        # même empreinte : rien


def test_nouveau_profil_reequipe_sans_doublon(tmp_path, monkeypatch):
    _monde(tmp_path, monkeypatch)
    P.migrer_graine(tmp_path, 1000)
    avant = len(R.charger(tmp_path).liste())
    g = P.graine() + ["ftv-publicite.fr"]      # domaine de pub connu des listes : la garde de catégorie l accepte
    monkeypatch.setattr(P, "graine", lambda dossier_listes=None: g)
    assert P.migrer_graine(tmp_path, 3000) is True
    assert len(R.charger(tmp_path).liste()) == avant + 1 and len(list(tmp_path.glob(P.MARQUE_GRAINE + "*"))) == 1


def test_etat_corrompu_jamais_touche(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    (tmp_path / "etat.json").write_text("{x")
    assert P.migrer_graine(tmp_path, 1) is False and not list(tmp_path.glob(P.MARQUE_GRAINE + "*"))
