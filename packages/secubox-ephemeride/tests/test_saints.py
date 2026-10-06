# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Saints du jour : données locales, fichier d'administrateur par-dessus, jamais d'exception."""
import json
from datetime import date, timedelta

from api import saints


def test_saint_bruno_le_6_octobre():
    s = saints.fournisseur().pour(date(2026, 10, 6))
    assert [x.nom for x in s] == ["Bruno"] and "Chartreux" in s[0].description


def test_plusieurs_saints_le_meme_jour():
    assert len(saints.fournisseur().pour(date(2026, 1, 13))) == 2


def test_les_366_jours_ont_un_saint_y_compris_le_29_fevrier():
    f = saints.fournisseur()
    jour = date(2028, 1, 1)                      # 2028 est bissextile
    n = 0
    while jour.year == 2028:
        assert f.pour(jour), jour
        jour += timedelta(days=1)
        n += 1
    assert n == 366


def test_le_29_fevrier_d_une_annee_normale_n_existe_pas_mais_le_28_oui():
    assert saints.fournisseur().pour(date(2027, 2, 28))


def test_fichier_administrateur_prioritaire_jour_par_jour(tmp_path):
    f = tmp_path / "saints.json"
    f.write_text(json.dumps({"saints": {"10-06": [{"nom": "Autre", "description": "local"}]}}))
    p = saints.fournisseur(fichier=f)
    assert [x.nom for x in p.pour(date(2026, 10, 6))] == ["Autre"]
    assert [x.nom for x in p.pour(date(2026, 10, 7))] == ["Serge"]          # jour absent du fichier : données livrées


def test_fichier_corrompu_ignore_sans_exception(tmp_path):
    f = tmp_path / "saints.json"
    f.write_text("{pas du json")
    assert [x.nom for x in saints.fournisseur(fichier=f).pour(date(2026, 10, 6))] == ["Bruno"]


def test_entree_invalide_ignoree(tmp_path):
    f = tmp_path / "saints.json"
    f.write_text(json.dumps({"saints": {"10-06": [{"description": "sans nom"}, "texte", {"nom": "Valide"}]}}))
    assert [x.nom for x in saints.fournisseur(fichier=f).pour(date(2026, 10, 6))] == ["Valide"]


def test_fournisseur_inexistant_donne_liste_vide():
    class Vide:
        def pour(self, jour):
            raise OSError("boom")
    assert saints.Chaine([Vide()]).pour(date(2026, 10, 6)) == []
