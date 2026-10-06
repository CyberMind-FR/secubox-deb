# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Observations de l'utilisateur : SQLite local, lecture, ajout, modification, suppression, historique."""
import pytest

from api import observations


@pytest.fixture
def base(tmp_path):
    return observations.Observations(tmp_path / "obs.db")


def test_ajout_et_lecture_avec_horodatage_utc(base):
    o = base.ajouter("Ciel dégagé ce soir.\nQuelques étoiles visibles.")
    assert o.id >= 1 and o.texte.startswith("Ciel") and o.cree.endswith("+00:00")
    assert base.dernier().id == o.id


def test_historique_du_plus_recent_au_plus_ancien(base):
    a = base.ajouter("première")
    b = base.ajouter("seconde")
    assert [x.id for x in base.lister()] == [b.id, a.id]
    assert [x.id for x in base.lister(limite=1)] == [b.id]


def test_modification_met_a_jour_la_date_de_modification(base):
    o = base.ajouter("avant")
    m = base.modifier(o.id, "après")
    assert m.texte == "après" and m.modifie >= o.cree and m.cree == o.cree


def test_suppression(base):
    o = base.ajouter("à supprimer")
    assert base.supprimer(o.id) is True
    assert base.dernier() is None and base.supprimer(o.id) is False


def test_modifier_un_inexistant_donne_none(base):
    assert base.modifier(999, "x") is None


@pytest.mark.parametrize("texte", ["", "   ", "\n\t"])
def test_texte_vide_refuse(base, texte):
    with pytest.raises(observations.ObservationInvalide):
        base.ajouter(texte)


def test_texte_trop_long_refuse(base):
    with pytest.raises(observations.ObservationInvalide):
        base.ajouter("x" * (observations.TEXTE_MAX + 1))


def test_les_requetes_sont_parametrees(base):
    o = base.ajouter("'); DROP TABLE observations;--")
    assert base.dernier().texte == "'); DROP TABLE observations;--" and o.id == base.dernier().id


def test_plafond_de_notes_conserve_les_plus_recentes(tmp_path):
    b = observations.Observations(tmp_path / "o.db", maximum=3)
    for i in range(5):
        b.ajouter(f"n{i}")
    assert [x.texte for x in b.lister(limite=10)] == ["n4", "n3", "n2"]


def test_persistance_entre_deux_ouvertures(tmp_path):
    observations.Observations(tmp_path / "o.db").ajouter("gardée")
    assert observations.Observations(tmp_path / "o.db").dernier().texte == "gardée"
