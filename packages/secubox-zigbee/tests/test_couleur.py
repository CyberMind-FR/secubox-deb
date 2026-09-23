# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-zigbee :: tests de la couleur et de la charge utile.

Ces tests ne montent ni courtier ni FastAPI : `api/couleur.py` est de
l'arithmetique pure, et c'est exactement pour cela qu'il est a part.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from couleur import charge_pour, xy_depuis_hex  # noqa: E402

TOUT = ["state", "brightness", "color_temp", "color_xy"]  # une LIGHT-BIBLI
INTER = ["state"]                                          # un INTER-BUR


# ── La conversion ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("hexa, attendu", [
    ("#FF0000", (0.70, 0.30)),
    ("#00FF00", (0.17, 0.75)),
    ("#0000FF", (0.14, 0.04)),
])
def test_les_primaires_tombent_sur_le_gamut_connu(hexa, attendu):
    """Les trois primaires ont des coordonnees publiees pour ce profil.

    C'est le seul controle qui aurait attrape une matrice sRGB standard mise
    a la place de la Wide RGB D65 : les deux donnent des couleurs plausibles,
    et seul le vert s'ecarte assez pour se voir dans un nombre.
    """
    x, y = xy_depuis_hex(hexa)
    assert x == pytest.approx(attendu[0], abs=0.02)
    assert y == pytest.approx(attendu[1], abs=0.02)


def test_le_gris_moyen_n_est_pas_a_mi_luminance():
    """#808080 vaut 21 % de lumiere, pas 50 %.

    Si quelqu'un retire la correction gamma, la chromaticite d'un gris ne
    bouge pas — un gris reste blanc. Ce test verifie donc la LUMINANCE, la
    seule grandeur ou l'oubli se voit.
    """
    from couleur import _lineaire
    assert _lineaire(128 / 255) == pytest.approx(0.216, abs=0.005)


def test_un_gris_reste_neutre():
    x, y = xy_depuis_hex("#808080")
    assert (x, y) == pytest.approx(xy_depuis_hex("#FFFFFF"), abs=0.001)


def test_le_noir_rend_le_blanc_d65_au_lieu_de_diviser_par_zero():
    assert xy_depuis_hex("#000000") == (0.3127, 0.3290)


@pytest.mark.parametrize("mauvais", ["", "#FFF", "bleu", "#GGGGGG", None])
def test_une_couleur_mal_formee_est_refusee(mauvais):
    with pytest.raises(ValueError):
        xy_depuis_hex(mauvais)


def test_le_diese_est_facultatif():
    assert xy_depuis_hex("FF0000") == xy_depuis_hex("#FF0000")


# ── La charge utile ─────────────────────────────────────────────────────────

def test_une_lampe_accepte_les_trois_champs():
    c = charge_pour(TOUT, etat="ON", couleur="#FF8800", luminosite=180)
    assert c["state"] == "ON"
    assert c["brightness"] == 180
    assert set(c["color"]) == {"x", "y"}


def test_un_interrupteur_refuse_la_couleur_au_lieu_de_l_ignorer():
    """LE TEST QUI COMPTE. Ignorer en silence, c'est repondre 200 sur une
    commande qui n'a rien fait — et envoyer chercher le bug dans la radio.
    """
    with pytest.raises(ValueError, match="couleur"):
        charge_pour(INTER, etat="ON", couleur="#FF0000")


def test_un_interrupteur_refuse_la_luminosite():
    with pytest.raises(ValueError, match="luminosite"):
        charge_pour(INTER, luminosite=120)


def test_un_interrupteur_accepte_toujours_son_etat():
    assert charge_pour(INTER, etat="TOGGLE") == {"state": "TOGGLE"}


@pytest.mark.parametrize("etat", ["ON", "off", "Toggle"])
def test_l_etat_est_normalise_en_majuscules(etat):
    assert charge_pour(INTER, etat=etat)["state"] == etat.upper()


def test_un_etat_inconnu_est_refuse():
    with pytest.raises(ValueError, match="etat"):
        charge_pour(INTER, etat="ALLUME")


@pytest.mark.parametrize("lum", [0, 255, -1, "beaucoup", 3.5e300])
def test_une_luminosite_hors_bornes_est_refusee(lum):
    with pytest.raises(ValueError):
        charge_pour(TOUT, luminosite=lum)


def test_une_commande_vide_est_refusee():
    """Sans ce garde, un corps vide publierait `{}` sur le topic /set —
    accepte par le courtier, sans effet, et compte comme un succes.
    """
    with pytest.raises(ValueError):
        charge_pour(TOUT)


def test_la_couleur_seule_ne_force_pas_l_allumage():
    """On envoie ce qui est demande, rien de plus : ajouter `state: ON`
    d'office rallumerait une lampe que l'on venait d'eteindre.
    """
    assert "state" not in charge_pour(TOUT, couleur="#00FF00")
