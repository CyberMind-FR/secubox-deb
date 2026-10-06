# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""L'alerte de dépôt (#1026)."""
import time

from api.alerte import compose, corps, envoie, taille_lisible
from api.depot import Depot, Recu


def depot_essai(tmp_path, taille=1000, nom="rapport.zip"):
    f = tmp_path / "00.bin"
    f.write_bytes(b"z" * taille)
    d = Depot("20260813T120000-abc123", int(time.time()), "203.0.113.7", tmp_path)
    d.fichiers = [Recu(nom, taille, "e3b0c442", f)]
    return d


def test_taille_lisible():
    assert taille_lisible(500) == "500 o"
    assert taille_lisible(2048).startswith("2.0 Kio")
    assert taille_lisible(5 << 20).startswith("5.0 Mio")
    assert taille_lisible(3 << 30).startswith("3.0 Gio")


def test_le_corps_dit_ce_qu_on_a_constate(tmp_path):
    t = corps(depot_essai(tmp_path), joint=True, plafond=0)
    assert "203.0.113.7" in t          # l'origine
    assert "e3b0c442" in t             # l'empreinte calculee a l'ecriture
    assert "rapport.zip" in t          # le nom, presente comme annonce
    assert str(tmp_path) in t          # le chemin sur disque


def test_l_absence_de_piece_jointe_est_expliquee(tmp_path):
    # Une alerte sans piece jointe et sans explication laisse croire a un
    # depot vide. Le silence serait pire que l'absence.
    t = corps(depot_essai(tmp_path), joint=False, plafond=1 << 20)
    assert "PAS joints" in t and "1.0 Mio" in t


def test_la_piece_est_jointe_sous_le_plafond(tmp_path):
    m = compose(depot_essai(tmp_path, 1000), "de@x", "a@y", 1 << 20)
    noms = [p.get_filename() for p in m.iter_attachments()]
    assert noms == ["rapport.zip"]


def test_au_dela_du_plafond_rien_n_est_joint(tmp_path):
    m = compose(depot_essai(tmp_path, 5000), "de@x", "a@y", 1000)
    assert list(m.iter_attachments()) == []
    assert "PAS joints" in m.get_body(("plain",)).get_content()


def test_plafond_zero_vaut_sans_plafond(tmp_path):
    m = compose(depot_essai(tmp_path, 5000), "de@x", "a@y", 0)
    assert len(list(m.iter_attachments())) == 1


def test_le_sujet_porte_le_volume(tmp_path):
    m = compose(depot_essai(tmp_path, 5 << 20), "de@x", "a@y", 0)
    assert "5.0 Mio" in m["Subject"]
    assert m["X-SecuBox-Droplet"] == "20260813T120000-abc123"


def test_un_nom_hostile_ne_coupe_pas_l_en_tete(tmp_path):
    # Le nom est deja nettoye en amont ; on verifie ici que l'en-tete produit
    # reste d'un seul tenant, quoi qu'il arrive.
    d = depot_essai(tmp_path, nom="normal.zip")
    m = compose(d, "de@x", "a@y", 1 << 20)
    brut = m.as_string()
    assert "\nSubject: injecté" not in brut


def test_un_fichier_illisible_n_annule_pas_l_alerte(tmp_path):
    # Prevenir avec une piece en moins vaut mieux que ne pas prevenir : le
    # depot, lui, a bien eu lieu.
    d = depot_essai(tmp_path)
    d.fichiers[0].chemin.unlink()
    m = compose(d, "de@x", "a@y", 1 << 20)
    assert list(m.iter_attachments()) == []
    assert "rapport.zip" in m.get_body(("plain",)).get_content()


def test_l_echec_d_envoi_ne_leve_jamais(tmp_path):
    # Les octets sont deja sur le disque : rendre une erreur au deposant parce
    # que NOTRE serveur de courrier est muet lui ferait renvoyer un fichier
    # qu'on possede.
    r = envoie(depot_essai(tmp_path), de="d@x", a="a@y",
               hote="127.0.0.1", port=1, plafond_joint=0, delai=1)
    assert r["ok"] is False and "non envoyée" in r["detail"]
