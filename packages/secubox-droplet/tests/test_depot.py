# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Espace de dépôt (#1026)."""
import hashlib
import io
import time

import pytest

from api.depot import (Depot, DepotRefuse, Limiteur, Recu, ecris_flux,
                       identifiant, nom_affichable)


# ── Le nom fourni est une donnée hostile ─────────────────────────────────

@pytest.mark.parametrize("brut,attendu", [
    ("rapport.zip", "rapport.zip"),
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\cmd.exe", "cmd.exe"),
    ("/absolu/chemin.tar.gz", "chemin.tar.gz"),
    ("", "depot.bin"),
    ("...", "depot.bin"),
    ("../", "depot.bin"),
])
def test_nom_affichable_ne_peut_jamais_designer_un_chemin(brut, attendu):
    assert nom_affichable(brut) == attendu


def test_caracteres_de_controle_retires():
    # Un retour à la ligne dans un nom COUPE UN EN-TETE DE COURRIER EN DEUX :
    # c'est un vecteur réel, pas une coquetterie d'affichage.
    assert "\n" not in nom_affichable("bon\nSubject: injecté.zip")
    assert "\x00" not in nom_affichable("nul\x00octet.zip")


def test_nom_tres_long_tronque_en_gardant_l_extension():
    n = nom_affichable("a" * 400 + ".zip")
    assert len(n) <= 120 and n.endswith(".zip")


def test_nom_long_sans_extension_utilisable():
    n = nom_affichable("b" * 400)
    assert len(n) <= 120 and n


# ── L'identifiant ────────────────────────────────────────────────────────

def test_identifiant_trie_dans_l_ordre_du_temps():
    a = identifiant(lambda: 1_000_000)
    b = identifiant(lambda: 2_000_000)
    assert a < b


def test_deux_depots_dans_la_meme_seconde_ne_se_marchent_pas_dessus():
    fixe = lambda: 1_700_000_000
    assert identifiant(fixe) != identifiant(fixe)


# ── L'écriture constate, elle ne croit pas ───────────────────────────────

def test_ecriture_rend_la_taille_reelle_et_l_empreinte(tmp_path):
    donnees = b"x" * 5000
    cible = tmp_path / "00.bin"
    taille, empreinte = ecris_flux(io.BytesIO(donnees), cible, 0)
    assert taille == 5000
    assert empreinte == hashlib.sha256(donnees).hexdigest()
    assert cible.read_bytes() == donnees


def test_depassement_refuse_et_le_partiel_est_efface(tmp_path):
    # Laisser le fichier partiel occuperait le disque sans qu'aucune trace ne
    # le rattache à un dépôt — exactement ce qu'un attaquant cherche.
    cible = tmp_path / "00.bin"
    with pytest.raises(DepotRefuse):
        ecris_flux(io.BytesIO(b"y" * 100_000), cible, 1000)
    assert not cible.exists()


def test_le_fichier_ecrit_n_est_pas_lisible_par_tout_le_monde(tmp_path):
    cible = tmp_path / "00.bin"
    ecris_flux(io.BytesIO(b"secret"), cible, 0)
    assert cible.stat().st_mode & 0o007 == 0


# ── Le limiteur ──────────────────────────────────────────────────────────

class Horloge:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_le_nombre_de_depots_est_borne():
    h = Horloge()
    l = Limiteur(octets_par_heure=0, depots_par_heure=3, horloge=h)
    for _ in range(3):
        l.autorise("10.0.0.1", 0)
    with pytest.raises(DepotRefuse):
        l.autorise("10.0.0.1", 0)


def test_le_volume_est_borne():
    h = Horloge()
    l = Limiteur(octets_par_heure=1000, depots_par_heure=0, horloge=h)
    l.autorise("10.0.0.1", 900)
    with pytest.raises(DepotRefuse):
        l.autorise("10.0.0.1", 200)


def test_le_seau_se_vide_continument():
    # Un compteur remis à zéro par fenêtre autoriserait deux fois le quota à
    # cheval sur la bascule ; le seau percé ne connaît pas ce bord.
    h = Horloge()
    l = Limiteur(octets_par_heure=3600, depots_par_heure=0, horloge=h)
    l.autorise("10.0.0.1", 3600)
    with pytest.raises(DepotRefuse):
        l.autorise("10.0.0.1", 100)
    h.t = 1800  # une demi-heure : la moitié du seau s'est vidée
    l.autorise("10.0.0.1", 1700)


def test_une_origine_n_empeche_pas_l_autre():
    h = Horloge()
    l = Limiteur(octets_par_heure=0, depots_par_heure=1, horloge=h)
    l.autorise("10.0.0.1", 0)
    l.autorise("10.0.0.2", 0)  # ne doit pas lever


def test_un_envoi_interrompu_est_rembourse():
    # Punir le déposant d'une panne réseau qui n'est pas la sienne serait
    # doublement injuste : il a déjà perdu son téléversement.
    h = Horloge()
    l = Limiteur(octets_par_heure=1000, depots_par_heure=0, horloge=h)
    l.autorise("10.0.0.1", 900)
    l.rembourse("10.0.0.1", 900)
    l.autorise("10.0.0.1", 900)


def test_la_table_ne_croit_pas_sans_fin():
    h = Horloge()
    l = Limiteur(1000, 10, horloge=h)
    for i in range(50):
        l.autorise(f"10.0.{i // 256}.{i % 256}", 1)
    h.t = 7200  # deux heures plus tard, tout est périmé
    l.oublie_les_vieux(borne=10)
    assert len(l._seaux) == 0


# ── Le dépôt ─────────────────────────────────────────────────────────────

def test_taille_du_depot(tmp_path):
    d = Depot("id", int(time.time()), "10.0.0.1", tmp_path)
    d.fichiers = [Recu("a", 10, "x", tmp_path / "0"),
                  Recu("b", 32, "y", tmp_path / "1")]
    assert d.taille == 42
