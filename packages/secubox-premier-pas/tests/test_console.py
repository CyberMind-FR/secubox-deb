# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Face console (#1522, couche 3) : les pages produisent ce que remplir attend."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import console as C, profil as P  # noqa: E402


def test_memes_etapes_que_le_moteur():
    assert [p.id for p in C.pages({})] + ["appliquer"] == list(P.ETAPES)


def test_lan_seul_masque_le_domaine_et_ne_l_envoie_pas():
    reseau = next(p for p in C.pages({}) if p.id == "reseau")
    reseau.champs[0].valeur = "lan"
    assert [c.cle for c in C.champs_visibles(reseau)] == ["mode"]
    assert reseau.valeurs(C.valeurs_de(reseau)) == {"mode": "lan"}


def test_rejoindre_demande_adresse_et_jeton():
    m = next(p for p in C.pages({}) if p.id == "maillage")
    m.champs[0].valeur = "rejoindre"
    assert [c.cle for c in C.champs_visibles(m)] == ["mode", "rejoindre", "jeton"]
    m.champs[1].valeur, m.champs[2].valeur = "192.168.1.200", "ab" * 16
    assert m.valeurs(C.valeurs_de(m)) == {"mode": "rejoindre", "rejoindre": "192.168.1.200", "jeton": "ab" * 16}


def test_prerempli_depuis_le_profil_sans_secret():
    ps = C.pages({"box": {"nom": "gk3", "fuseau": "Europe/Paris"}, "apt": {"auto": False}})
    assert next(p for p in ps if p.id == "nom").champs[0].valeur == "gk3"
    majs = next(p for p in ps if p.id == "majs")
    assert majs.valeurs(C.valeurs_de(majs)) == {"auto": False}
    admin = next(p for p in ps if p.id == "admin")
    assert all(c.valeur == "" for c in admin.champs)          # jamais pré-rempli


# ── #2312 : choisir une option dans une liste verticale ──────────────────────────────────────────
def _choix(valeur="a"):
    return C.Champ("profil", "Profil", "choix", [("a", "A"), ("b", "B"), ("c", "C")], valeur)


def test_haut_bas_choisissent_quand_la_page_n_a_qu_un_champ():
    import curses
    c = _choix()
    assert C.change_choix(c, curses.KEY_DOWN, True) and c.valeur == "b"
    assert C.change_choix(c, curses.KEY_UP, True) and C.change_choix(c, curses.KEY_UP, True) and c.valeur == "c"      # tourne


def test_haut_bas_gardent_leur_role_de_focus_quand_il_y_a_plusieurs_champs():
    import curses
    c = _choix()
    assert not C.change_choix(c, curses.KEY_DOWN, False) and c.valeur == "a"


def test_plus_moins_espace_chiffres_et_fleches_marchent_partout():
    import curses
    c = _choix()
    assert C.change_choix(c, "+", False) and c.valeur == "b"
    assert C.change_choix(c, "-", False) and c.valeur == "a"
    assert C.change_choix(c, " ", False) and c.valeur == "b"
    assert C.change_choix(c, "3", False) and c.valeur == "c"
    assert C.change_choix(c, curses.KEY_LEFT, False) and c.valeur == "b"
    assert C.change_choix(c, curses.KEY_RIGHT, False) and c.valeur == "c"
    assert not C.change_choix(c, "9", False) and c.valeur == "c"                      # chiffre hors liste : ignoré


def test_un_champ_texte_n_est_pas_touche():
    c = C.Champ("nom", "Nom", "texte", [], "x")
    assert not C.change_choix(c, "+", True) and c.valeur == "x"


def test_le_pied_de_page_n_utilise_que_de_l_ascii():
    import re
    src = (Path(__file__).resolve().parents[1] / "premier_pas" / "console.py").read_text(encoding="utf-8")
    pied = re.search(r'e\.addstr\(20, x0 \+ 2, "([^"]+)"', src).group(1)
    assert pied.isascii() and "Haut/Bas" in pied
