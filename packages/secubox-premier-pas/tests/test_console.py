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
