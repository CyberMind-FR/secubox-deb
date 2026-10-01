# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Recouvrement par le maillage (Coffre P8, #1367) : deux parts quelconques
sur n rouvrent le Coffre, une seule rien ; un jeu sert une fois."""
import importlib.machinery
import importlib.util
import itertools
import sqlite3
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE))

from coffre.coffre import Coffre, Interdit, Scelle, lit_part, part_texte  # noqa: E402
from coffre.journal import Journal  # noqa: E402

LEGER = {"t": 1, "m": 1024, "p": 1}
PHRASE = "une phrase assez longue pour le coffre"


@pytest.fixture
def coffre(tmp_path):
    c = Coffre(tmp_path / "coffre", Journal(tmp_path / "coffre.journal"), argon2=LEGER)
    c.initialiser(PHRASE)
    c.poser("box", "x", b"valeur")
    return c


@pytest.mark.parametrize("paire", list(itertools.combinations(range(3), 2)))
def test_deux_parts_quelconques_rouvrent(coffre, tmp_path, paire):
    jeu = coffre.recouvrement_preparer(["gk3", "c3box", "papier"])
    coffre.sceller()
    parts = [jeu["parts"][k] for k in paire]
    assert coffre.ouvrir_par_maillage(parts, qui="root")
    assert coffre.lire("box", "x") == b"valeur"
    assert coffre.recouvrement_etat() is None                     # le jeu a servi
    coffre.sceller()
    assert not coffre.ouvrir_par_maillage(parts)                  # et ne resservira pas


def test_une_part_seule_rien(coffre):
    jeu = coffre.recouvrement_preparer(["gk3", "papier"])
    coffre.sceller()
    assert not coffre.ouvrir_par_maillage([jeu["parts"][0]])
    assert not coffre.ouvrir_par_maillage([jeu["parts"][0], jeu["parts"][0]])   # la même, deux fois
    with pytest.raises(Scelle):
        coffre.lire("box", "x")
    assert coffre.recouvrement_etat()["detenteurs"] == ["gk3", "papier"]


def test_part_d_un_autre_jeu_ou_alteree(coffre):
    ancien = coffre.recouvrement_preparer(["gk3", "papier"])
    nouveau = coffre.recouvrement_preparer(["gk3", "papier"])     # l'ancien disparaît
    coffre.sceller()
    assert not coffre.ouvrir_par_maillage(ancien["parts"])
    jeu, i, part = lit_part(nouveau["parts"][1])
    faussee = part_texte(jeu, i, bytes([part[0] ^ 1]) + part[1:])
    assert not coffre.ouvrir_par_maillage([nouveau["parts"][0], faussee])
    assert coffre.ouvrir_par_maillage(nouveau["parts"])


def test_preparer_exige_le_coffre_ouvert_et_des_detenteurs_valides(coffre):
    for mauvais in (["gk3"], ["gk3", "gk3"], ["gk3", "../x"], ["a", "b", "c", "d", "e", "f"]):
        with pytest.raises(Interdit):
            coffre.recouvrement_preparer(mauvais)
    coffre.sceller()
    with pytest.raises(Scelle):
        coffre.recouvrement_preparer(["gk3", "papier"])


def test_part_lisible_et_tolerante(coffre):
    t = coffre.recouvrement_preparer(["gk3", "papier"])["parts"][1]
    jeu, i, part = lit_part(t)
    assert i == 1 and len(part) == 32
    assert lit_part(t.lower().replace("-", " ")) == (jeu, i, part)   # recopiée à la main
    for illisible in ("", "abc", "zzzzzzzz.1.AAAA", t.split(".")[0] + ".x." + t.split(".", 2)[2]):
        with pytest.raises(Interdit):
            lit_part(illisible)


def test_journal_sans_part(coffre, tmp_path):
    jeu = coffre.recouvrement_preparer(["gk3", "papier"])
    coffre.sceller()
    coffre.ouvrir_par_maillage(jeu["parts"])
    texte = (tmp_path / "coffre.journal").read_text()
    corps = [p.split(".", 2)[2] for p in jeu["parts"]]
    assert not any(c in texte for c in corps)
    assert "recouvrement_prepare" in texte and "recouvrement_consomme" in texte


def test_migration_v3_vers_v4(tmp_path):
    base = tmp_path / "c"
    c1 = Coffre(base, Journal(tmp_path / "j"), argon2=LEGER)
    c1.initialiser(PHRASE)
    with sqlite3.connect(base / "coffre.db") as cx:      # ramène la table des serrures en v3
        cx.executescript("""
            CREATE TABLE s3 (id TEXT PRIMARY KEY,
              genre TEXT NOT NULL CHECK (genre IN ('phrase','secours','appareil')),
              libelle TEXT NOT NULL DEFAULT '', sel BLOB NOT NULL, params TEXT NOT NULL,
              nonce BLOB NOT NULL, mk BLOB NOT NULL, creee INTEGER NOT NULL, cred_id TEXT);
            INSERT INTO s3 SELECT * FROM serrures; DROP TABLE serrures; ALTER TABLE s3 RENAME TO serrures;
            UPDATE meta SET valeur='3' WHERE cle='version';""")
    c2 = Coffre(base, Journal(tmp_path / "j"), argon2=LEGER)
    assert c2.ouvrir(PHRASE)
    c2.recouvrement_preparer(["gk3", "papier"])
    with sqlite3.connect(base / "coffre.db") as cx:
        assert cx.execute("SELECT valeur FROM meta WHERE cle='version'").fetchone()[0] == "4"


def _coffrectl():
    chargeur = importlib.machinery.SourceFileLoader("coffrectl", str(RACINE / "sbin" / "coffrectl"))
    spec = importlib.util.spec_from_loader("coffrectl", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    return m


def test_message_de_part_aller_retour():
    ctl = _coffrectl()
    corps = ctl.corps_part("gk2", "0a1b2c3d", "0a1b2c3d.1.ABCD-EFGH")
    assert ctl.lit_corps(corps) == {"origine": "gk2", "jeu": "0a1b2c3d", "part": "0a1b2c3d.1.ABCD-EFGH"}
    assert ctl.lit_corps("bonjour\npart: x") == {}
    assert ctl.lit_corps("coffre-recouvrement/1\norigine: gk2\n") == {}


def test_nextcloud_noms_dans_le_coffre():
    ctl = _coffrectl()
    from coffre.coffre import NOM_RE
    assert all(NOM_RE.match(ctl.nom_nextcloud(c)) for c in ctl.NEXTCLOUD_CLES)
    assert ctl.nom_nextcloud("mail_smtppassword") == "nextcloud-mail-smtppassword"
