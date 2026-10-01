# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le Coffre P1 (#1367) : MK, serrures, compartiments, secrets, journal chaîné."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coffre.coffre import Coffre, Interdit, NonInitialise, Scelle, normalise_code  # noqa: E402
from coffre.crypto import Refus  # noqa: E402
from coffre.journal import Journal  # noqa: E402
from coffre.memoire import CleVerrouillee  # noqa: E402

LEGER = {"t": 1, "m": 1024, "p": 1}      # Argon2id allégé : on teste le Coffre, pas le coût
PHRASE = "une phrase assez longue pour le coffre"
UUID = "p-0b6e3c3a-7d0f-4c1e-9a55-3f2a1b8c9d10"


class Horloge:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def coffre(tmp_path):
    h = Horloge()
    c = Coffre(tmp_path / "coffre", Journal(tmp_path / "coffre.journal"), delai_s=900, horloge=h, argon2=LEGER)
    c.horloge = h
    return c


def test_scelle_tant_que_non_initialise(coffre):
    assert not coffre.initialise and not coffre.ouvert
    with pytest.raises(NonInitialise):
        coffre.ouvrir(PHRASE)
    with pytest.raises(Interdit):
        coffre.initialiser("trop courte")


def test_initialiser_ouvrir_sceller(coffre):
    codes = coffre.initialiser(PHRASE)
    assert len(codes) == 5 and len(set(codes)) == 5 and all(len(normalise_code(c)) == 25 for c in codes)
    assert coffre.ouvert
    coffre.sceller()
    assert not coffre.ouvert
    assert coffre.ouvrir("mauvaise phrase, bien longue") is False and not coffre.ouvert
    assert coffre.ouvrir(PHRASE) is True and coffre.ouvert
    with pytest.raises(Interdit):
        coffre.initialiser(PHRASE)              # une seule MK


def test_secret_chiffre_et_scelle(coffre, tmp_path):
    coffre.initialiser(PHRASE)
    assert coffre.poser("box", "mqtt-z2m", b"motdepasse-tres-secret") == 1
    assert coffre.poser("box", "mqtt-z2m", b"motdepasse-tres-secret-2") == 2
    assert coffre.lire("box", "mqtt-z2m") == b"motdepasse-tres-secret-2"
    assert coffre.lister() == [{"compartiment": "box", "nom": "mqtt-z2m", "version": 2,
                                "modifie": coffre.lister()[0]["modifie"]}]
    # Sur disque : ni la valeur ni la phrase, en clair nulle part.
    brut = (tmp_path / "coffre" / "coffre.db").read_bytes()
    for wal in (tmp_path / "coffre").glob("coffre.db-*"):
        brut += wal.read_bytes()
    assert b"motdepasse-tres-secret" not in brut and PHRASE.encode() not in brut
    assert oct((tmp_path / "coffre" / "coffre.db").stat().st_mode & 0o777) == "0o600"
    coffre.sceller()
    with pytest.raises(Scelle):
        coffre.lire("box", "mqtt-z2m")
    with pytest.raises(Scelle):
        coffre.lister()


def test_code_de_secours_a_usage_unique(coffre):
    codes = coffre.initialiser(PHRASE)
    coffre.sceller()
    saisi = codes[2].lower().replace("-", " ")           # saisie libre : casse, espaces
    assert coffre.ouvrir(saisi, "secours") is True
    coffre.sceller()
    assert coffre.ouvrir(codes[2], "secours") is False   # consommé
    assert coffre.ouvrir(codes[0], "secours") is True
    # Ouvert ou non, un secret se vérifie : un code n'est pas une phrase.
    assert coffre.ouvrir(codes[1], "phrase") is False and coffre.ouvert
    assert coffre.ouvrir(PHRASE, "phrase") is True
    assert sum(1 for s in coffre.etat()["serrures"] if s["genre"] == "secours") == 3


def test_ajouter_une_serrure_ne_rechiffre_rien(coffre, tmp_path):
    coffre.initialiser(PHRASE)
    coffre.poser("box", "cle-apt", b"phrase-gpg")
    db = tmp_path / "coffre" / "coffre.db"

    def chiffre():
        with sqlite3.connect(db) as cx:
            return cx.execute("SELECT nonce, valeur FROM secrets").fetchone()

    avant = chiffre()
    ident = coffre.ajouter_serrure_phrase("une seconde phrase, autre humain", "second admin")
    assert chiffre() == avant
    coffre.sceller()
    assert coffre.ouvrir("une seconde phrase, autre humain") and coffre.lire("box", "cle-apt") == b"phrase-gpg"
    initiale = next(s["id"] for s in coffre.etat()["serrures"] if s["libelle"] == "phrase initiale")
    coffre.retirer_serrure(initiale)
    with pytest.raises(Interdit):
        coffre.retirer_serrure(ident)                    # la dernière phrase reste
    coffre.sceller()
    assert coffre.ouvrir(PHRASE) is False


def test_un_secret_deplace_ne_se_dechiffre_pas(coffre, tmp_path):
    coffre.initialiser(PHRASE)
    coffre.creer_compartiment(UUID, "Gandalf")
    coffre.poser("box", "a", b"valeur-a")
    coffre.poser(UUID, "b", b"valeur-b")
    db = tmp_path / "coffre" / "coffre.db"
    with sqlite3.connect(db) as cx:          # on échange les chiffrés des deux places
        a = cx.execute("SELECT nonce, valeur FROM secrets WHERE nom='a'").fetchone()
        b = cx.execute("SELECT nonce, valeur FROM secrets WHERE nom='b'").fetchone()
        cx.execute("UPDATE secrets SET nonce=?, valeur=? WHERE nom='a'", b)
        cx.execute("UPDATE secrets SET nonce=?, valeur=? WHERE nom='b'", a)
    with pytest.raises(Refus):
        coffre.lire("box", "a")
    with pytest.raises(Refus):
        coffre.lire(UUID, "b")
    with sqlite3.connect(db) as cx:          # même place, autre version : refusé aussi
        cx.execute("UPDATE secrets SET nonce=?, valeur=?, version=7 WHERE nom='a'", a)
    with pytest.raises(Refus):
        coffre.lire("box", "a")


@pytest.mark.parametrize("comp", ["gk2", "admin", "p-pas-un-uuid", "../box", ""])
def test_compartiment_par_personne_jamais_par_compte(coffre, comp):
    coffre.initialiser(PHRASE)
    with pytest.raises(Interdit):
        coffre.creer_compartiment(comp)


def test_rescellement_par_inactivite(coffre):
    coffre.initialiser(PHRASE)
    coffre.horloge.t += 899
    assert coffre.ouvert
    coffre.lister()                                       # une action repousse l'échéance
    coffre.horloge.t += 899
    assert coffre.ouvert
    coffre.horloge.t += 901
    assert not coffre.ouvert
    assert coffre.journal.derniers(1)[0] == {"t": coffre.journal.derniers(1)[0]["t"],
                                             "evt": "scellement", "details": {"raison": "inactivite"}}


def test_journal_chaine_et_sans_secret(coffre, tmp_path):
    codes = coffre.initialiser(PHRASE)
    coffre.poser("box", "x", b"valeur-ultra-secrete")
    coffre.lire("box", "x")
    coffre.sceller()
    coffre.ouvrir("faux mot de passe assez long")
    j = tmp_path / "coffre.journal"
    texte = j.read_text()
    for interdit in (PHRASE, "valeur-ultra-secrete", *codes, *(normalise_code(c) for c in codes)):
        assert interdit not in texte
    assert [e["evt"] for e in coffre.journal.derniers(10)] == [
        "initialisation", "secret_pose", "secret_lu", "scellement", "ouverture_refusee"]
    assert coffre.journal.verifier() == (True, None, 5)
    lignes = texte.splitlines()
    e = json.loads(lignes[1]); e["details"]["nom"] = "autre"
    lignes[1] = json.dumps(e, sort_keys=True, ensure_ascii=False)
    j.write_text("\n".join(lignes) + "\n")
    assert coffre.journal.verifier()[:2] == (False, 3)   # la ligne SUIVANTE ne s'enchaîne plus


def test_etat_sans_valeurs(coffre):
    coffre.initialiser(PHRASE)
    coffre.poser("box", "y", b"valeur-ne-doit-pas-sortir")
    e = coffre.etat()
    assert e["initialise"] and e["ouvert"] and e["reste_s"] == 900
    assert e["compartiments"] == [{"id": "box", "nature": "box", "libelle": "système", "secrets": 1}]
    assert "valeur-ne-doit-pas-sortir" not in json.dumps(e)


def test_cle_verrouillee_effacee():
    k = CleVerrouillee(b"\x11" * 32)
    assert k.octets() == b"\x11" * 32 and "11" not in repr(k)
    k.effacer()
    assert not k
    with pytest.raises(ValueError):
        k.octets()


def test_migration_schema_v1_vers_v2(tmp_path):
    """Un Coffre initialisé en P1 (schéma v1) prend les serrures d'appareil."""
    import os
    base = tmp_path / "c"
    c1 = Coffre(base, Journal(tmp_path / "j"), argon2=LEGER)
    c1.initialiser(PHRASE)
    c1.poser("box", "x", b"valeur")
    with sqlite3.connect(base / "coffre.db") as cx:           # ramène au schéma v1
        cx.executescript("""
            CREATE TABLE s1 (id TEXT PRIMARY KEY, genre TEXT NOT NULL CHECK (genre IN ('phrase','secours')),
              libelle TEXT NOT NULL DEFAULT '', sel BLOB NOT NULL, params TEXT NOT NULL,
              nonce BLOB NOT NULL, mk BLOB NOT NULL, creee INTEGER NOT NULL);
            INSERT INTO s1 SELECT id, genre, libelle, sel, params, nonce, mk, creee FROM serrures;
            DROP TABLE serrures; ALTER TABLE s1 RENAME TO serrures;
            UPDATE meta SET valeur='1' WHERE cle='version';""")
    c2 = Coffre(base, Journal(tmp_path / "j"), argon2=LEGER)
    assert c2.ouvrir(PHRASE) and c2.lire("box", "x") == b"valeur"
    c2.ajouter_serrure_appareil("A" * 43, os.urandom(32), os.urandom(32), "clé")
    with sqlite3.connect(base / "coffre.db") as cx:
        assert cx.execute("SELECT valeur FROM meta WHERE cle='version'").fetchone()[0] == "2"
