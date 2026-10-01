# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Compartiments des personnes (Coffre P5, #1367).

Ce qu'on garantit, et qu'on teste :
- il faut la MK (Coffre ouvert) ET la serrure de la personne ;
- l'administration — même Coffre ouvert — ne lit, ne pose, ne retire ni ne
  liste rien dans un compartiment de personne ;
- une serrure ne vaut que pour SA personne ;
- la dernière serrure d'une personne ne se retire pas.
"""
import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coffre.coffre import Coffre, Interdit, RefusPersonnel, Scelle, b64u  # noqa: E402
from coffre.journal import Journal  # noqa: E402

LEGER = {"t": 1, "m": 1024, "p": 1}
PHRASE = "une phrase assez longue pour le coffre"
ALICE = "0b6e3c3a-7d0f-4c1e-9a55-3f2a1b8c9d10"
BOB = "4f1d2e3c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"
PH_ALICE = "la phrase personnelle d'alice"
PH_BOB = "la phrase personnelle de bob"
A = {"secret": PH_ALICE, "genre": "phrase"}
B = {"secret": PH_BOB, "genre": "phrase"}


@pytest.fixture
def coffre(tmp_path):
    c = Coffre(tmp_path / "coffre", Journal(tmp_path / "coffre.journal"), argon2=LEGER)
    c.initialiser(PHRASE)
    c.personne_initialiser(ALICE, PH_ALICE)
    c.personne_initialiser(BOB, PH_BOB)
    return c


def test_la_personne_pose_et_relit_avec_sa_serrure(coffre):
    assert coffre.personne_poser(ALICE, A, "gpg-secrete", b"-----BEGIN PGP-----") == 1
    assert coffre.personne_lire(ALICE, A, "gpg-secrete") == b"-----BEGIN PGP-----"
    assert [s["nom"] for s in coffre.personne_lister(ALICE, A)] == ["gpg-secrete"]
    assert coffre.personne_etat(ALICE)["secrets"] == 1


def test_l_administration_ne_lit_rien_d_une_personne(coffre):
    coffre.personne_poser(ALICE, A, "x", b"a moi")
    comp = "p-" + ALICE
    for geste in (lambda: coffre.lire(comp, "x"), lambda: coffre.poser(comp, "y", b"v"),
                  lambda: coffre.retirer(comp, "x"), lambda: coffre.lister(comp)):
        with pytest.raises(Interdit):
            geste()
    assert all(s["compartiment"] == "box" for s in coffre.lister())    # ses noms ne s'y montrent pas


def test_une_serrure_ne_vaut_que_pour_sa_personne(coffre):
    coffre.personne_poser(ALICE, A, "x", b"a moi")
    with pytest.raises(RefusPersonnel):
        coffre.personne_lire(ALICE, B, "x")               # la phrase de Bob sur Alice
    with pytest.raises(RefusPersonnel):
        coffre.personne_lire(ALICE, {"secret": "mauvaise phrase", "genre": "phrase"}, "x")
    with pytest.raises(KeyError):
        coffre.personne_lire(BOB, B, "x")                 # Bob n'a pas ce secret


def test_serrure_deplacee_vers_une_autre_personne_refusee(coffre, tmp_path):
    with sqlite3.connect(tmp_path / "coffre" / "coffre.db") as cx:
        cx.execute("UPDATE serrures_personnelles SET personne=? WHERE personne=?", ("tmp", BOB))
        cx.execute("UPDATE serrures_personnelles SET personne=? WHERE personne=?", (BOB, ALICE))
    with pytest.raises(RefusPersonnel):                   # la serrure d'Alice, rangée chez Bob
        coffre.personne_lister(BOB, A)


def test_scelle_rien_de_personnel(coffre):
    coffre.personne_poser(ALICE, A, "x", b"a moi")
    coffre.sceller()
    with pytest.raises(Scelle):
        coffre.personne_lire(ALICE, A, "x")
    assert coffre.ouvrir(PHRASE)
    assert coffre.personne_lire(ALICE, A, "x") == b"a moi"


def test_clefs_d_appareil_et_derniere_serrure(coffre):
    prf, sel = os.urandom(32), os.urandom(32)
    ident = coffre.personne_ajouter_appareil(ALICE, A, "C" * 43, sel, prf, "clé FIDO")
    coffre.personne_poser(ALICE, A, "x", b"v")
    par_cle = {"secret": b64u(prf), "genre": "appareil", "cred_id": "C" * 43}
    assert coffre.personne_lire(ALICE, par_cle, "x") == b"v"
    serrures = coffre.personne_etat(ALICE)["serrures"]
    assert {s["genre"] for s in serrures} == {"phrase", "appareil"}
    assert next(s for s in serrures if s["genre"] == "appareil")["sel"] == b64u(sel)
    phrase = next(s["id"] for s in serrures if s["genre"] == "phrase")
    coffre.personne_retirer_serrure(ALICE, par_cle, phrase)            # la clé suffit désormais
    with pytest.raises(RefusPersonnel):
        coffre.personne_lire(ALICE, A, "x")
    with pytest.raises(Interdit):
        coffre.personne_retirer_serrure(ALICE, par_cle, ident)          # la dernière reste
    with pytest.raises(Interdit):
        coffre.personne_ajouter_appareil(ALICE, par_cle, "C" * 43, sel, prf)   # déjà une serrure


def test_initialiser_une_fois_et_reprendre_l_ancien_regime(tmp_path):
    from coffre.crypto import aad_secret, chiffrer, cle_compartiment
    c = Coffre(tmp_path / "c", Journal(tmp_path / "j"), argon2=LEGER)
    c.initialiser(PHRASE)
    comp = "p-" + ALICE
    with sqlite3.connect(tmp_path / "c" / "coffre.db") as cx:   # P1 : clé tirée de la MK seule
        cx.execute("INSERT INTO compartiments VALUES (?,?,?,?)", (comp, "personne", "", 0))
        nonce, ch = chiffrer(cle_compartiment(c._mk.octets(), comp), b"ancien", aad_secret(comp, "v", 1))
        cx.execute("INSERT INTO secrets VALUES (?,?,?,?,?,?)", (comp, "v", 1, nonce, ch, 0))
    c.personne_initialiser(ALICE, PH_ALICE)
    assert c.personne_lire(ALICE, A, "v") == b"ancien"
    with pytest.raises(Interdit):
        c.personne_initialiser(ALICE, "une autre phrase longue")


def test_journal_sans_valeur_ni_phrase(coffre, tmp_path):
    coffre.personne_poser(ALICE, A, "x", b"valeur-tres-secrete")
    with pytest.raises(RefusPersonnel):
        coffre.personne_lire(ALICE, B, "x")
    texte = (tmp_path / "coffre.journal").read_text()
    assert "valeur-tres-secrete" not in texte and PH_ALICE not in texte and PH_BOB not in texte
    assert "personne_refusee" in texte and "personne_secret_pose" in texte


@pytest.mark.parametrize("p", ["gk2", "p-" + ALICE, "../x", ""])
def test_personne_par_uuid_seulement(coffre, p):
    with pytest.raises(Interdit):
        coffre.personne_etat(p)


def test_cle_openpgp_personnelle(coffre, tmp_path, monkeypatch):
    import shutil
    import subprocess
    if not shutil.which("gpg"):
        pytest.skip("gpg absent")
    monkeypatch.setenv("TMPDIR", "/tmp")             # chemin court : socket de l'agent
    k = coffre.personne_openpgp_creer(ALICE, A, "Alice", "alice@example.org")
    assert len(k["empreinte"]) == 40 and "PUBLIC KEY BLOCK" in k["publique"] and "secrete" not in k
    noms = {s["nom"] for s in coffre.personne_lister(ALICE, A)}
    assert noms == {"openpgp-secrete", "openpgp-publique"}
    secrete = coffre.personne_lire(ALICE, A, "openpgp-secrete").decode()
    assert "PRIVATE KEY BLOCK" in secrete
    g = tmp_path / "g"
    g.mkdir(mode=0o700)
    env = {**os.environ, "GNUPGHOME": str(g)}
    subprocess.run(["gpg", "--batch", "--import"], input=secrete.encode(), env=env, check=True, capture_output=True)
    lignes = subprocess.run(["gpg", "--batch", "--with-colons", "--list-secret-keys"], env=env,
                            capture_output=True, text=True).stdout.splitlines()
    assert any(l.startswith("sec:") and ":ed25519:" in l for l in lignes)
    assert any(l.startswith("ssb:") and ":cv25519:" in l for l in lignes)
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, capture_output=True)
    with pytest.raises(Interdit):                                   # une seule
        coffre.personne_openpgp_creer(ALICE, A, "Alice", "alice@example.org")
    with pytest.raises(Interdit):
        coffre.personne_openpgp_creer(BOB, B, "Bob <x>", "bob@example.org")
    assert "PRIVATE KEY" not in (tmp_path / "coffre.journal").read_text()
    assert not [d for d in os.listdir("/tmp") if d.startswith("sbxk-")]   # trousseau jetable détruit
