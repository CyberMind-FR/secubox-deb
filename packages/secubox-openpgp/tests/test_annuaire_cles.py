# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Annuaire des clés personnelles (#1738, phase 2), avec un VRAI GnuPG.

- seule une clé PUBLIQUE, unique, valide et qui chiffre, entre ;
- une adresse n'est « vérifiée » que si la box l'a confiée à la personne ;
- WKD ne sert que les adresses vérifiées ;
- les box liées échangent l'annuaire signé par la clé de box liée au did, et
  rien d'autre n'est accepté."""
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time

import pytest

from secubox_openpgp.personnes import Annuaire, RefusCle, hash_wkd, verifier_cle, zbase32
from secubox_openpgp.service import Refus

from test_echange import noeuds, parc  # noqa: F401 — fixtures partagées (deux box liées)

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg absent")

ALICE = "0b6e3c3a-7d0f-4c1e-9a55-3f2a1b8c9d10"
BOB = "4f1d2e3c-1a2b-4c3d-8e9f-0a1b2c3d4e5f"


class _Personne:
    """Une personne et SA paire de clés, dans un trousseau à elle."""

    def __init__(self, uid, chiffre=True):
        self.home = tempfile.mkdtemp(prefix="sbxpers-")
        os.chmod(self.home, 0o700)
        self.env = {**os.environ, "GNUPGHOME": self.home}
        g = ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run(g + ["--quick-gen-key", uid, "ed25519", "sign", "1y"], env=self.env, check=True,
                       capture_output=True)
        self.fpr = [l.split(":")[9] for l in subprocess.run(["gpg", "--with-colons", "--list-keys"], env=self.env,
                    capture_output=True, text=True).stdout.splitlines() if l.startswith("fpr:")][0]
        if chiffre:
            subprocess.run(g + ["--quick-add-key", self.fpr, "cv25519", "encr", "1y"], env=self.env, check=True,
                           capture_output=True)
        self.publique = subprocess.run(["gpg", "--armor", "--export", self.fpr], env=self.env,
                                       capture_output=True, text=True).stdout
        self.secrete = subprocess.run(g + ["--armor", "--export-secret-keys", self.fpr], env=self.env,
                                      capture_output=True, text=True).stdout

    def fin(self):
        subprocess.run(["gpgconf", "--kill", "all"], env=self.env, capture_output=True)
        shutil.rmtree(self.home, ignore_errors=True)


@pytest.fixture(scope="module")
def personnes():
    p = {"alice": _Personne("Alice <alice@secubox.in>"),
         "bob": _Personne("Bob <bob@secubox.in>"),
         "signe_seul": _Personne("Sans chiffrement <x@secubox.in>", chiffre=False)}
    yield p
    for x in p.values():
        x.fin()


@pytest.fixture
def sbx_db(tmp_path):
    db = tmp_path / "sbx.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE sbx_app_links (user_uuid TEXT, app TEXT, app_id TEXT, app_handle TEXT, "
                  "PRIMARY KEY (app, app_id))")
        c.execute("INSERT INTO sbx_app_links VALUES (?, 'email', 'alice@secubox.in', 'alice@secubox.in')", (ALICE,))
    return db


def test_seule_une_cle_publique_valide_qui_chiffre(personnes):
    k = verifier_cle(personnes["alice"].publique)
    assert k["empreinte"] == personnes["alice"].fpr and k["courriels"] == ["alice@secubox.in"]
    assert "PUBLIC KEY BLOCK" in k["armure"]
    for refus in (personnes["alice"].secrete, personnes["signe_seul"].publique,
                  personnes["alice"].publique + personnes["bob"].publique, "pas une clé", ""):
        with pytest.raises(RefusCle):
            verifier_cle(refus)


def test_adresse_verifiee_seulement_si_confiee(tmp_path, sbx_db, personnes):
    a = Annuaire(tmp_path / "pgp", sbx_db=sbx_db)
    e = a.publier(ALICE, "alice", personnes["alice"].publique)
    assert e["verifies"] == ["alice@secubox.in"]
    # Bob publie une clé au nom de la boîte d'Alice : déclarée, jamais vérifiée.
    usurpation = _Personne("Faux <alice@secubox.in>")
    try:
        e2 = a.publier(BOB, "bob", usurpation.publique)
        assert e2["courriels"] == ["alice@secubox.in"] and e2["verifies"] == []
        lp = "alice"
        assert a.wkd("secubox.in", hash_wkd(lp)) is not None
        servie = a.wkd("secubox.in", hash_wkd(lp))
        assert usurpation.fpr.encode() not in servie and len(servie) > 50
    finally:
        usurpation.fin()


def test_wkd_binaire_de_la_bonne_cle(tmp_path, sbx_db, personnes):
    a = Annuaire(tmp_path / "pgp", sbx_db=sbx_db)
    a.publier(ALICE, "alice", personnes["alice"].publique)
    binaire = a.wkd("secubox.in", hash_wkd("alice"), "alice")
    r = subprocess.run(["gpg", "--show-keys", "--with-colons"], input=binaire, capture_output=True)
    assert personnes["alice"].fpr in r.stdout.decode()
    assert a.wkd("secubox.in", hash_wkd("bob")) is None
    assert a.wkd("autre.example", hash_wkd("alice")) is None
    assert len(hash_wkd("alice")) == 32 and set(hash_wkd("x")) <= set("ybndrfg8ejkmcpqxot1uwisza345h769")
    assert zbase32(b"\x00") == "yy"


def test_rotation_et_retrait(tmp_path, sbx_db, personnes):
    a = Annuaire(tmp_path / "pgp", sbx_db=sbx_db)
    a.publier(ALICE, "alice", personnes["alice"].publique)
    a.publier(ALICE, "alice", personnes["bob"].publique)          # nouvelle clé
    assert personnes["alice"].fpr in a.export()["retirees"]
    assert a.retirer(ALICE) == personnes["bob"].fpr
    assert a.mienne(ALICE) is None and personnes["bob"].fpr in a.export()["retirees"]
    with pytest.raises(RefusCle):
        a.publier("../x", "x", personnes["alice"].publique)


def test_echange_signe_entre_box_liees(parc, sbx_db, personnes):
    boxes, _, _, noeuds = parc
    a2 = boxes["gk2"].annuaire_cles()
    a2.sbx_db = sbx_db
    a2.publier(ALICE, "alice", personnes["alice"].publique)
    export = boxes["gk2"].export_annuaire()
    pair = boxes["gk3"].pairs()[noeuds["gk2"].did]
    assert boxes["gk3"].lire_annuaire_pair(pair, export) == 1
    [e] = boxes["gk3"].annuaire_cles().des_pairs()
    assert e["empreinte"] == personnes["alice"].fpr and e["origine"] == "gk2"
    assert e["verifies"] == ["alice@secubox.in"]
    assert "personne" not in json.dumps(e)                        # l'identifiant interne ne sort pas


def test_annuaire_d_un_pair_falsifie_ou_d_une_autre_box_refuse(parc, personnes):
    boxes, _, _, noeuds = parc
    export = boxes["gk2"].export_annuaire()
    pair_gk2 = boxes["gk3"].pairs()[noeuds["gk2"].did]
    altere = export.replace("A", "B", 1) if "A" in export[60:] else export[:-40] + export[-39:]
    with pytest.raises(Exception):
        boxes["gk3"].lire_annuaire_pair(pair_gk2, altere)
    # Signé par gk2, présenté comme venant de gkx (non liée) : refus.
    faux_pair = dict(pair_gk2, did=noeuds["gkx"].did, empreinte=noeuds["gkx"].empreinte,
                     cle_publique=noeuds["gkx"].tr.exporter_public(noeuds["gkx"].empreinte))
    with pytest.raises((Refus, Exception)):
        boxes["gk3"].lire_annuaire_pair(faux_pair, export)
    # Périmé.
    with pytest.raises(Refus):
        boxes["gk3"].lire_annuaire_pair(pair_gk2, export, maintenant=time.time() + 7200)


def test_rafraichir_par_le_maillage(parc, sbx_db, personnes):
    boxes, _, _, noeuds = parc
    a2 = boxes["gk2"].annuaire_cles()
    a2.sbx_db = sbx_db
    a2.publier(ALICE, "alice", personnes["alice"].publique)
    par_ip = {noeuds[n].ip: boxes[n] for n in boxes}
    bilan = boxes["gk3"].rafraichir_annuaires(obtenir=lambda ip: par_ip[ip].export_annuaire())
    assert bilan.get("gk2") == 1


# ── Autocrypt sortant (#1852, P2) : la table adresse → clé publique ──────────────────────────────────────────────────
def test_autocrypt_ne_sert_que_les_adresses_verifiees_et_des_cles_publiques(tmp_path, sbx_db, personnes):
    import base64
    a = Annuaire(tmp_path / "pgp", sbx_db=sbx_db)
    a.publier(ALICE, "alice", personnes["alice"].publique)
    usurpation = _Personne("Faux <alice@secubox.in>")
    try:
        a.publier(BOB, "bob", usurpation.publique)              # déclarée au nom d'Alice, jamais vérifiée
    finally:
        usurpation.fin()
    table = a.autocrypt()
    assert list(table) == ["alice@secubox.in"]
    binaire = base64.b64decode(table["alice@secubox.in"])
    r = subprocess.run(["gpg", "--show-keys", "--with-colons"], input=binaire, capture_output=True)
    sortie = r.stdout.decode()
    assert personnes["alice"].fpr in sortie and "\nsec:" not in "\n" + sortie and "\nssb:" not in "\n" + sortie
    assert "\n" not in table["alice@secubox.in"] and len(binaire) <= 6 * 1024


def test_autocrypt_omet_une_cle_expiree_et_vide_apres_retrait(tmp_path, sbx_db, personnes):
    a = Annuaire(tmp_path / "pgp", sbx_db=sbx_db)
    e = a.publier(ALICE, "alice", personnes["alice"].publique)
    assert a.autocrypt(maintenant=e["expire"] + 10) == {}
    assert a.autocrypt() != {}
    a.retirer(ALICE)
    assert a.autocrypt() == {}
