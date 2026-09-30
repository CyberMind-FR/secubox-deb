# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Échange signé et chiffré entre box, avec un VRAI GnuPG (#1736).

Trois box : A et B liées dans l'annuaire (openpgp_bind signé par leur
node.key), D qui a une clé OpenPGP mais aucune liaison — l'imposteur."""
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from annuaire import verbs
from annuaire.crypto import did_from_pubkey, public_from_private
from annuaire.log import Journal
from secubox_openpgp import enveloppe
from secubox_openpgp.gpg import ErreurGpg, Trousseau
from secubox_openpgp.service import Box, Refus

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg absent")


class _Noeud:
    def __init__(self, nom, ip):
        self.nom, self.ip = nom, ip
        self.priv = os.urandom(32)
        self.did = did_from_pubkey(public_from_private(self.priv))
        self.home = tempfile.mkdtemp(prefix=f"sbxpgp-{nom}-")
        os.chmod(self.home, 0o700)
        self.tr = Trousseau(self.home)
        self.empreinte = self.tr.generer(f"SecuBox {nom} ({self.did})")


@pytest.fixture(scope="module")
def noeuds():
    ns = {n: _Noeud(n, ip) for n, ip in (("gk2", "10.10.0.1"), ("gk3", "10.10.0.5"), ("gkx", "10.10.0.9"))}
    yield ns
    for n in ns.values():
        subprocess.run(["gpgconf", "--homedir", n.home, "--kill", "all"], capture_output=True)
        shutil.rmtree(n.home, ignore_errors=True)


@pytest.fixture
def parc(noeuds, tmp_path):
    """Annuaire commun : gk2 et gk3 publient fiche de nœud + liaison ; gkx non."""
    j = Journal(str(tmp_path / "journal.db"))
    for n in noeuds.values():
        verbs.genesis(j, n.priv)
        verbs.publish_node(j, n.priv, n.did, node_id=f"sb-{n.nom}", boxname=n.nom,
                           pubkey_wg="x" * 44, mesh_ip=n.ip, ddns=f"{n.nom}.secubox.in")
    for nom in ("gk2", "gk3"):
        n = noeuds[nom]
        verbs.openpgp_bind(j, n.priv, n.empreinte, n.tr.exporter_public(n.empreinte),
                           creee=int(time.time()), expire=0)
    boxes = {nom: Box(trousseau=n.tr, did=n.did, racine=tmp_path / nom,
                      lire_annuaire=lambda: verbs.export_entries(j))
             for nom, n in noeuds.items()}
    for b in boxes.values():
        b.racine.mkdir()
    # Le « réseau » : un dépôt chez le destinataire, par son adresse maillée.
    par_ip = {noeuds[nom].ip: boxes[nom] for nom in boxes}

    def poster(ip, corps):
        try:
            par_ip[ip].deposer(corps.decode())
            return 201
        except Refus:
            return 422
    return boxes, j, poster, noeuds


def test_aller_retour_gk2_vers_gk3(parc):
    boxes, _, poster, noeuds = parc
    r = boxes["gk2"].envoyer("gk3", "essai", "bonjour gk3", poster=poster)
    assert r["ok"] and r["boxname"] == "gk3"
    [m] = boxes["gk3"].lister()
    assert m["de"] == noeuds["gk2"].did and m["empreinte"] == noeuds["gk2"].empreinte
    lu = boxes["gk3"].lire(m["id"])
    assert (lu["objet"], lu["contenu"]) == ("essai", "bonjour gk3")
    # Et dans l'autre sens.
    boxes["gk3"].envoyer(noeuds["gk2"].did, "retour", "bien reçu", poster=poster)
    assert boxes["gk2"].lire(boxes["gk2"].lister()[0]["id"])["contenu"] == "bien reçu"


def test_conserve_chiffre_jamais_en_clair(parc):
    boxes, _, poster, _ = parc
    boxes["gk2"].envoyer("gk3", "secret", "phrase-témoin-unique", poster=poster)
    for f in (boxes["gk3"].racine / "boite").iterdir():
        assert "phrase-témoin-unique" not in f.read_text()
        assert oct(f.stat().st_mode & 0o777) == "0o600"


def test_message_altere_refuse(parc):
    boxes, _, _, _ = parc
    a = boxes["gk2"].preparer(boxes["gk2"].resoudre("gk3"), "o", "c")
    lignes = a.splitlines()
    i = len(lignes) // 2
    lignes[i] = lignes[i][:-2] + ("AA" if not lignes[i].endswith("AA") else "BB")
    with pytest.raises(Refus):
        boxes["gk3"].deposer("\n".join(lignes) + "\n")
    assert boxes["gk3"].lister() == []


def test_destine_a_une_autre_box(parc):
    """Chiffré pour gk2 mais déposé chez gk3 : illisible, refusé."""
    boxes, _, _, _ = parc
    a = boxes["gk3"].preparer(boxes["gk3"].resoudre("gk2"), "o", "c")
    with pytest.raises(Refus):
        boxes["gk3"].deposer(a)


def test_signataire_sans_liaison_refuse(parc):
    """gkx n'a aucune liaison : même en se disant gk2 dans l'enveloppe, et avec
    un message correctement chiffré pour gk3, il est refusé."""
    boxes, _, _, noeuds = parc
    gk3 = boxes["gk3"].resoudre("gk3", pairs={p["did"]: dict(p, soi=False)
                                               for p in boxes["gk3"].pairs().values()})
    x = noeuds["gkx"]
    x.tr.importer(gk3["cle_publique"], gk3["empreinte"])
    clair = enveloppe.construire(noeuds["gk2"].did, noeuds["gk3"].did, "faux", "je suis gk2")
    a = x.tr.chiffrer_signer(clair, pour=gk3["empreinte"], par=x.empreinte, usage="interbox")
    with pytest.raises(Refus):
        boxes["gk3"].deposer(a)


def test_rejeu_et_peremption(parc):
    boxes, _, _, _ = parc
    a = boxes["gk2"].preparer(boxes["gk2"].resoudre("gk3"), "o", "c")
    assert boxes["gk3"].deposer(a)["ok"]
    with pytest.raises(Refus):
        boxes["gk3"].deposer(a)                          # rejeu
    vieux = boxes["gk2"].preparer(boxes["gk2"].resoudre("gk3"), "o", "c",
                                  maintenant=time.time() - 3600)
    with pytest.raises(Refus):
        boxes["gk3"].deposer(vieux)                      # hors fenêtre


def test_revocation_coupe_l_expediteur(parc):
    boxes, j, poster, noeuds = parc
    a = boxes["gk2"].preparer(boxes["gk2"].resoudre("gk3"), "o", "avant")
    verbs.openpgp_revoke(j, noeuds["gk2"].priv, noeuds["gk2"].empreinte, "essai")
    with pytest.raises(Refus):
        boxes["gk3"].deposer(a)
    with pytest.raises(Refus):
        boxes["gk3"].envoyer("gk2", "o", "c", poster=poster)   # plus de pair lié


def test_importer_n_accepte_que_la_cle_liee(noeuds):
    gk2, gk3 = noeuds["gk2"], noeuds["gk3"]
    with pytest.raises(ErreurGpg):
        gk2.tr.importer(gk3.tr.exporter_public(gk3.empreinte), gk2.empreinte)


def test_pas_d_oracle_de_signature():
    """Aucune méthode ne signe des octets arbitraires : seulement une enveloppe."""
    assert not any(n in dir(Box) for n in ("signer", "sign", "dechiffrer", "decrypt"))
