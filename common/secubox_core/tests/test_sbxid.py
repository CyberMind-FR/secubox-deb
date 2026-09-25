# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SBX Identity Mesh — entités, capacités, double signature (#1417, AUTH v3 M1)."""
import copy
import os
import sqlite3
import sys
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from secubox_core import sbxid as S

GRAINE_O = "11" * 32          # nœud d'origine (GK4-3)
GRAINE_A = "22" * 32          # nœud d'accueil (GK4-2)
EMIS = "2026-09-25T08:00:00Z"


def _appareil(user):
    k = ec.generate_private_key(ec.SECP256R1())
    pt = k.public_key().public_bytes(serialization.Encoding.X962,
                                     serialization.PublicFormat.UncompressedPoint).hex()
    return k, S.Device(str(uuid.uuid4()), user.user_uuid, pt, name="iPhone", kind="iphone")


@pytest.fixture
def monde():
    noeud = S.Node.depuis_cle(S.pub_noeud(GRAINE_O))
    u = S.User(str(uuid.uuid4()), noeud.did, "gandalf", roles=["sbx_operator", "moderator"],
               tier="association")
    k, d = _appareil(u)
    return noeud, u, k, d


def _certifie(noeud, u, k, d, **kw):
    c = S.nouveau_certificat("device", u, d, node=noeud, emis=EMIS, **kw)
    S.signe_par_la_personne(c, d, k)
    return S.contresigne_par_le_noeud(c, GRAINE_O)


# ── Capacités et invariants ───────────────────────────────────────────────
def test_aucune_capacite_systeme():
    for c in ("ssh.login", "sudo.all", "root", "system.config", "SSH.x"):
        with pytest.raises(S.Refus):
            S.valide_capacite(c)
    assert all(not c.startswith(("ssh", "sudo", "root", "system.")) for r in S.ROLES.values() for c in r)


def test_subscriber_est_derive_de_l_abonnement():
    assert "subscriber" not in S.roles_effectifs(["member", "subscriber"], "free")
    assert "subscriber" in S.roles_effectifs(["member"], "premium")
    assert "nextcloud.files" in S.capacites(["member"], "association")
    assert "nextcloud.files" not in S.capacites(["member"], "free")


def test_suspendu_n_a_plus_rien(monde):
    _, u, _, _ = monde
    u.status = "suspended"
    assert u.capacites == []


@pytest.mark.parametrize("nom", ["root", "gk2", "Admin", "operator"])
def test_un_compte_systeme_n_est_jamais_une_identite(nom):
    with pytest.raises(S.Refus):
        S.User(str(uuid.uuid4()), "did:plc:" + "0" * 32, nom)


def test_did_appareil_recalcule_depuis_la_cle(monde):
    _, _, _, d = monde
    assert d.did == "did:sbx:" + S.empreinte_cle(d.public_key)[:32]


def test_flottant_refuse():
    with pytest.raises(S.Refus):
        S.canonical_bytes({"poids": 0.5})


# ── Double signature ──────────────────────────────────────────────────────
def test_aller_retour(monde):
    noeud, u, k, d = monde
    c = _certifie(noeud, u, k, d)
    v = S.verifie_certificat(c, cle_noeud=noeud.pubkey, appareils={d.device_uuid: d},
                             maintenant="2026-10-01T00:00:00Z")
    assert v.valide, v.motif
    assert "pseudo" not in c.payload and "email" not in c.payload     # rien de personnel
    assert "ecdsa-p256" in S.en_yaml(c) and "ed25519" in S.en_yaml(c)


def test_le_noeud_ne_signe_pas_avant_la_personne(monde):
    noeud, u, _, d = monde
    c = S.nouveau_certificat("device", u, d, node=noeud, emis=EMIS)
    with pytest.raises(S.Refus):
        S.contresigne_par_le_noeud(c, GRAINE_O)


def test_un_autre_noeud_ne_certifie_pas(monde):
    noeud, u, k, d = monde
    c = S.nouveau_certificat("device", u, d, node=noeud, emis=EMIS)
    S.signe_par_la_personne(c, d, k)
    with pytest.raises(S.Refus):
        S.contresigne_par_le_noeud(c, GRAINE_A)


@pytest.mark.parametrize("alteration,motif", [
    (lambda c: c.payload["capabilities"].append("admin.users2"), "nœud"),
    (lambda c: c.payload.__setitem__("epoch", 99), "nœud"),
    (lambda c: setattr(c, "sig_user", "00" * 64), "nœud"),     # sig_user est couverte par le nœud
    (lambda c: setattr(c, "sig_node", ""), "nœud"),
])
def test_toute_alteration_est_refusee(monde, alteration, motif):
    noeud, u, k, d = monde
    c = _certifie(noeud, u, k, d)
    alteration(c)
    v = S.verifie_certificat(c, cle_noeud=noeud.pubkey, appareils={d.device_uuid: d},
                             maintenant="2026-10-01T00:00:00Z")
    assert not v.valide and motif in v.motif


def test_signature_de_la_personne_requise(monde):
    """Un nœud seul ne suffit pas : il ne peut pas forger la signature d'une personne."""
    noeud, u, k, d = monde
    c = S.nouveau_certificat("device", u, d, node=noeud, emis=EMIS)
    c.signer_device, c.sig_user = d.device_uuid, "ab" * 64      # fausse signature « personne »
    c.sig_node = S.signe_noeud(GRAINE_O, c.message_node())       # le nœud contresigne quand même
    v = S.verifie_certificat(c, cle_noeud=noeud.pubkey, appareils={d.device_uuid: d},
                             maintenant="2026-10-01T00:00:00Z")
    assert not v.valide and "personne" in v.motif


def test_appareil_revoque_ou_d_autrui(monde):
    noeud, u, k, d = monde
    c = _certifie(noeud, u, k, d)
    d.revoked_at = 1
    v = S.verifie_certificat(c, cle_noeud=noeud.pubkey, appareils={d.device_uuid: d},
                             maintenant="2026-10-01T00:00:00Z")
    assert not v.valide and "révoqué" in v.motif
    autre = S.User(str(uuid.uuid4()), noeud.did, "alice")
    k2, d2 = _appareil(autre)
    with pytest.raises(S.Refus):
        S.signe_par_la_personne(S.nouveau_certificat("device", u, d if not d.revoked_at else d, node=noeud, emis=EMIS), d2, k2)


def test_epoque_et_echeance(monde):
    noeud, u, k, d = monde
    c = _certifie(noeud, u, k, d)
    ap = {d.device_uuid: d}
    assert "époque" in S.verifie_certificat(c, cle_noeud=noeud.pubkey, appareils=ap, epoque_connue=2,
                                            maintenant="2026-10-01T00:00:00Z").motif
    assert "expiré" in S.verifie_certificat(c, cle_noeud=noeud.pubkey, appareils=ap,
                                            maintenant="2028-01-01T00:00:00Z").motif


# ── Migration : trois signatures ──────────────────────────────────────────
def test_migration_exige_les_deux_noeuds(monde):
    noeud, u, k, d = monde
    accueil = S.Node.depuis_cle(S.pub_noeud(GRAINE_A))
    c = S.nouveau_certificat("migration", u, d, node=noeud, emis=EMIS,
                             extra={"from_node": noeud.did, "to_node": accueil.did})
    S.signe_par_la_personne(c, d, k)
    S.contresigne_par_le_noeud(c, GRAINE_O)
    ap = {d.device_uuid: d}
    v = S.verifie_certificat(c, cle_noeud=noeud.pubkey, cle_noeud_2=accueil.pubkey, appareils=ap,
                             maintenant="2026-10-01T00:00:00Z")
    assert not v.valide and "accueil" in v.motif               # l'accueil n'a pas encore signé
    with pytest.raises(S.Refus):
        S.contresigne_migration(c, GRAINE_O)                    # l'origine ne peut pas signer pour l'accueil
    S.contresigne_migration(c, GRAINE_A)
    v = S.verifie_certificat(c, cle_noeud=noeud.pubkey, cle_noeud_2=accueil.pubkey, appareils=ap,
                             maintenant="2026-10-01T00:00:00Z")
    assert v.valide, v.motif


# ── Interopérabilité avec l'annuaire (le journal du maillage) ──────────────
def test_interop_annuaire(monde):
    racine = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(racine / "packages" / "secubox-annuaire"))
    crypto = pytest.importorskip("annuaire.crypto")
    noeud, u, k, d = monde
    c = _certifie(noeud, u, k, d)
    assert crypto.canonical_bytes(c.payload) == c.message_user()
    assert crypto.did_from_pubkey(bytes.fromhex(noeud.pubkey)) == noeud.did
    assert crypto.verify(noeud.pubkey, c.message_node(), c.sig_node)


# ── Schéma ────────────────────────────────────────────────────────────────
def test_schema_refuse_systeme_et_ssh(tmp_path):
    db = sqlite3.connect(tmp_path / "sbx.db")
    S.initialise(db)
    S.initialise(db)                                            # idempotent
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO sbx_capabilities VALUES ('ssh.login')")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO sbx_users (user_uuid,pseudo,home_node,created_at) VALUES ('x','gk2','n',0)")
    assert db.execute("SELECT count(*) FROM sbx_role_capabilities WHERE role_id='sbx_operator'").fetchone()[0] > 10
