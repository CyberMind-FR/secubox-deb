# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Cœur cryptographique — algorithmes normalisés.

On ne teste pas AES ni X25519 : OpenSSL s'en charge, et les revérifier ici ne
prouverait rien. On teste ce que CE module ajoute, c'est-à-dire exactement là
où une erreur d'assemblage se logerait :

  * les clés directionnelles et les nonces compteur, qui sont la raison d'être
    du module ;
  * la liaison de domaine (deux usages, deux clés) ;
  * les refus explicites (clé de la mauvaise taille, ECDH avec soi-même) ;
  * la relecture des clés écrites AVANT ce module.
"""
import os

import pytest

from secubox_core.crypto.standard import Identity, Session, derive_key_material


def paire():
    return Identity.generate(), Identity.generate()


# ── Le canal fait ce qu'il annonce ───────────────────────────────────────────

def test_aller_retour_dans_les_deux_sens():
    A, B = paire()
    sa = Session.establish(A, B.public_bytes())
    sb = Session.establish(B, A.public_bytes())
    assert sb.decrypt(sa.encrypt(b"de A vers B")) == b"de A vers B"
    assert sa.decrypt(sb.encrypt(b"de B vers A")) == b"de B vers A"


def test_aad_authentifiee_mais_pas_chiffree():
    A, B = paire()
    sa = Session.establish(A, B.public_bytes())
    sb = Session.establish(B, A.public_bytes())
    scelle = sa.encrypt(b"corps", b"entete-visible")
    assert b"entete-visible" not in scelle          # pas chiffrée ≠ transmise
    assert sb.decrypt(scelle, b"entete-visible") == b"corps"
    with pytest.raises(ValueError):
        sb.decrypt(scelle, b"AUTRE-ENTETE")


def test_un_tiers_ne_lit_rien():
    A, B = paire()
    C = Identity.generate()
    scelle = Session.establish(A, B.public_bytes()).encrypt(b"secret")
    with pytest.raises(ValueError):
        Session.establish(C, A.public_bytes()).decrypt(scelle)


@pytest.mark.parametrize("position", [0, 5, 12, 20, -1])
def test_un_octet_modifie_est_rejete(position):
    """Le tag GCM doit attraper l'altération OÙ QU'ELLE SOIT — nonce compris."""
    A, B = paire()
    sa = Session.establish(A, B.public_bytes())
    sb = Session.establish(B, A.public_bytes())
    scelle = bytearray(sa.encrypt(b"charge utile de taille raisonnable"))
    scelle[position] ^= 0x01
    with pytest.raises(ValueError):
        sb.decrypt(bytes(scelle))


# ── Ce que le module APPORTE : nonces et directions ──────────────────────────

def test_les_nonces_ne_se_repetent_jamais():
    """C'est LA propriété qui justifie le compteur. Avec un nonce aléatoire on
    ne pourrait qu'espérer ; ici on constate."""
    A, B = paire()
    sa = Session.establish(A, B.public_bytes())
    vus = {sa.encrypt(b"m")[:12] for _ in range(2000)}
    assert len(vus) == 2000


def test_les_deux_sens_emploient_des_cles_differentes():
    """Sans clés directionnelles, deux compteurs partant de zéro sous la MÊME
    clé produiraient une réutilisation de nonce — la faute fatale d'AES-GCM.
    On vérifie donc qu'un message ne se déchiffre pas avec sa propre session."""
    A, B = paire()
    sa = Session.establish(A, B.public_bytes())
    scelle = sa.encrypt(b"pour B")
    with pytest.raises(ValueError):
        sa.decrypt(scelle)          # sa clé de réception n'est pas sa clé d'envoi


def test_meme_compteur_des_deux_cotes_sans_collision():
    """Les deux pairs chiffrent leur premier message : même nonce (0), clés
    différentes — donc aucun des deux ciphertexts n'est déchiffrable par
    l'autre clé, et la réutilisation de nonce est sans effet."""
    A, B = paire()
    sa = Session.establish(A, B.public_bytes())
    sb = Session.establish(B, A.public_bytes())
    a0, b0 = sa.encrypt(b"meme-clair"), sb.encrypt(b"meme-clair")
    assert a0[:12] == b0[:12] == (0).to_bytes(12, "big")
    assert a0[12:] != b0[12:]       # clés distinctes → chiffrés distincts


def test_le_plafond_d_invocations_est_refuse_et_non_franchi():
    A, B = paire()
    s = Session.establish(A, B.public_bytes())
    s._compteur = 2 ** 32 - 1
    s.encrypt(b"le dernier autorise")
    with pytest.raises(RuntimeError, match="plafond"):
        s.encrypt(b"celui de trop")


# ── Liaison de domaine ───────────────────────────────────────────────────────

def test_deux_sels_donnent_deux_canaux_etanches():
    A, B = paire()
    s1 = Session.establish(A, B.public_bytes(), salt=b"canal-1")
    s2 = Session.establish(B, A.public_bytes(), salt=b"canal-2")
    with pytest.raises(ValueError):
        s2.decrypt(s1.encrypt(b"m"))


def test_deux_info_donnent_deux_cles():
    A, B = paire()
    s1 = Session.establish(A, B.public_bytes(), info=b"usage-1")
    s2 = Session.establish(B, A.public_bytes(), info=b"usage-2")
    with pytest.raises(ValueError):
        s2.decrypt(s1.encrypt(b"m"))


def test_hkdf_separe_bien_les_domaines():
    secret = os.urandom(32)
    assert derive_key_material(secret, info=b"a") != derive_key_material(secret, info=b"b")
    assert derive_key_material(secret, salt=b"s1") != derive_key_material(secret, salt=b"s2")
    # Déterminisme : deux pairs doivent tomber sur la même clé.
    assert derive_key_material(secret, info=b"x") == derive_key_material(secret, info=b"x")


@pytest.mark.parametrize("mauvais", [b"", os.urandom(8)])
def test_hkdf_refuse_les_entrees_absurdes(mauvais):
    with pytest.raises(ValueError):
        derive_key_material(mauvais) if mauvais == b"" else \
            derive_key_material(mauvais, length=8)


# ── Confirmation de clé ──────────────────────────────────────────────────────

def test_confirmation_identique_des_deux_cotes():
    A, B = paire()
    sa = Session.establish(A, B.public_bytes(), salt=b"c")
    sb = Session.establish(B, A.public_bytes(), salt=b"c")
    assert Session.accorde(sa.confirmation(), sb.confirmation())


def test_confirmation_differe_si_la_session_differe():
    A, B = paire()
    C = Identity.generate()
    sa = Session.establish(A, B.public_bytes())
    sc = Session.establish(A, C.public_bytes())
    assert not Session.accorde(sa.confirmation(), sc.confirmation())


def test_confirmation_n_est_pas_une_cle_du_canal():
    """Publier la confirmation ne doit rien livrer du matériel de chiffrement."""
    A, B = paire()
    s = Session.establish(A, B.public_bytes())
    c = s.confirmation()
    assert c != s._empreinte
    assert s.confirmation(label=b"autre") != c


# ── Refus explicites ─────────────────────────────────────────────────────────

def test_ecdh_avec_soi_meme_est_refuse():
    A = Identity.generate()
    with pytest.raises(ValueError, match="propre clé"):
        Session.establish(A, A.public_bytes())


@pytest.mark.parametrize("n", [0, 31, 33, 64])
def test_cle_publique_de_mauvaise_taille_refusee(n):
    A = Identity.generate()
    with pytest.raises(ValueError):
        Session.establish(A, os.urandom(n))


def test_message_tronque_refuse():
    A, B = paire()
    s = Session.establish(A, B.public_bytes())
    with pytest.raises(ValueError, match="trop court"):
        s.decrypt(os.urandom(12))       # nonce sans tag


# ── Identité ─────────────────────────────────────────────────────────────────

def test_signature_ed25519():
    A = Identity.generate(with_signing=True)
    sig = A.sign(b"message")
    assert Identity.verify(A.signing_public_bytes(), sig, b"message")
    assert not Identity.verify(A.signing_public_bytes(), sig, b"AUTRE message")


def test_pas_de_signature_sans_cle_de_signature():
    with pytest.raises(RuntimeError):
        Identity.generate().sign(b"m")


def test_export_de_cle_privee_verrouille():
    A = Identity.generate()
    with pytest.raises(RuntimeError, match="refusé"):
        A.to_private_bytes()
    assert len(A.to_private_bytes(allow_insecure_export=True)) == 32


def test_aller_retour_disque_et_permission(tmp_path):
    A = Identity.generate()
    p = A.save(tmp_path / "k.pem")
    assert oct(p.stat().st_mode)[-3:] == "600"
    assert Identity.load(p).public_bytes() == A.public_bytes()


def test_relit_une_cle_ecrite_avant_ce_module(tmp_path):
    """Les clés déjà sur les box sont du PKCS#8 PEM — le format n'a pas changé.
    Ce test EST la garantie de non-régression du parc installé."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    ancienne = X25519PrivateKey.generate()
    p = tmp_path / "primary_x25519.key"
    p.write_bytes(ancienne.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    rechargee = Identity.load(p)
    attendu = ancienne.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    assert rechargee.public_bytes() == attendu


def test_cle_protegee_par_phrase(tmp_path):
    A = Identity.generate()
    p = A.save(tmp_path / "k.pem", passphrase=b"phrase-secrete")
    with pytest.raises(TypeError):
        Identity.load(p)                       # sans la phrase
    assert Identity.load(p, passphrase=b"phrase-secrete").public_bytes() == A.public_bytes()
