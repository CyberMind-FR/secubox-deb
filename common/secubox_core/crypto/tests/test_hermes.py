# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""Tests du cœur crypto souverain hermes (secubox_core.crypto)."""

import os
import stat

import pytest
from cryptography.exceptions import InvalidTag

from secubox_core.crypto import Identity, Session, derive_key_material


# ── Keygen X25519 ─────────────────────────────────────────────────────────────
def test_keygen_x25519_pubkey_32_bytes():
    ident = Identity.generate()
    assert len(ident.public_bytes()) == 32
    assert len(ident.public_hex()) == 64
    # Deux identités générées diffèrent.
    assert Identity.generate().public_bytes() != ident.public_bytes()


def test_from_to_private_bytes_roundtrip():
    ident = Identity.generate()
    raw = ident.to_private_bytes(allow_insecure_export=True)
    assert len(raw) == 32
    reborn = Identity.from_private_bytes(raw)
    assert reborn.public_bytes() == ident.public_bytes()


def test_private_export_locked_by_default():
    ident = Identity.generate()
    with pytest.raises(PermissionError):
        ident.to_private_bytes()


def test_from_private_bytes_rejects_bad_length():
    with pytest.raises(ValueError):
        Identity.from_private_bytes(b"\x00" * 31)


# ── Persistance 0600 + reload stable ──────────────────────────────────────────
def test_save_load_stable_and_0600(tmp_path):
    ident = Identity.generate()
    path = tmp_path / "device.pem"
    ident.save(path)
    # Permission 0600 exactement.
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"attendu 0600, obtenu {oct(mode)}"
    # Reload stable : même clé publique.
    reloaded = Identity.load(path)
    assert reloaded.public_bytes() == ident.public_bytes()


def test_save_load_encrypted(tmp_path):
    ident = Identity.generate()
    path = tmp_path / "device-enc.pem"
    ident.save(path, password=b"s3cr3t")
    reloaded = Identity.load(path, password=b"s3cr3t")
    assert reloaded.public_bytes() == ident.public_bytes()


# ── ECDH : deux identités dérivent le MÊME secret ─────────────────────────────
def test_ecdh_shared_key_matches():
    alice = Identity.generate()
    bob = Identity.generate()
    info = b"secubox-test/ecdh"
    salt = os.urandom(16)
    s_alice = Session.establish(alice, bob.public_bytes(), info=info, salt=salt)
    s_bob = Session.establish(bob, alice.public_bytes(), info=info, salt=salt)
    # Vérifié via round-trip croisé : Alice chiffre, Bob déchiffre.
    msg = b"canal etabli"
    assert s_bob.decrypt(s_alice.encrypt(msg)) == msg
    assert s_alice.decrypt(s_bob.encrypt(msg)) == msg


def test_ecdh_accepts_pubkey_object():
    alice = Identity.generate()
    bob = Identity.generate()
    s1 = Session.establish(alice, bob.public_key, info=b"i")
    s2 = Session.establish(bob, alice.public_key, info=b"i")
    m = b"objet cle publique"
    assert s2.decrypt(s1.encrypt(m)) == m


def test_ecdh_different_info_diverges():
    alice = Identity.generate()
    bob = Identity.generate()
    s1 = Session.establish(alice, bob.public_bytes(), info=b"ctx-A")
    s2 = Session.establish(bob, alice.public_bytes(), info=b"ctx-B")
    ct = s1.encrypt(b"hello")
    with pytest.raises(InvalidTag):
        s2.decrypt(ct)


# ── Round-trip ChaCha20-Poly1305 (+ échec AAD / altération) ───────────────────
def _session():
    a = Identity.generate()
    b = Identity.generate()
    return Session.establish(a, b.public_bytes(), info=b"rt")


def test_chacha_roundtrip_with_aad():
    s = _session()
    ct = s.encrypt(b"message secret", aad=b"header")
    assert s.decrypt(ct, aad=b"header") == b"message secret"


def test_chacha_roundtrip_empty_aad():
    s = _session()
    ct = s.encrypt(b"no aad")
    assert s.decrypt(ct) == b"no aad"


def test_chacha_wrong_aad_fails():
    s = _session()
    ct = s.encrypt(b"data", aad=b"good")
    with pytest.raises(InvalidTag):
        s.decrypt(ct, aad=b"bad")


def test_chacha_tampered_ciphertext_fails():
    s = _session()
    ct = bytearray(s.encrypt(b"data"))
    ct[-1] ^= 0x01  # altère le tag
    with pytest.raises(InvalidTag):
        s.decrypt(bytes(ct))


def test_chacha_nonce_is_random():
    s = _session()
    # Deux chiffrements du même clair diffèrent (nonce aléatoire).
    assert s.encrypt(b"same") != s.encrypt(b"same")


def test_decrypt_too_short():
    s = _session()
    with pytest.raises(ValueError):
        s.decrypt(b"short")


# ── derive_key_material déterministe ──────────────────────────────────────────
def test_derive_key_material_deterministic():
    secret = b"\x02" * 32
    k1 = derive_key_material(secret, info=b"ctx", length=32, salt=b"salt")
    k2 = derive_key_material(secret, info=b"ctx", length=32, salt=b"salt")
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_material_context_separation():
    secret = b"\x03" * 32
    assert derive_key_material(secret, info=b"A") != derive_key_material(
        secret, info=b"B"
    )


def test_derive_key_material_length_and_validation():
    secret = b"\x04" * 32
    assert len(derive_key_material(secret, info=b"x", length=64)) == 64
    with pytest.raises(ValueError):
        derive_key_material(secret, info=b"x", length=0)


# ── Signature Ed25519 optionnelle ─────────────────────────────────────────────
def test_optional_ed25519_signature():
    ident = Identity.generate(with_signing=True)
    assert ident.has_signing_key
    sig = ident.sign(b"payload")
    assert Identity.verify(ident.signing_public_bytes(), sig, b"payload")
    assert not Identity.verify(ident.signing_public_bytes(), sig, b"altered")


def test_no_signing_key_by_default():
    ident = Identity.generate()
    assert not ident.has_signing_key
    with pytest.raises(ValueError):
        ident.sign(b"x")
