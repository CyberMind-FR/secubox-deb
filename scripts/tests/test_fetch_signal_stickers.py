# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for scripts/fetch-signal-stickers.py (crypto + protobuf, hors réseau)."""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "fetch-signal-stickers.py"
_spec = importlib.util.spec_from_file_location("fss", _SCRIPT)
fss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fss)


def test_hkdf_longueur_et_determinisme():
    ikm, salt, info = b"\x01" * 32, b"\x00" * 32, b"Sticker Pack"
    a = fss.hkdf_sha256(ikm, salt, info, 64)
    b = fss.hkdf_sha256(ikm, salt, info, 64)
    assert len(a) == 64 and a == b
    # Le préfixe d'une dérivation plus courte est identique (propriété HKDF).
    assert fss.hkdf_sha256(ikm, salt, info, 32) == a[:32]


def test_decrypt_roundtrip():
    """decrypt() récupère un blob chiffré [IV][AES-256-CBC][HMAC] avec les clés
    dérivées de la pack_key — c'est exactement le format Signal."""
    pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key_hex = "aa" * 32
    dk = fss.hkdf_sha256(bytes.fromhex(key_hex), b"\x00" * 32, b"Sticker Pack", 64)
    aes_key, hmac_key = dk[:32], dk[32:]
    plaintext = b"bonjour signal - zanimalos"
    pad = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad]) * pad
    iv = b"\x11" * 16
    enc = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac.new(hmac_key, iv + ct, hashlib.sha256).digest()

    assert fss.decrypt(iv + ct + mac, key_hex) == plaintext

    # HMAC falsifié → refus (intégrité vérifiée avant déchiffrement).
    with pytest.raises(ValueError):
        fss.decrypt(iv + ct + (b"\x00" * 32), key_hex)


def _tag(field, wt):
    return bytes([(field << 3) | wt])


def _lenpref(field, payload):
    return _tag(field, 2) + bytes([len(payload)]) + payload


def test_parse_pack_et_stickers():
    sticker = _tag(1, 0) + bytes([7]) + _lenpref(2, "🙂".encode())  # id=7, emoji=🙂
    pb = (_lenpref(1, b"zanimalos")      # title
          + _lenpref(2, b"G.Kerma")      # author
          + _lenpref(4, sticker)         # one sticker
          + _lenpref(4, _tag(1, 0) + bytes([3]) + _lenpref(2, "🫡".encode())))
    pack = fss.parse_pack(pb)
    assert pack["title"] == "zanimalos"
    assert pack["author"] == "G.Kerma"
    assert [(s["id"], s["emoji"]) for s in pack["stickers"]] == [(7, "🙂"), (3, "🫡")]


def test_parse_map():
    assert fss.parse_map("published=6,draft=2,archived=9") == {
        "published": 6, "draft": 2, "archived": 9}
    assert fss.parse_map("") == {}


def test_ext_detection():
    assert fss._ext(b"\x89PNG\r\n\x1a\n....") == "png"
    assert fss._ext(b"RIFF\x00\x00\x00\x00WEBP....") == "webp"
    assert fss._ext(b"not an image") == "bin"
