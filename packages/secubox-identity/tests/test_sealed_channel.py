# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#1263 — Canal scellé device↔device (Session souveraine).

Teste le contrat exact que IdentityManager.seal_for/open_from délèguent à
secubox_core.crypto.Session (ECDH X25519 → HKDF-SHA256 → ChaCha20-Poly1305),
sans importer l'app (dont le singleton module-level écrit sous /var/lib).
Skippé si le cœur souverain n'est pas installé."""
import pytest

hermes = pytest.importorskip("secubox_core.crypto.hermes")


def _device_key(path):
    """Réplique la clé device : Identity.generate() + save() PEM 0600."""
    ident = hermes.Identity.generate()
    ident.save(path)
    return hermes.Identity.load(path)   # rechargée comme le fait le manager


def test_sealed_channel_roundtrip(tmp_path):
    A = _device_key(str(tmp_path / "a_x25519.key"))
    B = _device_key(str(tmp_path / "b_x25519.key"))
    msg = b"offre mirrornet scellee 2026"
    # A scelle pour B (seal_for) ; enveloppe = nonce(12) || ct || tag(16)
    sealed = hermes.Session.establish(A, B.public_bytes()).encrypt(msg)
    assert sealed != msg
    assert len(sealed) >= len(msg) + 12 + 16
    # B ouvre depuis A (open_from) — clé symétrique identique par ECDH
    got = hermes.Session.establish(B, A.public_bytes()).decrypt(sealed)
    assert got == msg


def test_sealed_channel_wrong_recipient(tmp_path):
    A = _device_key(str(tmp_path / "a.key"))
    B = _device_key(str(tmp_path / "b.key"))
    C = _device_key(str(tmp_path / "c.key"))
    sealed = hermes.Session.establish(A, B.public_bytes()).encrypt(b"secret")
    # Un tiers (C) ne dérive pas la bonne clé → tag Poly1305 invalide
    with pytest.raises(Exception):
        hermes.Session.establish(C, A.public_bytes()).decrypt(sealed)


def test_sealed_channel_aad_bound(tmp_path):
    A = _device_key(str(tmp_path / "a.key"))
    B = _device_key(str(tmp_path / "b.key"))
    sealed = hermes.Session.establish(A, B.public_bytes()).encrypt(b"x", b"contexte")
    # AAD différente à l'ouverture → rejet
    with pytest.raises(Exception):
        hermes.Session.establish(B, A.public_bytes()).decrypt(sealed, b"AUTRE")


def test_sealed_channel_salt_separates_keys(tmp_path):
    A = _device_key(str(tmp_path / "a.key"))
    B = _device_key(str(tmp_path / "b.key"))
    sealed = hermes.Session.establish(A, B.public_bytes(), salt=b"canal-1").encrypt(b"m")
    # Même paire, salt différent → clé différente → ne s'ouvre pas
    with pytest.raises(Exception):
        hermes.Session.establish(B, A.public_bytes(), salt=b"canal-2").decrypt(sealed)
    # Même salt → s'ouvre
    assert hermes.Session.establish(B, A.public_bytes(), salt=b"canal-1").decrypt(sealed) == b"m"
