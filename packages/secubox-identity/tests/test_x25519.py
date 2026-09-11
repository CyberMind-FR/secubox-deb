# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#1263 — X25519 device key : génération, persistance PEM, ECDH.

Teste la primitive utilisée par IdentityManager.ensure_x25519_pubkey sans
importer l'app (dont l'instanciation globale écrit sous /var/lib)."""
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


def _ensure(path):
    """Réplique ensure_x25519_pubkey : génère+persiste si absent, rend pubkey hex."""
    if os.path.exists(path):
        with open(path, "rb") as fh:
            priv = serialization.load_pem_private_key(fh.read(), password=None)
    else:
        priv = x25519.X25519PrivateKey.generate()
        with open(path, "wb") as fh:
            fh.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))
        os.chmod(path, 0o600)
    return priv, priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw).hex()


def test_x25519_keygen_persist_ecdh(tmp_path):
    p = str(tmp_path / "primary_x25519.key")
    priv1, pub1 = _ensure(p)
    assert len(bytes.fromhex(pub1)) == 32           # X25519 = 32 octets
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    _, pub2 = _ensure(p)                             # rechargé, pas régénéré
    assert pub1 == pub2                              # stable (persistant)
    # ECDH réel avec un pair : les deux dérivent le MÊME secret
    peer = x25519.X25519PrivateKey.generate()
    s_local = priv1.exchange(peer.public_key())
    s_peer = peer.exchange(
        x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(pub1)))
    assert s_local == s_peer and len(s_local) == 32
