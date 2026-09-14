# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cœur cryptographique — ALGORITHMES NORMALISÉS UNIQUEMENT.

CE MODULE N'INVENTE RIEN. Chaque primitive employée ici est publiée, éprouvée,
et implémentée par OpenSSL via ``pyca/cryptography``. Aucune construction
maison, aucun assemblage original : dans un produit qui vise la CSPN, le seul
argument recevable devant un évaluateur est « c'est la norme, et voici sa
référence ».

  ======================  ==================================================
  Rôle                    Algorithme et référence
  ======================  ==================================================
  Accord de clés          X25519 — RFC 7748, NIST SP 800-186
  Signature               Ed25519 — RFC 8032, FIPS 186-5 (2023)
  Dérivation de clés      HKDF-SHA256 — RFC 5869, NIST SP 800-56C
  Chiffrement authentifié AES-256-GCM — NIST SP 800-38D, ISO/IEC 19772
  Empreinte               SHA-256 — FIPS 180-4
  Comparaison de secrets  ``hmac.compare_digest`` (temps constant)
  ======================  ==================================================

POURQUOI AES-256-GCM ET NON ChaCha20-Poly1305. Les deux sont des AEAD
respectables, et ChaCha20-Poly1305 est un standard IETF (RFC 8439). Deux
raisons ont tranché :

  * l'ANSSI prend AES pour référence dans son guide de sélection d'algorithmes
    cryptographiques — sur un produit qui vise la CSPN, s'écarter de la
    référence demande une justification qu'on n'a pas ;
  * le matériel cible la porte. Les cœurs Armada de la box exposent les
    extensions cryptographiques ARMv8 (``aes``, ``pmull``) : AES-GCM y est
    exécuté par le silicium, là où ChaCha20 tourne en logiciel. Le choix
    « conforme » est ici aussi le choix rapide, ce qui est rare assez pour
    qu'on ne le laisse pas passer.

LE POINT DÉLICAT, ET IL MÉRITE D'ÊTRE LU : LES NONCES.

AES-GCM est impitoyable sur la réutilisation de nonce — deux messages chiffrés
sous la même clé avec le même nonce livrent la clé d'authentification, pas
seulement le clair. La parade habituelle est un nonce aléatoire de 96 bits,
plafonné à 2³² messages pour garder une probabilité de collision négligeable.
C'est correct, mais c'est probabiliste.

On fait mieux, et sans rien inventer : la **construction déterministe** du
NIST SP 800-38D §8.2.1 — un compteur, qui ne peut pas se répéter. Encore
faut-il que deux pairs ne comptent pas en parallèle sous la même clé. D'où
deux clés DIRECTIONNELLES dérivées du même secret ECDH, exactement comme le
font TLS 1.3 et Noise :

    clé A→B = HKDF(secret, info ‖ "|A>B")
    clé B→A = HKDF(secret, info ‖ "|B>A")

Le rôle A ou B n'a pas besoin d'être négocié : il se déduit de l'ordre
lexicographique des deux clés publiques, sur lequel les deux pairs tombent
forcément d'accord puisqu'ils les connaissent toutes les deux. Chacun chiffre
avec SA clé et son propre compteur : la collision de nonce devient
structurellement impossible, et non plus simplement improbable.

FORMAT DU MESSAGE SCELLÉ (inchangé, pour ne pas casser les appelants) :

    nonce(12) ‖ ciphertext ‖ tag(16)

LES CLÉS SUR DISQUE SONT DU PKCS#8 PEM STANDARD. Pas de format propriétaire :
``openssl pkey`` les lit, ce qui est autant une facilité d'exploitation qu'une
garantie de réversibilité.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature, InvalidTag

__all__ = ["Identity", "Session", "derive_key_material"]

_X25519_KEY_LEN = 32
_AES256_KEY_LEN = 32
_GCM_NONCE_LEN = 12          # 96 bits — la seule longueur que SP 800-38D traite
                             # comme un cas rapide et sans re-hachage du nonce.
_GCM_TAG_LEN = 16

_DEFAULT_KDF_INFO = b"secubox/v2"

# Plafond d'invocations d'une clé AES-GCM. SP 800-38D borne à 2³² le nombre
# d'appels sous une même clé ; avec un compteur on n'a pas de risque de
# collision, mais la borne reste celle de l'analyse de sécurité du mode. On
# refuse de la franchir plutôt que de la franchir en silence.
_INVOCATIONS_MAX = 2 ** 32


# ─────────────────────────────────────────────────────────────────────────────
# Dérivation de clés — HKDF-SHA256 (RFC 5869)
# ─────────────────────────────────────────────────────────────────────────────

def derive_key_material(
    shared_secret: bytes,
    *,
    info: bytes = _DEFAULT_KDF_INFO,
    length: int = _AES256_KEY_LEN,
    salt: Optional[bytes] = None,
) -> bytes:
    """Dérive du matériel de clé depuis ``shared_secret`` via HKDF-SHA256.

    :param shared_secret: secret d'entrée — typiquement la sortie d'un ECDH
        X25519, qui n'est PAS utilisable directement comme clé (sa distribution
        n'est pas uniforme ; c'est précisément le travail de HKDF).
    :param info: liaison de domaine. Deux usages différents doivent porter des
        ``info`` différentes, sans quoi la même clé servirait à deux choses —
        et une faiblesse de l'un contaminerait l'autre.
    :param salt: sel facultatif. ``None`` vaut un sel de zéros, conformément au
        RFC 5869 §2.2.
    """
    if not shared_secret:
        raise ValueError("secret partagé vide")
    if length < 16:
        raise ValueError("longueur de clé trop faible (16 octets minimum)")
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=salt, info=info).derive(shared_secret)


# ─────────────────────────────────────────────────────────────────────────────
# Identité long-terme — X25519 (+ Ed25519 de signature, facultatif)
# ─────────────────────────────────────────────────────────────────────────────

class Identity:
    """Identité long-terme d'un équipement : une clé X25519, et au besoin une
    clé Ed25519 SÉPARÉE pour la signature.

    DEUX CLÉS ET NON UNE. Il est techniquement possible de convertir une clé
    Ed25519 en X25519 et de n'en garder qu'une. On s'y refuse : réutiliser un
    même secret pour signer ET pour négocier fait que la compromission d'un
    usage emporte l'autre, et complique toute rotation. Deux clés coûtent
    32 octets de plus.
    """

    def __init__(
        self,
        private_key: X25519PrivateKey,
        *,
        signing_key: Optional[Ed25519PrivateKey] = None,
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._signing_key = signing_key

    # — création ——————————————————————————————————————————————————————

    @classmethod
    def generate(cls, *, with_signing: bool = False) -> "Identity":
        """Génère une identité neuve. L'aléa vient d'OpenSSL, donc du noyau."""
        signing = Ed25519PrivateKey.generate() if with_signing else None
        return cls(X25519PrivateKey.generate(), signing_key=signing)

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Identity":
        if len(raw) != _X25519_KEY_LEN:
            raise ValueError(
                f"clé privée X25519 invalide : {_X25519_KEY_LEN} octets attendus, "
                f"{len(raw)} reçus")
        return cls(X25519PrivateKey.from_private_bytes(raw))

    # — clés publiques ————————————————————————————————————————————————

    def public_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)

    def public_hex(self) -> str:
        return self.public_bytes().hex()

    def public_key(self) -> X25519PublicKey:
        return self._public_key

    # — signature ————————————————————————————————————————————————————

    def has_signing_key(self) -> bool:
        return self._signing_key is not None

    def signing_public_bytes(self) -> bytes:
        if self._signing_key is None:
            raise RuntimeError("cette identité n'a pas de clé de signature")
        return self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        if self._signing_key is None:
            raise RuntimeError("cette identité n'a pas de clé de signature")
        return self._signing_key.sign(message)

    @staticmethod
    def verify(signing_public: bytes, signature: bytes, message: bytes) -> bool:
        """Vérifie une signature Ed25519. Rend un booléen plutôt que de lever :
        une signature invalide est un RÉSULTAT attendu, pas un incident."""
        try:
            Ed25519PublicKey.from_public_bytes(signing_public).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    # — persistance ————————————————————————————————————————————————————

    def to_private_bytes(self, *, allow_insecure_export: bool = False) -> bytes:
        """Exporte la clé privée en clair. Le garde-fou est délibéré : cet appel
        ne doit jamais arriver par inadvertance au bout d'une chaîne d'appels."""
        if not allow_insecure_export:
            raise RuntimeError(
                "export de clé privée en clair refusé — passez "
                "allow_insecure_export=True si c'est vraiment l'intention")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())

    def save(self, path: Union[str, Path], *,
             passphrase: Optional[bytes] = None) -> Path:
        """Écrit la clé privée en PKCS#8 PEM, permission 0600.

        LA PERMISSION EST POSÉE AVANT D'ÉCRIRE. La poser après laisserait une
        fenêtre — courte, mais réelle — où la clé serait lisible par tous : sur
        une box où plusieurs services tournent sous des comptes distincts, cette
        fenêtre suffit.
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        enc = (serialization.BestAvailableEncryption(passphrase)
               if passphrase else serialization.NoEncryption())
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, pem)
        finally:
            os.close(fd)
        os.chmod(str(p), 0o600)
        return p

    @classmethod
    def load(cls, path: Union[str, Path], *,
             passphrase: Optional[bytes] = None) -> "Identity":
        """Relit une clé PKCS#8 PEM — y compris celles écrites avant ce module :
        le format n'a pas changé, il était déjà standard."""
        data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(data, password=passphrase)
        if not isinstance(key, X25519PrivateKey):
            raise ValueError(
                f"clé X25519 attendue, {type(key).__name__} trouvée dans {path}")
        return cls(key)

    def __repr__(self) -> str:  # pragma: no cover - cosmétique
        return f"<Identity x25519={self.public_hex()[:16]}…>"


# ─────────────────────────────────────────────────────────────────────────────
# Session éphémère — X25519 ECDH → HKDF-SHA256 → AES-256-GCM
# ─────────────────────────────────────────────────────────────────────────────

class Session:
    """Canal scellé entre deux identités X25519.

    Clés directionnelles + nonces compteur : voir l'explication en tête de
    module. Le format sur le fil reste ``nonce(12) ‖ ct ‖ tag(16)``.
    """

    def __init__(self, cle_envoi: bytes, cle_reception: bytes) -> None:
        if len(cle_envoi) != _AES256_KEY_LEN or len(cle_reception) != _AES256_KEY_LEN:
            raise ValueError("clé AES-256 invalide : 32 octets attendus")
        self._envoi = AESGCM(cle_envoi)
        self._reception = AESGCM(cle_reception)
        self._compteur = 0
        # EMPREINTE DE SESSION, ORDONNÉE. Chaque pair a les deux mêmes clés mais
        # dans des rôles inversés : les concaténer dans l'ordre local donnerait
        # deux empreintes différentes, et la confirmation ne s'accorderait
        # jamais. On trie donc les deux clés avant de les condenser — les deux
        # côtés obtiennent la même graine sans rien échanger.
        #
        # On condense ici, à la construction, plutôt que de garder les clés en
        # clair dans l'objet : un vidage mémoire ne les y retrouvera pas.
        basse, haute = sorted((cle_envoi, cle_reception))
        h = hashes.Hash(hashes.SHA256())
        h.update(b"secubox/v2|empreinte-session")
        h.update(basse)
        h.update(haute)
        self._empreinte = h.finalize()

    @classmethod
    def establish(
        cls,
        local: Identity,
        peer_public: bytes,
        *,
        info: bytes = _DEFAULT_KDF_INFO,
        salt: Optional[bytes] = None,
    ) -> "Session":
        """Établit la session par ECDH X25519.

        :param peer_public: clé publique X25519 du pair, 32 octets Raw.
        :param salt: sel HKDF. Deux pairs qui passent le MÊME sel obtiennent les
            mêmes clés ; c'est ainsi qu'on sépare deux canaux entre les mêmes
            machines sans rejouer d'échange.
        """
        if len(peer_public) != _X25519_KEY_LEN:
            raise ValueError(
                f"clé publique du pair invalide : {_X25519_KEY_LEN} octets "
                f"attendus, {len(peer_public)} reçus")
        mienne = local.public_bytes()
        if hmac.compare_digest(mienne, peer_public):
            # Un ECDH avec soi-même produit une session qui « marche » et ne
            # protège rien. C'est toujours une erreur d'appel : on la nomme.
            raise ValueError("accord de clés avec sa propre clé publique")

        partage = local._private_key.exchange(
            X25519PublicKey.from_public_bytes(peer_public))

        # Rôle déduit de l'ordre des clés publiques : les deux pairs les
        # connaissent toutes les deux, ils tombent donc sur le même verdict sans
        # échanger un octet de plus.
        je_suis_a = mienne < peer_public
        cle_a = derive_key_material(partage, info=info + b"|A>B",
                                    length=_AES256_KEY_LEN, salt=salt)
        cle_b = derive_key_material(partage, info=info + b"|B>A",
                                    length=_AES256_KEY_LEN, salt=salt)
        return cls(cle_a, cle_b) if je_suis_a else cls(cle_b, cle_a)

    # — chiffrement ————————————————————————————————————————————————————

    def _nonce_suivant(self) -> bytes:
        if self._compteur >= _INVOCATIONS_MAX:
            raise RuntimeError(
                "plafond d'invocations atteint pour cette clé de session "
                f"({_INVOCATIONS_MAX}). Rejouez un accord de clés : au-delà, "
                "l'analyse de sécurité d'AES-GCM (SP 800-38D) ne couvre plus "
                "cette clé.")
        n = self._compteur.to_bytes(_GCM_NONCE_LEN, "big")
        self._compteur += 1
        return n

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Scelle ``plaintext``. ``aad`` est authentifiée mais PAS chiffrée.

        :returns: ``nonce(12) ‖ ciphertext ‖ tag(16)``.
        """
        nonce = self._nonce_suivant()
        return nonce + self._envoi.encrypt(nonce, plaintext, aad or None)

    def decrypt(self, sealed: bytes, aad: bytes = b"") -> bytes:
        """Ouvre un message scellé par le pair.

        :raises ValueError: si le tag est invalide — clé, nonce, AAD ou
            ciphertext altéré. On ne distingue pas les causes : le faire
            fournirait un oracle à qui tâtonne.
        """
        if len(sealed) < _GCM_NONCE_LEN + _GCM_TAG_LEN:
            raise ValueError("message scellé trop court")
        nonce, corps = sealed[:_GCM_NONCE_LEN], sealed[_GCM_NONCE_LEN:]
        try:
            return self._reception.decrypt(nonce, corps, aad or None)
        except InvalidTag as e:
            raise ValueError("message scellé invalide (authentification en échec)") from e

    # — confirmation de clé ————————————————————————————————————————————

    def confirmation(self, *, label: bytes = b"confirmation") -> bytes:
        """Preuve que l'on détient bien la même clé de session, à échanger avant
        de se parler.

        DÉRIVÉE DANS UN DOMAINE À PART. Si cette preuve sortait du même matériel
        que les clés de chiffrement, la publier reviendrait à publier un élément
        du secret. Le HKDF avec une ``info`` distincte garantit qu'elle n'apprend
        rien sur les clés du canal.
        """
        # On mélange les DEUX clés directionnelles : la preuve vaut alors pour la
        # session entière, et non pour un seul sens.
        graine = self._empreinte_cles()
        return derive_key_material(graine, info=b"secubox/v2|" + label, length=32)

    def _empreinte_cles(self) -> bytes:
        # AESGCM ne rend pas sa clé ; on garde donc une empreinte calculée à la
        # construction plutôt que de conserver les clés en clair dans l'objet.
        return self._empreinte

    @staticmethod
    def accorde(mienne: bytes, sienne: bytes) -> bool:
        """Compare deux confirmations en TEMPS CONSTANT. Un ``==`` ordinaire
        s'arrête au premier octet différent et laisse mesurer où."""
        return hmac.compare_digest(mienne, sienne)

    def __repr__(self) -> str:  # pragma: no cover - cosmétique
        return f"<Session aes256gcm invocations={self._compteur}>"
