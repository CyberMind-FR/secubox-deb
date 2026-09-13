# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""hermes — cœur cryptographique souverain de SecuBox.

Portage des primitives de ``anibaledel/livreedhermes`` vers un backend
souverain **enfichable au runtime**.

PROVENANCE EXACTE (corrigée au passage 5, 2026-09-13). L'en-tête citait
``stegano/crypto_core.py`` au commit ``d4abc757`` — or ce fichier
**n'existait pas** à ce commit : ``stegano/`` n'y contenait que
``stegano_lib.py``, dont ``crypto_core.py`` a été extrait plus tard
(scission ``f00548d1``). La base réelle du portage est donc
``stegano_lib.py`` @ ``d4abc757`` ; l'équivalent amont s'appelle
aujourd'hui ``stegano/crypto_core.py``. Revu contre l'amont à
``origin/main`` du 2026-09-13 (126 commits plus loin) : voir
``docs/audits/AUDIT-CRYPTO-livreedhermes.md``, passage 5.

Seules des primitives **standard et éprouvées** de la bibliothèque
``cryptography`` sont utilisées — aucune construction « maison » sur le
chemin critique. La couche géométrique de Hermes (Ref256 / Carter) est
délibérément **hors de ce module** : elle ne sert qu'à la diversification
de clé et ne revendique aucune propriété cryptographique.

L'API sépare trois responsabilités :

* :class:`Identity`       — identité **long-terme** d'un device (X25519,
  + Ed25519 optionnel pour la signature) ;
* :class:`Session`        — session **éphémère** entre deux pairs
  (**X25519 ECDH → HKDF-SHA256**), chiffrement authentifié
  **ChaCha20-Poly1305** ;
* :func:`derive_key_material` — wrapper **HKDF-SHA256**.

Règles de sécurité (rappel CSPN) :

* les clés privées ne sont **jamais exportées en clair par défaut** ;
* elles sont persistées en PEM avec permission **0600**, posée **à la
  création du descripteur** — jamais par un ``chmod`` après coup, qui
  laisserait le fichier lisible entre les deux (l'amont a corrigé cette
  même fenêtre de course en ``2eca5145`` ; notre portage ne l'a jamais
  eue) ;
* signature (Ed25519) et accord de clés (X25519) reposent sur **deux
  clés distinctes**.

Limites connues, énoncées plutôt que tues :

* :class:`Session` n'offre **aucune confirmation de clé implicite** — un
  pair qui dérive avec une mauvaise clé publique obtient une session
  d'apparence valide, et l'erreur ne se manifeste qu'au premier
  déchiffrement raté. :meth:`Session.confirmation` existe pour la
  détecter **tout de suite** ;
* le nonce ChaCha20-Poly1305 fait 96 bits et est **tiré au hasard** à
  chaque message : au-delà de ~2³² messages sous la même clé, le risque
  de collision cesse d'être négligeable. :meth:`Session.encrypt` refuse
  de franchir cette borne plutôt que de la dépasser en silence.
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
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["Identity", "Session", "derive_key_material"]

# Longueurs standard (octets).
_X25519_KEY_LEN = 32
_CHACHA_NONCE_LEN = 12  # ChaCha20-Poly1305 (RFC 8439) : nonce de 96 bits.
_CHACHA_TAG_LEN = 16
_DEFAULT_KDF_LEN = 32
_DEFAULT_KDF_INFO = b"secubox-hermes/v1"
# Budget de nonces d'une session (#1263). Nonce ALEATOIRE de 96 bits : la
# probabilité de collision suit la borne des anniversaires, donc ~2^-32 après
# 2^32 messages. On s'arrête AVANT plutôt que de continuer en silence — une
# session qui atteint ce volume doit être renégociée, pas prolongée.
_NONCE_BUDGET = 2 ** 32


# ─────────────────────────────────────────────────────────────────────────────
# Dérivation de clé — HKDF-SHA256
# ─────────────────────────────────────────────────────────────────────────────
def derive_key_material(
    shared_secret: bytes,
    info: bytes,
    length: int = _DEFAULT_KDF_LEN,
    salt: Optional[bytes] = None,
) -> bytes:
    """Dérive du matériel de clé depuis ``shared_secret`` via **HKDF-SHA256**.

    :param shared_secret: secret d'entrée (p. ex. la sortie d'un ECDH X25519).
    :param info: contexte de liaison de domaine (« info » HKDF) — deux
        contextes distincts produisent des clés indépendantes.
    :param length: longueur du matériel de clé produit, en octets (défaut 32).
    :param salt: sel optionnel (« salt » HKDF). ``None`` équivaut à un sel de
        zéros de la taille du hash, conformément à la RFC 5869.
    :returns: ``length`` octets déterministes pour des entrées identiques.
    :raises ValueError: si ``length`` n'est pas strictement positif.

    Déterministe : mêmes ``(shared_secret, info, length, salt)`` → même sortie.
    """
    if length <= 0:
        raise ValueError("length doit être strictement positif")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(shared_secret)


# ─────────────────────────────────────────────────────────────────────────────
# Identité long-terme — X25519 (+ Ed25519 optionnel)
# ─────────────────────────────────────────────────────────────────────────────
class Identity:
    """Identité **long-terme** d'un device, fondée sur une clé **X25519**.

    L'accord de clés (X25519) et la signature (Ed25519) reposent sur deux
    clés distinctes : la clé de signature est optionnelle et n'est présente
    que si l'identité a été générée avec ``with_signing=True`` (ou chargée
    depuis un PEM la contenant).

    La clé privée n'est **jamais exportée en clair par défaut** : voir
    :meth:`to_private_bytes` et :meth:`save`.
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

    # ── Construction ────────────────────────────────────────────────────────
    @classmethod
    def generate(cls, *, with_signing: bool = False) -> "Identity":
        """Génère une nouvelle identité X25519.

        :param with_signing: si vrai, génère en plus une clé de signature
            **Ed25519** distincte.
        """
        signing = Ed25519PrivateKey.generate() if with_signing else None
        return cls(X25519PrivateKey.generate(), signing_key=signing)

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Identity":
        """Reconstruit une identité depuis 32 octets de clé privée X25519 brute.

        :raises ValueError: si ``raw`` n'a pas exactement 32 octets.
        """
        if len(raw) != _X25519_KEY_LEN:
            raise ValueError(
                f"clé privée X25519 invalide : {len(raw)} octets, "
                f"{_X25519_KEY_LEN} attendus"
            )
        return cls(X25519PrivateKey.from_private_bytes(raw))

    # ── Clé publique ──────────────────────────────────────────────────────────
    def public_bytes(self) -> bytes:
        """Clé publique X25519 au format brut (32 octets)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_hex(self) -> str:
        """Clé publique X25519 en hexadécimal (64 caractères)."""
        return self.public_bytes().hex()

    @property
    def public_key(self) -> X25519PublicKey:
        """Objet clé publique X25519 (pour un ECDH direct)."""
        return self._public_key

    # ── Signature (Ed25519, optionnelle) ──────────────────────────────────────
    @property
    def has_signing_key(self) -> bool:
        """Vrai si une clé de signature Ed25519 est attachée à l'identité."""
        return self._signing_key is not None

    def signing_public_bytes(self) -> bytes:
        """Clé publique Ed25519 brute (32 octets).

        :raises ValueError: si l'identité n'a pas de clé de signature.
        """
        if self._signing_key is None:
            raise ValueError("cette identité n'a pas de clé de signature Ed25519")
        return self._signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        """Signe ``message`` avec la clé Ed25519 (signature de 64 octets).

        :raises ValueError: si l'identité n'a pas de clé de signature.
        """
        if self._signing_key is None:
            raise ValueError("cette identité n'a pas de clé de signature Ed25519")
        return self._signing_key.sign(message)

    @staticmethod
    def verify(signing_public: bytes, signature: bytes, message: bytes) -> bool:
        """Vérifie une signature Ed25519. Renvoie ``True`` si valide."""
        from cryptography.exceptions import InvalidSignature

        pub = Ed25519PublicKey.from_public_bytes(signing_public)
        try:
            pub.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    # ── Export de la clé privée (verrouillé par défaut) ───────────────────────
    def to_private_bytes(self, *, allow_insecure_export: bool = False) -> bytes:
        """Clé privée X25519 brute (32 octets) — **verrouillé par défaut**.

        Exporter une clé privée en clair est dangereux : l'appelant doit le
        demander explicitement via ``allow_insecure_export=True``.

        :raises PermissionError: si ``allow_insecure_export`` n'est pas vrai.
        """
        if not allow_insecure_export:
            raise PermissionError(
                "export de clé privée en clair refusé : passer "
                "allow_insecure_export=True pour forcer (déconseillé)"
            )
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # ── Persistance PEM 0600 ──────────────────────────────────────────────────
    def save(
        self,
        path: Union[str, Path],
        *,
        password: Optional[bytes] = None,
    ) -> None:
        """Sauve la clé privée en PEM PKCS#8 avec permission **0600**.

        Le fichier est créé atomiquement en mode 0600 (``O_CREAT|O_EXCL`` via
        un temporaire puis ``os.replace``) pour éviter toute fenêtre où la clé
        serait lisible par d'autres.

        :param password: si fourni, la clé est chiffrée au repos
            (``BestAvailableEncryption``) ; sinon PEM non chiffré, protégé par
            la seule permission 0600.
        """
        path = Path(path)
        if password:
            enc: serialization.KeySerializationEncryption = (
                serialization.BestAvailableEncryption(password)
            )
        else:
            enc = serialization.NoEncryption()
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        tmp = path.with_name(path.name + ".tmp")
        # 0600 dès la création — pas de chmod post-écriture (fenêtre de course).
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        except BaseException:
            try:
                os.unlink(str(tmp))
            finally:
                raise
        os.replace(str(tmp), str(path))
        os.chmod(str(path), 0o600)

    @classmethod
    def load(
        cls,
        path: Union[str, Path],
        *,
        password: Optional[bytes] = None,
    ) -> "Identity":
        """Charge une identité depuis un PEM PKCS#8 (voir :meth:`save`).

        :param password: mot de passe si le PEM est chiffré.
        :raises TypeError: si le PEM ne contient pas une clé X25519.
        """
        path = Path(path)
        with open(path, "rb") as fh:
            data = fh.read()
        key = serialization.load_pem_private_key(data, password=password)
        if not isinstance(key, X25519PrivateKey):
            raise TypeError(
                f"PEM ne contient pas une clé X25519 (type {type(key).__name__})"
            )
        return cls(key)

    def __repr__(self) -> str:  # pragma: no cover - cosmétique
        sig = "+ed25519" if self._signing_key else "x25519"
        return f"<Identity {self.public_hex()[:16]}… {sig}>"


# ─────────────────────────────────────────────────────────────────────────────
# Session éphémère — ECDH X25519 + HKDF-SHA256, AEAD ChaCha20-Poly1305
# ─────────────────────────────────────────────────────────────────────────────
class Session:
    """Session symétrique authentifiée entre deux pairs.

    Une session est construite via :meth:`establish` : un **ECDH X25519**
    entre une :class:`Identity` locale et la clé publique d'un pair produit un
    secret partagé, dérivé en clé symétrique par **HKDF-SHA256** (avec un
    contexte ``info`` et un ``salt`` optionnel). Les deux pairs qui appliquent
    ``establish`` avec les mêmes ``info``/``salt`` obtiennent la **même clé**.

    Chiffrement : **ChaCha20-Poly1305** (RFC 8439). Chaque appel à
    :meth:`encrypt` tire un **nonce aléatoire de 12 octets** (préfixé au
    ciphertext), ce qui évite toute gestion d'état de compteur entre pairs.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(
                f"clé de session invalide : {len(key)} octets, 32 attendus "
                "(ChaCha20-Poly1305)"
            )
        self._key = key
        self._aead = ChaCha20Poly1305(key)
        self._envois = 0

    @classmethod
    def establish(
        cls,
        local: Identity,
        peer_public: Union[bytes, X25519PublicKey],
        *,
        info: bytes = _DEFAULT_KDF_INFO,
        salt: Optional[bytes] = None,
        length: int = _DEFAULT_KDF_LEN,
    ) -> "Session":
        """Établit une session par **ECDH X25519** puis **HKDF-SHA256**.

        :param local: identité locale (fournit la clé privée X25519).
        :param peer_public: clé publique X25519 du pair — 32 octets bruts ou
            un objet :class:`X25519PublicKey`.
        :param info: contexte HKDF (liaison de domaine).
        :param salt: sel HKDF optionnel — les deux pairs doivent utiliser la
            même valeur pour dériver la même clé.
        :param length: doit valoir 32 (clé ChaCha20-Poly1305).
        :raises ValueError: si ``peer_public`` brut n'a pas 32 octets, ou si
            ``length`` != 32.
        """
        if length != 32:
            raise ValueError("ChaCha20-Poly1305 exige une clé de 32 octets")
        if isinstance(peer_public, X25519PublicKey):
            peer_key = peer_public
        else:
            if len(peer_public) != _X25519_KEY_LEN:
                raise ValueError(
                    f"clé publique pair invalide : {len(peer_public)} octets, "
                    f"{_X25519_KEY_LEN} attendus"
                )
            peer_key = X25519PublicKey.from_public_bytes(peer_public)
        shared = local._private_key.exchange(peer_key)
        key = derive_key_material(shared, info=info, length=length, salt=salt)
        return cls(key)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Chiffre ``plaintext`` en **ChaCha20-Poly1305**.

        :param aad: données associées authentifiées mais non chiffrées ; elles
            devront être fournies à l'identique lors du :meth:`decrypt`.
        :returns: ``nonce(12) || ciphertext || tag(16)``.
        :raises RuntimeError: si le budget de nonces de la session est épuisé
            (~2³² messages) — il faut alors **renégocier** une session, pas
            continuer sous la même clé.
        """
        if self._envois >= _NONCE_BUDGET:
            raise RuntimeError(
                "budget de nonces épuisé pour cette session "
                f"({_NONCE_BUDGET} messages) : renégociez une session. "
                "Un nonce aléatoire de 96 bits ne garantit plus l'unicité "
                "au-delà de cette borne."
            )
        self._envois += 1
        nonce = os.urandom(_CHACHA_NONCE_LEN)
        ct = self._aead.encrypt(nonce, plaintext, aad or None)
        return nonce + ct

    def confirmation(self, *, label: bytes = b"confirmation") -> bytes:
        """Étiquette de **confirmation de clé** (32 octets) à échanger.

        POURQUOI ELLE EXISTE. :meth:`establish` ne valide rien : deux pairs qui
        dérivent avec des clés publiques différentes obtiennent chacun une
        session d'apparence parfaitement valide, et la divergence ne se révèle
        qu'au **premier déchiffrement raté** — parfois longtemps après, et sous
        la forme trompeuse d'une « donnée corrompue ». L'amont a documenté la
        même limite sur sa propre couche session (``2eca5145``).

        Les deux pairs comparent cette étiquette avec :meth:`accorde` : égales,
        ils partagent la clé ; différentes, la session est à jeter tout de
        suite. L'étiquette est dérivée par HKDF dans un **domaine séparé** de
        la clé de chiffrement : la publier n'apprend rien sur celle-ci.
        """
        return derive_key_material(
            self._key, info=_DEFAULT_KDF_INFO + b"/" + label, length=32
        )

    @staticmethod
    def accorde(mienne: bytes, sienne: bytes) -> bool:
        """Compare deux étiquettes de confirmation en **temps constant**.

        Une comparaison naïve (``==``) fuirait par son temps d'exécution le
        nombre d'octets de préfixe communs — de quoi reconstruire l'étiquette
        attendue octet par octet.
        """
        return hmac.compare_digest(mienne, sienne)

    def decrypt(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Déchiffre et **authentifie** un message produit par :meth:`encrypt`.

        :param aad: doit être identique à l'AAD passé au chiffrement.
        :raises ValueError: si le message est trop court.
        :raises cryptography.exceptions.InvalidTag: si le tag Poly1305 est
            invalide (clé, nonce, AAD ou ciphertext altéré).
        """
        if len(ciphertext) < _CHACHA_NONCE_LEN + _CHACHA_TAG_LEN:
            raise ValueError("ciphertext trop court")
        nonce, ct = ciphertext[:_CHACHA_NONCE_LEN], ciphertext[_CHACHA_NONCE_LEN:]
        return self._aead.decrypt(nonce, ct, aad or None)

    def __repr__(self) -> str:  # pragma: no cover - cosmétique
        return "<Session chacha20-poly1305 established>"
