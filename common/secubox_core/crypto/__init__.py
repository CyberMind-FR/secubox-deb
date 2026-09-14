# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox_core.crypto — cœur cryptographique de SecuBox.

    from secubox_core.crypto import Identity, Session, derive_key_material

UNE SEULE RÈGLE : QUE DES ALGORITHMES NORMALISÉS. X25519 (RFC 7748), Ed25519
(RFC 8032, FIPS 186-5), HKDF-SHA256 (RFC 5869), AES-256-GCM (NIST SP 800-38D),
SHA-256 (FIPS 180-4) — tous implémentés par OpenSSL via ``pyca/cryptography``.
Rien n'est écrit à la main, et rien n'est assemblé de façon originale.

Voir ``docs/POLITIQUE-CRYPTO.md`` pour le catalogue complet, les justifications
et la liste — courte et motivée — des exceptions imposées par des protocoles.

L'API sépare trois choses qui ne doivent pas se mélanger :
  * les identités long-terme (X25519, + Ed25519 pour signer) ;
  * les sessions éphémères (ECDH X25519 → HKDF-SHA256) ;
  * le chiffrement authentifié (AES-256-GCM, clés directionnelles et nonces
    compteur — voir le module pour le pourquoi).
"""

from .standard import Identity, Session, derive_key_material

__all__ = ["Identity", "Session", "derive_key_material"]
