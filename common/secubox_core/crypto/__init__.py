# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox_core.crypto — cœur cryptographique souverain (Hermes).

Backend crypto **souverain** de SecuBox, importable au runtime en :

    from secubox_core.crypto import Identity, Session, derive_key_material

Le seam enfichable de ``secubox-identity`` (#1263) fait ``from
secubox_core.crypto import hermes`` et adopte automatiquement ce backend dès
qu'il est installé, sinon retombe sur ``cryptography`` (mêmes primitives).

L'API sépare :
- les identités long-terme (X25519) ;
- les sessions éphémères (X25519 ECDH + HKDF-SHA256) ;
- le chiffrement symétrique authentifié (ChaCha20-Poly1305).
"""

from .hermes import Identity, Session, derive_key_material

__all__ = ["Identity", "Session", "derive_key_material"]
