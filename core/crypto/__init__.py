# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox cryptographic core.

Adapted from the Hermes implementation at commit
 d4abc757c448d35151c88f8d0bf6fa81cbaf652e.

The public API deliberately separates:
- long-term identities (X25519)
- ephemeral sessions (X25519 ECDH + HKDF-SHA256)
- authenticated symmetric encryption
"""

from .hermes import Identity, Session, derive_key_material

__all__ = ["Identity", "Session", "derive_key_material"]
