# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: le Coffre (secubox-vault 2.0, #1367 P1).

Conception : docs/design/coffre/README.md. Une clé maîtresse (MK) aléatoire,
jamais écrite, emballée par chaque serrure ; des compartiments dont la clé
dérive de la MK ; des secrets chiffrés et liés à leur place ; un journal
chaîné.
"""
