# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — VLESS+Reality+Vision egress-point manager (Xray-core)
CyberMind — https://cybermind.fr

Hamiltonian path (see docs at top of ``router.py`` for the full map):

    AUTH -> WALL -> BOOT -> MIND -> ROOT -> MESH

  AUTH  identity provisioning (x25519 keypair + UUID)        -> xray.py
  WALL  split-tunnel routing rules + traffic shaping         -> xray.py
  BOOT  instance lifecycle (secubox-xray@<id>.service)       -> service.py
  MIND  decision gates: target sanity + volume-guard actions -> validator.py, monitor.py
  ROOT  persistent state (SQLite WAL)                        -> store.py
  MESH  transport (Reality streamSettings)                   -> xray.py
"""

__version__ = "0.1.0"
