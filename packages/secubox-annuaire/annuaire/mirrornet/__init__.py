# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire — MirrorNet profile generation.
CyberMind — https://cybermind.fr

A cohesive sub-subsystem (schema · canonical/hash · generators · dry-run ·
endpoints) living inside the annuaire package so it REUSES the existing
BLAKE2b-chained journal, canonical serialization, Ed25519 crypto and ConfigBlob
propagation — never a parallel structure. A network profile revision is carried
as a `ConfigBlob` and chained through `annuaire.log.Journal`.
"""
