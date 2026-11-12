# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Composant SearXNG de secubox-metanews (#3581) : code commun à l'API (sans privilège) et à searxngctl (root).

Bibliothèque standard seulement, plus PyYAML (python3-yaml) pour settings.yml : searxngctl tourne en `python3 -I`."""

VERSION = "0.6.0"
