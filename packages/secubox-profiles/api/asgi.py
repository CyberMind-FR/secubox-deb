# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — entrypoint ASGI (`uvicorn api.asgi:app`)
CyberMind — https://cybermind.fr

Pas d'état à ouvrir/fermer (pas de connexion DB, pas de venv) : web.py lit
les fichiers TOML à la demande, à chaque requête. Ce module ne fait que
réexporter l'app pour que le service systemd ait un point d'entrée stable et
distinct du module de logique (`api.web`), au même endroit que les autres
paquets à socket dédié (voir secubox-billets/api/asgi.py).
"""
from __future__ import annotations

from .web import app

__all__ = ["app"]
