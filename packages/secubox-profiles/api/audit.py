# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — audit append-only des décisions d'apply (CSPN)
CyberMind — https://cybermind.fr

Une ligne JSON par décision, ajoutée en fin de fichier (jamais réécrite).
Best-effort : un audit qui ne peut pas s'écrire ne doit pas casser l'apply —
l'orchestrateur le signale, mais la sûreté vient de l'action, pas du log.
"""
from __future__ import annotations

import json
from pathlib import Path

AUDIT_LOG = Path("/var/log/secubox/audit.log")


def record(entry: dict, *, path: Path = AUDIT_LOG) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # best-effort — never fatal to the apply
