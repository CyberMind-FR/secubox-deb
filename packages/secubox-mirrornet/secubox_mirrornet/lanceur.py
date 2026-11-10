# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lanceur de secubox-mirrornet (#3645) : migre la base PUIS sert l'API, dans le processus PRINCIPAL de l'unité.

Une base plus récente que le code sort en code 3 depuis ce processus : `RestartPreventExitStatus=3` ne s'applique qu'au
processus principal (un échec d'ExecStartPre redémarrait en boucle)."""
from __future__ import annotations

import sys

from secubox_mirrornet import config, schema

SOCKET = "/run/secubox/mirrornet.sock"


def main(argv: list[str]) -> int:
    try:
        v = schema.initialiser(config.BASE)
    except RuntimeError as e:
        print(f"mirrornet : {e}", file=sys.stderr)
        return schema.CODE_BASE_TROP_RECENTE
    print(f"mirrornet : schéma en version {v}", flush=True)
    import uvicorn
    uvicorn.run("api.main:app", uds=argv[1] if len(argv) > 1 else SOCKET, workers=1, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
