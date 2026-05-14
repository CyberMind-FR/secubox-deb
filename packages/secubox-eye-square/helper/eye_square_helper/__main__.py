# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Entry point: bind FastAPI helper to /run/secubox/eye-square-helper.sock."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import uvicorn

from eye_square_helper.app import app

SOCK = Path(os.environ.get("EYE_SQUARE_HELPER_SOCK", "/run/secubox/eye-square-helper.sock"))


def main() -> int:
    SOCK.parent.mkdir(parents=True, exist_ok=True)
    if SOCK.exists():
        SOCK.unlink()
    uvicorn.run(
        app,
        uds=str(SOCK),
        log_level="info",
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
