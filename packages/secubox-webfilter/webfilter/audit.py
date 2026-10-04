# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Ligne d'audit (ajout seul) : /var/log/secubox/audit.log, une ligne JSON par décision."""
import json
import sys
import time
from pathlib import Path

AUDIT = Path("/var/log/secubox/audit.log")


def ecrire(action: str, detail: str = "", chemin: Path | None = None) -> None:
    try:
        with open(chemin or AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "webfilter",
                                "action": action, "detail": detail[:300]}, ensure_ascii=False) + "\n")
    except OSError as e:                                           # ne bloque pas l'opération, mais ne se tait pas
        print(f"secubox-webfilter : audit non écrit ({action}) : {e}", file=sys.stderr)
