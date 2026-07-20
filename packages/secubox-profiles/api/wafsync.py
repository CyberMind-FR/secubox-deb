# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — génération de la liste on-demand-vhosts pour sbxwaf
CyberMind — https://cybermind.fr

sbxwaf (Go) lit /etc/secubox/waf/on-demand-vhosts.json : l'ensemble des vhosts
sleepables (portal_domain d'un module eager/on-demand). Pour une requête vers
un de ces vhosts sans route active, sbxwaf proxy vers le waker au lieu de
retourner 421. Remplace le nginx-sync de la Tâche 7 (pivot d'architecture :
le déclencheur de réveil est sbxwaf, pas nginx).
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .lifecycle import effective_lifecycle
from .manifest import Manifest


def ondemand_vhosts(manifests: dict[str, Manifest]) -> list[str]:
    """Domaines portail (triés) des modules sleepables (eager/on-demand) et
    routés (portal_domain non nul). always-on/manual/sans-portail : exclus."""
    return sorted(
        m.portal_domain
        for m in manifests.values()
        if m.portal_domain is not None and effective_lifecycle(m) in ("eager", "on-demand")
    )


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def write_ondemand(*, manifests: dict[str, Manifest], out_path: Path) -> list[str]:
    """Écrit atomiquement la liste JSON des vhosts on-demand vers `out_path`,
    retourne la liste écrite."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doms = ondemand_vhosts(manifests)
    _write_atomic(out_path, json.dumps(doms))
    return doms
