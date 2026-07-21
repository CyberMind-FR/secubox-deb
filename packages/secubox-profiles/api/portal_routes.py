# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — mémoire durable des routes WAF des modules portail
CyberMind — https://cybermind.fr

Quand on ENDORT un module portail (STOP), l'actionneur retire sa route de
haproxy-routes.json. Le RÉVEIL, potentiellement des heures plus tard, doit
recréer cette route — mais à ce moment elle a disparu du fichier vivant, et le
snapshot 4R qui la portait a déjà tourné (R1..R4, 4 applies plus tard). Cette
mémoire est la SEULE source qui survit : à l'endormissement on `remember` la
valeur ([host, port]) réellement présente, au réveil on la `recall`.

Fichier = un dict {domaine: [host, port]}, écrit atomiquement (temp+rename),
mode 0644 (lu par le réveil qui tourne sous `secubox`, pas root). On ne fait
jamais échouer une transition d'état à cause de cette mémoire (best-effort) —
au pire le réveil ne restaure pas la route et le module reste injoignable, ce
qui est déjà le comportement sans cette mémoire.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

REMEMBER_FILE = Path("/var/lib/secubox/profiles/portal-routes.json")


def _load(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_atomic(path: Path, data: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".portal-routes-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        os.chmod(tmp, stat.S_IMODE(0o644))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def remember(domain: str, value, *, path: Path = REMEMBER_FILE) -> None:
    """Persiste durablement domaine→valeur (upsert). value None = no-op (rien à
    mémoriser). Best-effort : une écriture qui échoue ne doit pas faire échouer
    l'endormissement."""
    if value is None:
        return
    try:
        data = _load(path)
        data[domain] = value
        _write_atomic(path, data)
    except OSError:
        # mémoire best-effort : ne jamais casser un STOP à cause d'elle.
        pass


def recall(domain: str, *, path: Path = REMEMBER_FILE):
    """Renvoie la valeur mémorisée pour `domaine`, ou None si inconnue."""
    return _load(path).get(domain)
