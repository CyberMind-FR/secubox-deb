# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — export du set "sleepable" pour le moniteur de santé
CyberMind — https://cybermind.fr

Un module eager/on-demand (scale-to-zero, ref #896) qu'on observe éteint est
un état ATTENDU — pas une panne. Aujourd'hui rien dans ce dépôt ne consomme
cette distinction pour le moniteur de santé :

  - les scripts health-prober réels (module_prober.py / prober.py, qui
    produisent /var/cache/secubox/health/{modules,status}.json lus par
    secubox-hub) ne sont PAS encore rapatriés dans ce dépôt (TODO #393,
    `.claude/TODO.md`) — impossible de les corriger proprement d'ici ;
  - `secubox-hub` (dans ce dépôt) calcule lui-même un second signal, plus
    simple, pour les LEDs de la sidebar (`_refresh_health_batch`, un
    `systemctl list-units secubox-*` direct) — CELUI-LÀ est corrigible
    d'ici, et l'est (voir packages/secubox-hub/api/main.py).

Ce module exporte, en JSON stable, l'ensemble trié des ids de modules
sleepables (même critère que `lifecycle.is_sleepable` : eager/on-demand,
protected exclu via effective_lifecycle) — pour que TOUT consommateur (le
futur prober rapatrié, ou secubox-hub dans l'intervalle) puisse distinguer
« volontairement endormi » de « down » sans deviner un format.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .lifecycle import is_sleepable
from .manifest import Manifest


def sleepable_module_ids(manifests: dict[str, Manifest]) -> list[str]:
    """Ids (triés) des modules eager/on-demand — jamais always-on/manual, et
    jamais un module protégé même déclaré on-demand (is_sleepable applique
    déjà cette règle via effective_lifecycle)."""
    return sorted(mid for mid, m in manifests.items() if is_sleepable(m))


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        # mkstemp() creates 0600 (owner-only) — but this file is PUBLIC (a
        # module-id set, not a secret) and MUST be readable by secubox-hub,
        # which runs as a different unprivileged user (secubox). Without
        # this chmod, the health-distinction is silently inert on install
        # (#896 review).
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def write_sleepable(*, manifests: dict[str, Manifest], out_path: Path) -> list[str]:
    """Écrit atomiquement la liste JSON triée des ids sleepables vers
    `out_path` (temp+rename, même motif que wafsync.write_ondemand), retourne
    la liste écrite."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    ids = sleepable_module_ids(manifests)
    _write_atomic(out_path, json.dumps(ids))
    return ids
