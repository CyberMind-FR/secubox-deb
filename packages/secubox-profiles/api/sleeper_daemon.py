# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-sleeper : point d'entrée daemon (ExecStart)
CyberMind — https://cybermind.fr

Câble les dépendances de production à api.sleeper.serve() et tourne
indéfiniment (tick_limit=None). Lancé par secubox-sleeper.service EN ROOT :
contrairement au waker (frontend HTTP non-privilégié qui délègue via
sudo->systemd-run->wakectl), le sleeper EST l'actionneur privilégié — il
appelle apply.apply_plan directement (même chemin que secubox-wakectl et
secubox-profilectl apply/rollback), pas de sudo/systemd-run ici.

Deux dépendances restent des STUBS documentés — le sleeper ne bloque JAMAIS
dessus (should_sleep n'endort que sur un signal connu, jamais sur
l'indéterminé) :

  - `_signal_reader` (api/front_signals.py) : la source réelle des stats
    sbxwaf par vhost (last_request_ts/active_conns) n'est pas stabilisée —
    le WAF interim (secubox-toolbox-ng/cmd/sbxwaf, Go) n'écrit pas encore de
    waf-stats.json exploitable ("waf-stats.json gap", suivi projet #896).
    Tant que ce format n'existe pas côté sbxwaf, ce stub renvoie {} :
    vhost_signals() ne produit alors aucun Signal, et should_sleep() exige
    un Signal non-None pour agir — donc AUCUN module n'est jamais endormi
    par ce stub. Sûr par construction. NEEDS_CONTEXT pour T12/follow-up :
    brancher le vrai fichier/format dès qu'il existe.

  - `_hint_probe` (sonde /idle optionnelle par module) : aucun module
    n'expose encore cette route. Renvoie toujours None (indéterminé — ni
    veto ni feu vert fabriqué). Suivi #896.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import sleeper
from .actuate import TIMED_OUT
from .manifest import Manifest
from .observe import observe, observe_all

_LOG = logging.getLogger(__name__)

DEFAULT_ROOT = Path("/etc/secubox")
# Doit rester cohérent avec api/waker.py::_WAKE_ACTIVE_TTL_S (90s) : le
# waker garde une entrée _last_wake au moins jusqu'à cette TTL, donc un tick
# à cet intervalle (ou plus court) est garanti de voir le verrou pendant sa
# fenêtre de validité.
DEFAULT_INTERVAL_S = 30.0
_RUN_TIMEOUT_S = 30


def _root() -> Path:
    """Racine de config — surchargeable en test via SECUBOX_PROFILES_ROOT
    (même motif que api/web.py::_root, api/waker.py::_root)."""
    return Path(os.environ.get("SECUBOX_PROFILES_ROOT", str(DEFAULT_ROOT)))


def _run(argv: list[str]) -> tuple[int | None, str]:
    """Même contrat que secubox-wakectl._run / secubox-profilectl._run :
    rc=None = la commande n'a PAS pu s'exécuter (jamais un faux succès),
    rc=TIMED_OUT = elle a démarré mais n'a pas répondu à temps (délégué à
    wait_state pour lxc-start/lxc-stop, pas un échec dur en soi)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=_RUN_TIMEOUT_S)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return TIMED_OUT, ""
    except OSError:
        return None, ""


def _signal_reader() -> dict[str, dict[str, Any]]:
    """STUB documenté (voir docstring de module) : la source réelle des
    stats sbxwaf par vhost n'est pas encore stabilisée. {} => aucun Signal
    par vhost => should_sleep() ne peut jamais décider d'endormir un module
    à partir de ce stub (sig is None => False). NEEDS_CONTEXT : brancher le
    vrai fichier/format dès que sbxwaf l'écrit (T12/#896 follow-up)."""
    return {}


def _hint_probe(mid: str, m: Manifest) -> bool | None:
    """STUB documenté : aucune sonde /idle par-module n'existe encore.
    None = indéterminé — should_sleep ne veto ni n'autorise jamais sur une
    valeur fabriquée. Suivi #896."""
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def main_async(*, root: Path | None = None, interval: float = DEFAULT_INTERVAL_S,
                     tick_limit: int | None = None) -> None:
    await sleeper.serve(
        root=root if root is not None else _root(),
        interval=interval,
        sleep=asyncio.sleep,
        observe_all=observe_all,
        signal_reader=_signal_reader,
        hint_probe=_hint_probe,
        run=_run,
        observe=observe,
        now=time.monotonic,
        stamp=_now_iso,
        tick_limit=tick_limit,
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main_async())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
