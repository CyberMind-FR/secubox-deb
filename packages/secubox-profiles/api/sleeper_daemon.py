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

`_signal_reader` (Task 15, #896) lit désormais le vrai fichier émis par
sbxwaf (packages/secubox-toolbox-ng/cmd/sbxwaf/vhostsignals.go) :
/var/cache/secubox/waf/vhost-signals.json, rafraîchi ~5s, UNIQUEMENT pour
les vhosts on-demand (Begin/End bracketent chaque requête réelle proxyée —
jamais la branche waker). Lecture au mieux-effort, exactement comme
`_read_wake_locked` dans sleeper.py : fichier absent/illisible/corrompu =>
{}, jamais une exception qui ferait mourir la boucle. {} => vhost_signals()
ne produit aucun Signal => should_sleep() n'agit jamais dessus (Signal
non-None requis) — donc un fichier absent reste sûr par construction, comme
avant que ce reader existe.

CORRECTNESS CRITIQUE : sbxwaf écrit last_request_ts en HORLOGE MURALE unix
(time.Now().Unix() côté Go). front_signals.vhost_signals(reader, now)
calcule l'âge comme now() - last_request_ts — `now` DOIT donc être
l'horloge MURALE (time.time), PAS monotone (time.monotonic, dont l'epoch
n'a aucun rapport avec un timestamp unix mural — un âge calculé contre elle
serait un nombre sans rapport avec la réalité, jamais "idle depuis N
secondes"). Voir le câblage de `now=time.time` dans main_async ci-dessous.
Le `stamp` (chaîne ISO pour l'audit apply_plan) reste un rôle SÉPARÉ et
n'est pas concerné.

Un STUB documenté subsiste — le sleeper ne bloque JAMAIS dessus :

  - `_hint_probe` (sonde /idle optionnelle par module) : aucun module
    n'expose encore cette route. Renvoie toujours None (indéterminé — ni
    veto ni feu vert fabriqué). Suivi #896.
"""
from __future__ import annotations

import asyncio
import json
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

# Chemin partagé avec sbxwaf (packages/secubox-toolbox-ng/cmd/sbxwaf, flag
# --vhost-signals, même valeur littérale par défaut — voir
# secubox-waf-ng-worker@.service). Module-level pour rester monkeypatchable
# en test (même motif que api.waker._WAKE_ACTIVE_PATH).
VHOST_SIGNALS_PATH = Path("/var/cache/secubox/waf/vhost-signals.json")


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
    """Lit le snapshot per-vhost écrit par sbxwaf (VHOST_SIGNALS_PATH) au
    mieux-effort — même contrat que `_read_wake_locked` dans sleeper.py :
    fichier absent, illisible, ou JSON corrompu/de forme inattendue => {},
    JAMAIS une exception qui ferait mourir la boucle du sleeper. {} produit
    zéro Signal par vhost côté front_signals.vhost_signals(), donc
    should_sleep() n'agit jamais dessus (Signal non-None requis) — un
    fichier absent reste aussi sûr qu'avant que ce reader existe."""
    try:
        data = json.loads(VHOST_SIGNALS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        vhost: raw for vhost, raw in data.items()
        if isinstance(vhost, str) and isinstance(raw, dict)
    }


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
        # HORLOGE MURALE, pas monotone : sbxwaf écrit last_request_ts en
        # unix wall-clock (time.Now().Unix()) et
        # front_signals.vhost_signals(reader, now) calcule l'âge comme
        # now() - last_request_ts. time.monotonic() a une epoch arbitraire
        # sans rapport avec un timestamp unix — voir la docstring de module
        # ci-dessus pour le détail.
        now=time.time,
        stamp=_now_iso,
        tick_limit=tick_limit,
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main_async())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
