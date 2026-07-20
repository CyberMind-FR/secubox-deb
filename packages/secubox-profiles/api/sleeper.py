# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-sleeper : endort les modules on-demand idle
CyberMind — https://cybermind.fr

Décision PURE (should_sleep) + passe daemon (run_once, Task 5). Ne dort JAMAIS
sur une incertitude : toute sonde indéterminée (None) => on garde le module up.
"""
from __future__ import annotations

from .front_signals import Signal
from .lifecycle import idle_threshold, is_sleepable
from .manifest import Manifest


def should_sleep(m: Manifest, sig: Signal | None, *, hint_idle: bool | None,
                 now_up: bool) -> bool:
    if not now_up or not is_sleepable(m):
        return False
    if sig is None or sig.last_request_age is None or sig.active_conns is None:
        return False
    if hint_idle is False:            # a module /idle hint of False vetoes; None/True allow
        return False
    return sig.active_conns == 0 and sig.last_request_age >= idle_threshold(m)
