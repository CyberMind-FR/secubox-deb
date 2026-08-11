# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.test_wait_stable — la boucle de polling asynchrone,
avec horloge et sommeil injectés : zéro attente réelle, zéro page réelle.
"""

from __future__ import annotations

import pytest

from webllm.session import EmptyResponseError, wait_stable


class FakeClock:
    """Horloge factice : n'avance que lorsque `sleep` est appelé (déterministe)."""

    def __init__(self) -> None:
        self.value = 0.0

    def now(self) -> float:
        return self.value

    async def sleep(self, seconds: float) -> None:
        self.value += seconds


async def test_returns_text_once_stable_and_stop_button_gone():
    """Cas nominal : le texte grossit puis se stabilise, bouton stop disparu."""
    clock = FakeClock()
    frames = iter(
        [("a", True), ("ab", True), ("abc", True), ("abc", False), ("abc", False)]
    )

    async def poll():
        return next(frames)

    result = await wait_stable(
        poll,
        stability_polls=2,
        timeout_s=10,
        poll_interval_s=1,
        sleep=clock.sleep,
        clock=clock.now,
    )
    assert result == "abc"


async def test_times_out_when_text_keeps_growing():
    """Le texte grossit indéfiniment (streaming sans fin) : timeout, pas de blocage."""
    clock = FakeClock()
    counter = iter(range(10**9))

    async def poll():
        return (f"chunk-{next(counter)}", False)

    with pytest.raises(TimeoutError):
        await wait_stable(
            poll,
            stability_polls=2,
            timeout_s=3,
            poll_interval_s=1,
            sleep=clock.sleep,
            clock=clock.now,
        )


async def test_times_out_when_text_stable_but_streaming_flag_stuck():
    """Texte stable mais bouton stop visible en continu : jamais complet, timeout."""
    clock = FakeClock()

    async def poll():
        return ("réponse partielle", True)

    with pytest.raises(TimeoutError):
        await wait_stable(
            poll,
            stability_polls=2,
            timeout_s=3,
            poll_interval_s=1,
            sleep=clock.sleep,
            clock=clock.now,
        )


async def test_raises_on_stable_empty_response():
    """Une réponse vide qui se stabilise est signalée, pas rendue comme un succès."""
    clock = FakeClock()

    async def poll():
        return ("", False)

    with pytest.raises(EmptyResponseError):
        await wait_stable(
            poll,
            stability_polls=2,
            timeout_s=10,
            poll_interval_s=1,
            sleep=clock.sleep,
            clock=clock.now,
        )


async def test_does_not_poll_or_sleep_once_result_is_ready():
    """Une fois la stabilité atteinte, pas de tour de poll/sleep superflu.

    La 1re lecture initialise toujours le compteur (aucun `last_text` de
    référence), donc une seule attente est incompressible avant la 2e
    lecture stable ; il ne doit pas y en avoir de 3e.
    """
    clock = FakeClock()
    calls: list[int] = []

    async def poll():
        calls.append(1)
        return ("ok", False)

    result = await wait_stable(
        poll,
        stability_polls=1,
        timeout_s=10,
        poll_interval_s=1,
        sleep=clock.sleep,
        clock=clock.now,
    )
    assert result == "ok"
    assert len(calls) == 2
    assert clock.value == 1.0
