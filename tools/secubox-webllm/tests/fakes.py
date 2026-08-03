# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.fakes — doublures minimales de l'API Playwright.

Aucun test de ce package n'ouvre de navigateur ni de connexion réseau : ces
objets factices reproduisent la surface `page.locator(...)` utilisée par
`webllm.session.WebLLMSession`, pilotable finement par chaque test.
"""

from __future__ import annotations

from typing import Callable, Optional


class FakeLocator:
    """Doublure de `Locator` : lit/écrit dans l'état de la `FakePage` parente."""

    def __init__(self, page: "FakePage", selector: str) -> None:
        self._page = page
        self._selector = selector

    @property
    def last(self) -> "FakeLocator":
        return self

    async def inner_text(self) -> str:
        if self._selector == self._page.assistant_selector:
            return self._page.current_frame()[0]
        return self._page.texts.get(self._selector, "")

    async def is_visible(self) -> bool:
        if self._selector == self._page.stop_selector:
            visible = self._page.current_frame()[1]
            self._page.advance()  # une lecture complète (texte + stop) = un poll
            return visible
        return self._page.visible.get(self._selector, False)

    async def count(self) -> int:
        return self._page.counts.get(self._selector, 0)

    async def click(self) -> None:
        self._page.clicks.append(self._selector)

    async def type(self, text: str) -> None:
        self._page.typed.append(text)

    async def press(self, key: str) -> None:
        self._page.pressed.append(key)


class FakePage:
    """Page factice pilotable — reproduit la surface `page` de Playwright.

    `frame_provider(index)` renvoie (texte, bouton_stop_visible) pour le
    N-ième poll de la boucle de stabilité ; l'index avance d'un cran à
    chaque cycle (texte + stop) complet, reproduisant l'ordre exact des
    appels de `WebLLMSession._wait_for_completion`.
    """

    def __init__(
        self,
        *,
        assistant_selector: str = "",
        stop_selector: str = "",
        frame_provider: Optional[Callable[[int], tuple[str, bool]]] = None,
    ) -> None:
        self.assistant_selector = assistant_selector
        self.stop_selector = stop_selector
        self._frame_provider = frame_provider or (lambda _i: ("", False))
        self._index = 0
        self.texts: dict[str, str] = {}
        self.visible: dict[str, bool] = {}
        self.counts: dict[str, int] = {}
        self.clicks: list[str] = []
        self.typed: list[str] = []
        self.pressed: list[str] = []
        self.goto_calls: list[str] = []

    def current_frame(self) -> tuple[str, bool]:
        return self._frame_provider(self._index)

    def advance(self) -> None:
        self._index += 1

    def locator(self, selector: str) -> FakeLocator:
        return FakeLocator(self, selector)

    async def goto(self, url: str) -> None:
        self.goto_calls.append(url)
