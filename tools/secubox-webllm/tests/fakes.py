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

from dataclasses import dataclass
from typing import Callable, Optional, Union


@dataclass
class Frame:
    """État observable à un instant du polling : texte, streaming, nb messages."""

    text: str = ""
    stop_visible: bool = False
    assistant_count: int = 0


class FakeLocator:
    """Doublure de `Locator` : lit/écrit dans l'état de la `FakePage` parente.

    Chaque appel à `is_visible()` sur le sélecteur `stop_selector` avance
    d'un cran la « frame » courante — c'est le seul point d'avancement du
    temps simulé, à l'image du dernier appel de chaque cycle de polling réel
    (texte puis streaming). `count()`/`inner_text()` lisent la frame
    courante sans l'avancer.
    """

    def __init__(self, page: "FakePage", selector: str) -> None:
        self._page = page
        self._selector = selector

    @property
    def last(self) -> "FakeLocator":
        return self

    async def inner_text(self) -> str:
        if self._selector == self._page.assistant_selector:
            return self._page.current_frame().text
        return self._page.texts.get(self._selector, "")

    async def is_visible(self, timeout: Optional[float] = None) -> bool:
        if self._selector == self._page.stop_selector:
            visible = self._page.current_frame().stop_visible
            self._page.advance()  # un cycle de polling complet consommé
            return visible
        return self._page.visible.get(self._selector, False)

    async def count(self) -> int:
        if self._selector == self._page.assistant_selector:
            return self._page.current_frame().assistant_count
        return self._page.counts.get(self._selector, 0)

    async def is_enabled(self, timeout: Optional[float] = None) -> bool:
        if self._selector == self._page.send_selector:
            value = self._page.send_enabled
            if isinstance(value, BaseException):
                raise value
            return value
        return True

    async def click(self) -> None:
        self._page.clicks.append(self._selector)
        self._page.calls.append(("click", self._selector))

    async def fill(self, text: str) -> None:
        self._page.filled.append(text)
        self._page.calls.append(("fill", text))

    async def type(self, text: str) -> None:
        self._page.typed.append(text)
        self._page.calls.append(("type", text))

    async def press(self, key: str) -> None:
        self._page.pressed.append(key)
        self._page.calls.append(("press", key))


class FakePage:
    """Page factice pilotable — reproduit la surface `page` de Playwright.

    `frame_provider(index)` renvoie la `Frame` du N-ième cycle de polling ;
    l'index avance d'un cran par cycle complet (voir `FakeLocator.is_visible`
    sur `stop_selector`), partagé entre `_wait_new_answer` et
    `_wait_for_completion` — comme en réalité, les deux lisent le même état
    de page au fil du temps.
    """

    def __init__(
        self,
        *,
        assistant_selector: str = "",
        stop_selector: str = "",
        send_selector: str = "",
        frame_provider: Optional[Callable[[int], Frame]] = None,
        send_enabled: Union[bool, BaseException] = True,
    ) -> None:
        self.assistant_selector = assistant_selector
        self.stop_selector = stop_selector
        self.send_selector = send_selector
        self._frame_provider = frame_provider or (lambda _i: Frame())
        self._index = 0
        self.send_enabled = send_enabled
        self.texts: dict[str, str] = {}
        self.visible: dict[str, bool] = {}
        self.counts: dict[str, int] = {}
        self.clicks: list[str] = []
        self.filled: list[str] = []
        self.typed: list[str] = []
        self.pressed: list[str] = []
        self.goto_calls: list[str] = []
        # Journal unifié, dans l'ordre réel des appels (click/fill/type/press
        # confondus) — nécessaire pour prouver un ORDRE précis (ex : Shift+Enter
        # entre deux `type()`), ce que les listes séparées ci-dessus ne peuvent
        # pas garantir à elles seules.
        self.calls: list[tuple[str, str]] = []

    def current_frame(self) -> Frame:
        return self._frame_provider(self._index)

    def advance(self) -> None:
        self._index += 1

    def locator(self, selector: str) -> FakeLocator:
        return FakeLocator(self, selector)

    async def goto(self, url: str) -> None:
        self.goto_calls.append(url)
