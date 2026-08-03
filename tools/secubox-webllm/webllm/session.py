# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.session — logique générique de pilotage d'un chat web.

Aucune constante ni aucun sélecteur spécifique à un fournisseur ne doit
apparaître ici : tout ce qui varie entre claude.ai / chatgpt.com /
gemini.google.com vit dans un `Backend` (voir `webllm.backend`). C'est ce
qui permet d'ajouter un fournisseur sans toucher ce fichier.

Invariant : la session vit dans un profil de navigateur persistant local
(`launch_persistent_context`). Aucun cookie n'est jamais lu, extrait ni
rejoué hors de ce profil ; aucun port ni endpoint n'est ouvert ici.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional

from webllm.backend import Backend

__all__ = [
    "Config",
    "SessionNotReadyError",
    "EmptyResponseError",
    "StabilityTracker",
    "wait_stable",
    "split_prompt_lines",
    "WebLLMSession",
]


class SessionNotReadyError(RuntimeError):
    """Aucune session valide dans le profil — un login manuel est nécessaire."""


class EmptyResponseError(RuntimeError):
    """La réponse s'est stabilisée vide : probable erreur côté fournisseur."""


@dataclass(frozen=True)
class Config:
    """Paramètres génériques d'une session. Rien ici ne dépend du fournisseur."""

    headless: bool = False
    timeout_ms: int = 120_000
    poll_interval_ms: int = 700
    stability_polls: int = 3
    profile_root: Path = field(
        default_factory=lambda: Path.home() / ".secubox" / "webllm"
    )

    def profile_dir(self, backend_name: str) -> Path:
        """Répertoire de profil dédié à un backend — jamais partagé entre eux."""
        return self.profile_root / backend_name / "profile"


def split_prompt_lines(prompt: str) -> list[str]:
    """Découpe un prompt en lignes ; normalise les fins de ligne Windows."""
    return prompt.replace("\r\n", "\n").split("\n")


class StabilityTracker:
    """Constate la fin de génération par stabilité pure du texte observé.

    Une réponse est jugée complète quand le texte lu est identique au
    précédent ET que le bouton stop est absent, pendant `stability_polls`
    lectures consécutives. Tout changement de texte OU toute présence du
    bouton stop remet le compteur à zéro. C'est le principe hérité de
    l'implémentation d'origine : stabilité de l'innerText du dernier message
    assistant, plus absence du bouton d'arrêt.
    """

    def __init__(self, stability_polls: int) -> None:
        if stability_polls < 1:
            raise ValueError("stability_polls doit être >= 1")
        self._stability_polls = stability_polls
        self._last_text: Optional[str] = None
        self._stable_count = 0

    def observe(self, text: str, stop_visible: bool) -> bool:
        """Enregistre une lecture ; renvoie True si la réponse est jugée complète."""
        if text != self._last_text:
            self._last_text = text
            self._stable_count = 0
            return False
        if stop_visible:
            self._stable_count = 0
            return False
        self._stable_count += 1
        return self._stable_count >= self._stability_polls


async def wait_stable(
    poll: Callable[[], Awaitable[tuple[str, bool]]],
    *,
    stability_polls: int,
    timeout_s: float,
    poll_interval_s: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """Boucle de polling générique jusqu'à stabilité ou expiration du délai.

    Découplée de Playwright : `poll` renvoie (texte, bouton_stop_visible) à
    chaque itération. `sleep` et `clock` sont injectables pour rendre la
    boucle testable sans aucune attente réelle ni page réelle.
    """
    tracker = StabilityTracker(stability_polls)
    deadline = clock() + timeout_s
    while True:
        text, stop_visible = await poll()
        if tracker.observe(text, stop_visible):
            if not text.strip():
                raise EmptyResponseError("réponse stabilisée vide")
            return text
        if clock() >= deadline:
            raise TimeoutError(f"pas de stabilité de la réponse après {timeout_s}s")
        await sleep(poll_interval_s)


class WebLLMSession:
    """Session Playwright générique pilotant un `Backend` donné.

    Le profil de navigateur est persistant et dédié au backend
    (`~/.secubox/webllm/<backend>/profile`) : la session (cookies, storage)
    vit dans ce profil, jamais extraite ni rejouée ailleurs. Aucun relais
    serveur, aucune mutualisation entre utilisateurs.
    """

    def __init__(self, backend: Backend, config: Optional[Config] = None) -> None:
        self._backend = backend
        self._config = config or Config()
        self._playwright = None
        self._context = None
        self._page = None

    @property
    def backend(self) -> Backend:
        return self._backend

    @property
    def profile_dir(self) -> Path:
        return self._config.profile_dir(self._backend.name)

    async def __aenter__(self) -> "WebLLMSession":
        await self.open()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def open(self) -> None:
        """Lance Playwright et ouvre le contexte persistant du backend."""
        # Import tardif : pas de dépendance dure sur Playwright pour les tests.
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self._context = await self._playwright.chromium.launch_persistent_context(
            str(self.profile_dir), headless=self._config.headless
        )
        self._page = (
            self._context.pages[0]
            if self._context.pages
            else await self._context.new_page()
        )

    async def close(self) -> None:
        """Ferme proprement le contexte et l'instance Playwright."""
        if self._context is not None:
            await self._context.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def ensure_ready(self) -> None:
        """Vérifie qu'une session connectée existe, ou l'obtient (mode headed).

        En headless sans session valide : échec explicite immédiat — jamais
        d'attente infinie sur un login qui ne peut structurellement pas se
        produire sans affichage.
        """
        await self._page.goto(self._backend.url)
        if await self._is_logged_in():
            return
        if self._config.headless:
            raise SessionNotReadyError(
                f"aucune session {self._backend.name!r} valide dans "
                f"{self.profile_dir} — relancez une première fois sans "
                "--headless pour vous connecter manuellement"
            )
        deadline = time.monotonic() + self._config.timeout_ms / 1000
        while not await self._is_logged_in():
            if time.monotonic() >= deadline:
                raise SessionNotReadyError(
                    "login manuel non complété dans le délai imparti"
                )
            await asyncio.sleep(1)

    async def _is_logged_in(self) -> bool:
        count = await self._page.locator(
            self._backend.selectors.login_indicator
        ).count()
        return count > 0

    async def new_chat(self) -> None:
        """Repart d'une conversation vierge."""
        await self._page.goto(self._backend.url)

    async def ask(self, prompt: str) -> str:
        """Soumet un prompt et attend la réponse complète (par stabilité)."""
        await self._submit(prompt)
        return await self._wait_for_completion()

    async def _submit(self, prompt: str) -> None:
        selectors = self._backend.selectors
        composer = self._page.locator(selectors.composer)
        await composer.click()
        lines = split_prompt_lines(prompt)
        for index, line in enumerate(lines):
            if index:
                await composer.press(self._backend.line_break_key)
            await composer.type(line)
        if self._backend.submit_mode == "enter":
            await composer.press("Enter")
        else:
            await self._page.locator(selectors.send_button).click()

    async def _wait_for_completion(self) -> str:
        selectors = self._backend.selectors

        async def poll() -> tuple[str, bool]:
            text = await self._page.locator(
                selectors.assistant_message
            ).last.inner_text()
            stop_visible = await self._page.locator(selectors.stop_button).is_visible()
            return text, stop_visible

        return await wait_stable(
            poll,
            stability_polls=self._config.stability_polls,
            timeout_s=self._config.timeout_ms / 1000,
            poll_interval_s=self._config.poll_interval_ms / 1000,
        )
