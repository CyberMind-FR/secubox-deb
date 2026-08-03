# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.test_session — comportement de `WebLLMSession` avec une
`FakePage` en lieu et place de Playwright. Aucun navigateur, aucun réseau :
`session.open()` (qui importe `playwright.async_api`) n'est jamais appelé —
la page factice est injectée directement.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakePage
from webllm.backend import Backend, Selectors
from webllm.session import (
    Config,
    EmptyResponseError,
    SessionNotReadyError,
    WebLLMSession,
)


def _backend(**overrides: object) -> Backend:
    selectors = Selectors(
        composer="composer",
        send_button="send",
        stop_button="stop",
        assistant_message="assistant",
        login_indicator="login",
    )
    defaults: dict[str, object] = dict(
        name="fake",
        url="https://fake.example/chat",
        selectors=selectors,
        submit_mode="enter",
        line_break_key="Shift+Enter",
    )
    defaults.update(overrides)
    return Backend(**defaults)  # type: ignore[arg-type]


def _session(backend: Backend, config: Config, page: FakePage) -> WebLLMSession:
    session = WebLLMSession(backend, config)
    session._page = page  # injection directe : pas de navigateur réel en test
    return session


async def test_ensure_ready_headless_without_session_raises_immediately():
    """--headless sans session valide : erreur explicite, jamais d'attente infinie."""
    backend = _backend()
    page = FakePage(assistant_selector="assistant", stop_selector="stop")
    session = _session(backend, Config(headless=True), page)
    # login_indicator absent du profil : count() par défaut = 0 dans FakePage.

    with pytest.raises(SessionNotReadyError, match="relancez"):
        await session.ensure_ready()

    assert page.goto_calls == [backend.url]


async def test_ensure_ready_returns_immediately_when_already_logged_in():
    backend = _backend()
    page = FakePage(assistant_selector="assistant", stop_selector="stop")
    page.counts["login"] = 1
    session = _session(backend, Config(headless=True), page)

    await session.ensure_ready()  # ne doit lever aucune exception


async def test_submit_types_each_line_and_presses_line_break_between_them():
    backend = _backend()
    page = FakePage(assistant_selector="assistant", stop_selector="stop")
    session = _session(backend, Config(), page)

    await session._submit("ligne1\nligne2")

    assert page.typed == ["ligne1", "ligne2"]
    assert page.pressed == ["Shift+Enter", "Enter"]
    assert page.clicks == ["composer"]


async def test_submit_uses_send_button_when_submit_mode_is_button():
    backend = _backend(submit_mode="button")
    page = FakePage(assistant_selector="assistant", stop_selector="stop")
    session = _session(backend, Config(), page)

    await session._submit("bonjour")

    assert "Enter" not in page.pressed
    assert page.clicks == ["composer", "send"]


async def test_ask_returns_answer_once_stream_stabilizes():
    backend = _backend()
    frames = [
        ("Bon", True),
        ("Bonjour", True),
        ("Bonjour", False),
        ("Bonjour", False),
        ("Bonjour", False),
    ]
    page = FakePage(
        assistant_selector="assistant",
        stop_selector="stop",
        frame_provider=lambda i: frames[min(i, len(frames) - 1)],
    )
    session = _session(
        backend, Config(stability_polls=2, poll_interval_ms=1, timeout_ms=1000), page
    )

    answer = await session.ask("salut")

    assert answer == "Bonjour"
    assert page.typed == ["salut"]


async def test_ask_times_out_when_response_never_stabilizes():
    backend = _backend()
    page = FakePage(
        assistant_selector="assistant",
        stop_selector="stop",
        frame_provider=lambda i: (f"chunk-{i}", False),  # grossit indéfiniment
    )
    session = _session(
        backend, Config(stability_polls=2, poll_interval_ms=1, timeout_ms=20), page
    )

    with pytest.raises(TimeoutError):
        await session.ask("salut")


async def test_ask_raises_on_empty_stable_response():
    backend = _backend()
    page = FakePage(assistant_selector="assistant", stop_selector="stop")  # ("", False)
    session = _session(
        backend, Config(stability_polls=2, poll_interval_ms=1, timeout_ms=1000), page
    )

    with pytest.raises(EmptyResponseError):
        await session.ask("salut")


async def test_new_chat_navigates_to_backend_url():
    backend = _backend()
    page = FakePage(assistant_selector="assistant", stop_selector="stop")
    session = _session(backend, Config(), page)

    await session.new_chat()

    assert page.goto_calls == [backend.url]


async def test_profile_dir_is_isolated_per_backend():
    """Deux backends distincts ne doivent jamais partager le même profil."""
    claude = _session(_backend(name="claude-test"), Config(), FakePage())
    gpt = _session(_backend(name="gpt-test"), Config(), FakePage())

    assert claude.profile_dir != gpt.profile_dir
    assert "claude-test" in str(claude.profile_dir)
    assert "gpt-test" in str(gpt.profile_dir)
