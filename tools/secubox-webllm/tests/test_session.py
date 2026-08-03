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

from tests.fakes import FakePage, Frame
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
        line_break_key="Shift+Enter",
    )
    defaults.update(overrides)
    return Backend(**defaults)  # type: ignore[arg-type]


def _session(backend: Backend, config: Config, page: FakePage) -> WebLLMSession:
    session = WebLLMSession(backend, config)
    session._page = page  # injection directe : pas de navigateur réel en test
    return session


def _page(**kwargs: object) -> FakePage:
    kwargs.setdefault("assistant_selector", "assistant")
    kwargs.setdefault("stop_selector", "stop")
    kwargs.setdefault("send_selector", "send")
    return FakePage(**kwargs)  # type: ignore[arg-type]


# --- ensure_ready --------------------------------------------------------


async def test_ensure_ready_headless_without_session_raises_immediately():
    """--headless sans session valide : erreur explicite, jamais d'attente infinie."""
    backend = _backend()
    page = _page()
    session = _session(backend, Config(headless=True), page)
    # login_indicator absent du profil : count() par défaut = 0 dans FakePage.

    with pytest.raises(SessionNotReadyError, match="headed"):
        await session.ensure_ready()

    assert page.goto_calls == [backend.url]


async def test_ensure_ready_returns_immediately_when_already_logged_in():
    backend = _backend()
    page = _page()
    page.counts["login"] = 1
    session = _session(backend, Config(headless=True), page)

    await session.ensure_ready()  # ne doit lever aucune exception


# --- _submit : composer, découpage en lignes, repli d'envoi --------------


async def test_submit_clears_composer_before_typing():
    backend = _backend()
    page = _page()
    session = _session(backend, Config(), page)

    await session._submit("bonjour")

    assert page.filled == [""]
    assert page.calls[0] == ("click", "composer")
    assert page.calls[1] == ("fill", "")


async def test_submit_puts_shift_enter_between_lines_never_before_the_first():
    """Détail critique : Shift+Enter DOIT venir ENTRE deux `type()`, jamais
    avant le premier. Dans ProseMirror, un Entrée seul déclenche l'envoi ;
    inverser cet ordre tronquerait silencieusement le prompt à sa 1re ligne.
    """
    backend = _backend()
    page = _page()
    session = _session(backend, Config(), page)

    await session._submit("ligne1\nligne2\nligne3")

    assert page.typed == ["ligne1", "ligne2", "ligne3"]
    assert page.pressed.count("Shift+Enter") == 2  # 3 lignes -> 2 transitions

    # Preuve d'ordre stricte sur le journal unifié : aucun Shift+Enter avant
    # le tout premier `type`, et un Shift+Enter entre chaque paire de lignes.
    typed_and_breaks = [
        c for c in page.calls if c[0] in ("type", "press") and c[1] != "Enter"
    ]
    assert typed_and_breaks == [
        ("type", "ligne1"),
        ("press", "Shift+Enter"),
        ("type", "ligne2"),
        ("press", "Shift+Enter"),
        ("type", "ligne3"),
    ]


async def test_submit_single_line_never_presses_shift_enter():
    backend = _backend()
    page = _page()
    session = _session(backend, Config(), page)

    await session._submit("une seule ligne")

    assert "Shift+Enter" not in page.pressed


async def test_submit_clicks_send_button_when_enabled():
    backend = _backend()
    page = _page(send_enabled=True)
    session = _session(backend, Config(), page)

    await session._submit("bonjour")

    assert page.clicks == ["composer", "send"]
    assert "Enter" not in page.pressed


async def test_submit_falls_back_to_enter_when_send_button_disabled():
    """`is_enabled` répond (pas d'exception) mais renvoie False : repli."""
    backend = _backend()
    page = _page(send_enabled=False)
    session = _session(backend, Config(), page)

    await session._submit("bonjour")

    assert page.clicks == ["composer"]  # jamais cliqué sur le bouton d'envoi
    assert page.pressed[-1] == "Enter"


async def test_submit_falls_back_to_enter_when_send_button_probe_times_out():
    """`is_enabled` lève (bouton absent/non attaché à temps) : repli aussi."""
    backend = _backend()
    page = _page(send_enabled=TimeoutError("bouton introuvable"))
    session = _session(backend, Config(), page)

    await session._submit("bonjour")

    assert page.clicks == ["composer"]
    assert page.pressed[-1] == "Enter"


# --- _wait_new_answer : garde anti-réponse périmée ------------------------


async def test_wait_new_answer_returns_once_message_count_increases():
    backend = _backend()
    frames = [
        Frame(assistant_count=1, stop_visible=False),
        Frame(assistant_count=1, stop_visible=False),
        Frame(assistant_count=2, stop_visible=False),  # nouveau message ajouté
    ]
    page = _page(frame_provider=lambda i: frames[min(i, len(frames) - 1)])
    session = _session(backend, Config(poll_interval_ms=1), page)

    await session._wait_new_answer(previous_count=1)  # ne doit pas lever


async def test_wait_new_answer_returns_as_soon_as_streaming_starts():
    backend = _backend()
    frames = [
        Frame(assistant_count=1, stop_visible=False),
        Frame(assistant_count=1, stop_visible=True),  # streaming démarré, même bulle
    ]
    page = _page(frame_provider=lambda i: frames[min(i, len(frames) - 1)])
    session = _session(backend, Config(poll_interval_ms=1), page)

    await session._wait_new_answer(previous_count=1)  # ne doit pas lever


async def test_wait_new_answer_times_out_if_nothing_ever_starts():
    backend = _backend()
    page = _page(frame_provider=lambda _i: Frame(assistant_count=1, stop_visible=False))
    session = _session(backend, Config(poll_interval_ms=1, answer_timeout_ms=20), page)

    with pytest.raises(TimeoutError, match="aucune nouvelle réponse"):
        await session._wait_new_answer(previous_count=1)


# --- ask() bout-en-bout, y compris la preuve de la garde ------------------


async def test_ask_returns_answer_once_stream_stabilizes():
    backend = _backend()
    frames = [
        Frame(text="Bon", stop_visible=True, assistant_count=1),
        Frame(text="Bonjour", stop_visible=True, assistant_count=1),
        Frame(text="Bonjour", stop_visible=False, assistant_count=1),
        Frame(text="Bonjour", stop_visible=False, assistant_count=1),
    ]
    page = _page(frame_provider=lambda i: frames[min(i, len(frames) - 1)])
    session = _session(backend, Config(stability_polls=2, poll_interval_ms=1), page)

    answer = await session.ask("salut")

    assert answer == "Bonjour"
    assert page.typed == ["salut"]


async def test_ask_times_out_when_response_never_stabilizes():
    """Le streaming démarre tout de suite (garde franchie dès la 1re frame),
    mais le texte grossit indéfiniment ensuite : timeout côté stabilité, pas
    côté garde — c'est bien `_wait_for_completion` que ce test cible."""
    backend = _backend()
    page = _page(
        frame_provider=lambda i: Frame(
            text=f"chunk-{i}", stop_visible=True, assistant_count=1
        )  # streaming actif d'emblée, texte qui grossit indéfiniment
    )
    session = _session(
        backend,
        Config(stability_polls=2, poll_interval_ms=1, answer_timeout_ms=20),
        page,
    )

    with pytest.raises(TimeoutError, match="stabilité"):
        await session.ask("salut")


async def test_ask_raises_on_empty_stable_response():
    backend = _backend()
    page = _page(
        frame_provider=lambda _i: Frame(
            text="", stop_visible=True if _i == 0 else False, assistant_count=1
        )
    )
    session = _session(backend, Config(stability_polls=2, poll_interval_ms=1), page)

    with pytest.raises(EmptyResponseError):
        await session.ask("salut")


async def test_wait_for_completion_alone_would_return_the_stale_previous_answer():
    """Preuve du bug que la garde corrige : sans `_wait_new_answer`, guetter
    la stabilité dès la soumission verrait le dernier message du tour
    PRÉCÉDENT déjà stable, et le renverrait tel quel — avant même que la
    nouvelle réponse n'ait commencé à streamer.
    """
    backend = _backend()
    frames = [
        Frame(text="réponse précédente", stop_visible=False, assistant_count=1)
    ] * 3
    page = _page(frame_provider=lambda i: frames[min(i, len(frames) - 1)])
    session = _session(backend, Config(stability_polls=2, poll_interval_ms=1), page)

    answer = await session._wait_for_completion()  # appel direct, sans la garde

    assert answer == "réponse précédente"  # le danger est réel : d'où la garde


async def test_ask_never_returns_the_stale_previous_answer():
    """Le pendant corrigé du test précédent : `ask()` inclut la garde et ne
    doit jamais renvoyer le contenu périmé du tour précédent, même quand ce
    contenu était déjà parfaitement stable au moment de la soumission.
    """
    backend = _backend()
    frames = [
        Frame(text="réponse précédente", stop_visible=False, assistant_count=1),
        Frame(
            text="réponse précédente", stop_visible=True, assistant_count=1
        ),  # streaming démarre
        Frame(text="Bon", stop_visible=True, assistant_count=1),
        Frame(text="Bonjour", stop_visible=True, assistant_count=1),
        Frame(text="Bonjour", stop_visible=False, assistant_count=1),
        Frame(text="Bonjour", stop_visible=False, assistant_count=1),
    ]
    page = _page(frame_provider=lambda i: frames[min(i, len(frames) - 1)])
    session = _session(backend, Config(stability_polls=2, poll_interval_ms=1), page)

    answer = await session.ask("nouvelle question")

    assert answer == "Bonjour"
    assert answer != "réponse précédente"


# --- divers ----------------------------------------------------------------


async def test_new_chat_navigates_to_backend_url():
    backend = _backend()
    page = _page()
    session = _session(backend, Config(), page)

    await session.new_chat()

    assert page.goto_calls == [backend.url]


async def test_profile_dir_is_isolated_per_backend():
    """Deux backends distincts ne doivent jamais partager le même profil."""
    claude = _session(_backend(name="claude-test"), Config(), _page())
    gpt = _session(_backend(name="gpt-test"), Config(), _page())

    assert claude.profile_dir != gpt.profile_dir
    assert "claude-test" in str(claude.profile_dir)
    assert "gpt-test" in str(gpt.profile_dir)
