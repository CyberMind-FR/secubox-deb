# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.test_backend_registry — enregistrement et résolution
des backends. Vérifie que l'ajout d'un backend n'est qu'un `@register`, et
qu'une résolution par nom inconnu échoue explicitement (pas de KeyError nu).
"""

from __future__ import annotations

import pytest

import webllm  # noqa: F401 — déclenche l'enregistrement claude/gpt/gemini
from webllm.backend import Backend, Selectors, available_backends, get_backend, register


def _dummy_selectors() -> Selectors:
    return Selectors(
        composer="c",
        send_button="s",
        stop_button="t",
        assistant_message="a",
        login_indicator="l",
    )


def test_importing_webllm_registers_the_three_shipped_backends():
    assert {"claude", "gpt", "gemini"} <= set(available_backends())


def test_get_backend_returns_the_matching_backend():
    backend = get_backend("claude")
    assert backend.name == "claude"
    assert backend.url.startswith("https://claude.ai")


def test_get_backend_unknown_name_raises_explicit_error_not_bare_keyerror():
    with pytest.raises(KeyError, match="backend inconnu"):
        get_backend("ce-fournisseur-n-existe-pas")


def test_register_rejects_duplicate_backend_name():
    @register
    def _first() -> Backend:
        return Backend(
            name="test-doublon-xyz",
            url="https://example.invalid",
            selectors=_dummy_selectors(),
        )

    with pytest.raises(ValueError, match="déjà enregistré"):

        @register
        def _second() -> Backend:
            return Backend(
                name="test-doublon-xyz",
                url="https://example.invalid",
                selectors=_dummy_selectors(),
            )


def test_available_backends_is_sorted():
    names = available_backends()
    assert names == sorted(names)
