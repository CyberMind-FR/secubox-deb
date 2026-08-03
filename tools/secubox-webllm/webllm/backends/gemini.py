# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.backends.gemini — backend gemini.google.com.

Sélecteurs BEST-EFFORT, non vérifiés en conditions réelles. À corriger via
DevTools avant usage — voir README § Corriger un sélecteur cassé.
"""

from __future__ import annotations

from webllm.backend import Backend, Selectors, register


@register
def _backend() -> Backend:
    return Backend(
        name="gemini",
        url="https://gemini.google.com/app",
        selectors=Selectors(
            composer='div.ql-editor[contenteditable="true"]',
            send_button="button.send-button",
            stop_button='button[aria-label="Stop response"]',
            assistant_message="message-content.model-response-text",
            login_indicator='div.ql-editor[contenteditable="true"]',
        ),
        line_break_key="Shift+Enter",
    )
