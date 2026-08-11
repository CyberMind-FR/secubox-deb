# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.backends.openai — backend chatgpt.com.

Sélecteurs BEST-EFFORT, non vérifiés en conditions réelles. À corriger via
DevTools avant usage — voir README § Corriger un sélecteur cassé.
"""

from __future__ import annotations

from webllm.backend import Backend, Selectors, register


@register
def _backend() -> Backend:
    return Backend(
        name="gpt",
        url="https://chatgpt.com/",
        selectors=Selectors(
            composer="#prompt-textarea",
            send_button='button[data-testid="send-button"]',
            stop_button='button[data-testid="stop-button"]',
            assistant_message='div[data-message-author-role="assistant"]',
            login_indicator="#prompt-textarea",
        ),
        line_break_key="Shift+Enter",
    )
