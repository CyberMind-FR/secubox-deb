# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.backends.claude — backend claude.ai.

Sélecteurs BEST-EFFORT : ni la version d'origine ni son contenu n'ont été
retrouvés dans le dépôt ni fournis en conversation — reconstruits à partir
de la structure connue de l'interface (éditeur ProseMirror). À vérifier et
corriger via DevTools avant tout usage réel — voir README § Corriger un
sélecteur cassé. Ne pas supposer ce backend plus fiable que gpt/gemini.
"""

from __future__ import annotations

from webllm.backend import Backend, Selectors, register


@register
def _backend() -> Backend:
    return Backend(
        name="claude",
        url="https://claude.ai/new",
        selectors=Selectors(
            composer='div.ProseMirror[contenteditable="true"]',
            send_button='button[aria-label="Send message"]',
            stop_button='button[aria-label="Stop response"]',
            assistant_message="div.font-claude-message",
            login_indicator='div.ProseMirror[contenteditable="true"]',
        ),
        submit_mode="enter",
        line_break_key="Shift+Enter",
    )
