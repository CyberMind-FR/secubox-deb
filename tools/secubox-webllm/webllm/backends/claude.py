# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.backends.claude — backend claude.ai.

Sélecteurs REPRIS DE L'IMPLÉMENTATION D'ORIGINE (mono-backend claude), donc
éprouvés en usage réel — contrairement à `gpt`/`gemini` qui sont best-effort.
Ça n'exempte pas de la même vigilance dans la durée : l'UI de claude.ai peut
changer sans préavis, voir README § Corriger un sélecteur cassé.
"""

from __future__ import annotations

from webllm.backend import Backend, Selectors, register


@register
def _backend() -> Backend:
    return Backend(
        name="claude",
        url="https://claude.ai/new",
        selectors=Selectors(
            # Zone de saisie (ProseMirror contenteditable).
            composer='div[contenteditable="true"]',
            # Bouton d'envoi (repli sur Entrée si absent/désactivé).
            send_button='button[aria-label*="Send" i], button[aria-label*="Envoyer" i]',
            # Bouton d'arrêt de génération : présent = ça stream encore.
            stop_button='button[aria-label*="Stop" i], button[aria-label*="Arrêter" i]',
            # Dernier message de l'assistant.
            assistant_message="div.font-claude-message",
            # Même sélecteur que le composer : sa présence signe une session connectée.
            login_indicator='div[contenteditable="true"]',
        ),
        line_break_key="Shift+Enter",
    )
