# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: claude_web — shim de compatibilité ascendante.

`ClaudeWeb` était le client historique figé sur claude.ai (Playwright,
`launch_persistent_context`, complétion par stabilité de l'innerText). Toute
cette logique vit désormais dans le package `webllm`, générique et
multi-backend ; ce module ne fait plus qu'alias `webllm.WebLLMSession`
verrouillé sur le backend "claude" et sa CLI historique.

Préférer directement : `secubox-webllm --backend claude` ou
`python -m webllm.cli --backend claude`. Ce shim est conservé pour ne pas
casser des scripts existants qui importeraient `ClaudeWeb` directement.
"""

from __future__ import annotations

import sys
from typing import Optional

from webllm import Config, WebLLMSession, get_backend
from webllm.cli import main as _cli_main

__all__ = ["ClaudeWeb", "main"]


class ClaudeWeb(WebLLMSession):
    """Alias historique : session `WebLLMSession` verrouillée sur claude.ai."""

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(get_backend("claude"), config)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI historique : délègue à `webllm.cli` avec `--backend claude` forcé."""
    args = list(argv if argv is not None else sys.argv[1:])
    if not any(arg == "--backend" or arg.startswith("--backend=") for arg in args):
        args = ["--backend", "claude", *args]
    return _cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
