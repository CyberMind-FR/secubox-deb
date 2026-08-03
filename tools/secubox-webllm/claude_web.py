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

CHANGEMENT DE CHEMIN DE PROFIL — assumé, pas de migration automatique :
l'original stockait sa session dans `~/.secubox/claude-web/profile`. Le
nouveau découpage par backend utilise `~/.secubox/webllm/claude/profile`.
Le shim n'essaie PAS de rediriger silencieusement vers l'ancien chemin (ça
mélangerait deux conventions de profil dans la durée) : la CLI historique
(`main()` ci-dessous) affiche un avertissement explicite si l'ancien profil
existe mais pas le nouveau, pour éviter un ré-login surprise pris pour un
bug.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from webllm import Config, WebLLMSession, get_backend
from webllm.cli import main as _cli_main

__all__ = ["ClaudeWeb", "main"]

LEGACY_PROFILE_DIR = Path.home() / ".secubox" / "claude-web" / "profile"


class ClaudeWeb(WebLLMSession):
    """Alias historique : session `WebLLMSession` verrouillée sur claude.ai."""

    def __init__(self, config: Optional[Config] = None) -> None:
        super().__init__(get_backend("claude"), config)


def _warn_if_legacy_profile_orphaned(config: Config) -> None:
    """Avertit si l'ancien profil existe mais que le nouveau n'a pas de session."""
    new_dir = config.profile_dir("claude")
    if LEGACY_PROFILE_DIR.exists() and not new_dir.exists():
        print(
            f"note : ancien profil trouvé en {LEGACY_PROFILE_DIR} — "
            f"webllm utilise désormais {new_dir} (jamais migré automatiquement) ; "
            "reconnectez-vous une fois en mode headed.",
            file=sys.stderr,
        )


def main(argv: Optional[list[str]] = None) -> int:
    """CLI historique : délègue à `webllm.cli` avec `--backend claude` forcé."""
    args = list(argv if argv is not None else sys.argv[1:])
    if not any(arg == "--backend" or arg.startswith("--backend=") for arg in args):
        args = ["--backend", "claude", *args]
    _warn_if_legacy_profile_orphaned(Config())
    return _cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
