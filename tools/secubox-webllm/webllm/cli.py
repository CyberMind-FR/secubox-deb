# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webllm.cli — CLI unifiée multi-backend.

Ajouter un fournisseur ne touche jamais ce fichier : `--backend` choisit
parmi `available_backends()`, peuplé par le seul import de `webllm`.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

from webllm import (
    Config,
    EmptyResponseError,
    SessionNotReadyError,
    WebLLMSession,
    available_backends,
    get_backend,
)

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments — un seul, partagé par tous les backends."""
    parser = argparse.ArgumentParser(
        prog="secubox-webllm",
        description=(
            "Automatisation locale d'une session de chat web dans un profil "
            "de navigateur persistant. Mono-utilisateur, aucun relais serveur."
        ),
    )
    parser.add_argument(
        "--backend",
        default="claude",
        choices=available_backends(),
        help="Fournisseur cible (défaut : claude).",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Sans affichage navigateur — nécessite une session déjà connectée.",
    )
    parser.add_argument(
        "--new",
        action="store_true",
        help="Démarre une nouvelle conversation avant d'envoyer le prompt.",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        help="Racine des profils (défaut : ~/.secubox/webllm).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Délai maximal d'attente de la réponse, en secondes (défaut : 300).",
    )
    parser.add_argument(
        "prompt",
        nargs="*",
        help="Prompt à envoyer ; si absent, lu sur l'entrée standard.",
    )
    return parser


def _read_prompt(args: argparse.Namespace) -> str:
    """Résout le prompt depuis les arguments positionnels ou, à défaut, stdin."""
    if args.prompt:
        return " ".join(args.prompt)
    data = sys.stdin.read()
    if not data.strip():
        raise SystemExit("aucun prompt fourni (arguments positionnels ou stdin)")
    return data


def _build_config(args: argparse.Namespace) -> Config:
    config = Config(headless=args.headless, answer_timeout_ms=args.timeout * 1000)
    if args.profile is not None:
        config = replace(config, profile_root=args.profile)
    return config


async def _run(args: argparse.Namespace) -> int:
    backend = get_backend(args.backend)
    config = _build_config(args)
    prompt = _read_prompt(args)
    async with WebLLMSession(backend, config) as session:
        await session.ensure_ready()
        if args.new:
            await session.new_chat()
        answer = await session.ask(prompt)
    print(answer)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    """Point d'entrée `secubox-webllm`."""
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except (SessionNotReadyError, EmptyResponseError, TimeoutError) as exc:
        print(f"erreur : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
