# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Sous-processus yt-dlp : lancés dans leur PROPRE groupe, tués en groupe au délai (#4055).

yt-dlp lance lui-même des enfants (deno pour le défi « n » de YouTube, fournisseur de jetons
bgutil, ffmpeg à la fusion). `proc.kill()` ne tuait que yt-dlp : ses enfants survivaient,
rattachés à init, et continuaient de consommer le processeur (#3036, puis #4055 sur gk2).
On lance donc chaque yt-dlp en tête d'une nouvelle session et, au délai, on tue le GROUPE.
"""
import asyncio
import os
import signal


async def lancer(*argv):
    """`create_subprocess_exec` en nouvelle session (groupe de processus = pid du chef)."""
    return await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True)


async def tuer(proc, attente=10):
    """Tue le groupe entier (yt-dlp ET ses enfants), puis attend le chef : ni orphelin ni zombie."""
    if proc is None:
        return
    pid = getattr(proc, "pid", None)
    try:
        # Garde : jamais killpg(0) ni d'un pid douteux — ce serait NOTRE groupe.
        if not isinstance(pid, int) or pid <= 1:
            raise ProcessLookupError
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=attente)
    except asyncio.TimeoutError:
        pass
