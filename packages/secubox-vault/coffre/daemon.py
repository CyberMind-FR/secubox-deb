# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le démon du Coffre : deux sockets, un processus, une MK (#1367 P1).

La socket publique est relayée par l'agrégateur ; la socket racine vit dans un
répertoire 0700 que seul root (et le démon) traverse — sans fenêtre où
uvicorn l'aurait laissée en 0666. Un veilleur rescelle à l'échéance même sans
requête ; l'arrêt du processus rescelle aussi.
"""
import asyncio
import contextlib
import grp
import os
import signal

import uvicorn

from api.main import COFFRE, public, racine

PUBLIC = os.environ.get("SECUBOX_COFFRE_SOCKET", "/run/secubox/vault.sock")
RACINE = os.environ.get("SECUBOX_COFFRE_SOCKET_RACINE", "/run/secubox-coffre/racine.sock")
GROUPE_PUBLIC = os.environ.get("SECUBOX_COFFRE_GROUPE", "secubox")


class _Serveur(uvicorn.Server):
    """Deux serveurs dans une boucle : c'est nous qui tenons les signaux."""

    def install_signal_handlers(self):          # uvicorn < 0.29
        pass

    @contextlib.contextmanager
    def capture_signals(self):                  # uvicorn >= 0.29
        yield


async def _veilleur(serveurs) -> None:
    while not all(s.should_exit for s in serveurs):
        await asyncio.sleep(30)
        COFFRE.ouvert                           # l'accès rescelle à l'échéance


async def principal() -> None:
    os.umask(0o077)
    if not os.path.isdir(os.path.dirname(RACINE)):
        raise SystemExit(f"coffre : {os.path.dirname(RACINE)} absent — RuntimeDirectory vidé par un drop-in ?")
    for chemin in (PUBLIC, RACINE):
        try:
            os.unlink(chemin)
        except FileNotFoundError:
            pass
        except PermissionError:
            raise SystemExit(f"coffre : {chemin} appartient à un autre utilisateur — "
                             "l'unité le retire au démarrage (ExecStartPre)")
    serveurs = [_Serveur(uvicorn.Config(public, uds=PUBLIC, log_level="warning")),
                _Serveur(uvicorn.Config(racine, uds=RACINE, log_level="warning"))]
    boucle = asyncio.get_running_loop()

    def arret() -> None:
        COFFRE.sceller("arret")
        for s in serveurs:
            s.should_exit = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        boucle.add_signal_handler(sig, arret)
    taches = [asyncio.create_task(s.serve()) for s in serveurs]
    while not all(s.started for s in serveurs):
        if any(t.done() for t in taches):
            break
        await asyncio.sleep(0.05)
    if all(s.started for s in serveurs):
        os.chmod(RACINE, 0o600)
        os.chmod(PUBLIC, 0o660)
        with contextlib.suppress(KeyError, PermissionError):
            os.chown(PUBLIC, -1, grp.getgrnam(GROUPE_PUBLIC).gr_gid)
    veille = asyncio.create_task(_veilleur(serveurs))
    try:
        await asyncio.gather(*taches)
    finally:
        veille.cancel()
        COFFRE.sceller("arret")


if __name__ == "__main__":
    asyncio.run(principal())
