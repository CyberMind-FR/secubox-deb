# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Socket Unix du module : créée en 0660 (groupe `secubox`, donc nginx), jamais en 0666 comme le fait uvicorn quand il la lie lui-même."""
import os
import socket


def creer_socket(chemin: str) -> socket.socket:
    try:
        os.unlink(chemin)                              # socket périmée d'un précédent démarrage
    except FileNotFoundError:
        pass
    ancien = os.umask(0o117)                           # bind() crée la socket en 0777 & ~umask = 0660
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(chemin)
        s.listen(100)
    finally:
        os.umask(ancien)
    return s
