# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: freebox :: magasin du jeton d'application
CyberMind — https://cybermind.fr

Le jeton d'application Freebox ouvre l'API de la box : il ne quitte JAMAIS la machine. Un fichier JSON, 0600, écrit de façon atomique
(tmp + os.replace) par l'utilisateur du module ; aucune route ne le rend, aucun journal ne le contient. Illisible ou absent = vide.
"""
import json
import os


class Magasin:
    def __init__(self, chemin):
        self.chemin = chemin

    def lire(self):
        try:
            with open(self.chemin, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def ecrire(self, maj):
        """Fusionne `maj` dans le contenu actuel."""
        doc = {**self.lire(), **maj}
        os.makedirs(os.path.dirname(self.chemin) or ".", mode=0o700, exist_ok=True)
        tmp = self.chemin + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(doc, ensure_ascii=False).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, self.chemin)
        return doc

    def oublier(self):
        try:
            os.remove(self.chemin)
        except OSError:
            pass
