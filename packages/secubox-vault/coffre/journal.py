# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Journal chaîné du Coffre (§7) : chaque ligne porte le SHA-256 de la précédente.

Effacer, modifier ou réordonner une ligne casse la chaîne à cet endroit, et
`verifier` le dit. Il ne contient JAMAIS une valeur, une phrase ni un code :
des événements, des identifiants de serrure, des noms de secret.
"""
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ORIGINE = "0" * 64


def _empreinte(ligne: bytes) -> str:
    return hashlib.sha256(ligne.rstrip(b"\n")).hexdigest()


class Journal:
    def __init__(self, chemin: Path):
        self.chemin = Path(chemin)

    def _derniere(self, f) -> str:
        f.seek(0, os.SEEK_END)
        taille = f.tell()
        if taille == 0:
            return ORIGINE
        pas, fin = 4096, taille
        tampon = b""
        while fin > 0:
            debut = max(0, fin - pas)
            f.seek(debut)
            tampon = f.read(fin - debut) + tampon
            lignes = tampon.rstrip(b"\n").split(b"\n")
            if len(lignes) > 1 or debut == 0:
                return _empreinte(lignes[-1])
            fin = debut
        return ORIGINE

    def ajouter(self, evt: str, **details) -> None:
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.chemin, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o640)
        with os.fdopen(fd, "r+b") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                entree = {
                    "t": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "evt": evt,
                    "details": details,
                    "prec": self._derniere(f),
                }
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(entree, sort_keys=True, ensure_ascii=False).encode() + b"\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    def verifier(self) -> tuple:
        """(intègre, numéro de la première ligne fautive ou None, nombre de lignes)."""
        if not self.chemin.exists():
            return True, None, 0
        prec, n = ORIGINE, 0
        with open(self.chemin, "rb") as f:
            for n, ligne in enumerate(f, 1):
                try:
                    if json.loads(ligne)["prec"] != prec:
                        return False, n, n
                except (ValueError, KeyError):
                    return False, n, n
                prec = _empreinte(ligne)
        return True, None, n

    def derniers(self, n: int = 50) -> list:
        if not self.chemin.exists():
            return []
        with open(self.chemin, "rb") as f:
            lignes = f.read().splitlines()[-max(0, n):]
        sortie = []
        for l in lignes:
            try:
                e = json.loads(l)
                sortie.append({"t": e.get("t"), "evt": e.get("evt"), "details": e.get("details", {})})
            except ValueError:
                sortie.append({"t": None, "evt": "illisible", "details": {}})
        return sortie
