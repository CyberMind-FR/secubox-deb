# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Lecture des listes publiques et index compact : une empreinte de 64 bits par domaine, tableau trié, 8 octets par domaine."""
import array
import bisect
import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Iterator

from . import domaines

MAGIE = b"WFIDX1\n"


def lire(texte: str, format: str) -> Iterator[str]:
    if format not in ("domaines", "hosts"):
        raise ValueError(f"format de liste inconnu : {format}")
    for ligne in texte.splitlines():
        ligne = ligne.split("#", 1)[0].strip()
        if not ligne or ligne.startswith("!"):
            continue
        champs = ligne.split()
        if format == "hosts":
            if len(champs) < 2:
                continue
            champ = champs[1]
        else:
            champ = champs[0]
        n = domaines.valider(champ)
        if n:
            yield n


def _h(nom: str) -> int:
    return int.from_bytes(hashlib.blake2b(nom.encode("ascii"), digest_size=8).digest(), "big")


class Index:
    """Domaines listés, réduits à une empreinte de 64 bits. Une collision (≈ 10⁻¹⁰ pour 4,6 M de domaines) ne fait qu'ajouter un faux
    classement en mode observe ; l'index n'est jamais utilisé pour écrire une règle."""

    def __init__(self, empreintes: "array.array"):
        self._a = empreintes

    @classmethod
    def depuis(cls, noms: Iterable[str]) -> "Index":
        return cls(array.array("Q", sorted({_h(n) for n in noms})))

    def __len__(self) -> int:
        return len(self._a)

    def _present(self, nom: str) -> bool:
        h = _h(nom)
        i = bisect.bisect_left(self._a, h)
        return i < len(self._a) and self._a[i] == h

    def correspondance(self, nom: str) -> str | None:
        """L'ENTRÉE de liste (le nom ou l'un de ses parents) qui correspond, ou None. Compter cette entrée, et non le nom interrogé, borne la
        cardinalité des compteurs par la taille de la liste : des sous-domaines aléatoires d'un domaine listé ne créent qu'une ligne."""
        etiquettes = nom.lower().rstrip(".").split(".")
        for k in range(len(etiquettes) - 1):                      # ne teste jamais le seul TLD
            candidat = ".".join(etiquettes[k:])
            if self._present(candidat):
                return candidat
        return None

    def contient(self, nom: str) -> bool:
        return self.correspondance(nom) is not None

    def ecrire(self, chemin: Path) -> None:
        if not len(self._a):
            raise ValueError("index vide : jamais écrit")
        a = array.array("Q", self._a)
        if sys.byteorder == "little":
            a.byteswap()                                          # fichier en grand-boutiste, lisible partout
        fd, tmp = tempfile.mkstemp(dir=Path(chemin).parent, prefix=".idx-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(MAGIE + a.tobytes())
                f.flush()
                os.fchmod(f.fileno(), 0o640)
                os.fsync(f.fileno())
            os.replace(tmp, chemin)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def charger(cls, chemin: Path) -> "Index":
        brut = Path(chemin).read_bytes()
        if not brut.startswith(MAGIE) or (len(brut) - len(MAGIE)) % 8:
            raise ValueError(f"{chemin} n'est pas un index valide")
        a = array.array("Q")
        a.frombytes(brut[len(MAGIE):])
        if sys.byteorder == "little":
            a.byteswap()
        return cls(a)
