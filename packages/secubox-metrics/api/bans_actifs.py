# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Bans actifs du WAF, lus EN INCREMENTAL dans bans.jsonl (#3813).

`build_waf_stats` relisait tout `bans.jsonl` a chaque appel : 11 Mo et 105 000
lignes sur gk2, chaque ligne gardee en dict jusqu'a la fin (~32 Mo de pic par
appel). Les deux boucles du cache leger et chaque requete du bandeau de sante
qui trouvait le cache perime le faisaient EN MEME TEMPS, dans autant de fils :
20 appels concurrents laissent ~460 Mo de tas fragmente que glibc ne rend pas
(mesure sur une copie du fichier de gk2). C'etait la montee de 52 a 450 Mo en
15 min, puis 750 Mo.

Ici on ne lit que ce qui s'est ajoute depuis le passage precedent, ligne a
ligne, et on ne garde que les bans encore actifs ({ip: echeance}) : la memoire
suit le nombre de bans actifs, pas la taille du journal.

Depuis #3816, sbxwaf compacte le journal (nouveau fichier puis rename) : un
autre inode fait tout relire depuis le debut.
"""

import json
import os
import threading
import time
from pathlib import Path

FICHIER = Path("/var/lib/secubox/waf/bans.jsonl")


class BansActifs:
    def __init__(self, chemin: Path = FICHIER):
        self.chemin = chemin
        self._verrou = threading.Lock()
        self._cle: tuple | None = None   # (dev, inode) : detecte la rotation
        self._pos = 0                    # octets deja consommes
        self._actifs: dict[str, int] = {}  # ip -> echeance (0 = sans echeance)

    def compter(self, maintenant: int | None = None) -> int:
        """Nombre de bans actifs. OSError si le fichier est illisible."""
        now = int(time.time()) if maintenant is None else maintenant
        with self._verrou:
            self._lire(now)
            for ip in [ip for ip, exp in self._actifs.items() if exp and exp <= now]:
                del self._actifs[ip]     # un ban echu ne redevient actif que par une ligne neuve
            return len(self._actifs)

    def _lire(self, now: int) -> None:
        # Identite lue sur le descripteur OUVERT (fstat), jamais par un stat du chemin avant l'ouverture : sbxwaf
        # compacte le journal par rename (#3816) ; un rename entre stat et open ferait lire le nouveau fichier a la
        # position de l'ancien.
        with self.chemin.open("rb") as fh:
            st = os.fstat(fh.fileno())
            cle = (st.st_dev, st.st_ino)
            if cle != self._cle or st.st_size < self._pos:
                self._cle, self._pos, self._actifs = cle, 0, {}
            if st.st_size == self._pos:
                return
            fh.seek(self._pos)
            for brute in fh:
                if not brute.endswith(b"\n"):
                    break                # ligne en cours d'ecriture : relue au tour suivant
                self._pos += len(brute)
                self._appliquer(brute, now)

    def _appliquer(self, brute: bytes, now: int) -> None:
        try:
            r = json.loads(brute)
        except ValueError:
            return
        if not isinstance(r, dict):
            return
        ip = r.get("ip")
        if not ip or not isinstance(ip, str):
            return
        # Meme regle qu'avant : seule la DERNIERE ligne d'une IP compte.
        if r.get("action") == "ban":
            try:
                exp = int(r.get("exp") or 0)
            except (TypeError, ValueError):
                exp = -1                     # echeance illisible : non compte
            if exp == 0 or exp > now:
                self._actifs[ip] = exp
            else:
                self._actifs.pop(ip, None)   # deja echu : rien a garder
        else:
            self._actifs.pop(ip, None)


_bans = BansActifs()


def bans_actifs() -> int:
    return _bans.compter()
