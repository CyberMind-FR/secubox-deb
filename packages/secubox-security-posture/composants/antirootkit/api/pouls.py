# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit pouls du démon (#3058)

Le démon d'exécution est un autre processus que l'API : sans signe de vie partagé, il pouvait être aveugle (point de
contrôle périmé, auditd muet) pendant des mois sans que la page le dise. Il écrit ici, à chaque passage, un petit
fichier JSON (écriture atomique) que l'API lit pour `/status`. Les totaux survivent aux redémarrages.
"""

import json
import os
import time

DEFAUT = "/var/lib/secubox/antirootkit/pouls.json"
CHAMPS = ("passages", "evenements", "conteneurs_ignores", "signales", "reamorcages")


class Pouls:
    def __init__(self, chemin: str = DEFAUT, now=time.time):
        self.chemin = chemin
        self.now = now
        self.etat = {c: 0 for c in CHAMPS}
        self.etat.update({"ts": None, "dernier_evenement": None, "depuis": now()})
        try:
            with open(chemin) as fh:
                ancien = json.load(fh)
            for c in CHAMPS:
                self.etat[c] = int(ancien.get(c, 0))
            self.etat["dernier_evenement"] = ancien.get("dernier_evenement")
            self.etat["depuis"] = ancien.get("depuis", self.etat["depuis"])
        except (OSError, ValueError, TypeError):
            pass

    def _ecrit(self) -> None:
        self.etat["ts"] = self.now()
        tmp = f"{self.chemin}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(self.etat, fh)
            os.replace(tmp, self.chemin)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def passage(self, vus: int, conteneurs: int, signales: int, dernier_evenement=None) -> None:
        self.etat["passages"] += 1
        self.etat["evenements"] += vus
        self.etat["conteneurs_ignores"] += conteneurs
        self.etat["signales"] += signales
        if dernier_evenement is not None:
            self.etat["dernier_evenement"] = dernier_evenement
        self._ecrit()

    def reamorcage(self) -> None:
        self.etat["reamorcages"] += 1
        self._ecrit()


def lire(chemin: str = DEFAUT, now=time.time, aveugle_apres: int = 120):
    """Le pouls tel que l'API le montre, ou None (fichier absent ou illisible : jamais une erreur)."""
    try:
        with open(chemin) as fh:
            d = json.load(fh)
        ts = float(d["ts"])
    except (OSError, ValueError, TypeError, KeyError):
        return None
    age = max(0.0, now() - ts)
    d["age_s"] = round(age, 1)
    # aveugle = plus aucun passage depuis `aveugle_apres` s : le démon est arrêté ou bloqué
    d["aveugle"] = age > aveugle_apres
    return d
