# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: fichier d'échange pour le DPI (#1960).

Un RÉSUMÉ par appareil du LAN (regroupé par MAC), pour le jour courant : requêtes, blocages, nombre de noms, TOP 10 des services (organisation + type, d'après
`lists/services.txt`) et répartition par type. VIE PRIVÉE : le fichier ne contient AUCUN nom de domaine demandé, seulement des organisations et des types ; pas
d'historique requête par requête. Le DNS ne donne ni volumes ni contenu : rien d'autre ici. Lecture par le DPI (API admin) ; écriture atomique en `0640`,
lecture sans suivre les liens symboliques. Module sans entrée/sortie réseau.
"""
from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Dict, Optional, Set

try:
    from . import dnstv
except ImportError:                                  # lancé hors paquet
    from api import dnstv

FICHIER = "dpi-feed.json"
SERVICES_MAX = 10
LECTURE_MAX = 1024 * 1024
INCONNU = "(inconnu)"


def _declare(etat: dict, adresses) -> Optional[dict]:
    for c in etat.get("clients", []):
        if c["ip"] in adresses:
            return c
    return None


def construire(compteurs: dict, voisins: Dict[str, str], etat: dict, services, exclus: Set[str], maintenant: int) -> dict:
    """compteurs : client -> domaine -> (requêtes, bloquées). Une source = une MAC (adresses regroupées) ou, sans MAC connue, une adresse seule."""
    sources = dnstv.regrouper_sources([c for c in compteurs if c not in exclus], voisins)
    appareils = []
    for cle, adresses in sources.items():
        domaines: Dict[str, tuple] = {}
        for a in adresses:
            for d, (n, b) in compteurs[a].items():
                if dnstv.valider_domaine(d) == d:                                      # un nom hostile n'est ni compté ni jamais recopié
                    n0, b0 = domaines.get(d, (0, 0))
                    domaines[d] = (n0 + int(n), b0 + int(b))
        if not domaines:
            continue
        par_service: Dict[tuple, list] = {}
        types: Dict[str, int] = {}
        for d, (n, b) in domaines.items():
            org, typ = services.classer(d)
            s = par_service.setdefault((org or INCONNU, typ), [0, 0])
            s[0] += n
            s[1] += min(b, n)
            types[typ] = types.get(typ, 0) + n
        top = sorted(par_service.items(), key=lambda kv: (-kv[1][0], kv[0][0]))[:SERVICES_MAX]
        decl = _declare(etat, set(adresses))
        mac = cle if dnstv.MAC_RE.match(cle) else ""
        nom = decl["nom"] if decl else (f"appareil {mac[-5:]}" if mac else sorted(adresses)[0])
        appareils.append({
            "nom": nom, "mac": mac, "adresses": sorted(adresses), "mode": decl["mode"] if decl else "non déclaré", "origine": (decl.get("origine", "admin") if decl else ""),
            "requetes": sum(n for n, _ in domaines.values()), "bloquees": sum(min(b, n) for n, b in domaines.values()), "domaines": len(domaines),
            "services": [{"organisation": org, "type": typ, "requetes": n, "bloquees": b} for (org, typ), (n, b) in top], "types": types})
    appareils.sort(key=lambda a: (-a["requetes"], a["nom"]))
    return {"version": 1, "genere": int(maintenant), "fenetre": "jour courant (UTC)", "appareils": appareils}


def ecrire_feed(feed: dict, dossier: Optional[Path] = None) -> None:
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".dpifeed.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            os.fchmod(h.fileno(), 0o600)                      # lu par le seul utilisateur du module (propriétaire) ; l'API du DPI tourne sous le même
            json.dump(feed, h, ensure_ascii=False)
        os.replace(tmp, d / FICHIER)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)                                    # pas de temporaire orphelin si l'écriture échoue (disque plein)
        raise


def charger_feed(dossier: Optional[Path] = None) -> Optional[dict]:
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER
    try:
        # O_NONBLOCK + S_ISREG : un tube nommé posé à la place du fichier ne doit pas bloquer le moteur (revue #1960)
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "r", encoding="utf-8") as h:
                fd = -1
                brut = json.loads(h.read(LECTURE_MAX))
        finally:
            if fd >= 0:
                os.close(fd)
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("appareils"), list) or not isinstance(brut.get("genere"), int):
        return None
    return brut
