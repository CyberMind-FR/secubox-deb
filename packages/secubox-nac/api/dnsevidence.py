# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-nac — preuve DNS pour la détection d'OS (#2236).

Lit, EN LECTURE SEULE, la base de compteurs DNS par appareil d'ad-guard (`dnstv_counts`) et ne rend, par adresse, que les domaines de connectivité qui
trahissent un système (`osdetect.DNS_SUFFIXES`). Aucun autre domaine ne sort de ce module : le NAC n'a pas à connaître l'historique de navigation.
Toute erreur (base absente, verrouillée, illisible) donne un résultat vide — la détection par le nom continue.
"""
from __future__ import annotations

import logging
import sqlite3
import time

from .osdetect import DNS_SUFFIXES, domaine_de_connectivite

logger = logging.getLogger("secubox.nac.dnsevidence")

DB_DEFAUT = "/var/lib/secubox/ad-guard/dnstv/dnstv.db"
JOURS = 3


def domaines_par_adresse(db_path: str = DB_DEFAUT, jours: int = JOURS) -> dict:
    depuis = time.strftime("%Y-%m-%d", time.localtime(time.time() - jours * 86400))
    cond = " OR ".join(["domaine = ? OR domaine LIKE ?"] * len(DNS_SUFFIXES))
    args: list = []
    for s in DNS_SUFFIXES:
        args += [s, "%." + s]
    out: dict = {}
    try:
        cx = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2)
        try:
            for client, domaine in cx.execute(f"SELECT DISTINCT client, domaine FROM dnstv_counts WHERE jour>=? AND decision='ALLOWED' AND ({cond})", [depuis, *args]):
                if domaine_de_connectivite(domaine):                      # le LIKE est un pré-filtre ; la règle exacte décide
                    out.setdefault(client, []).append(domaine)
        finally:
            cx.close()
    except (sqlite3.Error, OSError):
        logger.info("dnsevidence: base DNS illisible (%s)", db_path)
        return {}
    return out
