# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Échantillons par pays du Radar (#3811), portés du POC gk0 (`_pays_echantillon`, 2026-11-18).

Un échantillon au plus par créneau de 15 min (`quand // 900`), lu par le client signé de la veille sur les routes
déjà déclarées `stats` (/waf/stats : top_countries, threats_today) et `bans` (/waf/bans : pays des bans actifs), les
mêmes que le relevé du Radar. Gardé 8 jours (purge à chaque écriture, et par `retention.purger`). Une source illisible
est rangée NULL, jamais 0 ; si les deux le sont, rien n'est écrit. Rien n'est extrapolé ici : la lecture « même heure
hier / J-7 » est faite par l'API (api/radar.py) sur les échantillons réels.
"""
import asyncio
import json
import logging
from collections import Counter

log = logging.getLogger("secubox-ai-veille")

PAS_S = 900
GARDE_S = 8 * 86400
TOP = 5


def _entier(v):
    return isinstance(v, int) and not isinstance(v, bool)


def extraire(stats, bans):
    """(alertes|None, tot_alertes|None, bans|None, tot_bans|None) d'une lecture de gk2 ; None = source illisible."""
    alertes = tot_alertes = par_pays = tot_bans = None
    if isinstance(stats, dict) and _entier(stats.get("threats_today")):
        tot_alertes, alertes = stats["threats_today"], {}
        top = stats.get("top_countries") if isinstance(stats.get("top_countries"), list) else []
        for x in top[:TOP]:
            if isinstance(x, dict) and isinstance(x.get("country"), str) and x["country"] and _entier(x.get("count")):
                alertes[x["country"][:8]] = x["count"]
    if isinstance(bans, dict) and isinstance(bans.get("bans"), list):
        liste = [b for b in bans["bans"] if isinstance(b, dict)]
        tot_bans = len(liste)
        par_pays = dict(Counter(str(b["country"])[:8] for b in liste if isinstance(b.get("country"), str)
                                and b["country"]).most_common(TOP))
    return alertes, tot_alertes, par_pays, tot_bans


def creneau_fait(db, maintenant_s: float) -> bool:
    return db.execute("SELECT 1 FROM pays_echantillons WHERE creneau = ?", (int(maintenant_s // PAS_S),)).fetchone() is not None


def ecrire(db, maintenant_s: float, alertes, tot_alertes, bans, tot_bans) -> bool:
    """Un échantillon (le premier du créneau gagne) et la purge des plus de 8 jours. Rend True s'il est écrit."""
    if alertes is None and bans is None:
        return False
    q = int(maintenant_s)
    db.execute("BEGIN IMMEDIATE")
    try:
        n = db.execute("INSERT OR IGNORE INTO pays_echantillons(creneau, quand, alertes_json, tot_alertes, bans_json, tot_bans) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (q // PAS_S, q, None if alertes is None else json.dumps(alertes, sort_keys=True), tot_alertes,
                        None if bans is None else json.dumps(bans, sort_keys=True), tot_bans)).rowcount
        db.execute("DELETE FROM pays_echantillons WHERE quand < ?", (q - GARDE_S,))
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return n > 0


async def lire(client):
    """Lecture de gk2 par le client signé ; une route en erreur rend None pour sa part (journalisé)."""
    res = await asyncio.gather(client.get("stats"), client.get("bans"), return_exceptions=True)
    for nom, x in zip(("stats", "bans"), res):
        if isinstance(x, BaseException):
            log.warning("pays : lecture %s en échec (%s)", nom, x.__class__.__name__)
    return extraire(*[None if isinstance(x, BaseException) else x for x in res])


async def tour(sql, client, maintenant_s: float) -> bool:
    """Un tour de la boucle (toutes les 60 s) : rien si le créneau est déjà échantillonné, sinon lecture puis écriture.
    `sql(f)` exécute f(db) hors de la boucle, sérialisé (Veille.sql)."""
    if await sql(lambda db: creneau_fait(db, maintenant_s)):
        return False
    lu = await lire(client)
    return await sql(lambda db: ecrire(db, maintenant_s, *lu))
