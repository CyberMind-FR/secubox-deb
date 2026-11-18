# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rétention de veille.db (V2 § 6) : événements 30 j, incidents 365 j, mesures 30 j ; lots de 1 000, transactions courtes.

Un événement qui prouve un incident gardé n'est jamais purgé (clé étrangère) ; la base elle-même n'est jamais supprimée.
"""
from datetime import timedelta, timezone

LOT = 1000
EVENEMENTS_J = 30
INCIDENTS_J = 365
MESURES_J = 30


def _rfc(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _par_lots(db, sql, params):
    total = 0
    while True:
        db.execute("BEGIN IMMEDIATE")
        n = db.execute(sql, params).rowcount
        db.commit()
        total += max(n, 0)
        if n < LOT:
            return total


def purger(db, maintenant):
    """Supprime l'échu ; rend le nombre de lignes retirées par table."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    lim_evt = _rfc(maintenant - timedelta(days=EVENEMENTS_J))
    lim_inc = _rfc(maintenant - timedelta(days=INCIDENTS_J))
    lim_mes = _rfc(maintenant - timedelta(days=MESURES_J))
    # Incidents d'abord : leurs preuves partent en cascade et libèrent les événements anciens qu'elles retenaient.
    incidents = _par_lots(
        db, "DELETE FROM incidents WHERE rowid IN (SELECT rowid FROM incidents WHERE derniere_vue < ? LIMIT %d)" % LOT,
        (lim_inc,))
    evenements = _par_lots(
        db, "DELETE FROM evenements WHERE rowid IN (SELECT rowid FROM evenements WHERE horodatage < ? "
            "AND id NOT IN (SELECT evenement_id FROM incident_preuves) LIMIT %d)" % LOT, (lim_evt,))
    mesures = _par_lots(
        db, "DELETE FROM mesures WHERE rowid IN (SELECT rowid FROM mesures WHERE horodatage < ? LIMIT %d)" % LOT,
        (lim_mes,))
    return {"evenements": evenements, "incidents": incidents, "mesures": mesures}
