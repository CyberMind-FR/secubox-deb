# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rétention de veille.db (V2 § 6, bornée en #3725) : événements 30 j, incidents 365 j, mesures 30 j, échantillons par
pays 8 j (#3811) ; lots de 1 000, transactions courtes.

Bornes (#3725) :
- dossiers sans incident ni action : 30 j après `derniere_vue` ; avec incident ou action : 365 j (liens, analyses et
  redescentes partent en cascade) ;
- propositions closes (refusee, expiree, faite, refusee_gk2, echec) et leurs approbations : 90 j, sauf si une action
  les porte encore ou si une proposition plus jeune (ou vivante) les cite en `reference` (chaîne ban → prolonger /
  unban) ;
- actions closes (faite dont le ban est fini, refusee_gk2, echec) : 365 j, AVANT leurs propositions (clé étrangère),
  jamais tant que le ban court (`fin_gk2` > maintenant) ni tant qu'une proposition plus jeune la cite ;
- acteurs_adresses : 30 j ; filtres retirés, rejetés ou en échec : 90 j ;
- audit_chaine : 365 j, seulement ce qui est déjà relayé dans audit.log ; aucune vérification de chaîne n'existe dans
  le code (chaque ligne se chaîne sur la dernière gardée), un début tronqué est donc sans effet ; audit.log reste la
  référence ;
- plafonds de secours par table (dossiers 200 000, propositions 200 000, actions 100 000, analyses 100 000) : les plus
  anciennes lignes closes d'abord.
Jamais purgé : une ligne vivante ou en vol (proposition proposee/approuvee/envoyee, action en envoi ou ban vivant,
dossier portant l'un d'eux, une redescente en attente ou un travail d'analyse en file). La base n'est jamais supprimée.
"""
from datetime import timedelta, timezone

LOT = 1000
EVENEMENTS_J = 30
INCIDENTS_J = 365
MESURES_J = 30
PAYS_J = 8
DOSSIER_SANS_TRACE_J = 30
PROPOSITIONS_J = 90
ACTIONS_J = 365
ADRESSES_J = 30
FILTRES_J = 90
AUDIT_J = 365
PLAFONDS = {"dossiers": 200_000, "propositions": 200_000, "actions": 100_000, "analyses": 100_000}

VIVANTES = "('proposee', 'approuvee', 'envoyee')"
CLOSES = "('refusee', 'expiree', 'faite', 'refusee_gk2', 'echec')"

# Dossier « vivant » : il porte une proposition en vol, une redescente en attente ou un travail d'analyse en file.
_DOSSIER_VIVANT = (f"(EXISTS (SELECT 1 FROM propositions q WHERE q.dossier_id = d.id AND q.etat IN {VIVANTES}) "
                   "OR EXISTS (SELECT 1 FROM redescentes r WHERE r.dossier_id = d.id AND r.appliquee_le IS NULL) "
                   "OR EXISTS (SELECT 1 FROM travaux t WHERE t.objet_id = d.id AND t.etat IN ('attente', 'en_cours')))")
_DOSSIER_AVEC_TRACE = ("(EXISTS (SELECT 1 FROM dossier_incidents di WHERE di.dossier_id = d.id) "
                       "OR EXISTS (SELECT 1 FROM propositions q2 JOIN actions a2 ON a2.proposition_id = q2.id "
                       "WHERE q2.dossier_id = d.id))")
# Action purgeable : close, ban fini, plus citée par une proposition plus jeune que `:lim_act`.
_ACTION_PURGEABLE = ("a.etat IN ('faite', 'refusee_gk2', 'echec') AND (a.fin_gk2 IS NULL OR a.fin_gk2 <= :maintenant_s) "
                     "AND NOT EXISTS (SELECT 1 FROM propositions r WHERE r.reference = a.proposition_id "
                     "AND (r.etat IN %s OR r.cree_le >= :lim_act))" % VIVANTES)
# Proposition purgeable : close, sans action, non citée par une proposition vivante ou plus jeune que `:lim_prop`.
_PROPOSITION_PURGEABLE = (f"p.etat IN {CLOSES} AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.proposition_id = p.id) "
                          "AND NOT EXISTS (SELECT 1 FROM propositions r WHERE r.reference = p.id "
                          f"AND (r.etat IN {VIVANTES} OR r.cree_le >= :lim_prop))")


def _rfc(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _par_lots(db, sql, params, limite=None):
    total = 0
    while True:
        db.execute("BEGIN IMMEDIATE")
        try:
            n = db.execute(sql, params).rowcount
            db.commit()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
        total += max(n, 0)
        if n < LOT:
            return total


def _borne_audit(db):
    """Dernier id purgeable de audit_chaine : avant la première ligne `relais` pas encore recopiée dans audit.log, et
    jamais la dernière ligne (tête de la chaîne)."""
    try:
        curseur = int(db.execute("SELECT valeur FROM executeur_etat WHERE cle = 'audit_relai'").fetchone()[0])
    except (TypeError, ValueError):
        curseur = 0
    tete = db.execute("SELECT COALESCE(MAX(id), 0) FROM audit_chaine").fetchone()[0]
    attente = db.execute("SELECT MIN(id) FROM audit_chaine WHERE id > ? AND json_valid(details_json) "
                         "AND json_extract(details_json, '$.relais') = 1", (curseur,)).fetchone()[0]
    return min(tete - 1, (attente - 1) if attente is not None else tete - 1)


def _plafonner(db, table, alias, cle, eligible, params):
    """Plafond de secours : retire les plus anciennes lignes ÉLIGIBLES au-delà du plafond de la table."""
    excedent = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] - PLAFONDS[table]
    total = 0
    while excedent > 0:
        n = min(excedent, LOT)
        db.execute("BEGIN IMMEDIATE")
        try:
            retire = db.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT {alias}.rowid FROM {table} {alias} "
                                f"WHERE {eligible} ORDER BY {alias}.{cle} LIMIT {n})", params).rowcount
            db.commit()
        except BaseException:
            if db.in_transaction:
                db.rollback()
            raise
        if retire <= 0:
            break                       # plus rien d'éligible : jamais une ligne vivante
        total += retire
        excedent -= retire
    return total


def purger(db, maintenant):
    """Supprime l'échu ; rend le nombre de lignes retirées par table."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    lim_evt = _rfc(maintenant - timedelta(days=EVENEMENTS_J))
    lim_inc = _rfc(maintenant - timedelta(days=INCIDENTS_J))
    lim_mes = _rfc(maintenant - timedelta(days=MESURES_J))
    params = {"maintenant_s": int(maintenant.timestamp()),
              "lim_act": _rfc(maintenant - timedelta(days=ACTIONS_J)),
              "lim_prop": _rfc(maintenant - timedelta(days=PROPOSITIONS_J))}
    res = {}
    # Ordre des clés étrangères : actions (qui portent les propositions), puis propositions (approbations en cascade).
    res["actions"] = _par_lots(
        db, "DELETE FROM actions WHERE rowid IN (SELECT a.rowid FROM actions a WHERE COALESCE(a.repondue_le, a.envoyee_le) "
            f"< :lim_act AND {_ACTION_PURGEABLE} LIMIT %d)" % LOT, params)
    res["propositions"] = _par_lots(
        db, "DELETE FROM propositions WHERE rowid IN (SELECT p.rowid FROM propositions p WHERE p.maj_le < :lim_prop "
            f"AND {_PROPOSITION_PURGEABLE} LIMIT %d)" % LOT, params)
    res["filtres"] = _par_lots(
        db, "DELETE FROM filtres WHERE rowid IN (SELECT rowid FROM filtres WHERE etat IN ('retire', 'rejete', 'echec') "
            "AND maj_le < :lim LIMIT %d)" % LOT, {"lim": params["lim_prop"]})
    # Dossiers (#3795, #3725) : sans incident ni action 30 j, avec 365 j ; vivants jamais. Liens, analyses et redescentes
    # partent en cascade ; les propositions closes gardent leur ligne (dossier_id passe à NULL).
    res["dossiers"] = _par_lots(
        db, "DELETE FROM dossiers WHERE rowid IN (SELECT d.rowid FROM dossiers d WHERE "
            f"NOT {_DOSSIER_VIVANT} AND ((d.derniere_vue < :lim_30 AND NOT {_DOSSIER_AVEC_TRACE}) "
            "OR d.derniere_vue < :lim_inc) LIMIT %d)" % LOT,
        {"lim_30": _rfc(maintenant - timedelta(days=DOSSIER_SANS_TRACE_J)), "lim_inc": lim_inc})
    # Incidents : leurs preuves partent en cascade et libèrent les événements anciens qu'elles retenaient.
    res["incidents"] = _par_lots(
        db, "DELETE FROM incidents WHERE rowid IN (SELECT rowid FROM incidents WHERE derniere_vue < ? LIMIT %d)" % LOT,
        (lim_inc,))
    res["evenements"] = _par_lots(
        db, "DELETE FROM evenements WHERE rowid IN (SELECT rowid FROM evenements WHERE horodatage < ? "
            "AND id NOT IN (SELECT evenement_id FROM incident_preuves) LIMIT %d)" % LOT, (lim_evt,))
    res["mesures"] = _par_lots(
        db, "DELETE FROM mesures WHERE rowid IN (SELECT rowid FROM mesures WHERE horodatage < ? LIMIT %d)" % LOT,
        (lim_mes,))
    res["pays"] = _par_lots(
        db, "DELETE FROM pays_echantillons WHERE rowid IN (SELECT rowid FROM pays_echantillons WHERE quand < ? LIMIT %d)"
            % LOT, (int((maintenant - timedelta(days=PAYS_J)).timestamp()),))
    res["adresses"] = _par_lots(
        db, "DELETE FROM acteurs_adresses WHERE rowid IN (SELECT rowid FROM acteurs_adresses WHERE horodatage < ? "
            "LIMIT %d)" % LOT, (_rfc(maintenant - timedelta(days=ADRESSES_J)),))
    res["audit"] = _par_lots(
        db, "DELETE FROM audit_chaine WHERE id IN (SELECT id FROM audit_chaine WHERE horodatage < :lim AND id <= :borne "
            "LIMIT %d)" % LOT, {"lim": _rfc(maintenant - timedelta(days=AUDIT_J)), "borne": _borne_audit(db)})
    # Plafonds de secours, après les âges : seulement des lignes éligibles, les plus anciennes d'abord.
    res["plafond_actions"] = _plafonner(db, "actions", "a", "envoyee_le", _ACTION_PURGEABLE, params)
    res["plafond_propositions"] = _plafonner(db, "propositions", "p", "maj_le", _PROPOSITION_PURGEABLE, params)
    res["plafond_analyses"] = _plafonner(db, "analyses", "n", "cree_le", "1 = 1", params)
    res["plafond_dossiers"] = _plafonner(db, "dossiers", "d", "derniere_vue", f"NOT {_DOSSIER_VIVANT}", params)
    return res


def liberer(db):
    """Rend le journal WAL au système de fichiers après une purge (la base ne rétrécit pas : ni VACUUM, ni suppression)."""
    try:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass
