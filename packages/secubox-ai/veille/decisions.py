# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Décisions humaines sur veille.db (#3723, V2 § 5.2 et § 10.3) : approbation, refus, suspension de l'automatique.

Bibliothèque standard seulement : importée par l'API (secubox-ai.service), par `secubox-aictl veille …` et par
l'exécuteur. Chaque décision est UNE transaction courte (BEGIN IMMEDIATE : deux décisions simultanées sont
sérialisées par SQLite, la seconde voit la première) qui écrit sa ligne `audit_chaine` chaînée sur la précédente.

L'API n'écrit jamais `/var/log/secubox/audit.log` (profil AppArmor `deny w`) : ses lignes portent `"relais": true`
et l'exécuteur de la veille (ajout seul permis à son profil) les recopie dans audit.log, dans l'ordre, une seule fois
(curseur `audit_relai` d'`executeur_etat`).

Suspension (`executeur_etat.suspension`, JSON) : posée par un administrateur (console, `secubox-aictl`), ou par
l'exécuteur lui-même (`par` = `secubox-ai-veille`) ; elle vit dans veille.db, donc survit au redémarrage. La valeur
`[suspension] automatique_suspendu` de politiques.toml s'y AJOUTE (l'une ou l'autre suspend), elle ne l'efface jamais.
"""
import hashlib
import json
import uuid
from datetime import datetime

ACTEUR_VEILLE = "secubox-ai-veille"
DECISIONS = {"approuver": "approuvee", "refuser": "refusee"}


class RefusDecision(Exception):
    """Décision refusée : `statut` HTTP (404, 409, 503) et `motif` court du code."""

    def __init__(self, statut: int, motif: str):
        super().__init__(f"{statut} {motif}")
        self.statut = statut
        self.motif = motif


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ajouter_audit(db, maintenant: datetime, acteur: str, operation: str, objet: str, resultat: str, details: dict,
                  relais: bool = False) -> None:
    """Ligne `audit_chaine` chaînée (même empreinte que collecte._audit, acteur en plus). À appeler DANS une
    transaction. `relais` : à recopier dans audit.log par la veille (l'appelant ne peut pas l'écrire)."""
    if relais:
        details = {**details, "relais": True}
    prec = db.execute("SELECT empreinte FROM audit_chaine ORDER BY id DESC LIMIT 1").fetchone()
    prec = prec[0] if prec else None
    h = iso(maintenant)
    d = json.dumps(details, ensure_ascii=False, sort_keys=True)
    emp = hashlib.sha256("\x1f".join([prec or "", h, acteur, operation, objet or "", d]).encode()).hexdigest()
    db.execute("INSERT INTO audit_chaine(horodatage, acteur, operation, objet, objet_id, resultat, details_json, "
               "empreinte_prec, empreinte) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)",
               (h, acteur, operation, objet, resultat, d, prec, emp))


def lire_etat(db, cle: str):
    r = db.execute("SELECT valeur FROM executeur_etat WHERE cle = ?", (cle,)).fetchone()
    return r[0] if r else None


def poser_etat(db, cle: str, valeur: str, maintenant: datetime) -> None:
    db.execute("INSERT INTO executeur_etat(cle, valeur, maj_le) VALUES (?, ?, ?) ON CONFLICT(cle) DO UPDATE SET "
               "valeur = excluded.valeur, maj_le = excluded.maj_le", (cle, valeur, iso(maintenant)))


def _transaction(db, fonction):
    db.execute("BEGIN IMMEDIATE")
    try:
        res = fonction()
        db.execute("COMMIT")
        return res
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def suspension(db) -> dict:
    """État de la suspension enregistrée (sans la politique) : {suspendu, par, motif, depuis}."""
    brut = lire_etat(db, "suspension")
    try:
        s = json.loads(brut) if brut else {}
    except ValueError:
        s = {"suspendu": True, "par": "?", "motif": "illisible"}      # illisible : suspendu par prudence
    if not isinstance(s, dict):
        s = {"suspendu": True, "par": "?", "motif": "illisible"}
    return {"suspendu": s.get("suspendu") is True, "par": s.get("par"), "motif": s.get("motif"),
            "depuis": s.get("depuis")}


def _poser_suspension(db, suspendu: bool, acteur: str, motif: str, maintenant: datetime, relais: bool,
                      operation: str) -> bool:
    avant = suspension(db)
    if avant["suspendu"] == suspendu:
        return False
    poser_etat(db, "suspension", json.dumps({"suspendu": suspendu, "par": acteur, "motif": motif,
                                             "depuis": iso(maintenant)}, sort_keys=True), maintenant)
    ajouter_audit(db, maintenant, acteur, operation, "automatique", "suspendu" if suspendu else "repris",
                  {"motif": motif, "avant": avant["suspendu"]}, relais=relais)
    return True


def suspendre(db, acteur: str, maintenant: datetime, motif: str = "manuel", relais: bool = True,
              operation: str = "veille_suspendre") -> bool:
    """Suspend l'automatique ; rend True si l'état a changé. Transaction propre."""
    return _transaction(db, lambda: _poser_suspension(db, True, acteur, motif, maintenant, relais, operation))


def reprendre(db, acteur: str, maintenant: datetime, relais: bool = True) -> bool:
    """Lève la suspension enregistrée (manuelle ou d'elle-même) ; rend True si l'état a changé."""
    return _transaction(db, lambda: _poser_suspension(db, False, acteur, "manuel", maintenant, relais,
                                                      "veille_reprendre"))


def suspendre_dans(db, acteur: str, maintenant: datetime, motif: str) -> bool:
    """Suspension par l'exécuteur, DANS sa transaction (audit `veille-auto-suspendue`, écrit par la veille)."""
    return _poser_suspension(db, True, acteur, motif, maintenant, False, "veille-auto-suspendue")


def decider(db, pid: str, version, acteur: str, decision: str, maintenant: datetime) -> dict:
    """Approuve ou refuse la proposition `(pid, version)`. Refus : 404 inconnue ; 409 `version` (changée),
    `expiree`, `decidee` (déjà décidée, envoyée ou close). Une seule décision par (proposition, version)."""
    if decision not in DECISIONS:
        raise ValueError(decision)
    if isinstance(version, bool) or not isinstance(version, int):
        raise RefusDecision(422, "version")

    def faire():
        r = db.execute("SELECT etat, version, expire_le, geste, cible FROM propositions WHERE id = ?",
                       (pid,)).fetchone()
        if r is None:
            raise RefusDecision(404, "inconnue")
        etat, v, expire_le, geste, cible = r
        if v != version:
            raise RefusDecision(409, "version")
        if etat != "proposee" or db.execute("SELECT 1 FROM approbations WHERE proposition_id = ? AND version = ?",
                                            (pid, version)).fetchone():
            raise RefusDecision(409, "decidee")
        if expire_le <= iso(maintenant):
            raise RefusDecision(409, "expiree")
        nouvel = DECISIONS[decision]
        db.execute("INSERT INTO approbations(id, proposition_id, version, acteur, decision, motif, cree_le) "
                   "VALUES (?, ?, ?, ?, ?, NULL, ?)", (str(uuid.uuid4()), pid, version, acteur, decision,
                                                       iso(maintenant)))
        n = db.execute("UPDATE propositions SET etat = ?, maj_le = ? WHERE id = ? AND etat = 'proposee' AND "
                       "version = ?", (nouvel, iso(maintenant), pid, version)).rowcount
        if n != 1:
            raise RefusDecision(409, "decidee")
        ajouter_audit(db, maintenant, acteur, f"proposition_{nouvel}", pid, nouvel,
                      {"geste": geste, "cible": cible, "version": version}, relais=True)
        return {"id": pid, "version": version, "etat": nouvel}
    return _transaction(db, faire)
