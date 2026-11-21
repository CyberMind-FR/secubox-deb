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
import re
import sqlite3
import uuid
from datetime import datetime, timedelta

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


def confirmer_filtre(db, fid: str, acteur: str, maintenant: datetime) -> dict:
    """Confirmation en un clic d'un filtre WAF d'office (#3723, carte 4) : `a_confirmer` → `confirme` seulement (404
    inconnu, 409 `etat` sinon). Jamais d'office : le critère « réponse légitime » n'est pas mesurable depuis gk3."""
    def faire():
        r = db.execute("SELECT etat, outil, cve FROM filtres WHERE id = ?", (fid,)).fetchone()
        if r is None:
            raise RefusDecision(404, "inconnu")
        if r[0] != "a_confirmer":
            raise RefusDecision(409, "etat")
        db.execute("UPDATE filtres SET etat = 'confirme', confirme_par = ?, maj_le = ? WHERE id = ? "
                   "AND etat = 'a_confirmer'", (acteur, iso(maintenant), fid))
        ajouter_audit(db, maintenant, acteur, "filtre_confirme", fid, "confirme", {"outil": r[1], "cve": r[2]},
                      relais=True)
        return {"id": fid, "etat": "confirme"}
    return _transaction(db, faire)


# ── console #3724 : redescendre, analyser à nouveau, défaire ──

#: Miroir de `analyste.FILE_MAX` (travaux en attente au plus) : une demande humaine ne déborde pas la file.
FILE_MAX_ANALYSES = 500
#: Gestes V2 qu'une levée défait (`unban`, `reference` = la proposition du geste) : ban et ban_bloc par /ai/unban,
#: partager par /ai/unban (retrait de l'indicateur, le ban reste), limiter et leurre par /ai/lever.
DEFAISABLES = ("ban", "ban_bloc", "limiter", "leurre", "partager")
#: Une levée demandée par la console expire comme une proposition (défaut de politiques.toml).
EXPIRATION_LEVEE_MIN = 120
_RE_ID_GK2 = re.compile(r"^[0-9a-f]{32}$")


def demander_redescente(db, did: str, acteur: str, maintenant: datetime) -> dict:
    """Décision humaine : redescendre le dossier `did` à `observer` ; la VEILLE l'applique à sa passe suivante
    (riposte.appliquer_redescentes). 404 inconnu ; 409 `niveau` (déjà observer), `en_attente` (déjà demandée)."""
    def faire():
        r = db.execute("SELECT niveau FROM dossiers WHERE id = ?", (did,)).fetchone()
        if r is None:
            raise RefusDecision(404, "inconnu")
        if r[0] == "observer":
            raise RefusDecision(409, "niveau")
        if db.execute("SELECT 1 FROM redescentes WHERE dossier_id = ? AND appliquee_le IS NULL", (did,)).fetchone():
            raise RefusDecision(409, "en_attente")
        rid = str(uuid.uuid4())
        db.execute("INSERT INTO redescentes(id, dossier_id, acteur, demandee_le) VALUES (?, ?, ?, ?)",
                   (rid, did, acteur, iso(maintenant)))
        ajouter_audit(db, maintenant, acteur, "dossier_redescendre", did, "en_attente",
                      {"decision": rid, "niveau": r[0]}, relais=True)
        return {"dossier": did, "etat": "en_attente"}
    return _transaction(db, faire)


def demander_analyse(db, did: str, acteur: str, maintenant: datetime) -> dict:
    """Décision humaine : analyser à nouveau le dossier (travail `analyser`, une seule ligne en attente par
    dossier). 404 inconnu ; 503 `file_pleine`. Déjà en file : `deja_en_file`, rien n'est audité deux fois."""
    def faire():
        if db.execute("SELECT 1 FROM dossiers WHERE id = ?", (did,)).fetchone() is None:
            raise RefusDecision(404, "inconnu")
        if db.execute("SELECT 1 FROM travaux WHERE genre = 'analyser' AND objet_id = ? AND etat = 'attente'",
                      (did,)).fetchone():
            return {"dossier": did, "etat": "deja_en_file"}
        if db.execute("SELECT COUNT(*) FROM travaux WHERE etat = 'attente'").fetchone()[0] >= FILE_MAX_ANALYSES:
            raise RefusDecision(503, "file_pleine")
        db.execute("INSERT INTO travaux(genre, objet_id, etat, essais, disponible_le, cree_le, repere) "
                   "VALUES ('analyser', ?, 'attente', 0, ?, ?, NULL)", (did, maintenant.timestamp(), iso(maintenant)))
        ajouter_audit(db, maintenant, acteur, "dossier_analyser", did, "en_file", {}, relais=True)
        return {"dossier": did, "etat": "en_file"}
    return _transaction(db, faire)


def cible_levee(db, aid: str, maintenant: datetime):
    """(action à lever, proposition visée, motif de refus) pour l'action `aid` ; une prolongation se défait par le ban
    qu'elle prolonge. Lecture seule (utilisée aussi par la vue du dossier)."""
    r = db.execute("SELECT a.id, a.etat, a.id_gk2, a.fin_gk2, p.id, p.geste, p.cible, p.reference FROM actions a "
                   "JOIN propositions p ON p.id = a.proposition_id WHERE a.id = ?", (aid,)).fetchone()
    if r is None:
        return None, None, "inconnue"
    _, etat, id_gk2, fin, pid, geste, cible, reference = r
    if etat != "faite":
        return None, None, "etat"
    if not isinstance(id_gk2, str) or not _RE_ID_GK2.fullmatch(id_gk2):
        return None, None, "source"               # aucun id rendu par gk2 à V2 : pas un geste posé par V2
    if geste not in DEFAISABLES:
        return None, None, "geste"
    if isinstance(fin, int) and not isinstance(fin, bool) and fin <= int(maintenant.timestamp()):
        return None, None, "echu"
    if db.execute("SELECT 1 FROM propositions WHERE geste = 'unban' AND reference = ? AND etat IN "
                  "('proposee', 'approuvee', 'envoyee', 'faite')", (pid,)).fetchone():
        return None, None, "deja"
    return aid, {"id": pid, "geste": geste, "cible": cible}, None


def demander_defaire(db, aid: str, acteur: str, maintenant: datetime) -> dict:
    """Décision humaine : défaire l'action V2 `aid`. Crée la levée (`unban`, `reference` = la proposition du geste,
    dont dépendent riposte._NON_LEVE et l'exécuteur), approuvée par cet administrateur ; l'EXÉCUTEUR l'envoie
    (/ai/unban ou /ai/lever selon le geste visé) après l'avoir revalidée. 404 `inconnue` ; 409 `etat` (pas faite),
    `source` (pas posée par V2), `geste` (levée, prolongation : défaire le ban qu'elle prolonge), `echu`, `deja`,
    `en_cours` (une levée de la même cible est déjà en vol)."""
    def faire():
        _, cible, motif = cible_levee(db, aid, maintenant)
        if motif:
            raise RefusDecision(404 if motif == "inconnue" else 409, motif)
        pid = str(uuid.uuid4())
        h = iso(maintenant)
        expire = iso(maintenant + timedelta(minutes=EXPIRATION_LEVEE_MIN))
        texte = f"défaire demandé par un administrateur : levée du geste {cible['geste']} de la cible"
        try:
            db.execute("INSERT INTO propositions(id, version, dossier_id, incident_id, analyse_id, geste, cible, "
                       "duree_s, mode, niveau, reference, politique, motif, etat, expire_le, cree_le, maj_le) "
                       "SELECT ?, 1, dossier_id, incident_id, NULL, 'unban', cible, NULL, 'clic', NULL, id, "
                       "'gestes.unban', ?, 'approuvee', ?, ?, ? FROM propositions WHERE id = ?",
                       (pid, texte, expire, h, h, cible["id"]))
        except sqlite3.IntegrityError:
            raise RefusDecision(409, "en_cours") from None
        db.execute("INSERT INTO approbations(id, proposition_id, version, acteur, decision, motif, cree_le) "
                   "VALUES (?, ?, 1, ?, 'approuver', 'defaire', ?)", (str(uuid.uuid4()), pid, acteur, h))
        ajouter_audit(db, maintenant, acteur, "action_defaire", pid, "approuvee",
                      {"action": aid, "reference": cible["id"], "geste": cible["geste"], "cible": cible["cible"]},
                      relais=True)
        return {"proposition": pid, "etat": "approuvee", "geste": "unban", "reference": cible["id"]}
    return _transaction(db, faire)
