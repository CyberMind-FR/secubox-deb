# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: contrat de stockage consommé par le canal (#3126)

Le canal ne connaît que ce protocole ; la version SQLite (Task 9) s'y conforme. Les valeurs reçues d'une box sont déjà bornées
et de forme vérifiée quand elles arrivent ici. Les méthodes sont synchrones : le canal les appelle hors de la boucle (to_thread).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Optional, Protocol

from .identite import Box

DOSSIER_DEFAUT = Path("/var/lib/secubox/pilotage")
HORS_LIGNE_S = 90            # une box non vue depuis ce délai passe « hors ligne »
EVENEMENTS_JOURS = 30        # durée de garde des événements
BOUCLES_FENETRE_S = 24 * 3600
PARAMS_MAX = 5000            # paramètres retenus par réponse (l'agent borne le corps à 256 Kio : TailleMax)
LIGNES_MAX = 2 * PARAMS_MAX  # lignes d'inventaire gardées par box : au-delà, les plus anciennes (releve_le) partent
OCTETS_MAX = 1 << 20         # OCTETS d'inventaire gardés par box : somme de length(CAST(valeur_json AS BLOB)), UTF-8 ; 2 × 256 Kio (corps
                             # borné à 256 Kio par l'agent, TailleMax, et par le maître, canal.TAILLE_MAX) + marge (R39)
EVENEMENTS_MAX = 5000        # événements gardés par box : au-delà, les plus anciens partent
VALEUR_MAX = 64 << 10       # caractères d'une valeur sérialisée ; au-delà elle est TRONQUÉE et marquée, jamais jetée (R38)
CHEMIN_MAX = 256
SORTIE_MAX = 256 << 10
REFUS_JOURNAL_S = 3600       # paramètres refusés : une ligne de journal par box et par heure au plus
OPERATIONS_MAX = 1000        # demandes gardées par box (L2) : au-delà, les plus anciennes partent
ORPHELINES_MAX = 100         # suivis de jobs inconnus gardés par box, plafond À PART : une box qui invente des jobs n'évince aucune demande
SUPPORTS_MAX = 100           # sessions de support gardées par box
SUPPORT_DUREE_MAX_MIN = 240  # borne d'une session de support (4 h), aussi celle d'une session que le maître n'a pas demandée
SUPPORT_TERMINAUX = ("refuse", "ferme", "annule", "expire")
TYPE_PROGRESSION = "X_SECUBOX_OperationProgress"
TYPE_FIN = "X_SECUBOX_OperationDone"
TYPE_SUPPORT = "X_SECUBOX_Support"
TYPES_DEDOUBLONNES = ("X_SECUBOX_HandsTied", "X_SECUBOX_Consent")   # remise « au moins une fois » : même (type, id, état) = rien de nouveau

C_MEM = "Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available"
C_SWAP_TOTAL = "Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal"
C_SWAP_USED = "Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed"
C_CPU = "Device.DeviceInfo.ProcessStatus.CPUUsage"
C_ECHECS = "Device.X_SECUBOX_Services.FailedNumberOfEntries"
C_MAINS = "Device.X_SECUBOX_Pilotage.MainsLiees"
TYPE_BOUCLE = "X_SECUBOX_ServiceLoop"
_RESUME = (C_MEM, C_SWAP_TOTAL, C_SWAP_USED, C_CPU, C_ECHECS, C_MAINS)

log = logging.getLogger("pilotage.stockage")


class StockageCanal(Protocol):
    def vu(self, box: Box, infos: dict) -> None:
        """Signe de vie : bonjour (infos = agent_version, boot_id, modele) ou sondage (infos = {})."""

    def notification(self, box: Box, evenement: dict) -> Optional[dict]:
        """Un événement NOTIFY remis par la box (le contenu de `body.event`). Rend l'opération qu'un X_SECUBOX_OperationDone
        vient de terminer (la première fois seulement), sinon None."""

    def resultat(self, box: Box, msg_id: str, reponse: dict) -> None:
        """Une réponse livrée à une requête émise pour cette box (`{msg_id, type, body}`)."""


class StockageMemoire:
    """Implémentation en mémoire, pour les tests."""

    def __init__(self) -> None:
        self.vus: list = []
        self.notifications: list = []
        self.resultats: list = []
        self.par_cle: dict = {}  # Box.cle -> [(msg_id, reponse)]

    def vu(self, box: Box, infos: dict) -> None:
        self.vus.append((box, dict(infos)))

    def notification(self, box: Box, evenement: dict) -> Optional[dict]:
        self.notifications.append((box, evenement))
        return None

    def resultat(self, box: Box, msg_id: str, reponse: dict) -> None:
        self.resultats.append((box, msg_id, reponse))
        self.par_cle.setdefault(box.cle, []).append((msg_id, reponse))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS boites(
    cle TEXT PRIMARY KEY, nom TEXT NOT NULL, adresse TEXT NOT NULL, reseau TEXT NOT NULL, client TEXT, abonnement TEXT,
    agent_version TEXT NOT NULL DEFAULT '', vu_le INTEGER NOT NULL,
    inventaire_le INTEGER, inventaire_partiel INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS boites_nom ON boites(nom);
CREATE TABLE IF NOT EXISTS inventaire(
    cle TEXT NOT NULL, chemin TEXT NOT NULL, valeur_json TEXT NOT NULL, releve_le INTEGER NOT NULL, tronque INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(cle, chemin));
CREATE TABLE IF NOT EXISTS evenements(
    id INTEGER PRIMARY KEY AUTOINCREMENT, cle TEXT NOT NULL, type TEXT NOT NULL, unite TEXT, valeur INTEGER,
    survenu_le INTEGER NOT NULL, recu_le INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS evenements_recu ON evenements(recu_le);
CREATE INDEX IF NOT EXISTS evenements_cle ON evenements(cle, recu_le);
CREATE INDEX IF NOT EXISTS evenements_cle_id ON evenements(cle, id);
CREATE TABLE IF NOT EXISTS releves(
    cle TEXT PRIMARY KEY, recu_le INTEGER NOT NULL, duree_s INTEGER NOT NULL, statut TEXT NOT NULL, sortie_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operations(
    id INTEGER PRIMARY KEY AUTOINCREMENT, cle TEXT NOT NULL, job TEXT, action TEXT, args_json TEXT NOT NULL DEFAULT '{}',
    acteur TEXT, support TEXT, etat TEXT NOT NULL, raison TEXT, etape TEXT, pct INTEGER, rc INTEGER, resume TEXT,
    demande_le INTEGER NOT NULL, maj_le INTEGER NOT NULL, fin_le INTEGER, suite_faite INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS operations_job ON operations(cle, job) WHERE job IS NOT NULL;
CREATE INDEX IF NOT EXISTS operations_cle ON operations(cle, id);
CREATE TABLE IF NOT EXISTS supports(
    cle TEXT NOT NULL, id TEXT NOT NULL, etat TEXT NOT NULL, duree_min INTEGER NOT NULL, acteur TEXT, fin INTEGER,
    demande_le INTEGER NOT NULL, maj_le INTEGER NOT NULL, PRIMARY KEY(cle, id));
"""


def _json(v) -> str:
    return json.dumps(v, ensure_ascii=False, allow_nan=False)


def _tronquer(v, maxi: int) -> Optional[str]:
    """Le JSON d'une valeur trop longue, ramené sous `maxi` caractères en gardant son début et son type : premiers éléments d'une liste, premières
    entrées d'un objet, premiers caractères d'une chaîne. None pour un autre type (un nombre ne dépasse jamais 64 Kio)."""
    if isinstance(v, (list, dict)):
        elements = list(v.items()) if isinstance(v, dict) else v
        taille, k = 2, 0                                     # crochets ou accolades ; séparateur « , » entre deux éléments
        for e in elements:
            t = len(_json(e[0])) + 2 + len(_json(e[1])) if isinstance(v, dict) else len(_json(e))
            if taille + t + (2 if k else 0) > maxi:
                break
            taille += t + (2 if k else 0)
            k += 1
        brut = _json(dict(elements[:k]) if isinstance(v, dict) else elements[:k])
    elif isinstance(v, str):
        n = maxi - 2
        brut = _json(v[:n])
        while len(brut) > maxi and n > 0:                    # échappements : une chaîne JSON est plus longue que son texte
            n -= max(1, len(brut) - maxi)
            brut = _json(v[:n])
    else:
        return None
    return brut if len(brut) <= maxi else None


def _nombre(v):
    """Un nombre JSON (ni booléen, ni NaN) ou None."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
        return None
    return v


class StockageSqlite:
    """SQLite `pilotage.db` (0640, WAL). Méthodes synchrones : une connexion courte par appel, transactions courtes ; à appeler
    hors de la boucle asyncio (to_thread). Les tables sont indexées par `Box.cle`, jamais par le nom seul (R15)."""

    def __init__(self, dossier: Path = DOSSIER_DEFAUT, horloge: Callable[[], float] = time.time, *,
                 lignes_max: int = LIGNES_MAX, octets_max: int = OCTETS_MAX, evenements_max: int = EVENEMENTS_MAX,
                 operations_max: int = OPERATIONS_MAX, orphelines_max: int = ORPHELINES_MAX) -> None:
        self.dossier = Path(dossier)
        self.horloge = horloge
        self.lignes_max, self.octets_max, self.evenements_max = lignes_max, octets_max, evenements_max
        self.operations_max, self.orphelines_max = operations_max, orphelines_max
        self.dossier.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.db = self.dossier / "pilotage.db"
        fd = os.open(self.db, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)  # jamais un lien ; droits posés avant tout contenu
        try:
            os.fchmod(fd, 0o640)  # une base préexistante est ramenée à 0640
        finally:
            os.close(fd)
        with self._cx() as cx:
            cx.execute("PRAGMA journal_mode=WAL")
            cx.executescript(_SCHEMA)
            if "tronque" not in {r["name"] for r in cx.execute("PRAGMA table_info(inventaire)")}:   # base d'avant R38
                cx.execute("ALTER TABLE inventaire ADD COLUMN tronque INTEGER NOT NULL DEFAULT 0")
            colonnes = {r["name"] for r in cx.execute("PRAGMA table_info(evenements)")}
            for col in ("ident", "etat"):                                                          # base de L1 (L2 tâche 6)
                if col not in colonnes:
                    cx.execute(f"ALTER TABLE evenements ADD COLUMN {col} TEXT")
        # connexion de garde, jamais utilisée : tant qu'elle reste ouverte, la fermeture d'une connexion courte ne déclenche ni
        # point de contrôle ni suppression du journal WAL (c'était une synchronisation disque par appel)
        self._garde = sqlite3.connect(self.db, check_same_thread=False)
        self._garde.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()  # la connexion rejoint réellement le journal WAL
        self._refus_journal: dict = {}  # Box.cle -> instant de la dernière ligne « paramètres refusés » ; borné

    def fermer(self) -> None:
        self._garde.close()

    def _maintenant(self) -> int:
        return int(self.horloge())

    @contextmanager
    def _cx(self):
        cx = sqlite3.connect(self.db, timeout=5.0, isolation_level=None)
        try:
            cx.row_factory = sqlite3.Row
            cx.execute("PRAGMA busy_timeout=5000")
            cx.execute("PRAGMA synchronous=NORMAL")
            cx.execute("PRAGMA temp_store=MEMORY")   # M15 : le profil AppArmor ne donne pas /tmp ; tris et index transitoires en mémoire
            yield cx
        finally:
            cx.close()

    @contextmanager
    def _tx(self):
        with self._cx() as cx:
            cx.execute("BEGIN IMMEDIATE")
            try:
                yield cx
            except BaseException:
                cx.execute("ROLLBACK")
                raise
            cx.execute("COMMIT")

    # --- protocole du canal ---

    def vu(self, box: Box, infos: dict) -> None:
        version = infos.get("agent_version") if isinstance(infos, dict) else None
        with self._tx() as cx:
            cx.execute(
                "INSERT INTO boites(cle,nom,adresse,reseau,client,abonnement,agent_version,vu_le) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(cle) DO UPDATE SET nom=excluded.nom, adresse=excluded.adresse, reseau=excluded.reseau, "
                "client=excluded.client, abonnement=excluded.abonnement, vu_le=excluded.vu_le, "
                "agent_version=CASE WHEN excluded.agent_version<>'' THEN excluded.agent_version ELSE agent_version END",
                (box.cle, box.nom, box.adresse, box.reseau, box.client, box.abonnement,
                 version if isinstance(version, str) else "", self._maintenant()))

    def notification(self, box: Box, evenement: dict) -> Optional[dict]:
        typ = evenement["type"]
        if typ == TYPE_PROGRESSION and evenement.get("job"):
            self.operation_progression(box.cle, evenement["job"], evenement.get("etape"), evenement.get("pct"))
            return None
        if typ == TYPE_FIN and evenement.get("job"):
            return self.operation_fin(box.cle, evenement["job"], evenement.get("rc"), evenement.get("resume"))
        ident = evenement.get("id")
        etat = evenement.get("etat") if "decision" not in evenement else evenement.get("decision")
        if typ == TYPE_SUPPORT and ident:
            if not self.support_noter(box.cle, ident, etat, evenement.get("fin")):
                return None   # rien de nouveau (renotification) : pas d'événement en double
        with self._tx() as cx:
            if typ in TYPES_DEDOUBLONNES:
                der = cx.execute("SELECT etat FROM evenements WHERE cle=? AND type=? AND ident IS ? ORDER BY id DESC LIMIT 1",
                                 (box.cle, typ, ident)).fetchone()
                if der is not None and der["etat"] == etat:
                    return None
            cx.execute("INSERT INTO evenements(cle,type,unite,valeur,survenu_le,recu_le,ident,etat) VALUES(?,?,?,?,?,?,?,?)",
                       (box.cle, typ, evenement.get("unit"), evenement.get("value"),
                        evenement["ts"], self._maintenant(), ident, etat))
            cx.execute("DELETE FROM evenements WHERE cle=? AND id<=(SELECT id FROM evenements WHERE cle=? ORDER BY id DESC LIMIT 1 OFFSET ?)",
                       (box.cle, box.cle, self.evenements_max))
        return None

    def resultat(self, box: Box, msg_id: str, reponse: dict) -> None:
        """Rien à garder ici : chaque réponse est consommée par celui qui l'a demandée (relève, lecture, relevé), qui sait la ranger."""

    # --- inventaire ---

    def inventaire_enregistrer(self, box: Box, corps: dict) -> bool:
        """Range une GET_RESP `{results:[{path,params,err?,failed?}], tronque?}`. Complète → l'inventaire de la box est remplacé ; tronquée,
        en erreur, source en échec ou plafond de paramètres atteint → les valeurs reçues sont ajoutées et rien n'est effacé (#3011).
        Un paramètre refusé seul (chemin hors `Device.`, valeur non JSON) n'en fait pas une passe dégradée : il n'entre simplement pas (R38) ;
        une valeur de plus de VALEUR_MAX caractères est tronquée et marquée (`tronques`), jamais jetée. Seules les lignes CHANGÉES sont
        écrites (M4) : une relève identique n'écrit que `inventaire_le`. Faux si rien d'exploitable."""
        resultats = corps.get("results") if isinstance(corps, dict) else None
        if not isinstance(resultats, list):
            return False
        degrade = corps.get("tronque") is True
        valeurs: dict = {}   # chemin -> (valeur_json, tronque)
        refuses = 0
        for r in resultats:
            if not isinstance(r, dict) or not isinstance(r.get("params"), dict):
                degrade = True
                continue
            if r.get("err") or r.get("failed"):  # source en échec ou erreur : les paramètres reçus restent bons, mais le relevé n'est pas complet
                degrade = True
            for chemin, v in r["params"].items():
                if len(valeurs) >= PARAMS_MAX:
                    degrade = True
                    break
                if not isinstance(chemin, str) or not chemin.startswith("Device.") or len(chemin) > CHEMIN_MAX:
                    refuses += 1
                    continue
                try:
                    brut = _json(v)
                except (TypeError, ValueError):
                    refuses += 1
                    continue
                tronque = 0
                if len(brut) > VALEUR_MAX:
                    brut, tronque = _tronquer(v, VALEUR_MAX), 1
                    if brut is None:
                        refuses += 1
                        continue
                valeurs[chemin] = (brut, tronque)
        if refuses:
            self._journaliser_refus(box, refuses)
        if not valeurs:
            return False
        maintenant = self._maintenant()
        with self._tx() as cx:
            # upsert différentiel : une ligne identique n'est pas réécrite (ni page modifiée, ni journal WAL)
            cx.executemany(
                "INSERT INTO inventaire(cle,chemin,valeur_json,releve_le,tronque) VALUES(?,?,?,?,?) ON CONFLICT(cle,chemin) DO UPDATE SET "
                "valeur_json=excluded.valeur_json, releve_le=excluded.releve_le, tronque=excluded.tronque "
                "WHERE inventaire.valeur_json IS NOT excluded.valeur_json OR inventaire.tronque IS NOT excluded.tronque",
                [(box.cle, k, v, maintenant, t) for k, (v, t) in valeurs.items()])
            presents = [r["chemin"] for r in cx.execute("SELECT chemin FROM inventaire WHERE cle=?", (box.cle,))]
            if not degrade:
                cx.executemany("DELETE FROM inventaire WHERE cle=? AND chemin=?", [(box.cle, k) for k in presents if k not in valeurs])
                cx.execute("UPDATE boites SET inventaire_partiel=0, inventaire_le=? WHERE cle=?", (maintenant, box.cle))
            else:
                cx.execute("UPDATE boites SET inventaire_partiel=1 WHERE cle=?", (box.cle,))
                if len(presents) > self.lignes_max:
                    # plafond par box : les lignes les plus anciennes PARMI celles absentes de cette passe partent (une ligne inchangée
                    # n'est plus redatée : ce qui vient d'être reçu n'est jamais purgé)
                    vieilles = [r["chemin"] for r in cx.execute(
                        "SELECT chemin FROM inventaire WHERE cle=? ORDER BY releve_le, rowid", (box.cle,)) if r["chemin"] not in valeurs]
                    cx.executemany("DELETE FROM inventaire WHERE cle=? AND chemin=?",
                                   [(box.cle, k) for k in vieilles[:len(presents) - self.lignes_max]])
                # plafond d'octets par box (R39), dans la même transaction : mêmes critères d'ancienneté et même exclusion de la passe courante
                total = cx.execute("SELECT COALESCE(SUM(length(CAST(valeur_json AS BLOB))),0) FROM inventaire WHERE cle=?", (box.cle,)).fetchone()[0]
                if total > self.octets_max:
                    for r in cx.execute("SELECT chemin, length(CAST(valeur_json AS BLOB)) AS n FROM inventaire WHERE cle=? "
                                        "ORDER BY releve_le, rowid",
                                        (box.cle,)).fetchall():
                        if total <= self.octets_max:
                            break
                        if r["chemin"] in valeurs:
                            continue
                        cx.execute("DELETE FROM inventaire WHERE cle=? AND chemin=?", (box.cle, r["chemin"]))
                        total -= r["n"]
        return True

    def _journaliser_refus(self, box: Box, n: int) -> None:
        maintenant = self.horloge()
        if maintenant - self._refus_journal.get(box.cle, -1e18) < REFUS_JOURNAL_S:
            return
        if len(self._refus_journal) >= 1024:
            self._refus_journal.pop(next(iter(self._refus_journal)))
        self._refus_journal[box.cle] = maintenant
        log.warning("inventaire de %s : %d paramètre(s) refusé(s) (chemin hors Device. ou valeur non JSON) ; une ligne par heure au plus", box.cle, n)

    def inventaire(self, cle: str) -> dict:
        """`tronques` : chemins dont la valeur rangée est le début tronqué de la valeur reçue (R38)."""
        with self._cx() as cx:
            b = cx.execute("SELECT inventaire_le, inventaire_partiel FROM boites WHERE cle=?", (cle,)).fetchone()
            lignes = cx.execute("SELECT chemin, valeur_json, tronque FROM inventaire WHERE cle=? ORDER BY chemin", (cle,)).fetchall()
        return {"valeurs": {r["chemin"]: json.loads(r["valeur_json"]) for r in lignes},
                "tronques": [r["chemin"] for r in lignes if r["tronque"]],
                "partiel": bool(b and b["inventaire_partiel"]), "releve_le": b["inventaire_le"] if b else None}

    # --- lecture des box ---

    def _box(self, r) -> dict:
        d = dict(r)
        d["en_ligne"] = self._maintenant() - d["vu_le"] < HORS_LIGNE_S
        return d

    def boite(self, cle: str) -> Optional[dict]:
        with self._cx() as cx:
            r = cx.execute("SELECT * FROM boites WHERE cle=?", (cle,)).fetchone()
        return self._box(r) if r else None

    def boites(self) -> list:
        with self._cx() as cx:
            return [self._box(r) for r in cx.execute("SELECT * FROM boites ORDER BY nom, reseau")]

    def boites_par_nom(self, nom: str) -> list:
        with self._cx() as cx:
            return [self._box(r) for r in cx.execute("SELECT * FROM boites WHERE nom=? ORDER BY reseau", (nom,))]

    def boites_vues_depuis(self, secondes: int) -> list:
        """Les box vues depuis moins de `secondes` secondes."""
        with self._cx() as cx:
            return [self._box(r) for r in cx.execute("SELECT * FROM boites WHERE ?-vu_le<? ORDER BY cle", (self._maintenant(), secondes))]

    def resumes(self) -> list:
        """Une ligne par box : métadonnées + résumé de l'inventaire. Une valeur absente ou illisible vaut None, jamais une valeur inventée."""
        maintenant = self._maintenant()
        with self._cx() as cx:
            boites = cx.execute("SELECT * FROM boites ORDER BY nom, reseau").fetchall()
            inv: dict = {}
            marques = ",".join("?" * len(_RESUME))
            for b in boites:  # par la clé primaire (cle, chemin), pas par un parcours de toute la table
                for r in cx.execute(f"SELECT chemin, valeur_json FROM inventaire WHERE cle=? AND chemin IN ({marques})", (b["cle"], *_RESUME)):
                    inv.setdefault(b["cle"], {})[r["chemin"]] = json.loads(r["valeur_json"])
            boucles = {r["cle"]: r["n"] for r in cx.execute(
                "SELECT cle, COUNT(*) AS n FROM evenements WHERE type=? AND recu_le>=? GROUP BY cle", (TYPE_BOUCLE, maintenant - BOUCLES_FENETRE_S))}
        out = []
        for b in boites:
            v = inv.get(b["cle"], {})
            kio, tot, util = _nombre(v.get(C_MEM)), _nombre(v.get(C_SWAP_TOTAL)), _nombre(v.get(C_SWAP_USED))
            echecs = _nombre(v.get(C_ECHECS))
            out.append({
                "cle": b["cle"], "nom": b["nom"], "reseau": b["reseau"], "client": b["client"], "adresse": b["adresse"],
                "en_ligne": maintenant - b["vu_le"] < HORS_LIGNE_S, "vu_le": b["vu_le"], "agent_version": b["agent_version"] or None,
                "mains_liees": v[C_MAINS] if isinstance(v.get(C_MAINS), bool) else None,  # inconnu = null (fermé par défaut côté L2)
                "memoire_dispo_mo": int(kio // 1024) if kio is not None else None,
                "swap_utilise_pct": round(util * 100 / tot) if tot and util is not None else None,
                "cpu_pct": round(_nombre(v.get(C_CPU)), 1) if _nombre(v.get(C_CPU)) is not None else None,
                "services_en_echec": int(echecs) if echecs is not None else None,
                "boucles_24h": boucles.get(b["cle"], 0),
                "inventaire_le": b["inventaire_le"], "inventaire_partiel": bool(b["inventaire_partiel"]),
            })
        return out

    # --- événements ---

    def evenements(self, cle: Optional[str] = None, depuis: Optional[int] = None, limite: int = 200) -> list:
        sql, args = ("SELECT e.id, e.cle, b.nom, e.type, e.unite, e.valeur, e.ident, e.etat, e.survenu_le, e.recu_le "
                     "FROM evenements e LEFT JOIN boites b ON b.cle=e.cle"), []
        cond = []
        if cle is not None:
            cond.append("e.cle=?")
            args.append(cle)
        if depuis is not None:
            cond.append("e.recu_le>=?")
            args.append(int(depuis))
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY e.id DESC LIMIT ?"
        args.append(max(1, min(int(limite), 1000)))
        with self._cx() as cx:
            return [dict(r) for r in cx.execute(sql, args)]

    def purger(self) -> int:
        """Supprime les événements reçus il y a plus de 30 jours (l'horloge de la box n'entre pas en compte)."""
        with self._tx() as cx:
            return cx.execute("DELETE FROM evenements WHERE recu_le<?", (self._maintenant() - EVENEMENTS_JOURS * 86400,)).rowcount

    # --- relevé de performance à la demande ---

    def releve_enregistrer(self, cle: str, duree_s: int, statut: str, sortie) -> None:
        try:
            brut = json.dumps(sortie, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            statut, brut = "erreur", json.dumps({"err": "sortie illisible"})
        if len(brut) > SORTIE_MAX:
            statut, brut = "erreur", json.dumps({"err": "sortie trop grosse"})
        with self._tx() as cx:
            cx.execute("INSERT OR REPLACE INTO releves(cle,recu_le,duree_s,statut,sortie_json) VALUES(?,?,?,?,?)",
                       (cle, self._maintenant(), duree_s, statut, brut))

    def releve_lire(self, cle: str) -> Optional[dict]:
        with self._cx() as cx:
            r = cx.execute("SELECT * FROM releves WHERE cle=?", (cle,)).fetchone()
        return None if r is None else {"statut": r["statut"], "duree_s": r["duree_s"], "recu_le": r["recu_le"], "sortie": json.loads(r["sortie_json"])}

    # --- opérations (L2 tâche 6) ---
    # Une ligne par demande d'action du maître (id), reliée au job de la box dès l'OPERATE_RESP. Les notifications de suivi
    # arrivent « au moins une fois », parfois avant l'OPERATE_RESP, parfois pour un job inconnu : une ligne orpheline
    # (action NULL) est créée, puis fusionnée dans la demande quand la réponse arrive. La première fin fait foi.

    def _op(self, cx, ident: int) -> Optional[dict]:
        r = cx.execute("SELECT * FROM operations WHERE id=?", (ident,)).fetchone()
        return _operation(r) if r else None

    def operation_demander(self, cle: str, action: str, args: dict, acteur: Optional[str], support: Optional[str]) -> int:
        maintenant = self._maintenant()
        with self._tx() as cx:
            ident = cx.execute("INSERT INTO operations(cle,action,args_json,acteur,support,etat,demande_le,maj_le) VALUES(?,?,?,?,?,?,?,?)",
                               (cle, action, _json(args or {}), acteur, support, "demande", maintenant, maintenant)).lastrowid
            cx.execute("DELETE FROM operations WHERE cle=? AND action IS NOT NULL AND id<=(SELECT id FROM operations WHERE cle=? "
                       "AND action IS NOT NULL ORDER BY id DESC LIMIT 1 OFFSET ?)", (cle, cle, self.operations_max))
        return ident

    def operation_reponse(self, ident: int, etat: str, job: Optional[str], raison: Optional[str]) -> Optional[dict]:
        """Range l'OPERATE_RESP de la demande `ident`. Un suivi déjà reçu pour ce job (ligne orpheline) y est fusionné : la
        demande prend son étape, sa progression et sa fin. Rend la ligne fusionnée."""
        job = job or None
        with self._tx() as cx:
            moi = cx.execute("SELECT * FROM operations WHERE id=?", (ident,)).fetchone()
            if moi is None:
                return None
            autre = cx.execute("SELECT * FROM operations WHERE cle=? AND job=? AND id<>?", (moi["cle"], job, ident)).fetchone() if job else None
            orph = autre if autre is not None and autre["action"] is None else None
            if autre is not None and orph is None:
                job = None   # job déjà porté par une AUTRE demande (réponse incohérente) : jamais deux demandes sur un job
            champs = {"etat": etat, "job": job, "raison": raison or None}
            if orph is not None:
                cx.execute("DELETE FROM operations WHERE id=?", (orph["id"],))
                champs.update(etape=orph["etape"], pct=orph["pct"], rc=orph["rc"], resume=orph["resume"], fin_le=orph["fin_le"])
                if orph["fin_le"] is not None:
                    champs["etat"] = "termine"
                elif orph["etape"] is not None and etat == "accepte":
                    champs["etat"] = "en_cours"
            champs["maj_le"] = self._maintenant()
            cx.execute(f"UPDATE operations SET {', '.join(k + '=?' for k in champs)} WHERE id=?", (*champs.values(), ident))
            return self._op(cx, ident)

    def operation_sans_reponse(self, ident: int) -> None:
        with self._tx() as cx:
            cx.execute("UPDATE operations SET etat='sans_reponse', maj_le=? WHERE id=? AND etat='demande'", (self._maintenant(), ident))

    def _orpheline(self, cx, cle: str, job: str):
        """(ligne du job, créée maintenant ?) ; un job inconnu est accepté (ligne orpheline, action NULL)."""
        r = cx.execute("SELECT * FROM operations WHERE cle=? AND job=?", (cle, job)).fetchone()
        if r is not None:
            return r, False
        maintenant = self._maintenant()
        ident = cx.execute("INSERT INTO operations(cle,job,etat,demande_le,maj_le) VALUES(?,?,?,?,?)",
                           (cle, job, "en_cours", maintenant, maintenant)).lastrowid
        cx.execute("DELETE FROM operations WHERE cle=? AND action IS NULL AND id<=(SELECT id FROM operations WHERE cle=? "
                   "AND action IS NULL ORDER BY id DESC LIMIT 1 OFFSET ?)", (cle, cle, self.orphelines_max))
        return cx.execute("SELECT * FROM operations WHERE id=?", (ident,)).fetchone(), True

    def operation_progression(self, cle: str, job: str, etape: Optional[str], pct: Optional[int]) -> bool:
        """Vrai si la progression a changé quelque chose. Une opération terminée ne recule jamais ; une progression ne recule
        jamais non plus (remise dans le désordre ou en double)."""
        with self._tx() as cx:
            r, cree = self._orpheline(cx, cle, job)
            if r["fin_le"] is not None:
                return False
            if r["pct"] is not None and pct is not None and pct < r["pct"]:
                return False
            if r["etape"] == etape and r["pct"] == pct and r["etat"] == "en_cours":
                return cree
            etat = "en_cours" if r["etat"] in ("demande", "accepte", "en_cours", "sans_reponse") else r["etat"]
            cx.execute("UPDATE operations SET etape=?, pct=?, etat=?, maj_le=? WHERE id=?", (etape, pct, etat, self._maintenant(), r["id"]))
            return True

    def operation_fin(self, cle: str, job: str, rc: Optional[int], resume: Optional[str]) -> Optional[dict]:
        """Range la fin d'un job ; rend l'opération la PREMIÈRE fois seulement (la remise est « au moins une fois »)."""
        with self._tx() as cx:
            r, _ = self._orpheline(cx, cle, job)
            if r["fin_le"] is not None:
                return None
            cx.execute("UPDATE operations SET etat='termine', rc=?, resume=?, pct=100, etape='terminee', fin_le=?, maj_le=? WHERE id=?",
                       (rc, resume or None, self._maintenant(), self._maintenant(), r["id"]))
            return self._op(cx, r["id"])

    def operation_reclamer_suite(self, ident: int) -> bool:
        """Vrai une seule fois par opération terminée dont l'action est connue : la suite (Rejoindre après un renommage) ne
        part qu'une fois, que la fin arrive avant ou après l'OPERATE_RESP."""
        with self._tx() as cx:
            return cx.execute("UPDATE operations SET suite_faite=1 WHERE id=? AND suite_faite=0 AND fin_le IS NOT NULL AND action IS NOT NULL",
                              (ident,)).rowcount == 1

    def operations(self, cle: Optional[str] = None, limite: int = 200) -> list:
        sql, args = "SELECT o.*, b.nom FROM operations o LEFT JOIN boites b ON b.cle=o.cle", []
        if cle is not None:
            sql += " WHERE o.cle=?"
            args.append(cle)
        sql += " ORDER BY o.id DESC LIMIT ?"
        args.append(max(1, min(int(limite), 1000)))
        with self._cx() as cx:
            return [_operation(r) for r in cx.execute(sql, args)]

    # --- sessions de support (L2 tâche 6, R-L2-31, R-L2-33) ---
    # Le maître borne lui-même une session ouverte : fin = la plus proche de la fin annoncée par la box et de la réception
    # de « ouvert » plus la durée demandée (4 h pour une session qu'il n'a pas demandée). Passée cette fin, la session est
    # « expire » même si aucune notification de fermeture n'arrive.

    def support_demander(self, cle: str, ident: str, duree_min: int, acteur: Optional[str]) -> None:
        maintenant = self._maintenant()
        with self._tx() as cx:
            cx.execute("INSERT OR REPLACE INTO supports(cle,id,etat,duree_min,acteur,fin,demande_le,maj_le) VALUES(?,?,?,?,?,?,?,?)",
                       (cle, ident, "demande", int(duree_min), acteur, None, maintenant, maintenant))
            cx.execute("DELETE FROM supports WHERE cle=? AND rowid<=(SELECT rowid FROM supports WHERE cle=? ORDER BY rowid DESC LIMIT 1 OFFSET ?)",
                       (cle, cle, SUPPORTS_MAX))

    def support_noter(self, cle: str, ident: str, etat: Optional[str], fin_rfc3339: Optional[str]) -> bool:
        """État notifié par la box ; vrai s'il change la vue du maître. Un état terminal ne se rouvre pas. Une session que le maître
        n'a pas demandée est rangée « inconnu » et n'en sort jamais ; « ouvert » n'est accepté que depuis « demande » ou
        « en_attente » (M2) : une box ne peut pas ouvrir seule une session."""
        if not isinstance(etat, str) or not etat:
            return False
        maintenant = self._maintenant()
        with self._tx() as cx:
            r = cx.execute("SELECT * FROM supports WHERE cle=? AND id=?", (cle, ident)).fetchone()
            if r is None:
                cx.execute("INSERT INTO supports(cle,id,etat,duree_min,acteur,fin,demande_le,maj_le) VALUES(?,?,?,?,?,?,?,?)",
                           (cle, ident, "inconnu", SUPPORT_DUREE_MAX_MIN, None, None, maintenant, maintenant))
                return True
            if r["etat"] in SUPPORT_TERMINAUX or r["etat"] in ("inconnu", etat):
                return False
            if etat == "ouvert" and r["etat"] not in ("demande", "en_attente"):
                return False
            fin = r["fin"]
            if etat == "ouvert":
                borne = maintenant + int(r["duree_min"]) * 60
                annoncee = _instant_rfc3339(fin_rfc3339)
                fin = min(borne, annoncee) if annoncee is not None else borne
            cx.execute("UPDATE supports SET etat=?, fin=?, maj_le=? WHERE cle=? AND id=?", (etat, fin, maintenant, cle, ident))
            return True

    def support_sans_reponse(self, cle: str, ident: str) -> None:
        """Pas de réponse de la box à la demande (504) : la session n'est pas « demande » pour toujours."""
        with self._tx() as cx:
            cx.execute("UPDATE supports SET etat='sans_reponse', maj_le=? WHERE cle=? AND id=? AND etat='demande'",
                       (self._maintenant(), cle, ident))

    def support_fermer_local(self, cle: str, ident: str) -> bool:
        """Fermeture décidée sur le maître (révocable des deux côtés) : effective ici tout de suite, box jointe ou non."""
        with self._tx() as cx:
            return cx.execute("UPDATE supports SET etat='ferme', maj_le=? WHERE cle=? AND id=? AND etat NOT IN (?,?,?,?)",
                              (self._maintenant(), cle, ident, *SUPPORT_TERMINAUX)).rowcount == 1

    def _expirer_supports(self, cx, cle: str) -> None:
        cx.execute("UPDATE supports SET etat='expire', maj_le=? WHERE cle=? AND etat='ouvert' AND fin IS NOT NULL AND fin<=?",
                   (self._maintenant(), cle, self._maintenant()))

    def supports(self, cle: str) -> list:
        with self._tx() as cx:
            self._expirer_supports(cx, cle)
            return [dict(r) for r in cx.execute("SELECT * FROM supports WHERE cle=? ORDER BY rowid DESC", (cle,))]

    def support_ouvert(self, cle: str, ident: Optional[str] = None) -> Optional[dict]:
        """La session ouverte (et non échue) de la box, celle d'identifiant `ident` si donné ; sinon None."""
        with self._tx() as cx:
            self._expirer_supports(cx, cle)
            sql, args = "SELECT * FROM supports WHERE cle=? AND etat='ouvert' AND fin>?", [cle, self._maintenant()]
            if ident is not None:
                sql += " AND id=?"
                args.append(ident)
            r = cx.execute(sql + " ORDER BY rowid DESC LIMIT 1", args).fetchone()
        return dict(r) if r else None


def _instant_rfc3339(v) -> Optional[int]:
    """Instant Unix d'une date RFC 3339 (« 2026-10-29T12:00:00Z ») ; None si absente ou illisible."""
    if not isinstance(v, str) or len(v) > 40:
        return None
    from datetime import datetime
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return int(d.timestamp()) if d.tzinfo is not None else None


def _operation(r) -> dict:
    d = dict(r)
    try:
        d["args"] = json.loads(d.pop("args_json") or "{}")
    except ValueError:
        d["args"] = {}
    d.pop("suite_faite", None)
    rc = d.get("rc")
    if d["etat"] != "termine":
        d["resultat"] = None
    elif rc == 0:
        d["resultat"] = "succes"
    elif rc is None or rc == -1:          # l'agent rend -1 quand la fin est introuvable (fins.json évincé, bus injoignable)
        d["resultat"] = "inconnu"
    else:
        d["resultat"] = "echec"
    return d
