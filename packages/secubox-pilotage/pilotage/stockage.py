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
EVENEMENTS_MAX = 5000        # événements gardés par box : au-delà, les plus anciens partent
VALEUR_MAX = 64 << 10       # caractères d'une valeur sérialisée ; au-delà elle est TRONQUÉE et marquée, jamais jetée (R38)
CHEMIN_MAX = 256
SORTIE_MAX = 256 << 10
REFUS_JOURNAL_S = 3600       # paramètres refusés : une ligne de journal par box et par heure au plus

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

    def notification(self, box: Box, evenement: dict) -> None:
        """Un événement NOTIFY remis par la box (le contenu de `body.event`)."""

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

    def notification(self, box: Box, evenement: dict) -> None:
        self.notifications.append((box, evenement))

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
                 lignes_max: int = LIGNES_MAX, evenements_max: int = EVENEMENTS_MAX) -> None:
        self.dossier = Path(dossier)
        self.horloge = horloge
        self.lignes_max, self.evenements_max = lignes_max, evenements_max
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

    def notification(self, box: Box, evenement: dict) -> None:
        with self._tx() as cx:
            cx.execute("INSERT INTO evenements(cle,type,unite,valeur,survenu_le,recu_le) VALUES(?,?,?,?,?,?)",
                       (box.cle, evenement["type"], evenement.get("unit"), evenement.get("value"),
                        evenement["ts"], self._maintenant()))
            cx.execute("DELETE FROM evenements WHERE cle=? AND id<=(SELECT id FROM evenements WHERE cle=? ORDER BY id DESC LIMIT 1 OFFSET ?)",
                       (box.cle, box.cle, self.evenements_max))

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
        sql, args = "SELECT e.id, e.cle, b.nom, e.type, e.unite, e.valeur, e.survenu_le, e.recu_le FROM evenements e LEFT JOIN boites b ON b.cle=e.cle", []
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
