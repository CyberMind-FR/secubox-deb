# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: les JETONS CLIENTS (#2185, parent #2182, décisions D4 et D5 de docs/dossiers/provisionnement-auto-load.md)

Un jeton par box : 128 bits aléatoires, montrés UNE fois à l'émission, stockés sous forme d'EMPREINTE SHA-256 seulement. À usage unique : la
réclamation le consomme et lie la box à sa CLÉ PUBLIQUE WireGuard (l'identité durable, générée sur la box). États : emis → reclame | revoque.

Le statut d'abonnement (actif, suspendu, revoque) est porté par chaque BOX (#3303 : formule, échéance, statut ; table `abonnements_box`, clé = id
du jeton, un jeton par box) ; le client ne fait que regrouper. Une box sans ligne propre (jeton émis avant sa réclamation, base d'avant #3303)
suit l'abonnement de son client, qui reste la valeur héritée à la création. La route par client fixe le client ET toutes ses box. Un abonnement
non actif refuse la réclamation et les nouvelles livraisons ; il ne coupe jamais une fonction locale de la box (décision du propriétaire).

Tout refus de réclamation porte le MÊME message (« jeton refusé ») : rien n'apprend à un tiers si un jeton est inconnu, expiré, pris ou révoqué.
La vraie raison est écrite dans le journal d'audit (append-only), qui ne reçoit JAMAIS la valeur d'un jeton.
"""
from __future__ import annotations

import calendar
import datetime
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

DB_DEFAUT = Path("/var/lib/secubox/autoload/jetons.db")
AUDIT_DEFAUT = Path("/var/log/secubox/autoload/audit.log")                 # sous-dossier : la règle générale de secubox-core (/var/log/secubox/*.log) ne le voit pas (#2489)
DUREE_DEFAUT_S = 90 * 86400
DUREE_MAX_S = 365 * 86400
ABONNEMENTS = ("actif", "suspendu", "revoque")
PROFILS = ("minimal", "lite", "isp", "full", "secure-gateway", "media-lab", "distante")      # profils réels de secubox-profiles (#3258) ; jamais light/standard
MOTIF_MIN = 3
# Services du maillage qu'une formule peut inclure (#3305) ; liste FERMÉE, dans l'ordre de publication.
SERVICES_MAILLAGE = ("annuaire-offres", "bans-waf", "openpgp", "macro")
FORMULE_ATELIER = "atelier"                  # formule interne du propriétaire (gk2, box de l'atelier) : tous les services
GRACE_S = 5 * 86400                          # pair du maillage sans abonnement : services rendus 5 jours après la première migration
MOTIF_CLIENT = "abonnement du client"        # marque d'une box suspendue/révoquée par la route client, que la même route peut lever

_NOM = re.compile(r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")
_SERIE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{3,63}$")
PREFIXE = "gk2_"                                                            # reconnaissable : un jeton qui fuite se repère (journaux, dépôts)
_VALEUR = re.compile(r"^gk2_[0-9a-f]{32}$")
_ETAPE = re.compile(r"^[a-z0-9_-]{1,40}$")
_FORMULE = re.compile(r"^[a-z0-9_-]{1,30}$")
_PAIR = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")                          # nom de pair du maillage (pairs-enroles.json de secubox-p2p)
_EMPREINTE_PAIR = re.compile(r"^sbx?-[0-9a-f]{12}$")
PRERAPPORT_MAX = 64 * 1024
_CLE_WG = re.compile(r"^[A-Za-z0-9+/]{43}=$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS jetons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  empreinte TEXT NOT NULL UNIQUE,
  client TEXT NOT NULL, profil TEXT NOT NULL, lot TEXT, serie TEXT,
  etat TEXT NOT NULL CHECK (etat IN ('emis','reclame','revoque')),
  emis_le INTEGER NOT NULL, expire_le INTEGER NOT NULL,
  reclame_le INTEGER, cle_pub TEXT, revoque_le INTEGER, motif TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS jetons_cle ON jetons(cle_pub) WHERE cle_pub IS NOT NULL;
CREATE INDEX IF NOT EXISTS jetons_client ON jetons(client);
CREATE INDEX IF NOT EXISTS jetons_lot ON jetons(lot);
CREATE TABLE IF NOT EXISTS clients (
  client TEXT PRIMARY KEY, abonnement TEXT NOT NULL CHECK (abonnement IN ('actif','suspendu','revoque')),
  formule TEXT, expire_le INTEGER, email TEXT
);
CREATE TABLE IF NOT EXISTS abonnements_box (
  jeton_id INTEGER PRIMARY KEY REFERENCES jetons(id), formule TEXT, statut TEXT NOT NULL CHECK (statut IN ('actif','suspendu','revoque')),
  expire_le INTEGER, motif TEXT, maj_le INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS formules (
  nom TEXT PRIMARY KEY, libelle TEXT NOT NULL, profil TEXT NOT NULL, mois INTEGER NOT NULL CHECK (mois BETWEEN 1 AND 120)
);
CREATE TABLE IF NOT EXISTS abonnements_maillage (
  nom TEXT PRIMARY KEY, empreinte TEXT, formule TEXT NOT NULL, statut TEXT NOT NULL CHECK (statut IN ('actif','suspendu','revoque')),
  expire_le INTEGER, motif TEXT, maj_le INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS progression (
  cle_pub TEXT PRIMARY KEY, etape TEXT NOT NULL, faites INTEGER NOT NULL, total INTEGER NOT NULL, termine INTEGER NOT NULL DEFAULT 0, maj_le INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS rapports (
  id INTEGER PRIMARY KEY AUTOINCREMENT, cle_pub TEXT NOT NULL, empreinte TEXT NOT NULL, contenu TEXT NOT NULL, recu_le INTEGER NOT NULL, envoye INTEGER NOT NULL DEFAULT 0,
  UNIQUE (cle_pub, empreinte)
);
CREATE TABLE IF NOT EXISTS prerapports (
  empreinte TEXT PRIMARY KEY, cle_pub TEXT NOT NULL, contenu TEXT NOT NULL, recu_le INTEGER NOT NULL, refuse INTEGER NOT NULL DEFAULT 0, motif TEXT
);
CREATE TABLE IF NOT EXISTS series (
  serie TEXT PRIMARY KEY, client TEXT NOT NULL, profil TEXT NOT NULL, lot TEXT,
  etat TEXT NOT NULL CHECK (etat IN ('attente','reclame')), enregistre_le INTEGER NOT NULL
);
"""


class JetonRefuse(Exception):
    """Message volontairement uniforme : le détail va à l'audit, jamais à l'appelant."""

    def __init__(self):
        super().__init__("jeton refusé")


@dataclass(frozen=True)
class Emission:
    id: int
    valeur: str
    expire_le: int


@dataclass(frozen=True)
class Reclamation:
    id: int
    client: str
    profil: str
    lot: Optional[str]
    serie: Optional[str]


def ajouter_mois(ts: int, n: int) -> int:
    """`ts` plus `n` mois calendaires (le 31 janvier + 1 mois = le 28 ou 29 février). Pour la durée d'un abonnement (« 12 mois »)."""
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 120:
        raise ValueError("durée : de 1 à 120 mois")
    d = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    m = d.month - 1 + n
    annee, mois = d.year + m // 12, m % 12 + 1
    jour = min(d.day, calendar.monthrange(annee, mois)[1])
    return int(d.replace(year=annee, month=mois, day=jour).timestamp())


def empreinte_prerapport(pre: dict) -> str:
    """SHA-256 du contenu canonique du pré-rapport SANS son champ `empreinte` (même calcul que autoload_agent.validation.empreinte)."""
    corps = {k: v for k, v in pre.items() if k != "empreinte"}
    return hashlib.sha256(json.dumps(corps, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _empreinte(valeur: str) -> str:
    return hashlib.sha256(valeur.encode("utf-8")).hexdigest()


def _nom(champ: str, valeur: Optional[str], facultatif: bool = False) -> Optional[str]:
    if valeur is None and facultatif:
        return None
    if not isinstance(valeur, str) or not _NOM.match(valeur):
        raise ValueError(f"{champ} : minuscules, chiffres et tirets, 40 au plus")
    return valeur


def valider_services(services) -> List[str]:
    """Liste fermée, dédoublonnée, dans l'ordre de SERVICES_MAILLAGE."""
    if not isinstance(services, (list, tuple)) or any(s not in SERVICES_MAILLAGE for s in services):
        raise ValueError("services : " + ", ".join(SERVICES_MAILLAGE))
    return [s for s in SERVICES_MAILLAGE if s in services]


def _services(brut) -> List[str]:
    try:
        return valider_services(json.loads(brut or "[]"))
    except (ValueError, TypeError):
        return []                                                               # valeur abîmée : aucun service (jamais tous)


def lire_droits_cx(cx: sqlite3.Connection, maintenant: float) -> dict:
    """Droits du maillage : un pair actif et non échu reçoit les services de sa formule ; sinon aucun. Ferme la connexion."""
    try:
        r = cx.execute("SELECT valeur FROM meta WHERE cle='grace_debut'").fetchone()
        pairs = []
        for p in cx.execute("SELECT m.nom, m.empreinte, m.formule, m.statut, m.expire_le, f.services FROM abonnements_maillage m "
                            "LEFT JOIN formules f ON f.nom=m.formule ORDER BY m.nom"):
            statut = etat_abonnement(p["statut"], p["expire_le"], maintenant)
            pairs.append({"nom": p["nom"], "empreinte": p["empreinte"], "formule": p["formule"], "statut": statut, "expire_le": p["expire_le"],
                          "services": _services(p["services"]) if statut == "actif" else []})
        return {"grace_jusqu_a": int(r["valeur"]) + GRACE_S if r else None, "services": list(SERVICES_MAILLAGE), "pairs": pairs}
    finally:
        cx.close()


def etat_abonnement(abonnement: str, expire_le: Optional[int], maintenant: float) -> str:
    """L'état d'abonnement CALCULÉ : un abonnement `actif` dont l'échéance est passée est `echu` (actif | suspendu | revoque | echu)."""
    if abonnement == "actif" and expire_le is not None and expire_le <= maintenant:
        return "echu"
    return abonnement


class Registre:
    def __init__(self, db: Path = DB_DEFAUT, audit: Optional[Path] = AUDIT_DEFAUT, horloge: Callable[[], float] = time.time):
        self.db, self.audit_chemin, self._horloge = Path(db), (Path(audit) if audit else None), horloge
        if not self.db.parent.exists():
            self.db.parent.mkdir(parents=True)
            os.chmod(self.db.parent, 0o750)                                          # notre dossier seulement ; un parent partagé n'est jamais resserré
        if not self.db.exists():
            os.close(os.open(self.db, os.O_CREAT | os.O_WRONLY, 0o600))        # jamais lisible par un autre compte, même un instant
        os.chmod(self.db, 0o600)
        with self._cx() as cx:
            cx.executescript(SCHEMA)
            colonnes = {r["name"] for r in cx.execute("PRAGMA table_info(clients)")}                 # base de la version 0.1/0.2 : on ajoute, sans rien perdre
            for col, typ in (("formule", "TEXT"), ("expire_le", "INTEGER"), ("email", "TEXT")):
                if col not in colonnes:
                    cx.execute(f"ALTER TABLE clients ADD COLUMN {col} {typ}")
            self._heriter(cx)
            if "services" not in {r["name"] for r in cx.execute("PRAGMA table_info(formules)")}:              # #3305
                cx.execute("ALTER TABLE formules ADD COLUMN services TEXT NOT NULL DEFAULT '[]'")
            cx.execute("INSERT OR IGNORE INTO formules (nom, libelle, profil, mois, services) VALUES (?,?,?,?,?)",
                       (FORMULE_ATELIER, "Atelier (interne)", "full", 120, json.dumps(list(SERVICES_MAILLAGE))))
            cx.execute("INSERT OR IGNORE INTO meta (cle, valeur) VALUES ('grace_debut', ?)", (str(self._maintenant()),))

    def _heriter(self, cx: sqlite3.Connection, client: Optional[str] = None) -> None:
        """Migration #3303, idempotente : toute box (jeton) sans ligne propre reçoit l'abonnement ACTUEL de son client (actif par défaut).
        Une ligne existante n'est jamais touchée."""
        filtre, args = ("AND j.client=?", (client,)) if client else ("", ())
        cx.execute("INSERT OR IGNORE INTO abonnements_box (jeton_id, formule, statut, expire_le, maj_le) "
                   "SELECT j.id, c.formule, CASE WHEN j.etat='revoque' THEN 'revoque' ELSE COALESCE(c.abonnement,'actif') END, c.expire_le, ? "
                   "FROM jetons j LEFT JOIN clients c ON c.client=j.client WHERE 1=1 " + filtre, (self._maintenant(), *args))

    # ── plomberie ────────────────────────────────────────────────────────────────────────────────────────────
    def _cx(self) -> sqlite3.Connection:
        cx = sqlite3.connect(self.db, timeout=15, isolation_level=None)
        cx.row_factory = sqlite3.Row
        return cx

    def _maintenant(self) -> int:
        return int(self._horloge())

    def _audit(self, action: str, detail: str) -> None:
        if not self.audit_chemin:
            return
        try:
            with open(self.audit_chemin, "a", encoding="utf-8") as f:                    # ajout seul
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._maintenant())), "module": "autoload",
                                    "action": action, "detail": detail[:300]}, ensure_ascii=False) + "\n")
        except OSError as e:                                                            # ne bloque pas l'opération, mais ne se tait pas
            print(f"secubox-autoload : audit non écrit ({action}) : {e}", file=sys.stderr)

    def _refus(self, raison: str, empreinte: str = "") -> "JetonRefuse":
        self._audit("jeton-refus", raison + (f" (empreinte {empreinte[:8]})" if empreinte else ""))
        return JetonRefuse()

    # ── émission ─────────────────────────────────────────────────────────────────────────────────────────────
    def emettre(self, client: str, profil: str, lot: Optional[str] = None, serie: Optional[str] = None, duree_s: int = DUREE_DEFAUT_S) -> Emission:
        client, profil, lot = _nom("client", client), _nom("profil", profil), _nom("lot", lot, True)
        if serie is not None and (not isinstance(serie, str) or not _SERIE.match(serie)):
            raise ValueError("serie : 4 à 64 caractères (lettres, chiffres, . _ -)")
        if isinstance(duree_s, bool) or not isinstance(duree_s, int) or not 1 <= duree_s <= DUREE_MAX_S:
            raise ValueError(f"durée : de 1 seconde à {DUREE_MAX_S // 86400} jours")
        valeur = PREFIXE + secrets.token_hex(16)
        maintenant = self._maintenant()
        with self._cx() as cx:
            cur = cx.execute("INSERT INTO jetons (empreinte, client, profil, lot, serie, etat, emis_le, expire_le) VALUES (?,?,?,?,?,'emis',?,?)",
                             (_empreinte(valeur), client, profil, lot, serie, maintenant, maintenant + duree_s))
            cx.execute("INSERT OR IGNORE INTO clients (client, abonnement) VALUES (?, 'actif')", (client,))
            self._heriter(cx, client)
            ident = cur.lastrowid
        self._audit("jeton-emis", f"id={ident} client={client} profil={profil} lot={lot or '-'} expire={maintenant + duree_s}")
        return Emission(ident, valeur, maintenant + duree_s)

    def preenregistrer(self, serie: str, client: str, profil: str, lot: Optional[str] = None) -> None:
        """Un client « déjà pré-évalué » : sa box s'identifie par son numéro de série et reçoit son jeton à la volée (D5)."""
        if not isinstance(serie, str) or not _SERIE.match(serie):
            raise ValueError("serie : 4 à 64 caractères (lettres, chiffres, . _ -)")
        client, profil, lot = _nom("client", client), _nom("profil", profil), _nom("lot", lot, True)
        with self._cx() as cx:
            cx.execute("INSERT INTO series (serie, client, profil, lot, etat, enregistre_le) VALUES (?,?,?,?,'attente',?)",
                       (serie, client, profil, lot, self._maintenant()))
            cx.execute("INSERT OR IGNORE INTO clients (client, abonnement) VALUES (?, 'actif')", (client,))
        self._audit("serie-preenregistree", f"serie={serie} client={client} profil={profil} lot={lot or '-'}")

    # ── réclamation ──────────────────────────────────────────────────────────────────────────────────────────
    def _abonnement_actif(self, cx: sqlite3.Connection, client: str, jeton_id: Optional[int] = None) -> bool:
        """L'abonnement de la BOX (#3303) s'il a sa ligne, sinon celui du client."""
        r = None
        if jeton_id is not None:
            r = cx.execute("SELECT statut AS abonnement, expire_le FROM abonnements_box WHERE jeton_id=?", (jeton_id,)).fetchone()
        if r is None:
            r = cx.execute("SELECT abonnement, expire_le FROM clients WHERE client=?", (client,)).fetchone()
        if r is None:
            return True
        return r["abonnement"] == "actif" and (r["expire_le"] is None or r["expire_le"] > self._maintenant())

    def reclamer(self, valeur: str, cle_pub: str) -> Reclamation:
        """Consomme le jeton et lie la box à sa clé publique. Toute raison de refus rend la même exception."""
        if not isinstance(valeur, str) or not _VALEUR.match(valeur):
            raise self._refus("format invalide")
        emp = _empreinte(valeur)
        if not isinstance(cle_pub, str) or not _CLE_WG.match(cle_pub):
            raise self._refus("clé publique invalide", emp)
        with self._cx() as cx:
            cx.execute("BEGIN IMMEDIATE")
            try:
                r = cx.execute("SELECT * FROM jetons WHERE empreinte=?", (emp,)).fetchone()
                if r is None:
                    cx.execute("ROLLBACK")
                    raise self._refus("inconnu", emp)
                raison = None
                if r["etat"] == "revoque":
                    raison = "révoqué"
                elif r["etat"] == "reclame":
                    if r["cle_pub"] == cle_pub and self._abonnement_actif(cx, r["client"], r["id"]):
                        cx.execute("ROLLBACK")                                               # même box, même clé : la réponse s'est perdue, on la redonne
                        self._audit("jeton-repris", f"id={r['id']} client={r['client']}")
                        return Reclamation(r["id"], r["client"], r["profil"], r["lot"], r["serie"])
                    raison = "déjà réclamé"
                elif r["expire_le"] <= self._maintenant():
                    raison = "expiré"
                elif not self._abonnement_actif(cx, r["client"], r["id"]):
                    raison = "abonnement non actif"
                if raison:
                    cx.execute("ROLLBACK")
                    raise self._refus(f"{raison} id={r['id']} client={r['client']}", emp)
                try:
                    cx.execute("UPDATE jetons SET etat='reclame', reclame_le=?, cle_pub=? WHERE id=? AND etat='emis'", (self._maintenant(), cle_pub, r["id"]))
                except sqlite3.IntegrityError:
                    cx.execute("ROLLBACK")
                    raise self._refus(f"clé déjà utilisée id={r['id']}", emp) from None
                cx.execute("COMMIT")
            except JetonRefuse:
                raise
            except sqlite3.Error:
                cx.execute("ROLLBACK")
                raise
        self._audit("jeton-reclame", f"id={r['id']} client={r['client']} profil={r['profil']}")
        return Reclamation(r["id"], r["client"], r["profil"], r["lot"], r["serie"])

    def reclamer_par_serie(self, serie: str, cle_pub: str) -> Reclamation:
        if not isinstance(serie, str) or not _SERIE.match(serie):
            raise self._refus("série : format invalide")
        if not isinstance(cle_pub, str) or not _CLE_WG.match(cle_pub):
            raise self._refus(f"clé publique invalide (série {serie})")
        maintenant = self._maintenant()
        with self._cx() as cx:
            cx.execute("BEGIN IMMEDIATE")
            try:
                s = cx.execute("SELECT * FROM series WHERE serie=?", (serie,)).fetchone()
                raison = "série inconnue" if s is None else ("série déjà réclamée" if s["etat"] != "attente"
                                                              else (None if self._abonnement_actif(cx, s["client"]) else "abonnement non actif"))
                if raison:
                    cx.execute("ROLLBACK")
                    raise self._refus(f"{raison} ({serie})")
                cur = cx.execute("INSERT INTO jetons (empreinte, client, profil, lot, serie, etat, emis_le, expire_le, reclame_le, cle_pub) "
                                 "VALUES (?,?,?,?,?,'reclame',?,?,?,?)",
                                 (_empreinte(secrets.token_hex(16)), s["client"], s["profil"], s["lot"], serie, maintenant, maintenant, maintenant, cle_pub))
                cx.execute("UPDATE series SET etat='reclame' WHERE serie=?", (serie,))
                self._heriter(cx, s["client"])
                cx.execute("COMMIT")
            except JetonRefuse:
                raise
            except sqlite3.IntegrityError:
                cx.execute("ROLLBACK")
                raise self._refus(f"clé déjà utilisée (série {serie})") from None
            except sqlite3.Error:
                cx.execute("ROLLBACK")
                raise
        self._audit("jeton-reclame", f"id={cur.lastrowid} client={s['client']} profil={s['profil']} serie={serie}")
        return Reclamation(cur.lastrowid, s["client"], s["profil"], s["lot"], serie)

    # ── cycle de vie ─────────────────────────────────────────────────────────────────────────────────────────
    def revoquer(self, ident: int, motif: str) -> Optional[str]:
        """Révoque un jeton (réclamé ou non). Rend la clé publique à retirer du tunnel (#2189), ou None."""
        motif = str(motif)[:200]
        with self._cx() as cx:
            cle = self._revoquer_jeton(cx, ident, motif)
        self._audit("jeton-revoque", f"id={ident} motif={motif}")
        return cle

    def _revoquer_jeton(self, cx: sqlite3.Connection, ident: int, motif: str) -> Optional[str]:
        r = cx.execute("SELECT cle_pub FROM jetons WHERE id=?", (ident,)).fetchone()
        if r is None:
            raise ValueError("jeton inconnu")
        cx.execute("UPDATE jetons SET etat='revoque', revoque_le=?, motif=? WHERE id=?", (self._maintenant(), motif, ident))
        return r["cle_pub"]

    def revoquer_lot_cles(self, lot: str, motif: str) -> List[str]:
        """Révoque tout un lot ; rend les clés publiques des box DÉJÀ réclamées, à retirer du tunnel."""
        lot = _nom("lot", lot)
        motif = str(motif)[:200]
        with self._cx() as cx:
            cles = [r["cle_pub"] for r in cx.execute("SELECT cle_pub FROM jetons WHERE lot=? AND etat='reclame' AND cle_pub IS NOT NULL", (lot,))]
            n = cx.execute("UPDATE jetons SET etat='revoque', revoque_le=?, motif=? WHERE lot=? AND etat!='revoque'", (self._maintenant(), motif, lot)).rowcount
        self._audit("lot-revoque", f"lot={lot} jetons={n} motif={motif}")
        return cles

    def revoquer_lot(self, lot: str, motif: str) -> int:
        with self._cx() as cx:
            avant = cx.execute("SELECT COUNT(*) FROM jetons WHERE lot=? AND etat!='revoque'", (_nom("lot", lot),)).fetchone()[0]
        self.revoquer_lot_cles(lot, motif)
        return avant

    def fixer_abonnement(self, client: str, statut: str, expire_le: Optional[int] = None, formule: Optional[str] = None) -> int:
        client = _nom("client", client)
        if statut not in ABONNEMENTS:
            raise ValueError("abonnement : " + ", ".join(ABONNEMENTS))
        if expire_le is not None and (isinstance(expire_le, bool) or not isinstance(expire_le, int) or expire_le <= 0):
            raise ValueError("échéance : une date (secondes Unix) positive")
        if formule is not None and (not isinstance(formule, str) or not _FORMULE.match(formule)):
            raise ValueError("formule : minuscules, chiffres, _ et -, 30 au plus")
        with self._cx() as cx:
            cx.execute("INSERT INTO clients (client, abonnement, formule, expire_le) VALUES (?,?,?,?) ON CONFLICT(client) DO UPDATE SET "
                       "abonnement=excluded.abonnement, formule=excluded.formule, expire_le=excluded.expire_le", (client, statut, formule, expire_le))
            self._heriter(cx, client)
            # Ses box (#3303) : une box suspendue ou révoquée INDIVIDUELLEMENT n'est jamais touchée ; une box suspendue PAR le client
            # (motif MOTIF_CLIENT) suit le client.
            box = cx.execute("UPDATE abonnements_box SET statut=?, formule=?, expire_le=?, motif=?, maj_le=? "
                             "WHERE (statut='actif' OR (statut='suspendu' AND motif=?)) AND jeton_id IN (SELECT id FROM jetons WHERE client=?)",
                             (statut, formule, expire_le, MOTIF_CLIENT if statut != "actif" else None, self._maintenant(), MOTIF_CLIENT, client)).rowcount
            n = cx.execute("SELECT COUNT(*) FROM jetons WHERE client=?", (client,)).fetchone()[0]
        self._audit("abonnement", f"client={client} statut={statut} formule={formule or '-'} expire={expire_le or '-'} box={box}")
        return n

    # ── abonnement par box et formules (#3303) ───────────────────────────────────────────────────────────────
    def formules(self) -> List[dict]:
        with self._cx() as cx:
            return [dict(r, services=_services(r["services"])) for r in cx.execute("SELECT nom, libelle, profil, mois, services FROM formules ORDER BY nom")]

    def fixer_formule(self, nom: str, libelle: str, profil: str, mois: int, services: Optional[List[str]] = None) -> None:
        if not isinstance(nom, str) or not _FORMULE.match(nom):
            raise ValueError("formule : minuscules, chiffres, _ et -, 30 au plus")
        if not isinstance(libelle, str) or not libelle.strip() or len(libelle) > 60 or any(ord(c) < 32 for c in libelle):
            raise ValueError("libellé : 1 à 60 caractères imprimables")
        if profil not in PROFILS:
            raise ValueError("profil : " + ", ".join(PROFILS))
        if isinstance(mois, bool) or not isinstance(mois, int) or not 1 <= mois <= 120:
            raise ValueError("durée : de 1 à 120 mois")
        services = valider_services(services or [])
        with self._cx() as cx:
            cx.execute("INSERT INTO formules (nom, libelle, profil, mois, services) VALUES (?,?,?,?,?) ON CONFLICT(nom) DO UPDATE SET "
                       "libelle=excluded.libelle, profil=excluded.profil, mois=excluded.mois, services=excluded.services",
                       (nom, libelle.strip(), profil, mois, json.dumps(services)))
        self._audit("formule", f"nom={nom} profil={profil} mois={mois} services={','.join(services) or '-'}")

    # ── droits du maillage (#3305) ───────────────────────────────────────────────────────────────────────────
    def fixer_maillage(self, nom: str, formule: str, empreinte: Optional[str] = None, statut: str = "actif",
                       mois: Optional[int] = None, motif: Optional[str] = None) -> None:
        """Abonnement d'un pair du maillage (nom de pairs-enroles.json, empreinte facultative mais vérifiée par le fournisseur si posée)."""
        if not isinstance(nom, str) or not _PAIR.match(nom):
            raise ValueError("nom de pair : minuscules, chiffres et -, 31 au plus")
        if empreinte is not None and (not isinstance(empreinte, str) or not _EMPREINTE_PAIR.match(empreinte)):
            raise ValueError("empreinte : sbx-<12 hex>")
        if statut not in ABONNEMENTS:
            raise ValueError("statut : " + ", ".join(ABONNEMENTS))
        if mois is not None and (isinstance(mois, bool) or not isinstance(mois, int) or not 1 <= mois <= 120):
            raise ValueError("durée : de 1 à 120 mois")
        motif = self._motif(motif) if statut != "actif" or motif else None
        expire = ajouter_mois(self._maintenant(), mois) if mois else None
        with self._cx() as cx:
            cx.execute("BEGIN IMMEDIATE")
            if cx.execute("SELECT 1 FROM formules WHERE nom=?", (formule if isinstance(formule, str) else "",)).fetchone() is None:
                cx.execute("ROLLBACK")
                raise ValueError("formule inconnue")
            cx.execute("INSERT INTO abonnements_maillage (nom, empreinte, formule, statut, expire_le, motif, maj_le) VALUES (?,?,?,?,?,?,?) "
                       "ON CONFLICT(nom) DO UPDATE SET empreinte=excluded.empreinte, formule=excluded.formule, statut=excluded.statut, "
                       "expire_le=excluded.expire_le, motif=excluded.motif, maj_le=excluded.maj_le",
                       (nom, empreinte, formule, statut, expire, motif, self._maintenant()))
            cx.execute("COMMIT")
        self._audit("maillage", f"pair={nom} formule={formule} statut={statut} expire={expire or '-'}" + (f" motif={motif}" if motif else ""))

    def droits_maillage(self) -> dict:
        return lire_droits_cx(self._cx(), self._maintenant())

    def _box(self, cx: sqlite3.Connection, ident: int):
        r = cx.execute("SELECT j.id, j.client, j.serie, j.etat, j.cle_pub, b.statut, b.formule, b.expire_le FROM jetons j "
                       "LEFT JOIN abonnements_box b ON b.jeton_id=j.id WHERE j.id=?", (ident,)).fetchone()
        if r is None:
            raise LookupError("box inconnue")
        if r["statut"] is None:                                                       # ligne absente (base concurrente) : héritage d'abord
            self._heriter(cx, r["client"])
            return self._box(cx, ident)
        return r

    @staticmethod
    def libelle_box(r) -> str:
        """Ce que l'administrateur retape pour révoquer : le numéro de série, sinon l'identifiant du jeton."""
        return r["serie"] or str(r["id"])

    def _fixer_box(self, ident: int, action: str, motif: Optional[str] = None, verifier=None, **champs) -> dict:
        """Tout dans un BEGIN IMMEDIATE : lecture, `verifier(cx, ligne)` (formule, jeton…), écriture."""
        with self._cx() as cx:
            cx.execute("BEGIN IMMEDIATE")
            try:
                r = self._box(cx, ident)
                if r["statut"] == "revoque":
                    raise PermissionError("box révoquée : un nouvel enrôlement exige un nouveau jeton")
                if verifier is not None:
                    verifier(cx, r)
                champs = {k: (v(r) if callable(v) else v) for k, v in champs.items()}
                poses = ", ".join(f"{k}=?" for k in champs)
                cx.execute(f"UPDATE abonnements_box SET {poses}, motif=?, maj_le=? WHERE jeton_id=?",
                           (*champs.values(), motif, self._maintenant(), ident))
                cx.execute("COMMIT")
            except BaseException:
                cx.execute("ROLLBACK")
                raise
        self._audit("abonnement-box", f"id={ident} client={r['client']} action={action} "
                    + " ".join(f"{k}={v}" for k, v in champs.items()) + (f" motif={motif}" if motif else ""))
        return champs

    @staticmethod
    def _motif(motif) -> str:
        motif = motif.strip() if isinstance(motif, str) else ""
        if len(motif) < MOTIF_MIN or len(motif) > 200 or any(ord(c) < 32 for c in motif):
            raise ValueError(f"motif obligatoire : {MOTIF_MIN} à 200 caractères imprimables")
        return motif

    def prolonger_box(self, ident: int, mois: int) -> int:
        """Nouvelle échéance = échéance en cours + `mois` ; d'aujourd'hui si elle est passée ou absente. Rend actif un abonnement échu."""
        if isinstance(mois, bool) or not isinstance(mois, int) or not 1 <= mois <= 120:
            raise ValueError("durée : de 1 à 120 mois")
        now = self._maintenant()

        def depart(r):
            return ajouter_mois(r["expire_le"] if (r["expire_le"] or 0) > now else now, mois)
        return self._fixer_box(ident, "prolonger", expire_le=depart)["expire_le"]

    def changer_formule_box(self, ident: int, formule: str) -> None:
        def existe(cx, _r):
            if cx.execute("SELECT 1 FROM formules WHERE nom=?", (formule if isinstance(formule, str) else "",)).fetchone() is None:
                raise ValueError("formule inconnue")
        self._fixer_box(ident, "formule", verifier=existe, formule=formule)

    def suspendre_box(self, ident: int, motif: str) -> None:
        self._fixer_box(ident, "suspendre", self._motif(motif), statut="suspendu")

    def reprendre_box(self, ident: int, motif: Optional[str] = None) -> None:
        self._fixer_box(ident, "reprendre", self._motif(motif) if motif and motif.strip() else None, statut="actif")

    def revoquer_box(self, ident: int, motif: str, confirmation: str) -> Optional[str]:
        """Révoque l'abonnement de CETTE box et son seul jeton. Rend la clé publique à retirer du tunnel."""
        motif = self._motif(motif)
        cle = []

        def confirmer_et_revoquer_le_jeton(cx, r):
            if confirmation != self.libelle_box(r):
                raise ValueError("confirmation : retapez le nom de la box")
            cle.append(self._revoquer_jeton(cx, ident, motif))          # même transaction que le statut de la box
        self._fixer_box(ident, "revoquer", motif, verifier=confirmer_et_revoquer_le_jeton, statut="revoque")
        self._audit("jeton-revoque", f"id={ident} motif={motif}")
        return cle[0]

    def abonnements(self, profils_appliques: Optional[dict] = None) -> List[dict]:
        """Une ligne par box : formule, échéance, jours restants, statut CALCULÉ, profil commandé (jeton), profil de la formule, profil appliqué
        (relevé du pilotage par adresse tunnel ; None = inconnu) et écart."""
        profils_appliques = profils_appliques or {}
        now = self._maintenant()
        sel = ("SELECT j.id, j.client, j.serie, j.lot, j.profil, j.etat, "
               "CASE WHEN b.statut IS NULL THEN (CASE WHEN j.etat='revoque' THEN 'revoque' ELSE COALESCE(c.abonnement,'actif') END) ELSE b.statut END AS statut, "
               "CASE WHEN b.statut IS NULL THEN c.formule ELSE b.formule END AS formule, "
               "CASE WHEN b.statut IS NULL THEN c.expire_le ELSE b.expire_le END AS expire_le, b.motif AS motif, "
               "f.profil AS profil_formule, f.libelle AS formule_libelle, {adresse} AS adresse "
               "FROM jetons j LEFT JOIN abonnements_box b ON b.jeton_id=j.id LEFT JOIN clients c ON c.client=j.client "
               "LEFT JOIN formules f ON f.nom=(CASE WHEN b.statut IS NULL THEN c.formule ELSE b.formule END) ORDER BY j.client, j.id")
        with self._cx() as cx:                                                          # lecture seule : la migration se fait à l'init et à l'émission
            adresse = ("(SELECT p.adresse FROM pairs p WHERE p.cle_pub=j.cle_pub AND p.retire_le IS NULL)" if self._table(cx, "pairs") else "NULL")
            lignes = cx.execute(sel.format(adresse=adresse)).fetchall()
        sortie = []
        for r in lignes:
            applique = profils_appliques.get(r["adresse"]) if r["adresse"] else None
            attendu = r["profil_formule"] or r["profil"]
            sortie.append({"id": r["id"], "box": self.libelle_box(r), "client": r["client"], "serie": r["serie"], "lot": r["lot"], "jeton": r["etat"],
                           "formule": r["formule"], "formule_libelle": r["formule_libelle"], "expire_le": r["expire_le"],
                           "jours_restants": None if r["expire_le"] is None else (r["expire_le"] - now) // 86400,
                           "statut": etat_abonnement(r["statut"], r["expire_le"], now), "motif": r["motif"],
                           "profil_commande": r["profil"], "profil_formule": r["profil_formule"], "profil_applique": applique,
                           "ecart": bool(applique and attendu and applique != attendu), "adresse": r["adresse"]})
        return sortie

    @staticmethod
    def _table(cx: sqlite3.Connection, nom: str) -> bool:
        return cx.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (nom,)).fetchone() is not None

    def livraison_autorisee(self, cle_pub: str) -> bool:
        """Une box réclamée dont le jeton n'est pas révoqué et dont le client est actif peut recevoir un profil. Rien d'autre."""
        if not isinstance(cle_pub, str) or not _CLE_WG.match(cle_pub):
            return False
        with self._cx() as cx:
            r = cx.execute("SELECT id, client, etat FROM jetons WHERE cle_pub=?", (cle_pub,)).fetchone()
            return bool(r and r["etat"] == "reclame" and self._abonnement_actif(cx, r["client"], r["id"]))

    def lister(self, etat: Optional[str] = None, client: Optional[str] = None, lot: Optional[str] = None) -> List[dict]:
        w, a = ["1=1"], []
        for col, v in (("j.etat", etat), ("j.client", client), ("j.lot", lot)):
            if v is not None:
                w.append(f"{col}=?")
                a.append(v)
        with self._cx() as cx:
            lignes = [dict(r) for r in cx.execute(
                "SELECT j.id, j.client, j.profil, j.lot, j.serie, j.etat, COALESCE(c.abonnement,'actif') AS abonnement, c.formule AS formule, "
                "c.expire_le AS abonnement_expire_le, j.emis_le, j.expire_le, j.reclame_le, j.cle_pub "
                "FROM jetons j LEFT JOIN clients c ON c.client=j.client WHERE " + " AND ".join(w) + " ORDER BY j.id", a)]
        now = self._maintenant()
        for x in lignes:
            x["abonnement"] = etat_abonnement(x["abonnement"], x["abonnement_expire_le"], now)
        return lignes

    # ── suivi des box (#2190) ────────────────────────────────────────────────────────────────────────────────
    def _box_reclamee(self, cx: sqlite3.Connection, cle_pub: str):
        if not isinstance(cle_pub, str) or not _CLE_WG.match(cle_pub):
            raise ValueError("clé publique invalide")
        r = cx.execute("SELECT id, client FROM jetons WHERE cle_pub=? AND etat='reclame'", (cle_pub,)).fetchone()
        if r is None:
            raise ValueError("box inconnue")
        return r

    def noter_progression(self, cle_pub: str, etape: str, faites: int, total: int, termine: bool = False) -> None:
        if not isinstance(etape, str) or not _ETAPE.match(etape):
            raise ValueError("étape : minuscules, chiffres, _ et -, 40 au plus")
        for nom, v in (("faites", faites), ("total", total)):
            if isinstance(v, bool) or not isinstance(v, int):
                raise ValueError(f"{nom} : un entier")
        if not 1 <= total <= 100 or not 0 <= faites <= total:
            raise ValueError("progression : 0 <= faites <= total <= 100")
        with self._cx() as cx:
            self._box_reclamee(cx, cle_pub)
            cx.execute("INSERT INTO progression (cle_pub, etape, faites, total, termine, maj_le) VALUES (?,?,?,?,?,?) ON CONFLICT(cle_pub) DO UPDATE SET "
                       "etape=excluded.etape, faites=excluded.faites, total=excluded.total, termine=excluded.termine, maj_le=excluded.maj_le",
                       (cle_pub, etape, faites, total, 1 if termine else 0, self._maintenant()))

    def boxes(self) -> List[dict]:
        """Une ligne par jeton : en attente, préparation, en cours, terminé ou révoqué, avec la progression en pour cent."""
        with self._cx() as cx:
            lignes = cx.execute("SELECT j.id, j.client, j.profil, j.lot, j.serie, j.etat, j.cle_pub, p.etape, p.faites, p.total, p.termine, p.maj_le "
                                "FROM jetons j LEFT JOIN progression p ON p.cle_pub=j.cle_pub ORDER BY j.id").fetchall()
        sortie = []
        for r in lignes:
            pct = round(100 * r["faites"] / r["total"]) if r["total"] else 0
            if r["etat"] == "revoque":
                statut, pct = "révoqué", pct
            elif r["etat"] == "emis":
                statut, pct = "en attente", 0
            elif r["termine"]:
                statut, pct = "terminé", 100
            elif r["total"] and r["faites"] > 0:
                statut = "en cours"
            else:
                statut = "préparation"
            sortie.append({"id": r["id"], "client": r["client"], "profil": r["profil"], "lot": r["lot"], "serie": r["serie"], "statut": statut,
                           "progression": pct, "etape": r["etape"], "maj_le": r["maj_le"]})
        return sortie

    # ── pré-rapports (#2188 côté box, #2190 côté infrastructure) ─────────────────────────────────────────────
    def recevoir_prerapport(self, cle_pub: str, pre: dict) -> str:
        if not isinstance(pre, dict) or not isinstance(pre.get("empreinte"), str):
            raise ValueError("pré-rapport : un objet avec son empreinte")
        brut = json.dumps(pre, ensure_ascii=False, sort_keys=True)
        if len(brut.encode("utf-8")) > PRERAPPORT_MAX:
            raise ValueError(f"pré-rapport : {PRERAPPORT_MAX} octets au plus")
        if empreinte_prerapport(pre) != pre["empreinte"]:
            raise ValueError("pré-rapport : l'empreinte ne correspond pas au contenu")
        with self._cx() as cx:
            r = self._box_reclamee(cx, cle_pub)
            cx.execute("INSERT OR IGNORE INTO prerapports (empreinte, cle_pub, contenu, recu_le) VALUES (?,?,?,?)", (pre["empreinte"], cle_pub, brut, self._maintenant()))
        self._audit("prerapport-recu", f"id={r['id']} client={r['client']} empreinte={pre['empreinte'][:12]}")
        return pre["empreinte"]

    def prerapports(self) -> List[dict]:
        with self._cx() as cx:
            return [{"empreinte": r["empreinte"], "client": r["client"], "profil": json.loads(r["contenu"]).get("profil", ""), "mode": json.loads(r["contenu"]).get("mode", ""),
                     "box": json.loads(r["contenu"]).get("box", ""),
                     "paquets": len(json.loads(r["contenu"]).get("paquets", [])), "recu_le": r["recu_le"], "refuse": bool(r["refuse"]), "motif": r["motif"]}
                    for r in cx.execute("SELECT p.empreinte, p.contenu, p.recu_le, p.refuse, p.motif, j.client FROM prerapports p "
                                        "JOIN jetons j ON j.cle_pub=p.cle_pub ORDER BY p.recu_le DESC")]

    def prerapport(self, empreinte: str) -> Optional[dict]:
        with self._cx() as cx:
            r = cx.execute("SELECT contenu FROM prerapports WHERE empreinte=?", (empreinte,)).fetchone()
        return json.loads(r["contenu"]) if r else None

    def refuser_prerapport(self, empreinte: str, motif: str) -> None:
        motif = str(motif)[:200]
        with self._cx() as cx:
            n = cx.execute("UPDATE prerapports SET refuse=1, motif=? WHERE empreinte=?", (motif, empreinte)).rowcount
        if not n:
            raise ValueError("pré-rapport inconnu")
        self._audit("prerapport-refuse", f"empreinte={empreinte[:12]} motif={motif}")

    def prerapport_refuse(self, empreinte: str, cle_pub: Optional[str] = None) -> bool:
        """Refusé ? Avec `cle_pub`, seulement pour un pré-rapport de CETTE box (une box ne sonde pas ceux des autres)."""
        with self._cx() as cx:
            r = cx.execute("SELECT refuse, cle_pub FROM prerapports WHERE empreinte=?", (empreinte,)).fetchone()
        return bool(r and r["refuse"] and (cle_pub is None or r["cle_pub"] == cle_pub))

    # ── rapport final et contact du client (#2192) ───────────────────────────────────────────────────────────
    def fixer_contact(self, client: str, email: Optional[str]) -> None:
        from . import rapport as R  # noqa: PLC0415
        client = _nom("client", client)
        adresse = None if email is None else R.courriel_valide(email)
        with self._cx() as cx:
            cx.execute("INSERT INTO clients (client, abonnement, email) VALUES (?, 'actif', ?) ON CONFLICT(client) DO UPDATE SET email=excluded.email", (client, adresse))
        self._audit("contact", f"client={client} contact={'renseigné' if adresse else 'retiré'}")

    def contact(self, client: str) -> Optional[str]:
        with self._cx() as cx:
            r = cx.execute("SELECT email FROM clients WHERE client=?", (client,)).fetchone()
        return r["email"] if r else None

    def recevoir_rapport(self, cle_pub: str, rap: dict) -> int:
        from . import rapport as R  # noqa: PLC0415
        R.valider(rap)
        emp = hashlib.sha256(json.dumps(rap, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        with self._cx() as cx:
            r = self._box_reclamee(cx, cle_pub)
            cx.execute("INSERT OR IGNORE INTO rapports (cle_pub, empreinte, contenu, recu_le) VALUES (?,?,?,?)", (cle_pub, emp, json.dumps(rap, ensure_ascii=False), self._maintenant()))
            ident = cx.execute("SELECT id FROM rapports WHERE cle_pub=? AND empreinte=?", (cle_pub, emp)).fetchone()["id"]
        self._audit("rapport-recu", f"id={r['id']} client={r['client']} rapport={ident}")
        return ident

    def rapports(self) -> List[dict]:
        with self._cx() as cx:
            return [{"id": r["id"], "client": json.loads(r["contenu"])["client"], "profil": json.loads(r["contenu"])["profil"], "paquets": len(json.loads(r["contenu"])["paquets"]),
                     "recu_le": r["recu_le"], "envoye": bool(r["envoye"])}
                    for r in cx.execute("SELECT id, contenu, recu_le, envoye FROM rapports ORDER BY id DESC")]

    def rapport(self, ident: int) -> Optional[dict]:
        with self._cx() as cx:
            r = cx.execute("SELECT contenu FROM rapports WHERE id=?", (ident,)).fetchone()
        return json.loads(r["contenu"]) if r else None

    def marquer_rapport_envoye(self, ident: int) -> None:
        with self._cx() as cx:
            cx.execute("UPDATE rapports SET envoye=1 WHERE id=?", (ident,))
