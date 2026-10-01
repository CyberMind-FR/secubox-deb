# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le Coffre : clé maîtresse, serrures, compartiments, secrets (§3).

SCELLÉ PAR DÉFAUT. La MK n'existe qu'en mémoire, entre une ouverture et le
scellement suivant (commande, inactivité, arrêt du processus). Sans elle, la
base n'est qu'un fichier de données chiffrées : elle peut partir telle quelle
sur le disque de sauvegarde (par `.backup`, jamais par `cp` — WAL).

UNE MK, PLUSIEURS SERRURES. Chaque serrure emballe la même MK sous sa propre
clé (Argon2id de son secret) : ajouter ou retirer une serrure ne rechiffre
rien. Les codes de secours sont des serrures à usage unique.

COMPARTIMENTS. `box` pour le système ; `p-<user_uuid>` pour une personne — par
son identifiant, jamais par un compte système (décision #1405).
"""
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import base64

from .crypto import (ARGON2_DEFAUT, TAILLE_CLE, Refus, aad_secret, aad_serrure, chiffrer, cle_compartiment,
                     dechiffrer, derive_kek, derive_kek_appareil, nouveau_sel, nouvelle_cle)
from .journal import Journal
from .memoire import CleVerrouillee

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS serrures (
    id TEXT PRIMARY KEY,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'secours', 'appareil')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, mk BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT);
CREATE TABLE IF NOT EXISTS compartiments (
    id TEXT PRIMARY KEY,
    nature TEXT NOT NULL CHECK (nature IN ('box', 'personne')),
    libelle TEXT NOT NULL DEFAULT '',
    cree INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (
    compartiment TEXT NOT NULL REFERENCES compartiments(id),
    nom TEXT NOT NULL,
    version INTEGER NOT NULL,
    nonce BLOB NOT NULL, valeur BLOB NOT NULL,
    modifie INTEGER NOT NULL,
    PRIMARY KEY (compartiment, nom));
"""

NB_CODES = 5
PHRASE_MIN = 12
DELAI_DEFAUT = 900
VALEUR_MAX = 64 * 1024
VERSION_SCHEMA = "2"
CRED_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,1024}$")
NOM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
COMPARTIMENT_RE = re.compile(
    r"^(box|p-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class Scelle(Exception):
    """Le Coffre est scellé : rien de ce qu'il garde n'est accessible."""


class NonInitialise(Exception):
    """Le Coffre n'a pas encore de clé maîtresse."""


class Interdit(ValueError):
    """Demande contraire aux règles du Coffre (nom, taille, dernière serrure…)."""


def code_secours() -> str:
    """25 caractères base32 (125 bits), lus par groupes de cinq."""
    brut = "".join(secrets.choice(_B32) for _ in range(25))
    return "-".join(brut[i:i + 5] for i in range(0, 25, 5))


def normalise_code(code: str) -> str:
    return "".join(c for c in code.upper() if c in _B32)


def b64u_decode(texte: str) -> bytes:
    return base64.urlsafe_b64decode(texte + "=" * (-len(texte) % 4))


def b64u(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).decode().rstrip("=")


_MIGRATION_V2 = """
CREATE TABLE serrures_v2 (
    id TEXT PRIMARY KEY,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'secours', 'appareil')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, mk BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT);
INSERT INTO serrures_v2 (id, genre, libelle, sel, params, nonce, mk, creee)
    SELECT id, genre, libelle, sel, params, nonce, mk, creee FROM serrures;
DROP TABLE serrures;
ALTER TABLE serrures_v2 RENAME TO serrures;
UPDATE meta SET valeur = '2' WHERE cle = 'version';
"""


class Coffre:
    def __init__(self, base: Path, journal: Journal, delai_s: int = DELAI_DEFAUT,
                 horloge: Callable[[], float] = time.monotonic, argon2: Optional[dict] = None):
        self.base = Path(base)
        self.db = self.base / "coffre.db"
        self.journal = journal
        self.delai_s = delai_s
        self._horloge = horloge
        self._argon2 = dict(argon2 or ARGON2_DEFAUT)
        self._mk: Optional[CleVerrouillee] = None
        self._dernier = 0.0
        self._verrou = threading.RLock()

    # ── base ────────────────────────────────────────────────────────────────
    def _cx(self) -> sqlite3.Connection:
        self.base.mkdir(parents=True, exist_ok=True)
        neuf = not self.db.exists()
        cx = sqlite3.connect(self.db, timeout=10)
        cx.execute("PRAGMA journal_mode=WAL")
        cx.execute("PRAGMA foreign_keys=ON")
        if neuf:
            os.chmod(self.db, 0o600)
        else:
            self._migre(cx)
        return cx

    @staticmethod
    def _migre(cx) -> None:
        """Schéma v1 (P1) → v2 (P4 : serrures d'appareil). Une transaction."""
        try:
            v = cx.execute("SELECT valeur FROM meta WHERE cle='version'").fetchone()
        except sqlite3.OperationalError:
            return
        if v and v[0] == "1":
            cx.executescript("BEGIN;" + _MIGRATION_V2 + "COMMIT;")

    @property
    def initialise(self) -> bool:
        if not self.db.exists():
            return False
        with self._cx() as cx:
            try:
                return cx.execute("SELECT 1 FROM meta WHERE cle='version'").fetchone() is not None
            except sqlite3.OperationalError:
                return False

    # ── mémoire ─────────────────────────────────────────────────────────────
    def _expire(self) -> None:
        if self._mk and self._horloge() - self._dernier > self.delai_s:
            self._sceller("inactivite")

    def _mk_ou_scelle(self) -> bytes:
        self._expire()
        if not self._mk:
            raise Scelle()
        self._dernier = self._horloge()
        return self._mk.octets()

    @property
    def ouvert(self) -> bool:
        with self._verrou:
            self._expire()
            return bool(self._mk)

    def _sceller(self, raison: str) -> None:
        if self._mk:
            self._mk.effacer()
            self._mk = None
            self.journal.ajouter("scellement", raison=raison)

    def sceller(self, raison: str = "commande") -> None:
        with self._verrou:
            self._sceller(raison)

    # ── serrures ────────────────────────────────────────────────────────────
    @staticmethod
    def _verifie_phrase(phrase: str) -> None:
        if not isinstance(phrase, str) or len(phrase) < PHRASE_MIN:
            raise Interdit(f"phrase trop courte ({PHRASE_MIN} caractères au moins)")

    def _ajoute_serrure(self, cx, genre: str, secret: str, mk: bytes, libelle: str) -> str:
        ident = secrets.token_hex(8)
        sel = nouveau_sel()
        kek = derive_kek(secret.encode(), sel, self._argon2)
        nonce, emballee = chiffrer(kek, mk, aad_serrure(ident))
        cx.execute("INSERT INTO serrures (id, genre, libelle, sel, params, nonce, mk, creee) VALUES (?,?,?,?,?,?,?,?)",
                   (ident, genre, libelle, sel, json.dumps(self._argon2), nonce, emballee, int(time.time())))
        return ident

    def _codes(self, cx, mk: bytes) -> list:
        codes = [code_secours() for _ in range(NB_CODES)]
        for i, c in enumerate(codes, 1):
            self._ajoute_serrure(cx, "secours", normalise_code(c), mk, f"code de secours {i}")
        return codes

    def initialiser(self, phrase: str) -> list:
        """Crée la MK, sa phrase et ses codes de secours. Rend les codes, UNE fois."""
        self._verifie_phrase(phrase)
        with self._verrou:
            if self.initialise:
                raise Interdit("le Coffre est déjà initialisé")
            mk = nouvelle_cle()
            with self._cx() as cx:
                cx.executescript(SCHEMA)
                self._ajoute_serrure(cx, "phrase", phrase, mk, "phrase initiale")
                codes = self._codes(cx, mk)
                cx.execute("INSERT INTO compartiments VALUES ('box', 'box', 'système', ?)", (int(time.time()),))
                cx.execute("INSERT INTO meta VALUES ('version', ?), ('cree', ?)",
                           (VERSION_SCHEMA, str(int(time.time()))))
            self._mk = CleVerrouillee(mk)
            del mk
            self._dernier = self._horloge()
            self.journal.ajouter("initialisation", serrures=1 + NB_CODES)
            return codes

    def ouvrir(self, secret: str, genre: str = "phrase", cred_id: Optional[str] = None, **contexte) -> bool:
        """Essaie les serrures du genre donné. `contexte` (qui, d'où) va au journal.

        `appareil` : `secret` est la sortie WebAuthn PRF (base64url), `cred_id`
        désigne la clé d'appareil qui l'a rendue.
        """
        if genre not in ("phrase", "secours", "appareil"):
            raise Interdit("genre de serrure inconnu")
        if not self.initialise:
            raise NonInitialise()
        if genre == "appareil":
            try:
                candidat = b64u_decode(secret or "")
            except (ValueError, TypeError):
                raise Interdit("sortie PRF illisible") from None
            if len(candidat) != TAILLE_CLE:
                raise Interdit("sortie PRF de 32 octets attendue")
        else:
            candidat = (secret if genre == "phrase" else normalise_code(secret or "")).encode()
        with self._verrou:
            self._expire()
            with self._cx() as cx:
                req = "SELECT id, sel, params, nonce, mk FROM serrures WHERE genre=?"
                args = [genre]
                if genre == "appareil" and cred_id:
                    req += " AND cred_id=?"
                    args.append(cred_id)
                lignes = cx.execute(req, args).fetchall()
                for ident, sel, params, nonce, emballee in lignes:
                    try:
                        kek = (derive_kek_appareil(candidat, sel) if genre == "appareil"
                               else derive_kek(candidat, sel, json.loads(params)))
                        mk = dechiffrer(kek, nonce, emballee, aad_serrure(ident))
                    except Refus:
                        continue
                    restants = None
                    if genre == "secours":              # usage unique
                        cx.execute("DELETE FROM serrures WHERE id=?", (ident,))
                        restants = cx.execute(
                            "SELECT COUNT(*) FROM serrures WHERE genre='secours'").fetchone()[0]
                    if not self._mk:
                        self._mk = CleVerrouillee(mk)
                    del mk
                    self._dernier = self._horloge()
                    details = {"genre": genre, "serrure": ident, **contexte}
                    if restants is not None:
                        details["codes_restants"] = restants
                    self.journal.ajouter("ouverture", **details)
                    return True
            self.journal.ajouter("ouverture_refusee", genre=genre, **contexte)
            return False

    def ajouter_serrure_phrase(self, phrase: str, libelle: str = "") -> str:
        self._verifie_phrase(phrase)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                ident = self._ajoute_serrure(cx, "phrase", phrase, mk, libelle[:80])
            self.journal.ajouter("serrure_ajoutee", serrure=ident, genre="phrase")
            return ident

    def ajouter_serrure_appareil(self, cred_id: str, sel: bytes, prf: bytes, libelle: str = "") -> str:
        """Une clé d'appareil (WebAuthn PRF) emballe la MK. Coffre ouvert exigé."""
        if not isinstance(cred_id, str) or not CRED_ID_RE.match(cred_id):
            raise Interdit("identifiant de clé d'appareil invalide")
        if len(sel) != TAILLE_CLE or len(prf) != TAILLE_CLE:
            raise Interdit("sel et sortie PRF de 32 octets attendus")
        with self._verrou:
            mk = self._mk_ou_scelle()
            ident = secrets.token_hex(8)
            nonce, emballee = chiffrer(derive_kek_appareil(prf, sel), mk, aad_serrure(ident))
            with self._cx() as cx:
                if cx.execute("SELECT 1 FROM serrures WHERE cred_id=?", (cred_id,)).fetchone():
                    raise Interdit("cette clé d'appareil est déjà une serrure")
                cx.execute("INSERT INTO serrures (id, genre, libelle, sel, params, nonce, mk, creee, cred_id) "
                           "VALUES (?,?,?,?,?,?,?,?,?)",
                           (ident, "appareil", libelle[:80], sel, json.dumps({"kdf": "hkdf-sha256"}),
                            nonce, emballee, int(time.time()), cred_id))
            self.journal.ajouter("serrure_ajoutee", serrure=ident, genre="appareil")
            return ident

    def serrures_appareil(self) -> list:
        """Ce qu'il faut au navigateur pour demander la sortie PRF : identifiant
        de la clé et sel — rien de secret."""
        if not self.initialise:
            return []
        with self._cx() as cx:
            return [{"id": i, "cred_id": c, "sel": b64u(s), "libelle": l} for i, c, s, l in cx.execute(
                "SELECT id, cred_id, sel, libelle FROM serrures WHERE genre='appareil' ORDER BY creee")]

    def retirer_serrure(self, ident: str) -> None:
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                ligne = cx.execute("SELECT genre FROM serrures WHERE id=?", (ident,)).fetchone()
                if not ligne:
                    raise Interdit("serrure inconnue")
                if ligne[0] == "phrase" and cx.execute(
                        "SELECT COUNT(*) FROM serrures WHERE genre='phrase'").fetchone()[0] <= 1:
                    raise Interdit("dernière phrase : le Coffre ne s'ouvrirait plus que par les codes")
                cx.execute("DELETE FROM serrures WHERE id=?", (ident,))
            self.journal.ajouter("serrure_retiree", serrure=ident, genre=ligne[0])

    def regenerer_codes(self) -> list:
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                cx.execute("DELETE FROM serrures WHERE genre='secours'")
                codes = self._codes(cx, mk)
            self.journal.ajouter("codes_regeneres", nombre=NB_CODES)
            return codes

    # ── compartiments et secrets ────────────────────────────────────────────
    @staticmethod
    def _verifie_place(compartiment: str, nom: Optional[str] = None) -> None:
        if not isinstance(compartiment, str) or not COMPARTIMENT_RE.match(compartiment):
            raise Interdit("compartiment invalide (box ou p-<user_uuid>)")
        if nom is not None and (not isinstance(nom, str) or not NOM_RE.match(nom)):
            raise Interdit("nom de secret invalide")

    def creer_compartiment(self, compartiment: str, libelle: str = "") -> None:
        self._verifie_place(compartiment)
        with self._verrou:
            self._mk_ou_scelle()
            nature = "box" if compartiment == "box" else "personne"
            with self._cx() as cx:
                fait = cx.execute("INSERT OR IGNORE INTO compartiments VALUES (?,?,?,?)",
                                  (compartiment, nature, libelle[:80], int(time.time()))).rowcount
            if fait:
                self.journal.ajouter("compartiment_cree", compartiment=compartiment)

    def poser(self, compartiment: str, nom: str, valeur: bytes) -> int:
        self._verifie_place(compartiment, nom)
        if not isinstance(valeur, (bytes, bytearray)) or len(valeur) > VALEUR_MAX:
            raise Interdit(f"valeur absente ou trop grande ({VALEUR_MAX} octets au plus)")
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                if not cx.execute("SELECT 1 FROM compartiments WHERE id=?", (compartiment,)).fetchone():
                    raise Interdit("compartiment inexistant")
                ancien = cx.execute("SELECT version FROM secrets WHERE compartiment=? AND nom=?",
                                    (compartiment, nom)).fetchone()
                version = (ancien[0] + 1) if ancien else 1
                nonce, chiffre = chiffrer(cle_compartiment(mk, compartiment), bytes(valeur),
                                          aad_secret(compartiment, nom, version))
                cx.execute("INSERT OR REPLACE INTO secrets VALUES (?,?,?,?,?,?)",
                           (compartiment, nom, version, nonce, chiffre, int(time.time())))
            self.journal.ajouter("secret_pose", compartiment=compartiment, nom=nom, version=version)
            return version

    def lire(self, compartiment: str, nom: str) -> bytes:
        self._verifie_place(compartiment, nom)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                ligne = cx.execute("SELECT version, nonce, valeur FROM secrets WHERE compartiment=? AND nom=?",
                                   (compartiment, nom)).fetchone()
            if not ligne:
                raise KeyError(nom)
            version, nonce, chiffre = ligne
            valeur = dechiffrer(cle_compartiment(mk, compartiment), nonce, chiffre,
                                aad_secret(compartiment, nom, version))
            self.journal.ajouter("secret_lu", compartiment=compartiment, nom=nom, version=version)
            return valeur

    def retirer(self, compartiment: str, nom: str) -> None:
        self._verifie_place(compartiment, nom)
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                fait = cx.execute("DELETE FROM secrets WHERE compartiment=? AND nom=?",
                                  (compartiment, nom)).rowcount
            if not fait:
                raise KeyError(nom)
            self.journal.ajouter("secret_retire", compartiment=compartiment, nom=nom)

    def lister(self, compartiment: Optional[str] = None) -> list:
        """Les NOMS des secrets — jamais leurs valeurs. Coffre ouvert exigé."""
        if compartiment is not None:
            self._verifie_place(compartiment)
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                req = "SELECT compartiment, nom, version, modifie FROM secrets"
                args = ()
                if compartiment is not None:
                    req += " WHERE compartiment=?"
                    args = (compartiment,)
                return [{"compartiment": c, "nom": n, "version": v, "modifie": m}
                        for c, n, v, m in cx.execute(req + " ORDER BY compartiment, nom", args)]

    # ── état ────────────────────────────────────────────────────────────────
    def etat(self) -> dict:
        integre, fautive, lignes = self.journal.verifier()
        sortie = {"initialise": self.initialise, "ouvert": self.ouvert, "delai_s": self.delai_s,
                  "journal": {"integre": integre, "ligne_fautive": fautive, "lignes": lignes}}
        if not sortie["initialise"]:
            return sortie
        with self._verrou:
            if self._mk:
                sortie["reste_s"] = max(0, int(self.delai_s - (self._horloge() - self._dernier)))
            with self._cx() as cx:
                sortie["serrures"] = [{"id": i, "genre": g, "libelle": l, "creee": c} for i, g, l, c in
                                      cx.execute("SELECT id, genre, libelle, creee FROM serrures ORDER BY creee, id")]
                sortie["compartiments"] = [
                    {"id": i, "nature": n, "libelle": l, "secrets": s} for i, n, l, s in cx.execute(
                        "SELECT c.id, c.nature, c.libelle, COUNT(s.nom) FROM compartiments c "
                        "LEFT JOIN secrets s ON s.compartiment = c.id GROUP BY c.id ORDER BY c.id")]
        return sortie
