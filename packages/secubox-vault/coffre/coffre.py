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

LE MOT DE PASSE DE CONNEXION EST UNE SERRURE (#1855). Pas de phrase à part :
une serrure « compte » par administrateur réel, l'Argon2id de son mot de passe
de connexion. La connexion la rejoue en deux temps — préparer (mot de passe
vérifié ICI dans users.json, MK déballée et mise en attente), puis confirmer
quand le second facteur a réussi. Un mot de passe seul n'ouvre rien.

RECOUVREMENT PAR LE MAILLAGE (P8). n parts aléatoires, confiées à des box
pairs (par leur messagerie OpenPGP liée) ou au papier ; chaque PAIRE de parts
ouvre une serrure `maillage`. Deux détenteurs quelconques rouvrent le Coffre ;
un seul, rien. Un jeu sert une fois : utilisé, il disparaît.

UNE PERSONNE A SES SERRURES (P5). Sa clé (32 octets aléatoires) n'est emballée
que par SES serrures — phrase ou clé d'appareil. La clé de son compartiment
demande la MK ET cette clé : l'admin qui ouvre le Coffre n'y lit rien, la
personne non plus tant que le Coffre est scellé. Rien de personnel n'est tenu
en mémoire — SAUF, depuis #1855, la clé d'une personne CONNECTÉE (sa serrure
« compte » = son mot de passe de connexion), tenue le temps de sa session et
oubliée à la déconnexion, à l'inactivité ou au scellement. Sinon chaque requête
apporte la serrure, la clé est dérivée, servie, oubliée.
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

from .crypto import (ARGON2_DEFAUT, TAILLE_CLE, Refus, aad_secret, aad_serrure, aad_serrure_personnelle, chiffrer,
                     cle_compartiment, cle_compartiment_personnel, dechiffrer, derive_kek, derive_kek_appareil,
                     derive_kek_maillage, nouveau_sel, nouvelle_cle)
from .journal import Journal
from .memoire import CleVerrouillee

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS serrures (
    id TEXT PRIMARY KEY,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'secours', 'appareil', 'maillage', 'compte')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, mk BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT,
    compte TEXT);
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
CREATE TABLE IF NOT EXISTS serrures_personnelles (
    id TEXT PRIMARY KEY,
    personne TEXT NOT NULL,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'appareil', 'compte')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, cle BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT);
"""

NB_CODES = 5
PHRASE_MIN = 12
DELAI_DEFAUT = 900
VALEUR_MAX = 64 * 1024
VERSION_SCHEMA = "6"
CRED_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,1024}$")
NOM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
COMPARTIMENT_RE = re.compile(
    r"^(box|p-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
PERSONNE_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DETENTEUR_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
DETENTEURS_MAX = 5
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class Scelle(Exception):
    """Le Coffre est scellé : rien de ce qu'il garde n'est accessible."""


class NonInitialise(Exception):
    """Le Coffre n'a pas encore de clé maîtresse."""


class Interdit(ValueError):
    """Demande contraire aux règles du Coffre (nom, taille, dernière serrure…)."""


class RefusPersonnel(Exception):
    """La serrure présentée n'ouvre pas le compartiment de cette personne."""


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

_MIGRATION_V3 = """
CREATE TABLE IF NOT EXISTS serrures_personnelles (
    id TEXT PRIMARY KEY,
    personne TEXT NOT NULL,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'appareil')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, cle BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT);
UPDATE meta SET valeur = '3' WHERE cle = 'version';
"""

_MIGRATION_V4 = """
CREATE TABLE serrures_v4 (
    id TEXT PRIMARY KEY,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'secours', 'appareil', 'maillage')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, mk BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT);
INSERT INTO serrures_v4 SELECT id, genre, libelle, sel, params, nonce, mk, creee, cred_id FROM serrures;
DROP TABLE serrures;
ALTER TABLE serrures_v4 RENAME TO serrures;
UPDATE meta SET valeur = '4' WHERE cle = 'version';
"""


_MIGRATION_V5 = """
CREATE TABLE serrures_v5 (
    id TEXT PRIMARY KEY,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'secours', 'appareil', 'maillage', 'compte')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, mk BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT,
    compte TEXT);
INSERT INTO serrures_v5 (id, genre, libelle, sel, params, nonce, mk, creee, cred_id)
    SELECT id, genre, libelle, sel, params, nonce, mk, creee, cred_id FROM serrures;
DROP TABLE serrures;
ALTER TABLE serrures_v5 RENAME TO serrures;
UPDATE meta SET valeur = '5' WHERE cle = 'version';
"""


_MIGRATION_V6 = """
CREATE TABLE serrures_perso_v6 (
    id TEXT PRIMARY KEY,
    personne TEXT NOT NULL,
    genre TEXT NOT NULL CHECK (genre IN ('phrase', 'appareil', 'compte')),
    libelle TEXT NOT NULL DEFAULT '',
    sel BLOB NOT NULL, params TEXT NOT NULL,
    nonce BLOB NOT NULL, cle BLOB NOT NULL,
    creee INTEGER NOT NULL,
    cred_id TEXT);
INSERT INTO serrures_perso_v6 SELECT id, personne, genre, libelle, sel, params, nonce, cle, creee, cred_id
    FROM serrures_personnelles;
DROP TABLE serrures_personnelles;
ALTER TABLE serrures_perso_v6 RENAME TO serrures_personnelles;
UPDATE meta SET valeur = '6' WHERE cle = 'version';
"""

COMPTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
ATTENTE_S = 300          # un ticket vit le temps d'un second facteur


def part_texte(jeu: str, indice: int, part: bytes) -> str:
    """Une part lisible et recopiable : « jeu.indice.XXXX-XXXX-… » (base32)."""
    b = base64.b32encode(part).decode().rstrip("=")
    return f"{jeu}.{indice}." + "-".join(b[k:k + 4] for k in range(0, len(b), 4))


def lit_part(texte: str) -> tuple:
    try:
        jeu, indice, corps = (texte or "").strip().split(".", 2)
        b = "".join(c for c in corps.upper() if c in _B32)
        part = base64.b32decode(b + "=" * (-len(b) % 8))
        indice = int(indice)
    except (ValueError, TypeError):
        raise Interdit("part de recouvrement illisible") from None
    if len(part) != TAILLE_CLE or not re.match(r"^[0-9a-f]{8}$", jeu):
        raise Interdit("part de recouvrement illisible")
    return jeu, indice, part


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
        self._attente: dict = {}          # ticket → ouverture préparée, le temps d'un second facteur
        self._perso_ouvertes: dict = {}   # personne → {pk, dernier} : sa clé, tenue le temps de sa session (#1855)

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
        """v1 (P1) → v2 (P4 : serrures d'appareil) → v3 (P5 : serrures
        personnelles). Une transaction par marche."""
        try:
            v = cx.execute("SELECT valeur FROM meta WHERE cle='version'").fetchone()
        except sqlite3.OperationalError:
            return
        v = v[0] if v else None
        if v == "1":
            cx.executescript("BEGIN;" + _MIGRATION_V2 + "COMMIT;")
            v = "2"
        if v == "2":
            cx.executescript("BEGIN;" + _MIGRATION_V3 + "COMMIT;")
            v = "3"
        if v == "3":
            cx.executescript("BEGIN;" + _MIGRATION_V4 + "COMMIT;")
            v = "4"
        if v == "4":
            cx.executescript("BEGIN;" + _MIGRATION_V5 + "COMMIT;")
            v = "5"
        if v == "5":
            cx.executescript("BEGIN;" + _MIGRATION_V6 + "COMMIT;")   # serrures personnelles « compte » (#1855)

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
        for v in self._perso_ouvertes.values():      # une session de personne ne survit pas au scellement
            v["pk"].effacer()
        self._perso_ouvertes.clear()
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

    # ── serrures « compte » : le mot de passe de connexion (#1855) ──────────
    def _ligne_compte(self, utilisateur: str, mot_de_passe: str, mk: bytes) -> tuple:
        ident = secrets.token_hex(8)
        sel = nouveau_sel()
        kek = derive_kek(mot_de_passe.encode(), sel, self._argon2)
        nonce, emballee = chiffrer(kek, mk, aad_serrure(ident))
        return (ident, "compte", f"connexion de {utilisateur}", sel, json.dumps(self._argon2), nonce, emballee,
                int(time.time()), None, utilisateur)

    @staticmethod
    def _pose_compte(cx, ligne: tuple) -> None:
        cx.execute("DELETE FROM serrures WHERE genre='compte' AND compte=?", (ligne[-1],))
        cx.execute("INSERT INTO serrures (id, genre, libelle, sel, params, nonce, mk, creee, cred_id, compte) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?)", ligne)

    def _purge_attente(self) -> None:
        t = self._horloge()
        for k in [k for k, v in self._attente.items() if v["fin"] < t]:
            v = self._attente.pop(k)
            if v.get("mk"):
                v["mk"].effacer()
            if v.get("perso"):
                v["perso"]["pk"].effacer()

    def compte_preparer(self, utilisateur: str, mot_de_passe: str, personne: Optional[str] = None) -> Optional[str]:
        """Le mot de passe de connexion VÉRIFIÉ (l'appelant l'a contrôlé dans
        users.json, l'API aussi) : prépare l'ouverture, rend un ticket — ou
        None si ce compte n'a pas de quoi ouvrir. Rien n'est ouvert ici."""
        if not isinstance(utilisateur, str) or not COMPTE_RE.match(utilisateur) or not mot_de_passe:
            raise Interdit("compte invalide")
        with self._verrou:
            self._purge_attente()
            self._expire()
            attente = {"utilisateur": utilisateur, "fin": self._horloge() + ATTENTE_S, "mk": None, "ligne": None}
            if not self.initialise:
                # PREMIÈRE CONNEXION D'UN ADMIN : le Coffre naît scellé, sa MK attend le second facteur.
                mk = nouvelle_cle()
                ligne = self._ligne_compte(utilisateur, mot_de_passe, mk)
                with self._cx() as cx:
                    cx.executescript(SCHEMA)
                    self._pose_compte(cx, ligne)
                    cx.execute("INSERT INTO compartiments VALUES ('box', 'box', 'système', ?)", (int(time.time()),))
                    cx.execute("INSERT INTO meta VALUES ('version', ?), ('cree', ?)",
                               (VERSION_SCHEMA, str(int(time.time()))))
                attente["mk"] = CleVerrouillee(mk)
                del mk
                self.journal.ajouter("initialisation", par="compte", qui=utilisateur)
            else:
                with self._cx() as cx:
                    lignes = cx.execute("SELECT id, sel, params, nonce, mk FROM serrures "
                                        "WHERE genre='compte' AND compte=?", (utilisateur,)).fetchall()
                for ident, sel, params, nonce, emballee in lignes:
                    try:
                        mk = dechiffrer(derive_kek(mot_de_passe.encode(), sel, json.loads(params)), nonce, emballee,
                                        aad_serrure(ident))
                    except Refus:
                        continue
                    attente["mk"] = CleVerrouillee(mk)
                    del mk
                    break
                if attente["mk"] is None:
                    if not self._mk:
                        self.journal.ajouter("compte_sans_serrure", qui=utilisateur)
                        return None
                    # Coffre ouvert par un autre : ce compte reçoit (ou renouvelle) SA serrure.
                    attente["ligne"] = self._ligne_compte(utilisateur, mot_de_passe, self._mk.octets())
            if personne:
                attente["perso"] = self._perso_preparer(personne, mot_de_passe)
            ticket = secrets.token_urlsafe(32)
            self._attente[ticket] = attente
            return ticket

    def compte_confirmer(self, ticket: str, **contexte) -> bool:
        """Le second facteur a réussi : l'ouverture préparée s'accomplit."""
        with self._verrou:
            self._purge_attente()
            a = self._attente.pop(ticket or "", None)
            if not a:
                return False
            if a.get("seulement_perso"):
                self._perso_installer(a["perso"], origine=contexte.get("origine", ""))
                return True
            if a["ligne"]:
                if not self._mk:
                    return False                  # rescellé entre-temps : la serrure attendra une autre fois
                with self._cx() as cx:
                    self._pose_compte(cx, a["ligne"])
                self._dernier = self._horloge()
                self.journal.ajouter("serrure_ajoutee", genre="compte", qui=a["utilisateur"])
                if a.get("perso"):
                    self._perso_installer(a["perso"], origine=contexte.get("origine", ""))
                return True
            if not self._mk:
                self._mk = CleVerrouillee(a["mk"].octets())
            a["mk"].effacer()
            self._dernier = self._horloge()
            self.journal.ajouter("ouverture", genre="compte", qui=a["utilisateur"], **contexte)
            if a.get("perso"):
                self._perso_installer(a["perso"], origine=contexte.get("origine", ""))
            return True

    def compte_changer(self, utilisateur: str, ancien: str, nouveau: str) -> bool:
        """Le mot de passe change : la serrure du compte est réemballée. Sans
        l'ancien (réinitialisation), elle devient caduque — une connexion,
        Coffre ouvert, la refera."""
        if not COMPTE_RE.match(utilisateur or "") or not ancien or not nouveau:
            return False
        with self._verrou:
            if not self.initialise:
                return False
            with self._cx() as cx:
                for ident, sel, params, nonce, emballee in cx.execute(
                        "SELECT id, sel, params, nonce, mk FROM serrures WHERE genre='compte' AND compte=?",
                        (utilisateur,)).fetchall():
                    try:
                        mk = dechiffrer(derive_kek(ancien.encode(), sel, json.loads(params)), nonce, emballee,
                                        aad_serrure(ident))
                    except Refus:
                        continue
                    self._pose_compte(cx, self._ligne_compte(utilisateur, nouveau, mk))
                    del mk
                    self.journal.ajouter("serrure_renouvelee", genre="compte", qui=utilisateur)
                    return True
            return False

    # ── recouvrement par le maillage (P8) ───────────────────────────────────
    def recouvrement_preparer(self, detenteurs: list) -> dict:
        """Un jeu neuf (l'ancien disparaît). Rend les parts, UNE fois : à
        confier aussitôt — coffrectl les envoie aux box pairs."""
        if not isinstance(detenteurs, list) or not 2 <= len(detenteurs) <= DETENTEURS_MAX:
            raise Interdit(f"de 2 à {DETENTEURS_MAX} détenteurs")
        if len(set(detenteurs)) != len(detenteurs) or not all(
                isinstance(d, str) and DETENTEUR_RE.match(d) for d in detenteurs):
            raise Interdit("détenteurs invalides ou en double")
        with self._verrou:
            mk = self._mk_ou_scelle()
            jeu = secrets.token_hex(4)
            parts = [nouvelle_cle() for _ in detenteurs]
            maintenant = int(time.time())
            with self._cx() as cx:
                cx.execute("DELETE FROM serrures WHERE genre='maillage'")
                for i in range(len(parts)):
                    for j in range(i + 1, len(parts)):
                        ident = secrets.token_hex(8)
                        sel = nouveau_sel()
                        kek = derive_kek_maillage(parts[i], parts[j], sel, jeu, i, j)
                        nonce, emballee = chiffrer(kek, mk, aad_serrure(ident))
                        params = {"kdf": "hkdf-sha256", "jeu": jeu, "paire": [i, j], "detenteurs": detenteurs}
                        cx.execute("INSERT INTO serrures (id, genre, libelle, sel, params, nonce, mk, creee) "
                                   "VALUES (?,?,?,?,?,?,?,?)",
                                   (ident, "maillage", f"recouvrement {jeu} : {detenteurs[i]} + {detenteurs[j]}",
                                    sel, json.dumps(params), nonce, emballee, maintenant))
            self.journal.ajouter("recouvrement_prepare", jeu=jeu, detenteurs=detenteurs)
            return {"jeu": jeu, "detenteurs": detenteurs,
                    "parts": [part_texte(jeu, i, p) for i, p in enumerate(parts)]}

    def recouvrement_etat(self) -> Optional[dict]:
        if not self.initialise:
            return None
        with self._cx() as cx:
            ligne = cx.execute("SELECT params, creee FROM serrures WHERE genre='maillage' LIMIT 1").fetchone()
        if not ligne:
            return None
        p = json.loads(ligne[0])
        return {"jeu": p["jeu"], "detenteurs": p["detenteurs"], "cree": ligne[1]}

    def recouvrement_annuler(self) -> None:
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                n = cx.execute("DELETE FROM serrures WHERE genre='maillage'").rowcount
            if n:
                self.journal.ajouter("recouvrement_annule")

    def ouvrir_par_maillage(self, textes: list, **contexte) -> bool:
        """Deux parts (ou plus) d'un même jeu rouvrent le Coffre. Le jeu
        disparaît alors : ses parts ont circulé, il ne resservira pas."""
        if not self.initialise:
            raise NonInitialise()
        lues = {}
        for t in textes or []:
            jeu, i, part = lit_part(t)
            lues[(jeu, i)] = part
        with self._verrou:
            self._expire()
            with self._cx() as cx:
                lignes = cx.execute("SELECT id, sel, params, nonce, mk FROM serrures WHERE genre='maillage'").fetchall()
                for ident, sel, params, nonce, emballee in lignes:
                    p = json.loads(params)
                    i, j = p["paire"]
                    a, b = lues.get((p["jeu"], i)), lues.get((p["jeu"], j))
                    if a is None or b is None:
                        continue
                    try:
                        mk = dechiffrer(derive_kek_maillage(a, b, sel, p["jeu"], i, j), nonce, emballee,
                                        aad_serrure(ident))
                    except Refus:
                        continue
                    cx.execute("DELETE FROM serrures WHERE genre='maillage'")
                    if not self._mk:
                        self._mk = CleVerrouillee(mk)
                    del mk
                    self._dernier = self._horloge()
                    self.journal.ajouter("ouverture", genre="maillage", jeu=p["jeu"],
                                         detenteurs=[p["detenteurs"][i], p["detenteurs"][j]], **contexte)
                    self.journal.ajouter("recouvrement_consomme", jeu=p["jeu"])
                    return True
            self.journal.ajouter("ouverture_refusee", genre="maillage", parts=len(lues), **contexte)
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
                if ligne[0] in ("phrase", "compte") and cx.execute(
                        "SELECT COUNT(*) FROM serrures WHERE genre IN ('phrase', 'compte')").fetchone()[0] <= 1:
                    raise Interdit("dernière serrure humaine (phrase ou compte) : le Coffre ne s'ouvrirait plus")
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

    @staticmethod
    def _cle_admin(cx, mk: bytes, compartiment: str) -> bytes:
        """Clé d'un compartiment côté administration — jamais celui d'une personne."""
        ligne = cx.execute("SELECT nature FROM compartiments WHERE id=?", (compartiment,)).fetchone()
        if not ligne:
            raise Interdit("compartiment inexistant")
        if ligne[0] == "personne":
            raise Interdit("compartiment personnel : seule la personne y accède, par sa serrure")
        return cle_compartiment(mk, compartiment)

    def creer_compartiment(self, compartiment: str, libelle: str = "") -> None:
        self._verifie_place(compartiment)
        if compartiment != "box":
            raise Interdit("un compartiment personnel naît de la première serrure de la personne")
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
                cle = self._cle_admin(cx, mk, compartiment)
                ancien = cx.execute("SELECT version FROM secrets WHERE compartiment=? AND nom=?",
                                    (compartiment, nom)).fetchone()
                version = (ancien[0] + 1) if ancien else 1
                nonce, chiffre = chiffrer(cle, bytes(valeur), aad_secret(compartiment, nom, version))
                cx.execute("INSERT OR REPLACE INTO secrets VALUES (?,?,?,?,?,?)",
                           (compartiment, nom, version, nonce, chiffre, int(time.time())))
            self.journal.ajouter("secret_pose", compartiment=compartiment, nom=nom, version=version)
            return version

    def lire(self, compartiment: str, nom: str) -> bytes:
        self._verifie_place(compartiment, nom)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                cle = self._cle_admin(cx, mk, compartiment)
                ligne = cx.execute("SELECT version, nonce, valeur FROM secrets WHERE compartiment=? AND nom=?",
                                   (compartiment, nom)).fetchone()
            if not ligne:
                raise KeyError(nom)
            version, nonce, chiffre = ligne
            valeur = dechiffrer(cle, nonce, chiffre, aad_secret(compartiment, nom, version))
            self.journal.ajouter("secret_lu", compartiment=compartiment, nom=nom, version=version)
            return valeur

    def retirer(self, compartiment: str, nom: str) -> None:
        self._verifie_place(compartiment, nom)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                self._cle_admin(cx, mk, compartiment)
                fait = cx.execute("DELETE FROM secrets WHERE compartiment=? AND nom=?",
                                  (compartiment, nom)).rowcount
            if not fait:
                raise KeyError(nom)
            self.journal.ajouter("secret_retire", compartiment=compartiment, nom=nom)

    def lister(self, compartiment: Optional[str] = None) -> list:
        """Les NOMS des secrets — jamais leurs valeurs. Coffre ouvert exigé.
        Ceux des personnes ne s'y montrent pas : leurs noms sont à elles."""
        if compartiment is not None:
            self._verifie_place(compartiment)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                req = ("SELECT s.compartiment, s.nom, s.version, s.modifie FROM secrets s "
                       "JOIN compartiments c ON c.id = s.compartiment WHERE c.nature = 'box'")
                args = ()
                if compartiment is not None:
                    self._cle_admin(cx, mk, compartiment)
                    req += " AND s.compartiment=?"
                    args = (compartiment,)
                return [{"compartiment": c, "nom": n, "version": v, "modifie": m}
                        for c, n, v, m in cx.execute(req + " ORDER BY s.compartiment, s.nom", args)]

    # ── compartiments des personnes (P5) ────────────────────────────────────
    @staticmethod
    def _verifie_personne(personne: str) -> str:
        if not isinstance(personne, str) or not PERSONNE_RE.match(personne):
            raise Interdit("personne invalide (user_uuid)")
        return "p-" + personne

    def _materiau(self, genre: str, secret: str) -> bytes:
        if genre == "appareil":
            try:
                m = b64u_decode(secret or "")
            except (ValueError, TypeError):
                raise Interdit("sortie PRF illisible") from None
            if len(m) != TAILLE_CLE:
                raise Interdit("sortie PRF de 32 octets attendue")
            return m
        if genre not in ("phrase", "compte"):
            raise Interdit("genre de serrure personnelle inconnu")
        if not isinstance(secret, str) or not secret:
            raise Interdit("phrase absente")
        return secret.encode()

    def _emballe_personne(self, cx, personne: str, genre: str, materiau: bytes, pk: bytes, libelle: str,
                          sel: Optional[bytes] = None, cred_id: Optional[str] = None) -> str:
        ident = secrets.token_hex(8)
        if genre in ("phrase", "compte"):
            sel = nouveau_sel()
            params = json.dumps(self._argon2)
            kek = derive_kek(materiau, sel, self._argon2)
        else:
            params = json.dumps({"kdf": "hkdf-sha256"})
            kek = derive_kek_appareil(materiau, sel)
        nonce, emballee = chiffrer(kek, pk, aad_serrure_personnelle(ident, personne))
        cx.execute("INSERT INTO serrures_personnelles (id, personne, genre, libelle, sel, params, nonce, cle, "
                   "creee, cred_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (ident, personne, genre, libelle[:80], sel, params, nonce, emballee, int(time.time()), cred_id))
        return ident

    def _cle_personne(self, cx, personne: str, ouverture: dict, action: str) -> bytes:
        """La clé de la personne, rendue par une de SES serrures — ou refus."""
        genre = (ouverture or {}).get("genre") or "phrase"
        if genre == "session":
            # La clé tenue depuis la CONNEXION de la personne (#1855) : rien à retaper.
            pk = self._pk_session(personne)
            if pk is None:
                self.journal.ajouter("personne_refusee", personne=personne, action=action, genre=genre)
                raise RefusPersonnel()
            return pk
        materiau = self._materiau(genre, (ouverture or {}).get("secret"))
        req = "SELECT id, sel, params, nonce, cle FROM serrures_personnelles WHERE personne=? AND genre=?"
        args = [personne, genre]
        if genre == "appareil" and (ouverture or {}).get("cred_id"):
            req += " AND cred_id=?"
            args.append(ouverture["cred_id"])
        for ident, sel, params, nonce, emballee in cx.execute(req, args).fetchall():
            try:
                kek = (derive_kek_appareil(materiau, sel) if genre == "appareil"
                       else derive_kek(materiau, sel, json.loads(params)))
                return dechiffrer(kek, nonce, emballee, aad_serrure_personnelle(ident, personne))
            except Refus:
                continue
        self.journal.ajouter("personne_refusee", personne=personne, action=action, genre=genre)
        raise RefusPersonnel()

    def personne_etat(self, personne: str) -> dict:
        """Ce que la personne peut savoir sans serrure : ses serrures (rien de
        secret — de quoi demander une sortie PRF) et le nombre de ses secrets."""
        comp = self._verifie_personne(personne)
        sortie = {"initialise": self.initialise, "ouvert": self.ouvert, "serrures": [], "secrets": 0,
                  "session": self._pk_session(personne, toucher=False) is not None}
        if not sortie["initialise"]:
            return sortie
        with self._cx() as cx:
            sortie["serrures"] = [
                {"id": i, "genre": g, "libelle": l, "creee": c,
                 **({"cred_id": ci, "sel": b64u(se)} if g == "appareil" else {})}
                for i, g, l, c, ci, se in cx.execute(
                    "SELECT id, genre, libelle, creee, cred_id, sel FROM serrures_personnelles "
                    "WHERE personne=? ORDER BY creee, id", (personne,))]
            sortie["secrets"] = cx.execute("SELECT COUNT(*) FROM secrets WHERE compartiment=?",
                                           (comp,)).fetchone()[0]
        return sortie

    def personne_initialiser(self, personne: str, phrase: str, libelle: str = "", genre: str = "phrase") -> None:
        """Première serrure de la personne : sa clé naît, son compartiment aussi.
        Coffre ouvert exigé. Un secret posé dans ce compartiment sous l'ancien
        régime (clé tirée de la MK seule, P1) est rechiffré sous la nouvelle."""
        comp = self._verifie_personne(personne)
        if genre == "phrase":
            self._verifie_phrase(phrase)           # un mot de passe de connexion a ses propres règles
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                if cx.execute("SELECT 1 FROM serrures_personnelles WHERE personne=?", (personne,)).fetchone():
                    raise Interdit("cette personne a déjà ses serrures")
                pk = nouvelle_cle()
                cx.execute("INSERT OR IGNORE INTO compartiments VALUES (?,?,?,?)",
                           (comp, "personne", "", int(time.time())))
                nouvelle = cle_compartiment_personnel(mk, comp, pk)
                for nom, version, nonce, chiffre in cx.execute(
                        "SELECT nom, version, nonce, valeur FROM secrets WHERE compartiment=?", (comp,)).fetchall():
                    aad = aad_secret(comp, nom, version)
                    n2, c2 = chiffrer(nouvelle, dechiffrer(cle_compartiment(mk, comp), nonce, chiffre, aad), aad)
                    cx.execute("UPDATE secrets SET nonce=?, valeur=? WHERE compartiment=? AND nom=?",
                               (n2, c2, comp, nom))
                ident = self._emballe_personne(cx, personne, genre, phrase.encode(), pk,
                                               libelle or ("phrase personnelle" if genre == "phrase" else "connexion"))
            del pk, nouvelle
            self.journal.ajouter("personne_initialisee", personne=personne, serrure=ident)

    # ── la connexion de la PERSONNE ouvre son compartiment (#1855) ──────────
    # Le mot de passe de connexion est une serrure de plus de la personne (genre
    # « compte »). À la connexion (second facteur compris), sa clé est TENUE en
    # mémoire le temps de la session : « Mon coffre » ne demande plus de phrase.
    # La MK reste exigée : un compartiment de personne demande la box ouverte ET
    # la personne. Un invité n'ouvre jamais la clé maîtresse.
    def _perso_preparer(self, personne: str, mot_de_passe: str) -> Optional[dict]:
        """La clé de la personne, déballée par SA serrure « compte » — ou None.
        Coffre ouvert et personne sans aucune serrure : son compartiment naît."""
        self._verifie_personne(personne)
        if not mot_de_passe:
            return None
        with self._verrou:
            if not self.initialise:
                return None
            for essai in (0, 1):
                with self._cx() as cx:
                    lignes = cx.execute("SELECT id, sel, params, nonce, cle FROM serrures_personnelles "
                                        "WHERE personne=? AND genre='compte'", (personne,)).fetchall()
                    aucune = not cx.execute("SELECT 1 FROM serrures_personnelles WHERE personne=?",
                                            (personne,)).fetchone()
                for ident, sel, params, nonce, emballee in lignes:
                    try:
                        pk = dechiffrer(derive_kek(mot_de_passe.encode(), sel, json.loads(params)), nonce, emballee,
                                        aad_serrure_personnelle(ident, personne))
                    except Refus:
                        continue
                    cle = CleVerrouillee(pk)
                    del pk
                    return {"personne": personne, "pk": cle}
                if essai == 0 and aucune and self._mk:
                    self.personne_initialiser(personne, mot_de_passe, "connexion", genre="compte")
                    continue
                return None
        return None

    def personne_compte_preparer(self, personne: str, utilisateur: str, mot_de_passe: str) -> Optional[str]:
        """Connexion d'un utilisateur ordinaire (ou invité avec compte) : rend un
        ticket, ou None si rien à ouvrir pour lui. Rien n'est ouvert ici."""
        if not isinstance(utilisateur, str) or not COMPTE_RE.match(utilisateur):
            raise Interdit("compte invalide")
        with self._verrou:
            self._purge_attente()
            self._expire()
            pend = self._perso_preparer(personne, mot_de_passe)
            if pend is None:
                self.journal.ajouter("personne_sans_serrure_compte", qui=utilisateur)
                return None
            ticket = "p." + secrets.token_urlsafe(32)
            self._attente[ticket] = {"utilisateur": utilisateur, "fin": self._horloge() + ATTENTE_S,
                                     "mk": None, "ligne": None, "perso": pend, "seulement_perso": True}
            return ticket

    def _perso_installer(self, pend: dict, origine: str = "") -> None:
        with self._verrou:
            ancien = self._perso_ouvertes.pop(pend["personne"], None)
            if ancien:
                ancien["pk"].effacer()
            self._perso_ouvertes[pend["personne"]] = {"pk": pend["pk"], "dernier": self._horloge()}
            self.journal.ajouter("personne_ouverte", personne=pend["personne"], genre="compte", origine=origine)

    def _pk_session(self, personne: str, toucher: bool = True) -> Optional[bytes]:
        """La clé tenue pour cette personne, ou None (jamais ouverte, expirée,
        Coffre scellé). Inactive plus longtemps que le Coffre : oubliée."""
        with self._verrou:
            v = self._perso_ouvertes.get(personne)
            if not v:
                return None
            if self._horloge() - v["dernier"] > self.delai_s or not self._mk:
                v["pk"].effacer()
                del self._perso_ouvertes[personne]
                self.journal.ajouter("personne_fermee", personne=personne, raison="inactivite")
                return None
            if toucher:
                v["dernier"] = self._horloge()
                return v["pk"].octets()
            return b""

    def personne_fermer(self, personne: str) -> None:
        """Déconnexion : la clé de la personne est oubliée."""
        with self._verrou:
            v = self._perso_ouvertes.pop(personne, None)
            if v:
                v["pk"].effacer()
                self.journal.ajouter("personne_fermee", personne=personne, raison="deconnexion")

    def personne_ajouter_compte(self, personne: str, ouverture: dict, mot_de_passe: str, libelle: str = "") -> str:
        """Relier le mot de passe de connexion à la personne (remplace le précédent).
        L'appelant a vérifié ce mot de passe contre le compte de la session."""
        self._verifie_personne(personne)
        if not isinstance(mot_de_passe, str) or not mot_de_passe:
            raise Interdit("mot de passe absent")
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                pk = self._cle_personne(cx, personne, ouverture, "serrure_ajoutee")
                cx.execute("DELETE FROM serrures_personnelles WHERE personne=? AND genre='compte'", (personne,))
                ident = self._emballe_personne(cx, personne, "compte", mot_de_passe.encode(), pk,
                                               libelle or "connexion")
            del pk
            self.journal.ajouter("personne_serrure_ajoutee", personne=personne, serrure=ident, genre="compte")
            return ident

    def personne_compte_changer(self, personne: str, ancien: str, nouveau: str) -> bool:
        """Le mot de passe de connexion change : la serrure « compte » est
        réemballée. Sans l'ancien (réinitialisation), elle devient caduque."""
        self._verifie_personne(personne)
        if not ancien or not nouveau:
            return False
        with self._verrou:
            if not self.initialise:
                return False
            with self._cx() as cx:
                for ident, sel, params, nonce, emballee in cx.execute(
                        "SELECT id, sel, params, nonce, cle FROM serrures_personnelles "
                        "WHERE personne=? AND genre='compte'", (personne,)).fetchall():
                    try:
                        pk = dechiffrer(derive_kek(ancien.encode(), sel, json.loads(params)), nonce, emballee,
                                        aad_serrure_personnelle(ident, personne))
                    except Refus:
                        continue
                    cx.execute("DELETE FROM serrures_personnelles WHERE id=?", (ident,))
                    self._emballe_personne(cx, personne, "compte", nouveau.encode(), pk, "connexion")
                    del pk
                    self.journal.ajouter("personne_serrure_renouvelee", personne=personne, genre="compte")
                    return True
            return False

    def personne_ajouter_phrase(self, personne: str, ouverture: dict, phrase: str, libelle: str = "") -> str:
        self._verifie_personne(personne)
        self._verifie_phrase(phrase)
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                pk = self._cle_personne(cx, personne, ouverture, "serrure_ajoutee")
                ident = self._emballe_personne(cx, personne, "phrase", phrase.encode(), pk, libelle)
            del pk
            self.journal.ajouter("personne_serrure_ajoutee", personne=personne, serrure=ident, genre="phrase")
            return ident

    def personne_ajouter_appareil(self, personne: str, ouverture: dict, cred_id: str, sel: bytes, prf: bytes,
                                  libelle: str = "") -> str:
        self._verifie_personne(personne)
        if not isinstance(cred_id, str) or not CRED_ID_RE.match(cred_id):
            raise Interdit("identifiant de clé d'appareil invalide")
        if len(sel) != TAILLE_CLE or len(prf) != TAILLE_CLE:
            raise Interdit("sel et sortie PRF de 32 octets attendus")
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                if cx.execute("SELECT 1 FROM serrures_personnelles WHERE personne=? AND cred_id=?",
                              (personne, cred_id)).fetchone():
                    raise Interdit("cette clé d'appareil est déjà une de vos serrures")
                pk = self._cle_personne(cx, personne, ouverture, "serrure_ajoutee")
                ident = self._emballe_personne(cx, personne, "appareil", prf, pk, libelle, sel=sel, cred_id=cred_id)
            del pk
            self.journal.ajouter("personne_serrure_ajoutee", personne=personne, serrure=ident, genre="appareil")
            return ident

    def personne_retirer_serrure(self, personne: str, ouverture: dict, ident: str) -> None:
        self._verifie_personne(personne)
        with self._verrou:
            self._mk_ou_scelle()
            with self._cx() as cx:
                self._cle_personne(cx, personne, ouverture, "serrure_retiree")
                if not cx.execute("SELECT 1 FROM serrures_personnelles WHERE id=? AND personne=?",
                                  (ident, personne)).fetchone():
                    raise Interdit("serrure inconnue")
                if cx.execute("SELECT COUNT(*) FROM serrures_personnelles WHERE personne=?",
                              (personne,)).fetchone()[0] <= 1:
                    raise Interdit("dernière serrure : votre compartiment ne s'ouvrirait plus")
                cx.execute("DELETE FROM serrures_personnelles WHERE id=? AND personne=?", (ident, personne))
            self.journal.ajouter("personne_serrure_retiree", personne=personne, serrure=ident)

    def _cle_perso(self, cx, mk: bytes, personne: str, ouverture: dict, action: str) -> bytes:
        comp = "p-" + personne
        pk = self._cle_personne(cx, personne, ouverture, action)
        try:
            return cle_compartiment_personnel(mk, comp, pk)
        finally:
            del pk

    def personne_poser(self, personne: str, ouverture: dict, nom: str, valeur: bytes) -> int:
        comp = self._verifie_personne(personne)
        self._verifie_place(comp, nom)
        if not isinstance(valeur, (bytes, bytearray)) or len(valeur) > VALEUR_MAX:
            raise Interdit(f"valeur absente ou trop grande ({VALEUR_MAX} octets au plus)")
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                cle = self._cle_perso(cx, mk, personne, ouverture, "secret_pose")
                ancien = cx.execute("SELECT version FROM secrets WHERE compartiment=? AND nom=?",
                                    (comp, nom)).fetchone()
                version = (ancien[0] + 1) if ancien else 1
                nonce, chiffre = chiffrer(cle, bytes(valeur), aad_secret(comp, nom, version))
                cx.execute("INSERT OR REPLACE INTO secrets VALUES (?,?,?,?,?,?)",
                           (comp, nom, version, nonce, chiffre, int(time.time())))
            self.journal.ajouter("personne_secret_pose", personne=personne, nom=nom, version=version)
            return version

    def personne_lire(self, personne: str, ouverture: dict, nom: str) -> bytes:
        comp = self._verifie_personne(personne)
        self._verifie_place(comp, nom)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                cle = self._cle_perso(cx, mk, personne, ouverture, "secret_lu")
                ligne = cx.execute("SELECT version, nonce, valeur FROM secrets WHERE compartiment=? AND nom=?",
                                   (comp, nom)).fetchone()
            if not ligne:
                raise KeyError(nom)
            version, nonce, chiffre = ligne
            valeur = dechiffrer(cle, nonce, chiffre, aad_secret(comp, nom, version))
            self.journal.ajouter("personne_secret_lu", personne=personne, nom=nom, version=version)
            return valeur

    def personne_retirer(self, personne: str, ouverture: dict, nom: str) -> None:
        comp = self._verifie_personne(personne)
        self._verifie_place(comp, nom)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                self._cle_perso(cx, mk, personne, ouverture, "secret_retire")
                fait = cx.execute("DELETE FROM secrets WHERE compartiment=? AND nom=?", (comp, nom)).rowcount
            if not fait:
                raise KeyError(nom)
            self.journal.ajouter("personne_secret_retire", personne=personne, nom=nom)

    def personne_lister(self, personne: str, ouverture: dict) -> list:
        comp = self._verifie_personne(personne)
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                self._cle_perso(cx, mk, personne, ouverture, "secrets_listes")
                return [{"nom": n, "version": v, "modifie": m} for n, v, m in cx.execute(
                    "SELECT nom, version, modifie FROM secrets WHERE compartiment=? ORDER BY nom", (comp,))]

    def personne_openpgp_creer(self, personne: str, ouverture: dict, nom: str, courriel: str) -> dict:
        """Une clé OpenPGP pour la personne, rangée dans SON compartiment
        (`openpgp-secrete`, `openpgp-publique`). Rend l'empreinte et la clé
        PUBLIQUE ; la secrète se relit avec la serrure, comme tout secret."""
        from . import openpgp_perso
        comp = self._verifie_personne(personne)
        try:
            openpgp_perso.verifie_uid(nom, courriel)
        except ValueError as e:
            raise Interdit(str(e)) from None
        with self._verrou:
            mk = self._mk_ou_scelle()
            with self._cx() as cx:
                cle = self._cle_perso(cx, mk, personne, ouverture, "openpgp_cree")
                if cx.execute("SELECT 1 FROM secrets WHERE compartiment=? AND nom='openpgp-secrete'",
                              (comp,)).fetchone():
                    raise Interdit("vous avez déjà une clé OpenPGP dans votre coffre")
                try:
                    k = openpgp_perso.generer(nom, courriel)
                except openpgp_perso.ErreurOpenPGP as e:
                    raise Interdit(str(e)) from None
                maintenant = int(time.time())
                for nom_secret, valeur in (("openpgp-secrete", k["secrete"]), ("openpgp-publique", k["publique"])):
                    nonce, chiffre = chiffrer(cle, valeur.encode(), aad_secret(comp, nom_secret, 1))
                    cx.execute("INSERT INTO secrets VALUES (?,?,?,?,?,?)",
                               (comp, nom_secret, 1, nonce, chiffre, maintenant))
            self.journal.ajouter("personne_openpgp_cree", personne=personne, empreinte=k["empreinte"])
            return {"empreinte": k["empreinte"], "uid": k["uid"], "publique": k["publique"]}

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
                sortie["serrures"] = [{"id": i, "genre": g, "libelle": l, "creee": c, **({"compte": u} if u else {})}
                                      for i, g, l, c, u in cx.execute(
                                          "SELECT id, genre, libelle, creee, compte FROM serrures ORDER BY creee, id")]
                sortie["compartiments"] = [
                    {"id": i, "nature": n, "libelle": l, "secrets": s} for i, n, l, s in cx.execute(
                        "SELECT c.id, c.nature, c.libelle, COUNT(s.nom) FROM compartiments c "
                        "LEFT JOIN secrets s ON s.compartiment = c.id GROUP BY c.id ORDER BY c.id")]
        sortie["recouvrement"] = self.recouvrement_etat()
        return sortie
