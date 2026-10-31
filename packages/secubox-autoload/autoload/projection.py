# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: projection PUBLIQUE des pairs (#3126, pilotage L1 « Voir »)

Le maître de pilotage a besoin de savoir à quel client appartient une box qui se connecte par `wg-autoload` : adresse tunnel → client, lot, série,
profil, abonnement (celui de la BOX depuis #3303, sinon celui du client). Ce fichier est écrit par root (autoloadctl exporter-pairs, appelé à la fin de tunnel-sync), lisible de tous (0644) :
il ne contient AUCUN secret — ni clé publique WireGuard, ni empreinte, ni valeur de jeton.

Pairs retenus : ceux de la table `pairs` NON retirés (`retire_le IS NULL`) dont la clé est liée à un jeton RÉCLAMÉ (`jetons.etat = 'reclame'`).
Le fichier vit dans `/var/lib/secubox/autoload-public/` (root:root 0755, créé par autoloadctl s'il manque) : le service autoload (qui possède
`/var/lib/secubox/autoload/`, 0750, avec la base) n'a aucune prise dessus. L'écriture est faite PAR DESCRIPTEUR : la racine puis le dossier sont ouverts
sans suivre de lien et vérifiés (propriétaire root, aucun droit d'écriture groupe/autres), le fichier temporaire y est créé en `O_EXCL|O_NOFOLLOW`,
puis posé par renommage atomique (un `pairs-publics.json` qui serait un lien est remplacé, jamais suivi). Pas de systemd-tmpfiles (« unsafe path transition »).
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path

from .jetons import etat_abonnement, lire_droits_cx

NOM = "pairs-publics.json"
NOM_DROITS = "droits-maillage.json"                  # #3305 : droits du maillage par pair, lus par l'annuaire du maître
DOSSIER_PUBLIC = "autoload-public"
VERSION = 1
DELAI_S = 15

_REQUETE = (
    "SELECT p.adresse AS adresse, j.client AS client, j.lot AS lot, j.serie AS serie, j.profil AS profil, "
    "COALESCE(b.statut, c.abonnement, 'actif') AS abonnement, CASE WHEN b.statut IS NULL THEN c.expire_le ELSE b.expire_le END AS abonnement_expire_le "
    "FROM pairs p JOIN jetons j ON j.cle_pub = p.cle_pub AND j.etat = 'reclame' LEFT JOIN clients c ON c.client = j.client "
    "LEFT JOIN abonnements_box b ON b.jeton_id = j.id "
    "WHERE p.retire_le IS NULL ORDER BY p.adresse"
)

_REQUETE_AVANT_3303 = (
    "SELECT p.adresse AS adresse, j.client AS client, j.lot AS lot, j.serie AS serie, j.profil AS profil, "
    "COALESCE(c.abonnement, 'actif') AS abonnement, c.expire_le AS abonnement_expire_le "
    "FROM pairs p JOIN jetons j ON j.cle_pub = p.cle_pub AND j.etat = 'reclame' LEFT JOIN clients c ON c.client = j.client "
    "WHERE p.retire_le IS NULL ORDER BY p.adresse"
)


class ProjectionErreur(Exception):
    """Le dossier de sortie est refusé (lien, mauvais propriétaire, inscriptible par d'autres) ou l'écriture a échoué."""


def dossier_public(db: Path) -> Path:
    """`/var/lib/secubox/autoload-public`, frère du dossier de la base (`/var/lib/secubox/autoload`)."""
    return Path(db).parent.parent / DOSSIER_PUBLIC


def lire_pairs(db: Path, maintenant: float = None) -> list:
    """Lecture seule (`mode=ro`) ; base absente → liste vide : root ne crée jamais la base, elle appartient au service.
    L'abonnement est l'état CALCULÉ de `Registre.lister` (échéance passée → `echu`)."""
    db = Path(db)
    if not db.exists():
        return []
    now = time.time() if maintenant is None else maintenant
    cx = None
    try:
        cx = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=DELAI_S, isolation_level=None)
        cx.row_factory = sqlite3.Row
        try:
            lignes = cx.execute(_REQUETE).fetchall()
        except sqlite3.OperationalError as e:
            if "abonnements_box" not in str(e):
                raise
            lignes = cx.execute(_REQUETE_AVANT_3303).fetchall()      # base pas encore migrée par le service : abonnement du client, comme avant
        return [{"adresse": r["adresse"], "client": r["client"], "lot": r["lot"], "serie": r["serie"], "profil": r["profil"],
                 "abonnement": etat_abonnement(r["abonnement"], r["abonnement_expire_le"], now)} for r in lignes]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):                     # base présente mais tables pas encore créées par le service : rien à publier
            return []
        raise ProjectionErreur(f"base illisible ({e})") from e      # verrouillée, etc. : on ne publie PAS une projection vide (#3011)
    except sqlite3.Error as e:                            # corrompue
        raise ProjectionErreur(f"base illisible ({e})") from e
    finally:
        if cx is not None:
            cx.close()


def _ouvrir(nom, dir_fd=None) -> int:
    return os.open(nom, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def _verifier(fd: int, nom, strict: bool) -> None:
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in {0, os.geteuid()} or (strict and st.st_mode & 0o022):
        raise ProjectionErreur(f"dossier {nom} refusé (propriétaire ou droits d'écriture inattendus)")


def _ouvrir_public(dossier: Path) -> int:
    """Ouvre `dossier` (créé en root:root 0755 s'il manque) sans jamais suivre de lien, après avoir vérifié sa racine."""
    dossier = Path(dossier)
    try:
        racine = _ouvrir(dossier.parent)
    except OSError as e:
        raise ProjectionErreur(f"dossier {dossier.parent} refusé ({e.strerror})") from e
    try:
        _verifier(racine, dossier.parent, strict=False)
        cree = False
        try:
            os.mkdir(dossier.name, 0o755, dir_fd=racine)
            cree = True
        except FileExistsError:
            pass
        fd = _ouvrir(dossier.name, racine)
        try:
            _verifier(fd, dossier, strict=True)
            if cree or stat.S_IMODE(os.fstat(fd).st_mode) != 0o755:
                os.fchmod(fd, 0o755)                      # indépendant de l'umask ; dossier existant trop fermé : root le possède, on le rouvre en lecture
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError as e:
        raise ProjectionErreur(f"dossier {dossier} refusé ({e.strerror})") from e
    finally:
        os.close(racine)


def ecrire(dossier: Path, projection: dict, nom: str = NOM) -> Path:
    """Pose `nom` (`pairs-publics.json` par défaut, 0644) dans `dossier` par renommage atomique, tout par descripteur de dossier."""
    donnees = (json.dumps(projection, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    dfd = _ouvrir_public(Path(dossier))
    tmp = f".{nom}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    try:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
            with os.fdopen(fd, "wb") as f:                # fdopen d'abord : le descripteur est fermé même si fchmod échoue
                os.fchmod(f.fileno(), 0o644)              # indépendant de l'umask
                f.write(donnees)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, nom, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        except OSError as e:
            raise ProjectionErreur(f"écriture de {nom} impossible ({e.strerror})") from e
        finally:
            try:
                os.unlink(tmp, dir_fd=dfd)                 # no-op si le renommage a réussi
            except OSError:
                pass
    finally:
        os.close(dfd)
    return Path(dossier) / nom


def exporter(db: Path, dossier: Path):
    """(chemin du fichier, nombre de pairs publiés) : une seule lecture de la base."""
    pairs = lire_pairs(db)
    return ecrire(dossier, {"version": VERSION, "pairs": pairs}), len(pairs)


def lire_droits(db: Path, maintenant: float = None) -> dict:
    """Droits du maillage (#3305), lecture seule. Base absente ou illisible : ProjectionErreur — on ne publie JAMAIS une politique vide
    par erreur (elle couperait tout le parc une fois la grâce passée)."""
    db = Path(db)
    if not db.exists():
        raise ProjectionErreur("base absente")
    try:
        cx = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=DELAI_S, isolation_level=None)
        cx.row_factory = sqlite3.Row
        return lire_droits_cx(cx, time.time() if maintenant is None else maintenant)
    except sqlite3.Error as e:
        raise ProjectionErreur(f"base illisible ({e})") from e


def exporter_droits(db: Path, dossier: Path):
    """(chemin de `droits-maillage.json`, nombre de pairs) : projection publique root 0644, sans secret."""
    d = lire_droits(db)
    return ecrire(dossier, {"version": VERSION, **d}, NOM_DROITS), len(d["pairs"])
