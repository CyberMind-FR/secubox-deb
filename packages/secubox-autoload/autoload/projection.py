# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload :: projection PUBLIQUE des pairs (#3126, pilotage L1 « Voir »)

Le maître de pilotage a besoin de savoir à quel client appartient une box qui se connecte par `wg-autoload` : adresse tunnel → client, lot, série,
profil, abonnement. Ce fichier est écrit par root (autoloadctl exporter-pairs, appelé à la fin de tunnel-sync), lisible de tous (0644) :
il ne contient AUCUN secret — ni clé publique WireGuard, ni empreinte, ni valeur de jeton.

Pairs retenus : ceux de la table `pairs` NON retirés (`retire_le IS NULL`) dont la clé est liée à un jeton RÉCLAMÉ (`jetons.etat = 'reclame'`).
L'écriture est faite PAR DESCRIPTEUR : le dossier est ouvert sans suivre de lien et vérifié, le fichier temporaire y est créé en `O_EXCL|O_NOFOLLOW`,
puis posé par renommage atomique (un `pairs-publics.json` qui serait un lien est remplacé, jamais suivi).
"""
from __future__ import annotations

import json
import os
import pwd
import secrets
import sqlite3
import stat
from pathlib import Path

NOM = "pairs-publics.json"
VERSION = 1
UTILISATEUR_SERVICE = "secubox-autoload"

_REQUETE = (
    "SELECT p.adresse AS adresse, j.client AS client, j.lot AS lot, j.serie AS serie, j.profil AS profil, COALESCE(c.abonnement, 'actif') AS abonnement "
    "FROM pairs p JOIN jetons j ON j.cle_pub = p.cle_pub AND j.etat = 'reclame' LEFT JOIN clients c ON c.client = j.client "
    "WHERE p.retire_le IS NULL ORDER BY p.adresse"
)


class ProjectionErreur(Exception):
    """Le dossier de sortie est refusé (lien, mauvais propriétaire, inscriptible par d'autres) ou l'écriture a échoué."""


def lire_pairs(db: Path) -> list:
    """Lecture seule (`mode=ro`) ; base absente → liste vide : root ne crée jamais la base, elle appartient au service."""
    db = Path(db)
    if not db.exists():
        return []
    cx = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=15, isolation_level=None)
    cx.row_factory = sqlite3.Row
    try:
        return [{k: r[k] for k in ("adresse", "client", "lot", "serie", "profil", "abonnement")} for r in cx.execute(_REQUETE)]
    except sqlite3.OperationalError:                      # base présente mais tables pas encore créées par le service
        return []
    finally:
        cx.close()


def _uids_admis() -> set:
    admis = {0, os.geteuid()}
    try:
        admis.add(pwd.getpwnam(UTILISATEUR_SERVICE).pw_uid)
    except KeyError:
        pass
    return admis


def _ouvrir_dossier(dossier: Path) -> int:
    try:
        fd = os.open(dossier, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise ProjectionErreur(f"dossier {dossier} refusé ({e.strerror})") from e
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in _uids_admis() or st.st_mode & 0o022:
        os.close(fd)
        raise ProjectionErreur(f"dossier {dossier} refusé (propriétaire ou droits d'écriture inattendus)")
    return fd


def ecrire(dossier: Path, projection: dict) -> Path:
    """Pose `pairs-publics.json` (0644) dans `dossier` par renommage atomique, tout par descripteur de dossier."""
    donnees = (json.dumps(projection, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    dfd = _ouvrir_dossier(Path(dossier))
    tmp = f".{NOM}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    try:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
            os.fchmod(fd, 0o644)                          # indépendant de l'umask
            with os.fdopen(fd, "wb") as f:
                f.write(donnees)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, NOM, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        except OSError as e:
            raise ProjectionErreur(f"écriture de {NOM} impossible ({e.strerror})") from e
        finally:
            try:
                os.unlink(tmp, dir_fd=dfd)                 # no-op si le renommage a réussi
            except OSError:
                pass
    finally:
        os.close(dfd)
    return Path(dossier) / NOM


def exporter(db: Path, dossier: Path) -> Path:
    return ecrire(dossier, {"version": VERSION, "pairs": lire_pairs(db)})
