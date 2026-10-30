# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: p2p :: projection PUBLIQUE des pairs enrôlés (#3126, pilotage)

Le contrôleur du pilotage (compte secubox-pilotage) identifie une box par son adresse de maillage. `/var/lib/secubox/p2p` est 0700 secubox
(jetons de jonction, #2475) : il ne peut pas lire `peers.json`, et ne doit pas. p2p publie donc, à chaque écriture de `peers.json`,
`/var/lib/secubox/p2p-public/pairs-enroles.json` (0644, dossier 0755 secubox créé par le postinst) : pour chaque pair ENRÔLÉ (empreinte et
mode de jonction présents) son nom, son adresse de maillage, son empreinte et son mode de jonction. Aucun secret, aucune clé, aucune adresse
LAN, aucune découverte mDNS non authentifiée. Écriture par descripteur : dossier ouvert sans suivre de lien et vérifié (propriétaire root ou
le compte courant, aucun droit d'écriture groupe/autres), temporaire O_EXCL|O_NOFOLLOW, renommage atomique.

Sans dépendance hors bibliothèque standard : le postinst l'exécute (`python3 -I … pairs_enroles.py`) pour republier depuis peers.json.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

NOM = "pairs-enroles.json"
DOSSIER_DEFAUT = Path("/var/lib/secubox/p2p-public")
PEERS_DEFAUT = Path("/var/lib/secubox/p2p/peers.json")
VERSION = 1
TAILLE_MAX = 1 << 20
CHAMPS = ("name", "mesh_ip", "fingerprint", "joined_via")


class ProjectionErreur(Exception):
    """Dossier refusé (absent, lien, mauvais propriétaire, inscriptible par d'autres) ou écriture impossible."""


def projection(doc) -> dict:
    """{"version", "pairs"} : pairs enrôlés seulement, champs de CHAMPS seulement, tous chaînes non vides."""
    liste = doc.get("peers") if isinstance(doc, dict) else doc
    pairs = []
    if isinstance(liste, list):
        for p in liste:
            if not isinstance(p, dict):
                continue
            if all(isinstance(p.get(c), str) and p.get(c).strip() for c in CHAMPS):
                pairs.append({c: p[c] for c in CHAMPS})
    return {"version": VERSION, "pairs": pairs}


def _ouvrir_dossier(dossier: Path) -> int:
    try:
        fd = os.open(dossier, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise ProjectionErreur(f"dossier {dossier} refusé ({e.strerror})") from e
    st = os.fstat(fd)
    if st.st_uid not in {0, os.geteuid()} or st.st_mode & 0o022:
        os.close(fd)
        raise ProjectionErreur(f"dossier {dossier} refusé (propriétaire ou droits d'écriture inattendus)")
    return fd


def publier(doc, dossier: Path = DOSSIER_DEFAUT) -> Path:
    """Pose `pairs-enroles.json` (0644) dans `dossier` par renommage atomique ; un lien à sa place est remplacé, jamais suivi."""
    donnees = (json.dumps(projection(doc), ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    dfd = _ouvrir_dossier(Path(dossier))
    tmp = f".{NOM}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    try:
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
            with os.fdopen(fd, "wb") as f:
                os.fchmod(f.fileno(), 0o644)  # indépendant de l'umask
                f.write(donnees)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, NOM, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        except OSError as e:
            raise ProjectionErreur(f"écriture de {NOM} impossible ({e.strerror})") from e
        finally:
            try:
                os.unlink(tmp, dir_fd=dfd)  # sans effet si le renommage a réussi
            except OSError:
                pass
    finally:
        os.close(dfd)
    return Path(dossier) / NOM


def lire_peers(chemin: Path):
    """Document de peers.json (sans suivre de lien, borné) ; absent → aucun pair ; illisible ou invalide → ProjectionErreur
    (on ne publie jamais une projection vide à la place d'un registre qu'on n'a pas su lire)."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return {"peers": []}
    except OSError as e:
        raise ProjectionErreur(f"{chemin} illisible ({e.strerror})") from e
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ProjectionErreur(f"{chemin} n'est pas un fichier ordinaire")
        brut = os.read(fd, TAILLE_MAX + 1)
    finally:
        os.close(fd)
    if len(brut) > TAILLE_MAX:
        raise ProjectionErreur(f"{chemin} trop gros")
    try:
        return json.loads(brut or b'{"peers": []}')
    except ValueError as e:
        raise ProjectionErreur(f"{chemin} invalide") from e


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="republie la projection des pairs enrôlés pour le pilotage")
    ap.add_argument("--peers", type=Path, default=PEERS_DEFAUT)
    ap.add_argument("--dossier", type=Path, default=DOSSIER_DEFAUT)
    a = ap.parse_args(argv)
    try:
        publier(lire_peers(a.peers), a.dossier)
    except ProjectionErreur as e:
        print(f"pairs-enroles : {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
