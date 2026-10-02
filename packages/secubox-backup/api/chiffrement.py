# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: backup — chiffrement des sauvegardes par défaut (#1903)
CyberMind — https://cybermind.fr

Les archives de configuration embarquent /etc/secubox (secrets compris) et /var/lib/secubox.
Elles étaient écrites EN CLAIR (certaines en 0666, dans des dossiers en 0777) : toute copie
hors de la box — envoi distant, disque de sauvegarde, copie manuelle — révélait tout.

- chiffrement ACTIVÉ par défaut, avec la clé PUBLIQUE de la box (age `age1…` ou GPG) lue dans
  /etc/secubox/backup-encryption.json ; sans destinataire, la sauvegarde ÉCHOUE (on ne produit
  jamais une archive en clair par omission). Désactiver est un choix explicite, journalisé.
- échec du chiffrement = échec de la sauvegarde ET destruction de l'archive en clair.
- fichiers 0640, dossiers 0750.
La clé PRIVÉE (restauration) reste à root : /etc/secubox/secrets/backup-age.key, à copier
HORS de la box — une clé gardée sur le même disque ne protège que les copies qui en sortent.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

CONFIG = Path(os.environ.get("SECUBOX_BACKUP_ENC", "/etc/secubox/backup-encryption.json"))
CLE_PRIVEE = Path(os.environ.get("SECUBOX_BACKUP_KEY", "/etc/secubox/secrets/backup-age.key"))
MODE_FICHIER = 0o640
MODE_DOSSIER = 0o750


class ErreurChiffrement(RuntimeError):
    pass


def existe(chemin: Path) -> bool:
    """Path.exists() lève PermissionError si le dossier parent n'est pas traversable (l'API sans
    privilège face à /etc/secubox/secrets) : « illisible » se lit comme « absent »."""
    try:
        return chemin.exists()
    except OSError:
        return False


def destinataire() -> Optional[str]:
    """Le destinataire configuré (clé publique age `age1…` ou identifiant GPG), ou None."""
    try:
        d = json.loads(CONFIG.read_text())
    except (OSError, ValueError):
        return None
    r = d.get("recipient") if isinstance(d, dict) else None
    return r.strip() if isinstance(r, str) and r.strip() else None


def commande_chiffrer(src: Path, dest: Path, rec: str) -> list:
    if rec.startswith("age1"):
        return ["age", "-r", rec, "-o", str(dest), str(src)]
    return ["gpg", "--batch", "--yes", "--trust-model", "always", "--encrypt",
            "--recipient", rec, "--output", str(dest), str(src)]


def chiffrer(fichier: Path, rec: Optional[str] = None, run=subprocess.run) -> Path:
    """Chiffre `fichier` vers `<fichier>.age` ; l'archive en clair est détruite SEULEMENT si le
    chiffré existe et n'est pas vide. En cas d'échec, rien de clair ne reste. Lève
    ErreurChiffrement."""
    rec = rec or destinataire()
    if not rec:
        fichier.unlink(missing_ok=True)          # jamais d'archive en clair par omission
        raise ErreurChiffrement("aucun destinataire de chiffrement : `backupctl init-key`")
    dest = Path(str(fichier) + ".age")
    r = run(commande_chiffrer(fichier, dest, rec), capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not dest.exists() or dest.stat().st_size == 0:
        dest.unlink(missing_ok=True)
        fichier.unlink(missing_ok=True)          # échec = pas d'archive en clair qui traîne
        raise ErreurChiffrement("chiffrement refusé : " + (r.stderr or "")[:200])
    os.chmod(dest, MODE_FICHIER)
    fichier.unlink()
    return dest


def dechiffrer(fichier: Path, cle: Optional[str] = None, run=subprocess.run) -> Path:
    """Déchiffre un `.age` (age ou GPG) vers un fichier TEMPORAIRE privé (dossier 0700) ; root et
    la clé privée sont requis. L'appelant détruit le résultat avec `detruire_clair`.

    Jamais vers le nom d'origine : ce chemin peut désigner l'archive en clair d'avant le
    chiffrement, que la restauration puis le nettoyage auraient écrasée puis supprimée."""
    nom = str(fichier)
    rep = Path(tempfile.mkdtemp(prefix="sbx-restore-"))
    os.chmod(rep, 0o700)
    sortie = rep / (Path(nom[:-4] if nom.endswith(".age") else nom).name)
    ident = cle or (str(CLE_PRIVEE) if existe(CLE_PRIVEE) else None)
    if shutil.which("age") and ident:
        cmd = ["age", "-d", "-i", ident, "-o", str(sortie), nom]
    else:
        cmd = ["gpg", "--batch", "--yes", "--decrypt", "--output", str(sortie), nom]
    r = run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not sortie.exists():
        shutil.rmtree(rep, ignore_errors=True)
        raise ErreurChiffrement("déchiffrement refusé : " + (r.stderr or "")[:200])
    return sortie


def detruire_clair(sortie: Path) -> None:
    """Supprime un résultat de `dechiffrer` et son dossier temporaire privé."""
    shutil.rmtree(sortie.parent, ignore_errors=True)


def restreint(dossier: Path) -> int:
    """Dossier 0750 et fichiers directs 0640 (jamais récursif). Rend le nombre de modifications."""
    n = 0
    try:
        if (dossier.stat().st_mode & 0o777) != MODE_DOSSIER:
            os.chmod(dossier, MODE_DOSSIER); n += 1
        for f in dossier.iterdir():
            if f.is_file() and (f.stat().st_mode & 0o777) != MODE_FICHIER:
                os.chmod(f, MODE_FICHIER); n += 1
    except OSError:
        pass
    return n


def en_clair(dossier: Path) -> list:
    """Archives de sauvegarde NON chiffrées d'un dossier."""
    try:
        return sorted(f for f in dossier.iterdir() if f.is_file() and not f.name.endswith(".age")
                      and (f.name.endswith(".tar.gz") or f.name.endswith(".tar")))
    except OSError:
        return []
