# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Fichiers d'état partagés entre l'API, le démon et le contrôleur root : `config.json` (écrit ici), `resultat.json`, `carte.json`, `connus.json` (lus),
`appliquer.demande` (déposée ici, consommée par l'unité root). Tout est lu de façon tolérante, écrit de façon atomique."""
import contextlib
import json
import os
import tempfile
import time
from pathlib import Path

from . import profils

MAX_JSON = 1024 * 1024


def lire_json(chemin, maxi: int = MAX_JSON):
    """Contenu JSON d'un fichier d'état, ou None (absent, énorme, illisible). Jamais d'exception."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(maxi + 1)
        if len(brut) > maxi:
            return None
        return json.loads(brut.decode("utf-8"))
    except (OSError, ValueError, RecursionError):                       # un JSON très imbriqué n'est pas une exception brute
        return None


def lire_config(etat, categories) -> dict:
    """La configuration enregistrée, validée ; `profils.vide` si aucune n'a encore été écrite. Une configuration corrompue lève ErreurProfils."""
    f = Path(etat) / "config.json"
    if not f.exists():
        return profils.vide(categories)
    brut = lire_json(f)
    if brut is None:
        raise profils.ErreurProfils("config.json illisible")
    return profils.valider(brut, categories)


def ecrire_config(etat, cfg: dict) -> None:
    etat = Path(etat)
    fd, tmp = tempfile.mkstemp(dir=etat, prefix=".cfg-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, sort_keys=True)
            f.flush()
            os.fchmod(f.fileno(), 0o600)
            os.fsync(f.fileno())
        os.replace(tmp, etat / "config.json")
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def deposer(etat, nom: str, perimee_s: int = 600) -> bool:
    """Dépose une demande par création exclusive ; False si une demande récente existe déjà (une demande plus vieille que `perimee_s` est remplacée)."""
    f = Path(etat) / nom
    Path(etat).mkdir(parents=True, exist_ok=True)
    try:
        if time.time() - f.stat().st_mtime > perimee_s:
            f.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    try:
        os.close(os.open(f, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640))
    except FileExistsError:
        return False
    return True
