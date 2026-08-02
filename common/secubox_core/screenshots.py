# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: screenshots — cycle de vie des vignettes capturées

Ce module ignore tout de chromium et du protocole CDP (voir `shotter.py` pour
ça) : il ne parle que de fichiers — un PNG et son fichier de métadonnées JSON
associé, par clé, sous un répertoire racine fourni par l'appelant. Il se
teste donc entièrement sans navigateur.

Deux appelants distincts partagent cette bibliothèque :
- secubox-streamlit : `fingerprint` = mtime + taille du script source.
- secubox-metablogizer : `fingerprint` = date de publication du site.

`fingerprint` est une chaîne opaque : ce module ne l'interprète jamais, il se
contente de la comparer à la valeur enregistrée lors de la dernière capture
réussie pour décider si une nouvelle capture est nécessaire (`is_stale`).

Deux règles impératives gouvernent `record()` :

1. Une capture en échec (`ok=False`) ne touche JAMAIS le PNG existant. Perdre
   une vignette valide parce qu'une capture a raté serait pire que d'afficher
   une vue ancienne — seul le fichier de métadonnées est mis à jour pour
   refléter l'échec (et permettre une nouvelle tentative via `is_stale`).
2. L'écriture du PNG (quand `ok=True`) et celle des métadonnées sont toutes
   deux atomiques : fichier temporaire dans le même répertoire, `flush` +
   `fsync`, puis `os.replace()`. Un lecteur concurrent ne voit jamais un
   fichier à moitié écrit — soit l'ancienne version complète, soit la
   nouvelle version complète.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PNG_NAME = "screenshot.png"
META_NAME = "screenshot.json"

# Mode explicite appliqué au PNG et aux métadonnées avant remplacement.
# `tempfile.mkstemp()` crée toujours son fichier temporaire en 0600 (il
# ignore délibérément l'umask, pensé pour un fichier que seul son auteur
# lit) : sans ce chmod, ce 0600 aurait survécu jusqu'au fichier final.
# Vérifié sur la board : les vignettes étaient `-rw------- secubox secubox` —
# sans conséquence tant que producteur et lecteur sont le même utilisateur,
# mais le producteur Streamlit prévu tourne en root (timer) alors que le
# lecteur (l'agrégateur) tourne en secubox. 0o644 reste réduit par l'umask du
# processus, comme n'importe quelle création de fichier normale.
_DEFAULT_FILE_MODE = 0o644


def _safe_key(key: str) -> str:
    """Rejette une clé qui échapperait à son répertoire (`../`, séparateur de
    chemin...). Défense en profondeur : `key` provient typiquement d'un nom
    d'appli ou de site, potentiellement dérivé d'une entrée externe."""
    if not key or key in (".", "..") or "/" in key or "\\" in key:
        raise ValueError(f"clé de vignette invalide : {key!r}")
    return key


def _app_dir(base_dir, key: str) -> Path:
    return Path(base_dir) / _safe_key(key)


def png_path(base_dir, key: str) -> Path:
    """Chemin du PNG le plus récemment capturé avec succès pour `key`."""
    return _app_dir(base_dir, key) / PNG_NAME


def meta_path(base_dir, key: str) -> Path:
    """Chemin du fichier de métadonnées JSON pour `key`."""
    return _app_dir(base_dir, key) / META_NAME


def read_meta(base_dir, key: str) -> dict:
    """Renvoie les métadonnées enregistrées pour `key`, ou `{}` si absentes,
    illisibles, ou d'une forme inattendue. Fail-empty : jamais d'exception —
    un appelant qui vient de vérifier `is_stale` ne doit pas se faire
    surprendre par un fichier disparu entre-temps ou corrompu."""
    try:
        data = json.loads(meta_path(base_dir, key).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def is_stale(base_dir, key: str, fingerprint: str) -> bool:
    """Une capture est nécessaire quand :
    - aucune métadonnée n'existe encore (jamais capturé) ;
    - la dernière tentative a échoué (`ok` faux — on retente au prochain
      passage, indépendamment du fingerprint) ;
    - le fingerprint enregistré diffère de celui fourni (la source a changé
      depuis la dernière capture réussie).

    `fingerprint` est une chaîne opaque : cette fonction ne fait que la
    comparer, jamais ne l'interprète."""
    meta = read_meta(base_dir, key)
    if not meta:
        return True
    if not meta.get("ok"):
        return True
    return meta.get("fingerprint") != fingerprint


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Écrit `data` dans `path` de façon atomique : fichier temporaire dans
    le même répertoire (pour que `os.replace()` reste sur le même système de
    fichiers, condition de son atomicité), `flush` + `fsync`, puis
    remplacement. En cas d'échec en cours d'écriture, le fichier temporaire
    est nettoyé et `path` n'est jamais touché — l'ancienne version (ou son
    absence) reste seule visible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        # mkstemp() always creates in 0600, ignoring the process umask by
        # design. Restore a normal, readable mode (still capped by the
        # umask, same as any regular file creation) before it becomes
        # visible under its final name.
        umask = os.umask(0)
        os.umask(umask)
        os.fchmod(fd, _DEFAULT_FILE_MODE & ~umask)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp_name)
        raise


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record(base_dir, key: str, png: bytes | None, fingerprint: str,
           ok: bool) -> dict:
    """Enregistre le résultat d'une tentative de capture pour `key`.

    Si `ok` est vrai, `png` est écrit atomiquement et devient la nouvelle
    vignette servie. Si `ok` est faux, `png` est ignoré quelle que soit sa
    valeur — le PNG déjà présent (s'il existe) n'est jamais touché, voir la
    règle 1 de la docstring du module. Dans les deux cas, le fichier de
    métadonnées est écrit atomiquement avec `captured_at` (horodatage
    RFC 3339, UTC), `fingerprint` et `ok` — y compris sur un échec, pour que
    `is_stale` sache qu'une nouvelle tentative est due.

    Renvoie les métadonnées écrites.
    """
    if ok:
        _atomic_write_bytes(png_path(base_dir, key), png or b"")
    meta = {
        "captured_at": _now_iso(),
        "fingerprint": fingerprint,
        "ok": bool(ok),
    }
    _atomic_write_bytes(meta_path(base_dir, key),
                        json.dumps(meta, indent=2).encode("utf-8"))
    return meta
