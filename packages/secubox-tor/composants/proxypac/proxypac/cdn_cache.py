# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.cdn_cache — hôtes CDN STATIQUES acceptés pour le cache de sbxmitm (#2804, cf. #2752).

La liste des hôtes acceptés (un par ligne) est lue à chaud par sbxmitm. Seuls les noms EXACTS de STATIQUES peuvent y entrer : jamais une API
(optimizationguide-pa, play.googleapis.com), jamais un sous-domaine, jamais cloudfront. STATIQUES est la copie de cdnStatiques (cdncache.go) ;
un test les compare."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

STATIQUES = frozenset({
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com", "ajax.aspnetcdn.com",
})


def _normal(hote: str) -> str:
    return (hote or "").strip().lower().rstrip(".")


def cacheable(hote: str) -> bool:
    return _normal(hote) in STATIQUES


def lire(fichier: Path) -> list:
    try:
        lignes = Path(fichier).read_text().splitlines()
    except OSError:
        return []
    return sorted({_normal(x) for x in lignes if x.strip() and not x.lstrip().startswith("#") and cacheable(x)})


def _ecrire(fichier: Path, hotes) -> None:
    fichier = Path(fichier)
    fichier.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=fichier.parent, prefix=".cdn-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("".join(h + "\n" for h in sorted(hotes)))
        os.chmod(tmp, 0o644)
        os.replace(tmp, fichier)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def ajouter(fichier: Path, hote: str) -> bool:
    """Ajoute l'hôte (idempotent) ; False, sans rien écrire, s'il n'est pas un CDN statique."""
    h = _normal(hote)
    if not cacheable(h):
        return False
    _ecrire(fichier, set(lire(fichier)) | {h})
    return True


def retirer(fichier: Path, hote: str) -> None:
    h = _normal(hote)
    _ecrire(fichier, set(lire(fichier)) - {h})
