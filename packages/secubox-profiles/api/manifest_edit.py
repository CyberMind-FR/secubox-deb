# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — édition ciblée du niveau d'éveil dans un manifeste
CyberMind — https://cybermind.fr

Le panel /profiles/ ne peut fixer le « niveau d'éveil » (lifecycle + wake_class)
qu'en écrivant le manifeste `/etc/secubox/modules.d/<mod>.toml` (root:root) — via
le ctl root (webui→ctl). Cette édition remplace UNIQUEMENT les deux clés
scalaires de premier niveau `lifecycle` et `wake_class`, en préservant tout le
reste (commentaires, `id`, `units`, table `portal` inline, `priority`…).

Les manifestes sont générés par `scan` en tables INLINE (pas de sections
`[table]`) : les clés sont toutes de premier niveau, donc remplacer une ligne
`lifecycle = "…"` ou en ajouter une en fin de fichier reste un TOML valide.
Par sûreté on REFUSE d'éditer un manifeste qui contiendrait un en-tête de
section `[…]` (format non attendu — un ajout en fin de fichier tomberait alors
dans la mauvaise section). Écriture atomique (temp+rename), mode préservé.
"""
from __future__ import annotations

import os
import re
import stat
import tempfile
from pathlib import Path

from .manifest import LIFECYCLES, WAKE_CLASSES

_SECTION = re.compile(r"^\[")


def _key_line(stripped: str, key: str) -> bool:
    """Vrai si `stripped` (ligne sans commentaire, trimée) est l'affectation de
    premier niveau `key = …`."""
    return re.match(rf"^{re.escape(key)}\s*=", stripped) is not None


def _write_atomic(path: Path, text: str) -> None:
    path = Path(path)
    orig_mode = os.stat(path).st_mode
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".manifest-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, stat.S_IMODE(orig_mode))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def set_lifecycle(path: Path, *, lifecycle: str, wake_class: str) -> None:
    """Fixe `lifecycle` et `wake_class` dans le manifeste `path`, en place,
    préservant tout le reste. Lève ValueError sur valeur hors énum ou manifeste
    à sections."""
    if lifecycle not in LIFECYCLES:
        raise ValueError(f"lifecycle invalide: {lifecycle!r} (attendu {LIFECYCLES})")
    if wake_class not in WAKE_CLASSES:
        raise ValueError(f"wake_class invalide: {wake_class!r} (attendu {WAKE_CLASSES})")

    lines = Path(path).read_text(encoding="utf-8").splitlines()
    if any(_SECTION.match(ln.strip()) for ln in lines):
        raise ValueError(f"{path}: manifeste à sections [..] non supporté "
                         "(format inline attendu)")

    want = {"lifecycle": f'lifecycle = "{lifecycle}"',
            "wake_class": f'wake_class = "{wake_class}"'}
    seen = {"lifecycle": False, "wake_class": False}
    out: list[str] = []
    for ln in lines:
        stripped = ln.split("#", 1)[0].strip()
        matched = next((k for k in want if _key_line(stripped, k)), None)
        if matched is None:
            out.append(ln)
        elif not seen[matched]:
            out.append(want[matched])   # remplace la 1re occurrence, canonique
            seen[matched] = True
        # occurrence en double d'une clé gérée : on la laisse tomber (1 seule)
    for k in ("lifecycle", "wake_class"):
        if not seen[k]:
            out.append(want[k])         # absente : ajoutée en fin (headerless)
    _write_atomic(path, "\n".join(out) + "\n")
