# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Safe extraction of an uploaded static-site archive into a site docroot."""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path


class ContentError(Exception):
    """Raised when an upload is unsafe (zip-slip / absolute path)."""


def _safe_join(root: Path, member: str) -> Path:
    # Reject absolute paths and any member that escapes root once resolved.
    if member.startswith("/") or member.startswith("\\"):
        raise ContentError(f"absolute path in archive: {member}")
    target = (root / member).resolve()
    if root.resolve() not in (target, *target.parents):
        raise ContentError(f"path escapes docroot: {member}")
    return target


def _prefixe_enveloppe(noms: list[str]) -> str:
    """Rend le dossier enveloppe unique d'une archive, ou "" s'il n'y en a pas.

    POURQUOI CE DEBALLAGE (#1023). `zip -r site.zip site/` — la façon dont tout
    le monde fabrique une archive — produit des membres tous préfixés par
    `site/`. Recopiés tels quels, ils donnent `public/site/index.html` : le
    docroot est vide, `index_present` est faux, et la publication échoue sans
    que rien n'indique que le contenu est là, un cran trop bas.

    LA CONDITION EST STRICTE : un seul premier segment, et aucun fichier posé à
    la racine. Déballer une archive qui contient déjà `index.html` à côté d'un
    dossier `assets/` reviendrait à jeter l'index — on préfère alors ne rien
    faire, parce que l'archive est déjà à la bonne forme.

    ET SURTOUT : ON NE DEBALLE JAMAIS UN SEGMENT HOSTILE. Une première version
    acceptait `..` comme enveloppe. L'archive `{"../escape.html"}` — celle-là
    même que la garde zip-slip existe pour refuser — se voyait alors retirer son
    `../`, atterrissait sagement dans le docroot, et ne levait plus d'erreur.
    Assainir une attaque au lieu de la refuser, c'est perdre la trace de la
    tentative. On ne travaille donc que sur les noms LITTERAUX, sans les
    normaliser, et on rend "" au moindre doute : le nom d'origine repart alors
    vers `_safe_join`, dont c'est le métier de le rejeter.
    """
    premiers = set()
    for nom in noms:
        tete, sep, _ = nom.partition("/")
        if not sep or not tete:
            return ""  # un fichier à la racine : l'archive est déjà bien formée
        if tete in (".", "..") or "\\" in tete:
            return ""  # segment hostile : à la garde de trancher, pas à nous
        premiers.add(tete)
        if len(premiers) > 1:
            return ""
    return premiers.pop() + "/" if premiers else ""


def extract_archive(docroot: Path, data: bytes, filename: str) -> dict:
    docroot.mkdir(parents=True, exist_ok=True)
    name = (filename or "").lower()
    if name.endswith(".zip"):
        # Validate ALL members before writing anything.
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as e:
            raise ContentError(f"not a valid zip archive: {e}")
        with zf as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            # Le déballage se calcule AVANT _safe_join et ne l'affaiblit pas :
            # le préfixe retiré est un segment issu des noms eux-mêmes, et
            # chaque cible reste vérifiée contre le docroot.
            enveloppe = _prefixe_enveloppe([m.filename for m in members])
            noms = [m.filename.removeprefix(enveloppe) for m in members]
            targets = [_safe_join(docroot, n) for n in noms]
            # Clear previous content (a zip is a fresh publish; history is in gitea).
            for child in docroot.iterdir():
                if child.name == ".git":
                    continue
                shutil.rmtree(child) if child.is_dir() else child.unlink()
            total = 0
            for m, target in zip(members, targets):
                target.parent.mkdir(parents=True, exist_ok=True)
                blob = z.read(m)
                target.write_bytes(blob)
                total += len(blob)
        return {"files": len(members), "bytes": total,
                "enveloppe": enveloppe.rstrip("/"),
                "index_present": (docroot / "index.html").exists()}

    # Single file: an .html (or anything) becomes index.html unless it has a
    # concrete non-index basename we should preserve.
    if name.endswith(".html") or "." not in Path(name).name:
        dest = docroot / "index.html"
    else:
        dest = _safe_join(docroot, Path(name).name)
    dest.write_bytes(data)
    return {"files": 1, "bytes": len(data), "index_present": (docroot / "index.html").exists()}
