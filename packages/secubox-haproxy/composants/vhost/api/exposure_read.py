# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.exposure_read — derive a vhost's exposure from its snippet."""
import fnmatch
import os
import re
import time
from pathlib import Path

_SNIPPET_DIR = Path("/etc/nginx/snippets/exposure")
_LAN = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_MESH = "10.10.0.0/24"


# ── Nom du filtre d'exposition d'un vhost (#3117) ──────────────────────────
# La SOURCE DE VÉRITÉ est la ligne `include /etc/nginx/snippets/exposure/<n>.conf;`
# du fichier de vhost lui-même : un vhost livré sous un nom neutre
# (`metablogizer.*`) inclut `metablogizer.conf`, pas `<FQDN>.conf`. À défaut
# d'include, on retombe sur le nom du FQDN (comportement historique).
_RE_INCLUDE = re.compile(r"^\s*include\s+/etc/nginx/snippets/exposure/([A-Za-z0-9._-]+)\.conf\s*;", re.M)
_RE_SERVER_NAME = re.compile(r"^\s*server_name\s+([^;]+);", re.M)
_RE_SERVER = re.compile(r"\bserver\s*\{")
_SITES_DIRS_DEFAUT = ("/etc/nginx/sites-enabled", "/etc/nginx/sites-available")
_INDEX_TTL = 5.0
_index_cache = {"cle": None, "t": 0.0, "idx": []}


def _sans_commentaires(texte):
    return "\n".join(l.split("#", 1)[0] for l in texte.splitlines())


def _indexer(sites_dirs):
    idx = []
    for d in sites_dirs:
        try:
            fichiers = sorted(Path(d).iterdir())
        except OSError:
            continue
        for f in fichiers:
            try:
                if not f.is_file():
                    continue
                texte = _sans_commentaires(f.read_text(errors="replace"))
            except OSError:
                continue
            if "snippets/exposure/" not in texte:
                continue
            for bloc in _RE_SERVER.split(texte)[1:]:
                inc = _RE_INCLUDE.search(bloc)
                if not inc:
                    continue
                for m in _RE_SERVER_NAME.finditer(bloc):
                    for tok in m.group(1).split():
                        idx.append((tok.lower(), inc.group(1)))
    return idx


def nom_du_filtre(vhost, sites_dirs=None):
    """Nom (sans `.conf`) du filtre d'exposition de `vhost`.

    Un `server_name` exact l'emporte sur un joker (`metablogizer.*`)."""
    dirs = tuple(sites_dirs) if sites_dirs is not None else tuple(
        os.environ.get("EXPOSURE_SITES_DIRS", ":".join(_SITES_DIRS_DEFAUT)).split(":"))
    maintenant = time.monotonic()
    if _index_cache["cle"] != dirs or maintenant - _index_cache["t"] > _INDEX_TTL:
        _index_cache.update(cle=dirs, t=maintenant, idx=_indexer(dirs))
    nom = vhost.lower()
    for tok, snip in _index_cache["idx"]:
        if tok == nom:
            return snip
    for tok, snip in _index_cache["idx"]:
        if "*" in tok and fnmatch.fnmatchcase(nom, tok):
            return snip
    return vhost


def read_exposure(vhost: str, snippet_dir=None, sites_dirs=None) -> dict:
    d = Path(snippet_dir) if snippet_dir is not None else _SNIPPET_DIR
    try:
        content = (d / f"{nom_du_filtre(vhost, sites_dirs)}.conf").read_text()
    except OSError:
        return {"reach": "wan", "mesh": False}
    mesh = _MESH in content
    if content.strip() == "":
        reach = "wan"
    elif any(c in content for c in _LAN):
        reach = "lan"
    else:
        reach = "localhost"
    return {"reach": reach, "mesh": mesh}
