# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.reach — per-vhost nginx reach snippet (pure + atomic)."""
import fnmatch
import os
import re
import time
from pathlib import Path

REACH_LEVELS = ("localhost", "lan", "wan")
LAN_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
MESH_CIDR = "10.10.0.0/24"
SNIPPET_DIR = Path(os.environ.get("EXPOSURE_SNIPPET_DIR", "/etc/nginx/snippets/exposure"))


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


def reach_snippet(reach: str, mesh: bool) -> str:
    """Build the nginx allow/deny block for a reach level (+ mesh CIDR).

    Matches $remote_addr — only effective with the global real_ip rewrite.
    wan → "" (public). localhost/lan → allow-list + terminal `deny all;`.
    """
    if reach not in REACH_LEVELS:
        raise ValueError(f"invalid reach: {reach!r}")
    if reach == "wan":
        return ""  # public; mesh adds nothing to an already-open gate
    lines = ["allow 127.0.0.1;"]
    if reach == "lan":
        lines += [f"allow {c};" for c in LAN_CIDRS]
    if mesh:
        lines.append(f"allow {MESH_CIDR};")
    lines.append("deny all;")
    return "\n".join(lines) + "\n"


def snippet_path(vhost: str) -> Path:
    return SNIPPET_DIR / f"{nom_du_filtre(vhost)}.conf"


def write_snippet(vhost: str, reach: str, mesh: bool) -> None:
    """Atomically write the vhost's exposure snippet (temp + os.replace)."""
    content = reach_snippet(reach, mesh)
    SNIPPET_DIR.mkdir(parents=True, exist_ok=True)
    nom = nom_du_filtre(vhost)
    dst = SNIPPET_DIR / f"{nom}.conf"
    tmp = SNIPPET_DIR / f"{nom}.conf.tmp"
    tmp.write_text(content)
    os.replace(tmp, dst)


def read_snippet_reach(vhost: str) -> dict:
    """Derive {reach, mesh} from the on-disk snippet. Missing/empty → wan."""
    p = snippet_path(vhost)
    try:
        content = p.read_text()
    except OSError:
        return {"reach": "wan", "mesh": False}
    mesh = MESH_CIDR in content
    if content.strip() == "":
        reach = "wan"
    elif any(c in content for c in LAN_CIDRS):
        reach = "lan"
    else:
        reach = "localhost"
    return {"reach": reach, "mesh": mesh}


def load_record(vhost: str, is_public_now: bool) -> dict:
    """Current exposure record for a vhost.

    If a snippet exists, derive from it. A missing snippet means ungated ==
    effectively public, so the current-effective report is 'wan' — matching
    read_snippet_reach and the vhost dashboard. Secure-by-default 'lan' is
    enforced at WRITE time (create-time seeding), not at read time.
    `is_public_now` is kept in the signature for API compatibility but no
    longer changes the missing-case result.
    """
    p = snippet_path(vhost)
    if p.exists():
        rr = read_snippet_reach(vhost)
        return {"vhost": vhost, "reach": rr["reach"], "mesh": rr["mesh"], "tor": False}
    return {"vhost": vhost, "reach": "wan", "mesh": False, "tor": False}
