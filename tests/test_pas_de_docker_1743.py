# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""LXC uniquement : aucun paquet ne tire ni ne pilote docker/podman (PATTERNS.md Pattern 11, #1743)."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
ASSUMES = RACINE / "tests" / "docker-podman-assumes.txt"

EXEC = re.compile(
    r"""(\b(docker|podman|buildah)\s+(run|exec|ps|pull|build|compose|start|stop|rm|inspect|logs|image|container|cp|load|save|network|volume|create|kill|restart)\b"""
    r"""|docker-compose|which\(\s*["'](docker|podman)["']\s*\)|\[\s*["'](docker|podman|buildah)["']\s*,"""
    r"""|["']/usr/bin/(docker|podman)["']|ExecStart=[^\n]*\b(docker|podman)\b"""
    r"""|^\s*Depends:.*\b(docker\.io|docker-ce|podman|buildah)\b"""
    r"""|^\s*(Recommends|Suggests):.*\b(docker\.io|podman|buildah)\b)""", re.M)
IGNORE = re.compile(r"(/vendor/|node_modules|\.gopath|/tests/|\.md$|changelog|/debian/secubox-[a-z0-9-]+/|\.venv|\.deb$|\.png$)")


def _fichiers_en_cause() -> set:
    out = subprocess.run(["git", "ls-files", "packages", "scripts", "image"], cwd=RACINE,
                         capture_output=True, text=True).stdout.splitlines()
    res = set()
    for f in out:
        p = RACINE / f
        if IGNORE.search("/" + f) or not p.is_file():
            continue
        if EXEC.search(p.read_text(errors="ignore")):
            res.add(f)
    return res


def _assumes() -> dict:
    d = {}
    for l in ASSUMES.read_text().splitlines():
        if l.strip() and not l.startswith("#") and "|" in l:
            chemin, raison = l.split("|", 1)
            d[chemin.strip()] = raison.strip()
    return d


def test_aucun_nouveau_fichier_ne_tire_ni_ne_pilote_docker_ou_podman():
    nouveaux = sorted(_fichiers_en_cause() - set(_assumes()))
    assert not nouveaux, (
        "docker/podman interdits (LXC uniquement) — fichiers nouveaux : " + ", ".join(nouveaux)
        + ". Faire tourner le service dans un LXC, ou, si c'est un simple commentaire, l'inscrire "
        "(avec sa raison) dans tests/docker-podman-assumes.txt.")


def test_la_liste_des_assumes_ne_peut_que_retrecir():
    perimes = sorted(set(_assumes()) - _fichiers_en_cause())
    assert not perimes, ("lignes à retirer de tests/docker-podman-assumes.txt (le fichier n'est plus "
                         "concerné) : " + ", ".join(perimes))


def test_chaque_dette_a_une_raison():
    assert all(len(r) > 15 for r in _assumes().values())


def test_aucun_paquet_ne_depend_de_docker_ni_podman():
    # Les dettes restantes sont nommées ; tout autre Depends/Recommends/Suggests docker|podman échoue.
    for ctl in sorted((RACINE / "packages").glob("*/debian/control")):
        rel = str(ctl.relative_to(RACINE))
        if rel in _assumes():
            continue
        assert not re.search(r"^\s*(Pre-)?(Depends|Recommends|Suggests):.*\b(docker\.io|docker-ce|podman|buildah|crun)\b",
                             ctl.read_text(), re.M), rel
