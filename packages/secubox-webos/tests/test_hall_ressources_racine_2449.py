# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2449 — le Hall sous /hall/ (adresse IP, live) : chaque ressource en chemin absolu doit avoir sa route nginx vers le dossier du Hall."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
HALL = (RACINE / "www/hall/index.html").read_text(encoding="utf-8")
CONF = (RACINE / "nginx/webos.conf").read_text(encoding="utf-8")


def _absolus():
    """Fichiers statiques que index.html demande à la racine (hors /api/, /i/, ancres et liens de navigation)."""
    refs = set(re.findall(r'(?:src|url)\(?=?["\'(]?(/(?:fonts|medaillons)/[^"\')\s]+|/[A-Za-z0-9_-]+\.(?:js|svg))', HALL))
    return {r for r in refs if not r.startswith("/api/")}


def test_les_ressources_absolues_du_hall_existent_dans_son_dossier():
    refs = _absolus()
    assert {"/domaine.js", "/lexie.js", "/hall-logo.svg"} <= refs and any(r.startswith("/fonts/") for r in refs) and any(r.startswith("/medaillons/") for r in refs)
    for r in refs:
        assert (RACINE / "www/hall" / r.lstrip("/")).is_file(), r


def test_chaque_ressource_absolue_a_sa_route_vers_le_dossier_du_hall():
    for r in _absolus():
        if r.startswith(("/fonts/", "/medaillons/")):
            assert re.search(r"location \^~ %s\s*\{ try_files \$uri /hall\$uri =404; \}" % re.escape(r.rsplit("/", 1)[0] + "/"), CONF), r
        else:
            assert re.search(r"location = %s\s*\{ try_files \$uri /hall%s =404; \}" % (re.escape(r), re.escape(r)), CONF), r
