# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2449 — le Hall sous /hall/ (adresse IP, live) : chaque ressource en chemin absolu doit avoir sa route nginx vers le dossier du Hall."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
HALL = (RACINE / "www/hall/index.html").read_text(encoding="utf-8")
CONF = (RACINE / "nginx/hall-racine.conf").read_text(encoding="utf-8")


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


def test_le_fragment_est_livre_a_routes_d_et_identique_a_webos_conf_2451():
    """Le vhost de l'adresse IP (webui.conf) n'inclut que secubox-routes.d ; les vhosts de domaine, secubox.d (webos.conf). Mêmes lignes dans les deux."""
    r = (RACINE / "debian/rules").read_text(encoding="utf-8")
    assert "etc/nginx/secubox-routes.d/hall-racine.conf" in r and "secubox.d/hall-racine.conf" not in r
    locs = lambda s: sorted(re.findall(r"^location [^\n]+$", s, re.M))
    webos = (RACINE / "nginx/webos.conf").read_text(encoding="utf-8")
    assert locs(CONF) == [l for l in locs(webos) if "/hall" in l or "/fonts/" in l or "/medaillons/" in l or "domaine" in l or "lexie" in l]
