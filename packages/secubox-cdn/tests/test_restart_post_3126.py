# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (relecture de sécurité de L5, R-L5-10) : `restart` recharge nginx, c'est une ACTION, donc POST.

En GET, elle passait pour une lecture : un porteur délégué du pilotage en portée `lecture` (GET/HEAD seulement) ou
un simple lien suivi par le navigateur déclenchait le rechargement. La page appelle la route en POST."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def _methodes_de(chemin: str) -> set:
    source = (PKG / "api" / "main.py").read_text(encoding="utf-8")
    return {m.upper() for m in re.findall(rf'@(?:router|app)\.(get|post|put|patch|delete)\("{re.escape(chemin)}"', source)}


def test_restart_est_un_post():
    assert _methodes_de("/restart") == {"POST"}


def test_la_page_appelle_restart_en_post():
    page = (PKG / "www" / "luci-static" / "resources" / "view" / "cdn-cache" / "maintenance.js").read_text(encoding="utf-8")
    appels = re.findall(r"sbxFetch\('/api/v1/cdn/restart',\s*[^,]+,\s*'([A-Z]+)'\)", page)
    assert appels == ["POST"]


def test_preload_url_est_un_post():
    """Le serveur va chercher l'URL fournie (SSRF) : une action, jamais une lecture (#3126, R-L5-14)."""
    assert _methodes_de("/preload_url") == {"POST"}


def test_les_pages_appellent_preload_url_en_post():
    for f in ("view/cdn-cache/maintenance.js", "cdn-cache/api.js"):
        page = (PKG / "www" / "luci-static" / "resources" / f).read_text(encoding="utf-8")
        assert re.findall(r"sbxFetch\('/api/v1/cdn/preload_url',\s*[^,]+,\s*'([A-Z]+)'\)", page) == ["POST"], f


def test_clear_stats_est_un_post():
    """Remet les statistiques à zéro : une action (#3126, R-L5-16)."""
    assert _methodes_de("/clear_stats") == {"POST"}
    page = (PKG / "www" / "luci-static" / "resources" / "view" / "cdn-cache" / "maintenance.js").read_text(encoding="utf-8")
    assert re.findall(r"sbxFetch\('/api/v1/cdn/clear_stats',\s*[^,]+,\s*'([A-Z]+)'\)", page) == ["POST"]
