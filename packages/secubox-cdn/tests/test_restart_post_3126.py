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
