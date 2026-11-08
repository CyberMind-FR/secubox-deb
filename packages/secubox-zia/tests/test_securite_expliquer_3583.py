# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Blocages du WAF expliqués (#3583) : faits établis par le code, modèle sans autorité, routes réservées à l'admin."""
import asyncio
import os
from pathlib import Path

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[3] / "secubox.conf.example"]

import api.main as main  # noqa: E402
import httpx  # noqa: E402
from api import securite  # noqa: E402

ENTREE = {"client_ip": "203.0.113.7", "country": "NL", "count": 42, "categories": ["sqli", "scanner"],
          "max_severity": "high", "first_seen": "2026-11-08T01:00:00Z", "last_seen": "2026-11-08T02:00:00Z",
          "currently_banned": True,
          "latest_alert": {"method": "GET", "host": "billets.gk2.secubox.in", "path": "/login?id=1' OR '1'='1",
                           "user_agent": "sqlmap/1.8", "rule_id": "sqli-12", "secret_interne": "ne sort pas"}}


def test_faits_seulement_mesures():
    f = securite.faits(ENTREE)
    assert f["adresse"] == "203.0.113.7" and f["alertes"] == 42 and f["deja_bannie"] is True
    assert f["categories"] == ["scanner", "sqli"]
    assert "secret_interne" not in f["derniere_requete"]
    assert f["derniere_requete"]["user_agent"] == "sqlmap/1.8"


def test_consigne_sans_invention_et_proposition_a_valider():
    c = securite.consigne(securite.faits(ENTREE))
    assert "N'invente aucun fait" in c and "Proposition (à valider)" in c and "Ne prétends jamais avoir agi" in c
    assert "203.0.113.7" in c and "sqlmap" in c


def _appel(methode, chemin, **k):
    async def run():
        tr = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=tr, base_url="http://t") as c:
            return await c.request(methode, "/api/v1/zia" + chemin, **k)
    return asyncio.run(run())


def test_routes_reservees_a_l_administrateur():
    assert _appel("GET", "/securite/blocages").status_code in (401, 403)
    assert _appel("POST", "/securite/expliquer", json={"adresse": "203.0.113.7"}).status_code in (401, 403)
