# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde d'administration de toolbox (#1783).

uvicorn écoute sur 0.0.0.0:8088 : le LAN, les pairs du tunnel et kbin (par
sbxwaf) l'atteignent sans nginx. Une route d'administration n'est servie que
si la requête porte l'en-tête que nginx pose APRÈS auth_request sur
/auth/verify?exige=admin. Ces tests passent par l'application réelle.
"""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_toolbox import app as mod

pytestmark = pytest.mark.garde_reelle

JETON = "a" * 64
NGINX = Path(__file__).resolve().parents[1] / "nginx"


@pytest.fixture
def client(tmp_path, monkeypatch):
    j = tmp_path / "garde-admin.jeton"
    j.write_text(JETON + "\n")
    monkeypatch.setattr(mod, "GARDE_JETON", j)
    # Une route peut lever faute de configuration locale : c'est un 500,
    # pas un refus — ce qu'on regarde ici, c'est la garde.
    return TestClient(mod.app, raise_server_exceptions=False)


@pytest.mark.parametrize("chemin", [
    "/admin/clients", "/admin/config", "/admin/clients/abc/report",
    "/admin/sentinel/c2", "/admin//config",
    "/rlevel/peers", "/exit_country", "/vpn/clients", "/tor/bridges",
])
def test_sans_en_tete_refuse(client, chemin):
    r = client.get(chemin)
    assert r.status_code == 403, (chemin, r.status_code)


@pytest.mark.parametrize("hote", ["kbin.gk2.secubox.in", "192.168.1.200:8088", "10.99.0.1:8088"])
def test_kbin_lan_et_tunnel_refuses(client, hote):
    assert client.get("/admin/clients", headers={"Host": hote}).status_code == 403


def test_en_tete_faux_refuse(client):
    r = client.get("/admin/config", headers={"X-Sbx-Garde-Admin": "b" * 64})
    assert r.status_code == 403


def test_jeton_absent_ferme_meme_en_tete_vide(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "GARDE_JETON", tmp_path / "absent.jeton")
    c = TestClient(mod.app)
    assert c.get("/admin/config", headers={"X-Sbx-Garde-Admin": ""}).status_code == 403


def test_en_tete_de_nginx_admis(client):
    r = client.get("/admin/config", headers={"X-Sbx-Garde-Admin": JETON})
    assert r.status_code != 403


def test_listes_publiques_en_lecture_restent_ouvertes(client):
    r = client.get("/admin/filter-control/list", headers={"Host": "kbin.gk2.secubox.in"})
    assert r.status_code != 403
    # … mais pas en écriture.
    r = client.post("/admin/filter-control/add", headers={"Host": "kbin.gk2.secubox.in"},
                    json={"pattern": "x"})
    assert r.status_code == 403


def test_routes_publiques_intactes(client):
    assert client.get("/status").status_code != 403


# ── nginx : chaque route d'administration passe par la garde ───────────────
def _conf():
    return (NGINX / "toolbox.conf").read_text()


def test_snippet_authentifie_avant_de_poser_l_en_tete():
    s = (NGINX / "secubox-toolbox-admin.conf").read_text()
    assert s.index("auth_request /__sbx_toolbox_admin;") < s.index("include /etc/nginx/snippets/secubox-toolbox-garde")


def test_verify_exige_un_administrateur():
    assert "/api/v1/auth/auth/verify?exige=admin" in _conf()


def test_aucune_regex_apres_le_prefixe_toolbox():
    """`^~ /api/v1/toolbox/` arrête l'évaluation des expressions régulières."""
    assert not re.search(r"location\s+~", _conf())


def test_chaque_route_admin_de_l_application_est_gardee_dans_nginx():
    conf = _conf()
    assert "location ^~ /api/v1/toolbox/admin/ {\n    include /etc/nginx/snippets/secubox-toolbox-admin.conf;" in conf
    for route in mod.app.routes:
        chemin = getattr(route, "path", "")
        if mod._chemin_admin(chemin) and not chemin.startswith("/admin/"):
            bloc = re.search(r"location = /api/v1/toolbox%s \{([^}]*)\}" % re.escape(chemin), conf)
            assert bloc, f"route d'administration sans location nginx exacte : {chemin}"
            assert "secubox-toolbox-admin.conf" in bloc.group(1), chemin
