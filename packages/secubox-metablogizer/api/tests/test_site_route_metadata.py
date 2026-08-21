# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""GET/PUT /site/{name} — métadonnées & édition (#1089).

Verrouille le contrat corrigé : GET renvoie désormais le site.json (titre,
aliases…), autrefois perdus ; PUT paramètre les détails, écrit atomiquement,
et REFUSE avant écriture un alias qui n'est pas un domaine.

    PYTHONPATH=api:../../common ../../.venv/bin/pytest api/tests/test_site_route_metadata.py -v
"""
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import importlib
    import main as m
    importlib.reload(m)

    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}

    sites = tmp_path / "sites"
    sites.mkdir(parents=True)
    monkeypatch.setattr(m, "SITES_ROOT", sites)
    monkeypatch.setattr(m, "NGINX_ENABLED_DIR", tmp_path / "enabled")
    (tmp_path / "enabled").mkdir()
    # Neutraliser l'invalidation de cache (déclenche un sous-processus).
    monkeypatch.setattr(m, "_invalidate_sites_cache", lambda: None)

    yield TestClient(m.app), sites, m
    m.app.dependency_overrides.clear()


def _seed(sites, name, doc):
    d = sites / name / "public"
    d.mkdir(parents=True)
    (d / "index.html").write_text("<h1>x</h1>")
    (sites / name / "site.json").write_text(json.dumps(doc))


def test_get_renvoie_les_metadonnees_du_site_json(client):
    c, sites, _m = client
    _seed(sites, "anibal-amiot", {
        "name": "anibal-amiot", "domain": "anibal-amiot.fr", "published": True,
        "title": "Livrée d Hermès",
        "aliases": ["www.anibal-amiot.fr", "anibal-amiot.com"],
    })

    r = c.get("/site/anibal-amiot")

    assert r.status_code == 200, r.text
    d = r.json()
    assert d["title"] == "Livrée d Hermès"
    assert d["aliases"] == ["www.anibal-amiot.fr", "anibal-amiot.com"]


def test_put_paramietre_et_persiste_les_details(client):
    c, sites, _m = client
    _seed(sites, "anibal-amiot", {
        "name": "anibal-amiot", "domain": "anibal-amiot.fr", "published": True})

    r = c.put("/site/anibal-amiot", json={
        "description": "Reliure d'art",
        "category": "artisanat",
        "tags": ["reliure"],
        "source_url": "https://github.com/anibaledel/livreedhermes.git",
    })

    assert r.status_code == 200, r.text
    on_disk = json.loads((sites / "anibal-amiot" / "site.json").read_text())
    assert on_disk["description"] == "Reliure d'art"
    assert on_disk["source_url"].endswith("livreedhermes.git")
    # domaine et published préservés
    assert on_disk["domain"] == "anibal-amiot.fr"


def test_put_refuse_un_alias_non_conforme_sans_ecrire(client):
    c, sites, _m = client
    _seed(sites, "anibal-amiot", {
        "name": "anibal-amiot", "domain": "anibal-amiot.fr", "published": True})

    r = c.put("/site/anibal-amiot", json={"aliases": ["pas; un domaine {"]})

    assert r.status_code == 422, r.text
    # rien n'a été gravé
    on_disk = json.loads((sites / "anibal-amiot" / "site.json").read_text())
    assert "aliases" not in on_disk


def test_put_site_inconnu_404(client):
    c, _sites, _m = client
    r = c.put("/site/inexistant", json={"title": "x"})
    assert r.status_code == 404
