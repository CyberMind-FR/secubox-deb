# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — API de lecture : enveloppe, bornes, erreurs, surcouche d'état des sources."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from api import main  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402
from secubox_datascope import config, store  # noqa: E402

T0 = "2026-11-21T10:00:00Z"
DEV = "device:aabbccddeeff"
SVC = "service:waf"


def _iso(delta=0):
    return (datetime.now(timezone.utc) - timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rel(a, b, t="CONNECTS_TO", sm="nac"):
    return {"src": a, "dst": b, "type": t, "evidence_type": "observed", "confidence": 1.0,
            "justification": "vu", "source_module": sm}


@pytest.fixture
def env(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    cache.mkdir()
    cfg = config.Config(base=tmp_path / "d.db", cache=cache, nac_db=tmp_path / "n", netstats=tmp_path / "s",
                        modules=tmp_path / "m")
    monkeypatch.setattr(main, "CFG", cfg)
    db = store.ouvrir(cfg.base)
    store.appliquer(db, store.Releve(
        source="network", etat="ok", empreinte="a",
        entites=[{"id": "node:h", "label": "h"}, {"id": DEV, "label": "tv", "attributes": {"hostname": "tv"}},
                 {"id": "interface:eth0", "label": "eth0"}],
        relations=[{"src": DEV, "dst": "interface:eth0", "type": "CONNECTS_TO", "evidence_type": "observed",
                    "confidence": 1.0, "justification": "vu"}]), T0)
    store.appliquer(db, store.Releve(
        source="status", etat="ok", empreinte="b",
        entites=[{"id": "node:h", "label": "h"},
                 {"id": SVC, "label": "waf", "attributes": {"overall": "operational"}}],
        relations=[{"src": SVC, "dst": "node:h", "type": "HOSTED_ON", "evidence_type": "reported",
                    "confidence": 1.0, "justification": "santé"}]), T0)
    db.close()
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield cfg
    main.app.dependency_overrides.clear()


@pytest.fixture
def client(env):
    return TestClient(main.app)


P = "/api/v1/datascope"


def _etat(cfg, source, etat):
    db = store.ouvrir(cfg.base)
    db.execute("UPDATE curseurs SET etat=? WHERE source=?", (etat, source))
    db.close()


def test_health_public(client):
    main.app.dependency_overrides.clear()
    r = TestClient(main.app).get(P + "/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_overview_lecture(env, client):
    (env.cache / "overview.json").write_text(json.dumps(
        {"genere_le": _iso(), "verifie_le": _iso(), "complet": True, "entites": {"device": 1}, "relations": 1,
         "sources": []}))
    j = client.get(P + "/overview").json()
    assert j["entites"] == {"device": 1} and j["perime"] is False


def test_overview_perime_sur_verifie_le(env, client):
    (env.cache / "overview.json").write_text(json.dumps(
        {"genere_le": _iso(), "verifie_le": _iso(400), "complet": True, "entites": {}, "relations": 0}))
    assert client.get(P + "/overview").json()["perime"] is True


@pytest.mark.parametrize("contenu", [None, "{pas du json"])
def test_overview_absent_ou_corrompu(env, client, contenu):
    if contenu:
        (env.cache / "overview.json").write_text(contenu)
    r = client.get(P + "/overview")
    j = r.json()
    assert r.status_code == 200 and j["disponible"] is False and j["motif"] and "entites" not in j


def test_context_sections_null_avec_motif(client):
    j = client.get(f"{P}/entities/{DEV}/context").json()
    assert j["recent_events"] is None and j["history"] is None
    assert j["motifs"] == {"recent_events": "non livré en V0.1", "history": "non livré en V0.1"}
    assert j["entity"]["id"] == DEV and j["summary"]["relations"] == 1 and j["relationships"]
    assert j["source_provenance"]


def test_actions_liens_seulement(client):
    a = client.get(f"{P}/entities/{DEV}/context").json()["available_actions"]
    assert a == [{"libelle": "Ouvrir dans le NAC", "href": "/nac/"}]
    s = client.get(f"{P}/entities/{SVC}/context").json()["available_actions"]
    assert s == [{"libelle": "Ouvrir le module waf", "href": "/waf/"}]
    assert client.get(f"{P}/entities/interface:eth0/context").json()["available_actions"] == []
    for x in a + s:
        assert set(x) == {"libelle", "href"}


def test_graph_borne_et_tronque(env, client):
    db = store.ouvrir(env.base)
    store.appliquer(db, store.Releve(source="network", etat="ok", empreinte="g",
                                     entites=[{"id": f"ip:10.0.{i // 250}.{i % 250}", "label": "x"}
                                              for i in range(600)]), T0)
    db.close()
    g = client.get(P + "/graph?type=ip").json()
    assert len(g["noeuds"]) == 500 and g["tronque"] is True and len(g["aretes"]) <= 1500


def test_graph_sans_filtre_lit_le_cache(env, client):
    assert client.get(P + "/graph").json()["disponible"] is False
    (env.cache / "graph.json").write_text(json.dumps(
        {"genere_le": T0, "complet": True, "tronque": False, "aretes": [],
         "noeuds": [{"id": SVC, "type": "service", "label": "waf", "source_module": "status"}]}))
    n = client.get(P + "/graph").json()["noeuds"][0]
    assert n["etat_source"] == "ok"


def test_id_invalide_400(client):
    for chemin in ("entities/pas-un-id", "entities/pas-un-id/context", "entities/x:1/neighbors"):
        assert client.get(f"{P}/{chemin}").status_code == 400
    assert client.get(P + "/entities?type=bidon").status_code == 400


def test_id_inconnu_404(client):
    for suffixe in ("", "/context", "/neighbors"):
        r = client.get(f"{P}/entities/device:inconnu{suffixe}")
        assert r.status_code == 404 and "detail" in r.json()


def test_entities_pagination_et_etat(client):
    j = client.get(P + "/entities?par_page=2&page=1").json()
    assert j["total"] == 4 and len(j["entites"]) == 2
    assert all(e["etat_source"] == "ok" for e in j["entites"])
    assert client.get(P + "/entities?par_page=201").status_code == 422
    assert [e["id"] for e in client.get(P + "/entities?q=tv").json()["entites"]] == [DEV]


@pytest.mark.parametrize("etat", ["unknown", "inaccessible"])
def test_surcouche_service_overall_unknown(env, client, etat):
    _etat(env, "status", etat)
    e = client.get(f"{P}/entities/{SVC}").json()
    assert e["etat_source"] == etat and e["attributes"]["overall"] == "unknown"
    assert client.get(f"{P}/entities/{DEV}").json()["etat_source"] == "ok"
    c = client.get(f"{P}/entities/{SVC}/context").json()
    assert c["entity"]["attributes"]["overall"] == "unknown"
    nv = client.get(f"{P}/entities/node:h/neighbors").json()
    s = [n for n in nv["noeuds"] if n["id"] == SVC][0]
    assert s["attributes"]["overall"] == "unknown" and s["etat_source"] == etat
    g = client.get(P + "/graph?type=service").json()["noeuds"][0]
    assert g["etat_source"] == etat


def test_overall_conserve_quand_ok(client):
    assert client.get(f"{P}/entities/{SVC}").json()["attributes"]["overall"] == "operational"


def test_entite_nac_prend_l_etat_de_network(env, client):
    _etat(env, "network", "inaccessible")
    assert client.get(f"{P}/entities/{DEV}").json()["etat_source"] == "inaccessible"


def test_sources(client):
    assert {s["source"] for s in client.get(P + "/sources").json()["sources"]} == {"network", "status"}


def test_base_absente_503(env, client, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "CFG", config.Config(base=tmp_path / "rien.db", cache=env.cache, nac_db=env.nac_db,
                                                   netstats=env.netstats, modules=env.modules))
    r = client.get(P + "/entities")
    assert r.status_code == 503 and not (tmp_path / "rien.db").exists()
