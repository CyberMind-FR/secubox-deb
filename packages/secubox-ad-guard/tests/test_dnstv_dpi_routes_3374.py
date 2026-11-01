# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374) : routes /adblock-tv/protection/dpi/* — données par appareil réservées à l'administrateur réel, paramètres fermés,
source absente honnête, frise des coupures avec SSAI."""
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_dpi as D

MAC = "aa:bb:cc:00:00:01"


@pytest.fixture
def client(tmp_path, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot4_routes as L
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", __import__("pathlib").Path(__file__).resolve().parents[1] / "lists")
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC}]}, tmp_path)
    now = int(time.time())
    m = dnstv.Magasin(tmp_path / "dnstv.db")
    m.ajouter([(dnstv.Evenement(now - 100, "192.168.1.50", d, "A", "NOERROR", dec), "") for d, dec in (
        ("replay-03.oqee.net", "ALLOWED"), ("pagead2.googlesyndication.com", "BLOCKED"))])
    m.ajouter([(dnstv.Evenement(now - 97, "192.168.1.50", "metaproxy.francetvpub.fr", "A", "NOERROR", "ALLOWED"), "")])
    mag = D.MagasinDPI(tmp_path / "dpi-appareils.db")
    mag.ingerer([{"mac": MAC, "minute": now // 60, "appli": "TLS", "hote": "replay-03.oqee.net", "port": 443, "distant": "", "flux": 1,
                  "octets": 5_000_000}])
    mag.ajouter_decouvertes(MAC, [{"type": "repli", "domaine": "metaproxy.francetvpub.fr", "categorie": "PUBLICITE", "ts": now - 97,
                                   "refus_ts": now - 100, "delai_s": 3, "confiance": 70, "raison": "apparu 3 s après le blocage de pagead2"}])
    D._ecrire_etat_dpi({"version": 1, "genere": now, "sources": {"sbxdpi": "absent", "conntrack": "absent"},
                        "appareils": [{"mac": MAC, "nom": "TV salon", "mode": "auto", "couverture": "dns+dpi"}],
                        "charge": {"haute_depuis": None, "pause": None}})
    app = FastAPI()
    app.include_router(L.router)
    qui = {"sub": "admin"}
    app.dependency_overrides[auth.require_jwt] = lambda: qui
    app.dependency_overrides[auth.require_lecture] = lambda: qui
    c = TestClient(app)
    c.qui = qui
    return c


def test_etat_admin_et_lecteur_delegue(client, monkeypatch):
    e = client.get("/adblock-tv/protection/dpi/etat").json()
    a = e["appareils"][0]
    assert a["mac"] == MAC and a["couverture"] == "dns+dpi" and a["forcage"]["pose"] is True
    assert "effectif seulement si" in a["forcage"]["note"]
    client.qui.update(sub="pilotage", delegue=True)
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_lecteur_nominatif", lambda p: True)
    e = client.get("/adblock-tv/protection/dpi/etat").json()
    assert "mac" not in e["appareils"][0] and "forcage" not in e["appareils"][0]


def test_applications_avec_badge_ssai_et_parametres_fermes(client):
    apps = client.get(f"/adblock-tv/protection/dpi/applications?mac={MAC}&fenetre=24h").json()["applications"]
    assert apps[0]["appli"] == "TLS" and apps[0]["ssai"] is True
    assert client.get("/adblock-tv/protection/dpi/applications?mac=pas-une-mac").status_code == 422
    assert client.get(f"/adblock-tv/protection/dpi/applications?mac={MAC}&fenetre=1an").status_code == 422
    assert client.get(f"/adblock-tv/protection/dpi/flux?mac={MAC}&limite=500").status_code == 422
    assert client.get(f"/adblock-tv/protection/dpi/flux?mac={MAC}").json()["total"] == 1


def test_decouvertes_par_id_avec_nom_d_appareil(client):
    d = client.get("/adblock-tv/protection/dpi/decouvertes?depuis=0").json()["decouvertes"]
    assert d[0]["appareil"] == "TV salon" and d[0]["domaine"] == "metaproxy.francetvpub.fr"
    assert client.get("/adblock-tv/protection/dpi/decouvertes?type=nimporte").status_code == 422


def test_frise_des_coupures(client):
    f = client.get(f"/adblock-tv/protection/dpi/coupures?mac={MAC}&fenetre=1h").json()["coupures"]
    assert f[0]["refus_domaine"] == "pagead2.googlesyndication.com"
    assert [(x["delai_s"], x["domaine"], x["type"]) for x in f[0]["apparitions"]] == [(3, "metaproxy.francetvpub.fr", "repli")]


def test_source_absente_est_honnete(client, tmp_path):
    (tmp_path / D.FICHIER_ETAT).unlink()
    e = client.get("/adblock-tv/protection/dpi/etat").json()
    assert e["disponible"] is False and e["raison"] == "absent"


def test_reprise_manuelle_de_nDPId(client, monkeypatch):
    from api import dnstv_lot4_routes as L
    appels = []
    monkeypatch.setattr(L, "_verbe", lambda v: appels.append(v) or {"ok": True})
    assert client.post("/adblock-tv/protection/dpi/reprendre").json()["ok"] is True and appels == ["ndpid-reprendre"]


def test_toutes_les_routes_par_appareil_exigent_require_jwt():
    from secubox_core import auth
    from api import dnstv_lot4_routes as L
    for r in L.router.routes:
        if r.path != "/adblock-tv/protection/dpi/etat":
            assert any(d.call is auth.require_jwt for d in r.dependant.dependencies), r.path


def test_reprise_ouverte_au_relais_du_pilotage():
    from pathlib import Path
    t = (Path(__file__).resolve().parents[1] / "pilotage" / "routes-ouvertes.d" / "ad-guard.toml").read_text()
    assert "^/adblock-tv/protection/dpi/reprendre$" in t
