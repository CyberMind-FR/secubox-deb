# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 6 SBX TV PRIVACY (#3374), « nettoyage » : code mort retiré (`POST /detect`, table `devices` inutilisée, classeur par sous-chaînes),
`/devices` et `/stats/by-device-type` sur l'inventaire réel (appareils dnstv par MAC, profils du lot 1), `/learn/thresholds` validé et
écrit atomiquement, docstring juste, remarques du lot 5b (marquage sans domaine, type transmis à `annule`), section « Listes blanches »."""
import importlib.machinery
import importlib.util
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import dnstv, dnstv_appareils, dnstv_dpi as D, main as m

ICI = Path(__file__).resolve().parents[1]
TV = "aa:bb:cc:00:00:01"
TEL = "aa:bb:cc:00:00:02"


@pytest.fixture
def monde(tmp_path, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "lire_voisins", lambda executer=None, interface=None: {})
    monkeypatch.setattr(r, "_CACHE", {"voisins": (0.0, {})})
    monkeypatch.setattr(m, "_FILTERS_F", m._P(tmp_path / "filters.json"))
    nac = {TV: {"mac": TV, "ip": "192.168.1.50", "os": "Tizen", "os_source": "dhcp", "hostname": "tv-salon", "oui_vendor": "Samsung Electronics",
                "device_type": "smart_tv", "device_subtype": "télévision"},
           TEL: {"mac": TEL, "ip": "192.168.1.60", "os": "Android 14", "os_source": "dhcp", "hostname": "Samsung-Galaxy-S23",
                 "oui_vendor": "Samsung Electronics", "device_type": "phone", "device_subtype": ""}}
    monkeypatch.setattr(dnstv_appareils, "lire_inventaire_nac", lambda *a, **k: nac)
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": TV},
                                                  {"ip": "192.168.1.60", "nom": "Galaxy", "mode": "observe", "mac": TEL}]}, tmp_path)
    now = int(time.time())
    ev = [(dnstv.Evenement(now, "192.168.1.50", "ads.example.org", "A", "NXDOMAIN", "BLOCKED"), ""),
          (dnstv.Evenement(now, "192.168.1.50", "a.example.org", "A", "NOERROR", "ALLOWED"), ""),
          (dnstv.Evenement(now, "192.168.1.60", "b.example.org", "A", "NOERROR", "ALLOWED"), "")]
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter(ev, exclus=set())
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    m.app.dependency_overrides.pop(require_jwt, None)


def _routes():
    return {(meth, r.path) for r in m.app.routes for meth in getattr(r, "methods", ())}


# ── 1. code mort ──
def test_post_detect_et_ecriture_de_la_table_devices_retires():
    assert ("POST", "/detect") not in _routes()
    for mort in ("record_detection", "get_device_stats", "get_stats_by_device_type", "classify_device"):
        assert not hasattr(m.AdGuard, mort), mort


def test_la_table_devices_d_une_box_existante_ne_casse_pas_la_mise_a_jour(tmp_path):
    import sqlite3
    db = tmp_path / "ad-guard.db"
    with sqlite3.connect(db) as cx:                                            # base d'une box déjà en 1.22.0, table remplie
        cx.execute("CREATE TABLE devices (mac_address TEXT PRIMARY KEY, ip_address TEXT, hostname TEXT, device_type TEXT, total_requests INTEGER,"
                   " blocked_requests INTEGER, ad_requests INTEGER, tracker_requests INTEGER, first_seen TEXT, last_seen TEXT)")
        cx.execute("INSERT INTO devices VALUES ('aa:aa:aa:aa:aa:aa','1.2.3.4','x','smart_tv',1,1,1,0,'','')")
    m.AdGuard(tmp_path)                                                        # aucune migration destructive
    with sqlite3.connect(db) as cx:
        assert cx.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_devices_vient_de_l_inventaire_reel_par_mac(monde):
    j = TestClient(m.app).get("/devices").json()
    assert j["source"] == "dnstv" and j["count"] == 2
    par = {d["mac_address"]: d for d in j["devices"]}
    assert par[TV]["device_type"] == "smart_tv" and par[TV]["total_requests"] == 2 and par[TV]["blocked_requests"] == 1 and par[TV]["block_rate"] == 50
    assert par[TV]["hostname"] == "TV salon"


# ── 2. classeur naïf ──
def test_un_samsung_galaxy_n_est_pas_une_tv(monde):
    j = TestClient(m.app).get("/devices").json()
    tel = [d for d in j["devices"] if d["mac_address"] == TEL][0]
    assert tel["device_type"] != "smart_tv" and tel["device_type"] == "unknown"
    t = TestClient(m.app).get("/stats/by-device-type").json()
    assert t["smart_tv"]["device_count"] == 1 and t["unknown"]["device_count"] == 1


def test_inventaire_illisible_le_dit(monde, monkeypatch):
    monkeypatch.setattr(dnstv, "lire_etat", lambda *a, **k: (None, "état illisible"))
    j = TestClient(m.app).get("/devices").json()
    assert j["devices"] == [] and j["lisible"] is False and j["note"]


def test_la_page_explique_un_inventaire_vide():
    src = (ICI / "www" / "ad-guard" / "index.html").read_text(encoding="utf-8")
    bloc = src[src.index("async function fetchDevices()"):src.index("async function fetchDelayed()")]
    assert "data?.note" in bloc and "TV Privacy" in bloc


# ── 3. /learn/thresholds ──
def test_seuils_valides_ecrits_atomiquement_sans_toucher_le_reste(monde):
    f = monde / "filters.json"
    f.write_text(json.dumps({"autolearn": True, "autolearn_min_sites": 2}))
    r = TestClient(m.app).post("/learn/thresholds", json={"autolearn_min_sites": 5})
    assert r.status_code == 200 and r.json()["changed"] == {"autolearn_min_sites": 5}
    assert json.loads(f.read_text()) == {"autolearn": True, "autolearn_min_sites": 5}
    assert sorted(p.name for p in monde.iterdir() if p.name.startswith("filters")) == ["filters.json"]     # pas de fichier temporaire laissé


@pytest.mark.parametrize("corps", [{}, {"inconnu": 3}, {"autolearn_min_sites": 0}, {"autolearn_min_sites": 10_000},
                                   {"autolearn_ti_min_weight": 101}, {"autolearn_social_window_hours": -1}, {"autolearn_min_sites": "x"},
                                   {"autolearn_min_sites": None}, {"autolearn_min_sites": 2.5}])
def test_seuils_invalides_refuses_sans_ecrire(monde, corps):
    f = monde / "filters.json"
    f.write_text('{"autolearn_min_sites": 2}')
    assert TestClient(m.app).post("/learn/thresholds", json=corps).status_code == 422
    assert f.read_text() == '{"autolearn_min_sites": 2}'


# ── 4. docstring ──
def test_docstring_sans_integration_ndpid_imaginaire():
    doc = m.__doc__ or ""
    assert "nDPId integration" not in doc and "sbxdpi" in doc


# ── 5. remarques du lot 5b ──
def test_marquer_id_sans_domaine_ne_reecrit_qu_une_decouverte_nouvelle(tmp_path):
    mag = D.MagasinDPI(tmp_path / "dpi-appareils.db")
    now = int(time.time())
    mag.ajouter_decouvertes(TV, [{"type": "sans-dns", "domaine": "203.0.113.1:443", "ts": now, "refus_ts": now, "confiance": 70}])
    mag.marquer_id(1, "confirmee", TV, "203.0.113.1:443")
    mag.marquer_id(1, "plus-tard", TV, None)                                   # « vu » tardif : ne défait pas un choix déjà appliqué
    assert mag.decouvertes()[0]["etat"] == "confirmee"


@pytest.fixture
def client5(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from secubox_core import auth
    from api import dnstv_assistant as A, dnstv_lot5_routes as L, dnstv_routes as r
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", ICI / "lists")
    A.vider_cache()
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": TV}]}, tmp_path)
    audits = []
    monkeypatch.setattr(r, "_ctl_entree", lambda action, entree: audits.append((action, json.loads(entree))))
    monkeypatch.setattr(A, "ecrire", lambda *a, **k: (_ for _ in ()).throw(OSError("disque plein")))
    app = FastAPI()
    app.include_router(L.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    c.audits = audits
    return c


@pytest.mark.parametrize("choix", ["bloquer", "legitime", "plus-tard"])
def test_annule_transmet_le_type_du_choix(client5, choix):
    r = client5.post("/adblock-tv/protection/assistant/choix", json={"mac": TV, "domaine": "x.example.com", "choix": choix})
    assert r.status_code == 503
    assert client5.audits[-1][1]["geste"] == "annule" and client5.audits[-1][1]["type"] == choix


def _ctl():
    ch = ICI / "sbin" / "secubox-adguard-tv"
    lo = importlib.machinery.SourceFileLoader("tvctl_lot6", str(ch))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("tvctl_lot6", lo))
    lo.exec_module(mod)
    return mod


@pytest.mark.parametrize("type_,domaine", [("legitime", "x.example.com"), ("plus-tard", "x.example.com"), ("bloquer", "x.example.com"),
                                           ("vu", None), ("autoriser", "x.example.com"), (None, None)])
def test_root_accepte_annule_avec_le_type_de_l_assistant(type_, domaine):
    r = {"acteur": "admin", "origine": "admin", "geste": "annule", "cibles": ["TV salon"], "minutes": None, "domaine": domaine,
         "type": type_, "force": False}
    assert _ctl()._enregistrement_protection(r)


def test_root_refuse_annule_d_un_type_inconnu():
    r = {"acteur": "admin", "origine": "admin", "geste": "annule", "cibles": ["TV salon"], "minutes": None, "domaine": None,
         "type": "n-importe", "force": False}
    assert not _ctl()._enregistrement_protection(r)


# ── 6. listes blanches ──
def test_readme_dit_quelle_liste_blanche_sert_a_quoi_et_laquelle_prime():
    t = (ICI / "README.md").read_text(encoding="utf-8")
    sec = t[t.index("## Listes blanches"):]
    for nom in ("dns-guard", "sinkhole", "adult-exempt", "ip-allowlist", "exceptions", "prime"):
        assert nom in sec, nom
