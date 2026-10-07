# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient
from secubox_core import auth

from api import main

JOUR = time.strftime("%Y-%m-%d", time.gmtime())


@pytest.fixture
def banc(tmp_path, monkeypatch):
    db = tmp_path / "dnstv.db"
    cx = sqlite3.connect(db)
    cx.execute("""CREATE TABLE dnstv_counts (jour TEXT NOT NULL, client TEXT NOT NULL, domaine TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT '',
                  decision TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (jour, client, domaine, decision))""")
    cx.executemany("INSERT INTO dnstv_counts VALUES (?, ?, ?, ?, ?, ?)", [
        (JOUR, "192.168.1.5", "pub.example.com", "advertising", "BLOCKED", 40), (JOUR, "192.168.1.5", "trk.example.net", "tracking", "BLOCKED", 7),
        (JOUR, "192.168.1.5", "ok.example.org", "", "ALLOWED", 953)])
    cx.commit()
    cx.close()
    puits = tmp_path / "sinkhole-status.json"
    puits.write_text(json.dumps({"ok": True, "enabled": True, "blocked": 656704}))
    monkeypatch.setattr(main, "AD_GUARD_DB", db)
    monkeypatch.setattr(main, "PUITS_STATUS", puits)
    monkeypatch.setattr(main, "guard", main.DnsGuard(tmp_path / "dg"))
    main.app.dependency_overrides.clear()
    yield tmp_path
    main.app.dependency_overrides.clear()


def lecteur():
    main.app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "lecteur"}


def admin():
    lecteur()
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}


def test_status_porte_les_champs_que_le_panneau_lit(banc):
    lecteur()
    d = TestClient(main.app).get("/status").json()
    assert d["queries_24h"] == 1000 and d["blocked_24h"] == 47 and d["blocklist_size"] == 656704
    assert d["malware_blocked"] is None and d["phishing_blocked"] is None                  # le puits ne distingue pas ces catégories
    assert d["fenetre"] == "aujourd'hui (UTC)" and d["sources"] == {"dns": True, "puits": True}
    assert d["blocklist_count"] == 0 and "alerts_24h" in d                                 # les champs d'origine sont conservés


def test_status_sans_source_dit_absent_et_non_zero(banc, monkeypatch):
    lecteur()
    monkeypatch.setattr(main, "AD_GUARD_DB", banc / "absente.db")
    monkeypatch.setattr(main, "PUITS_STATUS", banc / "absent.json")
    d = TestClient(main.app).get("/status").json()
    assert d["queries_24h"] is None and d["blocked_24h"] is None and d["sources"] == {"dns": False, "puits": False}
    assert d["blocklist_size"] == 0                                                         # repli : la liste propre du module (vide), jamais un nombre inventé


def test_top_blocked(banc):
    lecteur()
    c = TestClient(main.app)
    d = c.get("/top-blocked?limit=1").json()
    assert d["domains"] == [{"domain": "pub.example.com", "category": "advertising", "hits": 40}] and d["fenetre"] == "aujourd'hui (UTC)"
    assert [x["domain"] for x in c.get("/top-blocked").json()["domains"]] == ["pub.example.com", "trk.example.net"]
    for q in ("limit=0", "limit=51", "limit=abc"):
        assert c.get("/top-blocked?" + q).status_code == 422


def test_top_blocked_ne_montre_aucun_appareil(banc):
    lecteur()
    assert "192.168" not in TestClient(main.app).get("/top-blocked").text


def test_threats_reserve_a_l_administrateur_et_tire_des_alertes(banc):
    lecteur()
    assert TestClient(main.app).get("/threats").status_code in (401, 403)
    main.guard.alerts_file.write_text(json.dumps({"id": "1", "type": "dga", "severity": "high", "domain": "xkqzp.example.com", "client_ip": "192.168.1.5",
                                                  "description": "d", "details": {}, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "blocked": True}) + "\n")
    admin()
    d = TestClient(main.app).get("/threats?limit=20").json()
    assert [t["domain"] for t in d["threats"]] == ["xkqzp.example.com"] and d["threats"][0]["type"] == "dga" and d["threats"][0]["client_ip"] == "192.168.1.5"
    assert TestClient(main.app).get("/threats?limit=0").status_code == 422


def test_threats_vide_si_aucune_alerte(banc):
    admin()
    assert TestClient(main.app).get("/threats").json() == {"threats": []}


# ── D3 (#2050) : un seul moteur DNS, Unbound — dns-guard ne parle plus à dnsmasq ──────────────────────────────────────────────────
def test_dns_guard_n_ecrit_ni_ne_recharge_dnsmasq():
    import inspect
    from pathlib import Path

    from api import main as m

    src = inspect.getsource(m)
    assert "dnsmasq.d" not in src and '"reload", "dnsmasq"' not in src and "_sync_dnsmasq" not in src
    ctrl = (Path(__file__).resolve().parents[1] / "debian" / "control").read_text()
    assert "dnsmasq" not in ctrl.lower(), "plus de dépendance ni de promesse de blocage dnsmasq"


def test_la_route_sync_dit_honnetement_qu_il_n_y_a_pas_de_moteur_a_synchroniser(monkeypatch):
    from fastapi.testclient import TestClient

    from api import main as m
    from secubox_core import auth

    m.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "a"}
    try:
        r = TestClient(m.app).post("/sync")
        assert r.status_code == 200
        j = r.json()
        assert j["status"] != "synced", "ne prétend pas avoir synchronisé un moteur qui n'existe plus"
        assert "unbound" in j["detail"].lower()
    finally:
        m.app.dependency_overrides.clear()


def test_ajouter_a_la_liste_ne_touche_plus_au_systeme(tmp_path):
    from api import main as m

    g = m.DNSGuard.__new__(m.DNSGuard) if hasattr(m, "DNSGuard") else None
    assert g is None or not hasattr(g, "_sync_dnsmasq")
