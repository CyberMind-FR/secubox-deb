# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3741 : page Modes — gardes, appels exacts aux commandes root, codes, audit, touches 7 j, hôtes PHP."""
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from .test_gestes_ia_3716 import _importer_waf

SUDOERS_WAF = Path(__file__).resolve().parents[1] / "sudoers" / "secubox-waf"


class FauxCtl:
    def __init__(self):
        self.appels = []
        self.reponses = {}

    def __call__(self, argv, entree):
        self.appels.append((argv, json.loads(entree) if entree else None))
        code, sortie = self.reponses.get((argv[2].rsplit("/", 1)[-1], argv[3], argv[4]), (0, {"ok": True}))
        return subprocess.CompletedProcess(argv, code, json.dumps(sortie).encode(), b"")


@pytest.fixture
def c(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from api import modes as m
    from secubox_core.auth import require_jwt, require_lecture
    ctl = FauxCtl()
    monkeypatch.setattr(m, "_executer", ctl)
    monkeypatch.setattr(m, "STATS7J_CACHE", tmp_path / "cache.json")
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    client = TestClient(waf.app)
    client.ctl, client.m, client.waf, client.audit = ctl, m, waf, tmp_path / "audit.log"
    waf.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    waf.app.dependency_overrides[require_lecture] = lambda: {"sub": "admin"}
    try:
        yield client
    finally:
        waf.app.dependency_overrides.clear()


def test_ecritures_refusees_sans_jwt(c):
    c.waf.app.dependency_overrides.clear()
    assert c.post("/categories/modes", json={"changements": [{"categorie": "sqli", "mode": "detect"}]}).status_code in (401, 403)
    assert c.post("/leurres-service/modes", json={"modes": {}}).status_code in (401, 403)
    assert c.post("/php-hotes", json={"hotes": []}).status_code in (401, 403)


def test_categories_live_total_motifs_plus_structurels(c):
    c.ctl.reponses[("secubox-cvectl", "waf-modes", "lister")] = (0, {"ok": True, "categories": {
        "php2shell": {"mode": "detect", "motifs": 0, "structurels": 8, "enabled": True, "verrouille": False},
        "sqli": {"mode": "block", "motifs": 7, "structurels": 0, "enabled": True, "verrouille": False}}})
    r = c.get("/categories").json()
    assert r["source"] == "box" and r["total_rules"] == 15 and r["categories"]["php2shell"]["rules_count"] == 8
    assert c.ctl.appels[0][0] == ["sudo", "-n", "/usr/sbin/secubox-cvectl", "waf-modes", "lister", "--json"]


def test_categories_repli_paquet(c, monkeypatch, tmp_path):
    c.ctl.reponses[("secubox-cvectl", "waf-modes", "lister")] = (1, {})
    f = tmp_path / "livre.json"
    f.write_text(json.dumps({"categories": {"x": {"patterns": [{"id": "a", "pattern": "a"}], "mode": "detect"}}}))
    monkeypatch.setitem(c.m._config, "regles_livrees", str(f))
    r = c.get("/categories").json()
    assert r["source"] == "paquet" and r["categories"]["x"]["mode"] == "detect"


def test_lot_appel_exact_et_audit(c):
    lot = {"changements": [{"categorie": "php2shell", "mode": "escalate", "ban_seuil": 3, "ban_duree": "24h"}]}
    assert c.post("/categories/modes", json=lot).status_code == 200
    argv, entree = c.ctl.appels[-1]
    assert argv == ["sudo", "-n", "/usr/sbin/secubox-cvectl", "waf-modes", "appliquer", "--apply", "--json"]
    assert entree == {"acteur": "admin", **lot}
    a = json.loads(c.audit.read_text().splitlines()[-1])
    assert a["action"] == "waf-modes" and "php2shell=escalate/3/24h" in a["detail"]


@pytest.mark.parametrize("corps", [{"changements": []}, {"changements": [{"categorie": "x", "mode": "monitor"}]},
                                   {"changements": [{"categorie": "x", "mode": "escalate", "ban_seuil": 11}]},
                                   {"changements": [{"categorie": "x", "mode": "escalate", "fenetre": "1h"}]}])
def test_lot_forme_refusee(c, corps):
    assert c.post("/categories/modes", json=corps).status_code == 422 and c.ctl.appels == []


def test_mode_fixe_409_sans_audit_ok(c):
    c.ctl.reponses[("secubox-cvectl", "waf-modes", "appliquer")] = (3, {"ok": False, "erreur": "mode fixé"})
    r = c.post("/category/product_absent_probes/mode", json={"mode": "block"})
    assert r.status_code == 409 and not c.audit.exists()


def test_stats7j_faux_positifs_et_absence(c, tmp_path):
    now = datetime.now(timezone.utc)
    j = tmp_path / "waf-threats.log"
    lignes = [{"timestamp": now.isoformat(), "category": "php2shell", "client_ip": "local", "action": "detect"},
              {"timestamp": now.isoformat(), "category": "php2shell", "client_ip": "203.0.113.9", "action": "detect"},
              {"timestamp": (now - timedelta(days=8)).isoformat(), "category": "php2shell", "client_ip": "203.0.113.9"}]
    j.write_text("\n".join(json.dumps(x) for x in lignes) + "\nbruit\n")
    d = c.m.calculer_stats7j([str(j)], now, set())
    assert d["categories"]["php2shell"]["touches"] == 2 and d["categories"]["php2shell"]["faux_positifs_estimes"] == 1
    assert d["robots_verifies"] is None
    assert c.m.calculer_stats7j([str(tmp_path / "absent")], now, set())["categories"] is None


def test_leurres_modes(c):
    c.ctl.reponses[("wafctl", "leurres-modes", "lister")] = (0, {"ok": True, "modes": {"rdp": "observer"}})
    r = {x["service"]: x["mode"] for x in c.get("/leurres-service/modes").json()["leurres"]}
    assert r["rdp"] == "observer" and r["vnc"] == "bannir" and len(r) == 10
    assert c.post("/leurres-service/modes", json={"modes": {"inconnu": "observer"}}).status_code == 422
    c.ctl.reponses[("wafctl", "leurres-modes", "ecrire")] = (0, {"ok": True, "modes": {"vnc": "observer"}})
    assert c.post("/leurres-service/modes", json={"modes": {"vnc": "observer"}}).status_code == 200
    assert c.ctl.appels[-1] == (["sudo", "-n", "/usr/sbin/wafctl", "leurres-modes", "ecrire"], {"modes": {"vnc": "observer"}})


def test_php_hotes(c):
    c.ctl.reponses[("wafctl", "php-hotes", "lister")] = (0, {"ok": True, "vhosts": ["nc.ex.fr", "blog.ex.fr", "web.ex.fr"],
        "profils_vhosts": {"nc.ex.fr": "nextcloud"}, "php_services": ["nextcloud"],
        "php_hotes": ["^blog\\.ex\\.fr$", "^(webmail)\\."]})
    h = {x["hote"]: x for x in c.get("/php-hotes").json()["hotes"]}
    assert h["nc.ex.fr"]["conteneur_php"] == "oui" and h["nc.ex.fr"]["couvert"]
    assert h["blog.ex.fr"]["explicite"] and h["blog.ex.fr"]["conteneur_php"] == "inconnu"
    assert not h["web.ex.fr"]["couvert"] and not h["web.ex.fr"]["explicite"]
    assert c.post("/php-hotes", json={"hotes": ["a;b"]}).status_code == 422
    assert c.post("/php-hotes", json={"hotes": ["Web.ex.fr"]}).status_code == 200
    assert (["sudo", "-n", "/usr/sbin/wafctl", "php-hotes", "ecrire"], {"hotes": ["web.ex.fr"]}) in c.ctl.appels


def test_sudoers_lignes_exactes():
    t = SUDOERS_WAF.read_text()
    for ligne in ("/usr/sbin/wafctl leurres-modes lister", "/usr/sbin/wafctl leurres-modes ecrire",
              "/usr/sbin/wafctl php-hotes lister", "/usr/sbin/wafctl php-hotes ecrire"):
        assert ligne in t


def test_page_modes_et_onglet():
    www = Path(__file__).resolve().parents[1] / "www" / "waf"
    page = (www / "modes.html").read_text(encoding="utf-8")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in page and "sbx_token" in page and "demo=1" in page
    for route in ("/categories/modes", "/categories/stats7j", "/leurres-service/modes", "/php-hotes"):
        assert route in page
    assert "ban immédiat, requêtes suivantes bloquées" in page and "innerHTML" not in page
    assert "fenetre" not in page                      # pas de fenêtre par catégorie (fenêtre escalate globale)
    onglets = (www / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="modes"' in onglets and "modes: 'modes'" in onglets
