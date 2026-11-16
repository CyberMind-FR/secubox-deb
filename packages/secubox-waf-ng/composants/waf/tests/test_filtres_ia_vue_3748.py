# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3748 : onglet Filtres IA — gardes, cache, agrégation (touches, bans, leurres, écartés), retrait audité."""
import json
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from .test_gestes_ia_3716 import _importer_waf

MAINTENANT = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
FILTRES = [
    {"id": "ia-cve-2024-4577-a", "cve": "CVE-2024-4577", "produit": "PHP-CGI", "famille": "rce", "gravite": "critique",
     "categorie": "ia_filtres_critique", "pattern": "%AD"},
    {"id": "ia-cve-2023-38646-b", "cve": "CVE-2023-38646", "produit": "Metabase", "famille": "rce",
     "gravite": None, "categorie": "ia_filtres_moyenne", "pattern": "/api/setup/validate"},
]


def _ligne(ts, rid, ip, cat="ia_filtres_critique", action="blocked"):
    return json.dumps({"timestamp": ts.isoformat(), "rule_id": rid, "category": cat, "client_ip": ip,
                       "action": action}) + "\n"


class FauxCtl:
    def __init__(self):
        self.appels = []
        self.reponses = {"lister": (0, {"ok": True, "filtres": FILTRES}), "retirer": (0, {"ok": True, "id": "x"})}

    def __call__(self, argv, entree):
        self.appels.append((argv, json.loads(entree) if entree else None))
        code, sortie = self.reponses[argv[4]]
        return subprocess.CompletedProcess(argv, code, json.dumps(sortie).encode(), b"")


@pytest.fixture
def c(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from api import filtres_ia_vue as v
    from secubox_core.auth import require_jwt, require_lecture
    ctl = FauxCtl()
    monkeypatch.setattr(v, "_executer", ctl)
    monkeypatch.setattr(v, "CACHE", tmp_path / "cache.json")
    monkeypatch.setattr(v, "AUDIT_LOG", tmp_path / "audit-cvectl.log")
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    client = TestClient(waf.app)
    client.ctl, client.v, client.waf, client.audit = ctl, v, waf, tmp_path / "audit.log"
    waf.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    waf.app.dependency_overrides[require_lecture] = lambda: {"sub": "admin"}
    try:
        yield client
    finally:
        waf.app.dependency_overrides.clear()


def test_gardes(c):
    from secubox_core.auth import require_lecture
    for route in ("/filtres-ia/resume", "/filtres-ia/touches", "/filtres-ia/radar"):
        r = next(x for x in c.waf.app.routes if getattr(x, "path", "") == route)
        assert any(d.call is require_lecture for d in r.dependant.dependencies)
    c.waf.app.dependency_overrides.clear()
    assert c.post("/filtres-ia/ia-cve-2024-4577-a/retirer").status_code in (401, 403)
    assert c.ctl.appels == []


def test_cache_absent_rend_null_jamais_zero(c):
    r = c.get("/filtres-ia/resume").json()
    assert r["etat"] == "calcul en cours" and r["resume"] is None
    assert c.get("/filtres-ia/touches").json()["filtres"] is None
    assert c.get("/filtres-ia/radar").json()["points"] is None
    assert c.ctl.appels == []          # la requête ne lance rien


def test_agregation():
    from api import filtres_ia_vue as v
    h = MAINTENANT - timedelta(hours=1)
    touches = [
        {"ts": h, "id": "ia-cve-2024-4577-a", "categorie": "ia_filtres_critique", "ip": "203.0.113.5", "action": "blocked"},
        {"ts": h, "id": "ia-cve-2024-4577-a", "categorie": "ia_filtres_critique", "ip": "203.0.113.5", "action": "banned"},
        {"ts": h, "id": "ia-cve-2024-4577-a", "categorie": "ia_filtres_critique", "ip": "198.51.100.7", "action": "blocked"},
        {"ts": h, "id": "ia-cve-2023-38646-b", "categorie": "ia_filtres_moyenne", "ip": "local", "action": "detect"},
        {"ts": MAINTENANT - timedelta(days=3), "id": "ia-cve-2023-38646-b", "categorie": "ia_filtres_moyenne",
         "ip": "192.0.2.9", "action": "detect"},
    ]
    leurres = {"203.0.113.5": ["telnet"], "192.0.2.9": ["redis"], "198.18.0.1": ["rdp"]}
    d = v.agreger(FILTRES, touches, {"203.0.113.5", "192.0.2.9"}, leurres, {"total": 2, "par_raison": {"present": 2}},
                  set(), MAINTENANT)
    r = d["resume"]
    assert r["actifs"] == 2 and r["par_gravite"] == {"critique": 1, "haute": 0, "moyenne": 1}
    assert r["kev"] is None                       # gk2 ne garde pas KEV : « — »
    assert r["touches_24h"] == 4 and r["filtres_touches_24h"] == 2 and r["faux_positifs_24h"] == 1
    assert r["bans_actifs"] == 2 and r["bans_aussi_leurre"] == 2
    assert r["vulnerabilites_connues"] is None and r["candidats_relais"] is None
    assert d["leurres_communs"] == {"telnet": 1, "redis": 1}
    # le faux positif remonte en tête
    assert d["filtres"][0]["id"] == "ia-cve-2023-38646-b" and d["filtres"][0]["faux_positifs"] == 1
    php = d["filtres"][1]
    assert php["touches_24h"] == 3 and php["adresses_24h"] == 2 and php["bannies"] == 1 and php["leurres"] == ["telnet"]
    assert d["filtres"][0]["gravite"] == "moyenne"          # repli sur la catégorie
    pts = {p["ip"]: p for p in d["radar"]}
    assert pts["203.0.113.5"]["ia"] and pts["203.0.113.5"]["leurres"] == ["telnet"] and pts["203.0.113.5"]["banni"]
    assert not pts["198.18.0.1"]["ia"] and "local" not in pts


def test_sources_absentes_null():
    from api import filtres_ia_vue as v
    d = v.agreger(None, None, None, None, None, set(), MAINTENANT)
    r = d["resume"]
    assert d["filtres"] is None and r["actifs"] is None and r["touches_24h"] is None and r["bans_actifs"] is None
    assert d["radar"] is None and d["leurres_communs"] is None


def test_lire_touches_et_ecartes(tmp_path):
    from api import filtres_ia_vue as v
    j = tmp_path / "waf-threats.log"
    j.write_text(_ligne(MAINTENANT - timedelta(hours=2), "ia-x", "203.0.113.5")
                 + _ligne(MAINTENANT - timedelta(days=9), "ia-x", "203.0.113.5")
                 + _ligne(MAINTENANT, "sqli-1", "203.0.113.5", cat="sqli") + "pas du json ia_filtres_\n")
    t = v.lire_touches([str(j)], MAINTENANT)
    assert len(t) == 1 and t[0]["id"] == "ia-x"
    assert v.lire_touches([str(tmp_path / "absent")], MAINTENANT) is None
    a = tmp_path / "audit.log"
    a.write_text(json.dumps({"action": "leurre_filtres-ia-appliquer", "result": "rejet",
                             "detail": "ia-a:déjà couvert, ia-b:présent, ia-c:déjà couvert"}) + "\n"
                 + json.dumps({"action": "autre", "result": "rejet", "detail": "ia-z:x"}) + "\n")
    e = v.lire_ecartes(a, {"ia-c"})
    assert e == {"total": 2, "par_raison": {"déjà couvert": 1, "présent": 1}}
    assert v.lire_ecartes(tmp_path / "absent", set()) is None


def test_rafraichir_ecrit_le_cache(c, tmp_path):
    j = tmp_path / "waf-threats.log"
    j.write_text(_ligne(datetime.now(timezone.utc) - timedelta(hours=1), "ia-cve-2024-4577-a", "203.0.113.5"))
    c.v.configurer(audit=c.waf._audit, journal=str(j), bans=lambda: [{"ip": "203.0.113.5"}],
                   leurres=lambda: {"203.0.113.5": ["telnet"]}, liste_blanche=lambda: ["127.0.0.1"])
    c.v.rafraichir()
    assert c.ctl.appels[0][0] == ["sudo", "-n", "/usr/sbin/secubox-cvectl", "filtres-ia", "lister", "--json"]
    r = c.get("/filtres-ia/resume").json()["resume"]
    assert r["actifs"] == 2 and r["touches_24h"] == 1 and r["bans_actifs"] == 1 and r["ecartes"] is None
    assert c.get("/filtres-ia/radar").json()["points"][0]["ip"] == "203.0.113.5"


def test_retirer_audite_et_appelle_cvectl(c):
    c.v.CACHE.write_text(json.dumps({"filtres": [{"id": "ia-cve-2024-4577-a"}, {"id": "ia-b"}],
                                     "resume": {"actifs": 2}}))
    r = c.post("/filtres-ia/ia-cve-2024-4577-a/retirer")
    assert r.status_code == 200
    argv, entree = c.ctl.appels[-1]
    assert argv == ["sudo", "-n", "/usr/sbin/secubox-cvectl", "filtres-ia", "retirer", "--apply", "--json"]
    assert entree == {"acteur": "admin", "id": "ia-cve-2024-4577-a"}
    lignes = [json.loads(x) for x in c.audit.read_text().splitlines()]
    assert [x["detail"] for x in lignes] == ["intention ia-cve-2024-4577-a", "ok ia-cve-2024-4577-a"]
    assert c.get("/filtres-ia/touches").json()["filtres"] == [{"id": "ia-b"}]


def test_retirer_refus_et_id(c):
    assert c.post("/filtres-ia/sqli-1/retirer").status_code == 422
    assert c.ctl.appels == []
    c.ctl.reponses["retirer"] = (4, {"ok": False, "erreur": "filtre inconnu"})
    assert c.post("/filtres-ia/ia-inconnu/retirer").status_code == 404
    assert json.loads(c.audit.read_text().splitlines()[-1])["detail"] == "refus 404 ia-inconnu"


def test_retirer_sans_audit_ne_fait_rien(c, tmp_path, monkeypatch):
    monkeypatch.setattr(c.waf, "AUDIT_LOG", tmp_path / "absent" / "audit.log")
    assert c.post("/filtres-ia/ia-cve-2024-4577-a/retirer").status_code == 500
    assert c.ctl.appels == []
