# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3070 — OVH sans bibliothèque, vue « vhosts et domaines », clés d'API en 0600.

Constat gk2 : un seul fournisseur (Gandi) ; OVH exigeait la bibliothèque `ovh` (absente de la box et de Debian : HTTP 501)
alors que `gk2.net` (5 vhosts) est chez OVH ; aucune page ne disait quels domaines des 131 vhosts sont gérés, gérables ou
externes ; `providers.json` (clé d'API en clair) était en 0664."""
import asyncio
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path

import pytest

COMP = Path(__file__).resolve().parents[1]
RACINE = COMP.parents[3]
sys.path.insert(0, str(RACINE / "common"))
SRC = (COMP / "api" / "main.py").read_text(encoding="utf-8")
PAGE = (COMP / "www" / "dns-provider" / "index.html").read_text(encoding="utf-8")


@pytest.fixture
def m(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    spec = importlib.util.spec_from_file_location("dnsprov_3070", COMP / "api" / "main.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(mod, "PROVIDERS_FILE", tmp_path / "providers.json")
    monkeypatch.setattr(mod, "AUDIT_LOG_FILE", tmp_path / "audit.log")
    return mod


# ── OVH sans bibliothèque ──────────────────────────────────────────────────────

def test_l_adaptateur_ovh_ne_depend_plus_de_la_bibliotheque_ovh():
    bloc = SRC[SRC.index("class OVHAdapter"):SRC.index("class Route53Adapter")]
    assert "import ovh" not in bloc and "pip install ovh" not in bloc
    assert "httpx" in bloc and "X-Ovh-Signature" in bloc


def test_la_signature_ovh_est_celle_du_protocole(m):
    sig = m.ovh_signature("sec", "ck", "GET", "https://eu.api.ovh.com/1.0/domain/zone", "", 1700000000)
    attendu = "$1$" + hashlib.sha1(b"sec+ck+GET+https://eu.api.ovh.com/1.0/domain/zone++1700000000").hexdigest()
    assert sig == attendu


def test_ovh_liste_les_zones_et_signe_chaque_requete(m):
    import httpx
    vus = []

    def handler(req: httpx.Request) -> httpx.Response:
        vus.append((req.method, req.url.path))
        if req.url.path.endswith("/auth/time"):
            return httpx.Response(200, json=1700000000)
        assert req.headers["X-Ovh-Application"] == "ak" and req.headers["X-Ovh-Consumer"] == "ck"
        assert req.headers["X-Ovh-Timestamp"] == "1700000000"
        corps = req.content.decode() if req.content else ""
        assert req.headers["X-Ovh-Signature"] == m.ovh_signature("as", "ck", req.method, str(req.url), corps, 1700000000)
        if req.url.path == "/1.0/domain/zone":
            return httpx.Response(200, json=["gk2.net", "autre.fr"])
        return httpx.Response(404, json={"message": "inconnu"})
    m.OVHAdapter._transport = httpx.MockTransport(handler)
    try:
        a = m.get_adapter(m.ProviderType.OVH, {"application_key": "ak", "application_secret": "as", "consumer_key": "ck", "endpoint": "ovh-eu"})
        zones = asyncio.run(a.list_domains())
    finally:
        m.OVHAdapter._transport = None
    assert [z["name"] for z in zones] == ["gk2.net", "autre.fr"]
    assert ("GET", "/1.0/auth/time") in vus


def test_ovh_creer_un_enregistrement_rafraichit_la_zone(m):
    import httpx
    vus = []

    def handler(req: httpx.Request) -> httpx.Response:
        vus.append((req.method, req.url.path, req.content.decode() if req.content else ""))
        if req.url.path.endswith("/auth/time"):
            return httpx.Response(200, json=1700000000)
        if req.method == "POST" and req.url.path.endswith("/record"):
            return httpx.Response(200, json={"id": 4242})
        return httpx.Response(200, json=None)
    m.OVHAdapter._transport = httpx.MockTransport(handler)
    try:
        a = m.get_adapter(m.ProviderType.OVH, {"application_key": "ak", "application_secret": "as", "consumer_key": "ck", "endpoint": "ovh-eu"})
        r = asyncio.run(a.create_record("gk2.net", m.RecordCreate(type="A", name="@", value="192.0.2.1", ttl=300)))
    finally:
        m.OVHAdapter._transport = None
    assert r["id"] == "4242"
    cree = [v for v in vus if v[0] == "POST" and v[1].endswith("/record")][0]
    assert json.loads(cree[2]) == {"fieldType": "A", "subDomain": "", "target": "192.0.2.1", "ttl": 300}
    assert ("POST", "/1.0/domain/zone/gk2.net/refresh", "") in vus


def test_ovh_une_erreur_de_l_api_est_un_502_lisible(m):
    import httpx
    from fastapi import HTTPException

    def handler(req):
        if req.url.path.endswith("/auth/time"):
            return httpx.Response(200, json=1700000000)
        return httpx.Response(403, json={"message": "This call has not been granted"})
    m.OVHAdapter._transport = httpx.MockTransport(handler)
    try:
        a = m.get_adapter(m.ProviderType.OVH, {"application_key": "ak", "application_secret": "as", "consumer_key": "ck", "endpoint": "ovh-eu"})
        with pytest.raises(HTTPException) as e:
            asyncio.run(a.list_domains())
    finally:
        m.OVHAdapter._transport = None
    assert e.value.status_code == 502 and "not been granted" in str(e.value.detail)


# ── couverture : vhosts × zones des fournisseurs × NS publics ──────────────────

PROVIDERS = [{"id": "g1", "name": "gk2-gandi", "type": "gandi", "zones": ["secubox.in", "inutile.org"]}]


def test_la_couverture_classe_gere_gerable_externe(m):
    r = m.calcule_couverture(
        ["a.secubox.in", "b.secubox.in", "www.gk2.net", "blog.cybermind.fr", "x.exemple.org", "surf-*.surf-*"],
        PROVIDERS,
        {"gk2.net": "ovh", "cybermind.fr": "gandi", "exemple.org": "autre"})
    par = {d["domaine"]: d for d in r["domaines"]}
    assert set(par) == {"secubox.in", "gk2.net", "cybermind.fr", "exemple.org"}, "le joker surf-* n'est pas un domaine"
    assert par["secubox.in"]["statut"] == "gere" and par["secubox.in"]["fournisseur"] == "gk2-gandi" and par["secubox.in"]["vhosts"] == 2
    assert par["gk2.net"]["statut"] == "gerable" and par["gk2.net"]["hebergeur_ns"] == "ovh" and par["gk2.net"]["fournisseur_a_ajouter"] == "ovh"
    assert par["cybermind.fr"]["statut"] == "gerable" and par["cybermind.fr"]["fournisseur_a_ajouter"] == "gandi"
    assert par["exemple.org"]["statut"] == "externe" and par["exemple.org"]["fournisseur_a_ajouter"] is None
    assert r["resume"] == {"vhosts": 5, "domaines": 4, "geres": 1, "gerables": 2, "externes": 1}


def test_la_couverture_liste_les_zones_des_fournisseurs_sans_vhost(m):
    r = m.calcule_couverture(["a.secubox.in"], PROVIDERS, {})
    assert r["zones_sans_vhost"] == [{"zone": "inutile.org", "fournisseur": "gk2-gandi", "type": "gandi"}]


def test_la_zone_la_plus_specifique_l_emporte(m):
    p = [{"id": "g1", "name": "gandi", "type": "gandi", "zones": ["secubox.in"]},
         {"id": "o1", "name": "ovh", "type": "ovh", "zones": ["lab.secubox.in"]}]
    r = m.calcule_couverture(["x.lab.secubox.in", "y.secubox.in"], p, {})
    par = {d["domaine"]: d for d in r["domaines"]}
    assert par["lab.secubox.in"]["fournisseur"] == "ovh" and par["secubox.in"]["fournisseur"] == "gandi"


def test_hebergeur_ns_reconnait_les_fournisseurs_supportes(m):
    assert m.hebergeur_ns(["ns-113-b.gandi.net.", "ns-1-a.gandi.net."]) == "gandi"
    assert m.hebergeur_ns(["dns12.ovh.net.", "ns12.ovh.net."]) == "ovh"
    assert m.hebergeur_ns(["ada.ns.cloudflare.com."]) == "cloudflare"
    assert m.hebergeur_ns(["ns-1.awsdns-01.org."]) == "route53"
    assert m.hebergeur_ns(["ns1.exemple.org."]) == "autre"
    assert m.hebergeur_ns([]) is None


def test_domaines_des_vhosts_lus_dans_haproxy_toml(m, tmp_path):
    toml = tmp_path / "haproxy.toml"
    toml.write_text('[vhosts.a]\ndomain = "a.secubox.in"\nenabled = true\n[vhosts.b]\ndomain = "b.gk2.net"\nenabled = false\n'
                    '[vhosts.c]\ndomain = "surf-*.surf-*"\n[globals]\ndomain = "ignore.example"\n')
    assert m.domaines_des_vhosts(toml) == ["a.secubox.in"], "désactivé et joker exclus ; seul [vhosts.*] compte"
    assert m.domaines_des_vhosts(tmp_path / "absent.toml") == []


def test_la_route_couverture_croise_vhosts_fournisseurs_et_ns(m, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    toml = tmp_path / "haproxy.toml"
    toml.write_text('[vhosts.a]\ndomain = "a.secubox.in"\n[vhosts.b]\ndomain = "www.gk2.net"\n')
    monkeypatch.setattr(m, "HAPROXY_TOML", toml)
    (tmp_path / "providers.json").write_text(json.dumps({"providers": [
        {"id": "g1", "name": "gk2-gandi", "provider": "gandi", "enabled": True, "credentials": {"api_key": "SECRET-A-NE-PAS-RENDRE"}}]}))

    class Faux:
        async def list_domains(self):
            return [{"name": "secubox.in", "id": "secubox.in"}]
    monkeypatch.setattr(m, "get_adapter", lambda t, c: Faux())

    async def faux_ns(apex):
        return {"secubox.in": "gandi", "gk2.net": "ovh"}.get(apex)
    monkeypatch.setattr(m, "ns_hebergeur_de", faux_ns)
    m.stats_cache.clear()
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "t"}
    r = TestClient(m.app).get("/couverture")
    assert r.status_code == 200
    d = r.json()
    assert d["resume"]["geres"] == 1 and d["resume"]["gerables"] == 1
    assert [f["name"] for f in d["fournisseurs"]] == ["gk2-gandi"] and d["fournisseurs"][0]["zones"] == 1
    assert d["ovh_configure"] is False
    assert "SECRET-A-NE-PAS-RENDRE" not in r.text, "jamais une clé d'API dans une réponse"


# ── clés d'API : jamais lisibles par tous ──────────────────────────────────────

def test_providers_json_est_ecrit_en_0600(m, tmp_path):
    f = tmp_path / "providers.json"
    m._save_json(f, {"providers": []}, prive=True)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    m._save_json(f, {"providers": [1]}, prive=True)                   # réécriture : le mode reste
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_toutes_les_ecritures_de_providers_json_sont_privees():
    appels = re.findall(r"_save_json\(PROVIDERS_FILE[^)]*\)", SRC)
    assert appels and all("prive=True" in a for a in appels), appels


# ── page ───────────────────────────────────────────────────────────────────────

def test_la_page_montre_les_vhosts_et_les_domaines_geres_et_gerables():
    assert 'data-t="couverture"' in PAGE and 'id="t-couverture"' in PAGE
    assert "Vhosts et domaines" in PAGE and "/couverture" in PAGE
    for mot in ("Géré", "Gérable", "Externe"):
        assert mot in PAGE
    for interdit in ("innerHTML", "confirm(", "alert(", "onclick="):
        assert interdit not in PAGE


def test_le_postinst_et_le_demarrage_resserrent_un_providers_json_existant():
    postinst = (COMP / "debian" / "postinst").read_text()
    assert "chmod 0600 /var/lib/secubox/dns-provider/providers.json" in postinst
    assert "os.chmod(PROVIDERS_FILE, 0o600)" in SRC


# ── #3072 : le journal d'audit nomme le compte, pas « system » ────────────────

def test_journal_d_audit_attribue_l_action_au_compte(tmp_path, monkeypatch):
    import importlib.util
    from fastapi.testclient import TestClient
    spec = importlib.util.spec_from_file_location("dnsprov_3072", Path(__file__).resolve().parents[1] / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "AUDIT_LOG_FILE", tmp_path / "audit.log")
    monkeypatch.setattr(m, "CONFIG_FILE", tmp_path / "config.json", raising=False)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "gk2", "role": "admin"}
    c = TestClient(m.app)
    c.post("/config", json={"default_ttl": 600})
    lignes = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert lignes and all(x["user"] == "gk2" for x in lignes)


def test_audit_hors_requete_reste_system(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("dnsprov_3072b", Path(__file__).resolve().parents[1] / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "AUDIT_LOG_FILE", tmp_path / "audit.log")
    m._audit_log("demarrage", {})
    assert json.loads((tmp_path / "audit.log").read_text())["user"] == "system"
