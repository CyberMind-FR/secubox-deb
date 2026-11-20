# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — façade SADE en lecture seule (OBSERVE) : routes /defense/*, sources muettes, confidentialité (#2201)."""
import copy
import json
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api import defense, main  # noqa: E402
from secubox_core.auth import require_lecture  # noqa: E402

DONNEES = Path(__file__).resolve().parent / "donnees" / "substrat"
LECTURE = {"Authorization": "Bearer lecteur", "Cookie": "secubox_session=abc"}
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _j(nom):
    return json.loads((DONNEES / nom).read_text(encoding="utf-8"))


class Substrat:
    """Faux `substrat.lire` : réponses par (source, chemin), sinon source muette ; journal des appels."""

    def __init__(self):
        self.rep = {}
        self.appels = []

    def __call__(self, source, chemin, entetes=None, delai=3.0):
        self.appels.append((source, chemin, dict(entetes or {})))
        cle = (source, chemin.split("?")[0])
        if cle in self.rep:
            return {"ok": True, "donnees": copy.deepcopy(self.rep[cle]), "erreur": None}
        return {"ok": False, "donnees": None, "erreur": "socket absent"}


@pytest.fixture
def faux(monkeypatch):
    f = Substrat()
    f.rep = {
        ("actord", "/actors"): _j("actord_actors.json"),
        ("actord", "/proposals"): _j("actord_proposals.json"),
        ("actord", "/overview"): {"activite_24h": [1, 2, 3] + [0] * 21, "recents": [
            {"ts": int(time.time()) - 60, "heure": "09:47", "acteur": "ACT-0001", "type": "sqli", "module": "waf", "score": 86},
            {"ts": int(time.time()) - 40 * 86400, "heure": "08:00", "acteur": "ACT-0002", "type": "scan", "module": "waf", "score": 31},
        ]},
        ("waf", "/bans"): _j("waf_bans.json"),
        ("waf", "/bans/history"): _j("waf_bans_history.json"),
        ("threatmesh", "/status"): _j("threatmesh_status.json"),
        ("threatmesh", "/peers"): {"node": "gk-exemple", "peers": [{"id": "p1", "name": "gk-pair", "address": "198.51.100.9"}]},
    }
    monkeypatch.setattr(defense.substrat, "lire", f)
    defense._CACHE.clear()
    return f


@pytest.fixture
def admin(monkeypatch):
    async def ok(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(defense, "require_jwt", ok)


@pytest.fixture
def client():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(require_lecture, None)


ROUTES = ["/defense/status", "/defense/threats", "/defense/threats/ACT-0001", "/defense/actions", "/defense/mesh",
          "/defense/incidents"]


@pytest.mark.parametrize("route", ROUTES)
def test_sans_jeton_401(faux, route, monkeypatch):
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")  # le harnais racine arme sinon le mode tableau de bord
    assert TestClient(main.app).get(route).status_code == 401


def test_status_nominal(faux, client, admin):
    j = client.get("/defense/status", headers=LECTURE).json()
    assert j["mode"] == "observe"
    assert (j["menaces_suivies"], j["blocages_actifs"], j["a_valider"]) == (2, 2, 0)
    assert (j["score_max"], j["bande_max"]) == (86, "usager")
    assert all(j["sources"][s]["ok"] is True for s in ("actord", "waf", "threatmesh"))


def test_threats_nominal_admin(faux, client, admin):
    m = client.get("/defense/threats", headers=LECTURE).json()["menaces"]
    assert [x["id"] for x in m] == ["ACT-0001", "ACT-0002"]
    assert m[0] == {"id": "ACT-0001", "source": "203.0.113.10, 203.0.113.11", "score": 86, "bande": "usager",
                    "phase": 3, "couches": ["automatisé", "ciblé"], "tentatives": 142, "vu": "09:47"}
    assert m[1]["source"] == "ACT-0002" and m[1]["bande"] == "reactive" and m[1]["phase"] == 2
    assert m[1]["tentatives"] is None


def test_threat_detail_chronologie(faux, client, admin):
    j = client.get("/defense/threats/ACT-0001", headers=LECTURE).json()
    assert j["id"] == "ACT-0001" and j["score"] == 86
    assert {c["capteur"] for c in j["chronologie"]} == {"actord", "waf"}
    assert all(set(c) == {"ts", "capteur", "libelle"} for c in j["chronologie"])
    assert client.get("/defense/threats/ACT-9999", headers=LECTURE).status_code == 404


def test_actions_nominal_admin(faux, client, admin):
    a = client.get("/defense/actions", headers=LECTURE).json()["actions"]
    assert [x["cible"] for x in a] == ["203.0.113.10", "198.51.100.7"]
    assert a[0] == {"ts": None, "cible": "203.0.113.10", "geste": "ban", "origine": "sbxwaf", "ttl_s": 3120,
                    "etat": "actif"}


def test_mesh_nominal(faux, client, admin):
    n = client.get("/defense/mesh", headers=LECTURE).json()["noeuds"]
    assert n[0]["nom"] == "gk-exemple" and n[0]["soi"] is True and n[0]["recus"] == 12
    assert n[1] == {"nom": "gk-pair", "soi": False, "emis": None, "recus": 12, "etat": "actif"}


def test_incidents_filtre_par_jours(faux, client, admin):
    i = client.get("/defense/incidents?jours=7", headers=LECTURE).json()["incidents"]
    assert len(i) == 1 and i[0]["score"] == 86 and i[0]["bande"] == "usager"
    assert len(client.get("/defense/incidents?jours=90", headers=LECTURE).json()["incidents"]) == 2


def test_substrat_muet_ne_rend_jamais_500(client):
    # aucun faux : les trois sockets réels sont absents dans l'environnement de test
    defense._CACHE.clear()
    for route in ROUTES:
        r = client.get(route, headers=LECTURE)
        assert r.status_code in (200, 404, 503), route
    j = client.get("/defense/status", headers=LECTURE).json()
    assert all(v["ok"] is False for v in j["sources"].values())
    assert j["menaces_suivies"] is None and j["evenements_24h"] is None and j["score_max"] is None
    assert j["blocages_actifs"] is None and j["a_valider"] is None and j["bande_max"] is None


def test_une_source_ko_les_autres_servies(faux, client, admin):
    del faux.rep[("waf", "/bans")]
    del faux.rep[("waf", "/bans/history")]
    j = client.get("/defense/actions", headers=LECTURE).json()
    assert j["sources"]["waf"]["ok"] is False and j["actions"] == []
    assert client.get("/defense/threats", headers=LECTURE).json()["menaces"][0]["tentatives"] is None


def test_score_absent_reste_affiche(faux, client, admin):
    for a in faux.rep[("actord", "/actors")]:
        a.pop("priority")
    m = client.get("/defense/threats", headers=LECTURE).json()["menaces"]
    assert len(m) == 2 and m[0]["bande"] == "inconnu" and m[0]["phase"] == 0 and m[0]["score"] is None


def test_lecteur_simple_ne_recoit_jamais_d_adresse(faux, client):
    # pas de `admin` : require_jwt réel refuse (aucun jeton valide) -> vue réduite
    for route in ("/defense/threats", "/defense/threats/ACT-0001", "/defense/actions", "/defense/mesh",
                  "/defense/status", "/defense/incidents"):
        corps = client.get(route, headers=LECTURE).text
        assert not IP.search(corps), (route, corps)
    m = client.get("/defense/threats", headers=LECTURE).json()["menaces"]
    assert m[0]["source"] == "ACT-0001"
    # /actors en vue réduite ; /proposals n'existe qu'en vue complète (404 sinon) : demandée, adresses jamais copiées
    assert not any(c[2].get("X-Sbx-Vue") for c in faux.appels if c[0] == "actord" and c[1] != "/proposals")
    assert all(c[2].get("X-Sbx-Vue") == "complete" for c in faux.appels if c[1] == "/proposals")


def test_vue_complete_et_identifiants_transmis(faux, client, admin):
    client.get("/defense/threats", headers=LECTURE)
    actors = [c for c in faux.appels if c[:2] == ("actord", "/actors")][0]
    assert actors[2].get("X-Sbx-Vue") == "complete"
    waf = [c for c in faux.appels if c[0] == "waf"][0]
    assert waf[2].get("Authorization") == "Bearer lecteur" and waf[2].get("Cookie") == "secubox_session=abc"
    assert not any(c[2].get("Authorization") for c in faux.appels if c[0] == "actord")


def test_cache_15s_et_double_tampon(faux, client, admin):
    client.get("/defense/status", headers=LECTURE)
    n = len(faux.appels)
    client.get("/defense/status", headers=LECTURE)
    assert len(faux.appels) == n  # servi par le cache
    # expiration du cache, puis sources muettes : le relevé complet de moins de 120 s est conservé
    for e in defense._CACHE.values():
        e["retry_at"] = 0.0
    faux.rep.clear()
    j = client.get("/defense/status", headers=LECTURE).json()
    assert j["menaces_suivies"] == 2 and j["sources"]["actord"]["ok"] is True
    # au-delà de 120 s, on dit la vérité
    for e in defense._CACHE.values():
        e["retry_at"] = 0.0
        e["complet_a"] -= 200
    j = client.get("/defense/status", headers=LECTURE).json()
    assert j["menaces_suivies"] is None and j["sources"]["actord"]["ok"] is False


def test_evenements_24h_depuis_overview(faux, client, admin):
    assert client.get("/defense/status", headers=LECTURE).json()["evenements_24h"] == 6


def test_compteurs_non_plafonnes_au_dela_de_200(faux, client, admin):
    faux.rep[("actord", "/actors")] = [{"id": f"ACT-{i:04d}", "priority": 96 if i % 2 else 10, "last": "09:00"}
                                       for i in range(300)]
    j = client.get("/defense/status", headers=LECTURE).json()
    assert j["menaces_suivies"] == 300 and j["a_valider"] == 150
    assert len(client.get("/defense/threats", headers=LECTURE).json()["menaces"]) == 200


def test_incident_bloque_seulement_si_ban_actif(faux, client, admin):
    def issues():
        defense._CACHE.clear()
        return [i["issue"] for i in client.get("/defense/incidents?jours=7", headers=LECTURE).json()["incidents"]]
    assert issues() == ["bloqué"]  # ACT-0001 : 203.0.113.10 est dans les bans actifs
    faux.rep[("waf", "/bans")] = {"bans": [], "total": 0}
    assert issues() == ["proposé"]  # proposition shadow, rien d'appliqué
    faux.rep[("actord", "/proposals")] = {"shadow": True, "propositions": []}
    assert issues() == ["observé"]


def test_detail_sert_le_tampon_quand_actord_tombe(faux, client, admin):
    assert client.get("/defense/threats/ACT-0001", headers=LECTURE).status_code == 200
    for e in defense._CACHE.values():
        e["retry_at"] = 0.0
    faux.rep.clear()
    r = client.get("/defense/threats/ACT-0001", headers=LECTURE)
    assert r.status_code == 200 and r.json()["id"] == "ACT-0001"
    defense._CACHE.clear()
    assert client.get("/defense/threats/ACT-0001", headers=LECTURE).status_code == 503


def test_id_hors_forme_refuse_sans_toucher_au_cache(faux, client, admin):
    assert client.get("/defense/threats/n-importe-quoi", headers=LECTURE).status_code == 404
    assert not defense._CACHE


def test_cache_evince_les_plus_anciennes_sans_tout_vider(faux, client, admin, monkeypatch):
    monkeypatch.setattr(defense, "CACHE_MAX", 3)
    client.get("/defense/status", headers=LECTURE)
    for i in range(1, 5):
        client.get(f"/defense/threats/ACT-000{i}", headers=LECTURE)
    assert 0 < len(defense._CACHE) <= 3


def test_cache_admin_puis_lecteur_simple_sans_adresse(faux, client, monkeypatch):
    async def ok(request, creds=None):
        return {"sub": "admin"}
    monkeypatch.setattr(defense, "require_jwt", ok)
    assert "203.0.113.10" in client.get("/defense/threats", headers=LECTURE).text
    async def non(request, creds=None):
        raise defense.HTTPException(status_code=403)
    monkeypatch.setattr(defense, "require_jwt", non)
    corps = client.get("/defense/threats", headers=LECTURE).text
    assert not IP.search(corps)
