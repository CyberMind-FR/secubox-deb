# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tranche C (#3990) : pont SearXNG, outils bornés, politique, planificateur, recherche et digest RÉELS.

Le pont est lancé pour de vrai (processus, socket Unix) devant la vraie SearXNG du POC ; la recherche et le
digest parlent au vrai llama-server. Sans eux, ces tests sont sautés en le disant.
"""
import json
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

pytest.importorskip("openjarvis", reason="OpenJarvis absent : tests à lancer avec /opt/secubox-ai-agents/venv/bin/python (README)")

from conftest import PAQUET, moteur_present  # noqa: E402

PONT = PAQUET / "sbin/secubox-ai-pont-searxng"


def searxng_presente() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 8888), timeout=1):
            return True
    except OSError:
        return False


reel_web = pytest.mark.skipif(not searxng_presente(), reason="SearXNG du POC absente : test réel impossible ici")
reel_tout = pytest.mark.skipif(not (searxng_presente() and moteur_present()),
                               reason="SearXNG ou llama-server absent : test réel impossible ici")


@pytest.fixture
def pont(tmp_path):
    chemin = tmp_path / "pont.sock"
    p = subprocess.Popen(["/usr/bin/python3", "-I", str(PONT), str(chemin)])
    for _ in range(50):
        if chemin.exists():
            break
        time.sleep(0.1)
    yield str(chemin)
    p.terminate()
    p.wait(5)


@pytest.fixture
def client_c(jeton, pont, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_AGENTS_PONT", pont)
    import importlib

    from fastapi.testclient import TestClient

    import agents.app as module
    module = importlib.reload(module)
    with TestClient(module.app) as c:
        c.headers["Authorization"] = f"Bearer {jeton}"
        yield c


def _get(pont_sock, chemin):
    import httpx
    with httpx.Client(transport=httpx.HTTPTransport(uds=pont_sock), base_url="http://pont", timeout=30) as c:
        return c.get(chemin)


# --- pont --------------------------------------------------------------------------------------------

def test_pont_refuse_tout_sauf_search(pont):
    assert _get(pont, "/").status_code == 404
    assert _get(pont, "/search").status_code == 422                     # q requis
    assert _get(pont, "/search?q=x&categories=files").status_code == 422
    assert _get(pont, "/search?q=x&time_range=year").status_code == 422
    assert _get(pont, "/search?q=" + "a" * 301).status_code == 422
    assert _get(pont, "/http://exemple.org/search?q=x").status_code == 404


def test_pont_destination_unique_codee_en_dur():
    t = PONT.read_text()
    assert 'SEARXNG = "http://127.0.0.1:8888/search"' in t
    assert t.count("urllib.request.Request(") == 1 and "SEARXNG +" in t   # aucune URL venue de la requête


@reel_web
def test_pont_reel_liens_http_seulement(pont):
    r = _get(pont, "/search?q=debian%20trixie")
    assert r.status_code == 200
    res = r.json()["resultats"]
    assert res and all(x["url"].startswith(("http://", "https://")) and "://" in x["url"] for x in res)
    assert all(not x["url"].startswith("http:///") for x in res)


# --- outils et politique (ToolExecutor réel d'OpenJarvis) -----------------------------------------------

def test_outils_refuses_sans_capacite_accordee(pont, tmp_path):
    from openjarvis.core.types import ToolCall
    from openjarvis.tools._stubs import ToolExecutor

    from agents.outils import Contexte, RechercheWeb
    from agents.travaux import politique
    ctx = Contexte(echeance=time.monotonic() + 60)
    ex = ToolExecutor([RechercheWeb(ctx, pont)], capability_policy=politique(), agent_id="assistant")
    r = ex.execute(ToolCall(id="1", name="web_search", arguments=json.dumps({"query": "debian"})))
    assert not r.success and ctx.appels == 0                         # refusé AVANT l'appel
    assert politique().check("recherche", "code:execute") is False
    assert politique().check("recherche", "file:write") is False


def test_bornes_appels_echeance_annulation(pont):
    from agents.outils import Contexte, RechercheWeb
    ctx = Contexte(echeance=time.monotonic() + 60, appels_max=0)
    assert "au plus 0" in RechercheWeb(ctx, pont).execute(query="x").content
    ctx = Contexte(echeance=time.monotonic() - 1)
    assert "délai" in RechercheWeb(ctx, pont).execute(query="x").content
    ctx = Contexte(echeance=time.monotonic() + 60)
    ctx.annule.set()
    assert "annulé" in RechercheWeb(ctx, pont).execute(query="x").content


# --- planificateur (TaskScheduler + SchedulerStore réels) ------------------------------------------------

def test_planificateur_bornes_et_gestes(client_c):
    c = client_c
    assert c.post("/planificateur", json={"question": "état de Debian", "type": "interval", "valeur": "60"}
                  ).status_code == 422                                  # moins d'une heure
    assert c.post("/planificateur", json={"question": "x y z", "type": "once",
                                          "valeur": "2020-01-01T00:00:00+00:00"}).status_code == 422
    ids = []
    for i in range(10):
        r = c.post("/planificateur", json={"question": f"question {i}", "type": "interval", "valeur": "86400"})
        assert r.status_code == 200, r.text
        ids.append(r.json()["id"])
    assert c.post("/planificateur", json={"question": "onzième", "type": "interval", "valeur": "86400"}
                  ).status_code == 422                                  # 10 actives au plus
    assert c.post(f"/planificateur/{ids[0]}/pause").status_code == 200
    assert c.post(f"/planificateur/{ids[0]}/reprendre").status_code == 200
    assert c.delete(f"/planificateur/{ids[1]}").status_code == 200
    taches = c.get("/planificateur").json()["taches"]
    assert ids[1] not in [t["id"] for t in taches] and len(taches) == 9
    assert c.delete("/planificateur/zzz").status_code == 404


def test_planificateur_persistant(client_c, tmp_path):
    c = client_c
    r = c.post("/planificateur", json={"question": "persistance", "type": "interval", "valeur": "7200"})
    ident = r.json()["id"]
    from agents.travaux import Planificateur
    base = Path(os.environ["SECUBOX_AI_AGENTS_ETAT"])
    autre = Planificateur(base, travaux=None)                          # seconde ouverture de la même base
    assert ident in [t["id"] for t in autre.lister()]
    autre.store.close()


def test_digest_reglage_et_tache_cron(client_c):
    c = client_c
    assert c.put("/digest", json={"actif": True, "heure": "25:00", "themes": ["x"]}).status_code == 422
    assert c.put("/digest", json={"actif": True, "heure": "07:30", "themes": []}).status_code == 422
    r = c.put("/digest", json={"actif": True, "heure": "06:45", "themes": ["cybersécurité", "Debian"]})
    assert r.status_code == 200
    dig = [t for t in c.get("/planificateur").json()["taches"] if t["metadata"].get("genre") == "digest"]
    assert len(dig) == 1 and dig[0]["schedule_value"] == "45 6 * * *" and dig[0]["metadata"]["timezone"] == "Europe/Paris"
    c.put("/digest", json={"actif": False, "heure": "06:45", "themes": ["Debian"]})
    assert not [t for t in c.get("/planificateur").json()["taches"] if t["metadata"].get("genre") == "digest"]


# --- travaux réels ---------------------------------------------------------------------------------------

def _attendre(c, ident, s=420):
    fin = time.time() + s
    while time.time() < fin:
        t = c.get(f"/travaux/{ident}").json()
        if t["etat"] != "en_cours":
            return t
        time.sleep(3)
    raise AssertionError("travail trop long")


@reel_tout
def test_recherche_reelle_sources_citees_et_en_memoire(client_c):
    c = client_c
    r = c.post("/recherche", json={"question": "Quelle est la date de sortie de Debian 13 trixie ?"})
    assert r.status_code == 200
    ident = r.json()["travail"]
    assert c.post("/recherche", json={"question": "une autre en même temps"}).status_code == 409   # un à la fois
    t = _attendre(c, ident)
    assert t["etat"] == "fini", t
    assert t["verifie"] is True and t["sources"] and all(s["url"].startswith("http") for s in t["sources"])
    assert "2025" in t["resultat"]
    mem = c.get("/memoire/recherche", params={"q": "Debian trixie sortie"}).json()
    assert mem["documents"] == 1 and "Sources" in mem["resultats"][0]["texte"]


@reel_tout
def test_digest_reel_lecture_seule(client_c):
    c = client_c
    c.put("/digest", json={"actif": False, "heure": "07:00", "themes": ["Debian"]})
    ident = c.post("/digest/maintenant").json()["travail"]
    t = _attendre(c, ident)
    assert t["etat"] == "fini", t
    assert t["sources"] and t["resultat"]
    h = c.get("/digest").json()["historique"]
    assert h and h[0]["texte"] == t["resultat"]


@reel_tout
def test_annulation_d_un_travail_reel(client_c):
    c = client_c
    ident = c.post("/recherche", json={"question": "Quelles sont les nouveautés de Linux 6.12 ?"}).json()["travail"]
    assert c.post(f"/travaux/{ident}/annuler").status_code == 200
    t = _attendre(c, ident)
    assert t["etat"] == "annule"
    assert c.get("/memoire/recherche", params={"q": "Linux 6.12"}).json()["documents"] == 0


def test_consignes_installees_sans_entete_de_licence(tmp_path):
    from agents.travaux import installer_consignes
    installer_consignes(tmp_path)
    for f in ("agents/native_react/system_prompt.md", "prompts/personas/secubox.md"):
        t = (tmp_path / f).read_text()
        assert "SPDX" not in t and not t.startswith("<!--")
    assert "{tool_descriptions}" in (tmp_path / "agents/native_react/system_prompt.md").read_text()
