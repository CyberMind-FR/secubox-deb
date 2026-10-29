# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3258 (audit R1) — `POST /system/service_control` : nom d'unité validé, unités protégées, audit.

CONSTAT : le nom d'unité passait tel quel à `systemctl` (un `-H…` ou `--…` devenait une option), n'importe quel
`secubox-*.service`, cœur compris, pouvait être arrêté, et rien n'était écrit dans `/var/log/secubox/audit.log`.
Parade : motif de la règle polkit, `systemctl <action> -- <unité>`, arrêt d'une unité protégée refusé (403),
une ligne d'audit par appel (autorisé, refusé, en échec), jamais la sortie de `systemctl`."""
import asyncio
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

PAQUETS = Path(__file__).resolve().parents[2]
SYSTEM = PAQUETS / "secubox-system"
sys.path.insert(0, str(PAQUETS.parent / "common"))

from secubox_core import unites  # noqa: E402  — le contrôle partagé (revue #3258, I2)

SORTIE_SECRETE = "SORTIE-DE-SYSTEMCTL-A-NE-PAS-AUDITER"


def charge_api():
    spec = importlib.util.spec_from_file_location("api_systeme_3258", SYSTEM / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def api():
    return charge_api()


class Res:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.stderr, self.returncode = out, err, rc


@pytest.fixture
def banc(api, monkeypatch, tmp_path):
    """Faux `subprocess.run` (aucun systemctl réel) et journal d'audit dans tmp_path."""
    etat = {"appels": [], "rc": 0, "audit": tmp_path / "audit.log"}

    def run(argv, *a, **k):
        etat["appels"].append(list(argv))
        if etat["rc"]:
            raise subprocess.CalledProcessError(etat["rc"], argv, output="", stderr=SORTIE_SECRETE)
        return Res(SORTIE_SECRETE, 0, "")

    monkeypatch.setattr(unites.subprocess, "run", run)
    monkeypatch.setattr(unites, "AUDIT_LOG", etat["audit"])
    return etat


def appelle(api, service, action, sub="admin"):
    return asyncio.run(api.service_control(api.ServiceAction(service=service, action=action), user={"sub": sub}))


def lignes_audit(banc):
    if not banc["audit"].exists():
        return []
    return [json.loads(ligne) for ligne in banc["audit"].read_text(encoding="utf-8").splitlines() if ligne.strip()]


# ---------- nom d'unité ----------

@pytest.mark.parametrize("nom", [
    "-H root@ailleurs", "--host=x", "--", "secubox-hub.service --no-block", "nginx.service", "nftables",
    "secubox-../../x.service", "secubox-hub.service;reboot", "secubox-hub.timer", "", "secubox-.service",
])
def test_nom_invalide_400_rien_d_execute_et_audite(api, banc, nom):
    with pytest.raises(HTTPException) as e:
        appelle(api, nom, "restart")
    assert e.value.status_code == 400
    assert banc["appels"] == [], "rien ne doit partir vers systemctl"
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "refuse" and a[0]["code"] == 400
    assert a[0]["acteur"] == "admin" and a[0]["action"] == "restart"


def test_action_invalide_400_rien_d_execute_et_audite(api, banc):
    with pytest.raises(HTTPException) as e:
        appelle(api, "secubox-dpi.service", "kill")
    assert e.value.status_code == 400 and banc["appels"] == []
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "refuse" and a[0]["code"] == 400


# ---------- unités protégées ----------

def test_stop_protege_403_rien_d_execute_et_audite(api, banc):
    with pytest.raises(HTTPException) as e:
        appelle(api, "secubox-auth.service", "stop")
    assert e.value.status_code == 403 and "unité protégée : arrêt refusé" in e.value.detail
    assert banc["appels"] == []
    a = lignes_audit(banc)
    assert len(a) == 1
    assert a[0]["resultat"] == "refuse" and a[0]["code"] == 403
    assert a[0]["unite"] == "secubox-auth.service" and a[0]["action"] == "stop" and a[0]["acteur"] == "admin"


def test_stop_protege_sans_suffixe_reste_refuse(api, banc):
    """La page envoie le nom nu (`secubox-hub`) : il est complété en `.service` AVANT le contrôle de protection."""
    with pytest.raises(HTTPException) as e:
        appelle(api, "secubox-hub", "stop")
    assert e.value.status_code == 403 and banc["appels"] == []


@pytest.mark.parametrize("action", ["restart", "start", "reload"])
def test_reparer_un_protege_reste_permis(api, banc, action):
    r = appelle(api, "secubox-waf-ng.service", action)
    assert r["success"] is True
    assert banc["appels"] == [["systemctl", action, "--", "secubox-waf-ng.service"]]
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "ok" and a[0]["unite"] == "secubox-waf-ng.service"


def test_stop_non_protege_execute_avec_double_tiret(api, banc):
    r = appelle(api, "secubox-dpi.service", "stop")
    assert r["success"] is True and r["service"] == "secubox-dpi.service"
    assert banc["appels"] == [["systemctl", "stop", "--", "secubox-dpi.service"]]
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "ok" and a[0]["action"] == "stop"


def test_nom_nu_de_la_page_complete_en_service(api, banc):
    """La page /system/ envoie `secubox-dpi` (test_system_aurora_2556) : systemctl le complétait déjà, on le fait avant de valider."""
    r = appelle(api, "secubox-dpi", "start")
    assert r["success"] is True
    assert banc["appels"] == [["systemctl", "start", "--", "secubox-dpi.service"]]


def test_echec_de_systemctl_audite_sans_sa_sortie(api, banc):
    banc["rc"] = 1
    r = appelle(api, "secubox-dpi.service", "restart")
    assert r["success"] is False
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "echec" and a[0]["unite"] == "secubox-dpi.service"
    assert SORTIE_SECRETE not in banc["audit"].read_text(encoding="utf-8")


def test_la_sortie_de_systemctl_n_entre_jamais_dans_l_audit(api, banc):
    appelle(api, "secubox-dpi.service", "restart")
    assert SORTIE_SECRETE not in banc["audit"].read_text(encoding="utf-8")


def test_delai_depasse_audite_en_echec(api, banc, monkeypatch):
    def lent(argv, *a, **k):
        banc["appels"].append(list(argv))
        raise subprocess.TimeoutExpired(argv, 30)
    monkeypatch.setattr(unites.subprocess, "run", lent)
    r = appelle(api, "secubox-dpi.service", "restart")
    assert r["success"] is False
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "echec"


# ---------- revue I3 : plus d'action par GET ----------
# GET /system/service_action EXÉCUTAIT l'action : le cookie de session (SameSite=None sous TLS) part avec une balise
# <img> d'un site tiers, require_jwt l'accepte et la garde d'origine ne contrôle jamais un GET. Une image pouvait
# démarrer secubox-systeme-eteindre.service.

@pytest.fixture
def client(api):
    from fastapi.testclient import TestClient
    api.app.dependency_overrides[api.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(api.app)
    api.app.dependency_overrides.clear()


def test_get_service_action_rend_405_sans_rien_executer(client, banc):
    r = client.get("/service_action", params={"service": "secubox-systeme-eteindre", "action": "start"})
    assert r.status_code == 405
    assert banc["appels"] == [] and lignes_audit(banc) == []


def test_aucune_route_get_n_execute_une_action_de_service(api):
    for route in api.app.routes:
        if getattr(route, "path", "") in ("/service_action", "/service_control"):
            assert "GET" not in route.methods, route.path


def test_post_service_action_execute_et_audite(client, banc):
    r = client.post("/service_action", json={"service": "secubox-dpi", "action": "restart"})
    assert r.status_code == 200 and r.json()["success"] is True
    assert banc["appels"] == [["systemctl", "restart", "--", "secubox-dpi.service"]]
    a = lignes_audit(banc)
    assert len(a) == 1 and a[0]["resultat"] == "ok" and a[0]["module"] == "system" and a[0]["acteur"] == "admin"


def test_post_service_action_garde_la_protection(client, banc):
    r = client.post("/service_action", json={"service": "secubox-auth", "action": "stop"})
    assert r.status_code == 403 and banc["appels"] == []


def test_la_vue_luci_system_hub_appelle_en_post():
    js = (SYSTEM / "www" / "luci-static" / "resources" / "system-hub" / "api.js").read_text(encoding="utf-8")
    assert "sbxFetch('/api/v1/system/service_action', params, 'POST')" in js
    assert "sbxFetch('/api/v1/system/service_action', params, 'GET')" not in js


# ---------- constantes ----------

def test_motif_identique_a_la_regle_polkit():
    regle = (SYSTEM / "polkit" / "50-secubox-system.rules").read_text()
    motif = re.search(r"/(\^secubox-[^/]+)/\.test", regle).group(1)
    assert unites.MOTIF_UNITE.pattern == motif


def test_les_unites_protegees_existent_dans_le_depot():
    """Une unité protégée qui n'existe pas serait une protection décorative : chacune doit être livrée par un paquet."""
    livrees = {p.name for p in PAQUETS.glob("secubox-*/debian/*.service")} | {p.name for p in PAQUETS.glob("secubox-*/systemd/*.service")}
    assert isinstance(unites.UNITES_PROTEGEES, frozenset)
    assert unites.UNITES_PROTEGEES <= livrees, sorted(unites.UNITES_PROTEGEES - livrees)
    for u in ("secubox-auth.service", "secubox-aggregator.service", "secubox-core.service", "secubox-waf-ng.service",
              "secubox-system.service", "secubox-haproxy.service", "secubox-hub.service", "secubox-dns-guard.service"):
        assert u in unites.UNITES_PROTEGEES, u


def test_les_ids_proteges_du_moteur_de_profils_sont_couverts():
    """PROTECTED_IDS (secubox-profiles/api/manifest.py) et UNITES_PROTEGEES restent synchrones : tout id protégé
    dont l'unité `secubox-<id>.service` est livrée doit être protégé ici aussi."""
    src = (PAQUETS / "secubox-profiles" / "api" / "manifest.py").read_text()
    ids = re.search(r"PROTECTED_IDS = frozenset\(\{([^}]*)\}\)", src).group(1)
    livrees = {p.name for p in PAQUETS.glob("secubox-*/debian/*.service")} | {p.name for p in PAQUETS.glob("secubox-*/systemd/*.service")}
    for i in re.findall(r'"([^"]+)"', ids):
        unite = f"secubox-{i}.service"
        if unite in livrees:
            assert unite in unites.UNITES_PROTEGEES, unite
