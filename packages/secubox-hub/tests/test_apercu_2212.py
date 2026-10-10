# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2212 : la Vue d'ensemble agrège des caches déjà en mémoire ; une donnée absente reste inconnue (None), jamais inventée."""
from api.apercu import construire_apercu


def it(i, espace, actif=True):
    return {"id": i, "name": i, "path": f"/{i}/", "espace": espace, "active": actif, "installed": True}


MENU = {"espaces": [{"id": "protection", "nom": "Protection", "icone": "🛡️", "items": [it("waf", "protection"), it("fw", "protection", False)]},
                    {"id": "systeme", "nom": "Système", "icone": "⚙️", "items": [it("backup", "systeme")]}]}
STATS = {"cpu_percent": 12.5, "memory_percent": 40.0, "disk_percent": 71.0, "load_avg": [0.5, 0.4, 0.3]}


def test_chaque_espace_compte_actifs_et_total_et_signale_les_arretes():
    a = construire_apercu(MENU, STATS, [], 3600)
    p = next(e for e in a["espaces"] if e["id"] == "protection")
    assert (p["actifs"], p["total"]) == (1, 2) and p["arretes"] == ["fw"] and p["etat"] == "degrade"
    s = next(e for e in a["espaces"] if e["id"] == "systeme")
    assert s["etat"] == "ok"


def test_le_etat_global_suit_le_pire_espace_et_les_ressources():
    assert construire_apercu(MENU, STATS, [], 1)["etat"] == "degrade"
    ok = {"espaces": [MENU["espaces"][1]]}
    assert construire_apercu(ok, STATS, [], 1)["etat"] == "ok"
    assert construire_apercu(ok, {**STATS, "disk_percent": 96.0}, [], 1)["etat"] == "critique"


def test_donnees_absentes_restent_inconnues():
    a = construire_apercu({}, {}, None, None)
    assert a["espaces"] == [] and a["ressources"]["cpu"] is None and a["uptime"] is None
    assert a["alertes"] == {"total": 0, "recentes": []} and a["etat"] == "inconnu"


def test_les_alertes_sont_comptees_et_bornees():
    notifs = [{"id": i, "title": f"n{i}", "level": "warning"} for i in range(12)]
    al = construire_apercu(MENU, STATS, notifs, 1)["alertes"]
    assert al["total"] == 12 and len(al["recentes"]) == 5


def test_les_ressources_sont_arrondies_et_la_charge_reprise():
    r = construire_apercu(MENU, STATS, [], 1)["ressources"]
    assert r == {"cpu": 12.5, "memoire": 40.0, "disque": 71.0, "charge": [0.5, 0.4, 0.3]}


def test_la_route_apercu_est_en_lecture_et_ne_touche_que_les_caches(monkeypatch):
    from fastapi.testclient import TestClient
    from api import main as hub
    from secubox_core.auth import require_lecture
    monkeypatch.setattr(hub, "_menu_cache", MENU)
    monkeypatch.setitem(hub._cache, "system_stats", STATS)
    appels = []
    monkeypatch.setattr(hub, "_ensure_bg", lambda: None)      # le démarreur des tâches de fond n'est pas l'objet du test
    monkeypatch.setattr(hub.subprocess, "run", lambda *a, **k: appels.append(a))
    hub.app.dependency_overrides[require_lecture] = lambda: {"sub": "t"}
    try:
        r = TestClient(hub.app).get("/api/v1/hub/apercu")
    finally:
        hub.app.dependency_overrides.clear()
    assert r.status_code == 200 and r.json()["etat"] == "degrade" and not appels


def test_la_route_apercu_refuse_sans_jeton_hors_mode_tableau_de_bord(monkeypatch):
    from fastapi.testclient import TestClient
    from api import main as hub
    from secubox_core import auth
    monkeypatch.setattr(hub, "_ensure_bg", lambda: None)
    monkeypatch.setattr(auth, "mode_tableau_de_bord_actif", lambda: False)
    assert TestClient(hub.app).get("/api/v1/hub/apercu").status_code in (401, 403)
