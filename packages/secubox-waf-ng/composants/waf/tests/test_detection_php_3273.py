# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Chantier #3273, tâche 9 : les filtres PHP de sbxwaf rendus visibles dans la page du WAF.

`/detections` déclare « Analyse des requêtes PHP » (mode detect, vhosts armés lus dans vhost_profiles.json) ;
`/php/signaux` compte les lignes du journal des menaces par famille sur 24 h, depuis un cache fichier
alimenté en tâche de fond : le journal n'est jamais relu à la requête."""
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MAINTENANT = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)


def _importer_waf():
    """api.main exige geoip2 (absent de l'environnement de test) : un faux module suffit."""
    try:
        import geoip2  # noqa: F401
    except ImportError:
        g = types.ModuleType("geoip2")
        g.database, g.errors = types.ModuleType("geoip2.database"), types.ModuleType("geoip2.errors")
        g.errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})
        sys.modules.update({"geoip2": g, "geoip2.database": g.database, "geoip2.errors": g.errors})
    from api import main as waf
    return waf


def _ligne(categorie, il_y_a_h=1, regle="x-001", host="nc.example", ip="8.8.4.4", severity="high", traits=None):
    d = {"timestamp": (MAINTENANT - timedelta(hours=il_y_a_h)).isoformat(), "client_ip": ip, "host": host,
         "method": "POST", "path": "/", "category": categorie, "severity": severity, "rule_id": regle,
         "action": "detect"}
    if traits:
        d["behavior_traits"] = traits
    return json.dumps(d)


def _journal(tmp_path, lignes):
    p = tmp_path / "waf-threats.log"
    p.write_text("\n".join(lignes) + "\n")
    return p


def _client(monkeypatch, tmp_path, surcharger_garde=True):
    from fastapi.testclient import TestClient
    waf = _importer_waf()
    from secubox_core.auth import require_lecture
    monkeypatch.setattr(waf, "PHP_SIGNAUX_CACHE", tmp_path / "php-signaux.json")
    monkeypatch.setattr(waf, "VHOST_PROFILES", tmp_path / "vhost_profiles.json")
    monkeypatch.setattr(waf, "_unite_active", lambda u: True)
    monkeypatch.setattr(waf, "_ports_leurres", lambda: [])
    waf.app.dependency_overrides.clear()
    if surcharger_garde:
        waf.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    return TestClient(waf.app), waf


@pytest.fixture(autouse=True)
def _nettoyer():
    yield
    sys.modules["api.main"].app.dependency_overrides.clear() if "api.main" in sys.modules else None


def test_detections_contient_analyse_php(monkeypatch, tmp_path):
    client, waf = _client(monkeypatch, tmp_path)
    (tmp_path / "vhost_profiles.json").write_text(json.dumps({
        "vhosts": {"nc.example": "nextcloud", "mail.example": "roundcube", "wiki.example": "dokuwiki"},
        "php_services": ["nextcloud", "roundcube"], "php_hotes": ["^blog\\."]}))
    journal = _journal(tmp_path, [_ligne("php2shell"), _ligne("php2shell"), _ligne("nextcloud"),
                                  _ligne("multipart-tronque", severity="audit")])
    monkeypatch.setattr(waf, "THREATS_LOG", str(journal))
    waf._rafraichir_php_signaux(MAINTENANT.timestamp())
    d = {e["id"]: e for e in client.get("/detections").json()["detections"]}
    e = d["analyse_php"]
    assert e["nom"] == "Analyse des requêtes PHP"
    assert e["mode"] == "detect"
    assert e["actif"] is True
    assert sorted(e["classes"]) == ["^blog\\.", "mail.example", "nc.example"]
    assert e["detail"] == "3 signaux en 24 h"   # la ligne d'état (audit) n'est pas un signal d'attaque


def test_detections_analyse_php_inconnue_sans_cache_ni_profil(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    e = {x["id"]: x for x in client.get("/detections").json()["detections"]}["analyse_php"]
    assert e["classes"] == [] and e["actif"] is False
    assert "inconnu" in e["detail"]


def test_php_signaux_compte_par_famille_sur_24h(monkeypatch, tmp_path):
    client, waf = _client(monkeypatch, tmp_path)
    journal = _journal(tmp_path, [
        _ligne("php2shell", regle="php2shell-001"), _ligne("php2shell", regle="php2shell-001"),
        _ligne("php2shell", regle="php2shell-002", host="blog.example"),
        _ligne("roundcube", regle="roundcube-001", host="mail.example"),
        _ligne("roundcube", il_y_a_h=30, regle="roundcube-001", host="mail.example"),   # hors fenêtre
        _ligne("nextcloud", regle="nextcloud-001", traits=["outil:curl", "autre"]),
        _ligne("php_requete", regle="php-001"),
        _ligne("sqli", regle="sqli-001"),                                               # autre famille : ignorée
        _ligne("multipart-tronque", severity="audit"),                                   # ligne d'état
        _ligne("capture-concurrence", severity="audit"),
        "pas du json", ""])
    monkeypatch.setattr(waf, "THREATS_LOG", str(journal))
    waf._rafraichir_php_signaux(MAINTENANT.timestamp())
    r = client.get("/php/signaux")
    assert r.status_code == 200
    j = r.json()
    assert j["fenetre_h"] == 24
    assert j["familles"] == {"php2shell": 3, "roundcube": 1, "nextcloud": 1, "php_requete": 1, "outil": 1}
    assert j["regles"] == {"php2shell-001": 2, "php2shell-002": 1, "roundcube-001": 1, "nextcloud-001": 1, "php-001": 1}
    assert j["vhosts"] == {"nc.example": 4, "blog.example": 1, "mail.example": 1}
    assert j["etat"] == "ok"


def test_php_signaux_n_expose_aucune_adresse_privee_ni_valeur(monkeypatch, tmp_path):
    client, waf = _client(monkeypatch, tmp_path)
    journal = _journal(tmp_path, [_ligne("php2shell", ip="local"), _ligne("php2shell", ip="192.168.1.5"),
                                  _ligne("php2shell", ip="8.8.4.4"), _ligne("php2shell", ip="8.8.4.4")])
    monkeypatch.setattr(waf, "THREATS_LOG", str(journal))
    waf._rafraichir_php_signaux(MAINTENANT.timestamp())
    j = client.get("/php/signaux").json()
    assert j["adresses"] == {"8.8.4.4": {"php2shell": 2}}
    assert "192.168.1.5" not in json.dumps(j) and "local" not in j["adresses"]


def test_php_signaux_exige_une_session(monkeypatch, tmp_path):
    client, waf = _client(monkeypatch, tmp_path, surcharger_garde=False)
    # Le conftest racine arme le mode tableau de bord LAN pour tous les tests : ici on le désarme, la route exige alors un jeton.
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    assert client.get("/php/signaux").status_code == 401
    from secubox_core.auth import require_lecture
    route = next(r for r in waf.app.routes if getattr(r, "path", "") == "/php/signaux")
    assert any(dep.call is require_lecture for dep in route.dependant.dependencies)


def test_php_signaux_lit_le_cache(monkeypatch, tmp_path):
    client, waf = _client(monkeypatch, tmp_path)
    cache = {"fenetre_h": 24, "calcule_a": MAINTENANT.timestamp(), "etat": "ok",
             "familles": {"php2shell": 7, "roundcube": 0, "nextcloud": 0, "php_requete": 0, "outil": 2},
             "regles": {"php2shell-001": 7}, "vhosts": {"nc.example": 7}, "adresses": {}}
    (tmp_path / "php-signaux.json").write_text(json.dumps(cache))
    appels = []
    monkeypatch.setattr(waf, "THREATS_LOG", str(tmp_path / "absent.log"))
    monkeypatch.setattr(waf._php_signaux, "calculer", lambda *a, **k: appels.append(a) or {})
    for _ in range(3):
        assert client.get("/php/signaux").json()["familles"]["php2shell"] == 7
    assert appels == []   # le journal n'est jamais relu sur le chemin de la requête


def test_php_signaux_inconnu_sans_cache(monkeypatch, tmp_path):
    client, _ = _client(monkeypatch, tmp_path)
    j = client.get("/php/signaux").json()
    assert j["etat"] == "inconnu" and j["familles"] is None
