# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1960 : `GET /lan_dns` (vue DNS des appareils du LAN d'après le fichier d'échange d'ad-guard) et enrichissement de `GET /usage`."""
import inspect
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # api importable
from fastapi.testclient import TestClient  # noqa: E402
from secubox_core.auth import require_jwt  # noqa: E402
from api import main as m  # noqa: E402

APPAREIL = {"nom": "TV fb5b", "mac": "38:07:16:94:fb:5b", "adresses": ["192.168.1.128", "2a01:e0a::7"], "mode": "auto", "origine": "auto", "requetes": 50, "bloquees": 10, "domaines": 3,
            "services": [{"organisation": "France Télévisions", "type": "contenu", "requetes": 40, "bloquees": 0}, {"organisation": "FreeWheel", "type": "publicite", "requetes": 10, "bloquees": 10}],
            "types": {"contenu": 40, "publicite": 10}}


def feed(genere=None, appareils=None, version=1):
    return {"version": version, "genere": int(time.time()) if genere is None else genere, "fenetre": "jour courant (UTC)", "appareils": [APPAREIL] if appareils is None else appareils}


@pytest.fixture
def monde(tmp_path, monkeypatch):
    listes = tmp_path / "listes"
    listes.mkdir()
    (listes / "services.txt").write_text("fwmrm.net FreeWheel publicite\nftven.fr France_Télévisions contenu\nconnu.example.org Autre contenu\n")
    (listes / "advertising.txt").write_text("7cd77.v.fwmrm.net\n")
    regles = tmp_path / "rules.json"
    regles.write_text(json.dumps({"_meta": {}, "rules": [{"id": "app-connu", "application": "Connu", "usage": "streaming", "confidence": 90, "match": {"domain_suffix": ["connu.example.org"]}}]}))
    monkeypatch.setattr(m, "ADGUARD_FEED", tmp_path / "dpi-feed.json")
    monkeypatch.setattr(m, "ADGUARD_LISTES", listes)
    monkeypatch.setattr(m, "DPI_RULES_FILE", regles)
    monkeypatch.setattr(m, "_rules_mtime", -1.0)
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "root"}
    yield tmp_path
    m.app.dependency_overrides.pop(require_jwt, None)


def ecrire(monde, contenu):
    (monde / "dpi-feed.json").write_text(json.dumps(contenu) if not isinstance(contenu, str) else contenu)


def lan_dns():
    return TestClient(m.app).get("/lan_dns").json()


def test_sans_jeton_la_route_est_refusee():
    m.app.dependency_overrides.pop(require_jwt, None)
    assert TestClient(m.app).get("/lan_dns").status_code in (401, 403)


def test_la_route_est_synchrone():
    assert not inspect.iscoroutinefunction(m.lan_dns)


def test_fichier_absent_perime_corrompu_enorme_ou_lien_symbolique(monde):
    assert lan_dns() == {"disponible": False, "raison": "absent"}
    ecrire(monde, feed(genere=int(time.time()) - 2000))
    j = lan_dns()
    assert j["disponible"] is False and j["raison"] == "périmé" and j["age_s"] >= 2000
    ecrire(monde, "{corrompu")
    assert lan_dns()["raison"] == "illisible"
    ecrire(monde, feed(version=99))
    assert lan_dns()["raison"] == "illisible"
    (monde / "dpi-feed.json").write_text(" " * (3 * 1024 * 1024))
    assert lan_dns()["raison"] == "illisible"
    (monde / "dpi-feed.json").unlink()
    (monde / "ailleurs.json").write_text(json.dumps(feed()))
    os.symlink(monde / "ailleurs.json", monde / "dpi-feed.json")
    assert lan_dns()["disponible"] is False                                          # lien symbolique refusé : jamais suivi


def test_fichier_valide_rend_les_appareils_et_l_age(monde):
    ecrire(monde, feed())
    j = lan_dns()
    assert j["disponible"] is True and j["age_s"] <= 5 and j["fenetre"] == "jour courant (UTC)"
    a = j["appareils"][0]
    assert a["nom"] == "TV fb5b" and a["requetes"] == 50 and a["services"][1]["organisation"] == "FreeWheel" and a["types"] == {"contenu": 40, "publicite": 10}


def test_champs_bornes_et_entrees_mal_formees_ecartees(monde):
    hostile = dict(APPAREIL, nom="<img src=x onerror=alert(1)>" + "x" * 500, mac="m" * 99, adresses=["a" * 200] * 30, mode="x" * 99,
                   services=[{"organisation": "o" * 500, "type": "t" * 99, "requetes": 1, "bloquees": 0}] * 40, types={f"t{i}": i for i in range(50)})
    ecrire(monde, feed(appareils=[hostile, "pas un dict", {"nom": 5}, None, dict(APPAREIL, requetes="beaucoup")]))
    j = lan_dns()
    assert j["disponible"] is True and len(j["appareils"]) == 1
    a = j["appareils"][0]
    assert a["nom"].startswith("<img") and len(a["nom"]) <= 60 and len(a["mac"]) <= 17 and len(a["adresses"]) <= 8 and all(len(x) <= 64 for x in a["adresses"])
    assert len(a["services"]) <= 10 and all(len(s["organisation"]) <= 80 for s in a["services"]) and len(a["types"]) <= 12      # l'échappement HTML est du côté de la page


def usage_live(*noms):
    async def _live(path, default):
        return {"usages": [{"name": "streaming", "bytes": 5}], "unknown": [{"name": n, "flows": 1, "bytes": 10, "pct": 0.0} for n in noms]}
    return _live


def test_usage_est_enrichi_quand_les_donnees_d_ad_guard_existent(monde, monkeypatch):
    monkeypatch.setattr(m, "_sbxdpi_get", usage_live("7cd77.v.fwmrm.net", "inconnu.example.org", "k7.ftven.fr"))
    j = TestClient(m.app).get("/usage").json()
    par = {x["name"]: x for x in j["unknown"]}
    assert par["7cd77.v.fwmrm.net"]["etiquette"]["type"] == "publicite" and par["7cd77.v.fwmrm.net"]["etiquette"]["categorie"] == "advertising"
    assert par["k7.ftven.fr"]["etiquette"]["organisation"] == "France Télévisions" and "etiquette" not in par["inconnu.example.org"]
    assert j["adguard"] == {"etiquetes": 2, "total": 3} and j["usages"] == [{"name": "streaming", "bytes": 5}]


def test_la_regle_du_dpi_gagne_dans_usage(monde, monkeypatch):
    monkeypatch.setattr(m, "_sbxdpi_get", usage_live("x.connu.example.org"))
    par = {x["name"]: x for x in TestClient(m.app).get("/usage").json()["unknown"]}
    assert "etiquette" not in par["x.connu.example.org"]                                # le DPI connaît ce nom : aucune étiquette d'ad-guard


def test_usage_inchange_sans_donnees_d_ad_guard(monde, monkeypatch):
    monkeypatch.setattr(m, "ADGUARD_LISTES", monde / "absent")
    monkeypatch.setattr(m, "_sbxdpi_get", usage_live("7cd77.v.fwmrm.net"))
    j = TestClient(m.app).get("/usage").json()
    assert "adguard" not in j and "etiquette" not in j["unknown"][0]


def test_les_donnees_d_ad_guard_rechargees_quand_le_fichier_change(monde, monkeypatch):
    monkeypatch.setattr(m, "_sbxdpi_get", usage_live("nouveau.example.org"))
    assert "etiquette" not in TestClient(m.app).get("/usage").json()["unknown"][0]
    time.sleep(0.01)
    (monde / "listes" / "services.txt").write_text("example.org Exemple contenu\n")
    os.utime(monde / "listes" / "services.txt", (time.time() + 5, time.time() + 5))
    assert TestClient(m.app).get("/usage").json()["unknown"][0]["etiquette"]["organisation"] == "Exemple"
