# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2804 — proxypac étape 2 : l'opérateur accepte un CDN STATIQUE pour le cache de sbxmitm ; jamais une API.

La liste fermée existe des deux côtés (ici et dans cdncache.go) : un test les compare, car un écart ferait accepter ici ce que le moteur refuse
(ou pire, l'inverse)."""
import importlib
import re
from pathlib import Path

import pytest

from proxypac import cdn_cache

RACINE = Path(__file__).resolve().parents[4]
GO = RACINE / "secubox-toolbox-ng" / "cmd" / "sbxmitm" / "cdncache.go"


def test_la_liste_fermee_est_celle_du_moteur_go():
    src = GO.read_text()
    bloc = src.split("var cdnStatiques = map[string]bool{", 1)[1].split("}", 1)[0]
    assert set(re.findall(r'"([a-z0-9.-]+)":\s*true', bloc)) == set(cdn_cache.STATIQUES)


@pytest.mark.parametrize("hote", ["optimizationguide-pa.googleapis.com", "play.googleapis.com", "d111.cloudfront.net", "evil.cdnjs.cloudflare.com", "cdnjs.cloudflare.com.evil.net"])
def test_une_api_ou_un_faux_cdn_n_est_pas_cacheable(hote):
    assert not cdn_cache.cacheable(hote)


@pytest.mark.parametrize("hote", ["cdnjs.cloudflare.com", "FONTS.gstatic.com.", "unpkg.com"])
def test_un_cdn_statique_est_cacheable(hote):
    assert cdn_cache.cacheable(hote)


def test_ajouter_est_idempotent_trie_et_atomique(tmp_path):
    f = tmp_path / "hotes.txt"
    assert cdn_cache.ajouter(f, "unpkg.com") is True
    assert cdn_cache.ajouter(f, "cdnjs.cloudflare.com") is True
    assert cdn_cache.ajouter(f, "unpkg.com") is True
    assert f.read_text().splitlines() == ["cdnjs.cloudflare.com", "unpkg.com"]
    assert not list(tmp_path.glob(".*.tmp"))


def test_ajouter_refuse_un_hote_non_statique(tmp_path):
    f = tmp_path / "hotes.txt"
    assert cdn_cache.ajouter(f, "play.googleapis.com") is False
    assert not f.exists()


def test_retirer_et_lire(tmp_path):
    f = tmp_path / "hotes.txt"
    cdn_cache.ajouter(f, "unpkg.com")
    cdn_cache.ajouter(f, "cdn.jsdelivr.net")
    cdn_cache.retirer(f, "unpkg.com")
    assert cdn_cache.lire(f) == ["cdn.jsdelivr.net"]
    assert cdn_cache.lire(tmp_path / "absent.txt") == []


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXYPAC_RULES_DIR", str(tmp_path / "rules.d"))
    monkeypatch.setenv("PROXYPAC_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXYPAC_CANDIDATES", str(tmp_path / "candidates.json"))
    monkeypatch.setenv("PROXYPAC_REJETES", str(tmp_path / "rejetes.json"))
    monkeypatch.setenv("PROXYPAC_CDN_HOTES", str(tmp_path / "cdn-cache-hosts.txt"))
    from fastapi.testclient import TestClient
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app), tmp_path


def test_api_accepter_pour_le_cache_ecrit_la_liste_et_l_audit(tmp_path, monkeypatch):
    c, d = _client(tmp_path, monkeypatch)
    r = c.post("/candidate/cdnjs.cloudflare.com/cache")
    assert r.status_code == 200
    assert (d / "cdn-cache-hosts.txt").read_text().splitlines() == ["cdnjs.cloudflare.com"]
    assert "candidate-cache host=cdnjs.cloudflare.com" in (d / "audit.log").read_text()
    assert c.get("/cdn-cache").json() == {"hosts": ["cdnjs.cloudflare.com"]}


def test_api_refuse_une_api_google_avec_une_raison(tmp_path, monkeypatch):
    c, d = _client(tmp_path, monkeypatch)
    r = c.post("/candidate/optimizationguide-pa.googleapis.com/cache")
    assert r.status_code == 400 and "statique" in r.json()["detail"].lower()
    assert not (d / "cdn-cache-hosts.txt").exists()


def test_api_retirer_du_cache(tmp_path, monkeypatch):
    c, d = _client(tmp_path, monkeypatch)
    c.post("/candidate/unpkg.com/cache")
    assert c.delete("/cdn-cache/unpkg.com").status_code == 200
    assert c.get("/cdn-cache").json() == {"hosts": []}


def test_api_hote_invalide_refuse(tmp_path, monkeypatch):
    c, _ = _client(tmp_path, monkeypatch)
    assert c.post("/candidate/bad%20host/cache").status_code in (400, 404, 422)


def test_api_candidats_marques_cacheable_et_en_cache(tmp_path, monkeypatch):
    import json
    c, d = _client(tmp_path, monkeypatch)
    (d / "candidates.json").write_text(json.dumps([
        {"host": "cdnjs.cloudflare.com", "hits": 5, "clients": 2, "famille": "cloudflare"},
        {"host": "play.googleapis.com", "hits": 9, "clients": 3, "famille": "google"},
        {"host": "unpkg.com", "hits": 1, "clients": 1, "famille": "unpkg"}]))
    c.post("/candidate/unpkg.com/cache")
    par_hote = {x["host"]: x for x in c.get("/candidates").json()["candidates"]}
    assert (par_hote["cdnjs.cloudflare.com"]["cacheable"], par_hote["cdnjs.cloudflare.com"]["en_cache"]) == (True, False)
    assert (par_hote["play.googleapis.com"]["cacheable"], par_hote["play.googleapis.com"]["en_cache"]) == (False, False)
    assert (par_hote["unpkg.com"]["cacheable"], par_hote["unpkg.com"]["en_cache"]) == (True, True)
