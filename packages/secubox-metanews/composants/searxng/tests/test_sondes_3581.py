# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — sondes bornées : sur gk2, `yacyctl status` dépassait les 15 s de l'API et rendait 500. Ici une sonde lente ne fait
jamais dépasser 5 s, ne lève jamais, et le relevé est partagé quelques secondes. Seule la boucle locale est utilisée."""
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient

from sbx_searxng import sondes as S


@pytest.fixture
def muet():
    """Un serveur qui accepte la connexion et ne répond jamais (SearXNG figé)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    gardes, fin = [], threading.Event()

    def boucle():
        s.settimeout(0.2)
        while not fin.is_set():
            try:
                c, _ = s.accept()
                gardes.append(c)
            except OSError:
                pass

    t = threading.Thread(target=boucle, daemon=True)
    t.start()
    yield s.getsockname()[1]
    fin.set()
    t.join(2)
    for c in gardes:
        c.close()
    s.close()


def _cfg(cfg, port, ip="127.0.0.1"):
    c = {"lxc": dict(cfg["lxc"]), "searxng": dict(cfg["searxng"])}
    c["lxc"]["ip"], c["searxng"]["port"] = ip, port
    return c


def test_sonde_tcp_distingue_refus_et_ouverture(muet):
    assert S.sonde_tcp("127.0.0.1", muet) == "ouvert"
    libre = socket.socket()
    libre.bind(("127.0.0.1", 0))
    port = libre.getsockname()[1]
    libre.close()
    assert S.sonde_tcp("127.0.0.1", port) == "refuse"


def test_searxng_fige_releve_borne(cfg, muet):
    t0 = time.monotonic()
    r = S.releve(_cfg(cfg, muet), api="running")
    assert time.monotonic() - t0 < 5
    assert r["conteneur"] == "running" and r["service"] == "degraded" and r["overall"] == "yellow"


def test_sonde_qui_ne_rend_jamais_la_main(cfg):
    lente = lambda *a: time.sleep(6) or "ouvert"       # noqa: E731 — au-delà de tout délai
    t0 = time.monotonic()
    r = S.releve(cfg, api="running", tcp=lente, sante=lente, dossier=lambda c: True, delai_total=1.0)
    assert time.monotonic() - t0 < 2
    assert r["conteneur"] == "unknown" and r["service"] == "unknown" and r["overall"] == "yellow"


def test_sonde_qui_leve_vaut_inconnu(cfg):
    def casse(*a):
        raise RuntimeError("boum")
    r = S.releve(cfg, api=casse, tcp=casse, sante=casse, dossier=casse, delai_total=1.0)
    assert (r["conteneur"], r["service"], r["api"]) == ("unknown", "unknown", "unknown")


@pytest.mark.parametrize("tcp,sante,dossier,attendu", [
    ("ouvert", True, True, ("running", "running", "green")),
    ("refuse", False, True, ("running", "stopped", "yellow")),
    ("injoignable", False, True, ("stopped", "stopped", "red")),
    ("injoignable", False, False, ("absent", "stopped", "red")),
])
def test_composition(cfg, tcp, sante, dossier, attendu):
    r = S.composer(cfg, tcp, sante, dossier, "running")
    assert (r["conteneur"], r["service"], r["overall"]) == attendu


def test_cache_partage_et_fichier(tmp_path):
    appels = []
    c = S.Cache(tmp_path / "etat.json", ttl=5)
    calcul = lambda: appels.append(1) or {"n": len(appels)}   # noqa: E731
    assert c.obtenir(calcul) == {"n": 1} and c.obtenir(calcul) == {"n": 1}
    assert (tmp_path / "etat.json").stat().st_mode & 0o777 == 0o640
    autre = S.Cache(tmp_path / "etat.json", ttl=5)               # nouveau processus : relu depuis le fichier
    assert autre.obtenir(calcul) == {"n": 1} and appels == [1]
    c.oublier()
    assert not (tmp_path / "etat.json").exists() and c.obtenir(calcul) == {"n": 2}


def test_cache_perime_recalcule(tmp_path):
    c = S.Cache(tmp_path / "etat.json", ttl=0.05)
    n = iter(range(10))
    a = c.obtenir(lambda: next(n))
    time.sleep(0.1)
    assert c.obtenir(lambda: next(n)) == a + 1


def test_api_status_jamais_500_meme_sonde_lente(api_mod, monkeypatch, tmp_path, cfg):
    from secubox_core.auth import require_lecture

    toml = tmp_path / "searxng.toml"
    toml.write_text('[lxc]\nip = "10.100.0.85"\n')
    monkeypatch.setattr(api_mod, "CONFIG", str(toml))
    monkeypatch.setattr(api_mod, "ETAT", S.Cache(tmp_path / "etat.json", ttl=10))
    vrai = S.releve
    monkeypatch.setattr(api_mod.S, "releve", lambda c, api: vrai(c, api=api, tcp=lambda *a: time.sleep(6),
                                                                  sante=lambda *a: time.sleep(6), delai_total=1.0))
    api_mod.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    try:
        client = TestClient(api_mod.app)
        t0 = time.monotonic()
        s, c = client.get("/status"), client.get("/components")
        assert time.monotonic() - t0 < 5
        assert s.status_code == 200 and c.status_code == 200
        assert s.json()["overall"] == "yellow" and [x["state"] for x in c.json()["components"]] == ["unknown", "unknown", "running"]
    finally:
        api_mod.app.dependency_overrides.clear()


def test_api_configuration_refusee_rend_200_rouge(api_mod, monkeypatch, tmp_path):
    from secubox_core.auth import require_lecture

    toml = tmp_path / "searxng.toml"
    toml.write_text('[lxc]\nip = "8.8.8.8"\n')
    monkeypatch.setattr(api_mod, "CONFIG", str(toml))
    monkeypatch.setattr(api_mod, "ETAT", S.Cache(None, ttl=10))
    api_mod.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    try:
        r = TestClient(api_mod.app).get("/status")
        assert r.status_code == 200 and r.json()["overall"] == "red" and "configuration refusée" in r.json()["erreur"]
    finally:
        api_mod.app.dependency_overrides.clear()
