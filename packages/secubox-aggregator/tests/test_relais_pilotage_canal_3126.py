# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126, L2 « Agir », tâche 0 (M6) : le relais générique /api/v1/<nom>/… → /run/secubox/<nom>.sock ne joint JAMAIS le canal des box.

`pilotage-canal.sock` n'est servie qu'à l'écouteur nginx du tunnel, qui pose l'identité (X-Real-IP) et le marqueur de tunnel ; relayée ici,
un client choisirait l'une et l'autre. Avant ce correctif, seul le groupe www-data de la socket fermait ce chemin. Le faux canal compte les
connexions reçues : le relais doit rendre 404 sans jamais l'ouvrir. Un module ordinaire sert de témoin (le relais fonctionne)."""
from __future__ import annotations

import socketserver
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aggregator import main as agg


class _Compteur(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, chemin: str):
        self.connexions: list[int] = []
        serveur = self

        class _Gestionnaire(socketserver.BaseRequestHandler):
            def handle(self):
                serveur.connexions.append(1)
                self.request.recv(65536)
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n"
                                     b"Connection: close\r\n\r\n{\"ok\":true}")

        super().__init__(chemin, _Gestionnaire)


@pytest.fixture
def banc(tmp_path: Path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(agg, "RUN_DIR", str(run))
    monkeypatch.setattr(agg, "CONFIG_FILE", tmp_path / "absent.toml")
    sockets = {}
    for nom in ("pilotage-canal", "demo"):
        s = _Compteur(str(run / f"{nom}.sock"))
        threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        sockets[nom] = s
    try:
        yield TestClient(agg._build_app()), sockets
    finally:
        for s in sockets.values():
            s.shutdown()
            s.server_close()


def test_agregateur_ne_relaie_pas_pilotage_canal(banc):
    client, sockets = banc
    # témoin : un module à socket dédiée ordinaire est bien relayé
    assert client.get("/api/v1/demo/etat").status_code == 200 and len(sockets["demo"].connexions) == 1
    # ce qu'enverrait un client qui se fait passer pour une box passée par le tunnel
    forge = {"X-Real-IP": "10.10.0.10", "X-SecuBox-Pilotage-Tunnel": "1"}
    for methode, chemin in (("GET", "canal/v1/requetes?attente=0"), ("POST", "canal/v1/bonjour"), ("POST", "canal/v1/reponses"),
                            ("POST", "canal/v1/notifs"), ("GET", ""), ("OPTIONS", "canal/v1/requetes")):
        r = client.request(methode, f"/api/v1/pilotage-canal/{chemin}", headers=forge, json=[] if methode == "POST" else None)
        assert r.status_code == 404, (methode, chemin, r.status_code)
    assert sockets["pilotage-canal"].connexions == []          # la socket du canal n'a jamais été ouverte


def test_pilotage_canal_jamais_monte_meme_cite_dans_le_toml(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "pilotage-canal", "soc"]\n')
    monkeypatch.setattr(agg, "CONFIG_FILE", conf)
    assert agg._load_config()["modules"] == ["hub", "soc"]
