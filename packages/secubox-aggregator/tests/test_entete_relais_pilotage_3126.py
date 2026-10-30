# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126, L5 tâche 1 : `X-SecuBox-Pilotage-Relais` ne traverse JAMAIS l'agrégateur.

Seul le relais local `sbx-pilotage-relais` pose cet en-tête, directement sur la socket d'un module ; avec lui,
`secubox_core.auth` reconnaît le jeton délégué du pilotage. L'agrégateur sert les modules de deux façons — montés
dans son processus (la requête arrive à leur garde avec les en-têtes du client) et relayés vers une socket dédiée —
et doit l'effacer sur les deux chemins, quelle que soit la casse, avant tout module."""
from __future__ import annotations

import socketserver
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from aggregator import main as agg

ENTETE = "X-SecuBox-Pilotage-Relais"


class _Echo(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Socket dédiée qui retient la requête brute reçue."""
    daemon_threads = True

    def __init__(self, chemin: str):
        self.recu: list[bytes] = []
        serveur = self

        class _G(socketserver.BaseRequestHandler):
            def handle(self):
                serveur.recu.append(self.request.recv(65536))
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
                                     b"Connection: close\r\n\r\n{}")

        super().__init__(chemin, _G)


def _sous_app() -> FastAPI:
    app = FastAPI()

    @app.get("/entetes")
    def entetes(request: Request):
        return {"noms": sorted(k.lower() for k in request.headers.keys())}

    return app


@pytest.fixture
def banc(tmp_path: Path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(agg, "RUN_DIR", str(run))
    monkeypatch.setattr(agg, "CONFIG_FILE", tmp_path / "absent.toml")
    monkeypatch.setattr(agg, "_load_app_from_path", lambda name: _sous_app())
    echo = _Echo(str(run / "demo.sock"))
    threading.Thread(target=echo.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    app = agg._build_app()
    agg._mount_module(app, "monte")
    try:
        yield TestClient(app), echo
    finally:
        echo.shutdown()
        echo.server_close()
        agg._MOUNTED.clear()


@pytest.mark.parametrize("nom", [ENTETE, ENTETE.lower(), ENTETE.upper()])
def test_module_monte_ne_recoit_pas_l_entete(banc, nom):
    client, _ = banc
    r = client.get("/api/v1/monte/entetes", headers={nom: "1", "X-Temoin": "1"})
    assert r.status_code == 200
    noms = r.json()["noms"]
    assert "x-temoin" in noms                                  # témoin : les autres en-têtes passent
    assert ENTETE.lower() not in noms


def test_socket_dediee_ne_recoit_pas_l_entete(banc):
    client, echo = banc
    r = client.get("/api/v1/demo/etat", headers={ENTETE: "1", "X-Temoin": "1"})
    assert r.status_code == 200 and len(echo.recu) == 1
    brut = echo.recu[0].lower()
    assert b"x-temoin" in brut
    assert ENTETE.lower().encode() not in brut


def test_entete_repete_efface_en_entier(banc):
    client, _ = banc
    r = client.get("/api/v1/monte/entetes", headers=[(ENTETE, "1"), (ENTETE, "2"), ("X-Temoin", "1")])
    assert ENTETE.lower() not in r.json()["noms"]
