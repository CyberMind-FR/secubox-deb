# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126, R16, R22) : le lanceur sert l'administration et le canal DANS LE MÊME processus, même boucle, lifespan "on" pour les deux."""
import asyncio
import importlib.machinery
import importlib.util
import os
import stat
from pathlib import Path

import pytest
from fastapi import FastAPI

ICI = Path(__file__).resolve().parents[1]
LANCEUR = ICI / "sbin" / "secubox-pilotage-api"


@pytest.fixture(scope="module")
def lanceur():
    chargeur = importlib.machinery.SourceFileLoader("lanceur_pilotage", str(LANCEUR))
    spec = importlib.util.spec_from_loader("lanceur_pilotage", chargeur)
    module = importlib.util.module_from_spec(spec)
    chargeur.exec_module(module)
    return module


def test_sockets_attendues(lanceur):
    assert lanceur.SOCK_ADMIN == "/run/secubox/pilotage.sock"
    assert lanceur.SOCK_CANAL == "/run/secubox/pilotage-canal.sock"


def test_deux_serveurs_lifespan_on(lanceur, tmp_path):
    s_admin = lanceur.socket_unix(str(tmp_path / "pilotage.sock"))
    s_canal = lanceur.socket_unix(str(tmp_path / "pilotage-canal.sock"))
    try:
        srv_admin, srv_canal = lanceur.serveurs(FastAPI(), FastAPI(), s_admin, s_canal)
        assert srv_admin.config.lifespan == "on" and srv_canal.config.lifespan == "on"
        assert s_admin.getsockname() == str(tmp_path / "pilotage.sock") and s_canal.getsockname() == str(tmp_path / "pilotage-canal.sock")
    finally:
        s_admin.close()
        s_canal.close()


def test_sockets_0660_jamais_0666(lanceur, tmp_path):
    for nom in ("pilotage.sock", "pilotage-canal.sock"):
        s = lanceur.socket_unix(str(tmp_path / nom))
        try:
            assert stat.S_IMODE(os.stat(tmp_path / nom).st_mode) == 0o660
        finally:
            s.close()


def test_socket_perimee_remplacee(lanceur, tmp_path):
    chemin = tmp_path / "pilotage.sock"
    chemin.write_text("reste d'un autre")
    s = lanceur.socket_unix(str(chemin))
    try:
        assert stat.S_ISSOCK(os.stat(chemin).st_mode)
    finally:
        s.close()


def test_cycle_de_vie_des_deux_applis_dans_la_meme_boucle(lanceur, tmp_path):
    """Les deux lifespans démarrent et s'arrêtent dans la boucle unique de servir() ; le premier arrêt arrête l'autre serveur."""
    trace = []

    def appli(nom):
        async def vie(app):
            trace.append((nom, "debut", id(asyncio.get_running_loop())))
            yield
            trace.append((nom, "fin", id(asyncio.get_running_loop())))
        from contextlib import asynccontextmanager
        return FastAPI(lifespan=asynccontextmanager(vie))

    async def essai():
        s_admin = lanceur.socket_unix(str(tmp_path / "a.sock"))
        s_canal = lanceur.socket_unix(str(tmp_path / "c.sock"))
        serveurs = []
        tache = asyncio.create_task(lanceur.servir(appli("admin"), appli("canal"), s_admin, s_canal, rendre=serveurs.extend))
        for _ in range(100):
            if len([t for t in trace if t[1] == "debut"]) == 2:
                break
            await asyncio.sleep(0.05)
        assert len([t for t in trace if t[1] == "debut"]) == 2
        # un arrêt demandé à un seul serveur arrête l'autre
        serveurs[0].should_exit = True
        await asyncio.wait_for(tache, 15)

    asyncio.run(essai())
    assert {t[0] for t in trace if t[1] == "debut"} == {"admin", "canal"} and {t[0] for t in trace if t[1] == "fin"} == {"admin", "canal"}
    assert len({t[2] for t in trace}) == 1                                 # une seule boucle


def test_lanceur_en_tete_et_sain():
    texte = LANCEUR.read_text()
    assert texte.startswith("#!/usr/bin/python3\n") and "LicenseRef-CMSD-1.0" in texte
    assert 'lifespan="off"' not in texte
