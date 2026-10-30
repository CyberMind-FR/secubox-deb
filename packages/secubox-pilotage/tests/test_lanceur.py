# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126, R16, R22) : le lanceur sert l'administration et le canal DANS LE MÊME processus, même boucle, lifespan "on" pour les deux."""
import asyncio
import importlib.machinery
import importlib.util
import os
import re
import socket
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


def _ecoute(chemin):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(chemin))
    s.listen(8)
    return s


def test_descripteurs_systemd(lanceur):
    """R26 : les sockets viennent de systemd (LISTEN_FDS, FileDescriptorName) ; PID, nombre et noms sont vérifiés."""
    ok = {"LISTEN_PID": "42", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "admin:canal"}
    assert lanceur.descripteurs(ok, 42) == (3, 4)
    assert lanceur.descripteurs({**ok, "LISTEN_FDNAMES": "canal:admin"}, 42) == (4, 3)
    for mauvais in ({**ok, "LISTEN_PID": "41"}, {**ok, "LISTEN_FDS": "1"}, {**ok, "LISTEN_FDS": "3"}, {**ok, "LISTEN_FDNAMES": "admin:admin"},
                    {**ok, "LISTEN_FDNAMES": "admin:autre"}, {k: v for k, v in ok.items() if k != "LISTEN_FDNAMES"}, {}):
        with pytest.raises(lanceur.SansSocket):
            lanceur.descripteurs(mauvais, 42)


def test_deux_serveurs_lifespan_on_sur_fd(lanceur, tmp_path):
    s_admin, s_canal = _ecoute(tmp_path / "pilotage.sock"), _ecoute(tmp_path / "pilotage-canal.sock")
    try:
        srv_admin, srv_canal = lanceur.serveurs(FastAPI(), FastAPI(), s_admin.fileno(), s_canal.fileno())
        assert srv_admin.config.lifespan == "on" and srv_canal.config.lifespan == "on"
        assert srv_admin.config.fd == s_admin.fileno() and srv_canal.config.fd == s_canal.fileno()
    finally:
        s_admin.close()
        s_canal.close()


def test_le_lanceur_ne_cree_ni_ne_delie_aucune_socket(lanceur):
    """R26 : plus de bind, unlink, umask, chmod ni chown dans le lanceur (systemd s'en charge)."""
    texte = "\n".join(x for x in LANCEUR.read_text().splitlines() if not x.lstrip().startswith("#"))
    code_seul = re.sub(r'"""[\s\S]*?"""', "", texte)
    for interdit in (".bind(", "unlink", "umask", "chmod", "chown", "0o660", "rm -f"):
        assert interdit not in code_seul, interdit


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
        s_admin, s_canal = _ecoute(tmp_path / "a.sock"), _ecoute(tmp_path / "c.sock")
        serveurs = []
        tache = asyncio.create_task(lanceur.servir(appli("admin"), appli("canal"), s_admin.fileno(), s_canal.fileno(), rendre=serveurs.extend))
        for _ in range(100):
            if len([t for t in trace if t[1] == "debut"]) == 2:
                break
            await asyncio.sleep(0.05)
        assert len([t for t in trace if t[1] == "debut"]) == 2
        # un arrêt demandé à un seul serveur arrête l'autre
        serveurs[0].should_exit = True
        assert await asyncio.wait_for(tache, 15) is True               # arrêt demandé = sortie propre
        s_admin.close()
        s_canal.close()

    asyncio.run(essai())
    assert {t[0] for t in trace if t[1] == "debut"} == {"admin", "canal"} and {t[0] for t in trace if t[1] == "fin"} == {"admin", "canal"}
    assert len({t[2] for t in trace}) == 1                                 # une seule boucle


def _env(fds):
    return {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "2", "LISTEN_FDNAMES": "admin:canal"}


def test_lifespan_en_echec_sortie_non_nulle(lanceur, tmp_path):
    """I1 : un lifespan qui échoue au démarrage faisait revenir servir() en silence (rc 0) : Restart=on-failure ne relançait rien."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def casse(app):
        raise RuntimeError("base illisible")
        yield

    async def essai():
        s_admin, s_canal = _ecoute(tmp_path / "a.sock"), _ecoute(tmp_path / "c.sock")
        try:
            assert await asyncio.wait_for(lanceur.servir(FastAPI(), FastAPI(lifespan=casse), s_admin.fileno(), s_canal.fileno()), 20) is False
        finally:
            s_admin.close()
            s_canal.close()

    asyncio.run(essai())


def test_main_code_de_sortie(lanceur, tmp_path, monkeypatch):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def casse(app):
        raise RuntimeError("x")
        yield

    # sans socket de systemd : échec franc, jamais un service muet
    assert asyncio.run(lanceur.main({}, lambda: (FastAPI(), FastAPI()))) == 1
    s_admin, s_canal = _ecoute(tmp_path / "a.sock"), _ecoute(tmp_path / "c.sock")
    try:
        # descripteurs « de systemd » placés haut (3 et 4 appartiennent à pytest) : le départ est une constante du lanceur
        monkeypatch.setattr(lanceur, "SD_LISTEN_FDS_START", 200)
        os.dup2(s_admin.fileno(), 200)
        os.dup2(s_canal.fileno(), 201)
        assert asyncio.run(lanceur.main(_env(None), lambda: (FastAPI(), FastAPI(lifespan=casse)))) == 1
    finally:
        s_admin.close()
        s_canal.close()
        for fd in (200, 201):
            try:
                os.close(fd)
            except OSError:
                pass


def test_systemexit_au_demarrage_est_un_echec(lanceur, tmp_path, monkeypatch):
    """uvicorn >= 0.5x lève SystemExit(3) depuis serve() quand le démarrage échoue : même chemin que l'échec ancien (False, puis 1)."""
    import uvicorn

    vivants = []

    async def faux_serve(self, sockets=None):
        if self.config.app is cassee:
            raise SystemExit(3)
        vivants.append(self)
        while not self.should_exit:
            await asyncio.sleep(0.01)
        vivants.remove(self)

    cassee = FastAPI()
    monkeypatch.setattr(uvicorn.Server, "serve", faux_serve)

    async def essai():
        s_admin, s_canal = _ecoute(tmp_path / "a.sock"), _ecoute(tmp_path / "c.sock")
        try:
            assert await asyncio.wait_for(lanceur.servir(FastAPI(), cassee, s_admin.fileno(), s_canal.fileno()), 20) is False
            assert vivants == []
            assert [t for t in asyncio.all_tasks() if t is not asyncio.current_task()] == []
            monkeypatch.setattr(lanceur, "descripteurs", lambda env, pid: (s_admin.fileno(), s_canal.fileno()))
            assert await lanceur.main({}, lambda: (FastAPI(), cassee)) == 1
            assert vivants == []
        finally:
            s_admin.close()
            s_canal.close()

    asyncio.run(essai())


def test_lanceur_en_tete_et_sain():
    texte = LANCEUR.read_text()
    assert texte.startswith("#!/usr/bin/python3\n") and "LicenseRef-CMSD-1.0" in texte
    assert 'lifespan="off"' not in texte


def test_systemexit_d_uvicorn_journalise_avec_son_code(lanceur, capsys):
    """uvicorn lève SystemExit(3) quand il ne démarre pas : le lanceur continue (l'autre serveur est arrêté proprement) mais le
    code de sortie est journalisé, sans quoi la cause d'un redémarrage en boucle reste invisible."""
    class Sortant:
        async def serve(self):
            raise SystemExit(3)

    asyncio.run(lanceur._serve(Sortant()))
    err = capsys.readouterr().err
    assert "SystemExit" in err and "3" in err, err
