# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2870 — « Redémarrer le service nDPId » : la bonne unité, avec un droit borné.

La page appelait `systemctl restart ndpid` : (1) l'unité s'appelle `secubox-ndpid-engine.service` ; (2) le compte `secubox` n'a pas le droit de piloter systemd
(« Interactive authentication required »). On passe par `sudo -n /usr/bin/systemctl <verbe> secubox-ndpid-engine.service`, que le postinst autorise, et ces trois commandes seulement."""
import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

import secubox_core.config as _cfg

PAQUET = Path(__file__).resolve().parents[1]
MAIN = PAQUET / "composants" / "ndpid" / "api" / "main.py"
UNITE = "secubox-ndpid-engine.service"

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}


@pytest.fixture(scope="module")
def mod():
    # `zmq` (pyzmq) n'est pas installe partout ou l'on lance les tests : l'API n'en a besoin que pour son flux ZeroMQ, pas pour ces routes.
    for nom in ("zmq", "zmq.asyncio"):
        sys.modules.setdefault(nom, mock.MagicMock())
    # Le composant importe ses voisins par `api.<x>` : on isole SON paquet `api` (tous les modules s'appellent `api`), puis on restaure.
    racine = str(MAIN.parents[1])
    sauve = {k: v for k, v in sys.modules.items() if k == "api" or k.startswith("api.")}
    for k in sauve:
        del sys.modules[k]
    sys.path.insert(0, racine)
    try:
        spec = importlib.util.spec_from_file_location("api.main", str(MAIN))
        m = importlib.util.module_from_spec(spec)
        sys.modules["api.main"] = m
        # le module ouvre sa base SQLite et cree ses dossiers a l'import : on isole la machine.
        with mock.patch("pathlib.Path.mkdir"), mock.patch("sqlite3.connect"):
            spec.loader.exec_module(m)
    finally:
        sys.path.remove(racine)
    yield m
    for k in [k for k in sys.modules if k == "api" or k.startswith("api.")]:
        del sys.modules[k]
    sys.modules.update(sauve)


def _fausse(rc=0, err=""):
    appels = []

    def run(cmd, **k):
        appels.append((cmd, k))
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr=err)
    return appels, run


@pytest.mark.parametrize("verbe,fn", [("start", "start_ndpid"), ("stop", "stop_ndpid"), ("restart", "restart_ndpid")])
def test_chaque_action_appelle_la_vraie_unite_par_sudo(mod, monkeypatch, verbe, fn):
    appels, run = _fausse()
    monkeypatch.setattr(mod.subprocess, "run", run)
    r = getattr(mod, fn)()
    assert appels[0][0] == ["sudo", "-n", "/usr/bin/systemctl", verbe, UNITE], appels
    assert r["success"] is True and appels[0][1].get("timeout") == 30


def test_un_echec_dit_la_raison_reelle(mod, monkeypatch):
    appels, run = _fausse(rc=1, err="Unit secubox-ndpid-engine.service not found.")
    monkeypatch.setattr(mod.subprocess, "run", run)
    r = mod.restart_ndpid()
    assert r["success"] is False and "not found" in r["error"]


def test_un_delai_depasse_est_dit(mod, monkeypatch):
    def lent(cmd, **k):
        raise subprocess.TimeoutExpired(cmd, 30)
    monkeypatch.setattr(mod.subprocess, "run", lent)
    r = mod.restart_ndpid()
    assert r["success"] is False and "délai" in r["error"].lower()


def test_les_journaux_sont_ceux_de_la_vraie_unite(mod, monkeypatch):
    appels, run = _fausse()
    monkeypatch.setattr(mod.subprocess, "run", run)
    mod.get_logs(5)
    assert appels[0][0][:3] == ["journalctl", "-u", UNITE]


def test_le_postinst_autorise_ces_trois_commandes_et_pas_plus():
    p = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
    for verbe in ("start", "stop", "restart"):
        assert f"/usr/bin/systemctl {verbe} {UNITE}" in p
    assert "systemctl restart ndpid\n" not in p
    ligne = [l for l in p.splitlines() if UNITE in l and "NOPASSWD" in l][0]
    assert "*" not in ligne                                  # commandes exactes, aucun joker


def test_plus_aucune_reference_a_l_unite_ndpid_inexistante():
    src = MAIN.read_text(encoding="utf-8")
    assert '"systemctl", "start", "ndpid"' not in src and '"-u", "ndpid"' not in src
