# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3216 — l'agrégateur montait tous ses modules à l'import, avant qu'uvicorn n'écoute : 4 à 8 minutes de 502 sur le Hall,
l'authentification et l'administration à chaque redémarrage de gk2. La passerelle sert désormais tout de suite ; les modules
se montent ensuite un par un, les essentiels d'abord, et un module pas encore monté répond 503 + Retry-After."""
import importlib
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"

MODULE = """from fastapi import FastAPI
app = FastAPI()

@app.get("/ping")
def ping():
    return {{"module": "{nom}"}}
"""


def _etat_vierge(monkeypatch):
    """L'état du montage est global au module : chaque test part de listes neuves, rendues à la fin."""
    monkeypatch.setattr(ag, "_MOUNTED", [])
    monkeypatch.setattr(ag, "_LOAD_ERRORS", {})
    monkeypatch.setattr(ag, "_A_MONTER", [])
    monkeypatch.setattr(ag, "_MONTAGE", {"pret": False, "duree_s": None, "interrompu": None})


def _module(lib, nom, avant=""):
    api = lib / nom / "api"
    api.mkdir(parents=True)
    (api / "main.py").write_text(avant + MODULE.format(nom=nom), encoding="utf-8")


@pytest.fixture
def banc(tmp_path, monkeypatch):
    """Une bibliothèque de faux modules, une configuration, aucun socket dédié."""
    lib = tmp_path / "lib"
    lib.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    conf = tmp_path / "aggregator.toml"
    monkeypatch.setattr(ag, "SECUBOX_LIB", lib)
    monkeypatch.setattr(ag, "RUN_DIR", str(run))
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    monkeypatch.setattr(sys, "path", list(sys.path))
    _etat_vierge(monkeypatch)

    def configurer(*noms):
        conf.write_text("modules = [%s]\n" % ", ".join('"%s"' % n for n in noms), encoding="utf-8")

    return lib, configurer


def _attendre_pret(client, delai=15.0):
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        etat = client.get("/health").json()
        if etat["pret"]:
            return etat
        time.sleep(0.02)
    raise AssertionError("montage jamais terminé : %r" % etat)


def test_les_essentiels_sont_montes_d_abord():
    assert ag._ordre_montage(["x", "hub", "y", "auth", "users"]) == ["auth", "hub", "users", "x", "y"]
    assert ag._ordre_montage(["y", "x"]) == ["y", "x"]


def test_la_construction_ne_monte_aucun_module(banc):
    lib, configurer = banc
    for n in ("hub", "soc"):
        _module(lib, n)
    configurer("soc", "hub")
    app = ag._build_app()
    assert ag._MOUNTED == []
    assert "sbx_pkg_soc.main" not in sys.modules and "sbx_pkg_hub.main" not in sys.modules
    etat = TestClient(app).get("/health").json()                  # sans démarrage : rien n'est lancé
    assert etat["pret"] is False and etat["a_monter"] == ["hub", "soc"]
    assert {"status", "mounted", "failed", "total_mounted", "total_failed"} <= set(etat)


def test_un_module_pas_encore_monte_rend_503_et_retry_after(banc):
    lib, configurer = banc
    _module(lib, "soc")
    configurer("soc")
    r = TestClient(ag._build_app()).get("/api/v1/soc/ping")
    assert r.status_code == 503
    assert int(r.headers["retry-after"]) > 0


def test_le_montage_se_fait_au_demarrage_et_passe_avant_le_relais(banc):
    lib, configurer = banc
    for n in ("hub", "auth", "soc"):
        _module(lib, n)
    configurer("soc", "hub", "auth")
    with TestClient(ag._build_app()) as client:
        etat = _attendre_pret(client)
        assert etat["mounted"] == ["auth", "hub", "soc"]
        assert etat["a_monter"] == [] and etat["total_failed"] == 0
        assert isinstance(etat["duree_montage_s"], float)
        r = client.get("/api/v1/soc/ping")
        assert r.status_code == 200 and r.json() == {"module": "soc"}


def test_un_module_en_echec_est_isole(banc):
    lib, configurer = banc
    _module(lib, "boum", avant='raise RuntimeError("import cassé")\n')
    _module(lib, "soc")
    configurer("boum", "soc")
    with TestClient(ag._build_app()) as client:
        etat = _attendre_pret(client)
        assert etat["mounted"] == ["soc"]
        assert "import cassé" in etat["failed"]["boum"]
        assert client.get("/api/v1/boum/ping").status_code == 404   # plus « à monter » : ni 503, ni socket
        assert client.get("/api/v1/soc/ping").status_code == 200


def test_la_passerelle_repond_pendant_le_montage(banc):
    lib, configurer = banc
    noms = ["m%d" % i for i in range(6)]
    for n in noms:
        _module(lib, n, avant="import time\ntime.sleep(0.3)\n")     # import lent, comme sous swap
    configurer(*noms)
    with TestClient(ag._build_app()) as client:
        etat = client.get("/health").json()
        assert etat["pret"] is False and etat["a_monter"]             # servi AVANT la fin du montage
        assert _attendre_pret(client)["mounted"] == noms


def test_le_chemin_python_est_remis_en_ordre_apres_chaque_module(banc):
    lib, configurer = banc
    _module(lib, "debian", avant='import sys\nsys.path.insert(0, "/faux/dist-packages")\n')
    configurer("debian")
    origine = list(sys.path)
    with TestClient(ag._build_app()) as client:
        _attendre_pret(client)
    assert sys.path[: len(origine)] == origine
    assert "/faux/dist-packages" in sys.path[len(origine):]


def test_un_module_qui_appelle_sys_exit_n_arrete_pas_la_passerelle(banc):
    lib, configurer = banc
    _module(lib, "sortie", avant="raise SystemExit(3)\n")
    _module(lib, "soc")
    configurer("sortie", "soc")
    with TestClient(ag._build_app()) as client:
        etat = _attendre_pret(client)
        assert etat["mounted"] == ["soc"] and "SystemExit" in etat["failed"]["sortie"]


def test_un_montage_interrompu_est_signale(banc, monkeypatch):
    lib, configurer = banc
    _module(lib, "soc")
    configurer("soc")

    class Coupure(BaseException):
        pass

    def _casse(parent, name):
        raise Coupure("arrêt imprévu")

    monkeypatch.setattr(ag, "_mount_module", _casse)
    with TestClient(ag._build_app()) as client:
        fin = time.monotonic() + 10
        while not client.get("/health").json()["interrompu"] and time.monotonic() < fin:
            time.sleep(0.02)
        etat = client.get("/health").json()
        assert "Coupure" in etat["interrompu"] and etat["pret"] is False


def test_la_pause_suit_la_duree_de_l_import():
    assert ag._pause_apres(0.0) == ag.PAUSE_MONTAGE_S
    assert ag._pause_apres(0.5) == 0.5
    assert ag._pause_apres(30.0) == ag.PAUSE_MAX_S


def test_les_sockets_reservees_ne_sont_jamais_montees(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "vault", "actor", "radio"]\n', encoding="utf-8")
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub"]
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    assert {"vault", "actor", "radio"} <= set(ligne.split("=", 1)[1].strip('"').split())


def test_la_garde_passe_avant_le_503_pour_un_module_reserve(monkeypatch):
    _etat_vierge(monkeypatch)
    app = ag._build_app()
    ag._A_MONTER.append("actor")          # même « à monter », un module réservé exige d'abord un administrateur
    r = TestClient(app).get("/api/v1/actor/vue")
    assert r.status_code == 401


def test_la_migration_attend_la_fin_du_montage():
    texte = MIGRATE.read_text(encoding="utf-8")
    assert '"pret"' in texte and "sleep 8\n" not in texte
