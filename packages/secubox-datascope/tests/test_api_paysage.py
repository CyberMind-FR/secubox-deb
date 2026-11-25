# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3921 tâche 4 — routes du paysage : instantané, chronologie, instantané daté, différence, tendance."""
import sys
import zlib
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from api import main  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402
from secubox_datascope import config, store  # noqa: E402
from secubox_datascope import paysage_store as ps  # noqa: E402

NOW = 1795000000.0
P = "/api/v1/datascope/paysage"
H = 3600.0


def _g(adresses=100, bans=10, reseaux=2, avec=True, extra=()):
    noeuds = [{"id": "camp:abc", "type": "campagne", "libelle": "abc"}]
    if avec:
        noeuds.append({"id": "pop:collecte", "type": "population", "libelle": "collecte",
                       "metriques": {"adresses": adresses, "bans": bans, "reseaux": reseaux}})
    noeuds.extend(extra)
    return {"noeuds": noeuds, "aretes": []}


def ts(epoch):
    return ps._ts(epoch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = config.Config(base=tmp_path / "d.db", cache=tmp_path / "c", nac_db=tmp_path / "n",
                        netstats=tmp_path / "s", modules=tmp_path / "m")
    monkeypatch.setattr(main, "CFG", cfg)
    monkeypatch.setattr(main, "_maintenant", lambda: NOW + 100)
    db = store.ouvrir(cfg.base)
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield db
    db.close()
    main.app.dependency_overrides.clear()


@pytest.fixture
def client(env):
    return TestClient(main.app)


def _ecrire(db, epoch, **kw):
    assert ps.ecrire(db, epoch, kw.pop("partiel", False), _g(**kw), {"noeuds": 2}, {})


# --- /paysage -------------------------------------------------------------------------------------------------

def test_paysage_aucun(client):
    assert client.get(P).json() == {"disponible": False}


def test_paysage_nominal_et_difference_24h(env, client):
    _ecrire(env, NOW - 86400 - 600, adresses=100)
    _ecrire(env, NOW - 3600, adresses=110)
    _ecrire(env, NOW, adresses=200, extra=[{"id": "pop:neuf", "type": "population", "libelle": "n"}])
    d = client.get(P).json()
    assert d["disponible"] is True and d["age_s"] == 100 and d["epoch"] == NOW
    i = d["instantane"]
    assert i["ts"] == ts(NOW) and i["epoch"] == NOW and i["partiel"] is False
    assert i["compteurs"] == {"noeuds": 2} and len(i["graphe"]["noeuds"]) == 3
    j = d["difference_24h"]
    assert j["reference_ts"] == ts(NOW - 86400 - 600) and j["ecart_s"] == 86400 + 600
    assert j["apparus"] == ["pop:neuf"]
    assert [(h["id"], h["metrique"], h["de"], h["a"]) for h in j["hausses"]] == [("pop:collecte", "adresses", 100, 200)]
    assert "motif_difference_24h" not in d


def test_paysage_reference_la_plus_proche(env, client):
    _ecrire(env, NOW - 86400 - 5000, adresses=1000)
    _ecrire(env, NOW - 86400 + 3000, adresses=100)  # plus proche de dernier - 24 h
    _ecrire(env, NOW, adresses=100)
    j = client.get(P).json()["difference_24h"]
    assert j["reference_ts"] == ts(NOW - 86400 + 3000) and j["hausses"] == [] and j["baisses"] == []


def test_paysage_pas_de_reference_assez_ancienne(env, client):
    _ecrire(env, NOW - 11 * H, adresses=100)
    _ecrire(env, NOW - 3 * H, adresses=100)
    _ecrire(env, NOW, adresses=500)
    d = client.get(P).json()
    assert d["disponible"] is True and d["difference_24h"] is None and d["motif_difference_24h"]
    assert d["instantane"]["ts"] == ts(NOW)


def test_paysage_un_seul_instantane(env, client):
    _ecrire(env, NOW)
    d = client.get(P).json()
    assert d["difference_24h"] is None and d["motif_difference_24h"]


def test_paysage_reference_a_12h_exactement_acceptee(env, client):
    _ecrire(env, NOW - 12 * H)
    _ecrire(env, NOW)
    assert client.get(P).json()["difference_24h"]["reference_ts"] == ts(NOW - 12 * H)


def test_paysage_base_absente_503(tmp_path, monkeypatch):
    cfg = config.Config(base=tmp_path / "absente.db", cache=tmp_path, nac_db=tmp_path, netstats=tmp_path,
                        modules=tmp_path)
    monkeypatch.setattr(main, "CFG", cfg)
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        assert TestClient(main.app).get(P).status_code == 503
    finally:
        main.app.dependency_overrides.clear()


# --- /paysage/chronologie -----------------------------------------------------------------------------------

def test_chronologie_defaut_48h(env, client):
    _ecrire(env, NOW - 49 * H)
    _ecrire(env, NOW - 47 * H)
    _ecrire(env, NOW)
    d = client.get(P + "/chronologie").json()
    assert [x["epoch"] for x in d["instantanes"]] == [NOW - 47 * H, NOW]
    assert "graphe" not in d["instantanes"][0] and d["tronque"] is False


def test_chronologie_explicite(env, client):
    for k in range(4):
        _ecrire(env, NOW + k * 1800)
    d = client.get(P + "/chronologie", params={"de": NOW + 1, "a": NOW + 3600}).json()
    assert [x["epoch"] for x in d["instantanes"]] == [NOW + 1800, NOW + 3600]


def test_chronologie_bornee(env, client, monkeypatch):
    monkeypatch.setattr(main, "CHRONO_MAX", 3)
    for k in range(6):
        _ecrire(env, NOW + k * 1800)
    d = client.get(P + "/chronologie", params={"de": NOW, "a": NOW + 6 * 1800}).json()
    assert d["tronque"] is True and [x["epoch"] for x in d["instantanes"]] == [NOW + 3 * 1800, NOW + 4 * 1800,
                                                                                NOW + 5 * 1800]


@pytest.mark.parametrize("params", [
    {"de": 0, "a": 32 * 86400}, {"de": 10, "a": 5}, {"de": "nan", "a": 100}, {"de": 1, "a": "inf"},
    {"de": -1, "a": 100}, {"de": "abc", "a": 100}, {"de": 1e30, "a": 2e30}, {"de": 5},
])
def test_chronologie_parametres_invalides(client, params):
    assert client.get(P + "/chronologie", params=params).status_code == 400


def test_chronologie_31_jours_accepte(client):
    assert client.get(P + "/chronologie", params={"de": 100, "a": 100 + 31 * 86400}).status_code == 200


# --- /paysage/instantane/{ts} -----------------------------------------------------------------------------

def test_instantane_nominal_et_encode(env, client):
    _ecrire(env, NOW, adresses=7)
    for chemin in (ts(NOW), quote(ts(NOW), safe="")):
        r = client.get(P + "/instantane/" + chemin)
        assert r.status_code == 200, chemin
        d = r.json()
        assert d["ts"] == ts(NOW) and d["epoch"] == NOW and d["graphe"]["noeuds"][1]["metriques"]["adresses"] == 7
        assert "compteurs" in d and "difference" in d


def test_instantane_inconnu_404(env, client):
    _ecrire(env, NOW)
    assert client.get(P + "/instantane/" + ts(NOW - 5)).status_code == 404


@pytest.mark.parametrize("mauvais", ["x", "2026-11-24", "2026-11-24T10:00:00Z", "2026-11-24T10:00:00.1Z",
                                     "2026-13-45T10:00:00.000000Z", "2026-11-24T10:00:00.000000Z' OR 1=1",
                                     "2026-11-24T10:00:00.000000+00:00", "9" * 300,
                                     "2026-11-24T10:00:00.000000Z%0A"])
def test_instantane_ts_invalide_400(client, mauvais):
    assert client.get(P + "/instantane/" + mauvais).status_code == 400


# --- /paysage/difference --------------------------------------------------------------------------------

def test_difference_nominal(env, client):
    _ecrire(env, NOW - 100, adresses=100)
    _ecrire(env, NOW, adresses=300)
    r = client.get(P + "/difference", params={"de": ts(NOW - 100), "a": ts(NOW)})
    assert r.status_code == 200
    assert [(h["id"], h["de"], h["a"]) for h in r.json()["hausses"]] == [("pop:collecte", 100, 300)]
    assert r.json()["tronque"] is False


def test_difference_bornee(env, client, monkeypatch):
    monkeypatch.setattr(main, "DIFF_MAX", 2)
    ps.ecrire(env, NOW - 100, False, {"noeuds": []}, {}, {})
    ps.ecrire(env, NOW, False, {"noeuds": [{"id": f"pop:p{i}", "type": "population"} for i in range(5)]}, {}, {})
    d = client.get(P + "/difference", params={"de": ts(NOW - 100), "a": ts(NOW)}).json()
    assert d["apparus"] == ["pop:p0", "pop:p1"] and d["tronque"] is True


def test_difference_erreurs(env, client):
    _ecrire(env, NOW)
    assert client.get(P + "/difference", params={"de": ts(NOW), "a": ts(NOW - 5)}).status_code == 404
    assert client.get(P + "/difference", params={"de": ts(NOW - 5), "a": ts(NOW)}).status_code == 404
    assert client.get(P + "/difference", params={"de": "x", "a": ts(NOW)}).status_code == 400
    assert client.get(P + "/difference", params={"de": ts(NOW)}).status_code == 400
    assert client.get(P + "/difference").status_code == 400


# --- /paysage/tendance/{id} -------------------------------------------------------------------------------

def test_tendance_nominal_un_point_par_heure(env, client):
    for k in range(6):  # 3 heures, 2 instantanés par heure
        _ecrire(env, NOW - 6 * H + k * 1800, adresses=100 + k)
    d = client.get(P + "/tendance/pop:collecte").json()
    assert d["id"] == "pop:collecte" and len(d["points"]) == 3
    assert d["points"][0] == {"ts": ts(NOW - 6 * H), "epoch": NOW - 6 * H, "adresses": 100, "bans": 10, "reseaux": 2}
    assert [p["epoch"] for p in d["points"]] == sorted(p["epoch"] for p in d["points"])


def test_tendance_noeud_absent_omis_pas_zero(env, client):
    _ecrire(env, NOW - 3 * H, adresses=5)
    _ecrire(env, NOW - 2 * H, avec=False)
    _ecrire(env, NOW - 1 * H, adresses=9)
    d = client.get(P + "/tendance/pop:collecte").json()
    assert [p["adresses"] for p in d["points"]] == [5, 9]


def test_tendance_metrique_absente_nulle(env, client):
    g = {"noeuds": [{"id": "pop:x", "type": "population", "metriques": {"adresses": 4, "bans": "z", "reseaux": True}}]}
    ps.ecrire(env, NOW, False, g, {}, {})
    p = client.get(P + "/tendance/pop:x").json()["points"]
    assert p == [{"ts": ts(NOW), "epoch": NOW, "adresses": 4, "bans": None, "reseaux": None}]


def test_tendance_inconnu_liste_vide(env, client):
    _ecrire(env, NOW)
    r = client.get(P + "/tendance/pop:autre")
    assert r.status_code == 200 and r.json()["points"] == []


def test_tendance_flux_et_borne(env, client, monkeypatch):
    # 40 instantanés sur 10 h, 4 par heure (écrits tels quels) : 10 points, 10 décompressions
    for k in range(40):
        ps.ecrire(env, NOW - 10 * H + k * 900, False, _g(), {}, {})
    appels = []
    reel = zlib.decompress
    monkeypatch.setattr(ps.zlib, "decompress", lambda b: appels.append(1) or reel(b))
    d = client.get(P + "/tendance/pop:collecte", params={"jours": 1}).json()
    assert len(d["points"]) == 10 and len(appels) == 10
    monkeypatch.setattr(ps, "TENDANCE_GRAPHES_MAX", 4)
    assert len(client.get(P + "/tendance/pop:collecte", params={"jours": 1}).json()["points"]) == 4


def test_tendance_jours_borne(env, client):
    _ecrire(env, NOW - 20 * 86400)
    _ecrire(env, NOW)
    assert len(client.get(P + "/tendance/pop:collecte", params={"jours": 7}).json()["points"]) == 1
    assert len(client.get(P + "/tendance/pop:collecte", params={"jours": 30}).json()["points"]) == 2


@pytest.mark.parametrize("params", [{"jours": 31}, {"jours": 0}, {"jours": -2}, {"jours": "x"}])
def test_tendance_jours_invalide(client, params):
    assert client.get(P + "/tendance/pop:collecte", params=params).status_code == 400


@pytest.mark.parametrize("ident", ["pop", "POP:x", "pop:", "pop:a b", "pop:" + "a" * 161, "pop:é", "1:abc",
                                   "pop:x'--"])
def test_tendance_id_invalide(client, ident):
    assert client.get(P + "/tendance/" + quote(ident, safe=":")).status_code == 400


# --- reports de la relecture de la tâche 4 ------------------------------------------------------------------

@pytest.mark.parametrize("chemin,params", [
    ("/chronologie", {"de": "1" * 33}), ("/chronologie", {"a": "1" * 33}), ("/chronologie", {"a": "1" * 6000}),
    ("/difference", {"de": "2" * 41, "a": "x"}), ("/difference", {"de": "2" * 6000, "a": "2" * 6000}),
    ("/tendance/pop:collecte", {"jours": "0" * 9}), ("/tendance/pop:collecte", {"jours": "7" * 6000}),
])
def test_valeur_trop_longue_400_pas_422(client, chemin, params):
    assert client.get(P + chemin, params=params).status_code == 400


def test_paysage_reference_partielle_signalee(env, client):
    _ecrire(env, NOW - 86400, partiel=True)
    _ecrire(env, NOW)
    assert client.get(P).json()["difference_24h"]["reference_partiel"] is True


def test_paysage_reference_complete_signalee(env, client):
    _ecrire(env, NOW - 86400)
    _ecrire(env, NOW, partiel=True)
    d = client.get(P).json()
    assert d["difference_24h"]["reference_partiel"] is False and d["instantane"]["partiel"] is True


def test_paysage_reference_disparue_entre_deux_lectures(env, client, monkeypatch):
    _ecrire(env, NOW - 86400)
    _ecrire(env, NOW)
    reel = ps.lire
    monkeypatch.setattr(ps, "lire", lambda db, t: None if t == ts(NOW - 86400) else reel(db, t))
    r = client.get(P)
    d = r.json()
    assert r.status_code == 200 and d["disponible"] is True and d["difference_24h"] is None
    assert d["motif_difference_24h"]


@pytest.mark.parametrize("blob", [b"pas du zlib", b"", zlib.compress(b"{pas du json"), zlib.compress(b"\xff\xfe"),
                                  zlib.compress(b"[1,2]"), zlib.compress(b'{"noeuds": []}')[:-3],
                                  "du texte", 12, zlib.compress(b"[" * 100000)])
def test_instantane_corrompu_erreur_propre(env, client, blob):
    _ecrire(env, NOW - 86400)
    _ecrire(env, NOW)
    env.execute("UPDATE paysage_instantanes SET graphe=? WHERE ts=?", (blob, ts(NOW)))
    c = TestClient(main.app, raise_server_exceptions=False)
    for chemin in ("", "/instantane/" + ts(NOW), f"/difference?de={ts(NOW - 86400)}&a={ts(NOW)}"):
        r = c.get(P + chemin)
        assert r.status_code == 503 and "illisible" in r.json()["detail"], chemin
    assert c.get(P + "/instantane/" + ts(NOW - 86400)).status_code == 200


def test_reference_corrompue_pas_de_difference_mais_paysage_rendu(env, client):
    _ecrire(env, NOW - 86400)
    _ecrire(env, NOW)
    env.execute("UPDATE paysage_instantanes SET graphe=? WHERE ts=?", (b"x", ts(NOW - 86400)))
    d = client.get(P).json()
    assert d["disponible"] is True and d["difference_24h"] is None and "illisible" in d["motif_difference_24h"]


def test_tendance_instantane_corrompu_omis_et_compte(env, client):
    _ecrire(env, NOW - 2 * H, adresses=5)
    _ecrire(env, NOW - H, adresses=6)
    _ecrire(env, NOW, adresses=7)
    env.execute("UPDATE paysage_instantanes SET graphe=? WHERE ts=?", (b"x", ts(NOW - H)))
    d = client.get(P + "/tendance/pop:collecte").json()
    assert [p["adresses"] for p in d["points"]] == [5, 7] and d["illisibles"] == 1


def test_entete_corrompu_tolere(env, client):
    _ecrire(env, NOW)
    env.execute("UPDATE paysage_instantanes SET compteurs_json='{', difference_json='{'")
    assert client.get(P + "/chronologie", params={"de": NOW - 1, "a": NOW}).json()["instantanes"][0]["compteurs"] == {}
    d = client.get(P + "/instantane/" + ts(NOW)).json()
    assert d["compteurs"] == {} and d["difference"] is None  # indisponible, jamais « rien n'a changé »
    assert client.get(P).status_code == 200
