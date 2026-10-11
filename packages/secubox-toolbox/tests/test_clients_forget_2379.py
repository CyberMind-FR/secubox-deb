# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2379 — « oublier » des clients : la RAZ garde les lignes (statistiques effacées) ; oublier RETIRE le client et tout ce qui le concerne."""
import pathlib
import time

from secubox_toolbox import store


def _db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", pathlib.Path(tmp_path / "toolbox.db"))
    now = int(time.time())
    with store._conn() as c:
        for mh, vu in (("vieux1", now - 40 * 86400), ("vieux2", now - 90 * 86400), ("actif", now - 60)):
            c.execute("INSERT INTO clients(mac_hash,ip,state,score,level,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)",
                      (mh, "10.0.0.1", "validated", 5, "r3", vu - 1000, vu))
            c.execute("INSERT INTO events(mac_hash,ts,source,payload) VALUES(?,?,?,?)", (mh, vu, "dns", "{}"))
    return store


def _mh():
    with store._conn() as c:
        return sorted(r[0] for r in c.execute("SELECT mac_hash FROM clients"))


def test_oublier_les_inactifs_garde_les_actifs(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    n, lignes = store.forget_clients(inactive_days=30)
    assert n == 2 and _mh() == ["actif"]
    with store._conn() as c:
        assert c.execute("SELECT COUNT(*) FROM events WHERE mac_hash IN ('vieux1','vieux2')").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM events WHERE mac_hash='actif'").fetchone()[0] == 1
    assert lignes >= 2


def test_oublier_tous(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    n, _ = store.forget_clients(inactive_days=0)
    assert n == 3 and _mh() == []


def test_oublier_un_client_et_un_inconnu(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    assert store.forget_client("vieux1")[0] == 1 and _mh() == ["actif", "vieux2"]
    assert store.forget_client("inconnu") == (0, 0)
    assert store.forget_client("") == (0, 0)


def test_les_jours_negatifs_ou_absurdes_ne_suppriment_rien(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    for bad in (-1, None, "x"):
        assert store.forget_clients(inactive_days=bad) == (0, 0)
    assert len(_mh()) == 3


def test_la_ra_z_des_statistiques_garde_toujours_les_lignes(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    store.reset_client("vieux1")
    assert len(_mh()) == 3


# ── routes (#2379) ────────────────────────────────────────────────────────────
import asyncio

import pytest


class _Req:
    def __init__(self, body=None, host="admin.exemple.test"):
        self._body, self.headers = body, {"host": host}

    async def json(self):
        if self._body is None:
            raise ValueError("pas de corps")
        return self._body


@pytest.fixture
def api(tmp_path, monkeypatch):
    import secubox_toolbox.api as a
    from secubox_toolbox import social
    _db(tmp_path, monkeypatch)
    monkeypatch.setattr(social, "wipe_mac", lambda mh: 2)
    return a


def test_la_route_oublie_les_inactifs_et_compte(api):
    out = asyncio.run(api.admin_clients_forget(_Req({"inactive_days": 30})))
    assert out["ok"] and out["clients_forgotten"] == 2 and _mh() == ["actif"]


def test_la_route_zero_oublie_tous_meme_au_dela_de_200(api):
    out = asyncio.run(api.admin_clients_forget(_Req({"inactive_days": 0})))
    assert out["clients_forgotten"] == 3 and _mh() == []


@pytest.mark.parametrize("corps", [None, {}, {"inactive_days": -3}, {"inactive_days": "x"}, {"inactive_days": True}, {"inactive_days": 1.5}])
def test_un_corps_invalide_est_refuse_et_ne_supprime_rien(api, corps):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        asyncio.run(api.admin_clients_forget(_Req(corps)))
    assert e.value.status_code == 422 and len(_mh()) == 3


def test_oublier_un_client_par_la_route(api):
    out = asyncio.run(api.admin_client_forget("vieux1", _Req({})))
    assert out["clients_forgotten"] == 1 and "vieux1" not in _mh()


def test_les_routes_sont_fermees_sur_le_vhost_public(api):
    from fastapi import HTTPException
    for coro in (api.admin_clients_forget(_Req({"inactive_days": 0}, host="kbin.exemple.test")),
                 api.admin_client_forget("actif", _Req({}, host="kbin.exemple.test"))):
        with pytest.raises(HTTPException) as e:
            asyncio.run(coro)
        assert e.value.status_code == 403
    assert len(_mh()) == 3
