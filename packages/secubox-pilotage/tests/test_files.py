# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Files de requêtes cloisonnées par box (#3126)."""
import asyncio

import pytest

from pilotage.files import FileDeBoxPleine, Files


def run(coro):
    return asyncio.run(coro)


def test_depot_attente_et_livraison():
    async def cas():
        f = Files()
        fut = f.deposer("gk5", {"type": "GET", "body": {"paths": ["Device."]}})
        [rq] = await f.attendre_requetes("gk5", 1)
        assert rq["type"] == "GET" and len(rq["msg_id"]) == 16
        assert not fut.done()
        assert f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {"results": []}})
        assert (await fut)["type"] == "GET_RESP"
        # une seconde livraison du même msg_id est refusée
        assert not f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}})
    run(cas())


def test_cloisonnement():
    async def cas():
        f = Files()
        fut = f.deposer("gk5", {"type": "GET_SUPPORTED_DM", "body": {}})
        assert await f.attendre_requetes("lgm", 0.05) == []
        [rq] = await f.attendre_requetes("gk5", 1)
        assert not f.livrer_reponse("lgm", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}})
        assert not fut.done()
        assert not f.livrer_reponse("gk5", {"msg_id": "ffffffffffffffff", "type": "GET_RESP", "body": {}})
        assert not f.livrer_reponse("gk5", {"type": "GET_RESP"})
        assert f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}})
    run(cas())


def test_attente_se_reveille_au_depot_et_expire_a_vide():
    async def cas():
        f = Files()
        assert await f.attendre_requetes("gk5", 0.05) == []
        t = asyncio.create_task(f.attendre_requetes("gk5", 5))
        await asyncio.sleep(0.02)
        f.deposer("gk5", {"type": "GET", "body": {}})
        assert len(await asyncio.wait_for(t, 1)) == 1
    run(cas())


def test_expiration_des_requetes_non_servies():
    async def cas():
        f = Files(expiration_s=0.05)
        fut = f.deposer("gk5", {"type": "GET", "body": {}})
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(fut, 1)
        assert await f.attendre_requetes("gk5", 0.01) == []
        assert f.en_attente("gk5") == 0
    run(cas())


def test_expiration_d_une_requete_servie_sans_reponse():
    async def cas():
        f = Files(expiration_s=5, expiration_reponse_s=0.05)
        fut = f.deposer("gk5", {"type": "GET", "body": {}})
        [rq] = await f.attendre_requetes("gk5", 1)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(fut, 1)
        assert not f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}})
    run(cas())


def test_file_bornee_par_box():
    async def cas():
        f = Files(max_par_box=3)
        for _ in range(3):
            f.deposer("gk5", {"type": "GET", "body": {}})
        with pytest.raises(FileDeBoxPleine):
            f.deposer("gk5", {"type": "GET", "body": {}})
        f.deposer("lgm", {"type": "GET", "body": {}})  # les autres box ne sont pas touchées
        assert f.en_attente("gk5") == 3
    run(cas())


def test_delai_de_reponse_par_requete():
    from pilotage.files import delai_reponse_pour
    op = {"type": "OPERATE", "body": {"command": "Device.X_SECUBOX_Releve.Mesurer()", "args": {"duree_s": 60}}}
    assert delai_reponse_pour(op, 120) == 90
    assert delai_reponse_pour({**op, "body": {**op["body"], "args": {"duree_s": 300}}}, 120) == 330
    assert delai_reponse_pour({**op, "body": {**op["body"], "args": {"duree_s": 5000}}}, 120) == 330
    assert delai_reponse_pour({**op, "body": {**op["body"], "args": {}}}, 120) == 90
    assert delai_reponse_pour({"type": "GET", "body": {}}, 120) == 120


def test_operate_longue_repondue_apres_le_plafond_ordinaire():
    async def cas():
        f = Files(expiration_s=5, expiration_reponse_s=0.05)
        op = {"type": "OPERATE", "body": {"command": "Device.X_SECUBOX_Releve.Mesurer()", "args": {"duree_s": 60}}}
        fut = f.deposer("gk5", op)
        [rq] = await f.attendre_requetes("gk5", 1)
        await asyncio.sleep(0.15)  # au-delà de l'ancien plafond
        assert f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "OPERATE_RESP", "body": {"output": {}}})
        assert (await fut)["type"] == "OPERATE_RESP"
        # délai explicite
        fut = f.deposer("gk5", {"type": "GET", "body": {}}, delai_reponse=5)
        [rq] = await f.attendre_requetes("gk5", 1)
        await asyncio.sleep(0.1)
        assert f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}})
        await fut
    run(cas())


def test_un_seul_sondage_actif_par_box():
    async def cas():
        f = Files()
        t1 = asyncio.create_task(f.attendre_requetes("gk5", 5))
        await asyncio.sleep(0.01)
        t2 = asyncio.create_task(f.attendre_requetes("gk5", 5))
        await asyncio.sleep(0.01)
        assert await asyncio.wait_for(t1, 1) == []  # supplanté, sans rien prendre
        f.deposer("gk5", {"type": "GET", "body": {}})
        assert len(await asyncio.wait_for(t2, 1)) == 1
        # 200 sondages simultanés : un seul reste actif
        ts = [asyncio.create_task(f.attendre_requetes("gk5", 5)) for _ in range(200)]
        await asyncio.sleep(0.05)
        f.deposer("gk5", {"type": "GET", "body": {}})
        res = await asyncio.wait_for(asyncio.gather(*ts), 2)
        assert sorted(len(r) for r in res) == [0] * 199 + [1]
        assert res[-1] != []
    run(cas())


def test_validation_avant_prise():
    async def cas():
        f = Files()
        f.deposer("gk5", {"type": "GET", "body": {}})

        async def non():
            return False
        assert await f.attendre_requetes("gk5", 1, valide=non) == []
        assert f.en_attente("gk5") == 1
        async def oui():
            return True
        assert len(await f.attendre_requetes("gk5", 1, valide=oui)) == 1
    run(cas())


def test_future_annule_retire_sa_requete():
    async def cas():
        f = Files()
        fut = f.deposer("gk5", {"type": "GET", "body": {}})
        fut.cancel()
        await asyncio.sleep(0)
        assert f.en_attente("gk5") == 0
        assert await f.attendre_requetes("gk5", 0.01) == []
        # annulé après avoir été servi : la réponse tardive est ignorée
        fut = f.deposer("gk5", {"type": "GET", "body": {}})
        [rq] = await f.attendre_requetes("gk5", 1)
        fut.cancel()
        await asyncio.sleep(0)
        assert not f.livrer_reponse("gk5", {"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}})
        assert f.en_attente("gk5") == 0
    run(cas())


def test_reponse_non_servie_refusee():
    async def cas():
        f = Files()
        f.deposer("gk5", {"type": "GET", "body": {}})
        [e] = list(f._entrees.values())
        assert not f.livrer_reponse("gk5", {"msg_id": e.requete["msg_id"], "type": "GET_RESP", "body": {}})
    run(cas())


def test_duree_non_finie_donne_le_delai_par_defaut():
    from pilotage.files import delai_reponse_pour
    for d in (float("nan"), float("inf"), float("-inf"), "60", None, [60]):
        op = {"type": "OPERATE", "body": {"command": "Device.X_SECUBOX_Releve.Mesurer()", "args": {"duree_s": d}}}
        assert delai_reponse_pour(op, 120) == 90, d
