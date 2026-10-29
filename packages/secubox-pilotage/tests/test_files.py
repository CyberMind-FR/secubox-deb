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
