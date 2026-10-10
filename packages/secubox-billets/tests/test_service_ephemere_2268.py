# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2268 — Route de SERVICE : MetaNews (jeton de flotte, sub `metanews`) ne peut créer QUE des billets éphémères, et seulement en direct sur la socket."""
import time

import httpx
import jwt
import pytest_asyncio

from api import repo
from api.main import create_app

SECRET = "secret-de-test-pour-la-flotte-0123456789"


@pytest_asyncio.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", SECRET)
    import secubox_core.auth as A
    monkeypatch.setattr(A, "get_config", lambda *_a, **_k: {})


def jeton(sub="metanews", exp=300, secret=SECRET, alg="HS256"):
    return jwt.encode({"sub": sub, "iat": int(time.time()), "exp": int(time.time()) + exp}, secret, algorithm=alg)


@pytest_asyncio.fixture
async def client(conn, tmp_path):
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


CORPS = {"body": "**Sujet du jour**\n\nrésumé", "ref_url": "https://exemple.org/s/1", "ttl_s": 300}


async def test_le_service_cree_un_billet_ephemere_visible_dans_le_fil(conn, client):
    r = await client.post("/service/ephemere", json=CORPS, headers=h(jeton()))
    assert r.status_code == 201, r.text
    d = r.json()
    row = await repo.get_by_id(conn, d["id"])
    assert row["status"] == "published" and row["expires_at"] and d["expires_at"] == row["expires_at"]
    assert d["slug"] in (await client.get("/")).text


async def test_sans_jeton_ou_jeton_invalide_refuse(client):
    assert (await client.post("/service/ephemere", json=CORPS)).status_code in (401, 403)
    assert (await client.post("/service/ephemere", json=CORPS, headers=h("n-importe-quoi"))).status_code in (401, 403)
    assert (await client.post("/service/ephemere", json=CORPS, headers=h(jeton(secret="un-autre-secret-0123456789012345678")))).status_code in (401, 403)
    assert (await client.post("/service/ephemere", json=CORPS, headers=h(jeton(exp=-10)))).status_code in (401, 403)


async def test_seul_le_service_metanews_est_admis(client):
    for sub in ("bbs", "admin", "gandalf", "metanews2"):
        assert (await client.post("/service/ephemere", json=CORPS, headers=h(jeton(sub=sub)))).status_code == 403, sub


async def test_le_ttl_est_obligatoire_et_borne_a_une_heure(client):
    sans = {k: v for k, v in CORPS.items() if k != "ttl_s"}
    assert (await client.post("/service/ephemere", json=sans, headers=h(jeton()))).status_code == 422          # un service ne crée pas de billet DURABLE
    assert (await client.post("/service/ephemere", json={**CORPS, "ttl_s": 3601}, headers=h(jeton()))).status_code == 422
    assert (await client.post("/service/ephemere", json={**CORPS, "ttl_s": 10}, headers=h(jeton()))).status_code == 422


async def test_un_appel_venu_du_proxy_est_refuse(client):
    # nginx et le WAF posent toujours X-Real-IP / X-Forwarded-For : la route est INTERNE, réservée à l'appel direct sur la socket.
    for en_tete in ({"X-Forwarded-For": "203.0.113.9"}, {"X-Real-IP": "203.0.113.9"}):
        r = await client.post("/service/ephemere", json=CORPS, headers={**h(jeton()), **en_tete})
        assert r.status_code == 403 and "interne" in r.text.lower()


async def test_plafond_horaire_cote_billets(conn, client, monkeypatch):
    import api.routes.service as S
    monkeypatch.setattr(S, "PLAFOND_HORAIRE", 3)
    for i in range(3):
        assert (await client.post("/service/ephemere", json={**CORPS, "body": f"**S{i}**\nx"}, headers=h(jeton()))).status_code == 201
    r = await client.post("/service/ephemere", json={**CORPS, "body": "**S4**\nx"}, headers=h(jeton()))
    assert r.status_code == 429


async def test_le_service_ne_peut_ni_modifier_ni_supprimer(client):
    tok = h(jeton())
    assert (await client.delete("/admin/api/billets/x", headers=tok)).status_code in (401, 403)
    assert (await client.put("/admin/api/billets/x", json={"body": "y"}, headers=tok)).status_code in (401, 403, 404, 422)
    assert (await client.post("/admin/api/billets", json={"body": "durable"}, headers=tok)).status_code in (401, 403)
