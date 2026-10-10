# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2268 — Billets ÉPHÉMÈRES : une durée de vie (`ttl_s`), un billet qui disparaît du fil à l'échéance, un balayage qui l'archive puis le supprime."""
import asyncio
import json as _json
from datetime import datetime, timedelta, timezone
from pathlib import Path as _Path

import httpx
import pytest
import pytest_asyncio
from pydantic import ValidationError

from api import repo
from api.main import create_app
from api.models import BilletIn

T0 = "2026-07-11T12:00:00Z"
T_4MIN = "2026-07-11T12:04:00Z"
T_6MIN = "2026-07-11T12:06:00Z"
STATIC = _Path(__file__).resolve().parents[1] / "api" / "static"


def ulid(i):
    return "01EPHEM" + "0" * 17 + f"{i:02d}"


async def ephemere(conn, i, ttl=300, now=T0):
    return await repo.create_billet(conn, BilletIn(body=f"**Éphémère {i}**\ncorps {i}", publish=True, ttl_s=ttl), now=now, ulid=ulid(i))


async def durable(conn, i, now=T0):
    return await repo.create_billet(conn, BilletIn(body=f"**Durable {i}**\ncorps {i}", publish=True), now=now, ulid=ulid(i))


async def fil(conn, maintenant):
    rows, _ = await repo.list_published(conn, limit=50, ordre="activite", maintenant=maintenant)
    return [r["id"] for r in rows]


# ── Modèle ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_ttl_est_borne_et_exige_la_publication():
    assert BilletIn(body="x", publish=True, ttl_s=300).ttl_s == 300
    for mauvais in (0, 5, 29, 86401, -1):
        with pytest.raises(ValidationError):
            BilletIn(body="x", publish=True, ttl_s=mauvais)
    with pytest.raises(ValidationError):
        BilletIn(body="x", publish=False, ttl_s=300)                    # un brouillon n'expire pas : l'horloge part à la publication


async def test_l_echeance_est_publication_plus_ttl(conn):
    b = await ephemere(conn, 1, ttl=300)
    assert (await repo.get_by_id(conn, b))["expires_at"] == "2026-07-11T12:05:00Z"
    d = await durable(conn, 2)
    assert (await repo.get_by_id(conn, d))["expires_at"] is None


# ── Lecture ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_un_billet_ephemere_est_dans_le_fil_avant_son_echeance_et_plus_apres(conn):
    b = await ephemere(conn, 1)
    d = await durable(conn, 2)
    assert set(await fil(conn, T_4MIN)) == {b, d}
    assert await fil(conn, T_6MIN) == [d]                                # exclu DÈS l'échéance, sans attendre le balayage


async def test_maj_ne_rend_pas_un_billet_echu(conn):
    await ephemere(conn, 1)
    assert await repo.list_depuis(conn, "2026-07-11T11:00:00Z", maintenant=T_4MIN)
    assert await repo.list_depuis(conn, "2026-07-11T11:00:00Z", maintenant=T_6MIN) == []


async def test_les_flux_rss_et_json_n_exposent_pas_un_billet_echu(conn, tmp_path):
    b = await ephemere(conn, 1, ttl=30, now=(datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        assert (await repo.get_by_id(conn, b))["slug"] not in (await c.get("/feed.xml")).text
        assert (await repo.get_by_id(conn, b))["slug"] not in (await c.get("/feed.json")).text


async def test_le_permalien_d_un_billet_echu_repond_410(conn, tmp_path):
    ancien = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b = await ephemere(conn, 1, ttl=60, now=ancien)
    frais = await ephemere(conn, 2, ttl=3600, now=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/b/" + (await repo.get_by_id(conn, b))["slug"])
        assert r.status_code == 410 and "expiré" in r.text.lower()
        assert (await c.get("/b/" + (await repo.get_by_id(conn, frais))["slug"])).status_code == 200


# ── Balayage ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_le_balayage_archive_a_l_echeance_puis_supprime_apres_un_jour(conn):
    b = await ephemere(conn, 1)
    d = await durable(conn, 2)
    assert await repo.expirer(conn, T_4MIN) == (0, 0)
    assert await repo.expirer(conn, T_6MIN) == (1, 0)
    assert (await repo.get_by_id(conn, b))["status"] == "archived" and (await repo.get_by_id(conn, d))["status"] == "published"
    assert await repo.expirer(conn, T_6MIN) == (0, 0)                    # idempotent
    assert await repo.expirer(conn, "2026-07-12T12:06:00Z") == (0, 1)    # > 24 h après l'échéance : supprimé
    assert await repo.get_by_id(conn, b) is None and await repo.get_by_id(conn, d) is not None


async def test_le_balayage_ne_touche_jamais_un_billet_durable_ni_un_brouillon(conn):
    d = await durable(conn, 1)
    br = await repo.create_billet(conn, BilletIn(body="**Brouillon**\nx", publish=False), now=T0, ulid=ulid(2))
    assert await repo.expirer(conn, "2030-01-01T00:00:00Z") == (0, 0)
    assert (await repo.get_by_id(conn, d)) and (await repo.get_by_id(conn, br))


# ── API JWT ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_la_charge_utile_de_l_api_accepte_ttl_s():
    from api.routes.jwt_admin import BilletPayload
    assert BilletPayload(body="x", ttl_s=300).ttl_s == 300 and BilletPayload(body="x").ttl_s is None


# ── Navigateur réel : la carte s'éteint à l'échéance, avec un compte à rebours ──────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def page_ephemere(conn, tmp_path):
    maintenant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    e = await ephemere(conn, 1, ttl=60, now=maintenant)
    await conn.execute("UPDATE billet SET expires_at=? WHERE id=?", (repo._plus_secondes(maintenant, 4), e))      # 4 s de vie : le minimum public (30 s) est trop long pour un test
    await conn.commit()
    d = await durable(conn, 2, now=maintenant)
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        page = (await c.get("/")).text
    return {"page": page, "e": (await repo.get_by_id(conn, e))["slug"], "d": (await repo.get_by_id(conn, d))["slug"]}


def _navigateur(corps, page):
    pw = pytest.importorskip("playwright.sync_api")
    res = {}

    def tache():
        with pw.sync_playwright() as m:
            b = m.chromium.launch()
            try:
                ctx = b.new_context(viewport={"width": 1280, "height": 900})
                p = ctx.new_page()
                erreurs = []
                p.on("pageerror", lambda e: erreurs.append(str(e)))

                def statique(route):
                    f = STATIC / route.request.url.split("/static/", 1)[1].split("?")[0]
                    route.fulfill(status=200 if f.is_file() else 404, body=f.read_bytes() if f.is_file() else b"",
                                  content_type="text/css" if f.suffix == ".css" else "application/javascript")
                p.route("http://b.test/static/**", statique)
                p.route("http://b.test/activity/**", lambda r: r.fulfill(status=200, content_type="application/json", body='{"comments":[],"reactions":{}}'))
                p.route("http://b.test/feed/**", lambda r: r.fulfill(status=200, content_type="application/json", body='{"comments":[],"reactions":[],"html":"","slugs":[]}'))
                p.route("http://b.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=page["page"]))
                p.goto("http://b.test/")
                p.wait_for_selector("#fil-billets .card")
                res["ok"] = corps(p, erreurs)
                ctx.close()
            except BaseException as e:
                res["err"] = e
            finally:
                b.close()
    import threading
    t = threading.Thread(target=tache)
    t.start()
    t.join(60)
    if "err" in res:
        raise res["err"]
    assert res.get("ok")


async def test_la_carte_ephemere_affiche_son_compte_a_rebours_puis_s_eteint(page_ephemere):
    def corps(p, erreurs):
        e, d = page_ephemere["e"], page_ephemere["d"]
        carte = p.locator(f"#fil-billets .card[data-id='{e}']")
        assert carte.count() == 1
        assert "⏳" in carte.locator(".pastille-ephemere").inner_text()           # compte à rebours visible
        assert p.locator(f"#fil-billets .card[data-id='{d}'] .pastille-ephemere").count() == 0     # un billet durable n'en a pas
        p.wait_for_selector(f"#fil-billets .card[data-id='{e}']", state="detached", timeout=8000)    # elle disparaît d'elle-même
        assert p.locator(f"#fil-billets .card[data-id='{d}']").count() == 1                         # l'autre reste
        assert not erreurs
        return True
    await asyncio.to_thread(_navigateur, corps, page_ephemere)
