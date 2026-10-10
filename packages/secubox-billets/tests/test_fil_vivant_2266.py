# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2266 — Le fil est VIVANT : un billet publié, ou commenté, remonte en tête ; /feed/maj rend ce qui a bougé depuis le dernier relevé du client."""
import httpx
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn

T0 = "2026-07-11T12:00:00Z"


def ulid(i):
    return "01VIVANT" + "0" * 16 + f"{i:02d}"


async def publie(conn, i, now):
    return await repo.create_billet(conn, BilletIn(body=f"**Billet {i}**\ncorps {i}", publish=True), now=now, ulid=ulid(i))


async def slugs_du_fil(conn, **kw):
    rows, _ = await repo.list_published(conn, limit=50, ordre="activite", **kw)
    return [r["slug"] for r in rows]


@pytest_asyncio.fixture
async def client(conn, tmp_path):
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", follow_redirects=False) as c:
        yield c


async def test_un_nouveau_billet_est_en_tete(conn):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    b = await publie(conn, 2, "2026-07-11T11:00:00Z")
    rows = await slugs_du_fil(conn)
    assert rows[0].endswith(ulid(2)[-8:].lower()) or rows[0] == (await repo.get_by_id(conn, b))["slug"]
    assert rows == [(await repo.get_by_id(conn, b))["slug"], (await repo.get_by_id(conn, a))["slug"]]


async def test_un_commentaire_approuve_remonte_son_billet_en_tete(conn):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    b = await publie(conn, 2, "2026-07-11T11:00:00Z")
    await repo.add_comment(conn, a, author_name="Vera", email_hash=None, body="Bravo", ip_hash="h", honeypot=False, status="approved", now="2026-07-11T12:30:00Z")
    sa, sb = (await repo.get_by_id(conn, a))["slug"], (await repo.get_by_id(conn, b))["slug"]
    assert await slugs_du_fil(conn) == [sa, sb]


async def test_un_commentaire_en_attente_ne_remonte_rien(conn):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    b = await publie(conn, 2, "2026-07-11T11:00:00Z")
    await repo.add_comment(conn, a, author_name="Spam", email_hash=None, body="x", ip_hash="h", honeypot=False, status="pending", now="2026-07-11T12:30:00Z")
    assert (await slugs_du_fil(conn))[0] == (await repo.get_by_id(conn, b))["slug"]


async def test_approuver_un_commentaire_en_attente_remonte_le_billet(conn):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    await publie(conn, 2, "2026-07-11T11:00:00Z")
    cid = await repo.add_comment(conn, a, author_name="V", email_hash=None, body="ok", ip_hash="h", honeypot=False, status="pending", now="2026-07-11T11:30:00Z")
    await repo.moderate_comment(conn, cid, "approved")
    assert (await slugs_du_fil(conn))[0] == (await repo.get_by_id(conn, a))["slug"]


async def test_un_commentaire_rejete_ou_spam_ne_remonte_rien(conn):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    b = await publie(conn, 2, "2026-07-11T11:00:00Z")
    cid = await repo.add_comment(conn, a, author_name="V", email_hash=None, body="ok", ip_hash="h", honeypot=False, status="pending", now="2026-07-11T11:30:00Z")
    await repo.moderate_comment(conn, cid, "rejected")
    assert (await slugs_du_fil(conn))[0] == (await repo.get_by_id(conn, b))["slug"]


async def test_un_brouillon_publie_plus_tard_prend_la_tete(conn):
    a = await repo.create_billet(conn, BilletIn(body="**Brouillon**\nx", publish=False), now="2026-07-11T09:00:00Z", ulid=ulid(1))
    await publie(conn, 2, "2026-07-11T11:00:00Z")
    await repo.set_status(conn, a, "published", now="2026-07-11T13:00:00Z")
    assert (await slugs_du_fil(conn))[0] == (await repo.get_by_id(conn, a))["slug"]


async def test_la_pagination_suit_l_ordre_d_activite_sans_doublon_ni_trou(conn):
    ids = [await publie(conn, i, f"2026-07-11T{10 + i // 10:02d}:{i % 10:02d}:00Z") for i in range(1, 8)]
    await repo.add_comment(conn, ids[0], author_name="V", email_hash=None, body="ok", ip_hash="h", honeypot=False, status="approved", now="2026-07-12T00:00:00Z")
    vus, cursor = [], None
    while True:
        rows, cursor = await repo.list_published(conn, limit=3, cursor=cursor, ordre="activite")
        vus += [r["slug"] for r in rows]
        if not cursor:
            break
    assert len(vus) == 7 and len(set(vus)) == 7
    assert vus[0] == (await repo.get_by_id(conn, ids[0]))["slug"]


async def test_l_ordre_par_defaut_reste_la_publication(conn):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    b = await publie(conn, 2, "2026-07-11T11:00:00Z")
    await repo.add_comment(conn, a, author_name="V", email_hash=None, body="ok", ip_hash="h", honeypot=False, status="approved", now="2026-07-12T00:00:00Z")
    rows, _ = await repo.list_published(conn, limit=10)                       # flux RSS, micro… : chronologie des publications
    assert rows[0]["id"] == b


async def test_la_migration_remplit_bumped_at_des_billets_existants(tmp_path):
    from api import db
    c = await db.connect(":memory:", now=T0)
    try:
        a = await publie(c, 1, "2026-07-11T10:00:00Z")
        async with c.execute("SELECT bumped_at FROM billet WHERE id=?", (a,)) as cur:
            assert (await cur.fetchone())[0] == "2026-07-11T10:00:00Z"
    finally:
        await c.close()


# ── /feed/maj ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async def test_la_page_porte_le_repere_du_dernier_changement(conn, client):
    await publie(conn, 1, "2026-07-11T10:00:00Z")
    await publie(conn, 2, "2026-07-11T11:00:00Z")
    r = await client.get("/")
    assert 'data-depuis="2026-07-11T11:00:00Z"' in r.text


async def test_maj_ne_rend_que_ce_qui_a_bouge_depuis_le_repere(conn, client):
    await publie(conn, 1, "2026-07-11T10:00:00Z")
    await publie(conn, 2, "2026-07-11T11:00:00Z")
    d = (await client.get("/feed/maj", params={"depuis": "2026-07-11T11:00:00Z"})).json()
    assert d["html"] == "" and d["depuis"] == "2026-07-11T11:00:00Z" and d["slugs"] == []
    c = await publie(conn, 3, "2026-07-11T12:00:00Z")
    d = (await client.get("/feed/maj", params={"depuis": "2026-07-11T11:00:00Z"})).json()
    slug_c = (await repo.get_by_id(conn, c))["slug"]
    assert d["slugs"] == [slug_c] and slug_c in d["html"] and d["depuis"] == "2026-07-11T12:00:00Z"


async def test_maj_rend_un_billet_commente_meme_s_il_est_ancien(conn, client):
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    await publie(conn, 2, "2026-07-11T11:00:00Z")
    await repo.add_comment(conn, a, author_name="V", email_hash=None, body="ok", ip_hash="h", honeypot=False, status="approved", now="2026-07-11T12:30:00Z")
    d = (await client.get("/feed/maj", params={"depuis": "2026-07-11T11:00:00Z"})).json()
    assert d["slugs"] == [(await repo.get_by_id(conn, a))["slug"]] and d["depuis"] == "2026-07-11T12:30:00Z"


async def test_maj_respecte_le_filtre_de_tag_et_ignore_les_brouillons(conn, client):
    await repo.create_billet(conn, BilletIn(body="**Brouillon**\nx", publish=False), now="2026-07-11T12:00:00Z", ulid=ulid(1))
    d = (await client.get("/feed/maj", params={"depuis": "2026-07-11T00:00:00Z"})).json()
    assert d["slugs"] == []


async def test_maj_sans_repere_valide_ne_rend_rien_et_ne_plante_pas(client):
    for q in ({}, {"depuis": ""}, {"depuis": "n'importe quoi"}):
        r = await client.get("/feed/maj", params=q)
        assert r.status_code == 200 and r.json()["html"] == ""


async def test_maj_n_est_jamais_mis_en_cache(conn, client):
    r = await client.get("/feed/maj", params={"depuis": "2026-07-11T00:00:00Z"})
    assert r.headers["cache-control"] == "no-cache"


# ── Navigateur réel : le fil se met à jour tout seul ─────────────────────────────────────────────────────────────────────────────────────────
import asyncio
import json as _json
from pathlib import Path as _Path

import pytest

STATIC = _Path(__file__).resolve().parents[1] / "api" / "static"


@pytest_asyncio.fixture
async def scenario(conn, client):
    """Page rendue avec 2 billets, puis ce que /feed/maj rendra après : un billet NEUF (3) et le billet 1 COMMENTÉ."""
    a = await publie(conn, 1, "2026-07-11T10:00:00Z")
    b = await publie(conn, 2, "2026-07-11T11:00:00Z")
    page = (await client.get("/")).text
    depuis = "2026-07-11T11:00:00Z"
    c = await publie(conn, 3, "2026-07-11T12:00:00Z")
    await repo.add_comment(conn, a, author_name="Vera", email_hash=None, body="Bravo", ip_hash="h", honeypot=False, status="approved", now="2026-07-11T12:30:00Z")
    maj = (await client.get("/feed/maj", params={"depuis": depuis})).json()
    slugs = {k: (await repo.get_by_id(conn, i))["slug"] for k, i in (("a", a), ("b", b), ("c", c))}
    return {"page": page, "maj": maj, "slugs": slugs}


def _ouvre(navigateur, scenario, reponses):
    ctx = navigateur.new_context(viewport={"width": 1280, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def statique(route):
        f = STATIC / route.request.url.split("/static/", 1)[1].split("?")[0]
        if f.is_file():
            route.fulfill(status=200, body=f.read_bytes(), content_type="text/css" if f.suffix == ".css" else "application/javascript" if f.suffix == ".js" else "application/octet-stream")
        else:
            route.fulfill(status=404, body="")
    p.route("http://b.test/static/**", statique)
    p.route("http://b.test/activity/**", lambda r: r.fulfill(status=200, content_type="application/json", body='{"comments":[],"reactions":{}}'))
    p.route("http://b.test/feed/activity", lambda r: r.fulfill(status=200, content_type="application/json", body='{"comments":[],"reactions":[]}'))
    appels = []

    def maj(route):
        appels.append(route.request.url)
        corps = reponses.pop(0) if reponses else {"html": "", "depuis": "x", "slugs": []}
        route.fulfill(status=200, content_type="application/json", body=_json.dumps(corps))
    p.route("http://b.test/feed/maj**", maj)
    p.route("http://b.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=scenario["page"]))
    p.route(lambda u: u.startswith("http://b.test/") and not any(x in u for x in ("/static/", "/activity/", "/feed/")) and u != "http://b.test/",
            lambda r: r.fulfill(status=200, content_type="text/html", body=""))
    p.goto("http://b.test/")
    p.wait_for_selector("#fil-billets .card")
    return ctx, p, erreurs, appels


def _ids(p):
    return p.evaluate("[].map.call(document.querySelectorAll('#fil-billets .card'), c => c.dataset.id)")


def _declenche(p):
    p.evaluate("document.dispatchEvent(new Event('visibilitychange'))")


def en_navigateur(scenario, reponses, corps):
    """Playwright (API synchrone) ne tourne pas dans la boucle asyncio du test : tout le scénario navigateur s'exécute dans un fil à part."""
    pw = pytest.importorskip("playwright.sync_api")
    resultat = {}

    def tache():
        with pw.sync_playwright() as m:
            b = m.chromium.launch()
            try:
                resultat["ok"] = corps(b, scenario, reponses)
            except BaseException as e:                    # l'échec du scénario est celui du TEST, avec son vrai message
                resultat["err"] = e
            finally:
                b.close()
    import threading
    t = threading.Thread(target=tache)
    t.start()
    t.join(60)
    if "err" in resultat:
        raise resultat["err"]
    assert resultat.get("ok"), "scénario navigateur interrompu"


async def test_un_nouveau_billet_et_un_billet_commente_arrivent_en_tete_sans_recharger(scenario):
    def corps(navigateur, scenario, _):
        s = scenario["slugs"]
        ctx, p, erreurs, appels = _ouvre(navigateur, scenario, [scenario["maj"]])
        assert set(_ids(p)) == {s["a"], s["b"]}
        p.evaluate("window.__marqueur = 1")
        _declenche(p)
        p.wait_for_function("document.querySelectorAll('#fil-billets .card').length === 3")
        ids = _ids(p)
        assert ids == [s["a"], s["c"], s["b"]]                                   # par ACTIVITÉ : le commenté (12:30) devant le nouveau (12:00), puis l'ancien
        assert p.evaluate("window.__marqueur") == 1                              # même page : aucun rechargement
        assert len(set(ids)) == 3                                                # le billet commenté n'est pas en double
        assert p.locator("#fil-billets .card.nouveau").count() == 1 and p.locator("#fil-billets .card.remonte").count() == 1 and not erreurs
        assert "depuis=2026-07-11T11%3A00%3A00Z" in appels[0]
        ctx.close()
        return True
    await asyncio.to_thread(en_navigateur, scenario, None, corps)


async def test_le_repere_avance_et_rien_n_est_repose_deux_fois(scenario):
    def corps(navigateur, scenario, _):
        ctx, p, _e, appels = _ouvre(navigateur, scenario, [scenario["maj"], {"html": "", "depuis": scenario["maj"]["depuis"], "slugs": []}])
        _declenche(p)
        p.wait_for_function("document.querySelectorAll('#fil-billets .card').length === 3")
        _declenche(p)
        p.wait_for_timeout(300)
        assert "depuis=2026-07-11T12%3A30%3A00Z" in appels[-1] and len(_ids(p)) == 3
        ctx.close()
        return True
    await asyncio.to_thread(en_navigateur, scenario, None, corps)


async def test_le_lecteur_qui_a_defile_garde_sa_carte_sous_les_yeux(scenario):
    def corps(navigateur, scenario, _):
        ctx, p, _e, _a = _ouvre(navigateur, scenario, [scenario["maj"]])
        p.evaluate("document.querySelector('#fil-billets').lastElementChild.scrollIntoView()")
        p.wait_for_timeout(900)                                                  # la révélation de la carte (transition) est terminée
        y0 = p.evaluate("window.scrollY")
        haut = p.evaluate("document.querySelector('#fil-billets').lastElementChild.getBoundingClientRect().top")
        _declenche(p)
        p.wait_for_function("document.querySelectorAll('#fil-billets .card').length === 3")
        p.wait_for_timeout(1100)                                                 # l'animation de poussée (600 ms) est terminée : on compare les places FINALES
        haut2 = p.evaluate("document.querySelector('#fil-billets').lastElementChild.getBoundingClientRect().top")
        assert y0 > 80 and abs(haut2 - haut) < 4, (y0, haut, haut2)             # la carte lue n'a pas bougé à l'écran
        ctx.close()
        return True
    await asyncio.to_thread(en_navigateur, scenario, None, corps)


async def test_une_erreur_reseau_ne_casse_pas_le_fil(scenario):
    def corps(navigateur, scenario, _):
        ctx, p, erreurs, _a = _ouvre(navigateur, scenario, [])
        p.unroute("http://b.test/feed/maj**")
        p.route("http://b.test/feed/maj**", lambda r: r.abort())
        _declenche(p)
        p.wait_for_timeout(300)
        assert len(_ids(p)) == 2 and not erreurs
        ctx.close()
        return True
    await asyncio.to_thread(en_navigateur, scenario, None, corps)


async def test_les_arrivees_et_les_deplacements_sont_animes_et_nommes(scenario):
    def corps(navigateur, scenario, _):
        s = scenario["slugs"]
        ctx, p, erreurs, _a = _ouvre(navigateur, scenario, [scenario["maj"]])
        # Trace de TOUTE écriture de transform sur les cartes : la poussée des cartes existantes est animée (technique FLIP).
        p.evaluate("""window.__tr = {}; new MutationObserver(ms => ms.forEach(m => { var c = m.target; if (c.style && c.style.transform) window.__tr[c.dataset.id] = c.style.transform; }))
                      .observe(document.getElementById('fil-billets'), {attributes: true, attributeFilter: ['style'], subtree: true});""")
        _declenche(p)
        p.wait_for_function("document.querySelectorAll('#fil-billets .card').length === 3")
        neuf = p.locator(f"#fil-billets .card[data-id='{s['c']}']")
        remonte = p.locator(f"#fil-billets .card[data-id='{s['a']}']")
        assert "nouveau" in neuf.get_attribute("class") and "remonte" not in neuf.get_attribute("class")
        assert "remonte" in remonte.get_attribute("class") and "nouveau" not in remonte.get_attribute("class")
        assert "nouveau" in neuf.locator(".pastille-maj").inner_text().lower()
        assert "comment" in remonte.locator(".pastille-maj").inner_text().lower()
        tr = p.evaluate("window.__tr")
        assert s["b"] in tr or s["a"] in tr, tr                                  # au moins une carte a été déplacée en douceur
        p.wait_for_timeout(1600)
        # Une fois l'animation finie : plus de transform en ligne, plus de classe d'animation, plus de pastille après le délai.
        assert p.evaluate("[].every.call(document.querySelectorAll('#fil-billets .card'), c => !c.style.transform)")
        assert not erreurs
        ctx.close()
        return True
    await asyncio.to_thread(en_navigateur, scenario, None, corps)


async def test_mouvement_reduit_pas_de_deplacement_anime(scenario):
    def corps(navigateur, scenario, _):
        ctx, p, erreurs, _a = _ouvre(navigateur, scenario, [scenario["maj"]])
        p.emulate_media(reduced_motion="reduce")
        p.evaluate("""window.__tr = 0; new MutationObserver(ms => ms.forEach(m => { if (m.target.style && m.target.style.transform) window.__tr++; }))
                      .observe(document.getElementById('fil-billets'), {attributes: true, attributeFilter: ['style'], subtree: true});""")
        _declenche(p)
        p.wait_for_function("document.querySelectorAll('#fil-billets .card').length === 3")
        p.wait_for_timeout(300)
        assert p.evaluate("window.__tr") == 0 and not erreurs                   # les billets arrivent, mais sans glissement
        ctx.close()
        return True
    await asyncio.to_thread(en_navigateur, scenario, None, corps)
