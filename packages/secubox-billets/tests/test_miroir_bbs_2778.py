# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2778 — Les posts et réponses PUBLICS des fils BBS liés à un billet deviennent des commentaires SYSTÈME du billet (auteur en référence), le font remonter
dans le fil, et leur nombre s'affiche à droite des cartes du fil, comme les « likes » internes.

Jamais de contenu local/privé, supprimé, ni d'un fil non public. Lecture seule du BBS ; idempotent."""
import sqlite3
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from api import repo
from api.main import create_app
from api.models import BilletIn
from api.services import miroir_bbs as M

T0 = "2026-07-11T10:00:00Z"
DOMAINE = "gk2.secubox.in"


def epoch(iso):
    import calendar
    return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ"))


def fabrique_bbs(tmp_path, *, fils, posts):
    """Un mini BBS : index.db (users, threads, posts) + fichiers de corps sous content/ (format réel : en-tête --- puis corps)."""
    racine = tmp_path / "bbs"
    (racine / "content").mkdir(parents=True)
    db = racine / "index.db"
    c = sqlite3.connect(db)
    c.executescript("""
      CREATE TABLE users (id INTEGER PRIMARY KEY, handle TEXT NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', created_at INTEGER NOT NULL DEFAULT 0, disabled_at INTEGER);
      CREATE TABLE threads (id INTEGER PRIMARY KEY, title TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'local');
      CREATE TABLE posts (id INTEGER PRIMARY KEY, thread_id INTEGER NOT NULL, author_id INTEGER NOT NULL, body_path TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'local',
                          created_at INTEGER NOT NULL, deleted_at INTEGER);
      INSERT INTO users(id, handle, display_name) VALUES (1, 'gk2', 'Gérald'), (2, 'frodon', 'Frodon');""")
    for tid, titre, vis in fils:
        c.execute("INSERT INTO threads(id, title, visibility) VALUES (?,?,?)", (tid, titre, vis))
    for pid, tid, auteur, vis, quand, corps, supprime in posts:
        chemin = f"content/{tid}/{pid}.md"
        (racine / "content" / str(tid)).mkdir(parents=True, exist_ok=True)
        (racine / chemin).write_text(f"---\nthread: {tid}\nauthor: x\nvisibility: {vis}\n---\n{corps}\n")
        c.execute("INSERT INTO posts(id, thread_id, author_id, body_path, visibility, created_at, deleted_at) VALUES (?,?,?,?,?,?,?)", (pid, tid, auteur, chemin, vis, epoch(quand), supprime))
    c.commit()
    c.close()
    return str(db), str(racine / "content")


async def billet(conn, i=1, ref=None, corps="**Plan**\nle billet", now=T0):
    return await repo.create_billet(conn, BilletIn(body=corps, ref_url=ref, publish=True), now=now, ulid="01MIROIR" + "0" * 16 + f"{i:02d}")


FILS = [(1147, "business plan", "public")]


# ---------- repérer les fils liés ----------

def test_le_fil_de_ref_url_est_repere():
    assert M.fils_lies("https://bbs.gk2.secubox.in/t/1147", "peu importe", DOMAINE) == [1147]


def test_les_fils_cites_dans_le_corps_sont_reperes_sans_doublon():
    corps = "voir https://bbs.gk2.secubox.in/t/12 et https://bbs.gk2.secubox.in/t/13, encore /t/12 sur https://bbs.gk2.secubox.in/t/12"
    assert M.fils_lies("https://bbs.gk2.secubox.in/t/12", corps, DOMAINE) == [12, 13]


def test_un_autre_hote_n_est_pas_notre_bbs():
    assert M.fils_lies("https://bbs.evil.test/t/9", "https://exemple.org/t/10 https://bbs.gk2.secubox.in.evil.test/t/11", DOMAINE) == []
    assert M.fils_lies("https://hall.gk2.secubox.in/t/9", "", DOMAINE) == []


def test_le_nombre_de_fils_par_billet_est_borne():
    corps = " ".join(f"https://bbs.gk2.secubox.in/t/{i}" for i in range(1, 20))
    assert len(M.fils_lies(None, corps, DOMAINE)) == M.MAX_FILS


# ---------- lecture du BBS ----------

def test_seuls_les_posts_publics_non_supprimes_d_un_fil_public_sont_lus(tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS + [(2000, "prive", "local")], posts=[
        (1, 1147, 1, "public", "2026-07-11T10:00:00Z", "le billet lui-même", None),
        (2, 1147, 2, "public", "2026-07-11T11:00:00Z", "une réponse publique", None),
        (3, 1147, 2, "local", "2026-07-11T11:30:00Z", "réponse locale SECRETE", None),
        (4, 1147, 2, "public", "2026-07-11T12:00:00Z", "réponse supprimée", 1784000000),
        (5, 2000, 1, "public", "2026-07-11T12:00:00Z", "fil non public", None)])
    p1147 = M.lire_fil(db, content, 1147)
    assert [x["post_id"] for x in p1147] == [1, 2]
    assert M.lire_fil(db, content, 2000) == []
    assert "SECRETE" not in str(p1147)


def test_le_corps_est_celui_du_disque_sans_l_en_tete(tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=[(2, 1147, 2, "public", "2026-07-11T11:00:00Z", "Bonjour\nà tous", None)])
    p = M.lire_fil(db, content, 1147)[0]
    assert p["corps"] == "Bonjour\nà tous" and p["auteur"] == "frodon" and p["quand"] == "2026-07-11T11:00:00Z"


def test_un_corps_hors_du_dossier_de_contenu_est_refuse(tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=[(2, 1147, 2, "public", "2026-07-11T11:00:00Z", "ok", None)])
    c = sqlite3.connect(db)
    c.execute("UPDATE posts SET body_path='../../etc/passwd' WHERE id=2")
    c.commit()
    c.close()
    assert M.lire_fil(db, content, 1147) == []


def test_un_bbs_absent_ou_illisible_rend_une_liste_vide(tmp_path):
    assert M.lire_fil(str(tmp_path / "rien.db"), str(tmp_path), 1) == []
    (tmp_path / "x.db").write_text("pas une base")
    assert M.lire_fil(str(tmp_path / "x.db"), str(tmp_path), 1) == []


def test_le_corps_est_borne_et_nettoye(tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=[(2, 1147, 2, "public", "2026-07-11T11:00:00Z", "a\x00b" + "x" * 5000, None)])
    c = M.lire_fil(db, content, 1147)[0]["corps"]
    assert len(c) <= M.MAX_CORPS and "\x00" not in c


def test_les_references_de_fichiers_bbs_deviennent_des_liens_absolus(tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=[(2, 1147, 2, "public", "2026-07-11T11:00:00Z", "/f/126.png", None)])
    assert M.lire_fil(db, content, 1147, hote_bbs="bbs.gk2.secubox.in")[0]["corps"] == "https://bbs.gk2.secubox.in/f/126.png"


# ---------- synchronisation ----------

async def sync(conn, tmp_path, posts, ref="https://bbs.gk2.secubox.in/t/1147", corps="**Plan**\nle billet"):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=posts)
    bid = await billet(conn, ref=ref, corps=corps)
    n = await M.synchroniser(conn, db, content, DOMAINE, maintenant="2026-07-11T13:00:00Z")
    sync.bbs = (db, content)
    return bid, n


POSTS = [(1, 1147, 1, "public", "2026-07-11T10:00:00Z", "**Plan**\nle billet", None),
         (2, 1147, 2, "public", "2026-07-11T11:00:00Z", "une réponse publique", None)]


async def test_une_reponse_publique_devient_un_commentaire_systeme_avec_l_auteur_en_reference(conn, tmp_path):
    bid, n = await sync(conn, tmp_path, POSTS)
    cs = await repo.list_approved_comments(conn, bid)
    assert n == 1 and len(cs) == 1, "le billet lui-même (post 1, corps identique) n'est pas recopié"
    c = cs[0]
    assert c["body"] == "une réponse publique" and c["created_at"] == "2026-07-11T11:00:00Z"
    assert c["source"] == "bbs" and c["author_ref"] == "bbs:frodon" and c["author_name"] == "frodon"


async def test_la_synchronisation_est_idempotente(conn, tmp_path):
    bid, _ = await sync(conn, tmp_path, POSTS)
    db, content = sync.bbs
    assert await M.synchroniser(conn, db, content, DOMAINE, maintenant="2026-07-11T14:00:00Z") == 0
    assert len(await repo.list_approved_comments(conn, bid)) == 1


async def test_la_reponse_fait_remonter_le_billet_a_l_heure_de_la_reponse(conn, tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=POSTS)
    a = await billet(conn, 1, ref="https://bbs.gk2.secubox.in/t/1147", now="2026-07-11T10:00:00Z")
    b = await billet(conn, 2, ref=None, corps="**Autre**\nbillet", now="2026-07-11T12:00:00Z")
    rows, _ = await repo.list_published(conn, limit=10, ordre="activite")
    assert [r["id"] for r in rows][0] == b
    await M.synchroniser(conn, db, content, DOMAINE, maintenant="2026-07-11T13:00:00Z")
    rows, _ = await repo.list_published(conn, limit=10, ordre="activite")
    assert rows[0]["id"] == a or rows[0]["bumped_at"] is not None
    ba = (await repo.get_by_id(conn, a))["bumped_at"]
    assert ba == "2026-07-11T11:00:00Z", "à l'heure de la réponse (jamais l'heure de la synchro)"


async def test_le_bump_ne_recule_jamais(conn, tmp_path):
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=[POSTS[0], (2, 1147, 2, "public", "2026-07-11T09:00:00Z", "ancienne réponse", None)])
    a = await billet(conn, 1, ref="https://bbs.gk2.secubox.in/t/1147", now="2026-07-11T10:00:00Z")
    await M.synchroniser(conn, db, content, DOMAINE, maintenant="2026-07-11T13:00:00Z")
    assert (await repo.get_by_id(conn, a))["bumped_at"] == "2026-07-11T10:00:00Z"


async def test_une_reponse_devenue_locale_ou_supprimee_disparait(conn, tmp_path):
    bid, _ = await sync(conn, tmp_path, POSTS)
    db, content = sync.bbs
    c = sqlite3.connect(db)
    c.execute("UPDATE posts SET visibility='local' WHERE id=2")
    c.commit()
    c.close()
    await M.synchroniser(conn, db, content, DOMAINE, maintenant="2026-07-11T14:00:00Z")
    assert await repo.list_approved_comments(conn, bid) == []


async def test_un_billet_sans_fil_lie_n_est_pas_touche(conn, tmp_path):
    bid, n = await sync(conn, tmp_path, POSTS, ref=None)
    assert n == 0 and await repo.list_approved_comments(conn, bid) == []


async def test_le_corps_d_une_reponse_n_est_jamais_du_html_execute(conn, tmp_path):
    posts = [POSTS[0], (2, 1147, 2, "public", "2026-07-11T11:00:00Z", "<script>alert(1)</script> <b>x</b>", None)]
    bid, _ = await sync(conn, tmp_path, posts)
    c = (await repo.list_approved_comments(conn, bid))[0]
    assert c["body"] == "<script>alert(1)</script> <b>x</b>", "stocké tel quel : l'affichage échappe (linkify_plain)"


# ---------- fil et page ----------

@pytest_asyncio.fixture
async def client(conn, tmp_path):
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", follow_redirects=False) as c:
        yield c, app


async def test_le_nombre_de_commentaires_est_compte_par_billet(conn, tmp_path):
    bid, _ = await sync(conn, tmp_path, POSTS)
    autre = await billet(conn, 2, corps="**Autre**\nbillet")
    await repo.add_comment(conn, autre, author_name="V", email_hash=None, body="x", ip_hash="h", honeypot=False, status="pending", now="2026-07-11T12:00:00Z")
    assert await repo.comment_counts(conn, [bid, autre]) == {bid: 1, autre: 0}


async def test_la_page_du_billet_montre_la_reponse_du_bbs_avec_son_auteur(conn, client, tmp_path, monkeypatch):
    c, app = client
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=POSTS)
    monkeypatch.setattr(app.state, "bbs_db", db, raising=False)
    monkeypatch.setattr(app.state, "bbs_content", content, raising=False)
    monkeypatch.setattr(app.state, "domaine", DOMAINE, raising=False)
    bid = await billet(conn, ref="https://bbs.gk2.secubox.in/t/1147")
    slug = (await repo.get_by_id(conn, bid))["slug"]
    r = await c.get(f"/b/{slug}")
    assert r.status_code == 200
    assert "une réponse publique" in r.text and "frodon" in r.text
    assert "BBS" in r.text, "marqué comme commentaire système du BBS"


async def test_le_fil_montre_le_nombre_de_commentaires_a_droite_des_cartes(conn, client, tmp_path, monkeypatch):
    c, app = client
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=POSTS + [(3, 1147, 1, "public", "2026-07-11T11:30:00Z", "deuxième réponse", None)])
    monkeypatch.setattr(app.state, "bbs_db", db, raising=False)
    monkeypatch.setattr(app.state, "bbs_content", content, raising=False)
    monkeypatch.setattr(app.state, "domaine", DOMAINE, raising=False)
    await billet(conn, ref="https://bbs.gk2.secubox.in/t/1147")
    r = await c.get("/feed/suite")
    assert r.status_code == 200
    html = r.json()["html"]
    assert 'data-comment' in html and '<span class="n" title="commentaires' in html and ">2</span>" in html, "2 réponses du BBS, à côté de 💬"


async def test_un_billet_sans_commentaire_n_affiche_pas_de_zero(conn, client):
    c, _ = client
    await billet(conn, corps="**Seul**\nbillet")
    html = (await c.get("/feed/suite")).json()["html"]
    assert '<span class="n" title="commentaires, réponses du BBS comprises"></span>' in html


async def test_une_reponse_du_bbs_fait_remonter_le_billet_dans_le_fil_servi(conn, client, tmp_path, monkeypatch):
    c, app = client
    db, content = fabrique_bbs(tmp_path, fils=FILS, posts=POSTS)
    monkeypatch.setattr(app.state, "bbs_db", db, raising=False)
    monkeypatch.setattr(app.state, "bbs_content", content, raising=False)
    monkeypatch.setattr(app.state, "domaine", DOMAINE, raising=False)
    a = await billet(conn, 1, ref="https://bbs.gk2.secubox.in/t/1147", now="2026-07-11T10:00:00Z")
    b = await billet(conn, 2, corps="**Autre**\nbillet", now="2026-07-11T10:30:00Z")
    sa, sb = (await repo.get_by_id(conn, a))["slug"], (await repo.get_by_id(conn, b))["slug"]
    html = (await c.get("/feed/suite")).json()["html"]
    assert html.index(f"/b/{sa}") < html.index(f"/b/{sb}"), "la réponse de 11 h place le billet lié avant celui de 10 h 30"


async def test_une_panne_du_bbs_ne_casse_ni_le_fil_ni_la_page(conn, client, monkeypatch):
    c, app = client
    monkeypatch.setattr(app.state, "bbs_db", "/n/existe/pas.db", raising=False)
    monkeypatch.setattr(app.state, "domaine", DOMAINE, raising=False)
    bid = await billet(conn, ref="https://bbs.gk2.secubox.in/t/1147")
    slug = (await repo.get_by_id(conn, bid))["slug"]
    assert (await c.get("/feed/suite")).status_code == 200 and (await c.get(f"/b/{slug}")).status_code == 200


async def test_les_miroirs_sont_balayes_au_plus_toutes_les_20_secondes(conn, client, tmp_path, monkeypatch):
    c, app = client
    appels = []

    async def faux(*a, **k):
        appels.append(1)
        return 0
    monkeypatch.setattr(M, "synchroniser", faux)
    monkeypatch.setattr(app.state, "domaine", DOMAINE, raising=False)
    await c.get("/feed/suite")
    await c.get("/feed/suite")
    await c.get("/feed/maj?depuis=2026-07-11T10:00:00Z")
    assert len(appels) == 1, "trois requêtes du fil, un seul balayage"
