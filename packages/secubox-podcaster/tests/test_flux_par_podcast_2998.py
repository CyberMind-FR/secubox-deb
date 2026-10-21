# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2998 — chaque podcast a son propre flux RSS, et la bibliothèque publique les décrit un par un.

Lecture seule : `GET /share/feed/{fid}.xml` et la liste `podcasts` de `GET /public/library` portent la même garde
`require_lecture` que le flux global ; rien n'est écrit, rien de non téléchargé n'est exposé.
"""
import asyncio
import importlib
import inspect
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

SRC = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")


@pytest.fixture
def api(tmp_path, monkeypatch):
    import api.store as st
    importlib.reload(st)
    st.DB_PATH = tmp_path / "p.db"
    st.init()
    import api.main as m
    monkeypatch.setattr(m, "store", st)
    monkeypatch.setattr(m, "_worker_started", True)          # aucune tâche de fond en test
    monkeypatch.setattr(m, "MEDIA", tmp_path / "media")
    monkeypatch.setitem(m.CFG, "public_base", "https://podcaster.exemple.test")
    a = st.add_feed("https://a.test/rss", {"title": "Atelier", "description": "Le samedi", "image": "https://a.test/pochette.jpg"})
    b = st.add_feed("audiobook:chronique:1", {"title": "Chronique", "image": "/api/v1/podcaster/feeds/2/cover"})
    for fid, guid, titre, pub, done in ((a, "g1", "Un", 1000, True), (a, "g2", "Deux", 2000, True), (a, "g3", "Pas encore", 3000, False),
                                        (b, "g4", "Trois", 500, True)):
        st.upsert_episode(fid, {"guid": guid, "title": titre, "pubdate": pub, "mime": "audio/mpeg", "bytes": 1024})
        if done:
            ep = [e for e in st.list_episodes(fid) if e["guid"] == guid][0]
            st.set_episode(ep["id"], state="done", local_path=str(tmp_path / f"{guid}.mp3"))
    return m, st, a, b


class _Req:
    base_url = "http://sock/"


def _run(coro):
    return asyncio.run(coro)


def test_la_bibliotheque_decrit_chaque_podcast_avec_son_flux(api):
    m, st, a, b = api
    lib = _run(m.public_library())
    pods = {p["id"]: p for p in lib["podcasts"]}
    assert set(pods) == {a, b}
    at = pods[a]
    assert at["title"] == "Atelier" and at["description"] == "Le samedi" and at["image"] == "https://a.test/pochette.jpg"
    assert at["episodes"] == 2 and at["last"] == 2000 and at["bytes"] == 2048        # l'épisode non téléchargé ne compte pas
    assert at["rss"] == f"/api/v1/podcaster/share/feed/{a}.xml" and at["zip"] == f"/api/v1/podcaster/public/feed/{a}/zip"
    assert pods[b]["episodes"] == 1 and pods[b]["image"] == "/api/v1/podcaster/feeds/2/cover"
    assert lib["feeds"] == {"Atelier": 2, "Chronique": 1}                             # contrat existant conservé (Hall, cardlets)
    assert [e["feed_id"] for e in lib["episodes"]].count(a) == 2


def test_le_flux_rss_d_un_podcast_ne_porte_que_ses_episodes_telecharges(api):
    m, st, a, b = api
    r = _run(m.share_feed_podcast(a, _Req()))
    assert r.media_type == "application/rss+xml"
    ch = ET.fromstring(r.body).find("channel")
    assert ch.findtext("title") == "Atelier" and ch.findtext("description") == "Le samedi"
    assert ch.find("image").findtext("url") == "https://a.test/pochette.jpg"
    titres = [i.findtext("title") for i in ch.findall("item")]
    assert titres == ["Deux", "Un"] and "Pas encore" not in titres and "Trois" not in titres
    enc = ch.find("item").find("enclosure").get("url")
    assert enc.startswith("https://podcaster.exemple.test/api/v1/podcaster/media/")
    assert ch.find("link").text == f"https://podcaster.exemple.test/share/feed/{a}.xml" or ch.findtext("link")


def test_une_pochette_locale_devient_absolue_dans_le_flux(api):
    m, st, a, b = api
    ch = ET.fromstring(_run(m.share_feed_podcast(b, _Req())).body).find("channel")
    assert ch.find("image").findtext("url") == "https://podcaster.exemple.test/api/v1/podcaster/feeds/2/cover"


def test_un_podcast_inconnu_repond_404(api):
    m, *_ = api
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ex:
        _run(m.share_feed_podcast(9999, _Req()))
    assert ex.value.status_code == 404


def test_meme_garde_de_lecture_que_le_flux_global():
    deb = SRC.index("async def share_feed_podcast")
    decor = SRC[SRC.rfind("@router.get", 0, deb):deb]
    assert '"/share/feed/{fid}.xml"' in decor and "require_lecture" in decor
    assert "require_jwt" not in decor and "require_session" not in decor
    import api.main as m
    assert inspect.iscoroutinefunction(m.share_feed_podcast)
