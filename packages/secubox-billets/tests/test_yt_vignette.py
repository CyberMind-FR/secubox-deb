# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Miniatures YouTube relayées par la box (#1792).

Chargée en direct depuis i.ytimg, la vignette d'un billet-clip disparaissait
dès qu'un filtre refusait ce domaine (protection anti-pistage, liste de
blocage, CSP d'une page hôte). Elle est désormais servie depuis l'origine de
billets, et seulement pour une vidéo qu'un billet référence.
"""
import httpx
import pytest_asyncio

from api import main as M
from api import repo
from api.main import create_app
from api.models import BilletIn
from api.services import snapshot

NOW = "2026-07-11T12:00:00Z"
VID = "zKFqbyDR6M4"
JPEG = b"\xff\xd8\xff\xe0" + b"x" * 4000


@pytest_asyncio.fixture
async def client(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(tmp_path / "media"))
    appels = []

    def _faux(url, *, client, resolver):
        appels.append(url)
        return JPEG
    monkeypatch.setattr(snapshot, "_youtube_thumb_bytes", _faux)
    await repo.create_billet(conn, BilletIn(body="Suprême NTM — clip", publish=True,
                                            ref_url=f"https://www.youtube.com/watch?v={VID}"),
                             now=NOW, ulid="01YTVIG0000000000000000AA")
    app = create_app(conn, secret="s", revisions_dir=str(tmp_path / "r"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c, appels, tmp_path


def test_l_affiche_ne_pointe_plus_vers_google():
    p = M._poster_for({"ref_url": f"https://youtu.be/{VID}"})
    assert p == f"/yt-vignette?v={VID}"
    assert M._poster_for({"embed_snapshot_url": "/media/x.jpg", "ref_url": f"https://youtu.be/{VID}"}) == "/media/x.jpg"


async def test_relai_puis_cache(client):
    c, appels, tmp = client
    for _ in range(2):
        r = await c.get(f"/yt-vignette?v={VID}")
        assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"
        assert r.content == JPEG
    assert len(appels) == 1, "la seconde demande doit venir du cache"
    assert (tmp / "media" / "yt" / f"{VID}.jpg").is_file()


async def test_identifiant_inconnu_ou_malforme_jamais_telecharge(client):
    c, appels, _ = client
    for v in ("AAAAAAAAAAA", "../../etc/x", "court", ""):
        assert (await c.get("/yt-vignette", params={"v": v})).status_code == 404, v
    assert appels == []


async def test_la_carte_du_hall_porte_la_miniature(client):
    c, _, _ = client
    r = await c.get("/micro")
    assert r.status_code == 200
    assert f"/yt-vignette?v={VID}" in r.text
