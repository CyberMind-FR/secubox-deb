# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2395 — une vidéo attachée à un billet a une vignette (image d'aperçu extraite par ffmpeg), le fil ne montre plus un placeholder."""
import shutil
import subprocess

import pytest

from api.services import media

pytestmark = pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg absent")


@pytest.fixture
def mp4(tmp_path):
    f = tmp_path / "t.mp4"
    subprocess.run(["ffmpeg", "-y", "-f", "lavfi", "-i", "testsrc=duration=2:size=320x240:rate=10", "-pix_fmt", "yuv420p", str(f)],
                   check=True, capture_output=True)
    return f.read_bytes()


def test_une_video_donne_une_vignette_jpeg(mp4, tmp_path):
    nom = media.poster_video("01TESTVIDEO", mp4, "mp4", directory=tmp_path)
    assert nom == "01TESTVIDEO_t.jpg"
    assert (tmp_path / nom).read_bytes()[:3] == b"\xff\xd8\xff"


def test_un_contenu_illisible_ne_leve_pas_et_ne_cree_rien(tmp_path):
    assert media.poster_video("01BAD", b"pas une video", "mp4", directory=tmp_path) == ""
    assert not list(tmp_path.glob("01BAD*"))


def test_sans_ffmpeg_pas_de_vignette_mais_pas_d_erreur(mp4, tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    assert media.poster_video("01NOFF", mp4, "mp4", directory=tmp_path) == ""


def test_la_galerie_de_la_page_ne_montre_que_des_images():
    from pathlib import Path
    t = (Path(__file__).resolve().parents[1] / "api/templates/billet.html").read_text(encoding="utf-8")
    assert "m.mime.startswith('image/')" in t, "une vidéo avec vignette ne doit pas entrer dans la galerie d'images"


@pytest.mark.asyncio
async def test_le_rattrapage_donne_une_vignette_aux_videos_existantes(mp4, tmp_path, conn):
    from api import repo
    from api.services import backfill_media as bm
    (tmp_path / "01OLDVID.mp4").write_bytes(mp4)
    await conn.execute("INSERT INTO billet(id,created_at,updated_at,body,slug,status,style) VALUES('b1','2026-10-11T00:00:00Z','2026-10-11T00:00:00Z','x','b1','published','default')")
    await repo.add_media(conn, "b1", filename="01OLDVID.mp4", thumb="", mime="video/mp4", width=0, height=0, alt="", now="2026-10-11T00:00:00Z", ulid="01OLDVID")
    await conn.commit()
    r = await bm.rattraper_posters(conn, directory=tmp_path)
    assert r == {"vues": 1, "faites": 1}
    async with conn.execute("SELECT thumb FROM media WHERE id='01OLDVID'") as cur:
        assert (await cur.fetchone())["thumb"] == "01OLDVID_t.jpg"
    assert (await bm.rattraper_posters(conn, directory=tmp_path)) == {"vues": 0, "faites": 0}      # idempotent
