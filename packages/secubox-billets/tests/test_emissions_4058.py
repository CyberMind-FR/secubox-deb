# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#4058 — atelier des émissions côté billets : garde d'espace, rétention des MP4, compte d'auteur `emissions`."""
import os
import stat
import time

import httpx
import pytest
import pytest_asyncio

from api import manage, repo
from api.main import create_app
from api.routes import admin as admin_routes
from api.services import media
from api.services import security as sec

NOW = "2026-11-28T10:00:00Z"
MP3 = b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 40


@pytest.fixture
def dossier(tmp_path, monkeypatch):
    m = tmp_path / "media"
    m.mkdir()
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(m))
    monkeypatch.setenv("BILLETS_PDFPAGES_DIR", str(tmp_path / "pdfpages"))
    return m


# ── garde d'espace ───────────────────────────────────────────────────────
def test_espace_suffisant_lit_le_volume(dossier, monkeypatch):
    class U:
        free = 600 * 1024**2
    monkeypatch.setattr(media.shutil, "disk_usage", lambda p: U)
    assert media.espace_suffisant(10 * 1024**2) is True
    assert media.espace_suffisant(200 * 1024**2) is False           # 200 Mio + marge 512 Mio > 600 Mio
    assert media.espace_suffisant(200 * 1024**2, marge=0) is True


@pytest_asyncio.fixture
async def auteur_connecte(conn, tmp_path, dossier, monkeypatch):
    """Session d'administration simulée : la connexion réelle est indisponible dans ce banc (cf. test_chronologie_4058)."""
    await repo.create_author(conn, "gk", sec.hash_password("correct horse battery staple"), now=NOW,
                             author_id="01AUTHOR0000000000000000AA")
    auteur = await repo.get_author_by_id(conn, "01AUTHOR0000000000000000AA")

    async def _auteur(request):
        return auteur
    monkeypatch.setattr(admin_routes, "_current_author", _auteur)
    monkeypatch.setattr(admin_routes.sec, "csrf_ok", lambda a, b: True)
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    app.state.clock = lambda: NOW
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://billets.test",
                                 follow_redirects=False) as c:
        yield c


async def test_garde_espace_refuse(auteur_connecte, conn, dossier, monkeypatch):
    monkeypatch.setattr(media, "espace_suffisant", lambda octets, marge=512 * 1024**2: False)
    r = await auteur_connecte.post("/admin/billets", data={"body": "# EMISSION\n\ncorps", "csrf": "x"},
                                   files={"media_files": ("e.mp3", MP3, "audio/mpeg")})
    assert r.status_code == 507
    assert list(media.media_dir().iterdir()) == []
    assert await repo.list_all(conn) == []                         # rien écrit, pas même le billet


async def test_garde_espace_laisse_passer(auteur_connecte, conn, dossier, monkeypatch):
    monkeypatch.setattr(media, "espace_suffisant", lambda octets, marge=512 * 1024**2: True)
    r = await auteur_connecte.post("/admin/billets", data={"body": "# EMISSION\n\ncorps", "csrf": "x"},
                                   files={"media_files": ("e.mp3", MP3, "audio/mpeg")})
    assert r.status_code == 303
    assert [p.suffix for p in media.media_dir().iterdir()] == [".mp3"]


# ── rétention des MP4 ────────────────────────────────────────────────────
def _vieux(p, jours):
    t = time.time() - jours * 86400
    os.utime(p, (t, t))


def test_purge_mp4_garde_mp3(dossier):
    mp4 = dossier / "01OLDVIDEO.mp4"
    mp4.write_bytes(b"x")
    _vieux(mp4, 15)
    mp3 = dossier / "01OLDAUDIO.mp3"
    mp3.write_bytes(b"x")
    _vieux(mp3, 30)
    png = dossier / "01OLDIMAGE.png"
    png.write_bytes(b"x")
    _vieux(png, 30)
    recent = dossier / "01NEWVIDEO.mp4"
    recent.write_bytes(b"x")
    assert media.purger_mp4(14) == 1
    assert not mp4.exists() and mp3.exists() and png.exists() and recent.exists()


def test_purge_mp4_jours_invalides(dossier):
    with pytest.raises(ValueError):
        media.purger_mp4(0)


def test_retention_lue_du_toml(tmp_path, monkeypatch):
    f = tmp_path / "billets.toml"
    monkeypatch.setenv("BILLETS_TOML", str(f))
    assert media.retention_mp4_jours() == 14                     # fichier absent → défaut
    f.write_text("retention_mp4_jours = 3\n")
    assert media.retention_mp4_jours() == 3
    f.write_text("retention_mp4_jours = -1\n")
    assert media.retention_mp4_jours() == 14                     # valeur absurde → défaut


# ── compte d'auteur des émissions ────────────────────────────────────────
async def test_auteur_emissions_cree_et_jeton_0600(tmp_path, monkeypatch):
    jeton = tmp_path / "secrets" / "billets-emissions.jeton"
    jeton.parent.mkdir()
    base = tmp_path / "b.db"
    monkeypatch.setenv("BILLETS_DB", str(base))
    assert await manage._auteur_emissions(str(jeton)) == 0
    assert stat.S_IMODE(jeton.stat().st_mode) == 0o600
    j1 = jeton.read_text().strip()
    assert len(j1) >= 40
    # Rejouer : idempotent, le jeton n'est pas changé.
    assert await manage._auteur_emissions(str(jeton)) == 0
    assert jeton.read_text().strip() == j1
    from api import db
    c = await db.connect(str(base), now=NOW)
    try:
        assert (await repo.get_author_by_username(c, "emissions")) is not None
    finally:
        await c.close()


async def test_jeton_emissions_ouvre_l_api(conn, tmp_path, dossier, monkeypatch):
    jeton = tmp_path / "billets-emissions.jeton"
    jeton.write_text("j" * 48)
    jeton.chmod(0o600)
    monkeypatch.setenv("BILLETS_EMISSIONS_JETON", str(jeton))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "s" * 48)
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://billets.test") as c:
        r = await c.post("/admin/api/billets", json={"body": "# E\n\nx", "status": "draft"},
                         headers={"Authorization": "Bearer " + "j" * 48})
        assert r.status_code == 200, r.text
        bid = r.json()["id"]
        r = await c.post(f"/admin/api/billets/{bid}/media", files={"file": ("e.mp3", MP3, "audio/mpeg")},
                         headers={"Authorization": "Bearer " + "j" * 48})
        assert r.status_code == 200, r.text
        # Mauvais jeton : refusé.
        r = await c.post("/admin/api/billets", json={"body": "# E\n\nx"},
                         headers={"Authorization": "Bearer " + "k" * 48})
        assert r.status_code in (401, 403)


async def test_api_media_507(conn, tmp_path, dossier, monkeypatch):
    jeton = tmp_path / "billets-emissions.jeton"
    jeton.write_text("j" * 48)
    monkeypatch.setenv("BILLETS_EMISSIONS_JETON", str(jeton))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "s" * 48)
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    h = {"Authorization": "Bearer " + "j" * 48}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://billets.test") as c:
        bid = (await c.post("/admin/api/billets", json={"body": "# E\n\nx", "status": "draft"}, headers=h)).json()["id"]
        monkeypatch.setattr(media, "espace_suffisant", lambda octets, marge=512 * 1024**2: False)
        r = await c.post(f"/admin/api/billets/{bid}/media", files={"file": ("e.mp3", MP3, "audio/mpeg")}, headers=h)
        assert r.status_code == 507
        assert list(media.media_dir().iterdir()) == []
