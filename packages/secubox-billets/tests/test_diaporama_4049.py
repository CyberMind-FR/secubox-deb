# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#4049 — diaporama des médias d'un billet : PDF rendu en pages côté serveur, cache, bornes, garde de visibilité, gabarits."""
import asyncio
import io
import shutil

import httpx
import pytest
import pytest_asyncio
from PIL import Image

from api import repo
from api.main import create_app
from api.models import BilletIn
from api.services import pdfpages

NOW = "2026-11-28T10:00:00Z"
avec_pdftoppm = pytest.mark.skipif(shutil.which("pdftoppm") is None, reason="pdftoppm absent")


def _pdf(n: int) -> bytes:
    pages = [Image.new("RGB", (200, 280), (40 + 5 * i, 90, 160)) for i in range(n)]
    buf = io.BytesIO()
    pages[0].save(buf, format="PDF", save_all=True, append_images=pages[1:])
    return buf.getvalue()


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), (200, 90, 20)).save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture
def dossiers(tmp_path, monkeypatch):
    m, p = tmp_path / "media", tmp_path / "pdfpages"
    m.mkdir()
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(m))
    monkeypatch.setenv("BILLETS_PDFPAGES_DIR", str(p))
    return m, p


@pytest_asyncio.fixture
async def client(conn, dossiers):
    app = create_app(conn)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _billet(conn, dossiers, *, publie=True, pdf=None, image=False):
    bid = await repo.create_billet(conn, BilletIn(body="# RAPPORT D ANALYSES CROISEES\n\ncorps", publish=publie), now=NOW)
    mids = []
    if image:
        mid = "01IMAGE0000000000000000000"
        (dossiers[0] / f"{mid}.png").write_bytes(_png())
        (dossiers[0] / f"{mid}_t.png").write_bytes(_png())
        await repo.add_media(conn, bid, filename=f"{mid}.png", thumb=f"{mid}_t.png", mime="image/png",
                             width=32, height=24, alt="", now=NOW, ulid=mid)
        mids.append(mid)
    if pdf is not None:
        mid = "01PDF00000000000000000000" + str(len(mids))
        (dossiers[0] / f"{mid}.pdf").write_bytes(pdf)
        await repo.add_media(conn, bid, filename=f"{mid}.pdf", thumb="", mime="application/pdf",
                             width=0, height=0, alt="", now=NOW, ulid=mid)
        mids.append(mid)
    row = await repo.get_by_id(conn, bid)
    return row, mids


async def _attendre_rendu():
    for _ in range(200):
        if not pdfpages._taches:
            return
        await asyncio.sleep(0.05)


# ── service ──────────────────────────────────────────────────────────────────

@avec_pdftoppm
def test_rendu_pdf_donne_n_pages_en_cache(tmp_path):
    src = tmp_path / "d.pdf"
    src.write_bytes(_pdf(3))
    assert pdfpages.rendre("01DOCUMENT00000000000000", src, racine=tmp_path / "c") == 3
    assert pdfpages.pages("01DOCUMENT00000000000000", racine=tmp_path / "c") == 3
    f = pdfpages.page("01DOCUMENT00000000000000", 2, racine=tmp_path / "c")
    assert f is not None and f.read_bytes()[:3] == b"\xff\xd8\xff"
    assert pdfpages.page("01DOCUMENT00000000000000", 4, racine=tmp_path / "c") is None


@avec_pdftoppm
def test_borne_de_pages(tmp_path, monkeypatch):
    monkeypatch.setattr(pdfpages, "MAX_PAGES", 2)
    src = tmp_path / "d.pdf"
    src.write_bytes(_pdf(5))
    assert pdfpages.rendre("01BORNE000000000000000000", src, racine=tmp_path / "c") == 2
    assert pdfpages.pages("01BORNE000000000000000000", racine=tmp_path / "c") == 2


def test_pdf_invalide_marque_echec_sans_lever(tmp_path):
    src = tmp_path / "d.pdf"
    src.write_bytes(b"%PDF-1.7\nn'importe quoi")
    assert pdfpages.rendre("01INVALIDE0000000000000000", src, racine=tmp_path / "c") == 0
    assert pdfpages.echoue("01INVALIDE0000000000000000", racine=tmp_path / "c")
    # pas de nouvel essai : le marqueur suffit
    assert pdfpages.rendre("01INVALIDE0000000000000000", src, racine=tmp_path / "c") == 0


def test_identifiant_hostile_refuse(tmp_path):
    assert pdfpages.rendre("../../etc", tmp_path / "x.pdf", racine=tmp_path) == 0
    assert pdfpages.page("../x", 1, racine=tmp_path) is None


# ── routes et gabarits ───────────────────────────────────────────────────────

@avec_pdftoppm
async def test_fil_et_vue_montrent_le_diaporama_des_pages(client, conn, dossiers):
    row, (mid,) = await _billet(conn, dossiers, pdf=_pdf(2))
    r = await client.get("/")                       # 1er affichage : diapositive document + rendu planifié
    assert r.status_code == 200
    assert "data-diapo" in r.text and "dz-doc" in r.text
    await _attendre_rendu()
    assert pdfpages.pages(mid) == 2
    r = await client.get("/")
    assert f"/b/{row['slug']}/diapo/{mid}/1" in r.text and f"/b/{row['slug']}/diapo/{mid}/2" in r.text
    assert "data-multi" in r.text and 'data-dz-i="1"' in r.text
    r = await client.get(f"/b/{row['slug']}")
    assert r.status_code == 200 and f"/diapo/{mid}/2" in r.text and "ouvrir le PDF" in r.text
    r = await client.get(f"/b/{row['slug']}/diapo/{mid}/1")
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"


async def test_carte_jamais_vide_si_media(client, conn, dossiers):
    await _billet(conn, dossiers, image=True)
    r = await client.get("/")
    assert "data-diapo" in r.text and "/media/01IMAGE0000000000000000000.png" in r.text
    assert 'class="poster ph"' not in r.text


async def test_sans_media_repli_inchange(client, conn, dossiers):
    await _billet(conn, dossiers)
    r = await client.get("/")
    assert "data-diapo" not in r.text and "✎" in r.text


async def test_pdf_invalide_repli_sans_erreur(client, conn, dossiers):
    row, (mid,) = await _billet(conn, dossiers, pdf=b"%PDF-1.4\ncasse")
    r = await client.get("/")
    assert r.status_code == 200
    await _attendre_rendu()
    r = await client.get("/")
    assert r.status_code == 200 and "dz-doc" in r.text
    assert (await client.get(f"/b/{row['slug']}")).status_code == 200
    assert (await client.get(f"/b/{row['slug']}/diapo/{mid}/1")).status_code == 404


@avec_pdftoppm
async def test_garde_de_visibilite_des_diapositives(client, conn, dossiers):
    brouillon, (mid_b,) = await _billet(conn, dossiers, publie=False, pdf=_pdf(1))
    pdfpages.rendre(mid_b, dossiers[0] / f"{mid_b}.pdf")
    assert pdfpages.pages(mid_b) == 1
    assert (await client.get(f"/b/{brouillon['slug']}/diapo/{mid_b}/1")).status_code == 404   # brouillon
    publie, _ = await _billet(conn, dossiers, image=True)
    # le média d'un AUTRE billet (brouillon) ne sort pas par le slug d'un billet publié
    assert (await client.get(f"/b/{publie['slug']}/diapo/{mid_b}/1")).status_code == 404
    # une image n'est pas un PDF
    assert (await client.get(f"/b/{publie['slug']}/diapo/01IMAGE0000000000000000000/1")).status_code == 404
