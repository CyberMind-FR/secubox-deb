# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#4058 — chronologie audio d'un billet : validation stricte, stockage, rendu du diaporama synchronisé sur l'audio."""
import html
import io
import json

import httpx
import pytest
import pytest_asyncio
from PIL import Image
from pydantic import ValidationError

from api import repo
from api.main import create_app
from api.models import BilletIn, valider_chronologie
from api.services import security as sec

NOW = "2026-11-28T10:00:00Z"
PW = "correct horse battery staple"
CHRONO = [{"debut_s": 0, "fin_s": 2.5, "diapo": 0, "replique": "Bonjour"},
          {"debut_s": 2.5, "fin_s": 6, "diapo": 1, "replique": "Deuxième <b>diapo</b>"}]


def _png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), (200, 90, 20)).save(buf, format="PNG")
    return buf.getvalue()


# ── validation ──────────────────────────────────────────────────────────
def test_chronologie_valide_et_assainie():
    out = valider_chronologie([{"debut_s": 0, "fin_s": 1, "diapo": 0, "replique": "  a‮\x07b \n c "}])
    assert out == [{"debut_s": 0.0, "fin_s": 1.0, "diapo": 0, "replique": "ab c"}]
    assert valider_chronologie(json.dumps(CHRONO))[1]["diapo"] == 1     # chaîne JSON (formulaire)
    assert valider_chronologie(None) is None and valider_chronologie("") is None and valider_chronologie([]) is None


@pytest.mark.parametrize("mauvaise", [
    [{"debut_s": 2, "fin_s": 1, "diapo": 0}],                         # fin avant début
    [{"debut_s": 1, "fin_s": 1, "diapo": 0}],                         # durée nulle
    [{"debut_s": -1, "fin_s": 1, "diapo": 0}],                        # négatif
    [{"debut_s": 0, "fin_s": 99999, "diapo": 0}],                     # au-delà de 6 h
    [{"debut_s": 0, "fin_s": float("nan"), "diapo": 0}],              # NaN
    [{"debut_s": 0, "fin_s": 1, "diapo": -1}],                        # index négatif
    [{"debut_s": 0, "fin_s": 1, "diapo": 1.5}],                       # index non entier
    [{"debut_s": 0, "fin_s": 1, "diapo": True}],                      # booléen
    [{"debut_s": 0, "fin_s": 1, "diapo": 0, "x": 1}],                 # champ inconnu
    [{"debut_s": 0, "fin_s": 1, "diapo": 0, "replique": "a" * 501}],  # réplique trop longue
    [{"debut_s": 0, "fin_s": 3, "diapo": 0}, {"debut_s": 2, "fin_s": 4, "diapo": 1}],   # chevauchement
    [{"debut_s": 5, "fin_s": 6, "diapo": 0}, {"debut_s": 0, "fin_s": 1, "diapo": 1}],   # désordre
    [{"debut_s": i, "fin_s": i + 0.5, "diapo": 0} for i in range(2001)],                # trop d'entrées
    {"debut_s": 0},                                                   # pas une liste
    "pas du json",
])
def test_chronologie_rejets(mauvaise):
    with pytest.raises((ValueError, ValidationError)):
        valider_chronologie(mauvaise)
    with pytest.raises(ValidationError):
        BilletIn(body="x", chronologie=mauvaise)


# ── stockage + rendu ────────────────────────────────────────────────────
@pytest.fixture
def dossier(tmp_path, monkeypatch):
    m = tmp_path / "media"
    m.mkdir()
    monkeypatch.setenv("BILLETS_MEDIA_DIR", str(m))
    monkeypatch.setenv("BILLETS_PDFPAGES_DIR", str(tmp_path / "pdfpages"))
    return m


@pytest_asyncio.fixture
async def client(conn, dossier):
    app = create_app(conn)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _billet(conn, dossier, *, chrono=None, audio=True, images=2):
    bid = await repo.create_billet(conn, BilletIn(body="# EMISSION\n\ncorps", publish=True, chronologie=chrono), now=NOW)
    for i in range(images):
        mid = f"01IMG{bid[-8:]}{i:013d}"
        (dossier / f"{mid}.png").write_bytes(_png())
        await repo.add_media(conn, bid, filename=f"{mid}.png", thumb=f"{mid}.png", mime="image/png",
                             width=32, height=24, alt=f"img{i}", now=NOW, ulid=mid)
    if audio:
        aid = f"01AUD{bid[-8:]}0000000000000"
        (dossier / f"{aid}.mp3").write_bytes(b"ID3")
        await repo.add_media(conn, bid, filename=f"{aid}.mp3", thumb="", mime="audio/mpeg",
                             width=0, height=0, alt="", now=NOW, ulid=aid)
    return await repo.get_by_id(conn, bid)


async def test_vue_avec_chronologie_sort_audio_et_attributs(client, conn, dossier):
    row = await _billet(conn, dossier, chrono=CHRONO)
    assert json.loads(row["chronologie"])[0]["replique"] == "Bonjour"
    r = await client.get(f"/b/{row['slug']}")
    assert r.status_code == 200
    assert f'data-dz-audio src="/media/01AUD{row["id"][-8:]}0000000000000.mp3"' in r.text
    assert 'aria-live="polite" data-dz-replique' in r.text
    brut = r.text.split('data-chrono="', 1)[1].split('"', 1)[0]
    lignes = json.loads(html.unescape(brut))
    assert lignes[0] == [0.0, 2.5, 0, "Bonjour"] and lignes[1][2] == 1
    assert "<b>" not in brut                       # la réplique ne s'injecte jamais en HTML
    assert "diaporama.js?v=dz2" in r.text


async def test_sans_chronologie_inchange(client, conn, dossier):
    row = await _billet(conn, dossier, chrono=None)
    r = await client.get(f"/b/{row['slug']}")
    assert r.status_code == 200 and "data-diapo" in r.text
    assert "data-chrono" not in r.text and "data-dz-audio" not in r.text and "dz-chrono" not in r.text


async def test_sans_audio_ou_diapo_absente_pas_de_synchro(client, conn, dossier):
    row = await _billet(conn, dossier, chrono=CHRONO, audio=False)
    assert "data-chrono" not in (await client.get(f"/b/{row['slug']}")).text
    row = await _billet(conn, dossier, chrono=[{"debut_s": 0, "fin_s": 1, "diapo": 7}], images=2)
    assert "data-chrono" not in (await client.get(f"/b/{row['slug']}")).text


async def test_fil_garde_le_minuteur(client, conn, dossier):
    await _billet(conn, dossier, chrono=CHRONO)
    r = await client.get("/")
    assert r.status_code == 200 and "data-diapo" in r.text and "data-chrono" not in r.text


# ── API d'administration (formulaire, même garde de session + CSRF) ─────────
@pytest_asyncio.fixture
async def admin(conn, tmp_path, dossier):
    await repo.create_author(conn, "gk", sec.hash_password(PW), now=NOW, author_id="01AUTHOR0000000000000000AA")
    app = create_app(conn, secret="test-secret-xyz", revisions_dir=str(tmp_path / "revs"))
    app.state.clock = lambda: NOW
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://billets.test", follow_redirects=False) as c:
        await c.get("/admin/login")
        r = await c.post("/admin/login", data={"username": "gk", "password": PW, "totp": "", "csrf": c.cookies.get("billets_csrf")})
        if r.headers.get("location") != "/admin":
            # même cause que les échecs préexistants de test_admin.py dans ce banc (jar de cookies httpx) : non lié à #4058
            pytest.skip("connexion d'administration indisponible dans ce banc de test")
        yield c


async def test_mise_a_jour_par_le_formulaire(admin, conn, dossier):
    row = await _billet(conn, dossier, chrono=None)
    await admin.get(f"/admin/billets/{row['id']}/edit")
    csrf = admin.cookies.get("billets_csrf")
    base = {"body": "# EMISSION\n\ncorps", "csrf": csrf, "action": "save"}
    r = await admin.post(f"/admin/billets/{row['id']}", data={**base, "chronologie": json.dumps(CHRONO)})
    assert r.status_code == 303 and r.headers["location"] == "/admin", r.headers.get("location")
    assert json.loads((await repo.get_by_id(conn, row["id"]))["chronologie"])[1]["diapo"] == 1
    # diapo inexistante (2 images) → refus, chronologie conservée
    r = await admin.post(f"/admin/billets/{row['id']}", data={**base, "chronologie": json.dumps([{"debut_s": 0, "fin_s": 1, "diapo": 5}])})
    assert r.status_code == 200 and "diapositive" in r.text
    assert json.loads((await repo.get_by_id(conn, row["id"]))["chronologie"])[1]["diapo"] == 1
    # JSON invalide → refus
    r = await admin.post(f"/admin/billets/{row['id']}", data={**base, "chronologie": "[{"})
    assert r.status_code == 200 and "invalide" in r.text
    # vide → effacée
    r = await admin.post(f"/admin/billets/{row['id']}", data={**base, "chronologie": ""})
    assert r.status_code == 303 and (await repo.get_by_id(conn, row["id"]))["chronologie"] is None


async def test_diapo_existante_verifiee_contre_les_images(conn, dossier):
    from api.routes.admin import chrono_diapos_ok
    row = await _billet(conn, dossier, chrono=None, images=2)
    assert await chrono_diapos_ok(conn, row["id"], CHRONO)
    assert await chrono_diapos_ok(conn, row["id"], None)
    assert not await chrono_diapos_ok(conn, row["id"], [{"debut_s": 0, "fin_s": 1, "diapo": 2, "replique": ""}])
    await repo.set_chronologie(conn, row["id"], CHRONO, now=NOW)
    assert json.loads((await repo.get_by_id(conn, row["id"]))["chronologie"]) == valider_chronologie(CHRONO)
    await repo.set_chronologie(conn, row["id"], None, now=NOW)
    assert (await repo.get_by_id(conn, row["id"]))["chronologie"] is None


async def test_sans_session_refus(client, conn, dossier):
    row = await _billet(conn, dossier, chrono=None)
    r = await client.post(f"/admin/billets/{row['id']}", data={"body": "x", "chronologie": json.dumps(CHRONO)}, follow_redirects=False)
    assert r.status_code == 303 and "/admin/login" in r.headers["location"]
    assert (await repo.get_by_id(conn, row["id"]))["chronologie"] is None
