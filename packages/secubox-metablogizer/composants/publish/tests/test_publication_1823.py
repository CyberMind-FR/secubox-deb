# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: publish — une publication dit ce qui s'est VRAIMENT passé (#1823).

Vécu sur gk2 le 2026-10-01 : `guide-bipolarite` sur `bip.gk2.secubox.in`,
écran « Published Successfully! » et trois coches vertes — et rien de publié :
ni site, ni bloc nginx, ni route, ni certificat. Le domaine répondait 421.
"""

import asyncio
import io
import json
import tarfile
import time
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from starlette.datastructures import UploadFile

from api import main

RACINE = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def banc(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "BUNDLES_DIR", tmp_path / "bundles")
    (tmp_path / "bundles").mkdir()
    monkeypatch.setattr(main, "TRAVAUX_DIR", tmp_path / "travaux")
    monkeypatch.setattr(main, "HISTORY_FILE", tmp_path / "history.json")
    monkeypatch.setattr(main, "_notify_webhooks", _rien)
    monkeypatch.setattr(main, "domaine_box", lambda: "box.example")
    main._caller_token.set("jeton-du-banc")
    return tmp_path


async def _rien(*a, **k):
    return None


def _transport(monkeypatch, handler):
    """Toute requête du module part vers `handler` (au lieu du socket)."""
    monkeypatch.setattr(main.httpx, "AsyncHTTPTransport",
                        lambda **kw: httpx.MockTransport(handler))


def _zip(nom="guide-bipolarite/index.html", corps=b"<!doctype html><p>guide</p>"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(nom, corps)
    return UploadFile(file=io.BytesIO(buf.getvalue()), filename="guide.zip")


def _ndjson(*lignes):
    return httpx.Response(200, content="".join(json.dumps(l) + "\n" for l in lignes).encode(),
                          headers={"content-type": "application/x-ndjson"})


DEBUT = {"type": "debut", "domain": "bip.box.example",
         "etapes": [{"cle": c, "libelle": l} for c, l in
                    [("content", "Contenu"), ("vhost", "Service"), ("route", "Route"), ("cert", "Certificat")]]}


async def _publie(**kw):
    # Appel direct : les valeurs par défaut `Form(...)` ne sont pas résolues.
    kw.setdefault("domain", None)
    r = await main.isp_upload(file=kw.pop("file", None) or _zip(), **kw)
    await asyncio.gather(*list(main._TACHES))
    return r


# ── _call_module : un refus n'est pas un succès ───────────────────────────

@pytest.mark.parametrize("statut,corps", [
    (401, {"detail": "Session requise"}),
    (403, {"detail": "Capacité requise : metablog.publish"}),
    (404, {"detail": "Not Found"}),
    (422, {"detail": [{"msg": "field required"}]}),
])
def test_un_refus_porte_une_erreur(monkeypatch, statut, corps):
    _transport(monkeypatch, lambda req: httpx.Response(statut, json=corps))
    r = asyncio.run(main._call_module("metablogizer", "/site", "POST", {"name": "x"}))
    assert "error" in r, "un {detail} sans clé error passait pour une réussite"
    assert r["status"] == statut


def test_un_succes_rend_le_corps(monkeypatch):
    _transport(monkeypatch, lambda req: httpx.Response(200, json={"success": True}))
    assert asyncio.run(main._call_module("metablogizer", "/site", "POST", {})) == {"success": True}


# ── Le contenu statique passe par l'assistant de metablogizer ─────────────

def test_publication_reussie_suivie_jusqu_au_verdict(monkeypatch):
    vu = {}

    def assistant(req):
        vu["chemin"] = req.url.path
        vu["query"] = req.url.query
        vu["auth"] = req.headers.get("authorization")
        vu["type"] = req.headers.get("content-type", "")
        vu["corps"] = req.read()
        return _ndjson(DEBUT,
                       {"type": "etape", "cle": "content", "etat": "ok", "detail": ""},
                       {"type": "attente"},
                       {"type": "etape", "cle": "vhost", "etat": "ok", "detail": ""},
                       {"type": "etape", "cle": "route", "etat": "ok", "detail": ""},
                       {"type": "etape", "cle": "cert", "etat": "ok", "detail": ""},
                       {"type": "fin", "ok": True, "domain": "bip.box.example", "steps": {}})

    _transport(monkeypatch, assistant)
    r = asyncio.run(_publie(name="guide-bipolarite", domain="bip.box.example", auto_publish=True))

    # La réponse ne crie pas victoire : elle confie un travail.
    assert r.etat == "en_cours" and r.travail and r.success is False
    # Un seul appel, l'assistant, avec le FICHIER (multipart) et le jeton.
    assert vu["chemin"] == "/api/v1/metablogizer/publish/wizard"
    assert "flux=1" in str(vu["query"])
    assert vu["type"].startswith("multipart/form-data")
    assert vu["auth"] == "Bearer jeton-du-banc"
    assert b"bip.box.example" in vu["corps"] and b"guide-bipolarite/index.html" in vu["corps"]

    t = asyncio.run(main.isp_travail(r.travail))
    assert t["etat"] == "publie"
    assert t["url"] == "https://bip.box.example/"
    assert [e["etat"] for e in t["etapes"]] == ["ok", "ok", "ok", "ok"]


def test_une_etape_ratee_fait_un_echec_qui_la_nomme(monkeypatch):
    _transport(monkeypatch, lambda req: _ndjson(
        DEBUT,
        {"type": "etape", "cle": "content", "etat": "ok", "detail": ""},
        {"type": "etape", "cle": "vhost", "etat": "ok", "detail": ""},
        {"type": "etape", "cle": "route", "etat": "echec", "detail": "haproxyctl a refusé"},
        {"type": "etape", "cle": "cert", "etat": "ok", "detail": ""},
        {"type": "fin", "ok": False, "domain": "bip.box.example", "steps": {}}))
    r = asyncio.run(_publie(name="guide", domain="bip.box.example", auto_publish=True))
    t = asyncio.run(main.isp_travail(r.travail))
    assert t["etat"] == "echec" and t["url"] is None
    assert t["detail"] == "Route : haproxyctl a refusé"


def test_la_cause_decisive_est_nommee_d_abord(monkeypatch):
    """Vécu sur gk3 : « Version : no-git-repo » masquait le vrai blocage."""
    _transport(monkeypatch, lambda req: _ndjson(
        {**DEBUT, "etapes": DEBUT["etapes"] + [{"cle": "version", "libelle": "Version"}]},
        {"type": "etape", "cle": "content", "etat": "ok", "detail": ""},
        {"type": "etape", "cle": "version", "etat": "echec", "detail": "no-git-repo"},
        {"type": "etape", "cle": "vhost", "etat": "echec", "detail": "nginx refuse"},
        {"type": "fin", "ok": False}))
    r = asyncio.run(_publie(name="guide", auto_publish=True))
    t = asyncio.run(main.isp_travail(r.travail))
    assert t["detail"] == "Service : nginx refuse ; Version : no-git-repo"


def test_un_assistant_qui_refuse_est_un_echec(monkeypatch):
    _transport(monkeypatch, lambda req: httpx.Response(
        403, json={"detail": "Capacité requise : metablog.publish"}))
    r = asyncio.run(_publie(name="guide", auto_publish=True))
    t = asyncio.run(main.isp_travail(r.travail))
    assert t["etat"] == "echec"
    assert "403" in t["detail"] and "metablog.publish" in t["detail"]


def test_un_flux_coupe_sans_verdict_est_un_echec(monkeypatch):
    _transport(monkeypatch, lambda req: _ndjson(
        DEBUT, {"type": "etape", "cle": "content", "etat": "ok", "detail": ""}))
    r = asyncio.run(_publie(name="guide", auto_publish=True))
    t = asyncio.run(main.isp_travail(r.travail))
    assert t["etat"] == "echec" and "sans verdict" in t["detail"]


def test_le_domaine_par_defaut_est_celui_de_la_box(monkeypatch):
    vu = {}

    def assistant(req):
        vu["corps"] = req.read()
        return _ndjson({"type": "fin", "ok": True, "domain": "guide.box.example"})

    _transport(monkeypatch, assistant)
    r = asyncio.run(_publie(name="guide", auto_publish=True))
    assert r.domain == "guide.box.example"
    assert b"guide.box.example" in vu["corps"] and b"gk2" not in vu["corps"]


def test_sans_auto_publish_rien_n_est_lance(monkeypatch):
    _transport(monkeypatch, lambda req: pytest.fail("aucun appel attendu"))
    r = asyncio.run(_publie(name="guide", auto_publish=False))
    assert r.etat == "televerse" and r.travail is None
    assert (main.BUNDLES_DIR / "guide.zip").exists()


# ── Entrées refusées ──────────────────────────────────────────────────────

@pytest.mark.parametrize("nom", ["../etc/x", "a/b", "-x", "x" * 64])
def test_un_nom_qui_sortirait_du_repertoire_est_refuse(nom):
    with pytest.raises(HTTPException) as e:
        asyncio.run(main.isp_upload(file=_zip(), name=nom, domain=None, auto_publish=False))
    assert e.value.status_code == 400


@pytest.mark.parametrize("dom", ["bip", "bip..example", "bip.example/x", "http://bip.example"])
def test_un_domaine_invalide_est_refuse(dom):
    with pytest.raises(HTTPException) as e:
        asyncio.run(main.isp_upload(file=_zip(), name="guide", domain=dom, auto_publish=False))
    assert e.value.status_code == 400


def test_une_archive_tar_qui_sort_de_son_repertoire_est_refusee(tmp_path):
    arc = tmp_path / "x.tar.gz"
    with tarfile.open(arc, "w:gz") as tf:
        info = tarfile.TarInfo("../../evade.html")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
    dest = tmp_path / "dest"
    dest.mkdir()
    with pytest.raises(ValueError):
        main._extract_archive(arc, dest)
    assert not (tmp_path / "evade.html").exists()


# ── Le suivi ──────────────────────────────────────────────────────────────

def test_un_travail_inconnu_ou_mal_forme_est_404():
    for tid in ("0123456789abcdef", "../../etc/passwd"):
        with pytest.raises(HTTPException) as e:
            asyncio.run(main.isp_travail(tid))
        assert e.value.status_code == 404


def test_un_travail_muet_trop_longtemps_est_declare_mort():
    t = {"id": "00000000000000aa", "name": "g", "etat": "en_cours", "etapes": [],
         "battement": time.time() - main.TRAVAIL_SILENCE_MAX_S - 5}
    main._travail_ecrit(t)
    r = asyncio.run(main.isp_travail(t["id"]))
    assert r["etat"] == "echec" and "interrompu" in r["detail"]


# ── La page ───────────────────────────────────────────────────────────────

def test_la_page_ne_peint_plus_de_coche_sans_lire_la_reponse():
    page = (RACINE / "www" / "publish" / "index.html").read_text()
    for faux in ("Status').textContent = '✅';\n                document.getElementById('create",):
        assert faux not in page
    assert "'.gk2.secubox.in'" not in page, "domaine de gk2 en dur"
    assert "/isp/travail/" in page and "/chaine" in page
    # L'écran de succès n'est atteint qu'après lecture du verdict.
    assert "if (!result.success)" in page and "t.etat === 'publie'" in page
