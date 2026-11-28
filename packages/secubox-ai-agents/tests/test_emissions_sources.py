# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 6 (#4058) : lecture SEULE des dossiers de gk2."""
import asyncio
import os

import httpx
import pytest

from emissions.sources import Sources, jeton_fichier


def _client(vues):
    def gerer(req: httpx.Request) -> httpx.Response:
        vues.append(req)
        if req.url.path.endswith("/rapports"):
            return httpx.Response(200, json={"disponible": True, "sujets": [{"genre": "campagne", "id": "c1"}]})
        return httpx.Response(200, json={"cle": "campagne/c1", "dossier": {"sujet": {"id": "c1"}}})
    return httpx.AsyncClient(transport=httpx.MockTransport(gerer))


def test_genre_inconnu_refuse():
    s = Sources("http://127.0.0.1:1", lambda: "j", client=_client([]))
    for genre, ident in (("ban", "x"), ("campagne", "../etc"), ("acteur", "a/b"), ("acteur", "")):
        with pytest.raises(ValueError):
            asyncio.run(s.dossier(genre, ident))


def test_get_seulement():
    vues = []
    s = Sources("http://127.0.0.1:9/api/v1/waf/", lambda: "jeton-lecture", client=_client(vues))

    async def tout():
        assert (await s.lister())[0]["id"] == "c1"
        assert (await s.dossier("campagne", "c1"))["cle"] == "campagne/c1"
        assert (await s.dossier("acteur", "ACT-12"))["cle"]
    asyncio.run(tout())
    assert vues and all(r.method == "GET" for r in vues)
    assert [r.url.path for r in vues] == ["/api/v1/waf/rapports", "/api/v1/waf/rapports/campagne/c1",
                                         "/api/v1/waf/rapports/acteur/ACT-12"]
    assert all(r.headers["authorization"] == "Bearer jeton-lecture" for r in vues)
    assert not [n for n in dir(Sources) if n.startswith(("rediger", "ecrire", "post", "put", "supprimer"))]


def test_erreur_http_remonte():
    s = Sources("http://127.0.0.1:9", lambda: "j",
                client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403))))
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(s.lister())


def test_lister_sujets_absents():
    s = Sources("http://127.0.0.1:9", lambda: "j",
                client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"disponible": False}))))
    assert asyncio.run(s.lister()) == []


def test_jeton_fichier_0600(tmp_path):
    f = tmp_path / "lecture-gk2"
    f.write_text("abc\n")
    f.chmod(0o644)
    with pytest.raises(PermissionError):
        jeton_fichier(f)()
    f.chmod(0o600)
    assert jeton_fichier(f)() == "abc"
    assert os.stat(f).st_mode & 0o777 == 0o600
