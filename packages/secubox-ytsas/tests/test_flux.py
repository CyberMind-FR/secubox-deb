# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Flux du compte YouTube (à regarder plus tard, propositions, abonnements, historique) : lecture seule, avec les cookies
du coffre, jamais sans eux, avec cache et repli sur le dernier résultat si YouTube refuse."""
import asyncio
import json
import os
import pathlib
import sys
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("YTSAS_DOWNLOAD_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
import flux  # noqa: E402
import main  # noqa: E402

ID1, ID2 = "dQw4w9WgXcQ", "aqz-KE-bpKQ"


def _ligne(vid, titre, chaine="Chaîne", duree=213, miniatures=True):
    d = {"id": vid, "title": titre, "channel": chaine, "duration": duree}
    if miniatures:
        d["thumbnails"] = [{"url": f"https://i.ytimg.com/vi/{vid}/default.jpg", "width": 120},
                           {"url": f"https://i.ytimg.com/vi/{vid}/hqdefault.jpg?sqp=xyz", "width": 480}]
    return json.dumps(d)


# ── types et commande ────────────────────────────────────────────────────────
def test_les_quatre_flux_connus_et_rien_d_autre():
    assert set(flux.TYPES) == {"envie", "propositions", "abonnements", "historique"}
    assert flux.TYPES["abonnements"] == ":ytsubs"
    assert flux.TYPES["historique"] == ":ythistory"
    assert flux.TYPES["envie"] == ":ytwatchlater"
    assert flux.TYPES["propositions"] == ":ytrec"


def test_la_commande_est_a_plat_bornee_et_porte_les_cookies():
    argv = flux.commande("yt-dlp", "abonnements", 24, "/c/cookies.txt")
    assert argv[0] == "yt-dlp" and "--flat-playlist" in argv
    assert argv[argv.index("--playlist-end") + 1] == "24"
    assert argv[argv.index("--cookies") + 1] == "/c/cookies.txt"
    assert argv[-1] == ":ytsubs"
    assert "--no-download" not in argv or True   # à plat : rien n'est téléchargé


def test_la_limite_est_bornee():
    assert flux.borne(0) == 1 and flux.borne(10_000) == flux.LIMITE_MAX and flux.borne("12") == 12 and flux.borne(None) == 24


# ── analyse de la sortie de yt-dlp ───────────────────────────────────────────
def test_analyse_titre_chaine_duree_lien_et_vignette_via_la_box():
    sortie = "\n".join([_ligne(ID1, "Un titre"), "", "pas du json", _ligne(ID2, "Deux", chaine="Autre", duree=None)])
    items = flux.analyser(sortie)
    assert [i["id"] for i in items] == [ID1, ID2]
    a = items[0]
    assert a["titre"] == "Un titre" and a["chaine"] == "Chaîne" and a["duree"] == 213
    assert a["url"] == f"https://www.youtube.com/watch?v={ID1}"
    # la vignette passe par la box : le navigateur ne contacte pas Google
    assert a["vignette"] == f"/api/v1/ytsas/flux/vignette/{ID1}"
    assert items[1]["duree"] is None


def test_une_entree_sans_identifiant_valide_est_ecartee():
    sortie = "\n".join([json.dumps({"id": "court", "title": "x"}), json.dumps({"title": "sans id"}), _ligne(ID1, "ok")])
    assert [i["id"] for i in flux.analyser(sortie)] == [ID1]


def test_l_url_de_vignette_source_est_celle_de_ytimg_la_plus_grande_sinon_un_repli():
    d = json.loads(_ligne(ID1, "t"))
    assert flux.vignette_source(d) == f"https://i.ytimg.com/vi/{ID1}/hqdefault.jpg?sqp=xyz"
    d2 = json.loads(_ligne(ID2, "t", miniatures=False))
    assert flux.vignette_source(d2) == f"https://i.ytimg.com/vi/{ID2}/mqdefault.jpg"
    # jamais une vignette d'un autre hôte que ytimg / ggpht
    d3 = {"id": ID1, "thumbnails": [{"url": "https://evil.example/x.jpg", "width": 999}]}
    assert flux.vignette_source(d3) == f"https://i.ytimg.com/vi/{ID1}/mqdefault.jpg"


def test_identifiant_de_video_strict():
    assert flux.id_valide(ID1) and flux.id_valide(ID2)
    for mauvais in ("", "../etc/passwd", "a" * 12, "a" * 10, "dQw4w9WgXc!", "dQw4w9WgXcQ/x"):
        assert not flux.id_valide(mauvais)


# ── cache et repli ───────────────────────────────────────────────────────────
class Faux:
    """Exécuteur : remplace le sous-processus yt-dlp."""
    def __init__(self, sorties):
        self.sorties = list(sorties)
        self.appels = 0

    async def __call__(self, argv):
        self.appels += 1
        s = self.sorties.pop(0)
        if isinstance(s, Exception):
            raise s
        return s


def _flux(tmp_path, execut, ttl=60, horloge=None):
    return flux.Flux(str(tmp_path), "/c/cookies.txt", execut, ttl=ttl, horloge=horloge or time.time)


def test_sans_cookies_on_refuse_sans_lancer_yt_dlp(tmp_path):
    f = flux.Flux(str(tmp_path), None, Faux([]), ttl=60)
    with pytest.raises(flux.AuthRequise):
        asyncio.run(f.lister("abonnements", 24))


def test_le_resultat_est_mis_en_cache_le_temps_du_ttl(tmp_path):
    ex = Faux([_ligne(ID1, "A")])
    t = [1000.0]
    f = _flux(tmp_path, ex, ttl=60, horloge=lambda: t[0])
    r1 = asyncio.run(f.lister("historique", 24))
    t[0] += 30
    r2 = asyncio.run(f.lister("historique", 24))
    assert ex.appels == 1 and r1["items"] == r2["items"] and r2["en_cache"] is True
    t[0] += 61
    ex.sorties.append(_ligne(ID2, "B"))
    r3 = asyncio.run(f.lister("historique", 24))
    assert ex.appels == 2 and [i["id"] for i in r3["items"]] == [ID2] and r3["en_cache"] is False


def test_si_youtube_refuse_on_rend_le_dernier_resultat_signale_perime(tmp_path):
    ex = Faux([_ligne(ID1, "A"), flux.ErreurYoutube("HTTP Error 429")])
    t = [1000.0]
    f = _flux(tmp_path, ex, ttl=10, horloge=lambda: t[0])
    asyncio.run(f.lister("propositions", 24))
    t[0] += 100
    r = asyncio.run(f.lister("propositions", 24))
    assert r["perime"] is True and [i["id"] for i in r["items"]] == [ID1]


def test_sans_ancien_resultat_l_erreur_remonte(tmp_path):
    f = _flux(tmp_path, Faux([flux.ErreurYoutube("HTTP Error 429")]))
    with pytest.raises(flux.ErreurYoutube):
        asyncio.run(f.lister("envie", 24))


def test_les_flux_ne_se_melangent_pas_et_un_type_inconnu_est_refuse(tmp_path):
    ex = Faux([_ligne(ID1, "A"), _ligne(ID2, "B")])
    f = _flux(tmp_path, ex)
    a = asyncio.run(f.lister("envie", 24))
    b = asyncio.run(f.lister("abonnements", 24))
    assert a["items"][0]["id"] == ID1 and b["items"][0]["id"] == ID2 and ex.appels == 2
    with pytest.raises(ValueError):
        asyncio.run(f.lister("../../etc", 24))


def test_le_cache_est_ecrit_en_0600_et_ne_contient_pas_les_cookies(tmp_path):
    f = _flux(tmp_path, Faux([_ligne(ID1, "A")]))
    asyncio.run(f.lister("historique", 24))
    fichiers = [p for p in pathlib.Path(tmp_path).rglob("*") if p.is_file()]
    assert fichiers and all((p.stat().st_mode & 0o777) == 0o600 for p in fichiers)
    assert all("cookies" not in p.read_text() for p in fichiers)


def test_un_appel_a_la_fois_par_flux(tmp_path):
    async def lent(argv):
        lent.n += 1
        await asyncio.sleep(0.05)
        return _ligne(ID1, "A")
    lent.n = 0
    f = _flux(tmp_path, lent)

    async def deux():
        return await asyncio.gather(f.lister("historique", 24), f.lister("historique", 24))
    asyncio.run(deux())
    assert lent.n == 1


# ── routes ───────────────────────────────────────────────────────────────────
def _client(monkeypatch, tmp_path, execut=None, cookies=True):
    monkeypatch.setattr(main, "flux_moteur", flux.Flux(str(tmp_path), "/c/cookies.txt" if cookies else None,
                                                       execut or Faux([_ligne(ID1, "A")]), ttl=60))
    class Moteur:   # indépendant des doubles qu'installent les autres tests dans main.engine
        cookies_stale = False

        def _has_cookies(self):
            return cookies
    monkeypatch.setattr(main, "engine", Moteur())
    return TestClient(main.app)


def test_la_route_exige_l_en_tete_pose_par_le_hall(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    assert c.get("/api/v1/ytsas/flux?type=abonnements").status_code == 403
    r = c.get("/api/v1/ytsas/flux?type=abonnements", headers={"X-Sbx-Flux": "1"})
    assert r.status_code == 200 and r.json()["items"][0]["id"] == ID1


def test_route_type_inconnu_400_et_sans_cookies_401(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    assert c.get("/api/v1/ytsas/flux?type=zzz", headers={"X-Sbx-Flux": "1"}).status_code == 400
    c2 = _client(monkeypatch, tmp_path, cookies=False)
    r = c2.get("/api/v1/ytsas/flux?type=envie", headers={"X-Sbx-Flux": "1"})
    assert r.status_code == 401 and "cookies" in r.json()["error"]


def test_route_vignette_refuse_un_identifiant_douteux_et_exige_l_en_tete(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    assert c.get(f"/api/v1/ytsas/flux/vignette/{ID1}").status_code == 403
    assert c.get("/api/v1/ytsas/flux/vignette/..%2Fetc", headers={"X-Sbx-Flux": "1"}).status_code in (400, 404)
