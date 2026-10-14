# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2708 — chaînes suivies, playlists, dernières vidéos d'une chaîne, contenu d'une playlist : lecture seule, identifiants
à motif strict, adresse construite côté serveur, même cache / repli périmé / erreurs que les autres flux.
Exécuteur factice : AUCUN appel réel à YouTube (les cookies de la box sont périmés au moment de l'écriture)."""
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

UC1 = "UC" + "a" * 22
UC2 = "UC" + "B1_-" * 5 + "xy"
PL1 = "PL" + "x" * 16
VID1, VID2 = "dQw4w9WgXcQ", "aqz-KE-bpKQ"
H = {"X-Sbx-Flux": "1"}


def _chaine(ident=UC1, nom="Atelier Réseau", abonnes=12300, videos=240, handle="@atelier-reseau", avatar=True):
    d = {"_type": "url", "id": ident, "channel_id": ident, "channel": nom, "title": nom, "uploader_id": handle}
    if abonnes is not None:
        d["channel_follower_count"] = abonnes
    if videos is not None:
        d["playlist_count"] = videos
    if avatar:
        d["thumbnails"] = [{"url": "//yt3.ggpht.com/a/petit=s88", "width": 88}, {"url": "https://yt3.ggpht.com/a/grand=s176", "width": 176}]
    return json.dumps(d)


def _playlist(ident=PL1, titre="Réseaux", chaine="Cours Libres"):
    return json.dumps({"_type": "url", "id": ident, "title": titre, "channel": chaine,
                       "thumbnails": [{"url": f"https://i.ytimg.com/vi/{VID1}/hqdefault.jpg", "width": 480}]})


def _video(vid, titre="V", chaine="C", **plus):
    return json.dumps({"id": vid, "title": titre, "channel": chaine, "duration": 60, **plus})


class Faux:
    def __init__(self, sorties):
        self.sorties, self.argvs = list(sorties), []

    async def __call__(self, argv):
        self.argvs.append(argv)
        s = self.sorties.pop(0)
        if isinstance(s, Exception):
            raise s
        return s


def _f(tmp_path, ex, ttl=60, horloge=None, cookies="/c/cookies.txt"):
    return flux.Flux(str(tmp_path), cookies, ex, ttl=ttl, horloge=horloge or time.time)


# ── types et adresses fixes ──────────────────────────────────────────────────
def test_les_listes_de_chaines_et_playlists_sont_des_adresses_fixes():
    assert flux.TYPES["chaines"] == "https://www.youtube.com/feed/channels"
    assert flux.TYPES["playlists"] == "https://www.youtube.com/feed/playlists"
    argv = flux.commande("yt-dlp", "chaines", 24, "/c/cookies.txt")
    assert argv[-1] == flux.TYPES["chaines"] and "--flat-playlist" in argv and argv[argv.index("--cookies") + 1] == "/c/cookies.txt"


# ── motifs stricts ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("ok", [UC1, UC2, "@atelier", "@a.b_c-d", "@" + "a" * 64])
def test_chaines_valides(ok):
    assert flux.chaine_valide(ok)


@pytest.mark.parametrize("mauvais", [
    "", None, 12, "UC" + "a" * 21, "UC" + "a" * 23, "uc" + "a" * 22, "UC" + "a" * 21 + "!", UC1 + "\n", UC1 + "/videos",
    "@", "@" + "a" * 65, "@a b", "@a/b", "@a;rm", "@a\n", "@é", "atelier", "https://www.youtube.com/channel/" + UC1,
    "http://evil.example/" + UC1, "../" + UC1, "--exec", "-" + UC1, UC1 + "?x=1", "@a?list=PL" + "x" * 16,
])
def test_chaines_invalides(mauvais):
    assert not flux.chaine_valide(mauvais)


@pytest.mark.parametrize("ok", [PL1, "UU" + "z" * 22, "LL" + "q" * 10, "FL" + "q" * 40, "OLAK5uy_" + "k" * 10])
def test_playlists_valides(ok):
    assert flux.playlist_valide(ok)


@pytest.mark.parametrize("mauvais", [
    "", None, "WL", "PL", "PL" + "x" * 9, "PL" + "x" * 41, "XX" + "x" * 16, "pl" + "x" * 16, PL1 + "\n", PL1 + "&list=x",
    "https://www.youtube.com/playlist?list=" + PL1, "PL" + "x" * 15 + "/", "PL" + "x" * 15 + " ", "PL;" + "x" * 15, "-" + PL1,
])
def test_playlists_invalides(mauvais):
    assert not flux.playlist_valide(mauvais)


def test_l_adresse_pour_yt_dlp_est_construite_jamais_fournie():
    assert flux.url_detail("chaine", UC1) == f"https://www.youtube.com/channel/{UC1}/videos"
    assert flux.url_detail("chaine", "@atelier") == "https://www.youtube.com/@atelier/videos"
    assert flux.url_detail("playlist", PL1) == f"https://www.youtube.com/playlist?list={PL1}"
    for genre, ident in (("chaine", "https://evil.example/"), ("playlist", "https://evil.example/"), ("chaine", PL1),
                         ("playlist", UC1), ("video", VID1), ("chaine", "--exec=x")):
        with pytest.raises(ValueError):
            flux.url_detail(genre, ident)


def test_la_commande_de_detail_ferme_les_options_avant_l_adresse():
    argv = flux.commande_detail("yt-dlp", "chaine", UC1, 24, "/c/cookies.txt")
    assert argv[-2:] == ["--", f"https://www.youtube.com/channel/{UC1}/videos"]
    assert argv[argv.index("--playlist-end") + 1] == "24" and "--flat-playlist" in argv
    assert flux.commande_detail("yt-dlp", "playlist", PL1, 10_000, "/c")[flux.commande_detail("yt-dlp", "playlist", PL1, 10_000, "/c").index("--playlist-end") + 1] == str(flux.LIMITE_MAX)


def test_cle_de_vignette_opaque_et_valide_comme_un_identifiant_de_video():
    k = flux.cle_vignette(UC1)
    assert flux.id_valide(k) and k == flux.cle_vignette(UC1) and k != flux.cle_vignette(UC2)


# ── format des chaînes ───────────────────────────────────────────────────────
def test_chaines_nom_abonnes_videos_avatar_fournis():
    items = flux.analyser_chaines("\n".join([_chaine(), "pas du json", ""]))
    c = items[0]
    assert c["id"] == UC1 and c["nom"] == "Atelier Réseau" and c["handle"] == "@atelier-reseau"
    assert c["abonnes"] == 12300 and c["videos"] == 240
    assert c["url"] == f"https://www.youtube.com/channel/{UC1}"
    assert c["vignette"] == "/api/v1/ytsas/flux/vignette/" + flux.cle_vignette(UC1)
    assert c["_source"] == "https://yt3.ggpht.com/a/grand=s176"


def test_chaines_rien_n_est_invente_quand_yt_dlp_ne_dit_pas():
    c = flux.analyser_chaines(_chaine(abonnes=None, videos=None, avatar=False, handle="pas un handle"))[0]
    assert c["abonnes"] is None and c["videos"] is None and c["vignette"] is None and c["handle"] is None
    # un nombre négatif, un booléen ou un texte ne sont pas des nombres
    d = json.loads(_chaine())
    d.update(channel_follower_count=True, playlist_count="12")
    c = flux.analyser_chaines(json.dumps(d))[0]
    assert c["abonnes"] is None and c["videos"] is None


def test_chaines_identifiant_invalide_ecarte_et_avatar_hors_google_refuse():
    d = json.loads(_chaine())
    d["thumbnails"] = [{"url": "https://evil.example/x.jpg", "width": 999}]
    assert flux.analyser_chaines(json.dumps(d))[0]["vignette"] is None
    assert flux.analyser_chaines(_chaine(ident="UCcourt")) == []
    assert flux.analyser_chaines(_chaine(ident="../etc")) == []


# ── format des playlists ─────────────────────────────────────────────────────
def test_playlists_titre_chaine_miniature_et_pas_de_compte_invente():
    p = flux.analyser_playlists("\n".join([_playlist(), _playlist(ident="WL", titre="Plus tard"), _playlist(ident="PL;rm -rf /")]))
    assert len(p) == 1
    assert p[0]["id"] == PL1 and p[0]["titre"] == "Réseaux" and p[0]["chaine"] == "Cours Libres"
    assert p[0]["videos"] is None
    assert p[0]["url"] == f"https://www.youtube.com/playlist?list={PL1}"
    assert p[0]["vignette"] == "/api/v1/ytsas/flux/vignette/" + flux.cle_vignette(PL1)
    assert p[0]["_source"] == f"https://i.ytimg.com/vi/{VID1}/hqdefault.jpg"


def test_titre_du_detail():
    assert flux.titre_detail("playlist", _video(VID1, playlist_title="Ma liste")) == "Ma liste"
    assert flux.titre_detail("chaine", _video(VID1, chaine="La Chaîne")) == "La Chaîne"
    assert flux.titre_detail("chaine", json.dumps({"id": VID1})) == ""


# ── moteur : listes ──────────────────────────────────────────────────────────
def test_lister_chaines_cache_perime_et_cause(tmp_path):
    ex = Faux([_chaine(), flux.CookiesRefuses("Login details are needed")])
    t = [1000.0]
    f = _f(tmp_path, ex, ttl=10, horloge=lambda: t[0])
    r1 = asyncio.run(f.lister("chaines", 24))
    assert r1["type"] == "chaines" and r1["items"][0]["id"] == UC1 and r1["en_cache"] is False and r1["perime"] is False
    assert all(not k.startswith("_") for k in r1["items"][0])         # jamais d'adresse source dans la réponse
    t[0] += 5
    assert asyncio.run(f.lister("chaines", 24))["en_cache"] is True and len(ex.argvs) == 1
    t[0] += 100
    r3 = asyncio.run(f.lister("chaines", 24))
    assert r3["perime"] is True and r3["cause"] == "cookies" and r3["items"][0]["id"] == UC1
    assert "Login details" not in json.dumps(r3)


def test_lister_playlists_et_erreur_sans_ancien_resultat(tmp_path):
    f = _f(tmp_path, Faux([_playlist()]))
    assert asyncio.run(f.lister("playlists", 24))["items"][0]["id"] == PL1
    g = _f(tmp_path / "autre", Faux([flux.ErreurYoutube("HTTP Error 429")]))
    with pytest.raises(flux.ErreurYoutube):
        asyncio.run(g.lister("playlists", 24))
    h = _f(tmp_path / "vide", Faux(["rien d'exploitable\n"]))
    with pytest.raises(flux.ErreurYoutube):
        asyncio.run(h.lister("chaines", 24))


def test_la_vignette_d_une_chaine_est_servie_sous_sa_cle(tmp_path):
    f = _f(tmp_path, Faux([_chaine()]))
    asyncio.run(f.lister("chaines", 24))
    k = flux.cle_vignette(UC1)
    assert f.source_vignette(k) == "https://yt3.ggpht.com/a/grand=s176"


# ── moteur : détail ──────────────────────────────────────────────────────────
def test_detail_chaine_dernieres_videos_et_titre(tmp_path):
    ex = Faux(["\n".join([_video(VID1, "Récent", "Atelier Réseau"), _video(VID2, "Ancien", "Atelier Réseau")])])
    f = _f(tmp_path, ex)
    r = asyncio.run(f.detail("chaine", UC1, 12))
    assert r["type"] == "chaine" and r["id"] == UC1 and r["titre"] == "Atelier Réseau"
    assert [i["id"] for i in r["items"]] == [VID1, VID2] and r["items"][0]["url"] == f"https://www.youtube.com/watch?v={VID1}"
    assert ex.argvs[0][-2:] == ["--", f"https://www.youtube.com/channel/{UC1}/videos"]
    assert ex.argvs[0][ex.argvs[0].index("--playlist-end") + 1] == "12"


def test_detail_playlist_cache_puis_perime(tmp_path):
    ex = Faux([_video(VID1, "Un", playlist_title="Réseaux"), flux.ErreurYoutube("HTTP Error 429")])
    t = [1000.0]
    f = _f(tmp_path, ex, ttl=10, horloge=lambda: t[0])
    r1 = asyncio.run(f.detail("playlist", PL1, 24))
    assert r1["titre"] == "Réseaux" and r1["type"] == "playlist"
    t[0] += 3
    r2 = asyncio.run(f.detail("playlist", PL1, 24))
    assert r2["en_cache"] is True and r2["titre"] == "Réseaux" and len(ex.argvs) == 1
    t[0] += 100
    r3 = asyncio.run(f.detail("playlist", PL1, 24))
    assert r3["perime"] is True and r3["cause"] == "youtube" and r3["titre"] == "Réseaux"


def test_detail_identifiant_douteux_refuse_avant_tout_et_sans_lancer_yt_dlp(tmp_path):
    ex = Faux([])
    f = _f(tmp_path, ex)
    for genre, ident in (("chaine", "--cookies=/etc/shadow"), ("chaine", "https://x/"), ("playlist", PL1 + " --exec x"),
                         ("playlist", "PL" + "a" * 100), ("chaine", "@" + "a" * 70), ("autre", UC1)):
        with pytest.raises(ValueError):
            asyncio.run(f.detail(genre, ident, 24))
    assert ex.argvs == []
    # même sans cookies : la validation passe en premier
    g = _f(tmp_path, ex, cookies=None)
    with pytest.raises(ValueError):
        asyncio.run(g.detail("chaine", "pas valide", 24))
    with pytest.raises(flux.AuthRequise):
        asyncio.run(g.detail("chaine", UC1, 24))
    assert ex.argvs == []


def test_les_details_ne_se_melangent_pas_entre_eux(tmp_path):
    ex = Faux([_video(VID1, "A"), _video(VID2, "B")])
    f = _f(tmp_path, ex)
    a = asyncio.run(f.detail("chaine", UC1, 24))
    b = asyncio.run(f.detail("chaine", UC2, 24))
    assert a["items"][0]["id"] == VID1 and b["items"][0]["id"] == VID2 and len(ex.argvs) == 2


def test_le_cache_des_details_est_borne_et_en_0600(tmp_path, monkeypatch):
    monkeypatch.setattr(flux, "MAX_DETAILS_EN_CACHE", 3)
    ex = Faux([_video(VID1)] * 6)
    f = _f(tmp_path, ex)
    for i in range(6):
        asyncio.run(f.detail("chaine", "@c%d" % i, 24))
    fichiers = [p for p in pathlib.Path(tmp_path).rglob("d-*.json")]
    assert len(fichiers) == 3 and all((p.stat().st_mode & 0o777) == 0o600 for p in fichiers)
    assert all("@c" not in p.name and "cookies" not in p.read_text() for p in fichiers)


def test_un_appel_a_la_fois_pour_les_details(tmp_path):
    async def lent(argv):
        lent.n += 1
        await asyncio.sleep(0.05)
        return _video(VID1)
    lent.n = 0
    f = _f(tmp_path, lent)

    async def deux():
        return await asyncio.gather(f.detail("chaine", UC1, 24), f.detail("chaine", UC1, 24))
    asyncio.run(deux())
    assert lent.n == 1


# ── routes ───────────────────────────────────────────────────────────────────
def _client(monkeypatch, tmp_path, execut, cookies=True):
    monkeypatch.setattr(main, "flux_moteur", flux.Flux(str(tmp_path), "/c/cookies.txt" if cookies else None, execut, ttl=60))

    class Moteur:
        cookies_stale = False

        def _has_cookies(self):
            return cookies
    monkeypatch.setattr(main, "engine", Moteur())
    return TestClient(main.app)


def test_routes_exigent_l_en_tete_du_hall(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, Faux([_video(VID1)] * 4))
    assert c.get(f"/api/v1/ytsas/flux/chaine/{UC1}").status_code == 403
    assert c.get(f"/api/v1/ytsas/flux/playlist/{PL1}").status_code == 403
    assert c.get(f"/api/v1/ytsas/flux/chaine/{UC1}", headers=H).status_code == 200
    assert c.get(f"/api/v1/ytsas/flux/playlist/{PL1}", headers=H).status_code == 200


def test_route_chaine_rend_titre_et_videos_et_accepte_le_handle(monkeypatch, tmp_path):
    ex = Faux([_video(VID1, chaine="Atelier Réseau"), _video(VID2, chaine="Autre")])
    c = _client(monkeypatch, tmp_path, ex)
    j = c.get(f"/api/v1/ytsas/flux/chaine/{UC1}?limite=5", headers=H).json()
    assert j["type"] == "chaine" and j["id"] == UC1 and j["titre"] == "Atelier Réseau" and j["items"][0]["id"] == VID1
    j = c.get("/api/v1/ytsas/flux/chaine/%40atelier", headers=H).json()
    assert j["id"] == "@atelier" and ex.argvs[-1][-1] == "https://www.youtube.com/@atelier/videos"


@pytest.mark.parametrize("chemin", [
    "chaine/UCcourt", "chaine/" + "x" * 300, "chaine/%40a%20b", "chaine/%40a%0A", "chaine/..%2F..%2Fetc%2Fpasswd",
    "chaine/https:%2F%2Fevil.example%2F", "chaine/-" + UC1, "chaine/UC" + "a" * 22 + "%3Bid",
    "playlist/WL", "playlist/PL", "playlist/PL" + "x" * 41, "playlist/PL%3Bx" + "x" * 14, "playlist/" + UC1,
    "playlist/..%2Fetc", "playlist/PL" + "x" * 16 + "%0A", "playlist/PL" + "x" * 16 + "%26list%3Dx",
])
def test_routes_refusent_un_identifiant_douteux_400_sans_lancer_yt_dlp(monkeypatch, tmp_path, chemin):
    ex = Faux([_video(VID1)])
    c = _client(monkeypatch, tmp_path, ex)
    r = c.get("/api/v1/ytsas/flux/" + chemin, headers=H)
    assert r.status_code in (400, 404), r.status_code
    assert ex.argvs == []


def test_route_sans_cookies_401_cookies_refuses_401_perimes_et_panne_502(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, Faux([]), cookies=False)
    r = c.get(f"/api/v1/ytsas/flux/chaine/{UC1}", headers=H)
    assert r.status_code == 401 and "cookies" in r.json()["error"]

    async def refus(argv):
        raise flux.CookiesRefuses("Login details are needed")
    c = _client(monkeypatch, tmp_path, refus)
    r = c.get(f"/api/v1/ytsas/flux/playlist/{PL1}", headers=H)
    assert r.status_code == 401 and r.json()["cookies_perimes"] is True and "Login details" not in json.dumps(r.json())
    assert main.engine.cookies_stale is True

    async def panne(argv):
        raise flux.ErreurYoutube("délai dépassé")
    c = _client(monkeypatch, tmp_path / "p", panne)
    r = c.get(f"/api/v1/ytsas/flux/chaine/{UC1}", headers=H)
    assert r.status_code == 502 and r.json()["detail"] == "délai dépassé"


def test_routes_chaines_et_playlists_en_liste(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, Faux([_chaine(), _playlist()]))
    j = c.get("/api/v1/ytsas/flux?type=chaines", headers=H).json()
    assert j["type"] == "chaines" and j["items"][0]["abonnes"] == 12300
    j = c.get("/api/v1/ytsas/flux?type=playlists", headers=H).json()
    assert j["items"][0]["id"] == PL1 and "types" not in j
    r = c.get("/api/v1/ytsas/flux?type=zzz", headers=H)
    assert r.status_code == 400 and {"chaines", "playlists"} <= set(r.json()["types"])


def test_aucun_secret_ni_cookie_dans_une_reponse(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, Faux([_chaine(), _video(VID1)]))
    corps = c.get("/api/v1/ytsas/flux?type=chaines", headers=H).text + c.get(f"/api/v1/ytsas/flux/chaine/{UC1}", headers=H).text
    assert "cookies" not in corps.lower() and "/c/" not in corps and "ggpht" not in corps


def test_la_route_vignette_accepte_la_cle_opaque_et_pas_une_chaine_longue(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, Faux([]))
    assert c.get(f"/api/v1/ytsas/flux/vignette/{UC1}", headers=H).status_code == 400


# ── 0.8.2 : un libellé de yt-dlp n'est pas un nom de chaîne ──────────────────────────────────────────
@pytest.mark.parametrize("libelle", ["View full playlist", "view full playlist", "Voir la playlist complète", "Afficher la playlist complète", "  View full playlist  "])
def test_le_libelle_du_lien_de_yt_dlp_n_est_pas_le_nom_de_la_chaine(libelle):
    """Lecture réelle de `feed/playlists` : yt-dlp met le texte du lien (« View full playlist ») dans `uploader`."""
    brut = json.dumps({"_type": "url", "id": PL1, "title": "CLIPz", "uploader": libelle})
    assert flux.analyser_playlists(brut)[0]["chaine"] == ""


def test_un_vrai_nom_de_chaine_est_conserve():
    brut = json.dumps({"_type": "url", "id": PL1, "title": "CLIPz", "uploader": "Cours Libres"})
    assert flux.analyser_playlists(brut)[0]["chaine"] == "Cours Libres"
    assert flux.analyser_playlists(_playlist(chaine="Ma playlist complète de blues"))[0]["chaine"] == "Ma playlist complète de blues"
