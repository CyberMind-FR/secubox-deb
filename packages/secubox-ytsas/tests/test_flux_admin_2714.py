# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2714 — administration du Flux YouTube : état de chaque liste, actualisation, vidage, diagnostic.

Tout est simulé (exécuteur factice, aucun accès à YouTube ni à une box). Les cookies de la box étant périmés, rien n'est
vérifiable en réel : ces tests prouvent le contrat, la garde, l'assainissement et la borne anti-rafale."""
import asyncio
import json
import os
import pathlib
import re
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("YTSAS_DOWNLOAD_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
import flux  # noqa: E402
import main  # noqa: E402

PKG = pathlib.Path(__file__).resolve().parent.parent
HALL_CONF = (PKG.parent / "secubox-webos" / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
ROUTES = (PKG / "nginx" / "ytsas-routes.conf").read_text(encoding="utf-8")
PUBLIC = (PKG / "nginx" / "ytsas.conf").read_text(encoding="utf-8")

ID1, ID2 = "dQw4w9WgXcQ", "aqz-KE-bpKQ"
JETON = "a" * 64
ADMIN = {"X-Sbx-Garde-Admin": JETON}
SECRET = "SECRETVALUE0123456789abcdef"      # sert de « contenu de cookie » : il ne doit apparaître dans AUCUNE réponse


def _ligne(vid, titre="T"):
    return json.dumps({"id": vid, "title": titre, "channel": "C", "duration": 10})


class Executeur:
    """Exécuteur factice : file de réponses pour les lectures, `--version` à part. Compte les lectures YouTube."""
    def __init__(self, sorties=None, version="2026.08.19"):
        self.sorties = list(sorties or [])
        self.lectures = 0
        self.version = version
        self.versions = 0
        self.argv = []

    async def __call__(self, argv):
        self.argv.append(argv)
        if argv[1:] == ["--version"]:
            self.versions += 1
            if isinstance(self.version, Exception):
                raise self.version
            return self.version + "\n"
        self.lectures += 1
        s = self.sorties.pop(0) if self.sorties else _ligne(ID1)
        if isinstance(s, Exception):
            raise s
        return s


class Horloge:
    def __init__(self, t=100000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def banc(monkeypatch, tmp_path):
    cookies = tmp_path / "cookies.txt"
    cookies.write_text(f"# Netscape\n.youtube.com\tTRUE\t/\tTRUE\t0\tSID\t{SECRET}\n")
    garde = tmp_path / "garde"
    garde.write_text(JETON)

    class Moteur:      # indépendant des doubles qu'installent les autres tests dans main.engine
        cookies_stale = False
        presents = True

        def _has_cookies(self):
            return self.presents

    ex = Executeur()
    hor = Horloge(os.path.getmtime(cookies) + 60)
    fl = flux.Flux(str(tmp_path / "d"), str(cookies), ex, ttl=900, horloge=hor)
    monkeypatch.setattr(main, "flux_moteur", fl)
    monkeypatch.setattr(main, "engine", Moteur())
    monkeypatch.setattr(main, "COOKIE_PATH", str(cookies))
    monkeypatch.setattr(main, "GARDE_ADMIN_PATH", str(garde))
    return type("Banc", (), {"c": TestClient(main.app), "ex": ex, "hor": hor, "fl": fl, "moteur": main.engine,
                              "cookies": cookies, "garde": garde, "tmp": tmp_path})()


def get(b, chemin="/flux/etat", h=ADMIN):
    return b.c.get("/api/v1/ytsas" + chemin, headers=h)


def post(b, chemin, h=ADMIN):
    return b.c.post("/api/v1/ytsas" + chemin, headers=h)


def liste(etat, t):
    return next(x for x in etat["listes"] if x["type"] == t)


# ───────────────────────── garde ─────────────────────────
ROUTES_ADMIN = [("GET", "/flux/etat"), ("POST", "/flux/actualiser/envie"), ("POST", "/flux/vider/envie")]


@pytest.mark.parametrize("methode, chemin", ROUTES_ADMIN)
def test_sans_jeton_de_garde_toutes_les_routes_refusent(banc, methode, chemin):
    r = banc.c.request(methode, "/api/v1/ytsas" + chemin)
    assert r.status_code == 403
    assert banc.ex.lectures == 0


@pytest.mark.parametrize("methode, chemin", ROUTES_ADMIN)
def test_l_en_tete_du_hall_et_un_faux_jeton_n_ouvrent_rien(banc, methode, chemin):
    for h in ({"X-Sbx-Flux": "1"}, {"X-Sbx-Admin": "1"}, {"X-Sbx-Garde-Admin": "1"}, {"X-Sbx-Garde-Admin": "b" * 64},
              {"X-Sbx-Garde-Admin": ""}, {"X-Sbx-Flux": "1", "X-Sbx-Garde-Admin": JETON[:-1]}):
        assert banc.c.request(methode, "/api/v1/ytsas" + chemin, headers=h).status_code == 403, h
    assert banc.ex.lectures == 0 and banc.ex.versions == 0


@pytest.mark.parametrize("contenu", [None, "", "court"])
def test_sans_jeton_installe_tout_est_refuse_meme_avec_un_en_tete(banc, contenu):
    if contenu is None:
        banc.garde.unlink()
    else:
        banc.garde.write_text(contenu)
    for methode, chemin in ROUTES_ADMIN:
        assert banc.c.request(methode, "/api/v1/ytsas" + chemin, headers={"X-Sbx-Garde-Admin": contenu or ""}).status_code == 403


def test_les_routes_d_admin_ne_changent_pas_les_routes_du_hall(banc):
    assert banc.c.get("/api/v1/ytsas/flux?type=envie").status_code == 403           # le Hall exige toujours son en-tête
    assert banc.c.get("/api/v1/ytsas/flux?type=envie", headers={"X-Sbx-Flux": "1"}).status_code == 200
    # et le jeton d'administration n'ouvre pas la route du Hall
    assert banc.c.get("/api/v1/ytsas/flux?type=envie", headers=ADMIN).status_code == 403


# ───────────────────────── nginx : jamais via le Hall ni en public ─────────────────────────
def _motif_hall():
    m = re.search(r'location ~ "(\^/api/v1/ytsas/flux[^"]*)"', HALL_CONF)
    assert m
    return re.compile(m.group(1).replace(r"\z", r"\Z"))


@pytest.mark.parametrize("chemin", ["/api/v1/ytsas/flux/etat", "/api/v1/ytsas/flux/actualiser/envie", "/api/v1/ytsas/flux/vider/envie",
                                    "/api/v1/ytsas/flux/etat/", "/api/v1/ytsas/flux//etat"])
def test_le_motif_du_hall_n_admet_aucune_route_d_administration(chemin):
    assert not _motif_hall().match(chemin)


def test_le_motif_du_hall_admet_toujours_ses_routes_de_lecture():
    p = _motif_hall()
    assert p.match("/api/v1/ytsas/flux") and p.match("/api/v1/ytsas/flux/vignette/" + ID1)


def test_vhost_admin_garde_par_auth_request_administrateur_et_jeton():
    assert "location = /__sbx_ytsas_admin" in ROUTES and "internal;" in ROUTES
    assert "verify?exige=admin" in ROUTES
    assert ROUTES.count("auth_request /__sbx_ytsas_admin;") == 2
    assert ROUTES.count("include /etc/nginx/snippets/secubox-ytsas-garde*.conf;") == 2
    assert "limit_except GET { deny all; }" in ROUTES and "limit_except POST { deny all; }" in ROUTES
    for b in re.findall(r"location (?:= /api/v1/ytsas/flux/etat|~ \"\^/api/v1/ytsas/flux/\(actualiser\|vider\)[^\"]*\") \{(.*?)\n\}", ROUTES, re.S):
        assert b.index("auth_request") < b.index("secubox-ytsas-garde")        # le jeton n'est posé qu'après le contrôle
    assert "X-Sbx-Flux" not in ROUTES                                           # rien du Hall ici


def test_le_prefixe_ouvert_et_le_vhost_public_effacent_le_jeton_de_garde():
    prefixe = ROUTES[ROUTES.index("location /api/v1/ytsas/ {"):]
    assert 'proxy_set_header X-Sbx-Garde-Admin "";' in prefixe
    assert 'proxy_set_header X-Sbx-Garde-Admin "";' in PUBLIC
    assert "/flux/" not in PUBLIC


def test_le_jeton_est_installe_par_install_lxc_sans_etre_passe_en_argument():
    sh = (PKG / "lxc" / "install-lxc.sh").read_text(encoding="utf-8")
    assert "urandom" in sh and "umask 077" in sh and "secubox-ytsas-garde.conf" in sh and "YTSAS_GARDE_ADMIN=/data/ytsas/.garde-admin" in sh
    assert "echo \"$_v\"" not in sh and "echo $_v" not in sh


# ───────────────────────── état : lecture seule, sans YouTube ─────────────────────────
def test_etat_sans_cache_ne_lance_aucune_lecture_youtube(banc):
    r = get(banc)
    assert r.status_code == 200
    e = r.json()
    assert banc.ex.lectures == 0
    assert [x["type"] for x in e["listes"]] == list(flux.TYPES)
    for x in e["listes"]:
        assert x["date"] is None and x["videos"] is None and x["perime"] is None and x["duree_s"] is None and x["relance_dans_s"] == 0
    assert e["anti_rafale_s"] == 30 and e["ttl_s"] == 900


def test_etat_apres_lecture_du_hall_donne_date_nombre_duree_et_peremption(banc):
    banc.ex.sorties = [_ligne(ID1) + "\n" + _ligne(ID2)]
    asyncio.run(banc.fl.lister("abonnements", 24))
    assert banc.ex.lectures == 1
    e = get(banc).json()
    a = liste(e, "abonnements")
    assert a["videos"] == 2 and a["date"] == int(banc.hor.t) and a["perime"] is False and a["cause"] is None
    assert a["derniere_tentative"] == int(banc.hor.t) and isinstance(a["duree_s"], float)
    assert liste(e, "envie")["videos"] is None
    banc.hor.t += 1000
    a = liste(get(banc).json(), "abonnements")
    assert a["perime"] is True and a["age_s"] == 1000
    assert banc.ex.lectures == 1                    # afficher l'état ne relit jamais YouTube


def test_etat_dit_la_cause_quand_la_derniere_lecture_a_echoue(banc):
    banc.ex.sorties = [_ligne(ID1), flux.CookiesRefuses("Login details are needed"), flux.ErreurYoutube("HTTP Error 429")]
    banc.fl.ttl = 0
    asyncio.run(banc.fl.lister("historique", 24))
    asyncio.run(banc.fl.lister("historique", 24))
    assert liste(get(banc).json(), "historique")["cause"] == "cookies"
    asyncio.run(banc.fl.lister("historique", 24))
    h = liste(get(banc).json(), "historique")
    assert h["cause"] == "youtube" and h["perime"] is True and h["videos"] == 1


def test_sans_cookies_la_cause_est_absent(banc):
    banc.moteur.presents = False
    banc.cookies.unlink()
    e = get(banc).json()
    assert all(x["cause"] == "absent" for x in e["listes"])
    assert e["cookies"]["present"] is False and e["cookies"]["mtime"] is None and e["cookies"]["verdict"] == "absents"


# ───────────────────────── cookies : jamais de contenu ─────────────────────────
def test_cookies_presence_et_date_sans_jamais_le_contenu(banc):
    r = get(banc)
    c = r.json()["cookies"]
    assert c["present"] is True and c["mtime"] == int(os.path.getmtime(banc.cookies)) and c["verdict"] == "inconnu"
    assert set(c) == {"present", "mtime", "stale", "verdict"}
    for mot in (SECRET, "SID", ".youtube.com", "Netscape", str(banc.cookies), "cookies.txt"):
        assert mot not in r.text, mot


def test_verdict_des_cookies_refuses_acceptes_anciens(banc):
    banc.ex.sorties = [flux.CookiesRefuses("Login details are needed")]
    assert post(banc, "/flux/actualiser/envie").status_code == 502
    assert get(banc).json()["cookies"]["verdict"] == "refuses" and banc.moteur.cookies_stale is True
    banc.moteur.cookies_stale = False
    banc.hor.t += 100
    banc.fl.ttl = 0
    os.utime(banc.cookies, (banc.hor.t - 10, banc.hor.t - 10))       # nouveau dépôt, plus récent que le refus
    assert get(banc).json()["cookies"]["verdict"] == "inconnu"
    banc.hor.t += 100
    assert post(banc, "/flux/actualiser/envie").status_code == 200
    assert get(banc).json()["cookies"]["verdict"] == "acceptes"
    os.utime(banc.cookies, (1, 1))                                    # fichier très ancien
    banc.moteur.cookies_stale = False
    assert get(banc).json()["cookies"]["verdict"] == "anciens"


# ───────────────────────── actualiser ─────────────────────────
def test_actualiser_relit_malgre_un_cache_frais_et_rend_le_resume(banc):
    asyncio.run(banc.fl.lister("envie", 24))
    banc.ex.sorties = [_ligne(ID1) + "\n" + _ligne(ID2)]
    banc.hor.t += 5
    r = post(banc, "/flux/actualiser/envie")
    assert r.status_code == 200 and banc.ex.lectures == 2
    j = r.json()
    assert j["ok"] is True and j["type"] == "envie" and j["videos"] == 2 and j["perime"] is False and j["cause"] is None
    assert j["date"] == int(banc.hor.t) and isinstance(j["duree_s"], float)
    assert "items" not in j and "ID" not in r.text and ID1 not in r.text      # ni titre ni identifiant de vidéo


def test_borne_anti_rafale_par_liste_et_independante_entre_listes(banc):
    assert post(banc, "/flux/actualiser/envie").status_code == 200
    banc.hor.t += 10
    r = post(banc, "/flux/actualiser/envie")
    assert r.status_code == 429 and r.json()["cause"] == "rafale" and r.json()["reessayer_dans"] == 20 and r.headers["retry-after"] == "20"
    assert banc.ex.lectures == 1
    assert liste(get(banc).json(), "envie")["relance_dans_s"] == 20
    assert post(banc, "/flux/actualiser/propositions").status_code == 200       # une autre liste n'est pas freinée
    banc.hor.t += 20
    assert post(banc, "/flux/actualiser/envie").status_code == 200
    assert banc.ex.lectures == 3


def test_la_rafale_est_comptee_meme_apres_un_echec(banc):
    banc.ex.sorties = [flux.ErreurYoutube("HTTP Error 429")]
    assert post(banc, "/flux/actualiser/envie").status_code == 502
    assert post(banc, "/flux/actualiser/envie").status_code == 429
    assert banc.ex.lectures == 1


def test_une_seule_relance_a_la_fois(tmp_path):
    ouvre = asyncio.Event
    async def scenario():
        libere = ouvre()

        async def lent(argv):
            await libere.wait()
            return _ligne(ID1)
        f = flux.Flux(str(tmp_path), "/c/cookies.txt", lent, horloge=Horloge())
        t1 = asyncio.create_task(f.actualiser("envie"))
        await asyncio.sleep(0)
        with pytest.raises(flux.Occupe):
            await f.actualiser("abonnements")
        libere.set()
        assert (await t1)["items"]
    asyncio.run(scenario())


def test_actualiser_echec_avec_ancien_cache_repond_200_ok_faux_et_la_cause(banc):
    asyncio.run(banc.fl.lister("envie", 24))
    banc.ex.sorties = [flux.CookiesRefuses("Login details are needed")]
    banc.hor.t += 5
    r = post(banc, "/flux/actualiser/envie")
    assert r.status_code == 200
    assert r.json()["ok"] is False and r.json()["perime"] is True and r.json()["cause"] == "cookies" and r.json()["videos"] == 1
    assert "Login details" not in r.text


def test_actualiser_echec_sans_cache_repond_502_sans_401(banc):
    # 401 est réservé à « session expirée » côté page : une cause de YouTube ne doit jamais s'y confondre
    banc.ex.sorties = [flux.ErreurYoutube("HTTP Error 429")]
    r = post(banc, "/flux/actualiser/envie")
    assert r.status_code == 502 and r.json()["cause"] == "youtube"
    banc.hor.t += 60
    banc.ex.sorties = [flux.CookiesRefuses("Sign in to confirm you're not a bot")]
    r = post(banc, "/flux/actualiser/envie")
    assert r.status_code == 502 and r.json()["cause"] == "cookies"


def test_actualiser_sans_cookies_et_type_inconnu(banc):
    assert post(banc, "/flux/actualiser/zzz").status_code == 400
    assert post(banc, "/flux/vider/zzz").status_code == 400
    assert post(banc, "/flux/actualiser/..%2Fetc").status_code in (400, 404)
    banc.moteur.presents = False
    r = post(banc, "/flux/actualiser/envie")
    assert r.status_code == 409 and r.json()["cause"] == "absent" and banc.ex.lectures == 0


def test_methodes_incorrectes(banc):
    assert banc.c.get("/api/v1/ytsas/flux/actualiser/envie", headers=ADMIN).status_code == 405
    assert banc.c.post("/api/v1/ytsas/flux/etat", headers=ADMIN).status_code == 405
    assert banc.c.get("/api/v1/ytsas/flux/vider/envie", headers=ADMIN).status_code == 405


# ───────────────────────── vider ─────────────────────────
def test_vider_supprime_le_cache_d_une_seule_liste(banc):
    asyncio.run(banc.fl.lister("envie", 24))
    asyncio.run(banc.fl.lister("abonnements", 24))
    r = post(banc, "/flux/vider/envie")
    assert r.status_code == 200 and r.json() == {"ok": True, "type": "envie", "vide": True}
    e = get(banc).json()
    assert liste(e, "envie")["videos"] is None and liste(e, "abonnements")["videos"] == 1
    assert post(banc, "/flux/vider/envie").json()["vide"] is False             # idempotent
    assert banc.cookies.exists() and banc.ex.lectures == 2                      # ni cookies touchés, ni lecture lancée


# ───────────────────────── assainissement ─────────────────────────
SALE = (f"ERROR: unable to download https://rr3---sn-x.googlevideo.com/videoplayback?expire=1&sig=AAAA{SECRET}&ip=1.2.3.4 "
        f"from /var/lib/secubox/ytsas/cookies.txt SAPISID={SECRET} __Secure-3PSID=g.a000{SECRET} token eyJhbGciOiJIUzI1NiJ9abcdef0123456789xyz "
        "C:\\Users\\moi\\cookies.txt ~/cookies.txt")


@pytest.mark.parametrize("brut", [SALE, "x" * 400, f"Cookie: SID={SECRET}", "https://i.ytimg.com/vi/a/b.jpg?sqp=secretsecret"])
def test_assainir_retire_adresses_chemins_cookies_et_longues_chaines(brut):
    t = flux.assainir(brut)
    for interdit in (SECRET, "googlevideo", "https://", "/var/lib", "cookies.txt", "SAPISID=", "eyJhbGci", "C:\\", "ytimg", "\n"):
        assert interdit not in t, (interdit, t)
    assert len(t) <= flux.TAILLE_TEXTE_ECHEC


def test_assainir_garde_un_message_lisible():
    assert flux.assainir("HTTP Error 429: Too Many Requests") == "HTTP Error 429: Too Many Requests"
    assert flux.assainir("and/or fine") == "and/or fine"
    assert flux.assainir(None) == "" and flux.assainir(12) == ""


def test_derniers_echecs_assainis_dans_l_etat_et_dans_les_reponses(banc):
    banc.ex.sorties = [flux.ErreurYoutube(SALE), flux.CookiesRefuses("Sign in to confirm. Use --cookies " + str(banc.cookies) + " " + SECRET)]
    r1 = post(banc, "/flux/actualiser/envie")
    banc.hor.t += 60
    r2 = post(banc, "/flux/actualiser/propositions")
    assert r1.status_code == 502 and r2.status_code == 502
    r3 = get(banc)
    for r in (r1, r2, r3):
        for interdit in (SECRET, "googlevideo", "https://", "/var/lib", str(banc.cookies), "SAPISID="):
            assert interdit not in r.text, (interdit, r.text)
    echecs = r3.json()["diagnostic"]["echecs"]
    assert [e["liste"] for e in echecs] == ["propositions", "envie"] and [e["cause"] for e in echecs] == ["cookies", "youtube"]
    assert all(set(e) == {"liste", "date", "cause", "texte"} and len(e["texte"]) <= 160 for e in echecs)


def test_les_echecs_sont_bornes_a_dix(banc):
    banc.fl.ttl = 0
    banc.ex.sorties = [flux.ErreurYoutube(f"echec {i}") for i in range(15)]
    for _ in range(15):
        with pytest.raises(flux.ErreurYoutube):
            asyncio.run(banc.fl.lister("envie", 24))
    echecs = get(banc).json()["diagnostic"]["echecs"]
    assert len(echecs) == 10 and echecs[0]["texte"] == "echec 14"


# ───────────────────────── diagnostic ─────────────────────────
def test_diagnostic_version_moteur_js_et_cache(banc, monkeypatch):
    monkeypatch.setattr(flux.shutil, "which", lambda n: "/usr/bin/" + n if n in ("deno", "node") else None)
    asyncio.run(banc.fl.lister("envie", 24))
    d = get(banc).json()["diagnostic"]
    assert d["ytdlp"] == "2026.08.19" and d["js"] == {"present": True, "moteurs": ["deno", "node"], "par_defaut": True}
    assert d["cache"]["fichiers"] >= 2 and d["cache"]["octets"] > 0
    get(banc)
    assert banc.ex.versions == 1                                                          # mémorisée 10 minutes
    banc.hor.t += 601
    get(banc)
    assert banc.ex.versions == 2
    assert ["yt-dlp", "--version"] in banc.ex.argv


def test_diagnostic_sans_moteur_js_le_dit(banc, monkeypatch):
    monkeypatch.setattr(flux.shutil, "which", lambda n: None)
    d = get(banc).json()["diagnostic"]
    assert d["js"] == {"present": False, "moteurs": [], "par_defaut": False}


def test_diagnostic_node_seul_n_est_pas_actif_par_defaut(banc, monkeypatch):
    monkeypatch.setattr(flux.shutil, "which", lambda n: "/usr/bin/node" if n == "node" else None)
    assert get(banc).json()["diagnostic"]["js"] == {"present": True, "moteurs": ["node"], "par_defaut": False}


@pytest.mark.parametrize("sortie", [flux.ErreurYoutube("introuvable"), "pas une version !\n", "", "../../etc/passwd"])
def test_version_illisible_donne_none_sans_planter(banc, sortie):
    banc.ex.version = sortie if isinstance(sortie, Exception) else sortie.rstrip("\n")
    r = get(banc)
    assert r.status_code == 200 and r.json()["diagnostic"]["ytdlp"] is None


def test_taille_du_cache_compte_les_fichiers(banc):
    assert banc.fl.taille_cache() == {"fichiers": 0, "octets": 0}
    asyncio.run(banc.fl.lister("envie", 24))
    assert banc.fl.taille_cache()["fichiers"] >= 1


def test_aucune_reponse_ne_contient_de_cookie_en_nominal(banc):
    banc.ex.sorties = [_ligne(ID1, SECRET)]
    textes = [post(banc, "/flux/actualiser/envie").text, get(banc).text, post(banc, "/flux/vider/envie").text]
    for t in textes:
        assert SECRET not in t
