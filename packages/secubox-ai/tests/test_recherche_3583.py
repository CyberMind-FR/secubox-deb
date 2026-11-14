# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Recherche et lecture de pages (#3583, tâche 6) : garde SSRF, contrôle de réponse, budget. Aucun réseau réel."""
import logging

import json

import httpx
import pytest

from api import moteurs, recherche, reglages

HTML = "<html><body><p>" + ("Michel Murty est un sujet. " * 20) + "</p></body></html>"


@pytest.fixture
def web(monkeypatch, tmp_path):
    """Transport web de test : enregistre toute requête arrivée jusqu'au transport ; résolveur injecté."""
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "absent.toml"))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(tmp_path / "absente.key"))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    (tmp_path / "run" / "demandes").mkdir(parents=True)       # créé par secubox-aictl preparer en production
    etat = {"vues": [], "reqs": [], "reponses": {}, "dns": {}, "appels_dns": []}

    def handler(req):
        # La connexion est épinglée sur l'adresse validée : l'adresse d'origine se lit dans l'en-tête Host.
        origine = f"{req.url.scheme}://{req.headers['host']}{req.url.raw_path.decode()}"
        etat["vues"].append(origine)
        etat["reqs"].append({"url": str(req.url), "host": req.headers["host"],
                             "sni": req.extensions.get("sni_hostname")})
        return etat["reponses"].get(origine, httpx.Response(200, html=HTML))

    async def resolveur(hote):
        etat["appels_dns"].append(hote)
        return etat["dns"].get(hote, ["93.184.216.34"])

    inet6 = tmp_path / "if_inet6"
    inet6.write_text("", encoding="ascii")
    etat["inet6"] = inet6
    monkeypatch.setattr(recherche, "SOURCE_IF_INET6", str(inet6))

    monkeypatch.setattr(recherche, "FABRIQUE_TRANSPORT_WEB", lambda nom: httpx.MockTransport(handler))
    monkeypatch.setattr(recherche, "RESOLVEUR", resolveur)
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", None)
    return etat


@pytest.mark.asyncio
async def test_page_publique_lue(web):
    assert "Michel Murty" in await recherche.telecharger("https://exemple.test/")
    assert web["vues"] == ["https://exemple.test/"]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://10.0.0.1/", "http://[::1]/", "http://169.254.169.254/",
    "http://x:8080/", "http://user@exemple.test/", "http://user:mdp@exemple.test/", "ftp://exemple.test/",
    "file:///etc/passwd", "http://exemple.test:99999/"])
async def test_garde_refuse_sans_requete(web, url):
    assert await recherche.telecharger(url) == ""
    assert web["vues"] == []


@pytest.mark.asyncio
async def test_nom_resolu_en_prive_refuse(web):
    web["dns"]["interne.test"] = ["93.184.216.34", "192.168.1.5"]
    assert await recherche.telecharger("http://interne.test/") == ""
    assert web["vues"] == []


@pytest.mark.asyncio
async def test_redirection_vers_adresse_privee_non_suivie(web):
    web["reponses"]["http://exemple.test/"] = httpx.Response(302, headers={"location": "http://10.0.0.1/secret"})
    assert await recherche.telecharger("http://exemple.test/") == ""
    assert web["vues"] == ["http://exemple.test/"]          # seule la première requête est partie


@pytest.mark.asyncio
async def test_non_html_et_taille_bornee(web):
    web["reponses"]["http://a.test/"] = httpx.Response(200, headers={"content-type": "application/json"}, content=b"{}")
    assert await recherche.telecharger("http://a.test/") == ""
    web["reponses"]["http://b.test/"] = httpx.Response(200, headers={"content-type": "text/html"},
                                                      content=b"x" * 1_000_000)
    assert len(await recherche.telecharger("http://b.test/")) <= recherche.TAILLE_PAGE_MAX


@pytest.mark.asyncio
async def test_lire_page_garde_a_chaque_saut(web):
    web["reponses"]["http://site.test/"] = httpx.Response(
        200, html="<p>court</p><a href='/a.html'>a</a><a href='http://10.0.0.1/x.html'>b</a>"
                  "<iframe src='/cadre.html'></iframe>")
    web["reponses"]["http://site.test/cadre.html"] = httpx.Response(200, html=HTML)
    texte = await recherche.lire_page("http://site.test/")
    assert "Michel Murty" in texte
    assert not any("10.0.0.1" in v for v in web["vues"])      # autre hôte : jamais suivi


@pytest.mark.asyncio
async def test_lire_page_saut_vers_hote_prive_refuse(web, monkeypatch):
    """Première page publique avec un lien du même hôte ; le saut suivant se résout en privé : refusé."""
    web["reponses"]["http://site.test/"] = httpx.Response(200, html=HTML + "<a href='/suite.html'>suite</a>")
    suites = iter([["93.184.216.34"], ["10.0.0.9"]])
    web["dns"] = {}

    async def resolveur(hote):
        return next(suites)
    monkeypatch.setattr(recherche, "RESOLVEUR", resolveur)
    texte = await recherche.lire_page("http://site.test/")
    assert "Michel Murty" in texte
    assert web["vues"] == ["http://site.test/"]               # aucune requête vers /suite.html


def test_controler_reponse_retire_adresse_absente():
    bloc = '<donnees>[{"url": "https://fr.wikipedia.org/wiki/X", "page": "né en 1950"}]</donnees>'
    texte = "Voir https://fr.wikipedia.org/wiki/X et https://invente.example/faux. Né en 1950, mort en 1999."
    propre, retirees, annees = recherche.controler_reponse(texte, bloc)
    assert "invente.example" not in propre and "fr.wikipedia.org" in propre
    assert retirees == ["https://invente.example/faux"]
    assert annees == ["1999"]


def test_termes_passages_pertinent_lucidite():
    assert recherche.termes("Qui était Michel Murty ?") == ["michel", "murty"]
    assert recherche.passages("Rien ici. Michel Murty chante. Suite. Autre.", ["michel", "murty"]) == "Michel Murty chante. Suite."
    assert recherche.pertinent({"titre": "Michel Murty", "extrait": "", "url": "http://x"}, ["michel", "murty"])
    assert not recherche.pertinent({"titre": "Michel", "extrait": "", "url": "http://x"}, ["michel", "murty"])
    assert recherche.regler_lucidite(100)["mode"] == "lucide" and recherche.regler_lucidite("zz")["niveau"] == 85
    assert recherche.consigne_sources("B").startswith("Réponds UNIQUEMENT") and recherche.consigne_sources("B").endswith("B")


def _moteur_factice(monkeypatch):
    async def assurer():
        return moteurs.Moteur("local")

    async def ctx(m=None):
        return 100000

    async def jetons(texte, m=None):
        return len(texte) // 4

    monkeypatch.setattr(moteurs, "assurer_moteur", assurer)
    monkeypatch.setattr(moteurs, "contexte_reel", ctx)
    monkeypatch.setattr(moteurs, "compter_tokens", jetons)


@pytest.mark.asyncio
async def test_budget_respecte_sources_max_jetons(web, monkeypatch):
    _moteur_factice(monkeypatch)
    gros = "<p>" + ("Michel Murty chante des chansons. " * 400) + "</p>"
    web["reponses"]["https://officiel.fr/"] = httpx.Response(200, html=gros)

    prefs = reglages.lire_prefs()
    prefs["outils"].update(secubox=False, searxng=False, wikipedia=False)
    prefs["outils"]["sources_max_jetons"] = 1000
    # adresse donnée par l'utilisateur : page lue, bloc rogné au budget
    sources, evts = [], []

    class Suivi:
        async def put(self, e):
            evts.append(e)
    etat, bloc = await recherche.recherche_fiable("lis officiel.fr/", prefs, sources, Suivi())
    assert etat == "ok" and sources[0]["url"] == "https://officiel.fr/"
    tokens = next(e for e in evts if e['etape'] == 'budget')['tokens_sources']
    assert tokens <= 1000
    assert len(bloc) < len(gros)


@pytest.mark.asyncio
async def test_recherche_adresse_privee_illisible(web, monkeypatch):
    _moteur_factice(monkeypatch)
    prefs = reglages.lire_prefs()
    prefs["outils"].update(secubox=False, searxng=False, wikipedia=False)
    web["dns"]["prive.fr"] = ["10.0.0.9"]
    etat, bloc = await recherche.recherche_fiable("lis http://prive.fr/", prefs, [], None)
    assert (etat, bloc) == ("illisible", "") and web["vues"] == []


@pytest.mark.asyncio
async def test_searxng_absent_sans_distant(web):
    assert await recherche.outil_searxng("x") == []
    assert web["vues"] == []


@pytest.mark.asyncio
async def test_outils_secubox_et_wikipedia_et_heure(web):
    web["reponses"]["https://hall.gk2.secubox.in/api/v1/zia/objets?q=zia&limit=5"] = httpx.Response(
        200, json={"objets": [{"title": "T", "summary": "S", "url": "https://u/1", "service": "metanews"}, {"title": "", "url": "x"}]})
    r = await recherche.outil_secubox("zia")
    assert r == [{"titre": "T", "extrait": "S", "url": "https://u/1", "secubox": "metanews"}]
    web["reponses"]["https://fr.wikipedia.org/w/api.php?action=query&list=search&srsearch=zia&srlimit=3&format=json"] = \
        httpx.Response(200, json={"query": {"search": [{"title": "Un titre", "snippet": "<b>a</b> &amp; b"}]}})
    w = await recherche.outil_wikipedia("zia")
    assert w[0]["url"].endswith("/Un_titre") and w[0]["extrait"] == "a & b"
    assert (await recherche.outil_heure())[0]["titre"] == "Heure locale"


@pytest.mark.asyncio
async def test_aucun_contenu_dans_le_journal(web, caplog):
    caplog.set_level(logging.DEBUG)
    await recherche.telecharger("https://secret-adresse.test/page")
    await recherche.recherche_fiable("Qui est Michel Murty confidentiel ?", {**reglages.lire_prefs(), "outils": {"secubox": False}}, [], None)
    assert "secret-adresse" not in caplog.text and "confidentiel" not in caplog.text


# ---- R14 : épinglage de l'adresse validée, IPv6 local, NAT64 ----
@pytest.mark.asyncio
async def test_connexion_epinglee_sur_ladresse_validee(web):
    web["dns"]["exemple.test"] = ["93.184.216.34", "93.184.216.35"]
    assert "Michel Murty" in await recherche.telecharger("https://exemple.test/p?x=1")
    req = web["reqs"][0]
    assert req["url"] == "https://93.184.216.34/p?x=1"
    assert req["host"] == "exemple.test" and req["sni"] == "exemple.test"


@pytest.mark.asyncio
async def test_epinglage_ipv6_et_port(web):
    web["dns"]["v6.test"] = ["2606:2800:220:1::1"]
    await recherche.telecharger("http://v6.test:80/")
    assert web["reqs"][0]["url"] == "http://[2606:2800:220:1::1]/"   # httpx omet le port par défaut
    assert web["reqs"][0]["host"] == "v6.test:80"


@pytest.mark.asyncio
async def test_rebinding_une_seule_resolution(web, monkeypatch):
    """Une seconde résolution donnerait une adresse privée : la connexion part quand même sur la première."""
    reponses = iter([["93.184.216.34"], ["10.0.0.9"]])

    async def resolveur(hote):
        web["appels_dns"].append(hote)
        return next(reponses)
    monkeypatch.setattr(recherche, "RESOLVEUR", resolveur)
    assert "Michel Murty" in await recherche.telecharger("http://rebind.test/")
    assert web["appels_dns"] == ["rebind.test"]
    assert web["reqs"][0]["url"].startswith("http://93.184.216.34/")


@pytest.mark.asyncio
async def test_ipv6_du_prefixe_local_refuse(web):
    # préfixe global (2a01:e0a0:1:1::/64) : seule la table des interfaces peut le refuser
    web["inet6"].write_text("2a01e0a0000100010000000000000002 02 40 00 00 eth1\n"
                            "00000000000000000000000000000001 01 80 10 80 lo\n", encoding="ascii")
    web["dns"]["voisin.test"] = ["2a01:e0a0:1:1::99"]
    assert await recherche.telecharger("http://voisin.test/") == ""
    assert await recherche.telecharger("http://[2a01:e0a0:1:1::5]/") == ""
    assert web["vues"] == []
    web["dns"]["ailleurs.test"] = ["2a01:e0a0:1:2::99"]       # hors du préfixe : autorisée
    assert "Michel Murty" in await recherche.telecharger("http://ailleurs.test/")


@pytest.mark.asyncio
async def test_nat64_et_ipv4_mappe_refuses(web):
    web["dns"]["nat.test"] = ["64:ff9b::a00:1"]
    web["dns"]["map.test"] = ["::ffff:10.0.0.1"]
    web["dns"]["compat.test"] = ["::a00:1"]
    assert await recherche.telecharger("http://compat.test/") == ""
    assert await recherche.telecharger("http://nat.test/") == ""
    assert await recherche.telecharger("http://map.test/") == ""
    assert await recherche.telecharger("http://[64:ff9b::a00:1]/") == ""
    assert web["vues"] == []


# ---- I1 : searxng par le moteur distant ----
CLE = "sk-secret-tres-longue-9f8e7d"


@pytest.fixture
def distant(web, tmp_path, monkeypatch):
    conf, cle = tmp_path / "ai.toml", tmp_path / "distant.key"
    conf.write_text('[distant]\nurl = "https://ia.distante.test"\n', encoding="utf-8")
    cle.write_text(CLE + "\n", encoding="utf-8")
    monkeypatch.setenv("SECUBOX_AI_CONF", str(conf))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(cle))
    moteurs._cache_sonde.clear()
    vues = []
    comportement = {"sante": 200, "recherche": None}

    def h(req):
        vues.append((req.method, req.url.path, dict(req.url.params), req.headers.get("authorization")))
        if req.url.path == "/health":
            if comportement["sante"] == "tombe":
                raise httpx.ConnectError("injoignable", request=req)
            return httpx.Response(comportement["sante"], json={})
        if req.url.path == "/search":
            if comportement["recherche"] is not None:
                return httpx.Response(200, json=comportement["recherche"])
            return httpx.Response(200, json={"results": [
                {"title": "Michel Murty", "content": "chanteur", "url": "https://michelmurty.fr/"},
                {"title": "sans url"}]})
        return httpx.Response(404)
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", lambda nom: httpx.MockTransport(h))
    return vues, comportement


@pytest.mark.asyncio
async def test_searxng_requete_distante_avec_cle(distant):
    vues, _ = distant
    r = await recherche.outil_searxng("michel murty")
    assert r == [{"titre": "Michel Murty", "extrait": "chanteur", "url": "https://michelmurty.fr/"}]
    assert [v[1] for v in vues] == ["/health", "/search"]       # sonde R10 puis recherche
    assert vues[1] == ("GET", "/search", {"q": "michel murty", "format": "json", "language": "fr"}, f"Bearer {CLE}")


@pytest.mark.asyncio
async def test_searxng_distant_injoignable_saute_sans_attente(distant):
    vues, comportement = distant
    comportement["sante"] = "tombe"
    prefs = reglages.lire_prefs()
    prefs["outils"].update(secubox=False, wikipedia=False)
    evts = []

    class Suivi:
        async def put(self, e):
            evts.append(e)
    etat, bloc = await recherche.recherche_fiable("Michel Murty", prefs, [], Suivi())
    assert (etat, bloc) == ("indisponible", "")               # état du POC : un outil en panne
    assert [v[1] for v in vues] == ["/health"]                # jamais de /search
    assert any(e.get("moteur") == "searxng" and e.get("echec") == "injoignable" for e in evts)


@pytest.mark.asyncio
async def test_searxng_erreur_reseau_remonte(distant, monkeypatch):
    _, comportement = distant
    comportement["sante"] = 200
    import api.recherche as r

    def h(req):
        if req.url.path == "/health":
            return httpx.Response(200, json={})
        raise httpx.ConnectError("x", request=req)
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", lambda nom: httpx.MockTransport(h))
    with pytest.raises(httpx.ConnectError):
        await r.outil_searxng("x")


@pytest.mark.asyncio
async def test_idn_host_et_sni_en_ascii(web):
    web["dns"]["xn--lyse-9oad.fr"] = ["93.184.216.34"]
    assert "Michel Murty" in await recherche.telecharger("https://élysée.fr:443/")
    req = web["reqs"][0]
    assert req["host"] == "xn--lyse-9oad.fr:443" and req["sni"] == "xn--lyse-9oad.fr"
    assert req["url"] == "https://93.184.216.34/"
    assert web["appels_dns"] == ["xn--lyse-9oad.fr"]


# ---- Tâche 6b : SearXNG local de la box, gk0 en repli ----
LOCAL = "http://10.100.0.85:8888"


@pytest.fixture
def local(distant, tmp_path, monkeypatch):
    """SearXNG local configuré ; transport « searxng_local » enregistré à part du distant."""
    conf = tmp_path / "ai.toml"
    conf.write_text(f'[distant]\nurl = "https://ia.distante.test"\n[searxng]\nurl = "{LOCAL}"\n', encoding="utf-8")
    monkeypatch.setenv("SECUBOX_AI_CONF", str(conf))
    vues, etat = [], {"mode": "ok", "contenu": None}

    def h(req):
        vues.append((str(req.url.copy_with(query=None)), dict(req.url.params), req.headers.get("authorization")))
        if etat["mode"] == "tombe":
            raise httpx.ConnectError("injoignable", request=req)
        if etat["mode"] == "5xx":
            return httpx.Response(503)
        if etat["mode"] == "redir":
            return httpx.Response(302, headers={"location": "http://10.0.0.1/"})
        return httpx.Response(200, content=etat["contenu"] or json.dumps({"results": [
            {"title": "Local", "content": "c", "url": "https://l.fr/"}, {"title": "sans url"}]}).encode())
    monkeypatch.setattr(recherche, "FABRIQUE_TRANSPORT_WEB",
                        lambda nom: httpx.MockTransport(h) if nom == "searxng_local" else None)
    return vues, etat, distant


@pytest.mark.asyncio
async def test_local_repond_distant_non_sollicite(local):
    vues, _, (vues_distant, _) = local
    r = await recherche.outil_searxng("zia")
    assert r == [{"titre": "Local", "extrait": "c", "url": "https://l.fr/"}]
    assert vues == [(f"{LOCAL}/search", {"q": "zia", "format": "json", "language": "fr"}, None)]
    assert vues_distant == []                                  # ni sonde ni recherche vers gk0


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["tombe", "5xx", "redir"])
async def test_local_en_echec_repli_distant(local, mode):
    vues, etat, (vues_distant, _) = local
    etat["mode"] = mode
    r = await recherche.outil_searxng("zia")
    assert r[0]["titre"] == "Michel Murty"                      # réponse du distant
    assert [v[1] for v in vues_distant] == ["/health", "/search"] and len(vues) == 1


@pytest.mark.asyncio
async def test_local_json_invalide_ou_trop_gros_repli(local):
    vues, etat, (vues_distant, _) = local
    etat["contenu"] = b"pas du json"
    assert (await recherche.outil_searxng("zia"))[0]["titre"] == "Michel Murty"
    etat["contenu"] = b" " * (recherche.TAILLE_PAGE_MAX + 10)
    moteurs._cache_sonde.clear()
    assert (await recherche.outil_searxng("zia"))[0]["titre"] == "Michel Murty"


@pytest.mark.asyncio
async def test_local_et_distant_indisponibles_panne(local):
    _, etat, (_, comportement) = local
    etat["mode"], comportement["sante"] = "tombe", "tombe"
    prefs = reglages.lire_prefs()
    prefs["outils"].update(secubox=False, wikipedia=False)
    assert await recherche.recherche_fiable("Michel Murty", prefs, [], None) == ("indisponible", "")


@pytest.mark.asyncio
async def test_local_seul_sans_distant(local, tmp_path, monkeypatch):
    vues, etat, _ = local
    (tmp_path / "distant.key").unlink()                          # distant non configuré
    assert (await recherche.outil_searxng("zia"))[0]["titre"] == "Local"
    etat["mode"] = "tombe"
    with pytest.raises(httpx.HTTPError):
        await recherche.outil_searxng("zia")


@pytest.mark.asyncio
async def test_url_locale_vide_comportement_inchange(distant):
    vues, _ = distant
    assert reglages.config()["searxng"]["url"] == ""
    assert (await recherche.outil_searxng("zia"))[0]["titre"] == "Michel Murty"
    assert [v[1] for v in vues] == ["/health", "/search"]


@pytest.mark.parametrize("url", ["ftp://10.100.0.85/", "http://user@10.100.0.85:8888", "http://u:p@h/", "10.100.0.85:8888",
                                 "file:///x", "http://", 42])
def test_config_refuse_url_locale_invalide(tmp_path, monkeypatch, url):
    conf = tmp_path / "ai.toml"
    conf.write_text(f"[searxng]\nurl = {json.dumps(url)}\n", encoding="utf-8")
    monkeypatch.setenv("SECUBOX_AI_CONF", str(conf))
    assert reglages.config()["searxng"]["url"] == ""


def test_config_accepte_url_locale(tmp_path, monkeypatch):
    conf = tmp_path / "ai.toml"
    conf.write_text(f'[searxng]\nurl = "{LOCAL}"\n', encoding="utf-8")
    monkeypatch.setenv("SECUBOX_AI_CONF", str(conf))
    assert reglages.config()["searxng"]["url"] == LOCAL


@pytest.mark.asyncio
async def test_client_local_sans_env_ni_redirection_ni_journal(local, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    clients = []
    vrai = httpx.AsyncClient

    class Espion(vrai):
        def __init__(self, *a, **kw):
            clients.append(kw)
            super().__init__(*a, **kw)
    monkeypatch.setattr(recherche.httpx, "AsyncClient", Espion)
    await recherche.outil_searxng("secret-question")
    assert clients[0]["trust_env"] is False and clients[0]["follow_redirects"] is False
    assert "secret-question" not in caplog.text and "l.fr" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("corps", [{"results": {"a": 1}}, [], {"results": None}, {"x": 1}])
async def test_local_results_mal_forme_repli_distant(local, corps):
    _, etat, _ = local
    etat["contenu"] = json.dumps(corps).encode()
    assert (await recherche.outil_searxng("zia"))[0]["titre"] == "Michel Murty"


@pytest.mark.asyncio
@pytest.mark.parametrize("corps", [{"results": {"a": 1}}, ["x"], {"results": "texte"}])
async def test_distant_results_mal_forme_panne_sans_exception(distant, corps):
    _, comportement = distant
    comportement["recherche"] = corps
    prefs = reglages.lire_prefs()
    prefs["outils"].update(secubox=False, wikipedia=False)
    assert await recherche.recherche_fiable("Michel Murty", prefs, [], None) == ("indisponible", "")


@pytest.mark.asyncio
async def test_entrees_non_chaines_ignorees(distant):
    _, comportement = distant
    comportement["recherche"] = {"results": [
        {"title": "ok", "content": "c", "url": "https://a.fr/"},
        {"title": "x", "url": 42}, {"title": ["liste"], "url": "https://b.fr/"},
        {"title": "x", "content": 5, "url": "https://c.fr/"}, "chaine", {"url": ""}]}
    assert await recherche.outil_searxng("zia") == [{"titre": "ok", "extrait": "c", "url": "https://a.fr/"}]
