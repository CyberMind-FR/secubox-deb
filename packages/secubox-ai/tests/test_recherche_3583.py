# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Recherche et lecture de pages (#3583, tâche 6) : garde SSRF, contrôle de réponse, budget. Aucun réseau réel."""
import logging

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
    etat = {"vues": [], "reponses": {}, "dns": {}}

    def handler(req):
        etat["vues"].append(str(req.url))
        return etat["reponses"].get(str(req.url), httpx.Response(200, html=HTML))

    async def resolveur(hote):
        return etat["dns"].get(hote, ["93.184.216.34"])

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
    web["dns"]["site.test"] = ["93.184.216.34"]
    texte = await recherche.lire_page("http://site.test/")
    assert "Michel Murty" in texte
    assert not any("10.0.0.1" in v for v in web["vues"])      # autre hôte : jamais suivi
    # un saut vers un hôte devenu privé est refusé par la garde, pas par le filtre d'hôte
    web["dns"]["site.test"] = ["10.0.0.9"]
    web["vues"].clear()
    assert await recherche.lire_page("http://site.test/") == ""
    assert web["vues"] == []


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
    fixe = next(e for e in evts if e["etape"] == "budget")["tokens_consigne"]
    assert len(bloc) // 4 <= fixe + 1000 + 50
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
