# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Documents (#3583, tâche 9) : dépôt, lien gardé contre le SSRF, extraction, analyse, mémoire. Aucun réseau réel."""
import asyncio
import json
import logging
import os

import httpx
import pytest

from secubox_core.auth import require_jwt

from api import documents, memoire, moteurs, recherche, taches
from api.main import app

PDF = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
       b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
       b"4 0 obj<</Length 70>>stream\nBT /F1 12 Tf 20 100 Td (Le phare de Cordouan mesure soixante-sept metres.) Tj ET\nendstream\nendobj\n"
       b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\ntrailer<</Root 1 0 R/Size 6>>\n%%EOF\n")
HTML = ("<html><head><title>Le phare</title></head><body><nav>menu</nav><article>"
        + "<p>Le phare de Cordouan est un phare en mer. Voir <a href=\"https://exemple.fr/a\">ici</a>.</p>" * 20
        + "</article></body></html>")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "ai.toml"))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(tmp_path / "cle"))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    monkeypatch.setattr(recherche, "SOURCE_IF_INET6", str(tmp_path / "if_inet6"))
    (tmp_path / "if_inet6").write_text("", encoding="ascii")
    documents.DOCS.clear()
    taches.TACHES.clear()
    moteurs._cache_sonde.clear()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    app.dependency_overrides.pop(require_jwt, None)
    documents.DOCS.clear()
    taches.TACHES.clear()


def temporaires(env):
    d = env / "etat" / "documents"
    return list(d.iterdir()) if d.exists() else []


@pytest.fixture
def web(env, monkeypatch):
    etat = {"reqs": [], "reponses": {}, "dns": {}}

    def handler(req):
        origine = f"{req.url.scheme}://{req.headers['host']}{req.url.raw_path.decode()}"
        etat["reqs"].append({"origine": origine, "url": str(req.url), "host": req.headers["host"],
                             "sni": req.extensions.get("sni_hostname")})
        return etat["reponses"].get(origine, httpx.Response(200, html=HTML))

    async def resolveur(hote):
        return etat["dns"].get(hote, ["93.184.216.34"])

    monkeypatch.setattr(recherche, "FABRIQUE_TRANSPORT_WEB", lambda nom: httpx.MockTransport(handler))
    monkeypatch.setattr(recherche, "RESOLVEUR", resolveur)
    return etat


async def appeler(methode, chemin, **kw):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(methode, chemin, **kw)


# ---- Calculs purs ----
def test_taille_morceau():
    assert documents.taille_morceau(4096) == 5990
    assert documents.taille_morceau(32768) == 74803     # le brief disait 74800 : la formule du POC donne 74803
    assert documents.taille_morceau(1000) == 4000
    assert documents.taille_morceau(200000) == 80000


def test_decouper_garde_les_reperes():
    m = documents.decouper([("p. 1", "a" * 50), ("p. 2", "b" * 50)], 80)
    assert len(m) == 2 and m[0].startswith("[p. 1]") and m[1].startswith("[p. 2]")


# ---- Dépôt de fichier ----
@pytest.mark.asyncio
async def test_pdf_sans_titre_prend_le_nom_du_fichier(env):
    r = await appeler("POST", "/documents/fichier", content=PDF,
                      headers={"content-type": "application/pdf", "x-nom": "rapport%20phare.pdf"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["genre"] == "PDF" and d["titre"] == "rapport phare.pdf" and d["pages"] == 1 and d["tronque"] is False
    assert "Cordouan" in documents.DOCS[d["id"]]["texte"][0][1]
    assert temporaires(env) == []


@pytest.mark.asyncio
async def test_pdftotext_lance_sans_shell_sur_le_seul_chemin(env, monkeypatch):
    lances = []
    vrai = asyncio.create_subprocess_exec

    async def espion(*args, **kw):
        lances.append(args)
        return await vrai(*args, **kw)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", espion)
    r = await appeler("POST", "/documents/fichier", content=PDF, headers={"x-nom": "a.pdf"})
    assert r.status_code == 200
    assert [a[0] for a in lances] == ["pdfinfo", "pdftotext"]
    dossier = str(env / "etat" / "documents") + "/"
    pdftotext = lances[1]
    assert pdftotext[1:3] == ("-enc", "UTF-8") and pdftotext[3].startswith(dossier) and pdftotext[4] == "-"
    assert lances[0][1].startswith(dossier) and len(lances[0]) == 2
    assert all(isinstance(x, str) for a in lances for x in a)


@pytest.mark.asyncio
async def test_pdf_trop_long_est_tue_apres_le_delai(env, monkeypatch):
    monkeypatch.setattr(documents, "DELAI_PDFTOTEXT_S", 0.2)
    monkeypatch.setattr(documents, "DELAI_PDFINFO_S", 0.2)

    vrai = asyncio.create_subprocess_exec
    pids = []

    async def lent(*args, **kw):
        p = await vrai("sleep", "30", **kw)
        pids.append(p.pid)
        return p

    monkeypatch.setattr(asyncio, "create_subprocess_exec", lent)
    r = await appeler("POST", "/documents/fichier", content=PDF, headers={"x-nom": "a.pdf"})
    assert r.status_code == 422 and pids
    assert all(not os.path.exists(f"/proc/{p}") for p in pids)      # tué et récolté : aucun orphelin
    assert temporaires(env) == []


@pytest.mark.asyncio
async def test_html_texte_de_l_article_et_liens(env):
    r = await appeler("POST", "/documents/fichier", content=HTML.encode(),
                      headers={"content-type": "text/html; charset=utf-8", "x-nom": "p.html"})
    d = r.json()
    assert d["genre"] == "HTML" and d["titre"] == "Le phare" and d["liens"] == 1
    texte = " ".join(t for _, t in documents.DOCS[d["id"]]["texte"])
    assert "phare en mer" in texte and "menu" not in texte


@pytest.mark.asyncio
async def test_texte_brut_et_format_refuse(env):
    r = await appeler("POST", "/documents/fichier", content=("Bonjour le monde. " * 10).encode(),
                      headers={"content-type": "text/plain", "x-nom": "n.txt"})
    assert r.status_code == 200 and r.json()["genre"] == "texte" and r.json()["titre"] == "n.txt"
    r = await appeler("POST", "/documents/fichier", content=b"\x00\x01binaire",
                      headers={"content-type": "application/zip", "x-nom": "z"})
    assert r.status_code == 415 and temporaires(env) == []


@pytest.mark.asyncio
async def test_fichier_vide_et_sans_texte(env):
    assert (await appeler("POST", "/documents/fichier", content=b"")).status_code == 422
    r = await appeler("POST", "/documents/fichier", content=b"<html><body>x</body></html>",
                      headers={"content-type": "text/html"})
    assert r.status_code == 422 and temporaires(env) == []


@pytest.mark.asyncio
async def test_depot_trop_gros_413_et_fichier_efface(env, monkeypatch):
    monkeypatch.setattr(documents, "DOC_MAX", 1000)
    r = await appeler("POST", "/documents/fichier", content=b"x" * 5000, headers={"x-nom": "gros"})
    assert r.status_code == 413
    assert temporaires(env) == []


@pytest.mark.asyncio
async def test_texte_plafonne_a_3_millions(env):
    gros = ("mot " * 800_000).encode()          # 3,2 M caractères
    r = await appeler("POST", "/documents/fichier", content=gros, headers={"content-type": "text/plain", "x-nom": "g"})
    d = r.json()
    assert d["tronque"] is True
    assert sum(len(t) for _, t in documents.DOCS[d["id"]]["texte"]) == documents.TEXTE_MAX


@pytest.mark.asyncio
async def test_dossier_temporaire_0700(env):
    documents.dossier_temporaire()
    assert ((env / "etat" / "documents").stat().st_mode & 0o777) == 0o700


# ---- Lien : garde SSRF réutilisée ----
@pytest.mark.asyncio
async def test_lien_lu_avec_host_et_sni_epingles(env, web):
    r = await appeler("POST", "/documents", json={"url": "https://élysée.fr/page"})
    assert r.status_code == 200, r.text
    q = web["reqs"][0]
    idna = "élysée.fr".encode("idna").decode()
    assert idna.startswith("xn--") and q["host"] == idna and q["sni"] == idna
    assert q["url"].startswith("https://93.184.216.34/")
    assert temporaires(env) == []


@pytest.mark.asyncio
async def test_lien_redirige_vers_une_adresse_privee_refuse(env, web):
    web["reponses"]["http://exemple.test/a"] = httpx.Response(302, headers={"location": "http://interne.test/secret"})
    web["dns"]["interne.test"] = ["10.0.0.5"]
    r = await appeler("POST", "/documents", json={"url": "http://exemple.test/a"})
    assert r.status_code == 422
    assert [q["origine"] for q in web["reqs"]] == ["http://exemple.test/a"]      # jamais de requête vers la cible privée
    assert temporaires(env) == []


@pytest.mark.asyncio
async def test_lien_redirige_vers_une_adresse_litterale_privee(env, web):
    web["reponses"]["http://exemple.test/a"] = httpx.Response(301, headers={"location": "http://127.0.0.1/x"})
    r = await appeler("POST", "/documents", json={"url": "http://exemple.test/a"})
    assert r.status_code == 422 and len(web["reqs"]) == 1


@pytest.mark.asyncio
async def test_redirection_relative_suivie_puis_trop_de_sauts(env, web):
    web["reponses"]["http://exemple.test/a"] = httpx.Response(302, headers={"location": "/b"})
    r = await appeler("POST", "/documents", json={"url": "http://exemple.test/a"})
    assert r.status_code == 200 and [q["origine"] for q in web["reqs"]] == ["http://exemple.test/a", "http://exemple.test/b"]
    web["reqs"].clear()
    web["reponses"]["http://boucle.test/"] = httpx.Response(302, headers={"location": "/"})
    r = await appeler("POST", "/documents", json={"url": "http://boucle.test/"})
    assert r.status_code == 502 and len(web["reqs"]) == recherche.SAUTS_MAX


@pytest.mark.asyncio
async def test_lien_au_dela_du_plafond_coupe_et_fichier_efface(env, web, monkeypatch):
    monkeypatch.setattr(documents, "LIEN_MAX", 1000)
    web["reponses"]["https://exemple.test/gros"] = httpx.Response(200, content=b"x" * 5000, headers={"content-type": "text/plain"})
    r = await appeler("POST", "/documents", json={"url": "https://exemple.test/gros"})
    assert r.status_code == 413 and temporaires(env) == []


@pytest.mark.asyncio
async def test_lien_refus_de_forme_et_page_en_erreur(env, web):
    for url in ("ftp://exemple.test/x", "http://exemple.test:8080/", "http://u:p@exemple.test/", "http://10.0.0.1/"):
        assert (await appeler("POST", "/documents", json={"url": url})).status_code == 422
    assert web["reqs"] == []
    web["reponses"]["http://exemple.test/404"] = httpx.Response(404)
    assert (await appeler("POST", "/documents", json={"url": "http://exemple.test/404"})).status_code == 502
    assert (await appeler("POST", "/documents", json={})).status_code == 422
    assert temporaires(env) == []


# ---- Mémoire ----
@pytest.mark.asyncio
async def test_garder_le_document_en_memoire(env):
    r = await appeler("POST", "/documents/fichier", content=PDF, headers={"x-nom": "phare.pdf"})
    ident = r.json()["id"]
    m = await appeler("POST", f"/memoire/documents/{ident}")
    assert m.status_code == 200
    s = (await appeler("GET", f"/memoire/{m.json()['id']}")).json()
    assert s["genre"] == "document" and s["titre"] == "phare.pdf"
    trouves = memoire.memoire_chercher("Cordouan")
    assert trouves and trouves[0]["id"] == m.json()["id"]
    assert (await appeler("POST", "/memoire/documents/inconnu")).status_code == 404


# ---- Analyse ----
def moteur_simule(monkeypatch, reponses, n_ctx=4096):
    vus = []

    def fabrique(nom):
        def h(req):
            if req.url.path == "/health":
                return httpx.Response(200)
            if req.url.path == "/props":
                return httpx.Response(200, json={"default_generation_settings": {"n_ctx": n_ctx}})
            if req.url.path == "/v1/chat/completions":
                corps = json.loads(req.content)
                vus.append(corps)
                texte = reponses(corps) if callable(reponses) else reponses
                flux = "data: " + json.dumps({"choices": [{"delta": {"content": texte}}]}) + "\n\ndata: [DONE]\n\n"
                return httpx.Response(200, content=flux.encode(), headers={"content-type": "text/event-stream"})
            return httpx.Response(404)
        return httpx.MockTransport(h)

    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", fabrique)
    return vus


async def attendre(t):
    for _ in range(200):
        if taches.TACHES[t]["etat"] != "en_cours":
            return taches.TACHES[t]
        await asyncio.sleep(0.02)
    raise AssertionError("tâche non terminée")


async def deposer(texte, nom="n.txt"):
    r = await appeler("POST", "/documents/fichier", content=texte.encode(), headers={"content-type": "text/plain", "x-nom": nom})
    return r.json()["id"]


@pytest.mark.asyncio
async def test_analyse_liens_sans_moteur(env):
    ident = (await appeler("POST", "/documents/fichier", content=HTML.encode(), headers={"content-type": "text/html"})).json()["id"]
    r = await appeler("POST", f"/documents/{ident}/analyser", json={"action": "liens"})
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini" and "https://exemple.fr/a" in t["resultat"]


@pytest.mark.asyncio
async def test_analyse_resume_un_morceau(env, monkeypatch):
    vus = moteur_simule(monkeypatch, "Un phare en mer. [§1]")
    ident = await deposer("Le phare de Cordouan mesure soixante-sept mètres de haut. " * 3)
    r = await appeler("POST", f"/documents/{ident}/analyser", json={"action": "resume"})
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini" and t["resultat"] == "Un phare en mer. [§1]"
    assert len(vus) == 1 and "<donnees>[§1]" in vus[0]["messages"][-1]["content"]
    assert t["titre"].startswith("Résumé — n.txt")


@pytest.mark.asyncio
async def test_analyse_long_document_repartit_et_assemble(env, monkeypatch):
    vus = moteur_simule(monkeypatch, "résumé partiel")
    ident = await deposer(("Cordouan " * 600 + " ") * 40)               # bien plus de 10 morceaux de 5990
    r = await appeler("POST", f"/documents/{ident}/analyser", json={"action": "resume"})
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini" and "Document long" in t["resultat"]
    assert len(vus) == documents.MORCEAUX_MAX + 1


@pytest.mark.asyncio
async def test_analyse_question_sans_passage(env, monkeypatch):
    vus = moteur_simule(monkeypatch, "x")
    ident = await deposer("Le phare de Cordouan mesure soixante-sept mètres de haut. " * 3)
    r = await appeler("POST", f"/documents/{ident}/analyser", json={"action": "question", "question": "licornes volantes"})
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini" and "aucun passage" in t["resultat"] and vus == []
    r = await appeler("POST", f"/documents/{ident}/analyser", json={"action": "question", "question": "Cordouan hauteur"})
    t = await attendre(r.json()["tache"])
    assert t["resultat"] == "x" and len(vus) == 1


@pytest.mark.asyncio
async def test_analyse_refus_de_forme(env):
    assert (await appeler("POST", "/documents/inconnu/analyser", json={"action": "resume"})).status_code == 404
    ident = await deposer("Un texte assez long pour être gardé comme document de test ici.")
    assert (await appeler("POST", f"/documents/{ident}/analyser", json={"action": "danser"})).status_code == 422
    assert (await appeler("POST", f"/documents/{ident}/analyser", json={"action": "question"})).status_code == 422


@pytest.mark.asyncio
async def test_toutes_les_routes_exigent_le_jeton(env):
    app.dependency_overrides.pop(require_jwt, None)
    for methode, chemin in (("POST", "/documents"), ("POST", "/documents/fichier"), ("POST", "/documents/x/analyser"),
                            ("POST", "/memoire/documents/x")):
        assert (await appeler(methode, chemin, json={})).status_code in (401, 403)


@pytest.mark.asyncio
async def test_le_journal_ne_contient_ni_titre_ni_adresse(env, web, caplog):
    caplog.set_level(logging.DEBUG)
    await appeler("POST", "/documents", json={"url": "https://secret-adresse.test/titre-prive"})
    await appeler("POST", "/documents/fichier", content=("texte confidentiel " * 10).encode(),
                  headers={"content-type": "text/plain", "x-nom": "nom-prive.txt"})
    journal = caplog.text
    for interdit in ("secret-adresse", "titre-prive", "nom-prive", "confidentiel"):
        assert interdit not in journal
    assert "document genre=" in journal


MAUVAISES = ["http://-a.é.com/", "http://xn--é.com/", "http://☃\x00.com/"]


@pytest.mark.asyncio
@pytest.mark.parametrize("url", MAUVAISES)
async def test_adresse_illisible_refusee_sans_fuite(env, web, caplog, url):
    caplog.set_level(logging.DEBUG)
    assert await recherche.telecharger(url) == ""
    r = await appeler("POST", "/documents", json={"url": url})
    assert r.status_code == 422 and web["reqs"] == []
    assert "com" not in caplog.text and temporaires(env) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("url", MAUVAISES)
async def test_redirection_vers_adresse_illisible(env, web, caplog, url):
    caplog.set_level(logging.DEBUG)
    web["reponses"]["http://exemple.test/a"] = httpx.Response(302, headers={"location": url.encode()})
    r = await appeler("POST", "/documents", json={"url": "http://exemple.test/a"})
    assert r.status_code == 422 and len(web["reqs"]) == 1
    assert "xn--" not in caplog.text and ".com" not in caplog.text and temporaires(env) == []


@pytest.mark.asyncio
async def test_dossier_existant_trop_ouvert_est_resserre(env):
    d = env / "etat" / "documents"
    d.mkdir(parents=True)
    d.chmod(0o755)
    documents.dossier_temporaire()
    assert (d.stat().st_mode & 0o777) == 0o700
