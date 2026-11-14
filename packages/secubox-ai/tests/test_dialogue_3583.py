# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dialogue en flux (Essai), Continuer, reprise (#3583). Moteur simulé : aucun réseau réel."""
import json
import logging
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import dialogue, memoire, moteurs, reglages, taches
from api.main import app

QUESTION = "Quelle est la hauteur du phare de Cordouan ?"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "ai.toml"))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(tmp_path / "cle"))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    moteurs._cache_sonde.clear()
    taches.TRAVAUX.clear()
    dialogue.SUITES.clear()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    app.dependency_overrides.pop(require_jwt, None)
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", None)
    taches.TRAVAUX.clear()
    dialogue.SUITES.clear()


def sse(*messages):
    corps = "".join("data: " + json.dumps(m) + "\n\n" for m in messages) + "data: [DONE]\n\n"
    return httpx.Response(200, content=corps.encode(), headers={"content-type": "text/event-stream"})


def reponse_simple(*bouts, fin="stop", total=40):
    msgs = [{"prompt_progress": {"processed": 12, "total": 30, "cache": 0, "time_ms": 4}}]
    msgs += [{"choices": [{"delta": {"content": b}}]} for b in bouts]
    msgs.append({"choices": [{"delta": {}, "finish_reason": fin}],
                 "usage": {"prompt_tokens": 30, "completion_tokens": total - 30, "total_tokens": total},
                 "timings": {"predicted_per_second": 12.34}})
    return sse(*msgs)


def moteur_simule(monkeypatch, chat, n_ctx=4096, vus=None, local_seul=True):
    """Moteur local simulé : /health, /props, /tokenize, /v1/chat/completions (délégué à `chat`)."""
    vus = vus if vus is not None else []

    def fabrique(nom):
        def h(req):
            vus.append((nom, req.url.path, json.loads(req.content) if req.content else None))
            if req.url.path == "/health":
                return httpx.Response(200)
            if req.url.path == "/props":
                return httpx.Response(200, json={"default_generation_settings": {"n_ctx": n_ctx}})
            if req.url.path == "/tokenize":
                return httpx.Response(200, json={"tokens": [1] * 10})
            if req.url.path == "/v1/chat/completions":
                return chat(req)
            return httpx.Response(404)
        return httpx.MockTransport(h)

    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", fabrique)
    return vus


async def essai(corps):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/essai/flux", json=corps)
        if r.status_code != 200:
            return r.status_code, r.json()
        assert r.headers["content-type"].startswith("application/x-ndjson")
        return 200, [json.loads(ligne) for ligne in r.text.splitlines() if ligne]


def etapes(evts):
    return [e["etape"] for e in evts]


def sans_recherche():
    reglages.ecrire_prefs(reglages.valider({"outils": {"secubox": False, "searxng": False, "wikipedia": False}}))


def recherche_ok(monkeypatch, bloc='<donnees>[{"url": "https://exemple.fr/phare", "page": "67 mètres en 1611"}]</donnees>'):
    async def fausse(question, prefs, sources, suivi=None):
        await suivi.put({"etape": "requete", "mots": ["phare"]})
        sources.append({"titre": "Phare", "extrait": "x", "url": "https://exemple.fr/phare", "nature": "officiel", "lue": True})
        return "ok", bloc
    monkeypatch.setattr(dialogue, "recherche_fiable", fausse)


@pytest.mark.asyncio
async def test_ordre_des_evenements(env, monkeypatch):
    sans_recherche()
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("Il mesure ", "67 m."))
    code, evts = await essai({"question": QUESTION, "lucidite": 85})
    assert code == 200
    e = etapes(evts)
    assert e[:3] == ["travail", "lucidite", "memoire"]
    assert e.index("generation") < e.index("lecture") < e.index("texte") < e.index("bilan")
    assert e[-1] == "bilan" and "erreur" not in e and "recherche" not in e
    assert all("t" in x for x in evts)
    ident = evts[0]["id"]
    assert taches.TRAVAUX[ident]["fini"] is True and taches.TRAVAUX[ident]["texte"] == "Il mesure 67 m."
    bilan = evts[-1]
    assert bilan["modele_appele"] is True and bilan["fin"] == "stop" and bilan["suite"] is None
    assert bilan["tokens_total"] == 40 and bilan["contexte"] == 4096 and bilan["vitesse"] == 12.3
    gen = next(x for x in evts if x["etape"] == "generation")
    assert gen["contexte"] == 4096 and gen["max_tokens"] == 512
    charge = next(c for _, p, c in vus if p == "/v1/chat/completions")
    assert charge["return_progress"] is True and charge["stream"] is True
    assert charge["chat_template_kwargs"] == taches.SANS_RAISONNEMENT
    assert [m["role"] for m in charge["messages"]] == ["system", "user"]
    assert charge["temperature"] == 0.27 and charge["top_p"] == 0.83
    assert taches.COMPTEURS["en_cours"] == 0


@pytest.mark.asyncio
async def test_recherche_ok_controle_et_consigne(env, monkeypatch):
    recherche_ok(monkeypatch)
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("67 m selon https://exemple.fr/phare et https://faux.com/x"))
    code, evts = await essai({"question": QUESTION})
    e = etapes(evts)
    assert e.index("memoire") < e.index("recherche") < e.index("requete") < e.index("sources") < e.index("generation")
    assert e.index("texte") < e.index("controle") < e.index("bilan")
    ctl = next(x for x in evts if x["etape"] == "controle")
    assert ctl["adresses_retirees"] == 1 and "https://exemple.fr/phare" in ctl["texte"] and "faux.com" not in ctl["texte"]
    charge = next(c for _, p, c in vus if p == "/v1/chat/completions")
    assert "Réponds UNIQUEMENT" in charge["messages"][0]["content"]


@pytest.mark.parametrize("outils", [{"mode": "jamais"}, {"secubox": False, "searxng": False, "wikipedia": False}])
@pytest.mark.asyncio
async def test_porte_de_la_recherche(env, monkeypatch, outils):
    appels = []

    async def espion(*a, **k):
        appels.append(a)
        return "ok", ""
    monkeypatch.setattr(dialogue, "recherche_fiable", espion)
    reglages.ecrire_prefs(reglages.valider({"outils": outils}))
    moteur_simule(monkeypatch, lambda req: reponse_simple("ok"))
    code, evts = await essai({"question": QUESTION})
    assert code == 200 and appels == [] and "recherche" not in etapes(evts)


@pytest.mark.asyncio
async def test_un_seul_outil_suffit_pour_chercher(env, monkeypatch):
    reglages.ecrire_prefs(reglages.valider({"outils": {"secubox": False, "searxng": False, "wikipedia": True}}))
    recherche_ok(monkeypatch)
    moteur_simule(monkeypatch, lambda req: reponse_simple("ok"))
    code, evts = await essai({"question": QUESTION})
    assert "recherche" in etapes(evts)


@pytest.mark.asyncio
async def test_sans_source_le_modele_n_est_pas_appele(env, monkeypatch):
    async def vide(question, prefs, sources, suivi=None):
        return "vide", ""
    monkeypatch.setattr(dialogue, "recherche_fiable", vide)
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("inventé"))
    code, evts = await essai({"question": QUESTION, "lucidite": 85})
    assert evts[-1]["etape"] == "bilan" and evts[-1]["modele_appele"] is False and evts[-1]["recherche"] == "vide"
    assert any(x.get("morceau") == "Je n'ai trouvé aucune source qui parle de ce sujet : je ne sais pas." for x in evts)
    assert not [p for _, p, _ in vus if p == "/v1/chat/completions"]


@pytest.mark.asyncio
async def test_coupe_a_la_longueur_puis_continuer(env, monkeypatch):
    recherche_ok(monkeypatch)
    premier = "Le phare mesure 67 m (https://exemple.fr/phare), voir https://faux.com/x et"
    moteur_simule(monkeypatch, lambda req: reponse_simple(premier, fin="length", total=600))
    _, evts = await essai({"question": QUESTION})
    suite = evts[-1]["suite"]
    assert evts[-1]["fin"] == "length" and suite
    assert dialogue.SUITES[suite]["reponse"] == premier

    vus = moteur_simule(monkeypatch, lambda req: reponse_simple(" il date de 1611."))
    _, evts2 = await essai({"suite": suite})
    e = etapes(evts2)
    assert "memoire" not in e and "recherche" not in e
    assert e.index("suite") < e.index("generation")
    assert next(x for x in evts2 if x["etape"] == "suite")["caracteres"] == len(premier)
    charge = next(c for _, p, c in vus if p == "/v1/chat/completions")
    assert charge["messages"][-2] == {"role": "assistant", "content": premier}
    assert charge["messages"][-1] == {"role": "user", "content": dialogue.CONSIGNE_SUITE}
    assert "Réponds UNIQUEMENT" in charge["messages"][0]["content"]       # contexte gardé : consigne et sources
    ctl = next(x for x in evts2 if x["etape"] == "controle")
    assert ctl["texte"].startswith("Le phare mesure 67 m (https://exemple.fr/phare)")
    assert ctl["texte"].endswith(" il date de 1611.") and ctl["adresses_retirees"] == 1
    assert evts2[-1]["suite"] is None and suite not in dialogue.SUITES
    assert taches.TRAVAUX[evts2[0]["id"]]["question"].startswith("▶ suite : ")


@pytest.mark.asyncio
async def test_pas_de_suite_si_le_contexte_est_plein(env, monkeypatch):
    sans_recherche()
    moteur_simule(monkeypatch, lambda req: reponse_simple("x", fin="length", total=4090))
    _, evts = await essai({"question": QUESTION})
    assert evts[-1]["suite"] is None


@pytest.mark.asyncio
async def test_suite_expiree_ou_inconnue(env, monkeypatch):
    dialogue.SUITES["vieille"] = {"quand": time.time() - dialogue.SUITE_TTL - 1}
    assert (await essai({"suite": "vieille"}))[0] == 404
    assert "vieille" not in dialogue.SUITES
    code, corps = await essai({"suite": "inconnue"})
    assert code == 404 and "suite expirée" in corps["detail"]


def test_suite_demandee_sans_suite():
    assert dialogue.suite_demandee({"question": "x"}) == (None, "")


@pytest.mark.asyncio
async def test_moteur_coupe_en_plein_flux(env, monkeypatch):
    sans_recherche()

    async def coupe():
        yield b'data: {"choices": [{"delta": {"content": "Il mesure"}}]}\n\n'
        yield b'data: {"choices": [{"delta": {"content": " 67"}}]}\n\n'
        raise httpx.ReadError("connexion coupée")

    moteur_simule(monkeypatch, lambda req: httpx.Response(200, content=coupe(), headers={"content-type": "text/event-stream"}))
    code, evts = await essai({"question": QUESTION})
    assert code == 200
    e = etapes(evts)
    assert e[-1] == "erreur" and "bilan" not in e
    assert "moteur injoignable" in evts[-1]["message"]
    tr = taches.TRAVAUX[evts[0]["id"]]
    assert tr["fini"] is True and tr["fin"] and tr["texte"] == "Il mesure 67"
    assert taches.COMPTEURS["en_cours"] == 0
    assert all(x["fini"] for x in taches.TRAVAUX.values())


@pytest.mark.asyncio
async def test_moteur_refuse_la_requete(env, monkeypatch):
    sans_recherche()
    moteur_simule(monkeypatch, lambda req: httpx.Response(500))
    _, evts = await essai({"question": QUESTION})
    assert evts[-1] == {**evts[-1], "etape": "erreur", "message": "le moteur a refusé la requête"}
    assert taches.TRAVAUX[evts[0]["id"]]["fini"] is True


@pytest.mark.asyncio
async def test_reponse_ajoutee_a_l_historique(env, monkeypatch):
    recherche_ok(monkeypatch)
    moteur_simule(monkeypatch, lambda req: reponse_simple("67 m, https://faux.com/x"))
    await essai({"question": QUESTION})
    h = memoire.historique_liste()["historique"]
    assert len(h) == 1 and h[0]["genre"] == "dialogue" and h[0]["titre"] == QUESTION
    lu = memoire.historique_lire(h[0]["id"])
    assert "faux.com" not in lu["texte"] and lu["sources"] == ["https://exemple.fr/phare"]


@pytest.mark.asyncio
async def test_memoire_donnee_au_modele(env, monkeypatch):
    sans_recherche()
    memoire.memoire_ajouter("note", "Cordouan", "Le phare de Cordouan mesure 67,5 mètres.")
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("67,5 m [mémoire : Cordouan]"))
    _, evts = await essai({"question": QUESTION})
    souv = next(x for x in evts if x["etape"] == "memoire")["souvenirs"]
    assert souv and souv[0]["titre"] == "Cordouan" and "texte" not in souv[0]
    charge = next(c for _, p, c in vus if p == "/v1/chat/completions")
    assert memoire.CONSIGNE_MEMOIRE in charge["messages"][0]["content"]


@pytest.mark.asyncio
async def test_proposition_memoire(env, monkeypatch):
    sans_recherche()
    moteur_simule(monkeypatch, lambda req: reponse_simple("Noté."))
    _, evts = await essai({"question": "Retiens que le code du portail est l'heure"})
    prop = next(x for x in evts if x["etape"] == "proposition_memoire")
    assert prop["texte"] == "le code du portail est l'heure"


@pytest.mark.asyncio
async def test_le_journal_ne_contient_pas_la_question(env, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    recherche_ok(monkeypatch)
    moteur_simule(monkeypatch, lambda req: reponse_simple("Réponse secrète zqx"))
    await essai({"question": QUESTION})
    async def coupe():
        yield 'data: {"choices": [{"delta": {"content": "Réponse secrète zqx"}}]}\n\n'.encode()
        raise httpx.ReadError("x")
    moteur_simule(monkeypatch, lambda req: httpx.Response(200, content=coupe()))
    await essai({"question": QUESTION})
    assert caplog.records
    assert QUESTION not in caplog.text and "Cordouan" not in caplog.text and "zqx" not in caplog.text


@pytest.mark.asyncio
async def test_question_requise_et_image_invalide(env):
    assert (await essai({"question": "  "}))[0] == 422
    assert (await essai({"question": "x", "image": "data:image/gif;base64,AAAA"}))[0] == 422
    assert (await essai({"image": "data:image/png;base64," + "A" * (6 * 1024 * 1024)}))[0] == 413


@pytest.mark.asyncio
async def test_image_reste_sur_la_box_en_auto(env, monkeypatch):
    (env / "ai.toml").write_text('[distant]\nurl = "http://gk0.lan:8090"\n', encoding="utf-8")
    (env / "cle").write_text("cle-de-test", encoding="utf-8")
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("Un chat."))
    _, evts = await essai({"image": "data:image/png;base64,iVBORw0KGgo="})
    e = etapes(evts)
    assert "image" in e and "recherche" not in e and e[-1] == "bilan"
    chats = [(nom, c) for nom, p, c in vus if p == "/v1/chat/completions"]
    assert [nom for nom, _ in chats] == ["local"]
    contenu = chats[0][1]["messages"][-1]["content"]
    assert contenu[0] == {"type": "text", "text": "Décris cette image."}
    assert contenu[1]["image_url"]["url"].startswith("data:image/png;base64,")
    assert not [p for nom, p, _ in vus if nom == "distant" and p in ("/v1/chat/completions", "/props", "/tokenize")]


@pytest.mark.asyncio
async def test_reglages_par_question(env, monkeypatch):
    sans_recherche()
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("ok"))
    _, evts = await essai({"question": QUESTION, "reglages": {"temperature": 1.5, "max_tokens": 64,
                                                              "modele": "autre-modele.gguf"}})
    charge = next(c for _, p, c in vus if p == "/v1/chat/completions")
    assert charge["temperature"] == 1.5 and charge["max_tokens"] == 64
    prefs = reglages.lire_prefs()
    assert prefs["moteur"]["modele"] == "autre-modele.gguf"
    assert prefs["generation"]["max_tokens"] == 512          # réglage d'une question : jamais enregistré
    assert (env / "run" / "demandes" / "redemarrer.demande").exists()
    assert (await essai({"question": "x", "reglages": {"max_tokens": 1}}))[0] == 422
    assert (await essai({"question": "x", "reglages": {"modele": "../x.gguf"}}))[0] == 422


@pytest.mark.asyncio
async def test_delire_sans_recherche(env, monkeypatch):
    appels = []

    async def espion(*a, **k):
        appels.append(a)
        return "ok", ""
    monkeypatch.setattr(dialogue, "recherche_fiable", espion)
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple("(imaginé) ..."))
    _, evts = await essai({"question": QUESTION, "lucidite": 0})
    assert appels == [] and evts[1]["mode"] == "delire"
    charge = next(c for _, p, c in vus if p == "/v1/chat/completions")
    assert dialogue.CONSIGNE_DELIRE in charge["messages"][0]["content"]


def test_route_exige_jwt():
    assert TestClient(app).post("/essai/flux", json={"question": "x"}).status_code in (401, 403)


@pytest.mark.asyncio
async def test_suite_d_une_reponse_sur_image_reste_sur_la_box(env, monkeypatch):
    (env / "ai.toml").write_text('[distant]\nurl = "http://gk0.lan:8090"\n', encoding="utf-8")
    (env / "cle").write_text("cle-de-test", encoding="utf-8")
    moteur_simule(monkeypatch, lambda req: reponse_simple("Un chat", fin="length", total=100))
    _, evts = await essai({"image": "data:image/png;base64,iVBORw0KGgo="})
    vus = moteur_simule(monkeypatch, lambda req: reponse_simple(" roux."))
    _, evts2 = await essai({"suite": evts[-1]["suite"]})
    assert evts2[-1]["etape"] == "bilan"
    assert [nom for nom, p, _ in vus if p == "/v1/chat/completions"] == ["local"]
