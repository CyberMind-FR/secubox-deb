# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Menaces (#3583, tâche 10) : gk2 en lecture seule, contrôles anti-invention, double tampon. Aucun réseau réel.

Les cas viennent des essais du 2026-11-13 sur gk2 (inventions réelles du modèle) et de l'arbitrage R12 du
2026-11-14 (« surveiller » retiré, bannir = adresse vue en alerte et pas déjà bannie).
"""
import asyncio
import datetime as dt
import json
import logging
import time

import httpx
import pytest

from secubox_core.auth import require_jwt

from api import menaces, moteurs, reglages, taches
from api.main import app

SIG_AUTH = "a1b2c3d4e5f60718293a4b5c"      # tronquée à 16 dans le relevé : a1b2c3d4e5f60718
ALERTE_SEULE = "193.32.162.41"               # vue en alerte, jamais bannie
BANNIE = "45.135.232.10"                     # vue en alerte ET déjà bannie
BOX = "82.67.100.75"                         # adresse publique de gk2, vue comme vhost


def donnees_gk2():
    maintenant = dt.datetime.now().isoformat(timespec="seconds")
    bans = [{"ip": f"{151 + i // 250}.{i % 250}.7.9", "reason": "waf:scan", "origin": "sbxwaf", "country": "NL"}
            for i in range(866)]
    bans += [{"ip": f"45.135.232.{10 + i}", "reason": "waf:scan", "origin": "sbxwaf", "country": "NL"} for i in range(5)]
    bans += [{"ip": f"160.{i}.3.4", "reason": "authwatch:bruteforce", "origin": "authwatch", "country": "NL"}
             for i in range(77)]
    # 948 bans actifs : 871 waf:scan (91,9 %), 77 authwatch (8,1 %) ; un seul bloc /24 a au moins 3 adresses.
    return {
        "/waf/stats": {"threats_today": 1234, "observed_today": 5678,
                       "by_category": {"waf:scan": 800, "waf:sqli": 300, "authwatch:bruteforce": 134},
                       "by_severity": {"high": 100, "medium": 500},
                       "top_countries": [{"country": "US", "count": 400}, {"country": "DE", "count": 200}],
                       "top_vhosts": [{"vhost": "cloud.gk2.secubox.in", "count": 321}, {"vhost": BOX, "count": 55}]},
        "/waf/bans": {"bans": bans},
        "/waf/campaigns": {"attaquants": 12, "campagnes": [
            {"signature": SIG_AUTH, "outil": "authwatch", "attaquants": ["160.1.3.4", "160.2.3.4", "160.3.3.4"]},
            {"signature": "0f9e8d7c6b5a493827161514", "outil": "sbxwaf-scan", "attaquants": ["151.0.7.9"]},
            {"signature": "1234abcd5678ef90aabbccdd", "outil": "sbxwaf-scan", "attaquants": ["151.1.7.9"]}]},
        "/waf/alerts": {"alerts": [
            {"timestamp": maintenant, "client_ip": ALERTE_SEULE, "host": "cloud.gk2.secubox.in", "path": "/.env",
             "category": "waf:scan", "severity": "high", "action": "block", "tool": "zgrab", "country": "US"},
            {"timestamp": maintenant, "client_ip": BANNIE, "host": "cloud.gk2.secubox.in", "path": "/.git/config",
             "category": "waf:scan", "severity": "high", "action": "block", "tool": "curl", "country": "DE"},
            {"timestamp": maintenant, "client_ip": BOX, "host": BOX, "path": "/",
             "category": "waf:scan", "severity": "medium", "action": "log", "tool": "", "country": "FR"}]},
        "/security-posture/overview": {"overall": {"name": "Bonne", "score": 78}},
    }


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "ai.toml"))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(tmp_path / "cle"))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    menaces._reinitialiser()
    taches.TACHES.clear()
    moteurs._cache_sonde.clear()
    historique = []
    monkeypatch.setattr(taches, "HISTORIQUE_AJOUTER", lambda *a: historique.append(a))
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    app.dependency_overrides.pop(require_jwt, None)
    menaces._reinitialiser()
    taches.TACHES.clear()


@pytest.fixture
def gk2(env, monkeypatch):
    etat = {"donnees": donnees_gk2(), "pannes": set(), "reqs": []}

    def handler(req):
        etat["reqs"].append((req.method, str(req.url)))
        chemin = req.url.path.removeprefix("/api/v1")
        if "tout" in etat["pannes"] or chemin in etat["pannes"]:
            raise httpx.ConnectError("refusé", request=req)
        if chemin not in etat["donnees"]:
            return httpx.Response(404)
        return httpx.Response(200, json=etat["donnees"][chemin])

    monkeypatch.setattr(menaces, "FABRIQUE_TRANSPORT_GK2", lambda: httpx.MockTransport(handler))
    return etat


def moteur_simule(monkeypatch, reponses, sante=200):
    vus = []

    def fabrique(nom):
        def h(req):
            if req.url.path == "/health":
                return httpx.Response(sante)
            if req.url.path == "/props":
                return httpx.Response(200, json={"default_generation_settings": {"n_ctx": 4096}})
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


async def appeler(methode, chemin, **kw):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(methode, chemin, **kw)


async def attendre(t):
    for _ in range(300):
        if taches.TACHES[t]["etat"] != "en_cours":
            return taches.TACHES[t]
        await asyncio.sleep(0.02)
    raise AssertionError("tâche non terminée")


# ---- Relevé ----
@pytest.mark.asyncio
async def test_releve_agrege_sans_ia(gk2):
    r = await menaces.releve_menaces()
    assert r["erreurs"] == []
    c = r["chiffres"]
    assert c["bans_actifs"] == 948 and c["menaces_jour"] == 1234 and c["campagnes"] == 3
    assert c["attaquants_campagnes"] == 12 and c["alertes_derniere_heure"] == "3+"
    assert r["parts_bans_pct"] == {"waf:scan": 91.9, "authwatch:bruteforce": 8.1}
    assert r["blocs"] == [{"bloc": "45.135.232.0/24", "adresses": 5}]
    assert r["campagnes"][0]["signature"] == SIG_AUTH[:16] and r["campagnes"][0]["attaquants"] == 3
    assert r["pays"] == ["US 400", "DE 200"] and r["bans_par_pays"] == {"NL": 948}
    assert r["posture"] == {"name": "Bonne", "score": 78}
    assert r["evolution_1h"]["disponible"] is False
    # lecture seule : uniquement des GET, sur les cinq chemins du POC
    assert {m for m, _ in gk2["reqs"]} == {"GET"}
    assert {u for _, u in gk2["reqs"]} == {"https://admin.gk2.secubox.in/api/v1" + p for p in donnees_gk2()}


@pytest.mark.asyncio
async def test_releve_en_cache_15_s(gk2):
    await menaces.releve_menaces()
    n = len(gk2["reqs"])
    await menaces.releve_menaces()
    assert len(gk2["reqs"]) == n
    await menaces.releve_menaces(force=True)
    assert len(gk2["reqs"]) == 2 * n


@pytest.mark.asyncio
async def test_releve_url_de_la_configuration(gk2, env):
    (env / "ai.toml").write_text('[gk2]\nmenaces_url = "https://gk2.lan/api/v1/"\n', encoding="utf-8")
    await menaces.releve_menaces()
    assert all(u.startswith("https://gk2.lan/api/v1/waf/") or u.startswith("https://gk2.lan/api/v1/security")
               for _, u in gk2["reqs"])


@pytest.mark.asyncio
async def test_client_gk2_sans_env_ni_redirection_delais_courts(gk2, monkeypatch):
    clients = []
    vrai = httpx.AsyncClient

    class Espion(vrai):
        def __init__(self, *a, **kw):
            clients.append(kw)
            super().__init__(*a, **kw)
    monkeypatch.setattr(menaces.httpx, "AsyncClient", Espion)
    r = await menaces.releve_menaces()
    assert r["erreurs"] == [] and len(clients) == 5
    for kw in clients:
        assert kw["trust_env"] is False and kw["follow_redirects"] is False
        assert kw["timeout"].connect <= 3 and kw["timeout"].read <= 10


@pytest.mark.asyncio
async def test_gk2_injoignable_releve_avec_erreurs_et_resume_refuse_sans_modele(gk2, monkeypatch, env):
    gk2["pannes"].add("tout")
    vus = moteur_simule(monkeypatch, "ne doit jamais servir")
    r = await appeler("GET", "/menaces/releve")
    assert r.status_code == 200 and len(r.json()["erreurs"]) == 5
    r = await appeler("POST", "/menaces/resumer")
    assert r.status_code == 503 and "gk2" in r.json()["detail"]
    r = await appeler("POST", "/menaces/demander", json={"question": "Que se passe-t-il ?"})
    assert r.status_code == 503
    assert vus == [] and taches.TACHES == {}
    assert not (env / "run" / "demandes").exists()


@pytest.mark.asyncio
async def test_reponse_gk2_mal_formee_comptee_en_erreur(gk2):
    gk2["donnees"]["/waf/bans"] = ["pas", "un", "objet"]
    r = await menaces.releve_menaces()
    assert r["erreurs"] == ["/waf/bans"] and r["chiffres"]["bans_actifs"] == 0
    assert menaces.motif_inutilisable(r)


@pytest.mark.asyncio
async def test_posture_seule_en_panne_ne_bloque_pas(gk2):
    gk2["pannes"].add("/security-posture/overview")
    r = await menaces.releve_menaces()
    assert r["erreurs"] == ["/security-posture/overview"] and r["posture"] == {}
    assert menaces.motif_inutilisable(r) is None
    gk2["pannes"].add("/waf/bans")
    r = await menaces.releve_menaces(force=True)
    assert "/waf/bans" in menaces.motif_inutilisable(r)


@pytest.mark.asyncio
async def test_routes_gardees_par_jwt(gk2):
    app.dependency_overrides.pop(require_jwt, None)
    for methode, chemin in (("GET", "/menaces/releve"), ("POST", "/menaces/resumer"), ("POST", "/menaces/demander")):
        assert (await appeler(methode, chemin, json={"question": "x"})).status_code in (401, 403)
    assert gk2["reqs"] == []


# ---- Contrôles mécaniques (sans modèle) ----
@pytest.mark.asyncio
async def test_controle_chiffres_tendance_pays(gk2):
    r = await menaces.releve_menaces()
    # Cas réels : « 950 bans » inventé ; « 92 % » pour 91,9 (arrondi) ; Chine absente ; « en hausse » non mesurée.
    t = menaces.controler_resume("Il y a 950 bans actifs, 92 % pour des scans, venus de Chine, en hausse.", r)
    note = t.split("⚠ Contrôle du relais — ", 1)[1]
    assert "chiffres absents du relevé : 950" in note and "92" not in note
    assert "tendance ou nouveauté affirmée sans mesure" in note
    assert "pays absents du relevé : CN" in note


@pytest.mark.asyncio
async def test_controle_texte_exact_sans_note(gk2):
    r = await menaces.releve_menaces()
    t = "948 bans actifs, 91,9 % pour des scans ; alertes venues des US. Bloc 45.135.232.0/24 et `cloud`."
    assert menaces.controler_resume(t, r) == t


@pytest.mark.asyncio
async def test_controle_tendance_permise_si_mesuree(gk2):
    r = await menaces.releve_menaces()
    r = {**r, "evolution_1h": {"disponible": True, "minutes": 60, "nouvelles_menaces": 3, "ecart_bans_actifs": 1,
                               "par_categorie": {}}}
    assert "tendance" not in menaces.controler_resume("Les scans sont en hausse.", r)


# ---- Propositions : catalogue fermé, cibles du relevé ----
PROPOSITIONS = "\n".join([
    "Lecture courte.",
    "Proposition : bannir le bloc 45.135.232.0/24 pour 7 jours",
    "Proposition : bannir le bloc 10.20.30.0/24",                       # bloc absent du relevé
    f"Proposition : bannir l'adresse {ALERTE_SEULE}",                    # vue en alerte, pas bannie : gardée
    f"Proposition : bannir l'adresse {BANNIE}",                          # déjà bannie : inutile
    f"Proposition : bannir l'adresse {BOX}",                             # la box elle-même
    f"Proposition : surveiller l'adresse {ALERTE_SEULE}",                # geste inexistant (R12)
    "- **Proposition** : examiner la campagne authwatch",               # outil unique : sa signature
    "Proposition : examiner la campagne sbxwaf-scan",                   # outil ambigu (deux campagnes)
    "Proposition : examiner la campagne a1b2c3d4",                       # préfixe d'une signature connue
    "Proposition : vérifier le service cloud.gk2.secubox.in",
    "Proposition : redémarrer le pare-feu",                              # hors catalogue
])


@pytest.mark.asyncio
async def test_filtrer_propositions(gk2):
    r = await menaces.releve_menaces()
    texte, gardees, retirees = menaces.filtrer_propositions(PROPOSITIONS, r)
    assert texte == "Lecture courte."
    sig = SIG_AUTH[:16]
    assert [p["texte"] for p in gardees] == [
        "Bannir le bloc 45.135.232.0/24 pour 7 jours",
        f"Bannir l'adresse {ALERTE_SEULE}",
        f"Examiner la campagne {sig} (authwatch)",
        "Examiner la campagne a1b2c3d4",
        "Vérifier le service cloud.gk2.secubox.in",
    ]
    assert gardees[0]["lien"] == "https://admin.gk2.secubox.in/waf/attaquants.html"
    assert gardees[2] == {"genre": "campagne", "cible": sig, "texte": f"Examiner la campagne {sig} (authwatch)",
                          "lien": "https://admin.gk2.secubox.in/waf/campagnes.html"}
    assert retirees == ["bannir le bloc 10.20.30.0/24", f"bannir l'adresse {BANNIE}", f"bannir l'adresse {BOX}",
                        f"surveiller l'adresse {ALERTE_SEULE}", "examiner la campagne sbxwaf-scan",
                        "redémarrer le pare-feu"]


@pytest.mark.asyncio
async def test_adresse_non_publique_jamais_proposee(gk2):
    gk2["donnees"]["/waf/alerts"]["alerts"].append({"timestamp": "", "client_ip": "192.168.1.20", "host": "x"})
    r = await menaces.releve_menaces()
    _, gardees, retirees = menaces.filtrer_propositions("Proposition : bannir l'adresse 192.168.1.20", r)
    assert gardees == [] and retirees == ["bannir l'adresse 192.168.1.20"]


def test_consigne_et_catalogue_r12():
    assert "surveiller" not in menaces.FORMES_PROPOSITION.lower()
    assert all("surveill" not in g for g, *_ in menaces.ACTIONS_MENACES)
    assert ".env" in menaces.CONSIGNE_MENACES and "propose de la bannir" in menaces.CONSIGNE_MENACES


# ---- Faits écrits sans IA ----
@pytest.mark.asyncio
async def test_faits_menaces(gk2):
    r = await menaces.releve_menaces()
    f = menaces.faits_menaces(r)
    assert "• Alertes aujourd'hui : 1 234 — scan 64,8 %" in f
    assert "• Bans actifs : 948 — scan 91,9 % · bruteforce 8,1 %" in f
    assert "cloud.gk2.secubox.in (321)" in f and "45.135.232.0/24 (5)" in f
    assert f"la plus large : authwatch, 3 attaquants (signature {SIG_AUTH[:16]})" in f
    assert "• Posture : Bonne · 78" in f and "• Évolution : pas encore mesurée" in f


# ---- Résumé en double tampon ----
BROUILLON = "Voici le brouillon :\nBROUILLON INVENTÉ : 4000 attaques de Russie."
RELU = ("Voici le texte corrigé :\nIl y a 950 bans actifs, 92 % pour des scans, venus de Chine, en hausse.\n"
        f"Proposition : bannir l'adresse {ALERTE_SEULE}\nProposition : surveiller l'adresse {ALERTE_SEULE}")


def deux_passes(corps):
    return RELU if "<brouillon>" in corps["messages"][-1]["content"] else BROUILLON


@pytest.mark.asyncio
async def test_resume_double_tampon_et_controles(gk2, monkeypatch):
    vus = moteur_simule(monkeypatch, deux_passes)
    r = await appeler("POST", "/menaces/resumer")
    assert r.status_code == 200
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini", t["resultat"]
    res = t["resultat"]
    assert len(vus) == 2
    assert vus[0]["messages"][0]["content"] == menaces.CONSIGNE_MENACES
    assert "FAITS :\n• Alertes aujourd'hui" in vus[0]["messages"][-1]["content"]
    # le brouillon n'est jamais montré : il ne sert qu'à la relecture, sans la formule « Voici … : »
    assert "<brouillon>BROUILLON INVENTÉ" in vus[1]["messages"][-1]["content"]
    assert "BROUILLON" not in res and "Voici" not in res
    assert res.startswith("Faits (relevé de gk2, sans IA)\n• Alertes aujourd'hui")
    assert "Lecture (IA, relue contre les faits)\nIl y a 950 bans" in res
    note = res.split("⚠ Contrôle du relais — ", 1)[1]
    assert "950" in note and "CN" in note and "tendance" in note
    assert "(1 proposition(s) retirée(s)" in res and f"« surveiller l'adresse {ALERTE_SEULE} »" in res
    assert t["propositions"] == [{"genre": "ip", "cible": ALERTE_SEULE, "texte": f"Bannir l'adresse {ALERTE_SEULE}",
                                  "lien": "https://admin.gk2.secubox.in/waf/attaquants.html"}]
    rel = (await appeler("GET", "/menaces/releve")).json()
    assert rel["resume"] == res and rel["resume_propositions"] == t["propositions"]
    assert rel["resume_en_cours"] == r.json()["tache"] and rel["resume_quand"] > 0


@pytest.mark.asyncio
async def test_resume_deja_en_cours_rend_la_meme_tache(gk2):
    t = taches.nouvelle_tache("menaces", "Résumé des menaces de gk2")
    menaces.DERNIER_RESUME["en_cours"] = t
    r = await appeler("POST", "/menaces/resumer")
    assert r.json() == {"tache": t} and gk2["reqs"] == []


@pytest.mark.asyncio
async def test_deux_onglets_un_seul_resume(gk2, monkeypatch):
    libre = asyncio.Event()

    async def modele_lent(systeme, utilisateur, max_tokens=400, t=None):
        await libre.wait()
        return "Lecture."
    monkeypatch.setattr(taches, "demander_modele", modele_lent)
    r1, r2 = await asyncio.gather(appeler("POST", "/menaces/resumer"), appeler("POST", "/menaces/resumer"))
    assert r1.json()["tache"] == r2.json()["tache"] and len(taches.TACHES) == 1
    libre.set()
    assert (await attendre(r1.json()["tache"]))["etat"] == "fini"


@pytest.mark.asyncio
async def test_resume_relecture_vide_garde_le_brouillon_controle(gk2, monkeypatch):
    moteur_simule(monkeypatch, lambda c: "" if "<brouillon>" in c["messages"][-1]["content"] else "Lecture : 4000 alertes.")
    t = await attendre((await appeler("POST", "/menaces/resumer")).json()["tache"])
    assert "Lecture : 4000 alertes." in t["resultat"] and "chiffres absents du relevé : 4000" in t["resultat"]


# ---- Question sur les menaces ----
@pytest.mark.asyncio
async def test_demander_sur_une_adresse(gk2, monkeypatch):
    vus = moteur_simule(monkeypatch, f"Elle cherche des fichiers .env.\nProposition : bannir l'adresse {ALERTE_SEULE}")
    r = await appeler("POST", "/menaces/demander", json={"question": f"Que fait {ALERTE_SEULE} ?"})
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini" and t["resultat"] == "Elle cherche des fichiers .env."
    assert t["titre"] == f"Menaces — Que fait {ALERTE_SEULE} ?"
    donnees = json.loads(vus[0]["messages"][-1]["content"].split("<donnees>", 1)[1].rsplit("</donnees>", 1)[0])
    assert [a["client_ip"] for a in donnees["alertes"]] == [ALERTE_SEULE] and donnees["bans"] == []
    assert "alertes" not in donnees["releve"]
    assert [p["texte"] for p in t["propositions"]] == [f"Bannir l'adresse {ALERTE_SEULE}"]


@pytest.mark.asyncio
async def test_demander_campagne_de_l_adresse_signature_complete(gk2, monkeypatch):
    vus = moteur_simule(monkeypatch, f"Proposition : examiner la campagne {SIG_AUTH}\n"
                                     "Proposition : examiner la campagne 0f9e8d7c6b5a493827161514")
    r = await appeler("POST", "/menaces/demander", json={"question": "Et 160.1.3.4 ?"})
    t = await attendre(r.json()["tache"])
    donnees = json.loads(vus[0]["messages"][-1]["content"].split("<donnees>", 1)[1].rsplit("</donnees>", 1)[0])
    assert donnees["campagnes"] == [{"signature": SIG_AUTH, "outil": "authwatch", "attaquants": 3}]
    assert [b["ip"] for b in donnees["bans"]] == ["160.1.3.4"]
    # la campagne de l'adresse (signature complète) est reconnue ; une signature complète étrangère est retirée
    assert [p["cible"] for p in t["propositions"]] == [SIG_AUTH]
    assert "(1 proposition(s) retirée(s)" in t["resultat"]


@pytest.mark.asyncio
async def test_demander_adresse_inconnue_le_dit(gk2, monkeypatch):
    vus = moteur_simule(monkeypatch, "Aucune trace.")
    r = await appeler("POST", "/menaces/demander", json={"question": "Et 8.8.8.8 ?"})
    await attendre(r.json()["tache"])
    assert "Aucune trace de ces adresses" in vus[0]["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_demander_question_requise(gk2):
    assert (await appeler("POST", "/menaces/demander", json={"question": "  "})).status_code == 422


@pytest.mark.asyncio
async def test_journal_sans_adresse_ni_question_ni_resume(gk2, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    moteur_simule(monkeypatch, deux_passes)
    await attendre((await appeler("POST", "/menaces/resumer")).json()["tache"])
    await attendre((await appeler("POST", "/menaces/demander", json={"question": f"Que fait {ALERTE_SEULE} ?"})).json()["tache"])
    gk2["pannes"].add("tout")
    await menaces.releve_menaces(force=True)
    texte = caplog.text
    assert "menaces" in texte              # la panne de gk2 est bien tracée…
    for interdit in (ALERTE_SEULE, BANNIE, BOX, "Que fait", "950 bans", "BROUILLON", "Chine"):
        assert interdit not in texte       # … mais jamais une adresse, une question ou un résumé


# ---- Instantanés (tendances) ----
def fichier_instantanes(env):
    return env / "etat" / "instantanes-menaces.json"


@pytest.mark.asyncio
async def test_instantanes_ecrits_et_relus_au_redemarrage(gk2, env):
    await menaces.releve_menaces()
    lus = json.loads(fichier_instantanes(env).read_text())
    assert len(lus) == 1 and lus[0]["bans"] == 948 and lus[0]["menaces_jour"] == 1234
    assert not list((env / "etat").glob("*.tmp"))
    menaces._reinitialiser()                       # redémarrage du module
    menaces.charger_instantanes()
    assert list(menaces.INSTANTANES) == lus


@pytest.mark.asyncio
async def test_evolution_mesuree_apres_redemarrage(gk2, env):
    fichier_instantanes(env).parent.mkdir(parents=True)
    fichier_instantanes(env).write_text(json.dumps([
        {"quand": time.time() - 4 * 3600, "menaces_jour": 1, "bans": 1, "categories": {}},      # trop vieux : écarté
        {"quand": time.time() - 3600, "menaces_jour": 1000, "bans": 900,
         "categories": {"waf:scan": 700, "waf:sqli": 300}}]))
    r = await menaces.releve_menaces()             # premier relevé : charge les instantanés gardés
    ev = r["evolution_1h"]
    assert ev["disponible"] is True and ev["minutes"] == 60
    assert ev["nouvelles_menaces"] == 234 and ev["ecart_bans_actifs"] == 48
    assert ev["par_categorie"] == {"authwatch:bruteforce": 134, "waf:scan": 100}
    assert "• Sur 60 min : 234 nouvelles alertes ; écart des bans actifs +48" in menaces.faits_menaces(r)
    assert len(menaces.INSTANTANES) == 2


def test_evolution_remise_a_zero_minuit():
    menaces._reinitialiser()
    maintenant = time.time()
    menaces.INSTANTANES.extend([{"quand": maintenant - 3600, "menaces_jour": 900, "bans": 1, "categories": {}},
                                {"quand": maintenant, "menaces_jour": 10, "bans": 1, "categories": {}}])
    assert "remis à zéro" in menaces.evolution(maintenant)["raison"]
    menaces._reinitialiser()


@pytest.mark.parametrize("contenu", ["{pas du json", '{"quand": 1}', '[1, "x", {"quand": "hier"}]', "\udcff"])
def test_instantanes_corrompus_demarrage_vide(env, contenu):
    fichier_instantanes(env).parent.mkdir(parents=True)
    fichier_instantanes(env).write_bytes(contenu.encode("utf-8", "surrogateescape"))
    menaces.charger_instantanes()
    assert list(menaces.INSTANTANES) == []


def test_instantanes_bornes(env):
    fichier_instantanes(env).parent.mkdir(parents=True)
    maintenant = time.time()
    fichier_instantanes(env).write_text(json.dumps(
        [{"quand": maintenant - 3000 + i, "menaces_jour": i, "bans": i, "categories": {"a": i}} for i in range(200)]))
    menaces.charger_instantanes()
    assert len(menaces.INSTANTANES) == 90 and menaces.INSTANTANES[-1]["bans"] == 199


# ---- Veille de fond ----
@pytest.mark.asyncio
async def test_veille_resume_auto_si_moteur_actif_et_libre(gk2, monkeypatch):
    moteur_simule(monkeypatch, deux_passes)
    await menaces.releve_menaces()
    t = await menaces.tour_veille()
    assert t and taches.TACHES[t]["titre"] == "Résumé automatique des menaces de gk2"
    await attendre(t)
    assert menaces.DERNIER_RESUME["quand"] > 0
    assert await menaces.tour_veille() is None          # résumé récent : rien avant resume_auto_min


@pytest.mark.asyncio
async def test_veille_ne_passe_pas_devant_une_demande(gk2, monkeypatch):
    moteur_simule(monkeypatch, "x")
    await menaces.releve_menaces()
    monkeypatch.setitem(taches.COMPTEURS, "en_cours", 1)
    assert await menaces.tour_veille() is None and taches.TACHES == {}


@pytest.mark.asyncio
async def test_veille_ne_demarre_jamais_le_moteur(gk2, monkeypatch, env):
    vus = moteur_simule(monkeypatch, "x", sante=503)
    await menaces.releve_menaces()
    assert await menaces.tour_veille() is None and taches.TACHES == {} and vus == []
    assert not (env / "run" / "demandes").exists()


@pytest.mark.asyncio
async def test_veille_desactivee_ou_releve_en_erreur(gk2, monkeypatch, env):
    moteur_simule(monkeypatch, "x")
    assert await menaces.tour_veille() is None                 # aucun relevé encore
    gk2["pannes"].add("tout")
    await menaces.releve_menaces()
    assert await menaces.tour_veille() is None                 # dernier relevé en erreur
    gk2["pannes"].clear()
    await menaces.releve_menaces(force=True)
    reglages.ecrire_prefs(reglages.valider({"menaces": {"resume_auto_min": 0}}))
    assert await menaces.tour_veille() is None and taches.TACHES == {}


@pytest.mark.asyncio
async def test_cycle_de_vie_lance_et_arrete_la_veille(gk2, monkeypatch):
    monkeypatch.setattr(menaces, "PERIODE_RELEVE_S", 0.01)
    async with app.router.lifespan_context(app):
        for _ in range(100):
            if gk2["reqs"]:
                break
            await asyncio.sleep(0.01)
        assert gk2["reqs"] and len(menaces._VEILLE) == 2
        boucles = list(menaces._VEILLE)
    assert all(b.done() for b in boucles) and menaces._VEILLE == []


@pytest.mark.asyncio
async def test_releve_incomplet_sans_instantane(gk2, env):
    gk2["pannes"].add("/waf/bans")
    await menaces.releve_menaces()
    assert list(menaces.INSTANTANES) == [] and not fichier_instantanes(env).exists()


# ---- Reprise 1 de la relecture ----
@pytest.mark.asyncio
async def test_demander_reponse_controlee(gk2, monkeypatch):
    moteur_simule(monkeypatch, "Il y a 950 bans venus de Chine, en hausse.")
    r = await appeler("POST", "/menaces/demander", json={"question": "Quoi de neuf ?"})
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "fini"
    note = t["resultat"].split("⚠ Contrôle du relais — ", 1)[1]
    assert "chiffres absents du relevé : 950" in note and "CN" in note and "tendance" in note


@pytest.mark.asyncio
async def test_deja_bannie_portee_par_le_releve_pas_par_le_cache(gk2):
    a = await menaces.releve_menaces()
    gk2["pannes"].add("/waf/bans")
    b = await menaces.releve_menaces(force=True)          # le cache porte maintenant un relevé sans bans
    assert menaces._cache["releve"] is b and b["erreurs"] == ["/waf/bans"]
    _, gardees, retirees = menaces.filtrer_propositions(f"Proposition : bannir l'adresse {BANNIE}", a)
    assert gardees == [] and retirees == [f"bannir l'adresse {BANNIE}"]
    # la liste des bannies ne sort jamais : ni page, ni modèle, ni contrôle des chiffres
    assert "_bannies" not in (await appeler("GET", "/menaces/releve")).json()
    assert "_bannies" not in menaces.compact_releve(a) and BANNIE not in menaces.compact_releve(a, sans_alertes=True)
    # 160.76.3.4 est bannie : « 160,76 » ne doit pas devenir un chiffre « connu » du relevé
    assert "chiffres absents du relevé : 160,76" in menaces.controler_resume("Score 160,76.", a)


@pytest.mark.asyncio
async def test_champ_gk2_de_type_inattendu_resume_fini(gk2, monkeypatch):
    gk2["donnees"]["/waf/alerts"]["alerts"].append(
        {"timestamp": None, "client_ip": ["1.2.3.4"], "host": {"x": 1}, "path": "/", "category": "waf:scan"})
    moteur_simule(monkeypatch, deux_passes)
    t = await attendre((await appeler("POST", "/menaces/resumer")).json()["tache"])
    assert t["etat"] == "fini" and [p["cible"] for p in t["propositions"]] == [ALERTE_SEULE]
    t = await attendre((await appeler("POST", "/menaces/demander", json={"question": "Et 1.2.3.4 ?"})).json()["tache"])
    assert t["etat"] == "fini"


@pytest.mark.asyncio
async def test_exception_imprevue_finit_la_tache_en_echec(gk2, monkeypatch):
    def casse(r):
        raise TypeError("imprévu")
    monkeypatch.setattr(menaces, "faits_menaces", casse)
    r = await appeler("POST", "/menaces/resumer")
    t = await attendre(r.json()["tache"])
    assert t["etat"] == "echec" and "TypeError" in t["resultat"]
    assert menaces._resume_en_cours() is None


@pytest.mark.asyncio
async def test_panne_gk2_journalisee_au_changement_seulement(gk2, caplog):
    caplog.set_level(logging.INFO, logger="secubox.ai.menaces")

    def traces():
        return [x.getMessage() for x in caplog.records if x.name == "secubox.ai.menaces"]
    await menaces.releve_menaces()
    assert traces() == []
    gk2["pannes"].add("tout")
    for _ in range(3):
        await menaces.releve_menaces(force=True)
    assert len(traces()) == 1 and traces()[0].startswith("menaces.gk2 en erreur")
    gk2["pannes"].clear()
    await menaces.releve_menaces(force=True)
    await menaces.releve_menaces(force=True)
    assert traces()[1:] == ["menaces.gk2 rétabli"]
    gk2["pannes"].add("/waf/bans")
    await menaces.releve_menaces(force=True)
    assert len(traces()) == 3


@pytest.mark.asyncio
async def test_boucles_survivent_a_une_exception(env, monkeypatch):
    compte = {"releve": 0, "tour": 0}

    async def releve(force=False):
        compte["releve"] += 1
        if compte["releve"] == 1:
            raise RuntimeError("tour raté")

    async def tour():
        compte["tour"] += 1
        if compte["tour"] == 1:
            raise RuntimeError("tour raté")
    monkeypatch.setattr(menaces, "releve_menaces", releve)
    monkeypatch.setattr(menaces, "tour_veille", tour)
    monkeypatch.setattr(menaces, "PERIODE_RELEVE_S", 0)
    monkeypatch.setattr(menaces, "PERIODE_VEILLE_S", 0)
    menaces.demarrer_veille()
    try:
        for _ in range(200):
            if compte["releve"] >= 3 and compte["tour"] >= 3:
                break
            await asyncio.sleep(0.005)
        assert compte["releve"] >= 3 and compte["tour"] >= 3
        assert not any(b.done() for b in menaces._VEILLE)
    finally:
        await menaces.arreter_veille()


def test_instantane_du_futur_ecarte(env):
    fichier_instantanes(env).parent.mkdir(parents=True)
    maintenant = time.time()
    fichier_instantanes(env).write_text(json.dumps(
        [{"quand": maintenant + 3600, "menaces_jour": 1, "bans": 1, "categories": {}},
         {"quand": maintenant + 60, "menaces_jour": 2, "bans": 2, "categories": {}}]))
    menaces.charger_instantanes()
    assert [x["bans"] for x in menaces.INSTANTANES] == [2]


# ---- Pourcentages : une part du relevé, jamais un compte (#3583, vu le 14/11/2026) ----
def _releve_pct(**extra):
    return {"parts_alertes_pct": {"sasl_failed": 46.6}, "evolution_1h": {"disponible": True},
            "par_categorie": {"sasl_failed": 60, "scanners": 48}, **extra}


NOTE_PCT = "pourcentages absents du relevé (des comptes donnés pour des parts ?)"


def test_controle_pct_compte_pris_pour_part():
    r = {"evolution_1h": {"disponible": True, "par_categorie": {"sasl_failed": 60, "scanners": 48}}}
    t = menaces.controler_resume("Une hausse de +60 % sur les échecs SASL et de +48 % sur les scanners.", r)
    assert NOTE_PCT + " : 48 %, 60 %" in t
    assert "chiffres absents" not in t


def test_controle_pct_part_acceptee_virgule_et_arrondi():
    r = _releve_pct()
    assert menaces.controler_resume("Les échecs SASL pèsent 46,6 % des alertes.", r).count("⚠") == 0
    assert menaces.controler_resume("Environ 47 % des alertes.", r).count("⚠") == 0
    assert menaces.controler_resume("Environ 47% des alertes.", r).count("⚠") == 0


def test_controle_pct_valeur_seulement_comptee():
    r = {"par_categorie": {"x": 46.6}, "evolution_1h": {"disponible": True}}
    assert NOTE_PCT + " : 46,6 %" in menaces.controler_resume("Soit 46,6 % des alertes.", r)


@pytest.mark.asyncio
async def test_demander_controle_pct(gk2, monkeypatch):
    moteur_simule(monkeypatch, "Une hausse de +77 % des alertes.")
    r = await appeler("POST", "/menaces/demander", json={"question": "Que se passe-t-il ?"})
    t = await attendre(r.json()["tache"])
    assert NOTE_PCT + " : 77 %" in t["resultat"]
