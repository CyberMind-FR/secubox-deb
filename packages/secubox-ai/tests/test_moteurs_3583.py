# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteurs local et distant de secubox-ai (#3583) : choix, clé, demandes au contrôleur, routes."""
import json
import logging
import threading
import time

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import moteurs, reglages
from api.main import app

CLE = "sk-secret-tres-longue-9f8e7d"
URL = "https://ia.distante.test"


@pytest.fixture
def env(tmp_path, monkeypatch):
    conf, cle = tmp_path / "ai.toml", tmp_path / "distant.key"
    conf.write_text(f'[distant]\nurl = "{URL}"\n', encoding="utf-8")
    cle.write_text(CLE + "\n", encoding="utf-8")
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "etat"))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(conf))
    monkeypatch.setenv("SECUBOX_AI_CLE", str(cle))
    monkeypatch.setenv("SECUBOX_AI_RUN", str(tmp_path / "run"))
    (tmp_path / "run" / "demandes").mkdir(parents=True)       # créé par secubox-aictl preparer en production
    moteurs._cache_sonde.clear()
    yield tmp_path
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", None)


def tombe(req):
    raise httpx.ConnectError("injoignable", request=req)


def transports(monkeypatch, distant=None, local=None):
    """Installe des MockTransport ; renvoie la liste des requêtes vues (nom, méthode, chemin, en-têtes)."""
    vues = []

    def fabrique_h(nom, h):
        def f(req):
            vues.append((nom, req.method, req.url.path, dict(req.headers)))
            return h(req)
        return httpx.MockTransport(f)

    def ok(req):
        return httpx.Response(200, json={"status": "ok"})

    cibles = {"distant": distant or ok, "local": local or ok}
    monkeypatch.setattr(moteurs, "FABRIQUE_TRANSPORT", lambda nom: fabrique_h(nom, cibles[nom]))
    return vues


@pytest.mark.asyncio
async def test_distant_declare_et_sain(env, monkeypatch):
    vues = transports(monkeypatch)
    m = await moteurs.choisir()
    assert m.nom == "distant"
    assert vues[0][0] == "distant" and vues[0][2] == "/health"
    assert vues[0][3]["authorization"] == f"Bearer {CLE}"


@pytest.mark.asyncio
async def test_distant_muet_bascule_local(env, monkeypatch):
    def muet(req):
        raise httpx.ReadTimeout("délai", request=req)
    transports(monkeypatch, distant=muet)
    assert (await moteurs.choisir()).nom == "local"


@pytest.mark.asyncio
async def test_distant_en_erreur_bascule_local(env, monkeypatch):
    transports(monkeypatch, distant=tombe)
    assert (await moteurs.choisir()).nom == "local"


@pytest.mark.asyncio
async def test_sonde_courte_et_mise_en_cache(env, monkeypatch):
    vues = transports(monkeypatch)
    await moteurs.choisir()
    await moteurs.choisir()
    assert len([v for v in vues if v[0] == "distant"]) == 1
    assert moteurs.DELAI_SONDE_S == 2.0 and moteurs.CACHE_SONDE_S <= 10


@pytest.mark.asyncio
async def test_forcage_local_ne_touche_pas_au_distant(env, monkeypatch):
    vues = transports(monkeypatch)
    assert (await moteurs.choisir("local")).nom == "local"
    assert not vues


@pytest.mark.asyncio
async def test_forcage_distant_et_prefs(env, monkeypatch):
    transports(monkeypatch, distant=tombe)
    assert (await moteurs.choisir("distant")).nom == "distant"
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "local"}}))
    assert (await moteurs.choisir()).nom == "local"


@pytest.mark.asyncio
async def test_cle_absente_aucun_appel(env, monkeypatch):
    vues = transports(monkeypatch)
    (env / "distant.key").unlink()
    assert (await moteurs.choisir()).nom == "local"
    with pytest.raises(HTTPException) as e:
        await moteurs.choisir("distant")
    assert e.value.status_code == 503 and "non configuré" in e.value.detail
    d = (await moteurs.etat())["distant"]
    assert d == {"declare": True, "configure": False, "statut": None, "joignable": False}
    assert not [v for v in vues if v[0] == "distant"]


@pytest.mark.asyncio
@pytest.mark.parametrize("contenu", ["", "  \n"])
async def test_cle_vide_aucun_appel(env, monkeypatch, contenu):
    vues = transports(monkeypatch)
    (env / "distant.key").write_text(contenu)
    assert (await moteurs.choisir()).nom == "local"
    assert not [v for v in vues if v[0] == "distant"]


@pytest.mark.asyncio
async def test_cle_illisible_aucun_appel(env, monkeypatch):
    vues = transports(monkeypatch)
    (env / "distant.key").write_bytes(b"\xff\xfe\x00")
    assert (await moteurs.choisir()).nom == "local"
    assert not [v for v in vues if v[0] == "distant"]


@pytest.mark.asyncio
async def test_url_non_declaree_local(env, monkeypatch):
    vues = transports(monkeypatch)
    (env / "ai.toml").write_text("")
    assert (await moteurs.choisir()).nom == "local"
    assert not [v for v in vues if v[0] == "distant"]


@pytest.mark.asyncio
async def test_la_cle_ne_fuit_pas(env, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    # Un 401 et une panne réseau produisent de vraies lignes de journal.
    transports(monkeypatch, distant=lambda req: httpx.Response(401))
    m = await moteurs.choisir()
    assert m.nom == "local"
    moteurs._cache_sonde.clear()
    transports(monkeypatch, distant=tombe)
    await moteurs.choisir()
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "distant"}}))
    with pytest.raises(HTTPException) as exc:
        await moteurs.assurer_moteur(delai=0.05, pas=0.01)
    e = await moteurs.etat()
    assert caplog.records, "aucune ligne de journal exercée"
    assert CLE not in caplog.text and CLE not in repr(m) and CLE not in str(e) and CLE not in str(exc.value.detail)
    assert "clé refusée" in caplog.text and "injoignable" in caplog.text
    (env / "distant.key").unlink()
    with pytest.raises(HTTPException) as exc:
        await moteurs.choisir("distant")
    assert CLE not in str(exc.value.detail)


def test_deposer_demande(env):
    for a in ("demarrer", "arreter", "redemarrer"):
        moteurs.deposer_demande(a)
        assert (env / "run" / "demandes" / f"{a}.demande").exists()
    assert not list((env / "run" / "demandes").glob("*.tmp"))
    assert not [f for f in (env / "run" / "demandes").iterdir() if f.suffix != ".demande"]
    for mauvais in ("../x", "stop", ""):
        with pytest.raises(ValueError):
            moteurs.deposer_demande(mauvais)


@pytest.mark.asyncio
async def test_assurer_local_depose_et_attend(env, monkeypatch):
    etats = iter([httpx.ConnectError("pas encore"), httpx.ConnectError("encore"), None])

    def local(req):
        e = next(etats)
        if e:
            raise e
        return httpx.Response(200)
    transports(monkeypatch, distant=tombe, local=local)
    m = await moteurs.assurer_moteur(delai=5, pas=0)
    assert m.nom == "local"
    assert (env / "run" / "demandes" / "demarrer.demande").exists()


@pytest.mark.asyncio
async def test_assurer_local_ne_demarre_pas_si_deja_pret(env, monkeypatch):
    transports(monkeypatch, distant=tombe)
    await moteurs.assurer_moteur(delai=5, pas=0)
    assert not (env / "run" / "demandes" / "demarrer.demande").exists()


@pytest.mark.asyncio
async def test_assurer_local_echec_503(env, monkeypatch):
    def mort(req):
        raise httpx.ConnectError("non", request=req)
    transports(monkeypatch, distant=tombe, local=mort)
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=0.05, pas=0.01)
    assert e.value.status_code == 503


@pytest.mark.asyncio
async def test_assurer_distant_demande_le_demarrage(env, monkeypatch):
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "distant"}}))
    etat = {"demarre": False}

    def distant(req):
        if req.method == "POST" and req.url.path == "/moteur/demarrer":
            etat["demarre"] = True
            return httpx.Response(200)
        return httpx.Response(200 if etat["demarre"] else 503)
    vues = transports(monkeypatch, distant=distant)
    m = await moteurs.assurer_moteur(delai=5, pas=0)
    assert m.nom == "distant"
    assert ("distant", "POST", "/moteur/demarrer") in [v[:3] for v in vues]


@pytest.mark.asyncio
async def test_contexte_reel_et_tokens(env, monkeypatch):
    def local(req):
        if req.url.path == "/props":
            return httpx.Response(200, json={"default_generation_settings": {"n_ctx": 8192}})
        if req.url.path == "/tokenize":
            return httpx.Response(200, json={"tokens": [1, 2, 3]})
        return httpx.Response(200)
    transports(monkeypatch, local=local)
    m = await moteurs.choisir("local")
    assert await moteurs.contexte_reel(m) == 8192
    assert await moteurs.compter_tokens("bonjour", m) == 3


@pytest.mark.asyncio
async def test_contexte_zero_retombe_sur_prefs(env, monkeypatch):
    transports(monkeypatch, local=lambda req: httpx.Response(
        200, json={"default_generation_settings": {"n_ctx": 0}}))
    m = await moteurs.choisir("local")
    assert await moteurs.contexte_reel(m) == moteurs.CTX_AUTO_MIN  # défaut 0 (auto) : repli sur le minimum


@pytest.mark.asyncio
async def test_etat_dit_quel_moteur_repond(env, monkeypatch):
    transports(monkeypatch)
    e = await moteurs.etat()
    assert e["actif"] == "distant" and e["force"] == "auto" and e["local"]["pret"] is True
    transports(monkeypatch, distant=tombe)
    moteurs._cache_sonde.clear()
    assert (await moteurs.etat())["actif"] == "local"


def test_routes_gardees_et_forcage(env, monkeypatch):
    transports(monkeypatch)
    assert TestClient(app).get("/moteur").status_code in (401, 403)
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        c = TestClient(app)
        assert c.get("/moteur").json()["actif"] == "distant"
        assert c.post("/moteur/local").json()["actif"] == "local"
        assert reglages.lire_prefs()["moteur"]["force"] == "local"
        assert c.post("/moteur/auto").json()["force"] == "auto"
        assert c.post("/moteur/nimporte").status_code == 422
        assert c.get("/status").json()["moteur"]["force"] == "auto"
    finally:
        app.dependency_overrides.clear()


def test_force_invalide_refuse():
    with pytest.raises(HTTPException) as e:
        reglages.valider({"moteur": {"force": "cloud"}})
    assert e.value.status_code == 422


def test_deposer_demande_concurrent(env):
    erreurs = []

    def tache():
        try:
            for _ in range(300):
                moteurs.deposer_demande("demarrer")
        except Exception as e:  # noqa: BLE001
            erreurs.append(e)
    fils = [threading.Thread(target=tache) for _ in range(4)]
    [f.start() for f in fils]
    [f.join() for f in fils]
    assert not erreurs
    assert sorted(f.name for f in (env / "run" / "demandes").iterdir()) == ["demarrer.demande"]


# --- R10 : sémantique de la sonde ---
@pytest.mark.asyncio
async def test_sonde_503_endormi_choisit_distant_et_reveille(env, monkeypatch):
    etat = {"debout": False}

    def distant(req):
        if req.method == "POST" and req.url.path == "/moteur/demarrer":
            etat["debout"] = True
            return httpx.Response(202)
        return httpx.Response(200 if etat["debout"] else 503)
    vues = transports(monkeypatch, distant=distant)
    assert (await moteurs.choisir()).nom == "distant"
    m = await moteurs.assurer_moteur(delai=5, pas=0)
    assert m.nom == "distant"
    assert ("distant", "POST", "/moteur/demarrer") in [v[:3] for v in vues]
    assert not list((env / "run" / "demandes").iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [401, 403])
async def test_sonde_cle_refusee_local_et_journal(env, monkeypatch, caplog, code):
    caplog.set_level(logging.WARNING)
    transports(monkeypatch, distant=lambda req: httpx.Response(code))
    assert (await moteurs.choisir()).nom == "local"
    assert "clé refusée" in caplog.text and CLE not in caplog.text


@pytest.mark.asyncio
async def test_sonde_delai_arrive_a_la_requete(env, monkeypatch):
    delais = []

    def distant(req):
        delais.append(req.extensions["timeout"])
        return httpx.Response(200)
    transports(monkeypatch, distant=distant)
    await moteurs.choisir()
    assert delais[0]["read"] == 2.0 and delais[0]["connect"] == 2.0


@pytest.mark.asyncio
async def test_reseau_ou_delai_injoignable_local(env, monkeypatch):
    def delai(req):
        raise httpx.ConnectTimeout("délai", request=req)
    transports(monkeypatch, distant=delai)
    assert (await moteurs.choisir()).nom == "local"
    assert (await moteurs.etat())["distant"]["statut"] == "injoignable"


# --- auto : repli local, plus de cache périmé ---
@pytest.mark.asyncio
async def test_cache_perime_puis_distant_tombe_repli_local(env, monkeypatch):
    haut = {"ok": True}

    def distant(req):
        return httpx.Response(200) if haut["ok"] else tombe(req)
    transports(monkeypatch, distant=distant)
    assert (await moteurs.choisir()).nom == "distant"   # sonde mise en cache
    haut["ok"] = False
    debut = time.monotonic()
    m = await moteurs.assurer_moteur(delai=0.05, pas=0.01)
    assert m.nom == "local" and time.monotonic() - debut < 2
    assert not (env / "run" / "demandes" / "demarrer.demande").exists()  # local déjà prêt


@pytest.mark.asyncio
async def test_reveil_refuse_en_auto_repli_local(env, monkeypatch):
    def distant(req):
        return httpx.Response(401) if req.method == "POST" else httpx.Response(503)
    transports(monkeypatch, distant=distant)
    m = await moteurs.assurer_moteur(delai=0.05, pas=0.01)
    assert m.nom == "local"
    assert moteurs._cache_sonde == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("reponse,motif", [(lambda req: httpx.Response(401), "clé refusée"), (tombe, "injoignable")])
async def test_distant_force_echoue_vite_sans_cle_dans_le_message(env, monkeypatch, reponse, motif):
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "distant"}}))
    transports(monkeypatch, distant=reponse)
    debut = time.monotonic()
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=30, pas=1)
    assert e.value.status_code == 503 and motif in e.value.detail and CLE not in e.value.detail
    assert time.monotonic() - debut < 2


@pytest.mark.asyncio
async def test_reveil_distant_401_force_echoue_vite(env, monkeypatch):
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "distant"}}))
    transports(monkeypatch, distant=lambda req: httpx.Response(401) if req.method == "POST" else httpx.Response(503))
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=30, pas=1)
    assert e.value.status_code == 503 and "clé refusée" in e.value.detail


# --- R9 : état du contrôleur ---
def _ecrire_etat(env, etat, message, horodatage):
    (env / "run").mkdir(exist_ok=True)
    (env / "run" / "moteur-etat.json").write_text(
        json.dumps({"etat": etat, "message": message, "horodatage": horodatage}), encoding="utf-8")


@pytest.mark.asyncio
@pytest.mark.parametrize("etat_", ["refus_memoire", "erreur"])
async def test_refus_controleur_echec_immediat(env, monkeypatch, etat_):
    transports(monkeypatch, distant=tombe, local=tombe)
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "local"}}))
    _ecrire_etat(env, etat_, "mémoire insuffisante : 300 Mo libres", time.time() + 60)
    debut = time.monotonic()
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=30, pas=1)
    assert e.value.status_code == 503 and e.value.detail == "mémoire insuffisante : 300 Mo libres"
    assert time.monotonic() - debut < 2


@pytest.mark.asyncio
async def test_refus_ancien_ignore(env, monkeypatch):
    transports(monkeypatch, distant=tombe, local=tombe)
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "local"}}))
    _ecrire_etat(env, "refus_memoire", "ancien refus", time.time() - 3600)
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=0.1, pas=0.02)
    assert e.value.detail == "le moteur local n'a pas démarré"


@pytest.mark.asyncio
@pytest.mark.parametrize("contenu", [None, "pas du json", "[1]"])
async def test_etat_controleur_illisible_on_continue(env, monkeypatch, contenu):
    transports(monkeypatch, distant=tombe, local=tombe)
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "local"}}))
    if contenu is not None:
        (env / "run").mkdir(exist_ok=True)
        (env / "run" / "moteur-etat.json").write_text(contenu)
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=0.1, pas=0.02)
    assert e.value.detail == "le moteur local n'a pas démarré"


# --- R11 ---
@pytest.mark.asyncio
async def test_distant_ignore_le_proxy_de_l_environnement(env, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.test:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.test:3128")
    m = moteurs.Moteur("distant", URL, CLE)
    async with m.client(2) as c:
        assert c._trust_env is False
        assert c._transport_for_url(httpx.URL(URL + "/health")) is c._transport


@pytest.mark.asyncio
async def test_etat_actif_est_le_moteur_qui_repond(env, monkeypatch):
    transports(monkeypatch)
    e = await moteurs.etat()
    assert (e["choisi"], e["actif"]) == ("distant", "distant")
    # distant endormi : choisi mais ne répond pas encore
    moteurs._cache_sonde.clear()
    transports(monkeypatch, distant=lambda req: httpx.Response(503))
    e = await moteurs.etat()
    assert (e["choisi"], e["actif"]) == ("distant", None)
    # local forcé et muet
    reglages.ecrire_prefs(reglages.valider({"moteur": {"force": "local"}}))
    transports(monkeypatch, local=tombe)
    e = await moteurs.etat()
    assert (e["choisi"], e["actif"]) == ("local", None)


# ---- revue finale : dépôt absent = contrôleur non préparé (503, pas 500) ----
def test_depot_absent_503_controleur_non_prepare(env):
    import shutil as _shutil
    _shutil.rmtree(env / "run" / "demandes", ignore_errors=True)
    with pytest.raises(HTTPException) as e:
        moteurs.deposer_demande("demarrer")
    assert e.value.status_code == 503 and "contrôleur non préparé" in e.value.detail
    assert not (env / "run" / "demandes").exists()     # jamais créé par l'API (c'est le rôle de preparer)


@pytest.mark.asyncio
async def test_depot_absent_route_503(env, monkeypatch):
    import shutil as _shutil
    _shutil.rmtree(env / "run" / "demandes", ignore_errors=True)
    transports(monkeypatch, distant=tombe, local=tombe)
    with pytest.raises(HTTPException) as e:
        await moteurs.assurer_moteur(delai=1, pas=0, force="local")
    assert e.value.status_code == 503 and "contrôleur non préparé" in e.value.detail
