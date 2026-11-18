# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 tâche 6 — lancement des macros par l'API, exécutions, arrêt, flux en direct d'une exécution et cycle de vie (livrées
installées, exécutions interrompues au démarrage). Le moteur tourne sur la vraie `ExecutantApi` : une étape `action` passe par
`executer_action` (même audit `pilotage_action`), une étape `releve` par `lancer_releve` ; l'agent est joué par les files."""
import asyncio
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from secubox_core import auth

from api.actions import ExecutantApi
from api.main import creer_app_admin
from pilotage.diffusion import Diffusion
from pilotage.files import COMMANDE_MESURE, Files
from pilotage.inventaire import Inventaire
from pilotage.macros import LIVREES
from pilotage.moteur import EchecEtape, cle_flux
from pilotage.operations import CATALOGUE, Suivi
from pilotage.stockage import HORS_LIGNE_S, StockageSqlite
from outils import GK5, GK5_AUTOLOAD, Horloge, releve_gk5
from test_flux import Flux

DIAG = "livree:diagnostic-complet"
JOB = "a1b2c3d4e5f60718"
HUB = {"unite": "secubox-hub.service"}


class Monde:
    def __init__(self, tmp_path, mp, battement_s=15.0):
        self.h = Horloge(float(int(time.time())))   # instants entiers : inventaire_le est rangé en secondes
        self.s = StockageSqlite(tmp_path / "p", horloge=self.h)
        self.f = Files()
        self.lignes = []
        self.diffusion = Diffusion()
        self.session_ok = True
        mp.setattr(auth, "_session_validator", lambda jti: self.session_ok)
        mp.setattr(auth, "est_admin_reel", lambda payload: True)
        self.inv = Inventaire(self.f, self.s, horloge=self.h)
        suivi = Suivi(self.s, self.f, self.audit)
        self.app = creer_app_admin(self.s, self.f, self.inv, self.audit, horloge=self.h, suivi=suivi, delai_action_s=2.0,
                                   diffusion=self.diffusion, battement_s=battement_s, planificateur=False, sonde_s=0.01)
        self.moteur = self.app.state.moteur
        self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "alice", "jti": "j1", "exp": time.time() + 3600}
        self.s.macros_livrees_installer(LIVREES)
        self.s.vu(GK5, {})

    def audit(self, evenement, champs):
        self.lignes.append((evenement, dict(champs)))

    def macros_auditees(self):
        return [c["evenement"] for e, c in self.lignes if e == "pilotage_macro"]

    def client(self):
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="http://t")

    async def repondre(self, box, corps, type_="OPERATE_RESP"):
        (rq,) = await self.f.attendre_requetes(box.cle, 3)
        self.f.livrer_reponse(box.cle, {"msg_id": rq["msg_id"], "type": type_, "body": corps})
        return rq

    async def releve_rendu(self, box=GK5):
        """L'agent rend le relevé demandé, puis l'inventaire relevé après coup arrive."""
        rq = await self.repondre(box, {"output": {"ok": True}})
        assert rq["type"] == "OPERATE" and rq["body"]["command"] == COMMANDE_MESURE
        self.s.inventaire_enregistrer(box, releve_gk5())

    async def fin(self, ident, delai=5.0):
        async def attendre():
            while ident in self.moteur.taches or self.s.execution(ident)["etat"] == "en_cours":
                await asyncio.sleep(0.01)
        await asyncio.wait_for(attendre(), delai)
        return self.s.execution(ident)

    def flux(self, ident):
        return Flux(self.app, f"/executions/{ident}/flux")


@pytest.fixture
def m(tmp_path, monkeypatch):
    return Monde(tmp_path, monkeypatch)


def test_routes_d_execution_exigent_un_jwt(m):
    m.app.dependency_overrides.clear()
    c = TestClient(m.app)
    for methode, url in (("post", f"/macros/{DIAG}/lancer"), ("post", "/executions/action"), ("get", "/executions"),
                         ("get", "/executions/1"), ("post", "/executions/1/arreter"), ("get", "/executions/1/flux")):
        assert c.request(methode, url, json={}).status_code == 401, url
    vues = 0
    for r in m.app.routes:
        if getattr(r, "dependant", None) and (r.path.startswith("/executions") or r.path.endswith("/lancer")):
            vues += 1
            assert any(d.call is auth.require_jwt for d in r.dependant.dependencies), r.path
    assert vues == 6


@pytest.mark.asyncio
async def test_lancer_202_puis_lire_l_execution(m):
    async with m.client() as c:
        r = await c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]})
        assert r.status_code == 202, r.text
        ident = r.json()["execution"]
        await m.releve_rendu()
        await m.fin(ident)
        e = (await c.get(f"/executions/{ident}")).json()
        assert e["etat"] == "terminee" and e["macro_id"] == DIAG and e["macro_nom"] == "Diagnostic complet" and e["acteur"] == "alice"
        assert e["cibles"] == [{"cle": "maillage:gk5", "nom": "gk5"}]
        assert [(x["box"], x["type"], x["etat"]) for x in e["etapes"]] == [("maillage:gk5", "releve", "ok")]
        assert e["etapes"][0]["resultat"]["memoire_dispo_mo"] == 512
        liste = (await c.get("/executions", params={"limite": 1})).json()
        assert [x["id"] for x in liste] == [ident] and "etapes" not in liste[0]
        assert (await c.get("/executions", params={"limite": 0})).status_code == 422
        assert (await c.get("/executions", params={"limite": 201})).status_code == 422
        assert (await c.get("/executions/999")).status_code == 404
    assert m.macros_auditees() == ["lancement", "fin"]
    assert [e for e, _ in m.lignes].count("pilotage_releve_demande") == 1


def test_lancer_refus(m):
    c = TestClient(m.app)
    mid = c.post("/macros", json={"nom": "Redémarrer", "etapes": [{"type": "action", "action": "reboot"}]}).json()["id"]
    # confirmation forte : nom exact retapé, par identifiant tel qu'écrit dans les cibles
    assert c.post(f"/macros/{mid}/lancer", json={"cibles": ["gk5"]}).status_code == 400
    assert c.post(f"/macros/{mid}/lancer", json={"cibles": ["gk5"], "confirmations": {"gk5": "GK5"}}).status_code == 400
    assert c.post(f"/macros/{mid}/lancer", json={"cibles": ["gk5"], "confirmations": {"maillage:gk5": "gk5"}}).status_code == 400
    # box cliente sans session de support
    m.s.vu(GK5_AUTOLOAD, {})
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["autoload:gk5"]}).status_code == 409
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["autoload:gk5"], "support": {"autoload:gk5": "s1"}}).status_code == 409
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["autoload:gk5"], "support": {"autoload:gk5": "pas un id"}}).status_code == 422
    # nom ambigu, box inconnue, macro inconnue, cibles hors bornes, champ en trop
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]}).status_code == 409   # gk5 désigne deux box
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["fantome"]}).status_code == 404
    assert c.post("/macros/m-inconnue/lancer", json={"cibles": ["maillage:gk5"]}).status_code == 404
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": []}).status_code == 422
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["maillage:gk5"] * 33}).status_code == 422
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["maillage:gk5"], "x": 1}).status_code == 422
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["maillage:gk5", "maillage:gk5"]}).status_code == 400
    # hors ligne au lancement manuel
    m.h.avance(HORS_LIGNE_S + 1)
    assert c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["maillage:gk5"]}).status_code == 409
    # action seule : hors catalogue, renommer (action seule de la console, jamais par le moteur), paramètres invalides
    m.s.vu(GK5, {})
    assert c.post("/executions/action", json={"action": "shell", "cibles": ["maillage:gk5"]}).status_code == 400
    assert c.post("/executions/action", json={"action": "renommer", "args": {"nom": "gk9"}, "cibles": ["maillage:gk5"],
                                              "confirmations": {"maillage:gk5": "gk5"}}).status_code == 400
    assert c.post("/executions/action", json={"action": "service-redemarrer", "args": {"unite": "x; id"},
                                              "cibles": ["maillage:gk5"]}).status_code == 400
    assert c.post("/executions/action", json={"action": "reboot", "cibles": ["maillage:gk5"]}).status_code == 400
    assert m.s.executions() == [] and m.moteur.taches == {}


@pytest.mark.asyncio
async def test_action_seule_passe_par_executer_action(m):
    async with m.client() as c:
        r = await c.post("/executions/action", json={"action": "service-redemarrer", "args": HUB, "cibles": ["gk5"]})
        assert r.status_code == 202, r.text
        ident = r.json()["execution"]
        rq = await m.repondre(GK5, {"etat": "accepte", "job": JOB, "raison": ""})
        assert rq["body"]["command"] == CATALOGUE["service-redemarrer"].commande and rq["body"]["args"]["unite"] == HUB["unite"]
        # une seule exécution par box : l'action manuelle sur une box tenue par une exécution est refusée
        r = await c.post("/boxes/gk5/actions/service-redemarrer", json={"args": HUB})
        assert r.status_code == 409 and "exécution" in r.json()["detail"]
        assert (await c.post("/executions/action", json={"action": "maj-paquets", "cibles": ["gk5"]})).status_code == 409
        while not any(e == "pilotage_action" and ch["etat"] == "accepte" for e, ch in m.lignes):
            await asyncio.sleep(0.01)
        m.s.operation_fin(GK5.cle, JOB, 0, "fait")
        e = await m.fin(ident)
    assert e["etat"] == "terminee" and e["macro_id"] is None and e["macro_nom"] == "service-redemarrer"
    assert e["etapes"][0]["etat"] == "ok" and e["etapes"][0]["resultat"]["rc"] == 0
    actions = [(ch["action"], ch["etat"], ch["acteur"]) for ev, ch in m.lignes if ev == "pilotage_action"]
    assert actions == [("service-redemarrer", "demande", "alice"), ("service-redemarrer", "accepte", "alice")]
    assert m.macros_auditees() == ["lancement", "fin"]
    # la box libérée, l'action manuelle repasse
    assert m.moteur.occupees() == set()


@pytest.mark.asyncio
async def test_arreter(m):
    mise_a_jour = "livree:mise-a-jour-sure"
    async with m.client() as c:
        ident = (await c.post(f"/macros/{mise_a_jour}/lancer", json={"cibles": ["gk5"]})).json()["execution"]
        while not any(e == "pilotage_releve_demande" for e, _ in m.lignes):    # la première étape est partie
            await asyncio.sleep(0.01)
        r = await c.post(f"/executions/{ident}/arreter")
        assert r.status_code == 202 and r.json() == {"arret": "demande"}
        await m.releve_rendu()            # l'étape en cours (relevé « avant ») finit ; rien d'autre ne part
        e = await m.fin(ident)
        assert e["etat"] == "arretee"
        assert [x["etat"] for x in e["etapes"]] == ["ok", "non_lancee", "non_lancee", "non_lancee", "non_lancee"]
        assert (await c.post(f"/executions/{ident}/arreter")).status_code == 409
        assert (await c.post("/executions/999/arreter")).status_code == 404
    arret = next(ch for ev, ch in m.lignes if ev == "pilotage_macro" and ch["evenement"] == "arret")
    assert arret["par"] == "alice"


@pytest.mark.asyncio
async def test_flux_relaie_macro_et_operation(m):
    precoce = m.diffusion.abonner("bob", cle_flux(1))     # abonné avant le lancement : voit aussi « lancement »
    async with m.client() as c:
        ident = (await c.post("/executions/action", json={"action": "service-redemarrer", "args": HUB, "cibles": ["gk5"]})).json()["execution"]
        assert ident == 1
        f = m.flux(ident)
        etat = (await f.evenements(1))[0]                  # les `macro` déjà partis avant l'abonnement ne sont pas rejoués
        assert etat == ("etat", {"execution": ident, "connecte": True, "etat": "en_cours"})
        await m.repondre(GK5, {"etat": "accepte", "job": JOB, "raison": ""})
        while not any(e == "pilotage_action" and ch["etat"] == "accepte" for e, ch in m.lignes):
            await asyncio.sleep(0.01)
        m.diffusion.publier(GK5.cle, "notify", {"type": "X_SECUBOX_OperationProgress"})    # pas relayé : seulement `operation`
        m.s.operation_fin(GK5.cle, JOB, 0, "fait")
        await m.fin(ident)
        await asyncio.wait_for(f.t, 3)                    # le flux se ferme de lui-même après `fin`
        ev = await f.evenements(1)
    noms = [(n, d.get("evenement") or d.get("action")) for n, d in ev[1:]]
    assert noms[-1] == ("macro", "fin") and ev[-1][1]["etat"] == "terminee"
    assert ("operation", "service-redemarrer") in noms and ("macro", "box") in noms and ("macro", "etape") in noms
    assert noms.index(("operation", "service-redemarrer")) < noms.index(("macro", "fin"))
    assert all(n in ("macro", "operation") for n, _ in noms)
    assert m.diffusion.total() == 1                       # le flux de la page est libéré ; reste l'abonné précoce
    premier = await precoce.suivant(0)
    assert premier[0] == "macro" and premier[1]["evenement"] == "lancement"
    m.diffusion.liberer(precoce)


@pytest.mark.asyncio
async def test_flux_d_une_execution_finie_rend_la_fin_et_se_ferme(m):
    """Review Focus : page rechargée après la fin — l'état final puis la fermeture, aucune connexion pendue (4 places par login)."""
    async with m.client() as c:
        ident = (await c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]})).json()["execution"]
        await m.releve_rendu()
        await m.fin(ident)
    f = m.flux(ident)
    await asyncio.wait_for(f.t, 3)                        # fermé par le serveur, sans déconnexion du client
    ev = await f.evenements(2)
    assert f.statut == 200 and [n for n, _ in ev] == ["etat", "macro"]
    assert ev[0][1] == {"execution": ident, "connecte": True, "etat": "terminee"}
    assert ev[1][1]["evenement"] == "fin" and ev[1][1]["etat"] == "terminee" and ev[1][1]["execution"] == ident
    assert m.diffusion.total() == 0
    f = m.flux(999)
    await asyncio.wait_for(f.t, 3)
    assert f.statut == 404 and m.diffusion.total() == 0


@pytest.mark.asyncio
async def test_flux_cinquieme_ferme_le_plus_ancien(m):
    async with m.client() as c:
        ident = (await c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]})).json()["execution"]
        flux = []
        for _ in range(4):                                # ouverts l'un après l'autre : l'ordre d'abonnement est connu
            flux.append(m.flux(ident))
            await flux[-1].evenements(1)
        assert m.diffusion.compte("alice") == 4
        cinquieme = m.flux(ident)
        await cinquieme.evenements(1)
        await asyncio.wait_for(flux[0].t, 3)              # le plus ancien est clos
        assert m.diffusion.compte("alice") == 4 and not any(f.t.done() for f in flux[1:])
        await m.releve_rendu()
        await m.fin(ident)
        for f in [*flux[1:], cinquieme]:
            await asyncio.wait_for(f.t, 3)
            assert (await f.evenements(2))[-1][1]["evenement"] == "fin"
    assert m.diffusion.total() == 0


@pytest.mark.asyncio
async def test_flux_session_expiree_coupe(tmp_path, monkeypatch):
    w = Monde(tmp_path, monkeypatch, battement_s=0.05)
    async with w.client() as c:
        ident = (await c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]})).json()["execution"]
        f = w.flux(ident)
        while ("#", "battement") not in await f.evenements(1):
            await asyncio.sleep(0.01)
        w.session_ok = False
        await asyncio.wait_for(f.t, 3)
        ev = await f.evenements(1)
        assert ev[-1] == ("etat", {"execution": ident, "session": "expiree"})
        await w.releve_rendu()
        await w.fin(ident)
    assert w.diffusion.total() == 0


def test_demarrage_interrompt_et_installe_les_livrees(tmp_path):
    s = StockageSqlite(tmp_path / "p")
    ancienne = s.execution_creer(None, "maj-paquets", [{"cle": "maillage:gk5", "nom": "gk5"}],
                                 [{"type": "action"}], "alice")
    lignes = []
    f = Files()
    app = creer_app_admin(s, f, Inventaire(f, s), lambda e, ch: lignes.append((e, dict(ch))))
    assert [x for x in s.macros() if x["livree"]] == []          # rien n'est semé à la création de l'application
    with TestClient(app):
        assert s.execution(ancienne)["etat"] == "interrompue"
        assert [x["id"] for x in s.macros() if x["livree"]] == [x["id"] for x in LIVREES]
        assert app.state.moteur.taches == {}
    assert s.execution(ancienne)["etapes"][0]["etat"] == "interrompue"
    fin = [ch for e, ch in lignes if e == "pilotage_macro"]
    assert len(fin) == 1 and fin[0]["evenement"] == "fin" and fin[0]["etat"] == "interrompue" and fin[0]["execution"] == ancienne


@pytest.mark.asyncio
async def test_releve_manuel_en_cours_attendu_puis_echec(m):
    async with m.client() as c:
        # un relevé manuel qui finit pendant l'attente : la macro le laisse finir, puis demande le sien
        assert (await c.post("/boxes/gk5/releve", json={"duree_s": 10})).status_code == 202
        ident = (await c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]})).json()["execution"]
        await asyncio.sleep(0.05)
        assert m.lignes.count(("pilotage_releve_demande", {"cle": GK5.cle, "acteur": "alice", "duree_s": 10})) == 1
        await m.repondre(GK5, {"output": {}})             # le relevé manuel est rendu
        await m.releve_rendu()                            # puis celui de la macro
        assert (await m.fin(ident))["etat"] == "terminee"
        # un relevé manuel tenu plus de 60 s : l'étape échoue, rien n'est demandé en plus
        assert (await c.post("/boxes/gk5/releve", json={"duree_s": 10})).status_code == 202
        ident = (await c.post(f"/macros/{DIAG}/lancer", json={"cibles": ["gk5"]})).json()["execution"]
        while m.s.execution(ident)["etat"] == "en_cours":   # le temps passe : 61 s à chaque sonde, la box reste vue
            m.h.avance(61)
            m.s.vu(GK5, {})
            await asyncio.sleep(0.02)
        e = await m.fin(ident)
        assert e["etat"] == "echec" and "relevé déjà en cours" in e["raison"]
        assert e["etapes"][0]["etat"] == "echec" and "relevé déjà en cours" in e["etapes"][0]["resultat"]["raison"]
        assert [ev for ev, _ in m.lignes].count("pilotage_releve_demande") == 3
        await m.repondre(GK5, {"output": {}})


@pytest.mark.asyncio
async def test_executant_api_change_les_refus_en_echec_d_etape(m):
    x = ExecutantApi(m.app.state.contexte)
    b = m.s.boite(GK5.cle)
    with pytest.raises(EchecEtape, match="paramètres de l'étape invalides"):
        await x.action(b, "service-redemarrer", HUB, confirmation=None, support="pas un id !", acteur="alice")
    with pytest.raises(EchecEtape, match="action inconnue"):
        await x.action(b, "shell", {}, confirmation=None, support=None, acteur="alice")
    with pytest.raises(EchecEtape, match="paramètres invalides"):
        await x.action(b, "service-redemarrer", {"unite": "x; id"}, confirmation=None, support=None, acteur="alice")
    m.h.avance(HORS_LIGNE_S + 1)
    with pytest.raises(EchecEtape, match="box hors ligne"):
        await x.action(b, "service-redemarrer", HUB, confirmation=None, support=None, acteur="alice")
    with pytest.raises(EchecEtape, match="box hors ligne"):
        await x.releve(b, 60, "alice")
    assert [e for e, _ in m.lignes] == []
