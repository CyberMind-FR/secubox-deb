# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""API VoiceStudio : gardes, délégation au ctl, limites d'usager, honnêteté du moteur (#1917)."""
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))
sys.path.insert(0, str(PKG.parents[1] / "common"))

from api import main as m  # noqa: E402
from api.moteur import Moteur, MoteurIndisponible, _normaliser_voix  # noqa: E402
from secubox_core import auth as core_auth  # noqa: E402

ADMIN = {"sub": "gandalf", "role": "admin"}
PERSONNE = {"sub": "alice"}


class CtlFaux:
    """Remplace voicestudioctl api : enregistre les requêtes, rend des réponses scriptées."""
    def __init__(self):
        self.requetes = []
        self.reponses = {}
        self.statut = {"installe": True, "lxc": "RUNNING", "moteur": True, "mode": "permanent",
                       "demarrage": False, "ip": "10.100.0.230", "port": 3900}

    def __call__(self, requete, delai):
        self.requetes.append(requete)
        r = self.reponses.get(requete["action"])
        if isinstance(r, Exception):
            raise r
        if r is not None:
            return r
        return self.statut if requete["action"] == "status" else {"ok": True, "detail": ""}

    def actions(self):
        return [r["action"] for r in self.requetes]


@pytest.fixture
def ctl(monkeypatch):
    faux = CtlFaux()
    monkeypatch.setattr(m, "_executer", faux)
    m._CACHE_STATUT.update(t=0.0, v=None)
    m._CLE.update(v="", t=0.0)
    m._DEBIT.clear()
    m._OP.update(action=None, etat="repos", debut=None, fin=None, ok=None, detail="")
    return faux


@pytest.fixture
def client(ctl):
    m.app.dependency_overrides.clear()
    yield TestClient(m.app)
    m.app.dependency_overrides.clear()


def admin():
    m.app.dependency_overrides[core_auth.require_jwt] = lambda: ADMIN
    m.app.dependency_overrides[core_auth.require_lecture] = lambda: ADMIN


def personne():
    m.app.dependency_overrides[core_auth.require_personne] = lambda: PERSONNE


class MoteurFaux:
    def __init__(self, voix=None, audio=b"RIFFaudio", texte="bonjour", panne=None):
        self._voix, self._audio, self._texte, self._panne, self.appels = voix, audio, texte, panne, []

    async def voix(self):
        if self._panne:
            raise self._panne
        return self._voix if self._voix is not None else [{"id": "lexie", "nom": "Lexie"}]

    async def dire(self, texte, voix, format_):
        self.appels.append(("dire", texte, voix, format_))
        if self._panne:
            raise self._panne
        return self._audio

    async def transcrire(self, audio, nom, langue=""):
        self.appels.append(("transcrire", len(audio), nom, langue))
        if self._panne:
            raise self._panne
        return self._texte


# ── gardes : aucune route n'est ouverte par oubli ────────────────────────────
ROUTES_ADMIN = [("get", "/detail"), ("post", "/start"), ("post", "/stop"), ("post", "/restart"), ("post", "/installer"),
                ("post", "/config"), ("post", "/publier"), ("get", "/cle"), ("post", "/cle/renouveler"),
                ("get", "/journal"), ("post", "/sauvegarde"), ("get", "/voix"),
                ("post", "/essai/dire"), ("post", "/essai/transcrire")]
ROUTES_USAGER = [("get", "/usager/etat"), ("get", "/usager/voix"),
                 ("post", "/usager/dire"), ("post", "/usager/transcrire")]


@pytest.mark.parametrize("methode,chemin", ROUTES_ADMIN + ROUTES_USAGER)
def test_aucune_route_sans_session(client, methode, chemin):
    r = getattr(client, methode)(chemin)
    assert r.status_code in (401, 403), f"{methode} {chemin} répond {r.status_code} sans session"


def test_status_est_une_lecture_gardee(client):
    """Le harnais arme le mode tableau de bord (lecture LAN) : on vérifie donc la GARDE, pas le code."""
    [route] = [r for r in m.app.routes if getattr(r, "path", "") == "/status"]
    assert {d.call for d in route.dependant.dependencies} == {core_auth.require_lecture}


def test_seule_la_sante_est_publique(client):
    assert client.get("/health").status_code == 200
    publiques = []
    for route in m.app.routes:
        deps = getattr(route, "dependant", None)
        if deps is None or not hasattr(route, "methods"):
            continue
        noms = {d.call for d in deps.dependencies}
        if not noms and route.path not in ("/health",):
            publiques.append(route.path)
    assert publiques == []


def test_les_routes_usager_exigent_une_personne_et_non_un_admin_seul():
    """Une route d'usager porte require_personne, pas require_jwt : un usager n'est pas un admin."""
    for route in m.app.routes:
        if getattr(route, "path", "").startswith("/usager/"):
            appels = {d.call for d in route.dependant.dependencies}
            assert core_auth.require_personne in appels, route.path
            assert core_auth.require_jwt not in appels, route.path


def test_les_routes_d_administration_exigent_un_admin():
    for route in m.app.routes:
        chemin = getattr(route, "path", "")
        if chemin in ("/health", "/status") or chemin.startswith("/usager/") or not hasattr(route, "methods"):
            continue
        if chemin.startswith("/openapi") or chemin.startswith("/docs") or chemin.startswith("/redoc"):
            continue
        appels = {d.call for d in route.dependant.dependencies}
        assert core_auth.require_jwt in appels, chemin


# ── statut ───────────────────────────────────────────────────────────────────
def test_statut_ne_contient_aucun_secret(client, ctl):
    admin()
    ctl.statut["cle_presente"] = True
    corps = json.dumps(client.get("/status").json())
    assert "api_key" not in corps and "Bearer" not in corps
    assert client.get("/status").json()["running"] is True


def test_status_ne_livre_pas_la_topologie_au_lecteur_du_tableau_de_bord(client, ctl):
    """Mode tableau de bord = lecteur LAN anonyme : ni IP du conteneur, ni adresses publiées, ni commit."""
    admin()
    ctl.statut.update(publier=["192.168.1.9", "10.10.0.5"], commit="3915a62cb482", donnees_mo=606.2, mandataire="active")
    corps = json.dumps(client.get("/status").json())
    for fuite in ("10.100.0.230", "192.168.1.9", "10.10.0.5", "3915a62", "606", "mandataire", "limites"):
        assert fuite not in corps, fuite


def test_detail_rend_tout_a_l_administrateur(client, ctl):
    admin()
    ctl.statut.update(publier=["192.168.1.9"], commit="3915a62cb482", donnees_mo=606.2)
    d = client.get("/detail").json()
    assert d["publier"] == ["192.168.1.9"] and d["commit"] == "3915a62cb482" and d["running"] is True
    assert "limites" in d and "operation" in d


def test_un_echec_du_ctl_est_mis_en_cache_aussi(client, ctl):
    """Un client LAN qui insiste ne doit pas relancer sudo + systemd-run à chaque requête."""
    admin()
    ctl.reponses["status"] = HTTPException(503, "voicestudioctl indisponible")
    for _ in range(5):
        client.get("/status")
    assert ctl.actions().count("status") == 1


def test_statut_dit_endormi_et_non_panne(client, ctl):
    admin()
    ctl.statut.update(lxc="STOPPED", moteur=False)
    r = client.get("/status").json()
    assert r["asleep"] is True and r["running"] is False


def test_statut_est_mis_en_cache_quelques_secondes(client, ctl):
    admin()
    client.get("/status")
    client.get("/status")
    assert ctl.actions().count("status") == 1


def test_statut_degrade_proprement_si_le_ctl_est_absent(client, ctl):
    admin()
    ctl.reponses["status"] = HTTPException(503, "voicestudioctl indisponible")
    r = client.get("/status")
    assert r.status_code == 200 and r.json()["installed"] is False and "indisponible" in r.json()["error"]


# ── opérations longues ───────────────────────────────────────────────────────
def attendre(cond, delai=3.0):
    fin = time.monotonic() + delai
    while time.monotonic() < fin:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_demarrage_rend_202_aussitot_et_s_execute_en_arriere_plan(client, ctl):
    admin()
    r = client.post("/start")
    assert r.status_code == 202 and r.json()["operation"]["action"] == "start"
    assert attendre(lambda: m._OP["etat"] == "termine")
    assert m._OP["ok"] is True
    assert ctl.requetes[0]["par"] == "gandalf"                 # l'audit nomme l'administrateur


def test_une_operation_a_la_fois(client, ctl):
    admin()
    m._OP.update(etat="en-cours", action="installer")
    assert client.post("/stop").status_code == 409


def test_echec_d_operation_est_dit_et_non_masque(client, ctl):
    admin()
    ctl.reponses["start"] = HTTPException(400, "LXC absent — voicestudioctl install")
    client.post("/start")
    assert attendre(lambda: m._OP["etat"] == "termine")
    assert m._OP["ok"] is False and "LXC absent" in m._OP["detail"]


# ── configuration ────────────────────────────────────────────────────────────
def test_config_applique_chaque_valeur_par_le_ctl(client, ctl):
    admin()
    r = client.post("/config", json={"mode": "demande", "memoire": "6G"})
    assert r.status_code == 200 and r.json()["appliques"] == {"memoire": "6G", "mode": "demande"}
    cfg = [q for q in ctl.requetes if q["action"] == "config"]
    assert {(q["cle"], q["valeur"]) for q in cfg} == {("mode", "demande"), ("memoire", "6G")}
    assert all(q["par"] == "gandalf" for q in cfg)


@pytest.mark.parametrize("corps", [{}, {"mode": "toujours"}, {"memoire": "4G; reboot"}, {"cpu_poids": 0},
                                   {"cpu_poids": 100000}, {"inactivite_s": 5}])
def test_config_refuse_les_valeurs_invalides_avant_le_ctl(client, ctl, corps):
    admin()
    assert client.post("/config", json=corps).status_code == 422
    assert "config" not in ctl.actions()


def test_config_remonte_le_refus_du_ctl(client, ctl):
    admin()
    ctl.reponses["config"] = HTTPException(400, "modèle inconnu")
    r = client.post("/config", json={"asr": "evil/model"})
    assert r.status_code == 400 and "modèle inconnu" in r.json()["detail"]


@pytest.mark.parametrize("adresses", [["8.8.8.8; reboot"], ["abc"], ["::1"], ["1.2.3"], ["192.168.1.9"] * 9])
def test_publier_refuse_les_adresses_invalides(client, ctl, adresses):
    admin()
    assert client.post("/publier", json={"adresses": adresses}).status_code == 422
    assert "publier" not in ctl.actions()


def test_publier_transmet_la_liste(client, ctl):
    admin()
    assert client.post("/publier", json={"adresses": ["192.168.1.9", "10.10.0.5"]}).status_code == 200
    q = [x for x in ctl.requetes if x["action"] == "publier"][0]
    assert q["adresses"] == ["192.168.1.9", "10.10.0.5"]


# ── clé ──────────────────────────────────────────────────────────────────────
def test_apercu_de_cle_ne_revele_pas_la_cle(client, ctl):
    admin()
    ctl.reponses["cle-apercu"] = {"presente": True, "apercu": "c5p8…SLrg"}
    r = client.get("/cle")
    assert r.json() == {"presente": True, "apercu": "c5p8…SLrg"} and r.headers["cache-control"] == "no-store"


def test_renouvellement_rend_la_cle_une_fois_sans_cache(client, ctl):
    admin()
    ctl.reponses["cle-renouveler"] = {"ok": True, "cle": "NOUVELLE-CLE"}
    m._CLE.update(v="ancienne", t=time.monotonic())
    r = client.post("/cle/renouveler")
    assert r.json()["cle"] == "NOUVELLE-CLE" and r.headers["cache-control"] == "no-store"
    assert m._CLE["v"] == ""                                       # l'ancienne n'est plus gardée en mémoire


def test_la_cle_du_moteur_est_lue_une_fois_puis_gardee_en_memoire(ctl):
    ctl.reponses["cle-interne"] = {"cle": "k1"}
    assert asyncio.run(m._cle()) == "k1" and asyncio.run(m._cle()) == "k1"
    assert ctl.actions().count("cle-interne") == 1


# ── journal, sauvegarde ──────────────────────────────────────────────────────
def test_journal_et_sauvegarde(client, ctl):
    admin()
    ctl.reponses["logs"] = {"ok": True, "lignes": ["a", "b"]}
    ctl.reponses["sauvegarde"] = {"ok": True, "detail": "/var/backups/secubox/voicestudio/voicestudio-1.tar.gz"}
    assert client.get("/journal?n=50").json()["lignes"] == ["a", "b"]
    assert client.get("/journal?n=9999").status_code == 422
    r = client.post("/sauvegarde").json()
    assert r["fichier"] == "voicestudio-1.tar.gz"                   # le nom, pas le chemin du serveur


# ── usager ───────────────────────────────────────────────────────────────────
def test_usager_etat_annonce_le_reveil_en_mode_demande(client, ctl):
    personne()
    ctl.statut.update(lxc="STOPPED", moteur=False, mode="demande")
    r = client.get("/usager/etat").json()
    assert r["disponible"] is True and r["reveil_necessaire"] is True


def test_usager_etat_ne_promet_pas_un_moteur_arrete_en_mode_permanent(client, ctl):
    personne()
    ctl.statut.update(lxc="STOPPED", moteur=False, mode="permanent")
    assert client.get("/usager/etat").json()["disponible"] is False


def test_usager_etat_n_expose_pas_les_adresses_internes(client, ctl):
    personne()
    corps = json.dumps(client.get("/usager/etat").json())
    assert "10.100.0.230" not in corps


def test_dire_rend_de_l_audio(client, monkeypatch):
    personne()
    faux = MoteurFaux()
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    r = client.post("/usager/dire", json={"texte": "Bonjour la Savoie", "voix": "lexie", "format": "wav"})
    assert r.status_code == 200 and r.content == b"RIFFaudio" and r.headers["content-type"] == "audio/wav"
    assert faux.appels == [("dire", "Bonjour la Savoie", "lexie", "wav")]


def test_dire_refuse_un_texte_trop_long_sans_appeler_le_moteur(client, monkeypatch):
    personne()
    faux = MoteurFaux()
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    monkeypatch.setattr(m, "_limites", lambda: {"texte_max": 20, "audio_max_mo": 1, "delai_s": 5})
    r = client.post("/usager/dire", json={"texte": "x" * 21})
    assert r.status_code == 413 and faux.appels == []


@pytest.mark.parametrize("corps", [{"texte": ""}, {"texte": "   "}, {"texte": "a", "format": "exe"},
                                   {"texte": "a", "voix": "../../etc/passwd"}, {"texte": "a", "voix": "x" * 80}])
def test_dire_valide_l_entree(client, monkeypatch, corps):
    personne()
    faux = MoteurFaux()
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    assert client.post("/usager/dire", json=corps).status_code in (400, 422) and faux.appels == []


def test_moteur_en_panne_est_dit_503_et_non_masque(client, monkeypatch):
    personne()
    monkeypatch.setattr(m, "_moteur", lambda: MoteurFaux(panne=MoteurIndisponible("moteur injoignable")))
    r = client.post("/usager/dire", json={"texte": "bonjour"})
    assert r.status_code == 503 and "indisponible" in r.json()["detail"]


def test_le_verrou_est_rendu_meme_en_cas_de_panne(client, monkeypatch):
    personne()
    monkeypatch.setattr(m, "_moteur", lambda: MoteurFaux(panne=MoteurIndisponible("x")))
    for _ in range(3):
        client.post("/usager/dire", json={"texte": "bonjour"})
    assert m._UN_A_LA_FOIS._value == 1


def test_debit_borne_par_personne(client, monkeypatch):
    personne()
    monkeypatch.setattr(m, "_moteur", lambda: MoteurFaux())
    codes = [client.post("/usager/dire", json={"texte": "a"}).status_code for _ in range(22)]
    assert codes[:20] == [200] * 20 and codes[20:] == [429, 429]


def test_transcrire_renvoie_le_texte(client, monkeypatch):
    personne()
    faux = MoteurFaux(texte="allume la lumière")
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    r = client.post("/usager/transcrire", files={"fichier": ("a.wav", b"RIFF" + b"0" * 100)}, data={"langue": "fr"})
    assert r.status_code == 200 and r.json() == {"texte": "allume la lumière", "vide": False, "langue": "fr"}
    assert faux.appels == [("transcrire", 104, "a.wav", "fr")]


def test_transcrire_refuse_un_audio_trop_gros_sans_appeler_le_moteur(client, monkeypatch):
    personne()
    faux = MoteurFaux()
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    monkeypatch.setattr(m, "_limites", lambda: {"texte_max": 20, "audio_max_mo": 1, "delai_s": 5})
    r = client.post("/usager/transcrire", files={"fichier": ("a.wav", b"0" * (1024 * 1024 + 1))})
    assert r.status_code == 413 and faux.appels == []


def test_transcrire_refuse_un_audio_vide_et_une_langue_suspecte(client, monkeypatch):
    personne()
    faux = MoteurFaux()
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    assert client.post("/usager/transcrire", files={"fichier": ("a.wav", b"")}).status_code == 400
    assert client.post("/usager/transcrire", files={"fichier": ("a.wav", b"x")},
                       data={"langue": "fr; drop"}).status_code == 422
    assert faux.appels == []


def test_voix_listees(client, monkeypatch):
    personne()
    monkeypatch.setattr(m, "_moteur", lambda: MoteurFaux(voix=[{"id": "a", "nom": "A"}]))
    assert client.get("/usager/voix").json() == {"voix": [{"id": "a", "nom": "A"}]}


def test_l_essai_admin_utilise_la_meme_implementation(client, monkeypatch):
    admin()
    faux = MoteurFaux()
    monkeypatch.setattr(m, "_moteur", lambda: faux)
    assert client.post("/essai/dire", json={"texte": "test"}).status_code == 200
    assert faux.appels and faux.appels[0][0] == "dire"


# ── porte du ctl ─────────────────────────────────────────────────────────────
def test_executer_envoie_du_json_sur_stdin_et_jamais_en_argument(monkeypatch):
    vu = {}

    class P:
        returncode, stdout, stderr = 0, '{"ok": true}', ""

    def faux_run(argv, **k):
        vu.update(argv=argv, entree=k.get("input"), shell=k.get("shell"))
        return P()
    monkeypatch.setattr(m.subprocess, "run", faux_run)
    m._executer({"action": "config", "cle": "asr", "valeur": "x; rm -rf /"}, 5)
    assert vu["argv"] == m.CTL_ARGV and vu["shell"] is None
    assert "rm -rf" not in " ".join(vu["argv"]) and "rm -rf" in vu["entree"]


def test_sudoers_et_argv_sont_identiques():
    """Le sudoers accorde UN argv exact : si l'API en change, la porte se ferme en silence."""
    sudoers = (PKG / "debian" / "secubox-voicestudio.sudoers").read_text()
    ligne = [ligne for ligne in sudoers.splitlines() if ligne.startswith("secubox ")][0]
    assert ligne.split("NOPASSWD: ", 1)[1] == " ".join(m.CTL_ARGV[2:])
    assert "*" not in ligne


def test_executer_rend_une_erreur_claire_si_sudo_manque(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("sudo")
    monkeypatch.setattr(m.subprocess, "run", boom)
    with pytest.raises(HTTPException) as e:
        m._executer({"action": "status"}, 5)
    assert e.value.status_code == 503


def test_executer_refuse_une_reponse_illisible(monkeypatch):
    class P:
        returncode, stdout, stderr = 0, "pas du json", ""
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: P())
    with pytest.raises(HTTPException) as e:
        m._executer({"action": "status"}, 5)
    assert e.value.status_code == 502


# ── client du moteur ─────────────────────────────────────────────────────────
def moteur_avec(handler):
    async def cle():
        return "K"
    return Moteur("http://127.0.0.1:3900", cle, 5, transport=httpx.MockTransport(handler))


def test_le_client_envoie_la_cle_en_bearer_et_le_contrat_openai():
    vus = []

    def h(req):
        vus.append(req)
        if req.url.path == "/v1/audio/speech":
            return httpx.Response(200, content=b"AUDIO")
        return httpx.Response(200, json={"text": " salut "})
    mo = moteur_avec(h)
    assert asyncio.run(mo.dire("bonjour", "lexie", "mp3")) == b"AUDIO"
    assert asyncio.run(mo.transcrire(b"abc", "a.wav", "fr")) == "salut"
    assert all(r.headers["authorization"] == "Bearer K" for r in vus)
    assert json.loads(vus[0].content) == {"model": "tts-1", "input": "bonjour", "response_format": "mp3", "voice": "lexie"}


def test_le_client_dit_moteur_injoignable():
    def h(req):
        raise httpx.ConnectError("refus")
    with pytest.raises(MoteurIndisponible):
        asyncio.run(moteur_avec(h).voix())


@pytest.mark.parametrize("code", [401, 500, 503])
def test_le_client_dit_l_erreur_du_moteur(code):
    with pytest.raises(MoteurIndisponible) as e:
        asyncio.run(moteur_avec(lambda r: httpx.Response(code)).voix())
    assert str(code) in str(e.value) or "clé" in str(e.value)


@pytest.mark.parametrize("brut,attendu", [
    (["a", "b"], [{"id": "a", "nom": "a"}, {"id": "b", "nom": "b"}]),
    ({"voices": [{"id": "x", "name": "X", "language": "fr"}]}, [{"id": "x", "nom": "X", "langue": "fr"}]),
    ({"data": [{"voice_id": "v"}]}, [{"id": "v", "nom": "v"}]),
    ({"autre": 1}, []), (None, []), ([{"sans": "id"}], []),
])
def test_normalisation_des_voix(brut, attendu):
    assert _normaliser_voix(brut) == attendu


def test_l_usager_et_l_administrateur_n_ont_pas_le_meme_verrou(client, monkeypatch):
    """Un usager qui occupe le moteur 120 s ne doit pas affamer l'essai de l'administrateur."""
    assert m._UN_A_LA_FOIS is not m._UN_A_LA_FOIS_ADMIN
    admin()
    monkeypatch.setattr(m, "_moteur", lambda: MoteurFaux())
    m._UN_A_LA_FOIS._value = 0                              # un usager tient le moteur
    try:
        assert client.post("/essai/dire", json={"texte": "test"}).status_code == 200
    finally:
        m._UN_A_LA_FOIS._value = 1


def test_la_liste_des_voix_est_a_debit_borne(client, monkeypatch):
    personne()
    monkeypatch.setattr(m, "_moteur", lambda: MoteurFaux())
    codes = [client.get("/usager/voix").status_code for _ in range(32)]
    assert codes[:30] == [200] * 30 and codes[30:] == [429, 429]


def test_le_debit_ne_grossit_pas_sans_fin(client):
    m._DEBIT.clear()
    for i in range(600):
        m._DEBIT[(f"u{i}", "dire")] = [time.time() - 120]       # tous périmés
    m._debit({"sub": "nouveau"}, "dire", 20)
    assert len(m._DEBIT) < 10


def test_les_limites_ne_relisent_pas_les_fichiers_a_chaque_appel(monkeypatch):
    m._LIMITES.update(t=0.0, v=None)
    ouverts = []
    reel = open
    monkeypatch.setattr("builtins.open", lambda f, *a, **k: (ouverts.append(str(f)), reel(f, *a, **k))[1])
    m._limites()
    n = len(ouverts)
    m._limites()
    m._limites()
    assert len(ouverts) == n
