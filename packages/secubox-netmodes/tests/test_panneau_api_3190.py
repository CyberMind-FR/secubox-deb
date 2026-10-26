# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3190 — API du panneau Réseau : actions de port (anti-coupure de son propre accès), application et retour du mode
routeur en tâche de fond (202 + dernier résultat), état enrichi (échéance réelle du minuteur, bascule en cours), lecteur
anonyme sans acteur et mis en cache, `wan` refusé, est_mochabin fermé par défaut."""
import ast
import fcntl
import json
import os
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import secubox_core.config as _cfg

_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main, ports_api, routeur_api, routeur_ctl as rc  # noqa: E402

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402
from test_routeur_ctl_3189 import cp, preparer_racine, tenir  # noqa: E402

CTL = "/usr/sbin/netmodesctl"
VRAI_EST_MOCHABIN = routeur_api.est_mochabin                    # avant tout monkeypatch des fixtures
CONFIG = {"adresse": "192.168.77.1/24", "dhcp_debut": "192.168.77.100", "dhcp_fin": "192.168.77.199"}
ETAT = {"etat": "actif", "depuis": "2026-10-26T15:00:00Z", "acteur": "alice", "sauvegarde": "20261026T150000Z",
        "config": {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100", "dhcp_fin": "192.168.42.199",
                   "bail": "12h", "ports": ["lan0", "lan1", "lan2", "lan3"], "wan": "eth2"},
        "minuteur_actif": True, "dhcp_actif": True, "adresses_pont": ["192.168.255.1/24", "192.168.42.1/24"],
        "ports_coupes": [], "echeance": "2026-10-26T15:03:00Z", "bascule_en_cours": False}
POSTE = "192.168.42.50"
MAC_POSTE = "d4:93:90:27:a7:dd"
VOISINS = [{"dst": POSTE, "lladdr": MAC_POSTE.upper(), "state": ["REACHABLE"]},
           {"dst": "192.168.42.60", "lladdr": "dc:a6:32:e6:74:e1", "state": ["STALE"]},
           {"dst": "fe80::1", "lladdr": "aa:bb:cc:00:00:01", "state": ["STALE"]}]
FDB = [{"mac": MAC_POSTE, "ifname": "lan1", "master": "br-lan", "state": ""},
       {"mac": "dc:a6:32:e6:74:e1", "ifname": "lan3", "master": "br-lan", "state": ""},
       {"mac": "f0:ad:4e:27:88:9a", "ifname": "lan2", "master": "br-lan", "state": "permanent"},
       {"mac": MAC_POSTE, "ifname": "lan2", "flags": ["self"], "state": "permanent"}]


class Systeme:
    """Faux subprocess.run : sudo → réponses scriptées, dans l'ordre ; `ip -j neigh` et `bridge -j fdb` → tables du LAN.
    Toute autre commande fait échouer le test. `bloquer` (Event) : sudo attend d'être relâché (bascule longue)."""

    def __init__(self, reponses=(), voisins=None, fdb=None):
        self.reponses = list(reponses)
        self.voisins = VOISINS if voisins is None else voisins
        self.fdb = FDB if fdb is None else fdb
        self.appels: list[tuple[list[str], dict]] = []
        self.en_echec: set[str] = set()
        self.bloquer: threading.Event | None = None
        self.entre = threading.Event()
        self._verrou = threading.Lock()

    def __call__(self, argv, **kw):
        with self._verrou:
            self.appels.append((list(argv), kw))
        if argv[:2] == ["sudo", "-n"]:
            self.entre.set()
            if self.bloquer is not None:
                assert self.bloquer.wait(10)
            r = self.reponses.pop(0)
            if isinstance(r, Exception):
                raise r
            code, sortie = r
            return subprocess.CompletedProcess(argv, code, stdout=sortie if isinstance(sortie, str)
                                               else json.dumps(sortie), stderr="")
        if argv == ["ip", "-j", "neigh", "show", "dev", "br-lan"]:
            cle = "voisins"
        elif argv == ["bridge", "-j", "fdb", "show", "br", "br-lan"]:
            cle = "fdb"
        else:
            raise AssertionError(f"commande inattendue : {argv}")
        assert kw.get("timeout") and kw.get("capture_output") and kw.get("text") and not kw.get("shell"), kw
        if cle in self.en_echec:
            return subprocess.CompletedProcess(argv, 1, "", 'Device "br-lan" does not exist.\n')
        return subprocess.CompletedProcess(argv, 0, json.dumps(getattr(self, cle)), "")

    def sudo(self) -> list[list[str]]:
        return [a for a, _ in self.appels if a[:2] == ["sudo", "-n"]]

    def lectures(self) -> list[list[str]]:
        return [a for a, _ in self.appels if a[:2] != ["sudo", "-n"]]


def attendre_fin():
    fil = routeur_api._fil
    if fil is not None:
        fil.join(10)
        assert not fil.is_alive()


@pytest.fixture
def pont(tmp_path, monkeypatch):
    p = tmp_path / "br-lan"
    p.mkdir()
    monkeypatch.setattr(ports_api, "PONT_SYS", p)
    return p


@pytest.fixture
def client(monkeypatch, pont):
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "alice"}
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    monkeypatch.setattr(routeur_api, "est_mochabin", lambda: False)
    routeur_api._reinitialiser()
    yield TestClient(main.app, base_url="http://testserver")
    attendre_fin()
    main.app.dependency_overrides.clear()
    routeur_api._reinitialiser()


def faux(monkeypatch, reponses=(), **kw) -> Systeme:
    s = Systeme(reponses, **kw)
    monkeypatch.setattr(routeur_api.subprocess, "run", s)
    return s


def anonyme():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}


# --- application et retour en tâche de fond ----------------------------------------------------------------------------

def test_appliquer_202_puis_fil_avec_argv_exact(client, monkeypatch):
    s = faux(monkeypatch, [(0, {**ETAT, "etat": "en_attente", "delai_confirmation": 180})])
    r = client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    assert r.status_code == 202 and r.json() == {"lancee": True}
    attendre_fin()
    assert len(s.appels) == 1                                   # rien de synchrone : ni état, ni aperçu
    argv, kw = s.appels[0]
    assert argv == ["sudo", "-n", CTL, "routeur-appliquer", "alice"]
    assert json.loads(kw["input"]) == CONFIG and kw["check"] is False and kw["capture_output"] and kw["text"]
    assert kw["timeout"] == routeur_api.DELAI_FOND > routeur_api.DELAI_CTL


def test_derniere_apres_fin(client, monkeypatch):
    assert client.get("/routeur/derniere").json() == {"verbe": None, "code": None, "sortie": None, "fini": True,
                                                      "debut": None, "fin": None}
    sortie = {**ETAT, "etat": "en_attente", "delai_confirmation": 180}
    faux(monkeypatch, [(0, sortie)])
    client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"})
    attendre_fin()
    d = client.get("/routeur/derniere").json()
    assert d["verbe"] == "routeur-appliquer" and d["code"] == 200 and d["sortie"] == sortie and d["fini"] is True
    for cle in ("debut", "fin"):
        datetime.strptime(d[cle], "%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize("code, detail, http", [
    (3, "réseau interdit", 409), (4, "une application est déjà en cours", 409), (2, "acteur", 400), (1, "boum", 502)])
def test_derniere_garde_l_echec_du_controleur(client, monkeypatch, code, detail, http):
    faux(monkeypatch, [(code, {"erreur": detail if code != 4 else "occupé"})])
    assert client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"}).status_code == 202
    attendre_fin()
    d = client.get("/routeur/derniere").json()
    assert (d["code"], d["sortie"], d["fini"]) == (http, {"erreur": detail}, True)


def test_derniere_delai_et_exception(client, monkeypatch):
    faux(monkeypatch, [subprocess.TimeoutExpired("sudo", 2400)])
    client.post("/routeur/retour", json={"confirmer": "retour"})
    attendre_fin()
    d = client.get("/routeur/derniere").json()
    assert d["code"] == 502 and d["fini"] is True and "à temps" in d["sortie"]["erreur"]
    faux(monkeypatch, [RuntimeError("imprévu")])               # filet : jamais « en cours » pour toujours
    client.post("/routeur/retour", json={"confirmer": "retour"})
    attendre_fin()
    d = client.get("/routeur/derniere").json()
    assert d["code"] == 500 and d["fini"] is True and "RuntimeError" in d["sortie"]["erreur"]


def test_retour_202_argv_exact(client, monkeypatch):
    s = faux(monkeypatch, [(0, {**ETAT, "etat": "inactif"})])
    r = client.post("/routeur/retour", json={"confirmer": "retour"})
    assert r.status_code == 202 and r.json() == {"lancee": True}
    attendre_fin()
    assert s.sudo() == [["sudo", "-n", CTL, "routeur-retour", "alice"]]
    assert client.get("/routeur/derniere").json()["verbe"] == "routeur-retour"


def test_une_seule_bascule_a_la_fois(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT), (0, ETAT)])
    s.bloquer = threading.Event()
    assert client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"}).status_code == 202
    assert s.entre.wait(5)
    d = client.get("/routeur/derniere").json()
    assert d["verbe"] == "routeur-appliquer" and d["fini"] is False and d["code"] is None and d["fin"] is None
    for chemin, corps in (("/routeur/appliquer", {**CONFIG, "confirmer": "routeur"}),
                          ("/routeur/retour", {"confirmer": "retour"})):
        r = client.post(chemin, json=corps)
        assert r.status_code == 409 and r.json()["detail"] == "une bascule est déjà en cours", chemin
    for verbe in ("couper", "retablir"):                       # une action de port attend la fin de la bascule
        r = client.post(f"/ports/lan2/{verbe}", json={"confirmer": "lan2"})
        assert r.status_code == 409 and "bascule" in r.json()["detail"], verbe
    assert len(s.sudo()) == 1 and s.lectures() == []
    s.bloquer.set()
    attendre_fin()
    assert client.post("/routeur/retour", json={"confirmer": "retour"}).status_code == 202   # libre à nouveau
    attendre_fin()


def test_validation_avant_tout_sudo(client, monkeypatch):
    s = faux(monkeypatch, [])
    for corps in (CONFIG, {**CONFIG, "confirmer": "oui"}, {**CONFIG, "confirmer": "routeur", "wan": "eth2"},
                  {**CONFIG, "confirmer": "routeur", "adresse": "192.168.255.1/24"},
                  {"confirmer": "routeur"}):
        assert client.post("/routeur/appliquer", json=corps).status_code == 400, corps
    for corps in ({}, {"confirmer": "routeur"}):
        assert client.post("/routeur/retour", json=corps).status_code == 400, corps
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "a b;rm"}
    assert client.post("/routeur/appliquer", json={**CONFIG, "confirmer": "routeur"}).status_code == 400
    assert client.post("/routeur/retour", json={"confirmer": "retour"}).status_code == 400
    assert s.appels == [] and routeur_api._fil is None
    assert client.get("/routeur/derniere").json()["verbe"] is None


def test_wan_400_meme_eth2(client, monkeypatch):
    s = faux(monkeypatch, [])
    assert "wan" not in routeur_api.CLES_CONFIG
    for chemin in ("/routeur/apercu", "/routeur/appliquer"):
        for wan in ("eth2", "eth0"):
            r = client.post(chemin, json={**CONFIG, "confirmer": "routeur", "wan": wan})
            assert r.status_code == 400 and "eth2" in r.json()["detail"], (chemin, wan)
    assert s.appels == []


# --- état : lecteur anonyme, cache, échéance -----------------------------------------------------------------------------

def test_etat_anonyme_sans_acteur_ni_sauvegarde_et_un_seul_sudo(client, monkeypatch):
    anonyme()
    s = faux(monkeypatch, [(0, ETAT)])
    r1, r2 = client.get("/routeur/etat"), client.get("/routeur/etat")
    assert r1.status_code == r2.status_code == 200 and r1.json() == r2.json()
    assert s.sudo() == [["sudo", "-n", CTL, "routeur-etat"]]                # deux lectures en < 5 s : un sudo
    e = r1.json()
    assert "acteur" not in e and "sauvegarde" not in e and "alice" not in r1.text
    assert e["echeance"] == "2026-10-26T15:03:00Z" and e["bascule_en_cours"] is False
    assert {k: e[k] for k in ("etat", "depuis", "config", "minuteur_actif", "dhcp_actif", "adresses_pont",
                              "ports_coupes")} == {k: ETAT[k] for k in ("etat", "depuis", "config", "minuteur_actif",
                                                                       "dhcp_actif", "adresses_pont", "ports_coupes")}


def test_etat_anonyme_cache_de_5_s(client, monkeypatch):
    anonyme()
    t = [100.0]
    monkeypatch.setattr(routeur_api, "_monotone", lambda: t[0])
    s = faux(monkeypatch, [(0, ETAT), (0, {**ETAT, "etat": "en_attente"})])
    assert client.get("/routeur/etat").json()["etat"] == "actif"
    t[0] += 4.9
    assert client.get("/routeur/etat").json()["etat"] == "actif" and len(s.sudo()) == 1
    t[0] += 0.2
    assert client.get("/routeur/etat").json()["etat"] == "en_attente" and len(s.sudo()) == 2


def test_etat_anonyme_cle_inconnue_tue(client, monkeypatch):
    anonyme()
    faux(monkeypatch, [(0, {**ETAT, "nouvelle_cle": "secret"})])
    assert "nouvelle_cle" not in client.get("/routeur/etat").json()       # liste blanche, pas liste noire


def test_etat_anonyme_panne_aussi_en_cache(client, monkeypatch):
    anonyme()
    s = faux(monkeypatch, [(1, {"erreur": "boum"})])
    for _ in range(3):
        r = client.get("/routeur/etat")
        assert r.status_code == 502 and "boum" in r.json()["detail"]
    assert len(s.sudo()) == 1


def test_etat_admin_complet_jamais_la_copie_anonyme(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT), (0, ETAT), (0, ETAT)])
    anonyme()
    assert "acteur" not in client.get("/routeur/etat").json()
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    for _ in range(2):                                          # administrateur : complet, jamais depuis le cache anonyme
        e = client.get("/routeur/etat").json()
        assert e["acteur"] == "alice" and e["sauvegarde"] == ETAT["sauvegarde"] and e["echeance"] == ETAT["echeance"]
    anonyme()
    assert "acteur" not in client.get("/routeur/etat").json()   # et l'anonyme ne reçoit jamais la copie complète
    assert len(s.sudo()) == 3
    assert all(a == ["sudo", "-n", CTL, "routeur-etat"] for a in s.sudo())


def test_etat_admin_puis_anonyme(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT), (0, ETAT)])
    assert client.get("/routeur/etat").json()["acteur"] == "alice"
    anonyme()
    assert "acteur" not in client.get("/routeur/etat").json() and len(s.sudo()) == 2


# --- aperçu : avertissement ------------------------------------------------------------------------------------------------

def test_apercu_avertissement_depuis_le_lan(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)])
    r = client.post("/routeur/apercu", json=CONFIG, headers={"X-Real-IP": POSTE})
    assert r.status_code == 200 and r.json()["fichiers"] and "3 minutes" in r.json()["avertissement"]
    assert r.json()["avertissement"] == routeur_api.AVERTISSEMENT
    assert s.sudo() == [["sudo", "-n", CTL, "routeur-etat"]]


def test_apercu_sans_avertissement(client, monkeypatch):
    faux(monkeypatch, [(0, ETAT)])
    r = client.post("/routeur/apercu", json=CONFIG, headers={"X-Real-IP": "203.0.113.9"})     # hors du LAN
    assert r.status_code == 200 and "avertissement" not in r.json()
    faux(monkeypatch, [(0, ETAT)])
    meme = {"adresse": "192.168.42.1/24", "dhcp_debut": "192.168.42.100", "dhcp_fin": "192.168.42.199"}
    r = client.post("/routeur/apercu", json=meme, headers={"X-Real-IP": POSTE})               # même réseau
    assert r.status_code == 200 and "avertissement" not in r.json()
    faux(monkeypatch, [(1, {"erreur": "x"})])                                                  # état indisponible
    r = client.post("/routeur/apercu", json=CONFIG, headers={"X-Real-IP": POSTE})
    assert r.status_code == 200 and r.json()["fichiers"] and "avertissement" not in r.json()


def test_apercu_avertissement_par_x_forwarded_for(client, monkeypatch):
    faux(monkeypatch, [(0, ETAT)])
    r = client.post("/routeur/apercu", json=CONFIG, headers={"X-Forwarded-For": f"{POSTE}, 127.0.0.1"})
    assert r.json().get("avertissement") == routeur_api.AVERTISSEMENT


def test_apercu_invalide_400_sans_sudo(client, monkeypatch):
    s = faux(monkeypatch, [])
    assert client.post("/routeur/apercu", json={**CONFIG, "adresse": "192.168.255.1/24"}).status_code == 400
    assert s.appels == []


# --- est_mochabin fermé par défaut ---------------------------------------------------------------------------------------

def test_est_mochabin_ferme_par_defaut(tmp_path, monkeypatch):
    absent, autre, lisible = tmp_path / "absent", tmp_path / "absent2", tmp_path / "model"
    monkeypatch.setattr(routeur_api, "MODELES", (absent, autre))
    assert VRAI_EST_MOCHABIN() is True                          # modèle illisible : les anciens chemins restent refusés
    monkeypatch.setattr(routeur_api, "MODELES", (absent, lisible))
    lisible.write_bytes(b"Raspberry Pi 4 Model B\x00")
    assert VRAI_EST_MOCHABIN() is False                         # le second chemin lisible fait foi
    lisible.write_bytes(b"Globalscale Technologies MOCHAbin\x00")
    assert VRAI_EST_MOCHABIN() is True


def test_anciens_chemins_refuses_sur_carte_non_identifiee(client, monkeypatch, tmp_path):
    monkeypatch.setattr(routeur_api, "MODELES", (tmp_path / "absent",))
    monkeypatch.setattr(main, "est_mochabin", VRAI_EST_MOCHABIN)
    r = client.post("/apply_mode", json={"mode": "router"})
    assert r.status_code == 409 and "WAN" in r.json()["detail"]


# --- ports : couper, rétablir ----------------------------------------------------------------------------------------------

def test_couper_le_port_de_sa_session_409_sans_controleur(client, monkeypatch):
    s = faux(monkeypatch, [])
    r = client.post("/ports/lan1/couper", json={"confirmer": "lan1"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 409
    assert r.json()["detail"] == "vous couperiez votre propre accès (votre poste est derrière lan1)"
    assert s.sudo() == []                                       # avant tout appel au contrôleur
    assert s.lectures() == [["ip", "-j", "neigh", "show", "dev", "br-lan"], ["bridge", "-j", "fdb", "show", "br", "br-lan"]]


def test_couper_lit_frais_pas_le_cache_de_reseau(client, monkeypatch):
    from api import reseau_api
    s = faux(monkeypatch, [])
    monkeypatch.setattr(reseau_api, "_cache", {"t": time.monotonic(), "valeur": {"voisins_lan": [], "fdb": []}})
    r = client.post("/ports/lan1/couper", json={"confirmer": "lan1"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 409 and len(s.lectures()) == 2      # le cache (poste inconnu) n'est pas consulté


@pytest.mark.parametrize("entetes", [
    {"X-Forwarded-For": f"{POSTE}, 127.0.0.1"},                # X-Real-IP absent : droite de X-Forwarded-For
    {"X-Real-IP": "127.0.0.1", "X-Forwarded-For": POSTE},      # nginx sans real_ip : 127.0.0.1, XFF fait foi
    {"X-Real-IP": f"::ffff:{POSTE}"},                          # IPv4 dans IPv6
])
def test_couper_reconnait_le_poste_par_toutes_ses_adresses(client, monkeypatch, entetes):
    s = faux(monkeypatch, [])
    assert client.post("/ports/lan1/couper", json={"confirmer": "lan1"}, headers=entetes).status_code == 409
    assert s.sudo() == []


def test_couper_un_autre_port_argv_exact(client, monkeypatch):
    s = faux(monkeypatch, [(0, {**ETAT, "ports_coupes": ["lan2"]})])
    r = client.post("/ports/lan2/couper", json={"confirmer": "lan2"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 200 and r.json()["ports_coupes"] == ["lan2"]
    argv, kw = s.appels[-1]
    assert argv == ["sudo", "-n", CTL, "port-couper", "lan2", "alice"]
    assert kw["timeout"] == ports_api.DELAI_PORT == 60 and kw["check"] is False and kw.get("input") is None


def test_couper_poste_hors_du_lan_autorise(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)])
    assert client.post("/ports/lan1/couper", json={"confirmer": "lan1"},
                       headers={"X-Real-IP": "10.66.0.2"}).status_code == 200      # par le maillage : pas un voisin
    assert s.sudo() == [["sudo", "-n", CTL, "port-couper", "lan1", "alice"]]
    assert s.lectures() == [["ip", "-j", "neigh", "show", "dev", "br-lan"]]          # sans MAC : pas de table de pont


def test_couper_mac_absente_de_la_fdb_autorise(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)], fdb=[f for f in FDB if f["mac"] != MAC_POSTE])
    assert client.post("/ports/lan1/couper", json={"confirmer": "lan1"},
                       headers={"X-Real-IP": POSTE}).status_code == 200
    assert len(s.sudo()) == 1


def test_couper_mac_vue_sur_le_port_seulement_en_self_autorise(client, monkeypatch):
    faux(monkeypatch, [(0, ETAT)])                              # FDB : MAC_POSTE en « self » permanent sur lan2
    assert client.post("/ports/lan2/couper", json={"confirmer": "lan2"},
                       headers={"X-Real-IP": POSTE}).status_code == 200


@pytest.mark.parametrize("source", ["voisins", "fdb"])
def test_couper_lecture_en_echec_503_sans_controleur(client, monkeypatch, source):
    s = faux(monkeypatch, [])
    s.en_echec.add(source)
    r = client.post("/ports/lan1/couper", json={"confirmer": "lan1"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 503 and "rien n'a été coupé" in r.json()["detail"]
    assert s.sudo() == []


def test_couper_sans_pont_pas_de_lecture(client, monkeypatch, pont):
    pont.rmdir()                                                # br-lan absent : personne n'est derrière l'un de ses ports
    s = faux(monkeypatch, [(3, {"erreur": "le mode routeur est « inactif »"})])
    r = client.post("/ports/lan1/couper", json={"confirmer": "lan1"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 409 and "inactif" in r.json()["detail"]                # le contrôleur explique
    assert s.lectures() == [] and len(s.sudo()) == 1


def test_retablir_sans_verification_argv_exact(client, monkeypatch):
    s = faux(monkeypatch, [(0, ETAT)])
    r = client.post("/ports/lan1/retablir", json={"confirmer": "lan1"}, headers={"X-Real-IP": POSTE})
    assert r.status_code == 200
    assert s.lectures() == [] and s.sudo() == [["sudo", "-n", CTL, "port-retablir", "lan1", "alice"]]


@pytest.mark.parametrize("port", ["eth2", "eth0", "eth1", "br-lan", "lan4", "LAN1", "lan1 ", "*"])
def test_port_hors_liste_400(client, monkeypatch, port):
    s = faux(monkeypatch, [])
    for verbe in ("couper", "retablir"):
        r = client.post(f"/ports/{port}/{verbe}", json={"confirmer": port}, headers={"X-Real-IP": "203.0.113.9"})
        assert r.status_code in (400, 404), (port, verbe)       # 404 : chemin non routé (« * », espace)
    assert s.appels == []


def test_eth2_400_explicite(client, monkeypatch):
    s = faux(monkeypatch, [])
    r = client.post("/ports/eth2/couper", json={"confirmer": "eth2"})
    assert r.status_code == 400 and "lan0" in r.json()["detail"]
    assert s.appels == []


@pytest.mark.parametrize("corps", [None, {}, {"confirmer": "lan2"}, {"confirmer": True}, ["lan1"], "lan1"])
def test_confirmation_requise_400(client, monkeypatch, corps):
    s = faux(monkeypatch, [])
    for verbe in ("couper", "retablir"):
        r = client.post(f"/ports/lan1/{verbe}", **({} if corps is None else {"json": corps}))
        assert r.status_code == 400 and '"confirmer": "lan1"' in r.json()["detail"], (corps, verbe)
    assert s.appels == []


def test_ports_acteur_invalide_400(client, monkeypatch):
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "a b;rm"}
    s = faux(monkeypatch, [])
    assert client.post("/ports/lan1/retablir", json={"confirmer": "lan1"}).status_code == 400
    assert client.post("/ports/lan2/couper", json={"confirmer": "lan2"}).status_code == 400
    assert s.appels == []


@pytest.mark.parametrize("code, http, morceau", [(3, 409, "pas un port du pont"), (4, 409, "déjà en cours"),
                                                 (2, 400, "port refusé"), (1, 502, "lan2 n'est pas coupé")])
def test_ports_codes_du_controleur(client, monkeypatch, code, http, morceau):
    erreurs = {3: "lan2 n'est pas un port du pont", 4: "occupé", 2: "port refusé", 1: "lan2 n'est pas coupé après 15 s"}
    faux(monkeypatch, [(code, {"erreur": erreurs[code]})])
    r = client.post("/ports/lan2/couper", json={"confirmer": "lan2"}, headers={"X-Real-IP": "203.0.113.9"})
    assert r.status_code == http and morceau in r.json()["detail"]


def test_port_reussi_invalide_le_cache_de_lecture(client, monkeypatch):
    from api import reseau_api
    monkeypatch.setattr(reseau_api, "_cache", {"t": time.monotonic(), "valeur": {}})
    faux(monkeypatch, [(0, ETAT)])
    client.post("/ports/lan1/retablir", json={"confirmer": "lan1"})
    assert "t" not in reseau_api._cache                         # l'onglet Switch relit l'état réel tout de suite


# --- gardes et structure ---------------------------------------------------------------------------------------------------

def test_routes_gardees():
    gardes = {}
    for mod in (routeur_api, ports_api):
        for r in mod.router.routes:
            deps = {d.call for d in r.dependant.dependencies}
            for m in r.methods:
                gardes[(m, r.path)] = deps
    for (methode, chemin), deps in gardes.items():
        if methode == "POST":
            assert require_jwt in deps, chemin
    assert require_jwt in gardes[("GET", "/routeur/derniere")]
    assert require_lecture in gardes[("GET", "/routeur/etat")]
    assert {("POST", "/ports/{port}/couper"), ("POST", "/ports/{port}/retablir")} <= set(gardes)


def test_routes_ports_montees_dans_l_app():
    chemins = {getattr(r, "path", None) for r in main.app.routes}
    assert {"/ports/{port}/couper", "/ports/{port}/retablir", "/routeur/derniere"} <= chemins


def test_pas_de_subprocess_ni_sudo_dans_async():
    for mod in (routeur_api, ports_api):
        arbre = ast.parse(Path(mod.__file__).read_text())
        for fn in ast.walk(arbre):
            if isinstance(fn, ast.AsyncFunctionDef):
                texte = ast.unparse(fn)
                assert "subprocess" not in texte and "_ctl" not in texte and "sudo" not in texte, fn.name
    for mod in (routeur_api, ports_api):                        # toutes les routes sont `def`
        for r in mod.router.routes:
            assert not __import__("inspect").iscoroutinefunction(r.endpoint), r.path


# --- contrôleur : échéance réelle du minuteur, bascule en cours ---------------------------------------------------------

FIXE = datetime(2026, 10, 26, 15, 0, 0, tzinfo=timezone.utc)
MINUTEUR = "secubox-netmodes-retour.timer"
SHOW = ["systemctl", "show", "-p", "NextElapseUSecRealtime", "-p", "NextElapseUSecMonotonic", MINUTEUR]


class SystemeEtat:
    def __init__(self, minuteur=True, show="NextElapseUSecRealtime=\nNextElapseUSecMonotonic=19min 40.5s\n",
                 code_show=0):
        self.minuteur, self.show, self.code_show = minuteur, show, code_show
        self.journal: list[list[str]] = []

    def __call__(self, argv):
        self.journal.append(list(argv))
        if argv[:3] == ["systemctl", "is-active", "--quiet"]:
            return cp(argv, 0 if argv[3] == MINUTEUR and self.minuteur else 3)
        if argv == SHOW:
            return cp(argv, self.code_show, self.show)
        if argv == ["ip", "-j", "-4", "addr", "show", "dev", "br-lan"]:
            return cp(argv, 0, "[]")
        raise AssertionError(f"commande inattendue : {argv}")


@pytest.fixture
def racine(tmp_path):
    ancien = os.umask(0o022)
    yield preparer_racine(tmp_path / "racine")
    os.umask(ancien)


def contexte(racine, systeme, monotone=1000.0):
    return rc.Contexte(racine=racine, executer=systeme, maintenant=lambda: FIXE, attendre=lambda s: None,
                       monotone=lambda: monotone)


def test_echeance_du_minuteur_monotone(racine):
    """systemd-run --on-active : minuteur MONOTONE, NextElapseUSecRealtime vide ; l'instant vient de
    NextElapseUSecMonotonic (horloge monotone depuis le démarrage), ramené à l'heure UTC."""
    s = SystemeEtat()
    e = rc.etat(contexte(racine, s, monotone=1000.0))           # 19 min 40,5 s = 1180,5 s : 180 s plus tard
    assert e["echeance"] == "2026-10-26T15:03:00Z"
    assert SHOW in s.journal
    assert s.journal.index(SHOW) == s.journal.index(["systemctl", "is-active", "--quiet", MINUTEUR]) + 1


def test_echeance_horodatage_reel_utc(racine):
    s = SystemeEtat(show="NextElapseUSecRealtime=Mon 2026-10-26 15:28:29 UTC\nNextElapseUSecMonotonic=0\n")
    assert rc.etat(contexte(racine, s))["echeance"] == "2026-10-26T15:28:29Z"


def test_echeance_horodatage_reel_heure_locale(racine):
    ancien = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Paris"
    time.tzset()
    try:
        s = SystemeEtat(show="NextElapseUSecRealtime=Mon 2026-10-26 16:28:29 CET\nNextElapseUSecMonotonic=0\n")
        assert rc.etat(contexte(racine, s))["echeance"] == "2026-10-26T15:28:29Z"
    finally:
        if ancien is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = ancien
        time.tzset()


def test_echeance_la_plus_proche_des_deux(racine):
    s = SystemeEtat(show="NextElapseUSecRealtime=Mon 2026-10-26 15:28:29 UTC\nNextElapseUSecMonotonic=17min 0s\n")
    assert rc.etat(contexte(racine, s, monotone=1000.0))["echeance"] == "2026-10-26T15:00:20Z"


@pytest.mark.parametrize("show, code", [
    ("NextElapseUSecRealtime=\nNextElapseUSecMonotonic=infinity\n", 0),     # unité absente
    ("NextElapseUSecRealtime=n/a\nNextElapseUSecMonotonic=0\n", 0),
    ("", 0), ("NextElapseUSecRealtime=demain\nNextElapseUSecMonotonic=bientôt\n", 0),
    ("NextElapseUSecRealtime=Mon 2026-10-26 15:28:29 UTC\n", 1),           # systemctl en échec
    ("NextElapseUSecRealtime=\nNextElapseUSecMonotonic=99999999999y\n", 0), # aberrant : pas de débordement
])
def test_echeance_illisible_none(racine, show, code):
    assert rc.etat(contexte(racine, SystemeEtat(show=show, code_show=code)))["echeance"] is None


def test_sans_minuteur_echeance_none_sans_appel(racine):
    s = SystemeEtat(minuteur=False)
    e = rc.etat(contexte(racine, s))
    assert e["echeance"] is None and e["minuteur_actif"] is False and SHOW not in s.journal


def test_echeance_jamais_deduite_de_depuis(racine):
    (racine / "var/lib/secubox-netmodes").mkdir(parents=True, mode=0o700)
    (racine / "var/lib/secubox-netmodes/routeur-etat.json").write_text(json.dumps(
        {"etat": "en_attente", "depuis": "2026-10-26T14:00:00Z", "acteur": "alice", "sauvegarde": None}))
    e = rc.etat(contexte(racine, SystemeEtat(show="NextElapseUSecRealtime=\nNextElapseUSecMonotonic=infinity\n")))
    assert e["etat"] == "en_attente" and e["echeance"] is None  # pas « depuis + 180 »


def test_bascule_en_cours_verrou_tenu(racine):
    verrou = racine / "run/lock/secubox-netmodes.lock"
    ctx = contexte(racine, SystemeEtat(minuteur=False))
    assert rc.etat(ctx)["bascule_en_cours"] is False and not verrou.exists()   # absent : jamais créé par une lecture
    fd = tenir(verrou)                                          # une autre opération du contrôleur
    try:
        assert rc.etat(ctx)["bascule_en_cours"] is True
    finally:
        os.close(fd)
    assert rc.etat(ctx)["bascule_en_cours"] is False
    with rc._verrou(ctx):                                       # l'essai est relâché aussitôt : le verrou reste libre
        pass


def test_bascule_en_cours_deux_lectures_ne_se_genent_pas(racine):
    verrou = racine / "run/lock/secubox-netmodes.lock"
    verrou.touch()
    fd = os.open(verrou, os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_SH)                              # une autre lecture d'état, au même instant
    try:
        assert rc.etat(contexte(racine, SystemeEtat(minuteur=False)))["bascule_en_cours"] is False
    finally:
        os.close(fd)


def test_bascule_en_cours_tube_nomme_ne_suspend_pas(racine):
    os.mkfifo(racine / "run/lock/secubox-netmodes.lock")       # /run/lock est ouvert à tous
    fil = threading.Thread(target=lambda: rc.etat(contexte(racine, SystemeEtat(minuteur=False))), daemon=True)
    fil.start()
    fil.join(5)
    assert not fil.is_alive()


def test_bascule_en_cours_lien_symbolique_inconnu(racine, tmp_path):
    cible = tmp_path / "ailleurs"
    cible.touch()
    (racine / "run/lock/secubox-netmodes.lock").symlink_to(cible)
    assert rc.etat(contexte(racine, SystemeEtat(minuteur=False)))["bascule_en_cours"] is None


def test_appliquer_rend_l_echeance_reelle_puis_confirmer_l_efface(racine):
    """Bout à bout sur le système simulé de #3189 : l'état rendu par appliquer porte l'échéance du minuteur armé
    (180 s sur l'horloge monotone) et plus de bascule en cours (verrou relâché avant l'état) ; confirmé : plus rien."""
    from test_routeur_ctl_3189 import CFG42, Faux, Horloge
    f, h = Faux(racine), Horloge()
    ctx = rc.Contexte(racine=racine, executer=f, maintenant=h, attendre=f.attendre, monotone=f.monotone)
    e = rc.appliquer(ctx, CFG42, "admin")
    assert e["etat"] == "en_attente" and e["minuteur_actif"] is True and e["bascule_en_cours"] is False
    assert e["echeance"] == (h.t + timedelta(seconds=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
    e = rc.confirmer(ctx, "admin")
    assert e["etat"] == "actif" and e["minuteur_actif"] is False and e["echeance"] is None
