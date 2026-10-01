# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-aggregator — sockets dédiés réservés à l'administration
CyberMind — https://cybermind.fr

Le relais /api/v1/<nom>/… vers /run/secubox/<nom>.sock ne sert un module de
_SOCKETS_ADMIN (actor) qu'à un ADMINISTRATEUR RÉEL (#1581, #1608) :

  - la GARDE : 401 sans session, 403 pour un appareil ou un non-admin, et le
    socket n'est jamais contacté ;
  - la LOGIQUE : de vrais jetons signés, une session vivante ou révoquée, un
    compte admin, un appareil au profil admin ;
  - l'EFFET : ce que le module reçoit réellement sur son socket — le chemin
    sans préfixe et `X-Sbx-Vue: complete`, jamais la valeur du client.

Le module est un faux socket HTTP qui consigne chaque requête reçue.
"""
from __future__ import annotations

import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aggregator import main as agg
from secubox_core import auth

ADMIN = "gk2"
MEMBRE = "membre"
APPAREIL = "sbx-aafc7d62d710"


class _FauxModule(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, chemin: str):
        self.recues: list[dict] = []

        serveur = self

        class _Gestionnaire(BaseHTTPRequestHandler):
            def _repondre(self):
                n = int(self.headers.get("content-length") or 0)
                corps = self.rfile.read(n) if n else b""
                serveur.recues.append({
                    "methode": self.command,
                    "chemin": self.path,
                    "vue": self.headers.get_all("X-Sbx-Vue") or [],
                    "second_facteur": self.headers.get_all("X-SecuBox-Second-Facteur") or [],
                    "relais": self.headers.get_all("X-SecuBox-Relais") or [],
                    "corps": corps.decode("utf-8", "replace"),
                })
                sortie = json.dumps({"ok": True, "chemin": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(sortie)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(sortie)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _repondre

            def address_string(self):  # socket unix : pas d'adresse cliente
                return "unix"

            def log_message(self, *a):
                pass

        super().__init__(chemin, _Gestionnaire)


@pytest.fixture
def banc(tmp_path: Path, monkeypatch):
    """Agrégateur vide + deux faux modules (actor, réservé ; demo, libre)."""
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(agg, "RUN_DIR", str(run))
    monkeypatch.setattr(agg, "CONFIG_FILE", tmp_path / "absent.toml")

    # Jetons réels, signés ; sessions vivantes tenues ici.
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-uniquement")
    monkeypatch.setattr(auth, "get_config", lambda section="": {})
    vivantes: set[str] = set()
    monkeypatch.setattr(auth, "_session_validator", lambda jti: jti in vivantes)
    comptes = {
        ADMIN: {"role": "admin", "enabled": True},
        MEMBRE: {"role": "user", "enabled": True},
        # Un appareil au profil admin reste un appareil.
        APPAREIL: {"role": "admin", "enabled": True},
    }
    monkeypatch.setattr(auth.user_store, "get_user", lambda s: comptes.get(s))
    monkeypatch.setattr(auth.user_store, "is_enabled",
                        lambda s: bool((comptes.get(s) or {}).get("enabled")))
    monkeypatch.setattr(auth.appareils, "est_admis", lambda s: s == APPAREIL)

    modules = {}
    for nom in ("actor", "radio", "demo", "vault"):
        m = _FauxModule(str(run / f"{nom}.sock"))
        threading.Thread(target=m.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        modules[nom] = m

    def jeton(sub: str, vivant: bool = True) -> str:
        tok = auth.create_token(sub)
        if vivant:
            vivantes.add(auth._decode_token(tok)["jti"])
        return tok

    client = TestClient(agg._build_app())
    try:
        yield client, modules, jeton, run
    finally:
        client.close()
        for m in modules.values():
            m.shutdown()
            m.server_close()


def _cookie(tok: str) -> dict:
    return {"Cookie": f"{auth.SESSION_COOKIE}={tok}"}


# ── La garde ──────────────────────────────────────────────────────────────


def test_actor_sans_session_401(banc):
    client, modules, _, _ = banc
    for chemin in ("actors", "actors/ACT-0001", "campaigns", "stats", "evidence/x"):
        r = client.get(f"/api/v1/actor/{chemin}")
        assert r.status_code == 401, chemin
    assert modules["actor"].recues == []


def test_actor_toutes_methodes_gardees(banc):
    client, modules, _, _ = banc
    assert client.post("/api/v1/actor/feedback/ACT-0001",
                       json={"label": "unknown"}).status_code == 401
    for methode in ("PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
        assert client.request(methode, "/api/v1/actor/actors").status_code == 401, methode
    assert modules["actor"].recues == []


def test_actor_session_appareil_profil_admin_403(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/actor/actors", headers=_cookie(jeton(APPAREIL)))
    assert r.status_code == 403
    assert modules["actor"].recues == []


def test_actor_session_membre_non_admin_403(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/actor/campaigns", headers=_cookie(jeton(MEMBRE)))
    assert r.status_code == 403
    assert modules["actor"].recues == []


def test_actor_session_revoquee_401(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/actor/actors", headers=_cookie(jeton(ADMIN, vivant=False)))
    assert r.status_code == 401
    assert modules["actor"].recues == []


def test_actor_garde_avant_recherche_du_socket(banc):
    # Sans session, la réponse ne dit pas si le module tourne.
    client, _, _, run = banc
    (run / "actor.sock").unlink()
    assert client.get("/api/v1/actor/actors").status_code == 401


def test_actor_garde_indisponible_503(banc, monkeypatch):
    client, modules, jeton, _ = banc
    monkeypatch.setattr(agg, "_garde_administration", lambda personnelle=False: None)
    r = client.get("/api/v1/actor/actors", headers=_cookie(jeton(ADMIN)))
    assert r.status_code == 503
    assert modules["actor"].recues == []


# ── L'effet : ce que le module reçoit ─────────────────────────────────────


def test_actor_admin_reel_par_cookie_vue_complete(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/actor/campaigns?x=1", headers=_cookie(jeton(ADMIN)))
    assert r.status_code == 200
    assert r.json()["chemin"] == "/campaigns?x=1"
    recue = modules["actor"].recues[-1]
    assert recue["chemin"] == "/campaigns?x=1"   # préfixe retiré : racine d'actord
    assert recue["vue"] == ["complete"]


def test_actor_admin_reel_par_bearer_vue_complete(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/actor/actors",
                   headers={"Authorization": f"Bearer {jeton(ADMIN)}"})
    assert r.status_code == 200
    assert modules["actor"].recues[-1]["vue"] == ["complete"]


def test_actor_admin_reel_feedback_relaye(banc):
    client, modules, jeton, _ = banc
    r = client.post("/api/v1/actor/feedback/ACT-0001", json={"label": "unknown"},
                    headers=_cookie(jeton(ADMIN)))
    assert r.status_code == 200
    recue = modules["actor"].recues[-1]
    assert (recue["methode"], recue["chemin"]) == ("POST", "/feedback/ACT-0001")
    assert json.loads(recue["corps"]) == {"label": "unknown"}
    assert recue["vue"] == ["complete"]


def test_actor_entete_de_vue_du_client_remplace(banc):
    client, modules, jeton, _ = banc
    # Un admin qui envoie une autre valeur reçoit quand même UNE vue, la complète.
    r = client.get("/api/v1/actor/actors",
                   headers={**_cookie(jeton(ADMIN)), "X-Sbx-Vue": "reduite"})
    assert r.status_code == 200
    assert modules["actor"].recues[-1]["vue"] == ["complete"]
    # Sans session, l'en-tête du client n'ouvre rien.
    n = len(modules["actor"].recues)
    r = client.get("/api/v1/actor/actors", headers={"X-Sbx-Vue": "complete"})
    assert r.status_code == 401
    assert len(modules["actor"].recues) == n


# ── Les autres modules ne changent pas ────────────────────────────────────


def test_module_libre_inchange_sans_session(banc):
    client, modules, _, _ = banc
    r = client.get("/api/v1/demo/etat")
    assert r.status_code == 200
    assert modules["demo"].recues[-1]["chemin"] == "/etat"


def test_module_libre_ne_recoit_pas_l_entete_de_vue(banc):
    client, modules, _, _ = banc
    client.get("/api/v1/demo/etat", headers={"X-Sbx-Vue": "complete"})
    assert modules["demo"].recues[-1]["vue"] == []


def test_module_absent_404(banc):
    client, _, _, _ = banc
    assert client.get("/api/v1/inexistant/etat").status_code == 404


# ── radio (#1800) : la vue sysop ne s'ouvre qu'à un administrateur réel ─────
def test_radio_sans_session_401_et_module_jamais_contacte(banc):
    client, modules, _, _ = banc
    for chemin in ("chat", "current", "propositions", "stats", "suivante"):
        r = client.get(f"/api/v1/radio/{chemin}",
                       headers={"X-Forwarded-For": "8.8.8.8"})
        assert r.status_code == 401, chemin
    assert client.post("/api/v1/radio/suivante").status_code == 401
    assert modules["radio"].recues == []


def test_radio_session_appareil_403(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/radio/chat", headers=_cookie(jeton(APPAREIL)))
    assert r.status_code == 403
    assert modules["radio"].recues == []


def test_radio_admin_reel_relaye(banc):
    client, modules, jeton, _ = banc
    r = client.get("/api/v1/radio/chat", headers=_cookie(jeton(ADMIN)))
    assert r.status_code == 200
    assert modules["radio"].recues[-1]["chemin"] == "/chat"


# ── Le Coffre (#1367) ─────────────────────────────────────────────────────────


def test_coffre_relaye_aux_seuls_administrateurs(banc):
    """Le Coffre n'est jamais monté ici ; son relais se ferme sans session
    d'administrateur réel, quelle que soit la méthode."""
    client, _, _, _ = banc
    assert "vault" in agg._SOCKETS_ADMIN
    for methode, chemin in (("GET", "etat"), ("POST", "ouvrir"), ("POST", "sceller"),
                            ("GET", "secrets"), ("DELETE", "secrets/box/x"), ("GET", "journal")):
        assert client.request(methode, f"/api/v1/vault/{chemin}").status_code == 401, chemin



def test_coffre_ouverture_hors_lan_totp_verifie_ici(banc, monkeypatch):
    """P4 : hors LAN, le TOTP se vérifie dans l'agrégateur (plancher anti-rejeu),
    qui seul pose X-SecuBox-Second-Facteur ; celui d'un client est retiré."""
    from secubox_core import second_facteur
    client, modules, jeton, _ = banc
    codes = []
    monkeypatch.setattr(second_facteur, "verifie_totp", lambda qui, code: codes.append((qui, code)) or code == "123456")
    monkeypatch.setattr(second_facteur, "otp_lan", lambda: "facultatif")
    h = {"Authorization": f"Bearer {jeton(ADMIN)}", "X-SecuBox-LAN": "0"}
    r = client.post("/api/v1/vault/ouvrir", json={"secret": "x"}, headers=h)
    assert r.status_code == 401 and modules["vault"].recues == []
    r = client.post("/api/v1/vault/ouvrir", json={"secret": "x", "otp": "000000"},
                    headers={**h, "X-SecuBox-Second-Facteur": "verifie"})
    assert r.status_code == 401 and modules["vault"].recues == []     # l'en-tête forgé ne suffit pas
    r = client.post("/api/v1/vault/ouvrir", json={"secret": "x", "otp": "123456"}, headers=h)
    assert r.status_code == 200 and modules["vault"].recues[-1]["second_facteur"] == ["verifie"]
    assert codes[-1] == (ADMIN, "123456")
    # Ailleurs que /ouvrir, et même avec l'en-tête forgé : jamais relayé tel quel.
    client.get("/api/v1/vault/etat", headers={**h, "X-SecuBox-Second-Facteur": "verifie"})
    assert modules["vault"].recues[-1]["second_facteur"] == []


def test_coffre_lan_sans_second_facteur_si_la_politique_le_permet(banc, monkeypatch):
    from secubox_core import second_facteur
    client, modules, jeton, _ = banc
    monkeypatch.setattr(second_facteur, "otp_lan", lambda: "facultatif")
    h = {"Authorization": f"Bearer {jeton(ADMIN)}", "X-SecuBox-LAN": "1"}
    assert client.post("/api/v1/vault/ouvrir", json={"secret": "x"}, headers=h).status_code == 200
    assert modules["vault"].recues[-1]["second_facteur"] == []


def test_coffre_cinq_codes_faux_puis_429(banc, monkeypatch):
    from secubox_core import second_facteur
    client, modules, jeton, _ = banc
    monkeypatch.setattr(agg, "_echecs_otp", {})
    monkeypatch.setattr(second_facteur, "verifie_totp", lambda qui, code: False)
    h = {"Authorization": f"Bearer {jeton(ADMIN)}", "X-SecuBox-LAN": "0"}
    for _ in range(5):
        assert client.post("/api/v1/vault/ouvrir", json={"secret": "x", "otp": "1"}, headers=h).status_code == 401
    assert client.post("/api/v1/vault/ouvrir", json={"secret": "x", "otp": "1"}, headers=h).status_code == 429


# ── Le compartiment d'une personne (Coffre P5) ────────────────────────────────


def test_coffre_moi_relaye_a_une_personne_le_reste_aux_administrateurs(banc):
    """`vault/moi…` s'ouvre à une PERSONNE (le Coffre exige ensuite sa
    serrure) ; tout le reste du Coffre reste aux administrateurs réels."""
    client, modules, jeton, _ = banc
    porteur = {"Authorization": f"Bearer {jeton(MEMBRE)}"}
    assert client.get("/api/v1/vault/moi", headers=porteur).status_code == 200
    r = client.post("/api/v1/vault/moi/secrets/lister", json={"ouverture": {"secret": "x"}}, headers=porteur)
    assert r.status_code == 200 and modules["vault"].recues[-1]["chemin"] == "/moi/secrets/lister"
    n = len(modules["vault"].recues)
    for methode, chemin in (("GET", "etat"), ("POST", "ouvrir"), ("GET", "secrets"),
                            ("GET", "moitie"), ("GET", "journal")):
        assert client.request(methode, f"/api/v1/vault/{chemin}", headers=porteur).status_code == 403, chemin
    assert len(modules["vault"].recues) == n          # jamais contacté


def test_coffre_moi_sans_session_401_et_invite_403(banc, monkeypatch):
    client, modules, jeton, _ = banc
    assert client.get("/api/v1/vault/moi").status_code == 401
    avant = auth.user_store.get_user
    monkeypatch.setattr(auth.user_store, "get_user",
                        lambda s: {"role": "guest", "enabled": True} if s == "invite" else avant(s))
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda s: True)
    r = client.get("/api/v1/vault/moi", headers={"Authorization": f"Bearer {jeton('invite')}"})
    assert r.status_code == 403 and modules["vault"].recues == []


# ── La connexion ouvre le Coffre (#1855) : jamais par le relais web ───────────


def test_coffre_compte_jamais_par_le_relais(banc):
    client, modules, jeton, _ = banc
    porteur = {"Authorization": f"Bearer {jeton(ADMIN)}"}
    for chemin in ("compte/preparer", "compte/confirmer", "compte/changer", "compte"):
        r = client.post(f"/api/v1/vault/{chemin}", json={"utilisateur": "gk2", "mot_de_passe": "x"}, headers=porteur)
        assert r.status_code == 404, chemin
    assert modules["vault"].recues == []


def test_coffre_relais_marque_et_marque_du_client_remplacee(banc):
    client, modules, jeton, _ = banc
    h = {"Authorization": f"Bearer {jeton(ADMIN)}", "X-SecuBox-Relais": "forge"}
    assert client.get("/api/v1/vault/etat", headers=h).status_code == 200
    assert modules["vault"].recues[-1]["relais"] == ["agregateur"]     # la marque du relais, pas celle du client
    client.get("/api/v1/demo/x", headers={"X-SecuBox-Relais": "forge"})
    assert modules["demo"].recues[-1]["relais"] == []
