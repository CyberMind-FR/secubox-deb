# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Client HTTP de l'agent vers l'infrastructure (#2187, #2188, #2189) : TLS vérifié, pas de redirection, réponses bornées, erreurs distinguées."""
import json
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "secubox-premier-pas"))
from autoload_agent import client as C, moteur as M  # noqa: E402

CLE = "P" * 43 + "="
TUNNEL = {"endpoint": "admin.gk2.secubox.in:51830", "serveur_cle_pub": "S" * 43 + "=", "adresse": "10.64.0.2/32", "hub": "10.64.0.1/32"}


class Rep:
    def __init__(self, code=200, corps=b"{}", entetes=None):
        self.status, self._c, self.headers = code, corps, entetes or {}

    def read(self, n=-1):
        return self._c if n < 0 else self._c[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Faux:
    def __init__(self, *reponses):
        self.reponses, self.vus = list(reponses), []

    def __call__(self, requete, timeout=None, context=None):
        self.vus.append((requete.get_method(), requete.full_url, requete.data, dict(requete.header_items()), timeout, context))
        r = self.reponses.pop(0)
        if isinstance(r, Exception):
            raise r
        if r.status >= 400:
            raise urllib.error.HTTPError(requete.full_url, r.status, "x", r.headers, __import__("io").BytesIO(r._c))
        return r


def test_enrolement_en_https_verifie_avec_le_bon_corps():
    f = Faux(Rep(200, json.dumps({"client": "c1", "profil": "lite", "lot": None, "tunnel": TUNNEL}).encode()))
    r = C.ClientInfra(ouvrir=f).enroler("gk2_" + "a" * 32, None, CLE, "admin.gk2.secubox.in")
    assert r["tunnel"] == TUNNEL
    m, url, data, ent, timeout, ctx = f.vus[0]
    assert (m, url) == ("POST", "https://admin.gk2.secubox.in/api/v1/autoload/enrol") and timeout
    assert json.loads(data) == {"jeton": "gk2_" + "a" * 32, "cle_pub": CLE}
    assert ctx is not None and ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname                 # jamais verify=False
    assert ent.get("Content-type") == "application/json"


def test_enrolement_par_serie():
    f = Faux(Rep(200, json.dumps({"client": "c1", "profil": "isp", "lot": None, "tunnel": TUNNEL}).encode()))
    C.ClientInfra(ouvrir=f).enroler(None, "SBX-0001-AB", CLE, "admin.gk2.secubox.in")
    assert json.loads(f.vus[0][2]) == {"serie": "SBX-0001-AB", "cle_pub": CLE}


@pytest.mark.parametrize("code", [403, 429])
def test_un_refus_de_l_infrastructure_est_un_refus_d_enrolement(code):
    with pytest.raises(M.EnrolementRefuse):
        C.ClientInfra(ouvrir=Faux(Rep(code, b'{"detail":"jeton refus\\u00e9"}'))).enroler("gk2_" + "a" * 32, None, CLE, "admin.gk2.secubox.in")


@pytest.mark.parametrize("panne", [Rep(503), Rep(502), urllib.error.URLError("injoignable"), TimeoutError("lent")])
def test_une_panne_est_une_erreur_reseau_reessayable_pas_un_refus(panne):
    with pytest.raises(OSError):
        C.ClientInfra(ouvrir=Faux(panne)).enroler("gk2_" + "a" * 32, None, CLE, "admin.gk2.secubox.in")


@pytest.mark.parametrize("hote", ["evil.com/x", "a b.com", "http://x", "localhost", "1.2.3.4", "x" * 300 + ".com", "", "admin.gk2.secubox.in:8080"])
def test_l_hote_de_l_infrastructure_est_un_nom_de_domaine_seulement(hote):
    with pytest.raises(ValueError):
        C.ClientInfra(ouvrir=Faux(Rep())).enroler("gk2_" + "a" * 32, None, CLE, hote)


@pytest.mark.parametrize("corps", [b"pas du json", b"[1,2]", b'{"client":"c1"}', b'{"client":"c1","profil":"lite","tunnel":"x"}', b"x" * 70000])
def test_reponse_d_enrolement_invalide_ou_trop_grosse_refusee(corps):
    with pytest.raises((ValueError, OSError)):
        C.ClientInfra(ouvrir=Faux(Rep(200, corps))).enroler("gk2_" + "a" * 32, None, CLE, "admin.gk2.secubox.in")


def test_les_redirections_ne_sont_jamais_suivies():
    ouvreur = C.ouvreur_sans_redirection()
    import urllib.request as U
    h = [x for x in ouvreur.handlers if isinstance(x, U.HTTPRedirectHandler)]
    assert len(h) == 1 and h[0].redirect_request(None, None, 302, "x", {}, "https://evil.example/") is None


# ── tunnel : vrai petit serveur HTTP local ───────────────────────────────────────────────────────────────
class Hub(BaseHTTPRequestHandler):
    vus = []
    refus = False

    def log_message(self, *a):
        pass

    def _rep(self, code, obj):
        d = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(d)))
        self.end_headers()
        self.wfile.write(d)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        Hub.vus.append(("POST", self.path, json.loads(self.rfile.read(n))))
        self._rep(200, {"ok": True})

    def do_GET(self):
        Hub.vus.append(("GET", self.path, None))
        self._rep(200, {"refuse": Hub.refus})


@pytest.fixture
def hub():
    srv = HTTPServer(("127.0.0.1", 0), Hub)
    Hub.vus, Hub.refus = [], False
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_publication_progression_et_sondage_du_refus(hub):
    c = C.ClientInfra(base_tunnel=hub)
    pre = {"profil": "lite", "empreinte": "e" * 64}
    c.publier(pre)
    c.progression("installation", 6, 8)
    assert c.refuse("e" * 64) is False
    Hub.refus = True
    assert c.refuse("e" * 64) is True
    assert Hub.vus[0] == ("POST", "/prerapport", pre)
    assert Hub.vus[1] == ("POST", "/progression", {"etape": "installation", "faites": 6, "total": 8, "termine": False})
    assert Hub.vus[2][:2] == ("GET", f"/prerapport/{'e' * 64}/refus")


def test_la_base_du_tunnel_par_defaut_est_le_hub_et_rien_d_autre():
    assert C.ClientInfra().base_tunnel == "http://10.64.0.1:8470"


def test_empreinte_non_hexadecimale_refusee_avant_toute_requete():
    f = Faux()
    with pytest.raises(ValueError):
        C.ClientInfra(ouvrir=f).refuse("../../etc/passwd")
    assert f.vus == []


def test_la_cli_refuse_hors_root_et_montre_l_etat_sans_secret(tmp_path):
    import os
    import subprocess
    ctl = str(Path(__file__).resolve().parents[1] / "sbin" / "autoload-agentctl")
    env = dict(os.environ, SECUBOX_AUTOLOAD_AGENT_DOSSIER=str(tmp_path))
    (tmp_path / "etat.json").write_text(json.dumps({"faites": ["reponses"], "enrolement": {"tunnel": TUNNEL}}))
    etat = subprocess.run([sys.executable, ctl, "etat"], capture_output=True, text=True, env=env)
    assert etat.returncode == 0 and "reponses" in etat.stdout and "10.64.0.2" not in etat.stdout
    if os.geteuid() != 0:
        run = subprocess.run([sys.executable, ctl, "run"], capture_output=True, text=True, env=env)
        assert run.returncode == 2 and "root" in run.stderr


def test_le_trousseau_livre_est_la_cle_de_signature_du_provisionnement():
    """Le trousseau installé dans l'image est la partie publique de la clé « SecuBox Provisioning » (empreinte consignée dans le README)."""
    import subprocess
    ring = Path(__file__).resolve().parents[1] / "provisioning.gpg"
    r = subprocess.run(["gpg", "--show-keys", "--with-colons", str(ring)], capture_output=True, text=True)
    assert "fpr:::::::::14A5B0E26CEB6DF820038B88CF764A1B09C5047C:" in r.stdout and "SecuBox Provisioning" in r.stdout
    assert "sec:" not in r.stdout                                          # jamais une clé privée dans le dépôt
    assert (Path(__file__).resolve().parents[1] / "debian" / "rules").read_text().count("provisioning.gpg") >= 1
