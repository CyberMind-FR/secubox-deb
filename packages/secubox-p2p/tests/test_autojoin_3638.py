# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3638 — autojoin d'une box derrière un maître SecuBox (à valider ou exclure après coup), et relais automatique :
pair sans webos exposé par son admin, pair disparu retiré."""
import importlib.machinery
import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
from api import main  # noqa: E402

RELAIS = (ICI / "sbin" / "secubox-relais-maillage").read_text()
K1 = "YL8HZjBi/6xmOzU5SCFb28PXy/EPw669XwYIXT87HFM="
K2 = "MOd1B865CCLYGhjwCtbEHZk+0rqoVaoC6lAr+TsMo0Y="
DERRIERE = [ipaddress.ip_network("192.168.42.0/24")]


@pytest.fixture
def maitre(tmp_path, monkeypatch):
    p2p = tmp_path / "p2p"
    ml = p2p / "master-link"
    ml.mkdir(parents=True)
    (ml / "requests.json").write_text("[]")
    (ml / "tokens.json").write_text("[]")
    (p2p / "wg_mesh.json").write_text(json.dumps({"peers": []}))
    for nom, val in (("P2P_DIR", p2p), ("PEERS_FILE", p2p / "peers.json"), ("WG_MESH_CONFIG", p2p / "wg_mesh.json"),
                     ("ML_DIR", ml), ("ML_REQUESTS_FILE", ml / "requests.json"), ("ML_TOKENS_FILE", ml / "tokens.json"),
                     ("ML_CONFIG_FILE", ml / "config.json"), ("RELAIS_DEMANDE", p2p / "relais.demande")):
        monkeypatch.setattr(main, nom, val)
    monkeypatch.setattr(main.mesh, "load_handshakes", lambda *a, **k: {})
    monkeypatch.setattr(main.ancre, "lire", lambda *a, **k: None)
    monkeypatch.setattr(main, "_reseaux_derriere", lambda: DERRIERE)
    monkeypatch.setattr(main, "_provision", lambda *a, **k: None)
    monkeypatch.setenv("SBX_AUDIT", str(tmp_path / "audit.log"))
    main._autojoin_dernier.clear()
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    main.app.dependency_overrides.clear()


def _audit(tmp):
    f = tmp / "audit.log"
    return f.read_text() if f.exists() else ""


@pytest.mark.parametrize("adresse,ok", [("192.168.42.191", True), ("192.168.1.3", False), ("127.0.0.1", False),
                                        ("10.10.0.7", False), ("", False), ("pas-une-ip", False), ("fe80::1", False)])
def test_autojoin_autorise_seulement_derriere_le_maitre(adresse, ok):
    assert main.autojoin_autorise(adresse, DERRIERE) is ok


def test_jeton_emis_derriere_puis_refuse_ailleurs_et_sans_en_tete(maitre):
    c = TestClient(main.app)
    r = c.post("/master-link/autojoin", headers={"X-SecuBox-Enrol-IP": "192.168.42.191"})
    assert r.status_code == 200 and re.fullmatch(r"[0-9a-f]{64}", r.json()["token"])
    jetons = json.loads((maitre / "p2p/master-link/tokens.json").read_text())
    assert jetons[-1]["type"] == "autojoin" and jetons[-1]["auto_approve"] is True
    assert c.post("/master-link/autojoin", headers={"X-SecuBox-Enrol-IP": "192.168.42.191"}).status_code == 429
    assert c.post("/master-link/autojoin", headers={"X-SecuBox-Enrol-IP": "192.168.1.3"}).status_code == 403   # WAN
    assert c.post("/master-link/autojoin").status_code == 403          # route d'administration : en-tête vidé par nginx
    a = _audit(maitre)
    assert "autojoin_jeton_emis" in a and "autojoin_refuse" in a and r.json()["token"] not in a


def test_autojoin_desactivable(maitre):
    (maitre / "p2p/master-link/config.json").write_text(json.dumps({"role": "master", "autojoin": False}))
    r = TestClient(main.app).post("/master-link/autojoin", headers={"X-SecuBox-Enrol-IP": "192.168.42.191"})
    assert r.status_code == 404


def test_jonction_par_autojoin_marquee_a_valider_puis_validee(maitre):
    c = TestClient(main.app)
    jeton = c.post("/master-link/autojoin", headers={"X-SecuBox-Enrol-IP": "192.168.42.191"}).json()["token"]
    r = c.post("/master-link/join", json={"token": jeton, "fingerprint": "sbx-gk12", "hostname": "gk12",
                                          "wg_public_key": K1})
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    req = json.loads((maitre / "p2p/master-link/requests.json").read_text())
    assert req[0]["a_valider"] is True
    assert main._cles_a_valider() == {K1}
    assert "jonction_autojoin" in _audit(maitre)
    # le jeton est à usage unique
    r2 = c.post("/master-link/join", json={"token": jeton, "fingerprint": "sbx-autre", "hostname": "autre", "wg_public_key": K2})
    assert r2.status_code == 403
    # Valider
    assert c.post("/master-link/valider", json={"public_key": K2}).status_code == 404
    assert c.post("/master-link/valider", json={"public_key": "x"}).status_code == 400
    v = c.post("/master-link/valider", json={"public_key": K1})
    assert v.status_code == 200 and main._cles_a_valider() == set()
    assert "autojoin_valide" in _audit(maitre)


def test_valider_exige_un_administrateur():
    route = next(r for r in main.app.routes if getattr(r, "path", "") == "/master-link/valider")
    assert main.require_jwt in [d.call for d in route.dependant.dependencies]


def test_jonction_ordinaire_pas_a_valider(maitre):
    emis = main.ml_token_generate(ttl=300, auto_approve=True)
    r = TestClient(main.app).post("/master-link/join", json={"token": emis["token"], "fingerprint": "sbx-x", "hostname": "x",
                                                             "wg_public_key": K2})
    assert r.status_code == 200
    assert "a_valider" not in json.loads((maitre / "p2p/master-link/requests.json").read_text())[0]


def test_nginx_pose_et_vide_l_adresse_d_enrolement():
    assert "proxy_set_header X-SecuBox-Enrol-IP $remote_addr;" in (ICI / "nginx/p2p-masterlink.conf").read_text()
    assert 'proxy_set_header X-SecuBox-Enrol-IP "";' in (ICI / "nginx/p2p.conf").read_text()


# ── côté box ────────────────────────────────────────────────────────────────────────────────────────────────────────
def _autojoin(tmp_path, monkeypatch):
    monkeypatch.setenv("SBX_P2P_DIR", str(tmp_path))
    monkeypatch.setenv("SBX_AUTOJOIN_OFF", str(tmp_path / "autojoin.off"))
    chargeur = importlib.machinery.SourceFileLoader("secubox_autojoin", str(ICI / "sbin/secubox-autojoin"))
    spec = importlib.util.spec_from_loader("secubox_autojoin", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    monkeypatch.setattr(m.automesh, "CODE_DEPOSE", str(tmp_path / "automesh.code"))
    return m


def test_box_deja_maillee_ou_maitre_ne_fait_rien(tmp_path, monkeypatch):
    m = _autojoin(tmp_path, monkeypatch)
    assert m.deja_maillee() is False
    (tmp_path / "wg_mesh.json").write_text(json.dumps({"peers": [{"mesh_ip": "10.10.0.2"}]}))
    assert m.deja_maillee() is True                    # maître de ses propres pairs
    (tmp_path / "wg_mesh.json").write_text(json.dumps({"peers": []}))
    (tmp_path / "mesh.json").write_text(json.dumps({"upstream": "192.168.42.1"}))
    assert m.deja_maillee() is True
    (tmp_path / "mesh.json").write_text("{illisible")
    assert m.deja_maillee() is True                    # dans le doute, rien


class _Rep:
    def __init__(self, corps):
        self.corps = corps

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n):
        return self.corps


def test_box_depose_le_code_de_sa_passerelle(tmp_path, monkeypatch):
    m = _autojoin(tmp_path, monkeypatch)
    jeton = "c" * 64
    assert m.demander_jeton("192.168.42.1", ouvrir=lambda req, timeout: _Rep(json.dumps({"token": jeton}).encode())) == jeton
    assert m.demander_jeton("192.168.42.1", ouvrir=lambda req, timeout: _Rep(b'{"token": "court"}')) is None

    def refuse(req, timeout):
        raise OSError("refusé")
    assert m.demander_jeton("192.168.42.1", ouvrir=refuse) is None
    m.deposer("192.168.42.1", jeton)
    code = (tmp_path / "automesh.code").read_text()
    assert m.automesh.decoder(code) == ("192.168.42.1", jeton)
    assert oct((tmp_path / "automesh.code").stat().st_mode & 0o777) == "0o600"


def test_box_coupee_ne_demande_rien(tmp_path, monkeypatch):
    m = _autojoin(tmp_path, monkeypatch)
    (tmp_path / "autojoin.off").write_text("")
    monkeypatch.setattr(m, "passerelle", lambda: pytest.fail("ne doit pas chercher de passerelle"))
    assert m.main() == 0


# ── relais : apparition et disparition ─────────────────────────────────────────────────────────────────────────────
def _python_de(fonction):
    debut = RELAIS.index(fonction + "() {")
    return re.search(r"<<'PY'\n(.*?)\nPY\n", RELAIS[debut:], re.S).group(1)


def _execute(tmp_path, fonction, *args):
    code = tmp_path / (fonction + ".py")
    code.write_text(_python_de(fonction))
    return subprocess.run([sys.executable, "-I", str(code), *map(str, args)], capture_output=True, text=True)


WG = {"peers": [
    {"public_key": K1, "mesh_ip": "10.10.0.9", "name": "gk4", "added": "2026-10-27T06:39:49"},
    {"public_key": K2, "mesh_ip": "10.10.0.7", "name": "gk12", "added": "2026-11-10T04:00:00"},
    {"public_key": "AAAA", "mesh_ip": "10.10.0.20", "name": "neuf", "added": "2026-11-10T04:30:00"},
    {"public_key": "BBBB", "mesh_ip": "10.10.0.21", "name": "Pas_Valide"},
    {"public_key": "CCCC", "mesh_ip": "10.10.0.22", "name": "double"},
    {"public_key": "DDDD", "mesh_ip": "10.10.0.22", "name": "double2"},
]}


def test_nom_du_pair_par_la_jonction(tmp_path):
    f = tmp_path / "wg.json"
    f.write_text(json.dumps(WG))
    r = _execute(tmp_path, "nom_du_pair_wg", f, "10.10.0.7")
    assert r.returncode == 0 and r.stdout.strip() == "gk12"
    for ip in ("10.10.0.21", "10.10.0.22", "10.10.0.99"):
        assert _execute(tmp_path, "nom_du_pair_wg", f, ip).returncode == 1, ip


def test_pairs_disparus(tmp_path):
    f = tmp_path / "wg.json"
    f.write_text(json.dumps(WG))
    maintenant = int(time.time())
    poignees = f"{K1}\t{maintenant - 6 * 86400}\n{K2}\t{maintenant - 30}\nAAAA\t0\n"
    r = _execute(tmp_path, "pairs_disparus", f, 72 * 3600, maintenant, poignees)
    assert r.returncode == 0
    # gk4 muet depuis 6 jours : disparu ; gk12 vivant ; « neuf » jamais vu mais ajouté récemment : gardé ;
    # pairs absents de la mesure (BBBB…) : jamais déclarés disparus
    assert r.stdout.split() == ["10.10.0.9"]
    (tmp_path / "illisible.json").write_text("{")
    assert _execute(tmp_path, "pairs_disparus", tmp_path / "illisible.json", 1, maintenant, poignees).stdout == ""


def test_synchronisation_branche_l_apparition_et_la_disparition():
    s = RELAIS[RELAIS.index("cmd_synchroniser() {"):RELAIS.index("cmd_retirer() {")]
    assert 'reglage retrait_disparus_h 72' in s and "retirer_relais_de_ip" in s
    assert 'nom_du_pair_wg "$WG_ETAT" "$ip"' in s and 'source=jonction' in s
    assert '[ "$source" = webos ] || continue' in s       # source jonction : jamais de retrait de noms publiés
    assert 'pairs="${pairs_vivants# }"' in s              # les disparus ne sont plus sondés ; leurs ports partent


def test_jonction_demande_le_relais_tout_de_suite(maitre):
    main._demander_relais()
    assert (maitre / "p2p/relais.demande").exists()
    u = (ICI / "systemd/secubox-relais-maillage-demande.service").read_text()
    assert "ExecStartPre=/bin/rm -f /var/lib/secubox/p2p/relais.demande" in u
    assert "PathExists=/var/lib/secubox/p2p/relais.demande" in (ICI / "systemd/secubox-relais-maillage-demande.path").read_text()
    rules = (ICI / "debian/rules").read_text()
    for f in ("secubox-relais-maillage-demande.path", "secubox-autojoin.timer", "sbin/secubox-autojoin"):
        assert f in rules, f
