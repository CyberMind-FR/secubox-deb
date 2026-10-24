# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — codes de flash au format automesh (64 hex) et reflash qui remplace la clé du pair."""
import json
import os
import pathlib
import subprocess
import sys

import pytest
from fastapi import HTTPException

from api import automesh, jetons, main, mesh

RACINE = pathlib.Path(__file__).resolve().parents[1]
CLI = RACINE / "scripts" / "sbx-mesh-invite"
ANCIENNE = "A" * 43 + "="
NOUVELLE = "B" * 43 + "="
C3BOX = "C" * 43 + "="


def _cli(tmp_path, *args):
    env = dict(os.environ, SBX_P2P_DIR=str(tmp_path / "p2p"), SBX_AUDIT=str(tmp_path / "audit.log"),
               PYTHONPATH=str(RACINE))
    return subprocess.run([sys.executable, str(CLI), "--adresse", "192.168.1.1", *args],
                          capture_output=True, text=True, env=env, cwd=str(RACINE))


def test_code_au_format_automesh_64_hex(tmp_path):
    r = _cli(tmp_path, "--code", "--nom", "gk9", "--flash", "--json")
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    adresse, jeton = automesh.decoder(d["code"])
    assert adresse == "192.168.1.1" and len(jeton) == 64 and int(jeton, 16) >= 0
    assert d["nom"] == "gk9" and d["expire"]
    jetons_fichier = json.loads((tmp_path / "p2p" / "master-link" / "tokens.json").read_text())
    assert jetons_fichier[0]["nom_prevu"] == "gk9" and jetons_fichier[0]["flash"] is True
    assert jeton not in json.dumps(jetons_fichier)                      # empreinte seule


def test_cli_json_sans_le_jeton_dans_l_audit(tmp_path):
    r = _cli(tmp_path, "--code", "--nom", "gk9", "--json", "--ttl", "120")
    assert r.returncode == 0, r.stderr
    code = json.loads(r.stdout)["code"]
    _, jeton = automesh.decoder(code)
    audit = (tmp_path / "audit.log").read_text()
    ligne = json.loads(audit.splitlines()[-1])
    assert ligne["evenement"] == "code_emis" and ligne["nom"] == "gk9" and ligne["ttl"] == 120
    assert jeton not in audit and code not in audit


# ── côté maître : ml_join ────────────────────────────────────────────────────

class _Client:
    host = "127.0.0.1"


class _Req:
    client = _Client()


@pytest.fixture
def maitre(tmp_path, monkeypatch):
    wg = tmp_path / "wg_mesh.json"
    wg.write_text(json.dumps({
        "private_key": "P" * 43 + "=", "public_key": "M" * 43 + "=", "address": "10.10.0.1/24",
        "listen_port": 51820, "peers": [
            {"public_key": C3BOX, "allowed_ips": "10.10.0.2/32", "mesh_ip": "10.10.0.2", "name": "c3box"},
            {"public_key": ANCIENNE, "allowed_ips": "10.10.0.3/32", "mesh_ip": "10.10.0.3",
             "name": "gk9", "fingerprint": "ancien-fp"}]}))
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps({"peers": [{"id": "sb-x", "fingerprint": "ancien-fp", "name": "gk9",
                                            "mesh_ip": "10.10.0.3"}]}))
    requetes = [{"fingerprint": "ancien-fp", "hostname": "gk9", "status": "approved",
                 "mesh_ip": "10.10.0.3", "wg_public_key": ANCIENNE, "address": "192.168.1.9"}]
    monkeypatch.setattr(main, "WG_MESH_CONFIG", wg)
    monkeypatch.setattr(main, "PEERS_FILE", peers)
    monkeypatch.setattr(main, "get_ml_requests", lambda: requetes)
    monkeypatch.setattr(main, "save_ml_requests", lambda r: requetes.__setitem__(slice(None), r))
    monkeypatch.setattr(main, "get_ml_config", lambda: {"depth": 0, "auto_approve": False})
    monkeypatch.setattr(main, "ml_token_mark_used", lambda *a: None)
    etat = {"flash": True, "nom": "gk9"}
    monkeypatch.setattr(main, "ml_token_validate", lambda t: {
        "valid": True, "token_hash": "h", "auto_approve": True,
        "flash": etat["flash"], "nom_prevu": etat["nom"]})
    return wg, peers, requetes, etat


def _join(nom="gk9", fp="nouveau-fp", cle=NOUVELLE):
    return main.ml_join(main.JoinRequest(token="t", fingerprint=fp, hostname=nom,
                                         address="192.168.1.9", wg_public_key=cle, wg_port=51822), _Req())


def test_reflash_remplace_la_cle_et_garde_l_adresse(maitre):
    wg, peers, requetes, _ = maitre
    r = _join()
    assert r["status"] == "approved" and r["mesh_ip"] == "10.10.0.3"
    etat = json.loads(wg.read_text())
    cles = [p["public_key"] for p in etat["peers"]]
    assert NOUVELLE in cles and ANCIENNE not in cles and C3BOX in cles
    assert [p for p in etat["peers"] if p["public_key"] == NOUVELLE][0]["mesh_ip"] == "10.10.0.3"
    assert [q["fingerprint"] for q in requetes if q.get("hostname") == "gk9"] == ["nouveau-fp"]
    assert [p["fingerprint"] for p in json.loads(peers.read_text())["peers"]] == ["nouveau-fp"]


def test_doublon_sans_flash_refuse(maitre):
    wg, _, requetes, etat = maitre
    etat["flash"] = False
    avant = wg.read_text()
    with pytest.raises(HTTPException) as e:
        _join()
    assert e.value.status_code == 409 and wg.read_text() == avant
    assert "préparer un flash" in e.value.detail and "retirer l'ancien pair" in e.value.detail


def test_jeton_flash_pour_un_autre_nom_refuse(maitre):
    wg, _, _, etat = maitre
    etat["nom"] = "gk7"
    avant = wg.read_text()
    with pytest.raises(HTTPException) as e:
        _join()                                            # hostname gk9 demandé avec un jeton pour gk7
    assert e.value.status_code == 403 and wg.read_text() == avant


# ── correctifs du tour 1 ─────────────────────────────────────────────────────

def _charger_cli():
    import importlib.machinery
    import importlib.util
    l = importlib.machinery.SourceFileLoader("sbx_mesh_invite", str(CLI))
    spec = importlib.util.spec_from_loader("sbx_mesh_invite", l)
    m = importlib.util.module_from_spec(spec)
    l.exec_module(m)
    return m


def test_cli_ne_suit_pas_les_liens(tmp_path, monkeypatch, capsys):
    cli = _charger_cli()
    p2p = tmp_path / "p2p"
    ml = p2p / "master-link"
    ml.mkdir(parents=True)
    cible = tmp_path / "secret"
    cible.write_text("x")
    (p2p / "piege").symlink_to(cible)
    (ml / "tokens.json").symlink_to(cible)
    appels = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "lchown", lambda *a, **k: appels.append(a[0]))
    monkeypatch.setattr(os, "chown", lambda *a, **k: appels.append(("chown", a[0])))
    cli._rendre_au_service(str(p2p))
    assert str(ml) in appels                                       # le dossier lui-même
    assert str(ml / "tokens.json") not in appels and str(p2p / "piege") not in appels
    assert not [a for a in appels if isinstance(a, tuple)]
    assert "lien" in capsys.readouterr().err


def test_flash_ttl_48h_par_defaut(tmp_path):
    for args, attendu in ((("--flash", "--nom", "gk9"), 172800), (("--flash", "--nom", "gk9", "--ttl", "60"), 60), ((), 3600)):
        d = tmp_path / str(attendu)
        d.mkdir(exist_ok=True)
        assert _cli(d, "--code", "--json", *args).returncode == 0
        assert json.loads((d / "p2p" / "master-link" / "tokens.json").read_text())[0]["ttl"] == attendu


@pytest.fixture
def audit(tmp_path, monkeypatch):
    monkeypatch.setenv("SBX_AUDIT", str(tmp_path / "audit.log"))
    return lambda: [json.loads(l) for l in (tmp_path / "audit.log").read_text().splitlines()] \
        if (tmp_path / "audit.log").exists() else []


def test_decisions_auditees_sans_jeton(maitre, audit):
    _, _, _, etat = maitre
    _join()
    l = [x for x in audit() if x["evenement"] == "pair_remplace_reflash"][0]
    assert l["nom"] == "gk9" and l["ancienne_empreinte"] == "ancien-fp" and l["nouvelle_empreinte"] == "nouveau-fp" and l["mesh_ip"] == "10.10.0.3"
    etat["nom"] = "gk7"
    with pytest.raises(HTTPException):
        _join(fp="autre")
    etat.update(flash=False, nom="gk9")
    with pytest.raises(HTTPException):
        _join(fp="encore")
    raisons = [x["raison"] for x in audit() if x["evenement"] == "jonction_refusee"]
    assert raisons == ["jeton flash pour un autre nom", "nom deja pris"]
    assert '"t"' not in json.dumps(audit())


def test_homonyme_rejete_ou_revoque_n_empeche_pas(maitre):
    _, _, requetes, etat = maitre
    etat["flash"] = False
    requetes[0]["status"] = "rejected"
    assert _join()["status"] == "approved"


@pytest.mark.parametrize("nom", ["unknown", "localhost", "secubox", "secubox-mochabin", "secubox-espressobin"])
def test_nom_par_defaut_jamais_refuse(maitre, nom):
    _, _, requetes, etat = maitre
    etat.update(flash=False, nom=nom)
    requetes.append({"fingerprint": "autre-fp", "hostname": nom, "status": "approved", "mesh_ip": "10.10.0.9"})
    assert _join(nom=nom, fp="n-" + nom, cle="D" * 43 + "=")["status"] == "approved"


def test_reflash_ancien_pair_sans_cle_dans_la_demande(maitre):
    wg, _, requetes, _ = maitre
    requetes[0].pop("wg_public_key")
    r = _join()
    assert r["mesh_ip"] == "10.10.0.3"
    pairs = json.loads(wg.read_text())["peers"]
    assert ANCIENNE not in [p["public_key"] for p in pairs]
    assert [p["allowed_ips"] for p in pairs if p["public_key"] == NOUVELLE] == ["10.10.0.3/32"]
