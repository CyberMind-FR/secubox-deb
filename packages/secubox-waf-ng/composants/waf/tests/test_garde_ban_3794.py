# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3794, tâche 5 : `POST /garde/ban`, geste du compte de service `garde` (portée `garde-ban`).

Adresse publique seule (IPv4 ou IPv6), durée 1 h à 30 j, plafonds 120/h et 1000/j, journal garde-ban.jsonl et
audit. `wafctl` est simulé (`gestes_ia._executer`) ; rien ne touche un pare-feu.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(COMPOSANT))

from tests.test_gestes_ia_3716 import FauxWafctl, _importer_waf, _regroupement_neuf  # noqa: E402

USAGER_GARDE = {"sub": "garde", "compte_service": "garde", "jti": "c" * 32, "cle": "d" * 64}


class Banc:
    def __init__(self, client, gb, faux, tmp):
        self.c, self.gb, self.faux, self.tmp = client, gb, faux, tmp

    def ban(self, cible, duree_s=14400, **extra):
        return self.c.post("/garde/ban", json={"geste": "ban", "cible": cible, "duree_s": duree_s,
                                               "motif": "scan", **extra})

    def audit(self):
        p = self.tmp / "audit.log"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def journal(self):
        p = Path(self.gb.JOURNAL_GARDE)
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def _preparer(monkeypatch, tmp_path):
    waf = _importer_waf()
    from api import gestes_ia as g
    from api import garde_ban as gb
    monkeypatch.setenv("SECUBOX_WAF_GESTES_IA", "1")
    monkeypatch.setattr(waf, "AUDIT_LOG", tmp_path / "audit.log")
    monkeypatch.setattr(gb, "JOURNAL_GARDE", tmp_path / "garde-ban.jsonl")
    _regroupement_neuf(monkeypatch, g)
    faux = FauxWafctl()
    monkeypatch.setattr(g, "_executer", faux)
    return waf, g, gb, faux


@pytest.fixture
def c(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from secubox_core.compte_service import require_garde
    waf, _g, gb, faux = _preparer(monkeypatch, tmp_path)
    waf.app.dependency_overrides[require_garde] = lambda: dict(USAGER_GARDE)
    try:
        yield Banc(TestClient(waf.app), gb, faux, tmp_path)
    finally:
        waf.app.dependency_overrides.clear()


@pytest.mark.parametrize("cible", ["198.51.100.7", "2a01:e0a:1:2::7"])
def test_garde_ban_ip_publique(c, cible):
    r = c.ban(cible)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["cible"] == cible and d["fin"] - int(time.time()) in range(14390, 14401) and d["audit"] == d["id"]
    # même chemin que l'ai-ban : `wafctl ban` (waf_ban ou waf_ban6 selon la famille, avec timeout)
    assert c.faux.appel("ban") == ["sudo", "-n", "/usr/sbin/wafctl", "ban", cible, "14400s"]
    j = c.journal()
    assert len(j) == 1 and j[0]["type"] == "ban" and j[0]["cible"] == cible and j[0]["id"] == d["id"]


@pytest.mark.parametrize("cible", ["192.168.0.1", "fd00::1", "1.2.3.0/24", "10.100.3.4", "100.64.0.1",
                                   "127.0.0.1", "fe80::1", "ff02::1", "::1", "::ffff:198.51.100.7",
                                   "224.0.0.1", "2A01:E0A:1:2::7", "01.2.3.4", "pas-une-ip", ""])
def test_garde_ban_refuse_privee_ula_bloc(c, cible):
    r = c.ban(cible)
    assert r.status_code == 409, r.text
    assert set(r.json()["detail"]) == {"motif"}
    assert c.faux.appels == [] and c.journal() == []


@pytest.mark.parametrize("duree", [3599, 2_592_001, "14400", 14400.0, True, -1])
def test_garde_ban_duree_hors_bornes(c, duree):
    assert c.ban("198.51.100.7", duree_s=duree).status_code == 422
    assert c.faux.appels == []


def test_garde_ban_bornes_de_duree_admises(c):
    assert c.ban("198.51.100.7", duree_s=3600).status_code == 200
    assert c.ban("198.51.100.8", duree_s=2_592_000).status_code == 200


def test_garde_ban_champs_en_trop_refuses(c):
    assert c.ban("198.51.100.7", mode="clic").status_code == 422
    assert c.c.post("/garde/ban", json={"geste": "unban", "cible": "198.51.100.7", "duree_s": 3600}).status_code == 422


def test_garde_ban_deja_actif(c):
    assert c.ban("198.51.100.7").status_code == 200
    r = c.ban("198.51.100.7")
    assert r.status_code == 409 and r.json() == {"detail": {"motif": "deja_actif"}}


def test_garde_ban_plafond_heure(c):
    maintenant = int(time.time())
    with open(c.gb.JOURNAL_GARDE, "w", encoding="utf-8") as f:
        for i in range(120):
            f.write(json.dumps({"type": "ban", "id": f"{i:032x}", "at": maintenant - 60, "cible": f"203.0.113.{i}",
                                "fin": maintenant - 1}) + "\n")
    r = c.ban("198.51.100.7")
    assert r.status_code == 409 and r.json() == {"detail": {"motif": "plafond"}}
    assert c.faux.appels == []


def test_garde_ban_plafond_jour(c):
    maintenant = int(time.time())
    with open(c.gb.JOURNAL_GARDE, "w", encoding="utf-8") as f:
        for i in range(1000):
            f.write(json.dumps({"type": "ban", "id": f"{i:032x}", "at": maintenant - 7200, "cible": "203.0.113.9",
                                "fin": maintenant - 1}) + "\n")
    assert c.ban("198.51.100.7").json() == {"detail": {"motif": "plafond"}}


def test_garde_ban_audite(c):
    r = c.ban("198.51.100.7")
    ident = r.json()["id"]
    actions = [x["action"] for x in c.audit()]
    assert actions == ["garde-ban-demande", "garde-ban"]
    ligne = c.audit()[-1]
    assert ligne["by"] == "garde" and ligne["module"] == "waf" and ident in ligne["detail"]
    assert "198.51.100.7" in ligne["detail"] and "d" * 64 in ligne["detail"]
    # un refus est audité aussi
    c.ban("192.168.0.1")
    assert [x for x in c.audit() if x["action"] == "garde-ban-refus"]


def test_garde_ban_refus_wafctl_409(c):
    c.faux.reponses["ban"] = (1, "", "refus:protegee\n")
    r = c.ban("198.51.100.7")
    assert r.status_code == 409 and r.json() == {"detail": {"motif": "protegee"}}
    assert c.journal() == []


def test_garde_ban_audit_echoue_ban_retire(c, monkeypatch):
    vrai = c.gb._config["audit"]

    def audit(action, detail, user):
        if action == "garde-ban":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(c.gb._config, "audit", audit)
    r = c.ban("198.51.100.7")
    assert r.status_code == 500
    assert "unban" in c.faux.verbes()
    assert [e["type"] for e in c.journal()] == ["ban", "annule"]


# ── Vraie garde : jetons Ed25519 ───────────────────────────────────────
def _cle(cs, tmp_path, compte):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    objet = Ed25519PrivateKey.generate()
    pub = objet.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    prive = objet.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    dossier = tmp_path / "comptes" / compte
    dossier.mkdir(parents=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(dossier, 0o755)
    f = dossier / f"{cs.empreinte(pub)}.pub"
    f.write_bytes(pub)
    os.chmod(f, 0o644)
    return prive


@pytest.fixture
def c_vrai(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    waf, _g, gb, faux = _preparer(monkeypatch, tmp_path)
    from secubox_core import auth
    from secubox_core import compte_service as cs
    monkeypatch.setattr(cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path / "comptes"))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit-garde.log"))
    monkeypatch.setattr(cs, "_rejeu", cs._Rejeu())
    monkeypatch.setattr(cs, "_cache_cles", {})
    monkeypatch.setattr(cs, "_derniers_refus", {})
    monkeypatch.setattr(cs, "_minuterie", {"active": None})
    monkeypatch.setattr(cs, "_armer_minuterie", lambda: None)
    monkeypatch.setattr(cs, "_DEMARRAGE", 0.0)
    yield TestClient(waf.app), cs, faux, tmp_path


def test_garde_ban_jeton_garde_reel(c_vrai):
    client, cs, faux, tmp_path = c_vrai
    prive = _cle(cs, tmp_path, "garde")
    corps = json.dumps({"geste": "ban", "cible": "198.51.100.7", "duree_s": 14400, "motif": "scan"}).encode()
    entete = {"Authorization": f"Bearer {cs.frapper_jeton(prive, 'garde', 'gk2', corps, time.time())}",
              "Content-Type": "application/json"}
    r = client.post("/garde/ban", content=corps, headers=entete)
    assert r.status_code == 200, r.text
    assert client.post("/garde/ban", content=corps, headers=entete).status_code == 401      # rejeu


def test_garde_ban_jeton_portee_ai_ban_refuse(c_vrai):
    client, cs, faux, tmp_path = c_vrai
    prive_ai = _cle(cs, tmp_path, "ai-ban")
    corps = json.dumps({"geste": "ban", "cible": "198.51.100.7", "duree_s": 14400, "motif": "scan"}).encode()
    entete = {"Authorization": f"Bearer {cs.frapper_jeton(prive_ai, 'ai-ban', 'gk2', corps, time.time())}",
              "Content-Type": "application/json"}
    assert client.post("/garde/ban", content=corps, headers=entete).status_code in (401, 403)
    # et un jeton garde ne vaut pas sur /ai/ban
    prive_garde = _cle(cs, tmp_path, "garde")
    corps_ai = json.dumps({"geste": "ban", "cible": "198.51.100.7", "duree_s": 3600, "mode": "clic",
                           "conseil": "c"}).encode()
    entete = {"Authorization": f"Bearer {cs.frapper_jeton(prive_garde, 'garde', 'gk2', corps_ai, time.time())}",
              "Content-Type": "application/json"}
    assert client.post("/ai/ban", content=corps_ai, headers=entete).status_code in (401, 403)
    assert faux.appels == []


def test_compte_garde_dans_la_liste_fermee():
    from secubox_core import compte_service as cs
    assert cs.COMPTES_SERVICE["garde"] == "garde-ban"
    assert cs.COMPTES_SERVICE["ai-ban"] == "waf-ban"


def test_wafctl_cle_garde_ban_dans_l_aide():
    sortie = subprocess.run(["bash", str(COMPOSANT / "scripts" / "wafctl"), "aide"], capture_output=True, text=True,
                            check=False).stdout
    assert "cle-garde-ban" in sortie and "/etc/secubox/secrets/garde-ban.pem" in sortie
