# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3795 — `GET /dnsguard/alertes` pour la veille V2 : compte `ai-lecture` (jeton lié au chemin VU PAR L'APPLICATION),
lecture par la fin bornée, `depuis` RFC 3339 / epoch, `max` ≤ 2000, anonyme du LAN et autre porteur."""
import json
import os
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.routing import Mount


def _alerte(i, t):
    return {"id": f"dns-{i}", "type": "malicious", "severity": "high", "domain": f"d{i}.example",
            "client_ip": "192.168.1.5", "description": "x", "details": {"rule": "dns.listed"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + "Z", "blocked": False}


@pytest.fixture
def v(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from secubox_core import auth
    from secubox_core import compte_service as cs
    from api import dnsguard_lecture as dl
    monkeypatch.setattr(cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path / "comptes"))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit-garde.log"))
    monkeypatch.setattr(auth, "_secret", lambda: "secret-de-la-box-gk2-assez-long-pour-hs256")
    monkeypatch.setattr(cs, "_rejeu", cs._Rejeu())
    monkeypatch.setattr(cs, "_cache_cles", {})
    monkeypatch.setattr(cs, "_derniers_refus", {})
    monkeypatch.setattr(cs, "_minuterie", {"active": None})
    monkeypatch.setattr(cs, "_armer_minuterie", lambda: None)
    monkeypatch.setattr(cs, "_DEMARRAGE", 0.0)
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    monkeypatch.setattr(dl, "ALERTES", tmp_path / "alerts.jsonl")
    objet = Ed25519PrivateKey.generate()
    pub = objet.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    dossier = tmp_path / "comptes" / "ai-lecture"
    dossier.mkdir(parents=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(dossier, 0o755)
    f = dossier / f"{cs.empreinte(pub)}.pub"
    f.write_bytes(pub)
    os.chmod(f, 0o644)
    prive = objet.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    module = FastAPI()
    module.include_router(dl.router)
    agregateur = FastAPI()                              # montage en processus de l'agrégateur (groupable, #2748)
    agregateur.router.routes.append(Mount("/api/v1/ad-guard", app=module))

    class V:
        c, a, t, d = TestClient(module), TestClient(agregateur), tmp_path, dl

        def get(self, chemin, params=None, signe=None, client=None):
            j = cs.frapper_jeton(prive, "ai-lecture", "gk2", b"", time.time(), methode="GET", chemin=signe or chemin)
            return (client or self.c).get(chemin, params=params, headers={"Authorization": f"Bearer {j}"})

        def ecrire(self, lignes, fin=b""):
            (tmp_path / "alerts.jsonl").write_bytes(b"".join((json.dumps(x) + "\n").encode() for x in lignes) + fin)
    return V()


def test_depuis_epoch_et_rfc3339(v):
    now = int(time.time())
    v.ecrire([_alerte(i, now - 1000 + i * 10) for i in range(50)], fin=b'{"partielle"')
    r = v.get("/dnsguard/alertes", params={"depuis": now - 1000 + 400})
    assert r.status_code == 200, r.text
    d = r.json()
    assert [a["id"] for a in d["alertes"]] == [f"dns-{i}" for i in range(40, 50)]
    assert d["complet"] is True and d["trou"] is False and d["suivant"] is None
    rfc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - 1000 + 400)) + "+00:00"
    assert [a["id"] for a in v.get("/dnsguard/alertes", params={"depuis": rfc}).json()["alertes"]][0] == "dns-40"


def test_max_les_plus_anciennes_et_suivant(v):
    now = int(time.time())
    v.ecrire([_alerte(i, now - 1000 + i * 10) for i in range(50)])
    d = v.get("/dnsguard/alertes", params={"depuis": now - 2000, "max": 5}).json()
    assert [a["id"] for a in d["alertes"]] == [f"dns-{i}" for i in range(5)]
    assert d["complet"] is False and d["suivant"] == d["alertes"][-1]["timestamp"]
    d2 = v.get("/dnsguard/alertes", params={"depuis": d["suivant"], "max": 3}).json()
    assert [a["id"] for a in d2["alertes"]] == ["dns-4", "dns-5", "dns-6"]          # borne inclusive


def test_lecture_par_la_fin_bornee(v, monkeypatch):
    now = int(time.time())
    v.ecrire([_alerte(i, now - 100000 + i) for i in range(3000)])
    lus = []
    vrai = open

    def espion(p, mode="r", *a, **k):
        f = vrai(p, mode, *a, **k)
        if "alerts" in str(p):
            orig = f.read
            f.read = lambda n=-1: (lus.append(n), orig(n))[1]
        return f
    with monkeypatch.context() as m:
        m.setattr("builtins.open", espion)
        d = v.get("/dnsguard/alertes", params={"depuis": now - 100000 + 2990}).json()
    assert len(d["alertes"]) == 10 and sum(lus) < os.path.getsize(v.t / "alerts.jsonl")
    assert all(n > 0 for n in lus)                       # jamais read() du fichier entier
    monkeypatch.setattr(v.d, "OCTETS_MAX", 4096)
    d = v.get("/dnsguard/alertes", params={"depuis": 0, "max": 2000}).json()
    assert d["trou"] is True and 0 < len(d["alertes"]) < 3000


def test_bornes_422(v):
    v.ecrire([])
    assert v.get("/dnsguard/alertes", params={"max": 2000}).status_code == 200
    for p in ({"max": 2001}, {"max": 0}, {"max": "x"}, {"depuis": "hier"}, {"depuis": "-1"},
              {"depuis": "2026-11-18T10:00:00"}, {"depuis": "9" * 11}, {"depuis": "x" * 41}):
        assert v.get("/dnsguard/alertes", params=p).status_code == 422, p


def test_chemin_signe_selon_le_service(v):
    v.ecrire([_alerte(1, int(time.time()))])
    # Socket propre (relais de l'agrégateur, préfixe retiré) : /dnsguard/alertes.
    assert v.get("/dnsguard/alertes").status_code == 200
    # Monté dans l'agrégateur (cas par défaut, groupable) : chemin complet.
    r = v.get("/api/v1/ad-guard/dnsguard/alertes", client=v.a)
    assert r.status_code == 200 and r.json()["alertes"][0]["id"] == "dns-1"
    assert v.get("/api/v1/ad-guard/dnsguard/alertes", signe="/dnsguard/alertes", client=v.a).status_code == 401
    assert v.get("/dnsguard/alertes", signe="/dnsguard/autre").status_code == 401


def test_anonyme_lan_et_autre_porteur(v):
    import jwt
    from secubox_core import auth
    v.ecrire([_alerte(1, int(time.time()))])
    r = v.c.get("/dnsguard/alertes", headers={auth.ENTETE_LAN: "1"})
    assert r.status_code == 200                          # require_lecture inchangé pour le tableau de bord du LAN
    autre = jwt.encode({"sub": "x", "exp": int(time.time()) + 60}, "y" * 40, algorithm="HS256")
    assert v.c.get("/dnsguard/alertes", headers={"Authorization": f"Bearer {autre}"}).status_code == 401


def test_route_montee_dans_l_application():
    from api import main
    routes = {getattr(r, "path", None): r for r in main.app.routes}
    r = routes["/dnsguard/alertes"]
    assert "require_lecture_ou_ai_lecture" in {d.call.__name__ for d in r.dependant.dependencies}
