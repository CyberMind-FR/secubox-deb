# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Routes de l'annuaire des clés (#1738) : la personne vient de la session,
WKD est public mais ne sert que le vérifié, l'export n'est servi qu'au maillage."""
import os
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

os.environ["SECUBOX_OPENPGP_SANS_RAFRAICHIR"] = "1"

import importlib.util  # noqa: E402
from pathlib import Path  # noqa: E402

# `api` est aussi le paquet de secubox-annuaire, placé avant nous sur le chemin.
_spec = importlib.util.spec_from_file_location("openpgp_api_main",
                                               Path(__file__).resolve().parents[1] / "api" / "main.py")
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)
from secubox_core import capacites  # noqa: E402
from secubox_core.auth import require_personne  # noqa: E402
from secubox_openpgp.personnes import Annuaire, hash_wkd  # noqa: E402

from test_annuaire_cles import ALICE, personnes  # noqa: E402,F401

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg absent")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "RACINE", tmp_path / "pgp")
    monkeypatch.setattr(m, "GNUPGHOME", str(tmp_path / "pgp" / "node"))
    (tmp_path / "pgp").mkdir()
    monkeypatch.setattr(Annuaire, "adresses_de", lambda self, u: {"alice@secubox.in"} if u == ALICE else set())
    qui = {"sub": "alice"}
    monkeypatch.setattr(capacites, "personne_du_porteur",
                        lambda p: {"user_uuid": ALICE, "pseudo": "alice"} if p.get("sub") == "alice" else None)
    monkeypatch.setattr(m, "_nom_box", lambda: "gk2")
    m.app.dependency_overrides[require_personne] = lambda: dict(qui)
    yield TestClient(m.app), qui
    m.app.dependency_overrides.clear()


def test_publier_lister_et_wkd(client, personnes):
    c, _ = client
    assert c.get("/moi").json()["cle"] is None
    r = c.post("/moi/cle", json={"cle_publique": personnes["alice"].publique})
    assert r.status_code == 200 and r.json()["verifies"] == ["alice@secubox.in"]
    assert c.get("/moi").json()["adresses_confiees"] == ["alice@secubox.in"]
    [e] = c.get("/annuaire").json()["cles"]
    assert e["empreinte"] == personnes["alice"].fpr and "cle_publique" not in e and "personne" not in e
    assert "PUBLIC KEY BLOCK" in c.get(f"/annuaire/{personnes['alice'].fpr}.asc").text
    w = c.get(f"/wkd/secubox.in/hu/{hash_wkd('alice')}", params={"l": "alice"})
    assert w.status_code == 200 and w.headers["content-type"] == "application/octet-stream"
    sortie = subprocess.run(["gpg", "--show-keys", "--with-colons"], input=w.content, capture_output=True).stdout
    assert personnes["alice"].fpr.encode() in sortie
    assert c.get(f"/wkd/secubox.in/hu/{hash_wkd('bob')}").status_code == 404
    assert c.get("/wkd/secubox.in/policy").status_code == 200
    assert c.delete("/moi/cle").json()["retiree"] == personnes["alice"].fpr
    assert c.get(f"/wkd/secubox.in/hu/{hash_wkd('alice')}").status_code == 404


def test_cle_secrete_refusee_et_personne_requise(client, personnes):
    c, qui = client
    assert c.post("/moi/cle", json={"cle_publique": personnes["alice"].secrete}).status_code == 422
    qui["sub"] = "inconnu"
    assert c.get("/moi").status_code == 403
    assert c.get("/annuaire").status_code == 403


def test_export_reserve_au_maillage(client):
    c, _ = client
    assert c.get("/annuaire/export").status_code == 403
