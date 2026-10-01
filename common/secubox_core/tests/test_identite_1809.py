# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Session plafonnée, oubli d'un appareil, coffre d'une personne supprimée (#1809)."""
import json

from secubox_core import appareils, capacites, coffre


def test_une_session_plafonnee_guest_n_est_jamais_une_personne(monkeypatch):
    appels = []
    monkeypatch.setattr(capacites, "_demande_de", lambda s, j: appels.append(1) or None)
    assert capacites.personne_du_porteur({"sub": "sbx-abc", "jti": "j", "plafond": "guest"}) is None
    assert appels == [], "refusé avant même de chercher la demande"


def test_un_plafond_user_n_empeche_pas_la_personne(monkeypatch):
    appels = []
    monkeypatch.setattr(capacites, "_demande_de", lambda s, j: appels.append(1) or None)
    capacites.personne_du_porteur({"sub": "sbx-abc", "jti": "j", "plafond": "user"})
    assert appels == [1]


def test_oublier_seulement_un_appareil_revoque(tmp_path, monkeypatch):
    f = tmp_path / "appareils.json"
    monkeypatch.setattr(appareils, "FICHIER", f)
    appareils.inscris("sbx-a", nom="A", profil="guest", did="did:sbx:a")
    appareils.inscris("sbx-b", nom="B", profil="guest", did="did:sbx:b")
    assert appareils.oublie("sbx-a") is False, "actif : on révoque d'abord"
    appareils.revoque("sbx-a")
    assert appareils.oublie("sbx-a") is True
    assert [a["compte"] for a in json.loads(f.read_text())["appareils"]] == ["sbx-b"]


def test_effacer_le_coffre_d_une_personne(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_WEBOS_ACCES", str(tmp_path))
    uid = "0b1c2d3e-0000-4000-8000-000000000001"
    d = tmp_path / f"p-{uid}"
    d.mkdir()
    (d / "mail.json").write_text("{}")
    assert coffre.efface_personne(uid) is True and not d.exists()
    assert coffre.efface_personne(uid) is False
    assert coffre.efface_personne("../../etc") is False
