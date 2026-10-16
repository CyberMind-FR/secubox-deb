# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2776 — accepter une proposition dont le scope porte un deux-points (`mitm-exclusion:gk2`, publié par la toolbox).

CONSTAT (gk2) : « Acceptation impossible : String should match pattern '^[a-z0-9][a-z0-9._-]*$' ». Chaque maillon de l'acceptation (requête, octroi, nom de fichier
appliqué) refusait le deux-points. Il n'est pas un séparateur de chemin : sans danger ; « / », « .. » en tête, espaces et majuscules restent refusés."""
import json

import pytest
from pydantic import ValidationError

from annuaire import config_apply
from annuaire.crypto import did_from_pubkey, generate_keypair

SCOPES_REELS = ["mitm-exclusion:gk2", "mitm-exclusion:c3box", "meshdemo", "firewall", "a.b_c-d:e"]
SCOPES_REFUSES = ["", ":x", "-x", ".x", "../etc", "a/b", "a b", "A", "x\n", "a\x00b", "x;y", "a:b/c"]


def _did():
    _priv, pub = generate_keypair()
    return did_from_pubkey(pub)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    from fastapi.testclient import TestClient
    from api import main as apimain
    apimain._journal = None
    apimain._DB_PATH = str(tmp_path / "journal.db")
    apimain.app.dependency_overrides[apimain._require_jwt] = lambda: {"sub": "admin"}      # l'authentification n'est pas le sujet
    yield TestClient(apimain.app), apimain
    apimain.app.dependency_overrides.pop(apimain._require_jwt, None)


@pytest.mark.parametrize("scope", SCOPES_REELS)
def test_la_requete_d_acceptation_accepte_les_scopes_reels(scope):
    from api.main import CenterProposalAcceptRequest
    assert CenterProposalAcceptRequest(center_did=_did(), scope=scope, layer="baseline").scope == scope


@pytest.mark.parametrize("scope", SCOPES_REFUSES)
def test_la_requete_d_acceptation_refuse_les_scopes_dangereux(scope):
    from api.main import CenterProposalAcceptRequest
    with pytest.raises(ValidationError):
        CenterProposalAcceptRequest(center_did=_did(), scope=scope, layer="baseline")


@pytest.mark.parametrize("scope", SCOPES_REELS)
def test_la_requete_d_octroi_accepte_les_scopes_reels(scope):
    from api.main import CenterGrantRequest
    assert CenterGrantRequest(center_did=_did(), scope=scope, layer="baseline").scope == scope


@pytest.mark.parametrize("scope", SCOPES_REFUSES)
def test_la_requete_d_octroi_refuse_les_scopes_dangereux(scope):
    from api.main import CenterGrantRequest
    with pytest.raises(ValidationError):
        CenterGrantRequest(center_did=_did(), scope=scope, layer="baseline")


def test_l_acceptation_de_bout_en_bout_pour_mitm_exclusion(client, monkeypatch):
    tc, apimain = client
    appels = []

    def faux(args, timeout=25):
        appels.append(list(args))
        if args[0] == "grant":
            return 0, json.dumps({"grant_id": "g1"}), ""
        return 0, json.dumps({"applied": [], "proposals": []}), ""
    monkeypatch.setattr(apimain, "_centers_ctl", faux)
    centre = _did()
    r = tc.post("/centers/proposal/accept", json={"center_did": centre, "scope": "mitm-exclusion:gk2", "layer": "baseline"})
    assert r.status_code == 200, r.text
    assert appels[0] == ["grant", centre, "mitm-exclusion:gk2", "baseline"] and appels[1] == ["route"]


def test_l_acceptation_d_un_scope_dangereux_est_refusee_avant_toute_delegation(client, monkeypatch):
    tc, apimain = client
    appels = []
    monkeypatch.setattr(apimain, "_centers_ctl", lambda a, timeout=25: (appels.append(a), (0, "{}", ""))[1])
    r = tc.post("/centers/proposal/accept", json={"center_did": _did(), "scope": "../etc/passwd", "layer": "baseline"})
    assert r.status_code == 422 and not appels


@pytest.mark.parametrize("scope", SCOPES_REELS)
def test_le_modele_d_octroi_delegue_accepte_les_scopes_reels(scope):
    from annuaire.model import Grant
    g = Grant(grant_id="g", center_did=_did(), scope=scope, layer="baseline", issued_by=_did()) if "layer" in Grant.model_fields else None
    if g is None:
        pytest.skip("forme du modèle différente")
    assert g.scope == scope


@pytest.mark.parametrize("scope", SCOPES_REFUSES)
def test_le_modele_d_octroi_delegue_refuse_les_scopes_dangereux(scope):
    from annuaire.model import Grant
    with pytest.raises(ValidationError):
        Grant(grant_id="g", center_did=_did(), scope=scope, layer="baseline", issued_by=_did())


@pytest.mark.parametrize("scope", SCOPES_REELS)
def test_un_scope_avec_deux_points_est_un_nom_de_fichier_sur(scope):
    assert config_apply._valid_scope(scope) is True
    assert "/" not in scope and not scope.startswith(".")


@pytest.mark.parametrize("scope", SCOPES_REFUSES + [None, 3, ["a"]])
def test_config_apply_refuse_les_scopes_dangereux(scope):
    assert config_apply._valid_scope(scope) is False


def test_les_offres_et_incidents_gardent_leur_motif_strict():
    from annuaire import model
    import inspect
    src = inspect.getsource(model)
    # le motif sans deux-points reste celui des offres/incidents d'assistance : on n'élargit que la chaîne de configuration
    assert src.count('pattern=r"^[a-z0-9][a-z0-9._-]*$"') >= 3
