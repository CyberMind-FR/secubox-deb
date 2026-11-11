# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""MirrorNet 4b (#3659) côté annuaire : l'abonnement d'un producteur à un espace nomme, SIGNÉS, les jeux à propager."""
import json

import pytest
from pydantic import ValidationError

from annuaire import verbs as V
from annuaire.crypto import canonical_bytes, verify
from annuaire.model import Subscription, charge_signee
from tests.test_mirrornet_cycle_3647 import _membre, api, j  # noqa: F401 (fixtures)


def test_jeux_absents_charge_d_avant(j):  # noqa: F811
    """Sans `jeux`, la charge signée est exactement celle de 0.19 : les abonnements anciens restent valides."""
    s = Subscription(subscription_id="ab" * 16, subscriber="did:plc:" + "1" * 32, service_id="cd" * 16)
    assert "jeux" not in charge_signee(s)


@pytest.mark.parametrize("jeux", [[], ["xyz"], ["ab" * 8, "ab" * 8], ["ab" * 8] * 33, ["AB" * 8]])
def test_jeux_bornes(jeux):
    with pytest.raises(ValidationError):
        Subscription(subscription_id="ab" * 16, subscriber="did:plc:" + "1" * 32, service_id="cd" * 16, jeux=jeux)


def test_jeux_dans_la_charge_signee(j):  # noqa: F811
    pf, _, df = _membre(j)
    pa, pub_a, da = _membre(j)
    esp = V.offer_service(j, pf, df, name="Espace", kind="espace", endpoint="mesh:espace", approval_mode="auto")
    s = V.subscribe(j, pa, da, esp.service_id, jeux=["ab" * 8])
    entree = [e for e in j.iter_entries() if e.payload.get("subscription_id") == s.subscription_id][0]
    assert entree.payload["jeux"] == ["ab" * 8]
    assert verify(pub_a.hex(), canonical_bytes(entree.payload), entree.sig)


def _offre_tiers(jj, kind, **kw):
    pf, _, df = _membre(jj)
    return V.offer_service(jj, pf, df, name="T", kind=kind, endpoint="mesh:x", approval_mode="auto", **kw)


def test_self_abonnement_espace_exige_des_jeux_a_soi(api):  # noqa: F811
    tc, M, jj, did, tmp = api
    M.app.dependency_overrides[M._require_jwt] = lambda: {"sub": "admin"}
    jeu = tc.post("/self/service/offer", json={"name": "Météo", "kind": "dataset", "endpoint": "mesh:meteo",
                                               "approval_mode": "auto", "classe": "public"}).json()["service_id"]
    pro = tc.post("/self/service/offer", json={"name": "Contrat", "kind": "dataset", "endpoint": "mesh:c",
                                               "approval_mode": "pending", "classe": "professionnel"}).json()["service_id"]
    esp = _offre_tiers(jj, "espace", quotas={"octets": 10 ** 9})
    autre = _offre_tiers(jj, "dataset")
    url = f"/self/service/{esp.service_id}/subscribe"
    assert tc.post(url, json={}).status_code == 422                               # espace sans jeux
    assert tc.post(url, json={"jeux": [autre.service_id]}).status_code == 409    # jeu d'un autre nœud
    assert tc.post(url, json={"jeux": [pro]}).status_code == 409                 # classe professionnelle
    assert tc.post(url, json={"jeux": ["0" * 16]}).status_code == 409            # jeu inconnu
    r = tc.post(url, json={"jeux": [jeu]})
    assert r.status_code == 200, r.text
    assert r.json()["jeux"] == [jeu] and r.json()["state"] == "approved"
    # Compatibilité et capacité de l'espace figées dans l'abonnement signé.
    assert r.json()["compat_acceptee"] == {"compat": {}, "quotas": {"octets": 10 ** 9}}
    export = json.loads((tmp / "mirrornet-export.json").read_text())
    sub = [e for e in export["entrees"] if e["op"] == "service_subscribe"][0]
    assert sub["payload"]["jeux"] == [jeu]
    # `jeux` sur une offre qui n'est pas un espace : refusé.
    api_ = _offre_tiers(jj, "api")
    assert tc.post(f"/self/service/{api_.service_id}/subscribe", json={"jeux": [jeu]}).status_code == 422
