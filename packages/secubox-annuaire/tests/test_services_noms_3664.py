# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3664 — GET /services : nom de la box du fournisseur et « mienne » pour les offres de cette box."""
from annuaire import verbs as V
from conftest import _membre  # fixtures j et api : tests/conftest.py


def test_services_nom_et_mienne(api):  # noqa: F811
    tc, M, jj, did, tmp = api
    M.app.dependency_overrides[M.lecture_ou_pair] = lambda: {"sub": "admin"}

    async def libre(*a, **k):
        return None
    M.exiger_droit, ancien = libre, M.exiger_droit
    try:
        pf, _, df = _membre(jj)
        V.publish_node(jj, pf, df, node_id="sb-x", boxname="gk1", pubkey_wg="cle", mesh_ip="10.10.0.5", ddns="gk1.secubox.in")
        V.offer_service(jj, pf, df, name="Boutique", kind="service", endpoint="https://b.gk1", approval_mode="auto")
        M.app.dependency_overrides[M._require_jwt] = lambda: {"sub": "admin"}
        assert tc.post("/self/service/offer", json={"name": "Boutique", "kind": "app", "endpoint": "https://b.gk2"}).status_code == 200
        r = tc.get("/services").json()
        par = {(s["provider_nom"], s["mienne"]) for s in r["services"]}
        assert ("gk1", False) in par and (None, True) in par and r["soi"] == did
    finally:
        M.exiger_droit = ancien
