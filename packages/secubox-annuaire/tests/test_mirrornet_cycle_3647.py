# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""MirrorNet v1 phase 3 (#3647) côté annuaire : offres étendues rétrocompatibles, échéance, renouvellement,
résiliation, révocation d'un abonné, niveaux de confiance, export pour secubox-mirrornet, routes /self."""
import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from annuaire import confiance, mirrornet_export as MX
from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.model import Identity, MemberState, Op, ServiceOffer, SubscriptionState
from annuaire import verbs as V


def _membre(j):
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=hashlib.sha256(pub).hexdigest()[:32],
                     state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    j.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload, author=did,
             sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, pub, did


@pytest.fixture
def j(tmp_path):
    return Journal(str(tmp_path / "j.db"))


def _offre(j, priv, did, **etendus):
    etendus.setdefault("duree_s", 3600)
    return V.offer_service(j, priv, did, name="Miroir", kind="mirror", endpoint="http://10.10.0.2/x",
                           approval_mode="auto", **etendus)


# --- rétrocompatibilité ---------------------------------------------------------------------------------------

def test_offre_ancienne_signee_sans_les_nouveaux_champs_reste_valide(j):
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ancienne = {"service_id": "ab" * 16, "provider": did, "name": "Vieille", "kind": "api", "endpoint": "http://x",
                "scope": {}, "approval_mode": "auto", "description": "", "pac": None,
                "created_at": "2026-01-01T00:00:00+00:00"}
    sig = sign(priv, canonical_bytes(ancienne))
    V.ingest_offer(j, ServiceOffer(**ancienne, sig=sig), pub.hex())
    stockee = next(e.payload for e in j.iter_entries() if e.op == Op.SERVICE_OFFER)
    assert stockee == ancienne                      # aucun champ MirrorNet ajouté à la charge signée


def test_offre_sans_champs_etendus_signe_comme_avant(j):
    priv, _pub, did = _membre(j)
    o = V.offer_service(j, priv, did, name="S", kind="api", endpoint="http://x")
    stockee = next(e.payload for e in j.iter_entries() if e.op == Op.SERVICE_OFFER)
    for k in ("version", "tarif", "duree_s", "grace_s", "classe", "quotas", "compat", "sonde"):
        assert k not in stockee
    assert o.sig


def test_offre_etendue_federee_et_verifiee_ailleurs(tmp_path, j):
    priv, pub, did = _membre(j)
    o = _offre(j, priv, did, tarif={"modele": "forfait", "credits": 100, "periode_s": 3600}, classe="public",
               version="1.0", grace_s=60)
    autre = Journal(str(tmp_path / "autre.db"))
    V.ingest_offer(autre, o, pub.hex())
    stockee = next(e.payload for e in autre.iter_entries() if e.op == Op.SERVICE_OFFER)
    assert stockee["tarif"]["credits"] == 100 and stockee["duree_s"] == 3600


@pytest.mark.parametrize("tarif", [{"modele": "or"}, {"modele": "forfait", "credits": -1},
                                   {"modele": "forfait", "credits": 1.5}, {"modele": "forfait", "devise": "EUR"}])
def test_tarif_invalide_refuse(j, tarif):
    priv, _pub, did = _membre(j)
    with pytest.raises(ValidationError):
        _offre(j, priv, did, tarif=tarif)


# --- cycle de vie ---------------------------------------------------------------------------------------------

def _abonne(j, duree_s=3600, approval="auto"):
    pf, _, df = _membre(j)
    pa, _, da = _membre(j)
    o = V.offer_service(j, pf, df, name="M", kind="mirror", endpoint="http://x", approval_mode=approval,
                        duree_s=duree_s)
    exp = (datetime.now(timezone.utc) + timedelta(seconds=duree_s)).isoformat()
    s = V.subscribe(j, pa, da, o.service_id, expire_le=exp, tarif_accepte={"modele": "gratuit"})
    return pf, df, pa, da, o, s


def test_renouvellement_prolonge_d_une_periode(j):
    _pf, _df, pa, da, _o, s = _abonne(j)
    avant = datetime.fromisoformat(V.echeance_abonnement(j, s.subscription_id))
    res = V.renew_subscription(j, pa, da, s.subscription_id)
    apres = datetime.fromisoformat(V.echeance_abonnement(j, s.subscription_id))
    assert apres - avant == timedelta(seconds=3600) and res["expire_le"] == apres.isoformat()


def test_renouvellement_refuse_hors_abonne_ou_en_attente(j):
    pf, df, pa, da, _o, s = _abonne(j)
    with pytest.raises(PermissionError):
        V.renew_subscription(j, pf, df, s.subscription_id)
    *_x, s2 = _abonne(j, approval="pending")
    pa2, da2 = _x[2], _x[3]
    with pytest.raises(ValueError):
        V.renew_subscription(j, pa2, da2, s2.subscription_id)


def test_periode_close_ne_se_renouvelle_pas(j):
    pf, df, pa, da, o, _s = _abonne(j)
    passe = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    s = V.subscribe(j, pa, da, o.service_id, expire_le=passe)
    with pytest.raises(ValueError, match="période close"):
        V.renew_subscription(j, pa, da, s.subscription_id)
    # Un SERVICE_RENEW signé APRÈS l'échéance (rejoué, horloge fausse) est ignoré par le calcul d'échéance.
    tard = {"subscription_id": s.subscription_id, "service_id": o.service_id, "subscriber": da,
            "expire_le": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "renewed_at": datetime.now(timezone.utc).isoformat()}
    V._signer_et_ajouter(j, pa, da, Op.SERVICE_RENEW, "ServiceRenew", tard)
    assert V.echeance_abonnement(j, s.subscription_id) == passe


def test_renouvellement_d_un_tiers_ignore(j):
    _pf, _df, _pa, _da, o, s = _abonne(j)
    pt, _, dt = _membre(j)
    faux = {"subscription_id": s.subscription_id, "service_id": o.service_id, "subscriber": dt,
            "expire_le": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "renewed_at": datetime.now(timezone.utc).isoformat()}
    V._signer_et_ajouter(j, pt, dt, Op.SERVICE_RENEW, "ServiceRenew", faux)
    assert V.echeance_abonnement(j, s.subscription_id) == s.expire_le


def test_resiliation_par_l_abonne_puis_refus_du_doublon(j):
    _pf, _df, pa, da, _o, s = _abonne(j)
    assert V.cancel_subscription(j, pa, da, s.subscription_id, "plus besoin")["role"] == "abonne"
    assert V.subscription_state(j, s.subscription_id) is SubscriptionState.REVOKED
    with pytest.raises(ValueError):
        V.cancel_subscription(j, pa, da, s.subscription_id)


def test_revocation_d_un_abonne_par_le_fournisseur_seulement(j):
    pf, df, pa, da, _o, s = _abonne(j)
    with pytest.raises(PermissionError):
        V.revoke_subscriber(j, pa, da, s.subscription_id, "x")
    with pytest.raises(PermissionError):
        V.cancel_subscription(j, pf, df, s.subscription_id)
    V.revoke_subscriber(j, pf, df, s.subscription_id, "quota dépassé")
    assert V.subscription_state(j, s.subscription_id) is SubscriptionState.REVOKED


def test_motif_borne(j):
    _pf, _df, pa, da, _o, s = _abonne(j)
    with pytest.raises(ValueError):
        V.cancel_subscription(j, pa, da, s.subscription_id, "x" * 201)
    with pytest.raises(ValueError):
        V.cancel_subscription(j, pa, da, s.subscription_id, "a\nb")


# --- niveaux de confiance ----------------------------------------------------------------------------------------

def test_niveaux(j):
    _p1, _pub1, d1 = _membre(j)
    p2, pub2, d2 = _membre(j)
    V.publish_node(j, p2, d2, node_id="sb-x", boxname="gk9", pubkey_wg="A" * 43 + "=", mesh_ip="10.10.0.9", ddns="")
    p3, _pub3, d3 = _membre(j)
    V.revoke(j, p3, d3, d3, "auto-révocation")
    n = confiance.niveaux(j)
    assert n[d1][0] == "LIMITED" and "non liée" in n[d1][1]
    assert n[d2][0] == "LIMITED" and "A21" in n[d2][1]
    assert n[d3][0] == "REVOKED"
    assert confiance.niveau(j, "did:plc:" + "0" * 32)[0] == "OBSERVER"


# --- export -----------------------------------------------------------------------------------------------------

def test_export_ne_garde_que_les_abonnements_de_soi(tmp_path, j):
    pf, df, pa, da, o, s = _abonne(j)
    pt, _, dt = _membre(j)
    V.subscribe(j, pt, dt, o.service_id)                    # abonnement d'un tiers à l'offre d'un autre
    vu_par_abonne = MX.construire(j, da, {})
    subs = [e for e in vu_par_abonne["entrees"] if e["op"] == "service_subscribe"]
    assert [e["payload"]["subscription_id"] for e in subs] == [s.subscription_id]
    assert any(e["op"] == "service_offer" for e in vu_par_abonne["entrees"])
    vu_par_fournisseur = MX.construire(j, df, {})
    assert len([e for e in vu_par_fournisseur["entrees"] if e["op"] == "service_subscribe"]) == 2
    assert all(e["author_pubkey"] for e in vu_par_abonne["entrees"])


def test_export_ecrit_atomique_0640_et_seulement_si_change(tmp_path, j):
    _abonne(j)
    chemin = tmp_path / "export.json"
    d = MX.construire(j, None, {})
    assert MX.ecrire(d, chemin) is True
    assert stat.S_IMODE(os.stat(chemin).st_mode) == 0o640
    assert MX.ecrire(d, chemin) is False
    assert json.loads(chemin.read_text())["format"] == 1
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".mirrornet-export.")]


# --- routes /self ---------------------------------------------------------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    from fastapi.testclient import TestClient
    from api import main as M
    M._journal = None
    M._DB_PATH = str(tmp_path / "journal.db")
    M._EXPORT_CACHE.update(hauteur=None, donnees=None)
    jj = M.get_journal()
    priv, _pub, did = _membre(jj)
    cle = tmp_path / "node.key"
    cle.write_text(priv.hex())
    monkeypatch.setenv("ANNUAIRE_KEY_PATH", str(cle))
    monkeypatch.setattr(M, "MIRRORNET_EXPORT", tmp_path / "mirrornet-export.json")
    monkeypatch.setattr(M, "AUDIT_DROITS", tmp_path / "audit.log")
    monkeypatch.setattr(M, "JOIGNABILITE_ETAT", tmp_path / "joignabilite.json")
    tc = TestClient(M.app)
    yield tc, M, jj, did, tmp_path
    M.app.dependency_overrides.clear()


def test_routes_self_exigent_un_administrateur(api):
    tc, *_ = api
    for chemin in ("/self/service/offer", "/self/service/x/subscribe", "/self/subscription/x/renew",
                   "/self/subscription/x/cancel"):
        assert tc.post(chemin, json={}).status_code == 401


def test_parcours_self_publier_abonner_renouveler_resilier(api):
    tc, M, jj, did, tmp = api
    M.app.dependency_overrides[M._require_jwt] = lambda: {"sub": "admin"}
    r = tc.post("/self/service/offer", json={"name": "Miroir apt", "kind": "mirror", "endpoint": "http://10.10.0.2/a",
                                             "tarif": {"modele": "gratuit"}, "duree_s": 3600, "classe": "public"})
    assert r.status_code == 200, r.text
    assert r.json()["provider"] == did
    # S'abonner à sa propre offre : refus.
    assert tc.post(f"/self/service/{r.json()['service_id']}/subscribe", json={}).status_code == 409
    # Offre d'un autre membre, approbation automatique : abonnement avec échéance et tarif accepté.
    pf, _, df = _membre(jj)
    o = V.offer_service(jj, pf, df, name="Autre", kind="api", endpoint="http://x", approval_mode="auto",
                        duree_s=600, tarif={"modele": "gratuit"})
    r = tc.post(f"/self/service/{o.service_id}/subscribe", json={"version": "1"})
    assert r.status_code == 200, r.text
    sub = r.json()
    assert sub["state"] == "approved" and sub["expire_le"] and sub["tarif_accepte"] == {"modele": "gratuit"}
    assert sub["provider"] == df
    # Second abonnement en cours à la même offre : refusé par l'annuaire lui-même (course sans clé d'idempotence).
    assert tc.post(f"/self/service/{o.service_id}/subscribe", json={}).status_code == 409
    r = tc.post(f"/self/subscription/{sub['subscription_id']}/renew")
    assert r.status_code == 200, r.text
    r = tc.post(f"/self/subscription/{sub['subscription_id']}/cancel", json={"motif": "fin"})
    assert r.status_code == 200 and r.json()["role"] == "abonne"
    assert tc.post(f"/self/subscription/{sub['subscription_id']}/cancel", json={}).status_code == 409
    lignes = [json.loads(x) for x in (tmp / "audit.log").read_text().splitlines()]
    assert [x["action"] for x in lignes] == ["mirrornet_offre_publiee", "mirrornet_abonnement",
                                             "mirrornet_renouvellement", "mirrornet_resiliation"]
    assert all(x["par"] == "admin" for x in lignes) and lignes[-1]["role"] == "abonne"
    export = json.loads((tmp / "mirrornet-export.json").read_text())
    assert export["soi"] == did and {e["op"] for e in export["entrees"]} >= {"service_offer", "service_revoke_sub"}


def test_publier_tarif_invalide_422(api):
    tc, M, *_ = api
    M.app.dependency_overrides[M._require_jwt] = lambda: {"sub": "admin"}
    r = tc.post("/self/service/offer", json={"name": "x", "kind": "api", "endpoint": "http://x",
                                             "tarif": {"modele": "or"}})
    assert r.status_code == 422


def test_joignabilite_suivie_et_exportee(api):
    _tc, M, jj, _did, tmp = api
    p2, _pub2, d2 = _membre(jj)
    V.publish_node(jj, p2, d2, node_id="sb-y", boxname="gk8", pubkey_wg="B" * 43 + "=", mesh_ip="10.10.0.8", ddns="")
    M._JOIGNABILITE.clear()
    M._noter_joignabilite({"10.10.0.8": False})
    premier = M._JOIGNABILITE["10.10.0.8"]["echec_depuis"]
    M._noter_joignabilite({"10.10.0.8": False})
    assert M._JOIGNABILITE["10.10.0.8"]["echec_depuis"] == premier       # depuis le PREMIER échec
    M._exporter_mirrornet()
    export = json.loads((tmp / "mirrornet-export.json").read_text())
    assert export["joignabilite"][d2]["echec_depuis"] == premier
    M._noter_joignabilite({"10.10.0.8": True})
    assert M._JOIGNABILITE["10.10.0.8"]["echec_depuis"] is None and M._JOIGNABILITE["10.10.0.8"]["ok_le"]


# --- relecture de sécurité ---------------------------------------------------------------------------------------

def test_vol_de_service_id_sans_effet(j):
    """Un pair signe sous SON did une offre reprenant le service_id d'un autre : ni présentée, ni autorité."""
    pf, df, pa, da, o, s = _abonne(j, approval="pending")
    pv, _, dv = _membre(j)
    charge = dict(o.model_dump(exclude={"sig", "signer_did"}, exclude_none=True), provider=dv, name="Piège")
    V._signer_et_ajouter(j, pv, dv, Op.SERVICE_OFFER, "ServiceOffer", charge)
    assert V._get_offer(j, o.service_id)["provider"] == df
    assert V._find_any_offer(j, o.service_id)["provider"] == df
    with pytest.raises(PermissionError):
        V.revoke_subscriber(j, pv, dv, s.subscription_id, "vol")
    # Même signée directement, la révocation de l'usurpateur ne compte pas.
    V._signer_et_ajouter(j, pv, dv, Op.SERVICE_REVOKE_OFFER_SUB, "ServiceRevokeOfferSub",
                         {"subscription_id": s.subscription_id, "provider": dv, "motif": "vol"})
    V._signer_et_ajouter(j, pv, dv, Op.SERVICE_APPROVE, "ServiceApprove",
                         {"subscription_id": s.subscription_id, "service_id": o.service_id, "approver": dv})
    assert V.subscription_state(j, s.subscription_id) is SubscriptionState.PENDING


def test_abonnement_lie_au_fournisseur(j):
    pf, df, pa, da, o, _s = _abonne(j)
    _px, _, dx = _membre(j)
    with pytest.raises(ValueError, match="fournisseur"):
        V.subscribe(j, pa, da, o.service_id, provider=dx)
    s = V.subscribe(j, pa, da, o.service_id, provider=df)
    assert s.provider == df and V.subscription_state(j, s.subscription_id) is SubscriptionState.APPROVED


def test_echeance_bornee_par_la_duree_de_l_offre(j):
    pf, df, pa, da, o, _s = _abonne(j, duree_s=3600)
    loin = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
    s = V.subscribe(j, pa, da, o.service_id, expire_le=loin)
    ech = datetime.fromisoformat(V.echeance_abonnement(j, s.subscription_id))
    assert ech <= datetime.now(timezone.utc) + timedelta(seconds=3601)
    sans = V.subscribe(j, pa, da, o.service_id)                    # sans expire_le : demande + duree_s
    assert V.echeance_abonnement(j, sans.subscription_id) is not None
    # Renouvellement signé avec une échéance démesurée : plafonné à une période.
    avant = datetime.fromisoformat(V.echeance_abonnement(j, s.subscription_id))
    V._signer_et_ajouter(j, pa, da, Op.SERVICE_RENEW, "ServiceRenew",
                         {"subscription_id": s.subscription_id, "service_id": o.service_id, "subscriber": da,
                          "expire_le": loin, "renewed_at": datetime.now(timezone.utc).isoformat()})
    apres = datetime.fromisoformat(V.echeance_abonnement(j, s.subscription_id))
    assert apres - avant == timedelta(seconds=3600)


def test_export_exclut_l_usurpateur_et_les_observateurs(j):
    pf, df, pa, da, o, s = _abonne(j)
    pv, _, dv = _membre(j)
    charge = dict(o.model_dump(exclude={"sig", "signer_did"}, exclude_none=True), provider=dv)
    V._signer_et_ajouter(j, pv, dv, Op.SERVICE_OFFER, "ServiceOffer", charge)
    ex = MX.construire(j, da, {})
    auteurs = {e["author"] for e in ex["entrees"] if e["op"] == "service_offer"}
    assert auteurs == {df}
