# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3647 — MirrorNet phase 3 : états dérivés à horloge simulée, synchronisation vérifiée de l'export de l'annuaire,
catalogue filtré par niveau de confiance, routes d'écriture relayées (jeton de l'administrateur), idempotence."""
import hashlib
import importlib
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))

from secubox_mirrornet import abonnements as A  # noqa: E402
from secubox_mirrornet import catalogue, schema  # noqa: E402
from secubox_mirrornet.verif import canonical_bytes  # noqa: E402

T0 = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


# --- fabrique d'entrées signées (mêmes règles que l'annuaire) -------------------------------------------------------

class Noeud:
    def __init__(self, nom):
        self.cle = Ed25519PrivateKey.generate()
        self.pub = self.cle.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.did = "did:plc:" + hashlib.sha256(bytes.fromhex(self.pub)).hexdigest()[:32]
        self.nom = nom

    def signe(self, op, charge):
        return {"op": op, "payload_type": "x", "payload": charge, "author": self.did, "author_pubkey": self.pub,
                "sig": self.cle.sign(canonical_bytes(charge)).hex()}


def offre(n, sid=None, **etendus):
    charge = {"service_id": sid or uuid.uuid4().hex, "provider": n.did, "name": "Miroir apt", "kind": "mirror",
              "endpoint": "http://10.10.0.2/apt", "scope": {}, "approval_mode": "auto", "description": "",
              "pac": None, "created_at": T0.isoformat()}
    charge.update(etendus)
    return n.signe("service_offer", charge)


def abonnement(n, sid, expire=None, sub_id=None):
    charge = {"subscription_id": sub_id or uuid.uuid4().hex, "subscriber": n.did, "service_id": sid,
              "requested_at": T0.isoformat()}
    if expire:
        charge["expire_le"] = expire
    return n.signe("service_subscribe", charge)


def export(soi, entrees, noeuds, joign=None):
    return {"format": 1, "soi": soi.did if soi else None, "hauteur": 42, "genere_le": T0.isoformat(),
            "entrees": entrees, "joignabilite": joign or {},
            "noeuds": {n.did: {"boxname": n.nom, "mesh_ip": None, "niveau": niv, "cause": "test"} for n, niv in noeuds}}


@pytest.fixture
def cx(tmp_path):
    schema.initialiser(tmp_path / "m.db")
    c = schema.ouvrir(tmp_path / "m.db")
    yield c
    c.close()


def _etat(cx, sub_id):
    return cx.execute("SELECT vers, motif FROM subscription_event e JOIN subscription s ON s.id = e.subscription_id "
                      "WHERE s.ref_annuaire = ? ORDER BY e.ts DESC, e.rowid DESC LIMIT 1", (sub_id,)).fetchone()


# --- dérivation pure -------------------------------------------------------------------------------------------------

def test_transitions_a_horloge_simulee():
    fin = (T0 + timedelta(hours=1)).isoformat()
    f = A.Faits(role="abonne", expire_le=fin, approbation_auto=False, grace_s=600)
    assert A.deriver(f, T0)[0] == "Demande"
    f.approuve = True
    assert A.deriver(f, T0)[0] == "Actif"
    f.echec_fournisseur_depuis = T0.isoformat()
    assert A.deriver(f, T0 + timedelta(minutes=5))[0] == "Grace"
    assert A.deriver(f, T0 + timedelta(minutes=11))[0] == "Suspendu"
    f.echec_fournisseur_depuis = None
    assert A.deriver(f, T0 + timedelta(hours=1))[0] == "Expire"
    f.renouvellements.append(((T0 + timedelta(minutes=50)).isoformat(), (T0 + timedelta(hours=2)).isoformat()))
    etat, _m, ech = A.deriver(f, T0 + timedelta(hours=1, minutes=30))
    assert etat == "Actif" and ech == T0 + timedelta(hours=2)
    f.resilie_par_abonne = "fin"                       # la résiliation l'emporte sur le renouvellement
    assert A.deriver(f, T0)[:2] == ("Resilie", "résilié par l'abonné : fin")
    g = A.Faits(role="abonne", approbation_auto=True, rejete=True)
    assert A.deriver(g, T0)[0] == "Refuse"


def test_renouvellement_signe_apres_l_echeance_ignore():
    fin = (T0 + timedelta(hours=1)).isoformat()
    f = A.Faits(role="abonne", expire_le=fin, approbation_auto=True,
                renouvellements=[((T0 + timedelta(hours=2)).isoformat(), (T0 + timedelta(days=30)).isoformat())])
    assert A.deriver(f, T0 + timedelta(hours=3))[0] == "Expire"


def test_fournisseur_pas_de_grace_cote_fournisseur():
    f = A.Faits(role="fournisseur", approbation_auto=True, echec_fournisseur_depuis=T0.isoformat(), grace_s=1)
    assert A.deriver(f, T0 + timedelta(days=9))[0] == "Actif"


@pytest.mark.parametrize("champ,attendu", [("revoque_par_fournisseur", "abonné révoqué par le fournisseur"),
                                           ("fournisseur_revoque", "fournisseur révoqué dans le journal"),
                                           ("offre_retiree", "offre retirée par le fournisseur")])
def test_causes_de_resiliation(champ, attendu):
    f = A.Faits(role="abonne", approbation_auto=True)
    setattr(f, champ, "" if champ == "revoque_par_fournisseur" else True)
    assert A.deriver(f, T0)[:2] == ("Resilie", attendu)


# --- synchronisation vérifiée -------------------------------------------------------------------------------------------

def test_synchro_offres_verifiees_et_abonnement_de_soi(cx):
    f, moi, tiers = Noeud("gk6"), Noeud("gk12"), Noeud("gk4")
    o = offre(f, duree_s=3600, tarif={"modele": "gratuit"}, classe="public")
    sid = o["payload"]["service_id"]
    s_moi = abonnement(moi, sid, expire=(T0 + timedelta(hours=1)).isoformat())
    s_tiers = abonnement(tiers, sid)
    ex = export(moi, [o, s_moi, s_tiers], [(f, "LIMITED"), (moi, "LIMITED"), (tiers, "LIMITED")])
    st = catalogue.synchroniser(cx, ex, T0)
    assert st["offres"] == 1 and st["abonnements"] == 1 and st["rejetees"] == 0 and st["transitions"] == 1
    assert _etat(cx, s_moi["payload"]["subscription_id"])[0] == "Actif"
    assert _etat(cx, s_tiers["payload"]["subscription_id"]) is None       # abonnement d'un tiers : pas indexé
    # Deuxième passe identique : aucun nouvel événement (ajout seul, seulement aux changements).
    assert catalogue.synchroniser(cx, ex, T0 + timedelta(minutes=1))["transitions"] == 0
    # L'échéance passe : Expire, un événement de plus.
    assert catalogue.synchroniser(cx, ex, T0 + timedelta(hours=2))["transitions"] == 1
    assert _etat(cx, s_moi["payload"]["subscription_id"])[0] == "Expire"
    assert cx.execute("SELECT soi, hauteur FROM synchro").fetchone()[0] == moi.did


def test_signature_falsifiee_cle_d_autrui_et_vol_d_identifiant_rejetes(cx):
    f, pirate = Noeud("gk6"), Noeud("x")
    bonne = offre(f, sid="ab" * 16)
    falsifiee = json.loads(json.dumps(offre(f)))
    falsifiee["payload"]["name"] = "Autre nom"                       # charge modifiée après signature
    usurpee = offre(f)
    usurpee["author_pubkey"] = pirate.pub                            # clé qui ne hache pas vers le did
    vol = offre(pirate, sid="ab" * 16)                               # même service_id, autre fournisseur
    mal_formee = offre(f, classe="secret")
    ex = export(None, [bonne, falsifiee, usurpee, vol, mal_formee], [(f, "LIMITED"), (pirate, "LIMITED")])
    st = catalogue.synchroniser(cx, ex, T0)
    assert st["offres"] == 1 and st["rejetees"] == 4
    assert cx.execute("SELECT fournisseur_did FROM offer").fetchone()[0] == f.did


def test_gestes_de_la_mauvaise_partie_ignores(cx):
    f, moi, tiers = Noeud("gk6"), Noeud("gk12"), Noeud("gk4")
    o = offre(f, approval_mode="pending")
    sid = o["payload"]["service_id"]
    s = abonnement(moi, sid)
    sub_id = s["payload"]["subscription_id"]
    faux_ok = tiers.signe("service_approve", {"subscription_id": sub_id, "service_id": sid, "approver": tiers.did,
                                              "approved_at": T0.isoformat()})
    faux_revoc = tiers.signe("service_revoke_offer_sub", {"op": "service_revoke_offer_sub", "subscription_id": sub_id,
                                                          "provider": tiers.did, "motif": "x", "revoked_at": T0.isoformat()})
    ex = export(moi, [o, s, faux_ok, faux_revoc], [(f, "LIMITED"), (moi, "LIMITED"), (tiers, "LIMITED")])
    catalogue.synchroniser(cx, ex, T0)
    assert _etat(cx, sub_id)[0] == "Demande"
    vrai_ok = f.signe("service_approve", {"subscription_id": sub_id, "service_id": sid, "approver": f.did,
                                          "approved_at": T0.isoformat()})
    ex["entrees"].append(vrai_ok)
    catalogue.synchroniser(cx, ex, T0)
    assert _etat(cx, sub_id)[0] == "Actif"
    ex["entrees"].append(f.signe("service_revoke_offer_sub", {"op": "service_revoke_offer_sub", "subscription_id": sub_id,
                                                              "provider": f.did, "motif": "quota",
                                                              "revoked_at": T0.isoformat()}))
    catalogue.synchroniser(cx, ex, T0)
    assert tuple(_etat(cx, sub_id)) == ("Resilie", "abonné révoqué par le fournisseur : quota")
    historique = [r[0] for r in cx.execute("SELECT vers FROM subscription_event ORDER BY rowid")]
    assert historique == ["Demande", "Actif", "Resilie"]


def test_grace_puis_suspension_par_la_joignabilite(cx):
    f, moi = Noeud("gk6"), Noeud("gk12")
    o = offre(f, grace_s=600)
    s = abonnement(moi, o["payload"]["service_id"])
    sub_id = s["payload"]["subscription_id"]
    joign = {f.did: {"ok_le": None, "echec_depuis": T0.isoformat()}}
    ex = export(moi, [o, s], [(f, "LIMITED"), (moi, "LIMITED")], joign)
    catalogue.synchroniser(cx, ex, T0 + timedelta(minutes=2))
    assert _etat(cx, sub_id)[0] == "Grace"
    catalogue.synchroniser(cx, ex, T0 + timedelta(minutes=20))
    assert _etat(cx, sub_id)[0] == "Suspendu"
    ex["joignabilite"] = {f.did: {"ok_le": T0.isoformat(), "echec_depuis": None}}
    catalogue.synchroniser(cx, ex, T0 + timedelta(minutes=21))
    assert _etat(cx, sub_id)[0] == "Actif"


def test_export_absent_ou_invalide(tmp_path):
    with pytest.raises(catalogue.ExportIllisible, match="absent"):
        catalogue.lire_export(tmp_path / "rien.json")
    (tmp_path / "e.json").write_text('{"format": 9}')
    with pytest.raises(catalogue.ExportIllisible, match="format"):
        catalogue.lire_export(tmp_path / "e.json")


# --- API ---------------------------------------------------------------------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    from secubox_mirrornet import config
    import secubox_core.auth as auth
    main = importlib.import_module("api.main")
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": "admin"} if t.startswith("jeton") else None)
    monkeypatch.setattr(config, "BASE", tmp_path / "m.db")
    monkeypatch.setattr(config, "EXPORT", tmp_path / "export.json")
    monkeypatch.setattr(config, "CONF", tmp_path / "absent.toml")
    schema.initialiser(tmp_path / "m.db")
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield main, tmp_path
    main.app.dependency_overrides.clear()


def _ecrire(tmp, ex):
    (tmp / "export.json").write_text(json.dumps(ex))


def test_catalogue_filtre_par_niveau(api):
    main, tmp = api
    moi, lim, obs, rev = Noeud("gk12"), Noeud("gk6"), Noeud("obs"), Noeud("rev")
    o_ok = offre(lim, tarif={"modele": "gratuit"}, classe="public")
    o_payante = offre(lim, tarif={"modele": "forfait", "credits": 100}, classe="public")
    o_obs, o_rev, o_moi = offre(obs), offre(rev), offre(moi)
    _ecrire(tmp, export(moi, [o_ok, o_payante, o_obs, o_rev, o_moi],
                        [(moi, "LIMITED"), (lim, "LIMITED"), (obs, "OBSERVER"), (rev, "REVOKED")]))
    main.synchroniser_maintenant()
    c = TestClient(main.app)
    ids = {s["id"]: s for s in c.get("/api/v1/mirrornet/services").json()["services"]}
    assert set(ids) == {o_ok["payload"]["service_id"], o_moi["payload"]["service_id"]}
    assert ids[o_moi["payload"]["service_id"]]["mienne"] is True
    assert c.get(f"/api/v1/mirrornet/services/{o_rev['payload']['service_id']}").status_code == 404
    assert c.get(f"/api/v1/mirrornet/services/{o_ok['payload']['service_id']}").json()["fournisseur"] == "gk6"


def _annuaire_simule(main, tmp, moi, ex, monkeypatch, appels):
    def appeler(chemin, corps, jeton, socket_chemin=None):
        appels.append((chemin, corps, jeton))
        if chemin.endswith("/subscribe"):
            sid = chemin.split("/")[3]
            s = moi.signe("service_subscribe", dict(abonnement(moi, sid)["payload"],
                                                    requested_at=datetime.now(timezone.utc).isoformat()))
            ex["entrees"].append(s)
            _ecrire(tmp, ex)
            return 200, dict(s["payload"], state="approved")
        if chemin.endswith("/cancel"):
            sub_id = chemin.split("/")[3]
            ex["entrees"].append(moi.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub_id,
                                                                  "subscriber": moi.did, "motif": corps["motif"],
                                                                  "revoked_at": T0.isoformat()}))
            _ecrire(tmp, ex)
            return 200, {"status": "revoked", "par": "abonne"}
        return 409, {"detail": "refusé par l'annuaire"}
    monkeypatch.setattr(main.annuaire, "appeler", appeler)


def test_abonnement_relaye_idempotent_puis_resiliation(api, monkeypatch):
    main, tmp = api
    moi, f = Noeud("gk12"), Noeud("gk6")
    o = offre(f, tarif={"modele": "gratuit"}, classe="public")
    sid = o["payload"]["service_id"]
    ex = export(moi, [o], [(moi, "LIMITED"), (f, "LIMITED")])
    _ecrire(tmp, ex)
    appels = []
    _annuaire_simule(main, tmp, moi, ex, monkeypatch, appels)
    c = TestClient(main.app)
    h = {"Authorization": "Bearer jeton-admin", "X-Idempotence": "cle-abonnement-1"}
    c.headers["Authorization"] = "Bearer jeton-admin"
    r = c.post(f"/api/v1/mirrornet/services/{sid}/subscribe", headers=h)
    assert r.status_code == 200, r.text
    sub = r.json()
    assert sub["etat"] == "Actif" and sub["existant"] is False and sub["role"] == "abonne"
    assert appels[0][0] == f"/self/service/{sid}/subscribe" and appels[0][2] == "jeton-admin"
    assert appels[0][1] == {"provider": f.did}                     # le fournisseur évalué part avec la demande
    # Même clé : réponse rejouée, aucun nouvel appel. Autre clé : l'abonnement en cours est rendu (`existant`).
    assert c.post(f"/api/v1/mirrornet/services/{sid}/subscribe", headers=h).json() == sub
    r2 = c.post(f"/api/v1/mirrornet/services/{sid}/subscribe", headers={"X-Idempotence": "cle-abonnement-2"})
    assert r2.json()["existant"] is True and len(appels) == 1
    # Clé réutilisée pour une autre requête : 409.
    assert c.delete(f"/api/v1/mirrornet/subscriptions/{sub['id']}", headers=h).status_code == 409
    r = c.delete(f"/api/v1/mirrornet/subscriptions/{sub['id']}?motif=fin")
    assert r.status_code == 200 and appels[-1][1] == {"motif": "fin"}
    d = c.get(f"/api/v1/mirrornet/subscriptions/{sub['id']}").json()
    assert d["etat"] == "Resilie" and [h["vers"] for h in d["historique"]] == ["Actif", "Resilie"]
    assert c.delete(f"/api/v1/mirrornet/subscriptions/{sub['id']}").status_code == 409     # déjà clos


def test_evaluation_refuse_sans_appeler_l_annuaire(api, monkeypatch):
    main, tmp = api
    moi, obs = Noeud("gk12"), Noeud("obs")
    o_moi, o_obs = offre(moi), offre(obs)
    ex = export(moi, [o_moi, o_obs], [(moi, "LIMITED"), (obs, "OBSERVER")])
    _ecrire(tmp, ex)
    appels = []
    _annuaire_simule(main, tmp, moi, ex, monkeypatch, appels)
    c = TestClient(main.app)
    r = c.post(f"/api/v1/mirrornet/services/{o_moi['payload']['service_id']}/subscribe")
    assert r.status_code == 409 and "propre offre" in r.json()["detail"]
    r = c.post(f"/api/v1/mirrornet/services/{o_obs['payload']['service_id']}/subscribe")
    assert r.status_code == 409 and "OBSERVER" in r.json()["detail"]
    assert appels == []


def test_echec_libere_la_cle_d_idempotence(api, monkeypatch):
    main, tmp = api
    moi, f = Noeud("gk12"), Noeud("gk6")
    o = offre(f)
    _ecrire(tmp, export(moi, [o], [(moi, "LIMITED"), (f, "LIMITED")]))
    monkeypatch.setattr(main.annuaire, "appeler", lambda *a, **k: (503, {"detail": "annuaire injoignable"}))
    c = TestClient(main.app)
    h = {"X-Idempotence": "cle-echec-0001"}
    assert c.post(f"/api/v1/mirrornet/services/{o['payload']['service_id']}/subscribe", headers=h).status_code == 503
    cx = schema.ouvrir(tmp / "m.db")
    assert cx.execute("SELECT COUNT(*) FROM requete").fetchone()[0] == 0
    cx.close()
    assert c.post("/api/v1/mirrornet/services/x/subscribe", headers={"X-Idempotence": "court"}).status_code == 404


def test_publication_valide_et_jeux_de_donnees_permis(api, monkeypatch):
    main, tmp = api
    _ecrire(tmp, export(None, [], []))
    appels = []
    monkeypatch.setattr(main.annuaire, "appeler", lambda ch, corps, j, **k: appels.append((ch, corps)) or (200, {"ok": 1}))
    c = TestClient(main.app)
    corps = {"name": "Miroir", "kind": "mirror", "endpoint": "http://10.10.0.2/a", "tarif": {"modele": "gratuit"},
             "duree_s": 86400}
    assert c.post("/api/v1/mirrornet/services/publish", json=corps).status_code == 200
    assert appels == [("/self/service/offer", dict(corps, approval_mode="pending", description=""))]
    assert c.post("/api/v1/mirrornet/services/publish", json=corps, headers={"X-Idempotence": "cle-pub-0001"}).status_code == 200
    assert c.post("/api/v1/mirrornet/services/publish", json=dict(corps, endpoint="http://autre"),
                  headers={"X-Idempotence": "cle-pub-0001"}).status_code == 409   # même clé, autre corps
    assert c.post("/api/v1/mirrornet/services/publish", json=dict(corps, kind="dataset")).status_code == 200   # #3653
    assert c.post("/api/v1/mirrornet/services/publish", json=dict(corps, inconnu=1)).status_code == 422


def test_relais_du_seul_jeton_valide(api):
    main, _tmp = api
    from secubox_core.auth import SESSION_COOKIE
    from starlette.requests import Request

    def req(*h):
        return Request({"type": "http", "headers": list(h)})
    cookie = (b"cookie", f"{SESSION_COOKIE}=jeton-cookie".encode())
    assert main._jeton(req((b"authorization", b"Bearer jeton-a"), cookie)) == "jeton-a"
    assert main._jeton(req((b"authorization", b"Bearer perime"), cookie)) == "jeton-cookie"   # le validé, pas l'autre
    assert main._jeton(req((b"authorization", b"Bearer perime"))) is None


def test_reponse_indeterminee_jamais_rejouee(api, monkeypatch):
    main, tmp = api
    moi, f = Noeud("gk12"), Noeud("gk6")
    o = offre(f)
    _ecrire(tmp, export(moi, [o], [(moi, "LIMITED"), (f, "LIMITED")]))
    appels = []
    monkeypatch.setattr(main.annuaire, "appeler",
                        lambda *a, **k: appels.append(a) or (504, {"detail": "annuaire sans réponse"}))
    c = TestClient(main.app)
    h = {"X-Idempotence": "cle-indeterminee", "Authorization": "Bearer jeton-admin"}
    url = f"/api/v1/mirrornet/services/{o['payload']['service_id']}/subscribe"
    assert c.post(url, headers=h).status_code == 504
    assert c.post(url, headers=h).status_code == 504 and len(appels) == 1     # pas de seconde signature


def test_topologie_masquee_au_lecteur_anonyme(api):
    main, tmp = api
    moi, f = Noeud("gk12"), Noeud("gk6")
    o = offre(f, tarif={"modele": "gratuit"}, classe="public", sonde="/sante")
    _ecrire(tmp, export(moi, [o], [(moi, "LIMITED"), (f, "LIMITED")]))
    main.synchroniser_maintenant()
    c = TestClient(main.app)
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}
    s = c.get("/api/v1/mirrornet/services").json()["services"][0]
    assert "endpoint" not in s and "sonde" not in s and "fournisseur_echec_depuis" not in s
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "admin"}
    assert c.get("/api/v1/mirrornet/services").json()["services"][0]["endpoint"] == "http://10.10.0.2/apt"


def test_abonnement_lie_a_un_autre_fournisseur_rejete(cx):
    f, moi, x = Noeud("gk6"), Noeud("gk12"), Noeud("x")
    o = offre(f)
    s = abonnement(moi, o["payload"]["service_id"])
    s = moi.signe("service_subscribe", dict(s["payload"], provider=x.did))
    st = catalogue.synchroniser(cx, export(moi, [o, s], [(f, "LIMITED"), (moi, "LIMITED")]), T0)
    assert st["abonnements"] == 0 and st["rejetees"] == 1


def test_echeance_bornee_et_demande_dans_le_futur():
    f = A.Faits(role="fournisseur", approbation_auto=True, demande_le=T0.isoformat(), duree_s=3600,
                expire_le=(T0 + timedelta(days=3650)).isoformat())
    assert A.deriver(f, T0 + timedelta(hours=2))[0] == "Expire"           # échéance plafonnée à demande + durée
    f.renouvellements = [((T0 + timedelta(minutes=30)).isoformat(), (T0 + timedelta(days=999)).isoformat())]
    assert A.deriver(f, T0 + timedelta(hours=1))[2] == T0 + timedelta(hours=2)   # une période au plus
    g = A.Faits(role="fournisseur", approbation_auto=True, demande_le=(T0 + timedelta(days=1)).isoformat())
    assert A.deriver(g, T0)[0] == "Demande"


def test_toml_livre_lisible_et_applique(monkeypatch):
    from secubox_mirrornet import config
    monkeypatch.setattr(config, "CONF", ICI / "conf" / "mirrornet.toml")
    import tomllib
    tomllib.loads((ICI / "conf" / "mirrornet.toml").read_text())
    assert config.reglages() == {"confiance_min": "LIMITED", "grace_s": 432000, "intervalle_s": 60,
                                 "taille_max_mo": 256, "garder": 3, "reserve_mo": 1024}


def test_charge_reetiquetee_ou_au_nom_d_un_autre_rejetee(cx):
    """C2 / C1 côté MirrorNet : un renouvellement réétiqueté en résiliation, un abonnement signé au nom d'autrui."""
    f, moi, x = Noeud("gk6"), Noeud("gk12"), Noeud("x")
    o = offre(f)
    s = abonnement(moi, o["payload"]["service_id"])
    sub_id = s["payload"]["subscription_id"]
    renouv = moi.signe("service_renew", {"op": "service_renew", "subscription_id": sub_id, "subscriber": moi.did,
                                         "renewed_at": T0.isoformat(), "expire_le": (T0 + timedelta(days=1)).isoformat()})
    reetiquete = dict(renouv, op="service_revoke_sub")
    au_nom = x.signe("service_subscribe", dict(s["payload"], subscription_id="e" * 64))      # subscriber = moi
    st = catalogue.synchroniser(cx, export(moi, [o, s, reetiquete, au_nom], [(f, "LIMITED"), (moi, "LIMITED")]), T0)
    assert st["rejetees"] == 2 and st["abonnements"] == 1
    assert _etat(cx, sub_id)[0] == "Actif"
