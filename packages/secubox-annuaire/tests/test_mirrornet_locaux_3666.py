# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Indices TV Privacy (#3666) côté annuaire : offre, versions et abonnements « tv-indices » signés en tâche de fond à
partir de la demande `publications.json` déposée par secubox-mirrornet."""
import asyncio
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from annuaire import confiance
from annuaire import mirrornet_locaux as ML
from annuaire import verbs as V
from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.model import Identity, MemberState, Op, SubscriptionState
from tests.test_mirrornet_cycle_3647 import _membre, j  # noqa: F401 (fixture)

E1 = "b2:" + "1" * 64
E2 = "b2:" + "2" * 64
E3 = "b2:" + "3" * 64


def _dem(publier=True, recevoir=True, empreinte=E1, taille=120):
    if empreinte is None:
        taille = None
    return {"publier": publier, "recevoir": recevoir, "empreinte": empreinte, "taille": taille}


def _hauteur(j):  # noqa: F811
    return sum(1 for _ in j.iter_entries())


def _maintenant(minutes=0):
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def _tv(j, priv, did, **kw):  # noqa: F811
    kw.setdefault("scope", {"usage": "tv-indices"})
    return V.offer_service(j, priv, did, name="Indices TV Privacy — autre", kind=kw.pop("kind", "dataset"),
                           endpoint="mirrornet://x", approval_mode="auto", classe="communaute", **kw)


def _observateur(j):  # noqa: F811
    """Identité connue du journal mais pas MEMBER (niveau OBSERVER)."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=hashlib.sha256(pub).hexdigest()[:32],
                     state=MemberState.OBSERVED)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    j.append(op=Op.AUTO_ADD, payload_type="Identity", payload=payload, author=did,
             sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, did


def _mes_offres(j, did):  # noqa: F811
    return [o for o in V._get_offers(j) if o.get("provider") == did]


# --- publication ------------------------------------------------------------------------------------------------

def test_offre_creee_puis_idempotente(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    gestes = []
    r = ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant(),
                   auditer=lambda action, **d: gestes.append((action, d)))
    assert r == {"offre": "creee", "version": E1, "abonnements": 0, "resiliations": 0}
    (o,) = _mes_offres(j, did)
    assert o["name"] == "Indices TV Privacy — gk6" and o["kind"] == "dataset"
    assert o["approval_mode"] == "auto" and o["scope"] == {"usage": "tv-indices"} and o["classe"] == "communaute"
    (v,) = V.dataset_versions(j, o["service_id"])
    assert (v["empreinte"], v["taille"], v["numero"], v["classe"], v["format"], v["licence"], v["provenance"],
            v["donnees_personnelles"]) == (E1, 120, 1, "communaute", "application/json", "CC0-1.0",
                                           "secubox-ad-guard:tv-indices", "non")
    assert [g[0] for g in gestes] == ["mirrornet_tv_indices_offre_publiee", "mirrornet_tv_indices_version_publiee"]
    h = _hauteur(j)
    r2 = ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant(120))
    assert r2 == {"offre": "existante", "version": None, "abonnements": 0, "resiliations": 0}
    assert _hauteur(j) == h


def test_offre_sans_empreinte_puis_version(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    r = ML.traiter(j, priv, did, "gk6", _dem(empreinte=None, recevoir=False), _maintenant())
    assert r["offre"] == "creee" and r["version"] is None
    (o,) = _mes_offres(j, did)
    assert V.dataset_versions(j, o["service_id"]) == []
    r = ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant())
    assert r["offre"] == "existante" and r["version"] == E1


def test_nom_de_box_absent_ou_hostile(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    ML.traiter(j, priv, did, "", _dem(empreinte=None, recevoir=False), _maintenant())
    (o,) = _mes_offres(j, did)
    assert o["name"] == f"Indices TV Privacy — box-{did[8:16]}"
    p2, _, d2 = _membre(j)
    ML.traiter(j, p2, d2, "gk\n7" + "x" * 200, _dem(empreinte=None, recevoir=False), _maintenant())
    (o2,) = _mes_offres(j, d2)
    assert "\n" not in o2["name"] and len(o2["name"]) <= 80


def test_une_version_par_heure_au_plus(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant())
    r = ML.traiter(j, priv, did, "gk6", _dem(empreinte=E2, recevoir=False), _maintenant(10))
    assert r["version"] is None                                  # contenu changé, mais moins d'une heure
    r = ML.traiter(j, priv, did, "gk6", _dem(empreinte=E2, recevoir=False), _maintenant(61))
    assert r["version"] == E2
    (o,) = _mes_offres(j, did)
    vs = V.dataset_versions(j, o["service_id"])
    assert [v["numero"] for v in vs] == [1, 2] and vs[1]["parent"] == E1
    h = _hauteur(j)
    # Même contenu qu'une version passée (immuable) : rien, sans exception ; même contenu que la dernière : rien.
    assert ML.traiter(j, priv, did, "gk6", _dem(empreinte=E1, recevoir=False), _maintenant(200))["version"] is None
    assert ML.traiter(j, priv, did, "gk6", _dem(empreinte=E2, recevoir=False), _maintenant(200))["version"] is None
    assert _hauteur(j) == h
    assert ML.traiter(j, priv, did, "gk6", _dem(empreinte=E3, recevoir=False), _maintenant(200))["version"] == E3


def test_publier_faux_retire_l_offre(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant())
    gestes = []
    r = ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None, recevoir=False), _maintenant(),
                   auditer=lambda action, **d: gestes.append(action))
    assert r["offre"] == "retiree" and r["version"] is None
    assert _mes_offres(j, did) == [] and gestes == ["mirrornet_tv_indices_offre_retiree"]
    h = _hauteur(j)
    r = ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None, recevoir=False), _maintenant())
    assert r["offre"] is None and _hauteur(j) == h


def test_offre_d_un_autre_usage_jamais_retiree(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    autre = V.offer_service(j, priv, did, name="Météo", kind="dataset", endpoint="mesh:m", approval_mode="auto")
    ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None, recevoir=False), _maintenant())
    assert [o["service_id"] for o in _mes_offres(j, did)] == [autre.service_id]


# --- réception --------------------------------------------------------------------------------------------------

def _maillage(j):  # noqa: F811
    priv, _pub, did = _membre(j)                                 # ce nœud
    pb, _, db = _membre(j)                                       # membre LIMITED avec une offre tv-indices
    V.publish_node(j, pb, db, node_id="sb-b", boxname="gk9", pubkey_wg="A" * 43 + "=", mesh_ip="10.10.0.9", ddns="")
    ob = _tv(j, pb, db)
    po, do = _observateur(j)                                     # OBSERVER avec une offre tv-indices
    assert confiance.niveau(j, do)[0] == "OBSERVER" and confiance.niveau(j, db)[0] == "LIMITED"
    oo = _tv(j, po, do)
    pn, _, dn = _membre(j)                                       # membre : jeu sans usage, ou usage tv mais pas dataset
    on = V.offer_service(j, pn, dn, name="Sans usage", kind="dataset", endpoint="mesh:n", approval_mode="auto")
    oa = _tv(j, pn, dn, kind="api")
    return priv, did, (pb, db, ob), (do, oo), (on, oa)


def _mes_abonnements(j, did):  # noqa: F811
    return [e.payload for e in j.iter_entries(ops=("service_subscribe",)) if e.author == did]


def test_abonnement_auto_aux_seuls_membres_de_confiance(j):  # noqa: F811
    priv, did, (_pb, db, ob), (_do, oo), (on, oa) = _maillage(j)
    gestes = []
    r = ML.traiter(j, priv, did, "gk6", _dem(), _maintenant(), auditer=lambda action, **d: gestes.append((action, d)))
    assert r["abonnements"] == 1
    (s,) = _mes_abonnements(j, did)
    assert s["service_id"] == ob.service_id and s["provider"] == db
    assert V.subscription_state(j, s["subscription_id"]) is SubscriptionState.APPROVED
    assert ("mirrornet_tv_indices_abonnement" in [g[0] for g in gestes])
    vus = {s["service_id"] for s in _mes_abonnements(j, did)}
    assert oo.service_id not in vus and on.service_id not in vus and oa.service_id not in vus
    mienne = next(o for o in _mes_offres(j, did) if (o.get("scope") or {}).get("usage") == "tv-indices")
    assert mienne["service_id"] not in vus                       # jamais à sa propre offre
    h = _hauteur(j)
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())["abonnements"] == 0
    assert _hauteur(j) == h


def test_fournisseur_revoque_jamais_ecoute(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    pb, _, db = _membre(j)
    _tv(j, pb, db)
    V.revoke(j, pb, db, db, "auto-révocation")
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())["abonnements"] == 0


def test_recevoir_faux_resilie_puis_vrai_reabonne(j):  # noqa: F811
    priv, did, (_pb, _db, ob), _o, _n = _maillage(j)
    ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())
    (s,) = _mes_abonnements(j, did)
    gestes = []
    r = ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant(),
                   auditer=lambda action, **d: gestes.append(action))
    assert r["resiliations"] == 1 and r["abonnements"] == 0
    assert V.subscription_state(j, s["subscription_id"]) is SubscriptionState.REVOKED
    assert gestes == ["mirrornet_tv_indices_resiliation"]
    h = _hauteur(j)
    assert ML.traiter(j, priv, did, "gk6", _dem(recevoir=False), _maintenant())["resiliations"] == 0
    assert _hauteur(j) == h
    # Réception rallumée : la résiliation de fond n'empêche pas le réabonnement.
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())["abonnements"] == 1
    assert len([s for s in _mes_abonnements(j, did) if s["service_id"] == ob.service_id]) == 2


def test_resiliation_du_proprietaire_respectee(j):  # noqa: F811
    priv, did, _b, _o, _n = _maillage(j)
    ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())
    (s,) = _mes_abonnements(j, did)
    V.cancel_subscription(j, priv, did, s["subscription_id"], "je n'en veux plus")
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())["abonnements"] == 0


def test_revocation_par_le_fournisseur_respectee(j):  # noqa: F811
    priv, did, (pb, db, _ob), _o, _n = _maillage(j)
    ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())
    (s,) = _mes_abonnements(j, did)
    V.revoke_subscriber(j, pb, db, s["subscription_id"], "abus")
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())["abonnements"] == 0


def test_abonnement_echu_renouvele(j):  # noqa: F811
    priv, _pub, did = _membre(j)
    pb, _, db = _membre(j)
    ob = _tv(j, pb, db, duree_s=60)
    ML.traiter(j, priv, did, "gk6", _dem(), _maintenant())
    (s,) = _mes_abonnements(j, did)
    assert s["expire_le"]                                        # échéance de l'offre signée par l'abonné
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant(0.5))["abonnements"] == 0
    assert ML.traiter(j, priv, did, "gk6", _dem(), _maintenant(5))["abonnements"] == 1
    assert {s["service_id"] for s in _mes_abonnements(j, did)} == {ob.service_id}


# --- Review Focus 5 : aucune clé, aucune demande ----------------------------------------------------------------

@pytest.mark.parametrize("priv_vide,did_vide,dem", [
    (True, False, _dem()), (False, True, _dem()), (False, False, None),
    (False, False, {"publier": "oui", "recevoir": True, "empreinte": None, "taille": None}),
    (False, False, {"publier": True, "recevoir": True, "empreinte": "b2:xyz", "taille": 1}),
    (False, False, {"publier": True, "recevoir": True, "empreinte": E1, "taille": None}),
    (False, False, {"publier": True, "recevoir": True, "empreinte": E1, "taille": True}),
])
def test_rien_sans_cle_ni_demande_valide(j, priv_vide, did_vide, dem):  # noqa: F811
    priv, did, _b, _o, _n = _maillage(j)
    h = _hauteur(j)
    r = ML.traiter(j, None if priv_vide else priv, None if did_vide else did, "gk6", dem, _maintenant())
    assert r == {"offre": None, "version": None, "abonnements": 0, "resiliations": 0}
    assert _hauteur(j) == h


# --- lecture de publications.json -------------------------------------------------------------------------------

def _ecrire(chemin, jeu, **dessus):
    d = {"format": 1, "jeux": {"tv-indices": jeu}}
    d.update(dessus)
    chemin.write_text(json.dumps(d))
    return chemin


def test_lire_demandes_valide(tmp_path):
    c = _ecrire(tmp_path / "publications.json", _dem())
    assert ML.lire_demandes(c) == _dem()
    c = _ecrire(tmp_path / "publications.json", _dem(publier=False, empreinte=None))
    assert ML.lire_demandes(c) == _dem(publier=False, empreinte=None)


def test_lire_demandes_chemin_surchargeable(tmp_path, monkeypatch):
    c = _ecrire(tmp_path / "p.json", _dem())
    monkeypatch.setattr(ML, "PUBLICATIONS", c)
    assert ML.lire_demandes() == _dem()


def test_lire_demandes_refuse_lien_gros_invalide(tmp_path):
    vrai = _ecrire(tmp_path / "vrai.json", _dem())
    lien = tmp_path / "lien.json"
    os.symlink(vrai, lien)
    assert ML.lire_demandes(lien) is None
    gros = tmp_path / "gros.json"
    gros.write_text(json.dumps({"format": 1, "jeux": {"tv-indices": _dem()}, "x": "a" * (ML.TAILLE_MAX + 1)}))
    assert ML.lire_demandes(gros) is None
    assert ML.lire_demandes(tmp_path / "absent.json") is None
    assert ML.lire_demandes(tmp_path) is None                    # un dossier
    mauvais = tmp_path / "m.json"
    for brut in ("pas du json", "[]", json.dumps({"format": 2, "jeux": {"tv-indices": _dem()}}),
                 json.dumps({"format": 1, "jeux": {}}), json.dumps({"format": 1, "jeux": {"tv-indices": []}}),
                 json.dumps({"format": 1, "jeux": {"tv-indices": {**_dem(), "taille": -1}}}),
                 json.dumps({"format": 1, "jeux": {"tv-indices": {**_dem(), "taille": 3 * 1024 * 1024}}}),
                 json.dumps({"format": 1, "jeux": {"tv-indices": {**_dem(), "recevoir": 1}}})):
        mauvais.write_text(brut)
        assert ML.lire_demandes(mauvais) is None, brut


# --- branchement dans l'API (tâche de fond) ---------------------------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    from api import main as M
    M._journal = None
    M._DB_PATH = str(tmp_path / "journal.db")
    M._EXPORT_CACHE.update(hauteur=None, donnees=None, le=0.0)
    jj = M.get_journal()
    priv, _pub, did = _membre(jj)
    cle = tmp_path / "node.key"
    cle.write_text(priv.hex())
    monkeypatch.setenv("ANNUAIRE_KEY_PATH", str(cle))
    monkeypatch.setattr(M, "MIRRORNET_EXPORT", tmp_path / "mirrornet-export.json")
    monkeypatch.setattr(M, "AUDIT_DROITS", tmp_path / "audit.log")
    monkeypatch.setattr(ML, "PUBLICATIONS", tmp_path / "publications.json")
    yield M, jj, did, tmp_path
    M._journal = None


def test_fond_signe_audite_par_fond_et_exporte(api):
    M, jj, did, tmp = api
    _ecrire(tmp / "publications.json", _dem(recevoir=False))
    r = M._tv_indices_fond()
    assert r["offre"] == "creee" and r["version"] == E1
    lignes = [json.loads(x) for x in (tmp / "audit.log").read_text().splitlines()]
    assert [x["action"] for x in lignes] == ["mirrornet_tv_indices_offre_publiee", "mirrornet_tv_indices_version_publiee"]
    assert all(x["par"] == "fond" and x["module"] == "annuaire" for x in lignes)
    export = json.loads((tmp / "mirrornet-export.json").read_text())
    assert any(e["op"] == "service_dataset_version" for e in export["entrees"])
    assert M._tv_indices_fond()["offre"] == "existante"
    assert len((tmp / "audit.log").read_text().splitlines()) == 2


def test_fond_sans_cle_ni_fichier_sans_exception(api, monkeypatch):
    M, jj, _did, tmp = api
    h = _hauteur(jj)
    assert M._tv_indices_fond() is None                         # pas de publications.json
    _ecrire(tmp / "publications.json", _dem())
    monkeypatch.setenv("ANNUAIRE_KEY_PATH", str(tmp / "absente.key"))
    assert M._tv_indices_fond() is None                         # node.key absente
    assert _hauteur(jj) == h and not (tmp / "audit.log").exists()


def test_boucle_de_synchro_appelle_le_traitement_et_survit(monkeypatch):
    from api import main as M

    class _Fin(Exception):
        pass

    appels = []
    monkeypatch.setattr(M, "_inscrire_si_besoin", lambda: True)
    monkeypatch.setattr(M, "_cycle_sync", lambda *a, **k: appels.append("sync"))

    def _casse():
        appels.append("tv")
        raise RuntimeError("panne")
    monkeypatch.setattr(M, "_tv_indices_fond", _casse)

    async def _dors(_s):
        raise _Fin

    monkeypatch.setattr(asyncio, "sleep", _dors)
    with pytest.raises(_Fin):
        asyncio.run(M._dir_sync_loop())
    assert appels == ["sync", "tv"]
