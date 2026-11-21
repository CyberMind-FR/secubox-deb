# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3723 — indicateurs d'adresses du WAF (`ip-indices`) signés par l'annuaire comme `tv-indices` : SA propre offre,
ses versions, ses abonnements ; les offres et abonnements tv-indices ne sont jamais touchés par le jeu ip-indices, et
inversement."""
import json
from datetime import datetime, timedelta, timezone

from annuaire import mirrornet_locaux as ML
from annuaire import verbs as V
from annuaire.model import SubscriptionState
from conftest import _membre  # fixtures j : tests/conftest.py

E1 = "b2:" + "1" * 64
E2 = "b2:" + "2" * 64


def _dem(publier=True, recevoir=True, empreinte=E1, taille=120):
    return {"publier": publier, "recevoir": recevoir, "empreinte": empreinte, "taille": taille if empreinte else None}


def _maintenant(minutes=0):
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def _mes_offres(j, did):
    return [o for o in V._get_offers(j) if o.get("provider") == did]


def _usage(o):
    return (o.get("scope") or {}).get("usage")


def _offre_pair(j, priv, did, usage):
    return V.offer_service(j, priv, did, name=f"offre {usage}", kind="dataset", endpoint="mirrornet://x",
                           approval_mode="auto", classe="communaute", scope={"usage": usage})


def _mes_abonnements(j, did):
    return [e.payload for e in j.iter_entries(ops=("service_subscribe",)) if e.author == did]


def test_tv_constantes_inchangees():
    assert ML.USAGE == "tv-indices" and ML.JEUX["tv-indices"]["offre"] is ML.OFFRE
    assert ML.OFFRE == {"kind": "dataset", "approval_mode": "auto", "classe": "communaute",
                        "scope": {"usage": "tv-indices"}, "description": ML.OFFRE["description"]}
    assert ML.MANIFESTE["provenance"] == "secubox-ad-guard:tv-indices"
    assert ML.JEUX["tv-indices"]["audit"] == "mirrornet_tv_indices"


def test_offre_ip_indices_creee_signee_et_versionnee(j):
    priv, _pub, did = _membre(j)
    gestes = []
    r = ML.traiter(j, priv, did, "gk2", _dem(recevoir=False), _maintenant(),
                   auditer=lambda action, **d: gestes.append(action), jeu="ip-indices")
    assert r == {"offre": "creee", "version": E1, "abonnements": 0, "resiliations": 0}
    (o,) = _mes_offres(j, did)
    assert o["scope"] == {"usage": "ip-indices"} and o["kind"] == "dataset" and o["classe"] == "communaute"
    assert o["endpoint"] == f"mirrornet://{did}/ip-indices" and o["name"] == "Indicateurs d'adresses — gk2"
    (v,) = V.dataset_versions(j, o["service_id"])
    assert v["empreinte"] == E1 and v["provenance"] == "secubox-waf-ng:ip-indices"
    assert v["donnees_personnelles"] == "agregees"
    assert gestes == ["mirrornet_ip_indices_offre_publiee", "mirrornet_ip_indices_version_publiee"]
    assert ML.traiter(j, priv, did, "gk2", _dem(recevoir=False), _maintenant(120), jeu="ip-indices")["offre"] == \
        "existante"


def test_les_deux_jeux_cote_a_cote_sans_se_toucher(j):
    priv, _pub, did = _membre(j)
    ML.traiter(j, priv, did, "gk2", _dem(recevoir=False), _maintenant(), jeu="tv-indices")
    ML.traiter(j, priv, did, "gk2", _dem(recevoir=False, empreinte=E2), _maintenant(), jeu="ip-indices")
    assert sorted(_usage(o) for o in _mes_offres(j, did)) == ["ip-indices", "tv-indices"]
    tv = next(o for o in _mes_offres(j, did) if _usage(o) == "tv-indices")
    # l'offre tv reste conforme : jamais retirée ni recréée par l'un ou l'autre jeu
    for jeu in ("tv-indices", "ip-indices"):
        assert ML.traiter(j, priv, did, "gk2", _dem(recevoir=False), _maintenant(180), jeu=jeu)["offre"] == "existante"
    assert ML._conforme(tv) and not ML._conforme(tv, "ip-indices")
    assert [o["service_id"] for o in _mes_offres(j, did) if _usage(o) == "tv-indices"] == [tv["service_id"]]
    # publier faux pour ip-indices : seule son offre est retirée
    r = ML.traiter(j, priv, did, "gk2", _dem(publier=False, empreinte=None, recevoir=False), _maintenant(300),
                   jeu="ip-indices")
    assert r["offre"] == "retiree"
    assert [_usage(o) for o in _mes_offres(j, did)] == ["tv-indices"]


def test_abonnement_ip_indices_et_resiliation_par_jeu(j):
    priv, _pub, did = _membre(j)
    pb, _, db = _membre(j)
    V.publish_node(j, pb, db, node_id="sb-b", boxname="gk9", pubkey_wg="A" * 43 + "=", mesh_ip="10.10.0.9", ddns="")
    o_ip = _offre_pair(j, pb, db, "ip-indices")
    o_tv = _offre_pair(j, pb, db, "tv-indices")
    r = ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None), _maintenant(), jeu="ip-indices")
    assert r["abonnements"] == 1
    (s,) = _mes_abonnements(j, did)
    assert s["service_id"] == o_ip.service_id and s["provider"] == db
    assert V.subscription_state(j, s["subscription_id"]) is SubscriptionState.APPROVED
    # le jeu tv s'abonne à SON offre, et « recevoir faux » côté tv ne résilie jamais l'abonnement ip-indices
    ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None), _maintenant(), jeu="tv-indices")
    assert {x["service_id"] for x in _mes_abonnements(j, did)} == {o_ip.service_id, o_tv.service_id}
    r = ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None, recevoir=False), _maintenant(),
                   jeu="tv-indices")
    assert r["resiliations"] == 1
    assert V.subscription_state(j, s["subscription_id"]) is SubscriptionState.APPROVED
    # et inversement
    r = ML.traiter(j, priv, did, "gk6", _dem(publier=False, empreinte=None, recevoir=False), _maintenant(),
                   jeu="ip-indices")
    assert r["resiliations"] == 1
    assert V.subscription_state(j, s["subscription_id"]) is not SubscriptionState.APPROVED


def test_abonnement_ip_au_seuil_de_mirrornet(j):
    priv, _pub, did = _membre(j)
    pb, _, db = _membre(j)                                       # LIMITED
    _offre_pair(j, pb, db, "ip-indices")
    dem = {**_dem(publier=False, empreinte=None), "confiance_min": "PARTNER"}
    assert ML.traiter(j, priv, did, "gk6", dem, _maintenant(), jeu="ip-indices")["abonnements"] == 0
    dem["confiance_min"] = "LIMITED"
    assert ML.traiter(j, priv, did, "gk6", dem, _maintenant(), jeu="ip-indices")["abonnements"] == 1


def test_lire_demandes_par_jeu(tmp_path):
    c = tmp_path / "publications.json"
    c.write_text(json.dumps({"format": 1, "confiance_min": "LIMITED",
                             "jeux": {"tv-indices": _dem(), "ip-indices": _dem(empreinte=E2)}}))
    assert ML.lire_demandes(c)["empreinte"] == E1
    assert ML.lire_demandes(c, jeu="ip-indices")["empreinte"] == E2
    assert ML.lire_demandes(c, jeu="autre") is None
    c.write_text(json.dumps({"format": 1, "jeux": {"tv-indices": _dem()}}))
    assert ML.lire_demandes(c, jeu="ip-indices") is None


def test_jeu_inconnu_aucun_geste(j):
    priv, _pub, did = _membre(j)
    r = ML.traiter(j, priv, did, "gk2", _dem(), _maintenant(), jeu="autre")
    assert r == {"offre": None, "version": None, "abonnements": 0, "resiliations": 0}
    assert _mes_offres(j, did) == []
