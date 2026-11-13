# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3659 — espace offert en service : compatibilité, propagation des jeux nommés (signés), lignée des copies, mise à jour
refaite, retrait et purge, autorisation côté producteur, routes."""
# ruff: noqa: F811 — fixtures pytest importées (cx, api) puis reçues en paramètre
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cycle_3647 import T0, Noeud, abonnement, export, offre  # noqa: E402
from test_donnees_3653 import api, b2, cx, retrait, version  # noqa: E402,F401 (fixtures)

from secubox_mirrornet import catalogue, espace, objets, transfert  # noqa: E402

REG = {"taille_max_mo": 1, "garder": 2, "reserve_mo": 0}
COMPAT = {"classes": ["public", "communaute"], "formats": [], "licences": []}


@pytest.fixture(autouse=True)
def _vierge():
    transfert._REPRISE.clear()
    espace.REFUS.clear()
    yield
    transfert._REPRISE.clear()
    espace.REFUS.clear()


def _propagation(producteur, gardien, soi, contenus, compat=None, quotas=None, classe="public", dp="non",
                 fmt="application/x-ndjson"):
    """Jeu du producteur (versions chaînées), offre d'espace du gardien, abonnement du producteur nommant le jeu."""
    o = offre(producteur, kind="dataset", tarif={"modele": "gratuit"}, classe=classe,
              approval_mode="pending" if classe == "specialise" else "auto")
    sid = o["payload"]["service_id"]
    entrees, parent = [o], ""
    for i, d in enumerate(contenus, 1):
        v = version(producteur, sid, i, d, classe=classe, dp=dp, parent=parent)
        v = producteur.signe("service_dataset_version", dict(v["payload"], format=fmt))
        entrees.append(v)
        parent = b2(d)
    compat = COMPAT if compat is None else compat
    quotas = quotas or {"octets": 1000, "octets_objet": 100}
    e = offre(gardien, kind="espace", tarif={"modele": "gratuit"}, classe="public", compat=compat, quotas=quotas)
    esp = e["payload"]["service_id"]
    debut = min(T0, datetime.now(timezone.utc)) - timedelta(minutes=1)
    s = producteur.signe("service_subscribe", dict(abonnement(producteur, esp)["payload"], requested_at=debut.isoformat(),
                                                   jeux=[sid], compat_acceptee={"compat": compat, "quotas": quotas}))
    entrees += [e, s]
    ex = export(soi, entrees, [(producteur, "LIMITED"), (gardien, "LIMITED")])
    ex["noeuds"][producteur.did]["mesh_ip"] = "10.10.0.11"
    ex["noeuds"][gardien.did]["mesh_ip"] = "10.10.0.7"
    return sid, esp, s["payload"]["subscription_id"], ex


def _flux(contenus, urls):
    def flux(url):
        urls.append(url)
        yield next(c for c in contenus if b2(c) in url)
    return flux


# --- fonctions pures -----------------------------------------------------------------------------------------------

def test_caracteristiques_bornees():
    c = espace.caracteristiques({}, {})
    assert c["classes"] == ["public"] and c["octets"] == 0 and c["octets_objet"] == 0
    c = espace.caracteristiques({"classes": ["public", "prive", "professionnel", "specialise"], "agregees": 1},
                                {"octets": 100, "octets_objet": 500})
    assert c["classes"] == ["public", "specialise"] and c["agregees"] is False and c["octets_objet"] == 100
    assert espace.caracteristiques("pas un dict", None)["octets"] == 0


@pytest.mark.parametrize("v, motif", [
    ({"classe": "professionnel"}, "jamais"),
    ({"classe": "prive"}, "jamais"),
    ({"classe": "specialise"}, "hors de la compatibilité"),
    ({"donnees_personnelles": "agregees"}, "données personnelles"),
    ({"donnees_personnelles": "base_legale:contrat-12"}, "données personnelles"),
    ({"format": "text/csv"}, "format"),
    ({"licence": "CC-BY-4.0"}, "licence"),
    ({"taille": 101}, "par objet"),
])
def test_refus_version(v, motif):
    esp = espace.caracteristiques({"classes": ["public", "communaute"], "formats": ["application/json"],
                                   "licences": ["ODbL-1.0"]}, {"octets": 1000, "octets_objet": 100})
    base = {"classe": "public", "donnees_personnelles": "non", "format": "application/json", "licence": "ODbL-1.0",
            "taille": 10}
    assert espace.refus_version(esp, base) is None
    assert motif in espace.refus_version(esp, dict(base, **v))


def test_agregees_admises_si_l_espace_le_dit():
    esp = espace.caracteristiques({"classes": ["communaute"], "agregees": True}, {"octets": 10})
    v = {"classe": "communaute", "donnees_personnelles": "agregees", "format": "x", "licence": "y", "taille": 1}
    assert espace.refus_version(esp, v) is None


# --- côté espace -----------------------------------------------------------------------------------------------------

def test_propagation_lignee_et_mise_a_jour(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    contenus = [b"v1", b"v2"]
    sid, _esp, _sub, ex = _propagation(p, moi, moi, contenus)
    catalogue.synchroniser(cx, ex, T0)
    urls = []
    st = espace.propager(cx, REG, flux=_flux(contenus, urls))
    assert st["copiees"] == 1 and urls == [f"http://10.10.0.11:8799/mirrornet/objets/{b2(b'v2')}"]
    assert objets.present(b2(b"v2")) and not objets.present(b2(b"v1"))       # la dernière version seulement
    lg = espace.lignee(cx, sid)
    assert [(c["numero"], c["origine"], c["parent"]) for c in lg["copies"]] == [(2, "gk6", "gk6")]
    assert lg["versions"][0]["parent"] == b2(b"v1")                          # chaîne des manifestes
    assert espace.propager(cx, REG, flux=_flux(contenus, urls))["copiees"] == 0 and len(urls) == 1
    # Nouvelle version du producteur : la mise à jour se refait chez l'espace.
    contenus.append(b"v3")
    ex["entrees"].append(version(p, sid, 3, b"v3", parent=b2(b"v2")))
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux(contenus, urls))
    assert objets.present(b2(b"v3")) and objets.present(b2(b"v2"))            # garder = 2
    # Retrait par le producteur : effacé de l'espace.
    ex["entrees"].append(retrait(p, sid, b"v3"))
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux(contenus, urls))
    assert not objets.present(b2(b"v3"))
    g = espace.gardees(cx)
    assert g[0]["producteur"] == "gk6" and g[0]["jeux"] == [sid] and g[0]["occupe"] == 2 and g[0]["capacite"] == 1000


def test_falsifie_refuse(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    _sid, _esp, _sub, ex = _propagation(p, moi, moi, [b"v1"])
    catalogue.synchroniser(cx, ex, T0)
    st = espace.propager(cx, REG, flux=lambda url: iter([b"autre chose"]))
    assert st["refusees"] == 1 and not objets.present(b2(b"v1"))
    assert espace.gardees(cx)[0]["copies"] == []


def test_compatibilite_et_capacite_refusees_sans_transfert(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    urls = []
    _sid, _e, _s, ex = _propagation(p, moi, moi, [b"v1"], fmt="text/csv",
                                    compat={"classes": ["public"], "formats": ["application/json"]})
    catalogue.synchroniser(cx, ex, T0)
    assert espace.propager(cx, REG, flux=_flux([b"v1"], urls))["refusees"] == 1 and urls == []
    assert "format" in espace.gardees(cx)[0]["refus"][0]["motif"]


def test_capacite_atteinte(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    urls, contenus = [], [b"0123456789", b"9876543210"]
    sid, _e, _s, ex = _propagation(p, moi, moi, contenus[:1], quotas={"octets": 15})
    catalogue.synchroniser(cx, ex, T0)
    assert espace.propager(cx, REG, flux=_flux(contenus, urls))["copiees"] == 1
    ex["entrees"].append(version(p, sid, 2, contenus[1], parent=b2(contenus[0])))
    catalogue.synchroniser(cx, ex, T0)
    assert espace.propager(cx, REG, flux=_flux(contenus, urls))["refusees"] == 1 and len(urls) == 1
    assert "capacité" in espace.gardees(cx)[0]["refus"][0]["motif"]


def test_donnees_personnelles_jamais_propagees(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    urls = []
    _sid, _e, _s, ex = _propagation(p, moi, moi, [b"v1"], classe="communaute", dp="agregees")
    catalogue.synchroniser(cx, ex, T0)
    assert espace.propager(cx, REG, flux=_flux([b"v1"], urls))["refusees"] == 1 and urls == []


def test_resiliation_purge_les_copies(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    _sid, _esp, sub, ex = _propagation(p, moi, moi, [b"v1"])
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux([b"v1"], []))
    assert objets.present(b2(b"v1"))
    ex["entrees"].append(p.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub,
                                                        "subscriber": p.did, "motif": "fin", "revoked_at": T0.isoformat()}))
    catalogue.synchroniser(cx, ex, T0)
    st = espace.propager(cx, REG, flux=_flux([b"v1"], []))
    assert st["purgees"] == 1 and not objets.present(b2(b"v1"))


def test_jeu_d_un_autre_producteur_jamais_tire(cx):
    """L'abonnement nomme un jeu qui n'est pas au producteur abonné : l'espace ne tire rien."""
    p, moi, tiers = Noeud("gk6"), Noeud("gk2"), Noeud("gk12")
    o = offre(tiers, kind="dataset", tarif={"modele": "gratuit"}, classe="public")
    sid_t = o["payload"]["service_id"]
    _sid, esp, _sub, ex = _propagation(p, moi, moi, [b"v1"])
    s = p.signe("service_subscribe", dict(abonnement(p, esp)["payload"], requested_at=T0.isoformat(), jeux=[sid_t]))
    ex["entrees"] = [e for e in ex["entrees"] if e["op"] != "service_subscribe"] + [o, version(tiers, sid_t, 1, b"t1"), s]
    ex["noeuds"][tiers.did] = {"boxname": "gk12", "mesh_ip": "10.10.0.9", "niveau": "LIMITED", "cause": "t"}
    catalogue.synchroniser(cx, ex, T0)
    assert espace.a_propager(cx) == []


def test_objet_deja_detenu_copie_sans_transfert(cx):
    """L'espace est aussi abonné au jeu : l'objet reçu comme abonné devient la copie, parent = d'où il est venu."""
    p, moi = Noeud("gk6"), Noeud("gk2")
    sid, _esp, _sub, ex = _propagation(p, moi, moi, [b"v1"])
    debut = min(T0, datetime.now(timezone.utc)) - timedelta(minutes=1)
    ex["entrees"].append(moi.signe("service_subscribe", dict(abonnement(moi, sid)["payload"],
                                                             requested_at=debut.isoformat())))
    catalogue.synchroniser(cx, ex, T0)
    transfert.tirer(cx, REG, flux=_flux([b"v1"], []))
    urls = []
    assert espace.propager(cx, REG, flux=_flux([b"v1"], urls))["copiees"] == 1 and urls == []
    assert espace.lignee(cx, sid)["copies"][0]["parent"] == "gk6"


# --- côté producteur -------------------------------------------------------------------------------------------------

def test_producteur_sert_seulement_l_espace_choisi(cx):
    moi, g, autre = Noeud("gk6"), Noeud("gk2"), Noeud("gk12")
    sid, _esp, sub, ex = _propagation(moi, g, moi, [b"v1"])
    ex["noeuds"][autre.did] = {"boxname": "gk12", "mesh_ip": "10.10.0.9", "niveau": "LIMITED", "cause": "t"}
    # Second jeu du producteur, NON nommé dans l'abonnement.
    o2 = offre(moi, kind="dataset", tarif={"modele": "gratuit"}, classe="public")
    ex["entrees"] += [o2, version(moi, o2["payload"]["service_id"], 1, b"autre jeu")]
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is None
    assert transfert.autoriser(cx, "10.10.0.9", b2(b"v1")) is not None               # pas l'espace choisi
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"autre jeu")) is not None        # jeu non nommé
    ex["entrees"].append(retrait(moi, sid, b"v1"))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is not None               # version retirée


def test_producteur_ne_sert_plus_apres_resiliation(cx):
    moi, g = Noeud("gk6"), Noeud("gk2")
    _sid, _esp, sub, ex = _propagation(moi, g, moi, [b"v1"])
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is None
    ex["entrees"].append(moi.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub,
                                                          "subscriber": moi.did, "motif": "", "revoked_at": T0.isoformat()}))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is not None


@pytest.mark.parametrize("agregees, attendu", [(False, False), (True, True)])
def test_producteur_agregees_selon_l_espace(cx, agregees, attendu):
    moi, g = Noeud("gk6"), Noeud("gk2")
    compat = dict(COMPAT, agregees=agregees)
    _sid, _esp, _sub, ex = _propagation(moi, g, moi, [b"v1"], classe="communaute", dp="agregees", compat=compat)
    catalogue.synchroniser(cx, ex, T0)
    assert (transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is None) is attendu


def test_jeux_ignores_hors_espace(cx):
    """`jeux` sur l'abonnement à une offre qui n'est pas un espace : indexé vide, n'ouvre rien."""
    moi, g = Noeud("gk6"), Noeud("gk2")
    sid, _esp, _sub, ex = _propagation(moi, g, moi, [b"v1"])
    m = offre(g, kind="mirror", tarif={"modele": "gratuit"}, classe="public")
    s = moi.signe("service_subscribe", dict(abonnement(moi, m["payload"]["service_id"])["payload"],
                                            requested_at=T0.isoformat(), jeux=[sid]))
    ex["entrees"] = [e for e in ex["entrees"] if e["op"] != "service_subscribe"] + [m, s]
    catalogue.synchroniser(cx, ex, T0)
    assert cx.execute("SELECT jeux FROM subscription").fetchone()[0] == "[]"
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is not None


# --- routes ----------------------------------------------------------------------------------------------------------

def _ecrire(tmp, ex):
    (tmp / "export.json").write_text(json.dumps(ex))


@pytest.mark.parametrize("corps, motif", [
    ({}, "quotas.octets"),
    ({"quotas": {"octets": 10, "octets_objet": 11}}, "octets_objet"),
    ({"quotas": {"octets": 10}, "compat": {"classes": ["professionnel"]}}, "classes"),
    ({"quotas": {"octets": 10}, "compat": {"formats": ["a b"]}}, "formats"),
    ({"quotas": {"octets": 10}, "compat": {"autre": 1}}, "admet"),
    ({"quotas": {"octets": 10}, "classe": "prive"}, "privée"),
])
def test_publier_espace_valide(api, monkeypatch, corps, motif):
    main, _tmp = api
    monkeypatch.setattr(main.annuaire, "appeler", lambda *a, **k: (200, {}))
    r = TestClient(main.app).post("/api/v1/mirrornet/services/publish",
                                  json=dict({"name": "Espace", "kind": "espace", "endpoint": "mirrornet://gk2"}, **corps))
    assert r.status_code == 422 and motif in r.text


def test_propager_evalue_puis_relaie_les_jeux(api, monkeypatch):
    main, tmp = api
    moi, g = Noeud("gk6"), Noeud("gk2")
    sid, esp, _sub, ex = _propagation(moi, g, moi, [b"v1"], fmt="text/csv",
                                      compat={"classes": ["public"], "formats": ["application/json"]})
    ex["entrees"] = [e for e in ex["entrees"] if e["op"] != "service_subscribe"]
    _ecrire(tmp, ex)
    appels = []

    def appeler(chemin, corps, jeton, socket_chemin=None):
        appels.append((chemin, corps))
        s = moi.signe("service_subscribe", dict(abonnement(moi, esp)["payload"], jeux=corps["jeux"],
                                                requested_at=datetime.now(timezone.utc).isoformat()))
        ex["entrees"].append(s)
        _ecrire(tmp, ex)
        return 200, dict(s["payload"], state="approved")
    monkeypatch.setattr(main.annuaire, "appeler", appeler)
    c = TestClient(main.app)
    r = c.post(f"/api/v1/mirrornet/espaces/{esp}/propager", json={"jeux": [sid]})
    assert r.status_code == 409 and "format" in r.text and appels == []        # incompatible : rien de signé
    # Offre d'espace rééditée par le gardien (même service_id) : formats admis.
    ex["entrees"].append(offre(g, sid=esp, kind="espace", tarif={"modele": "gratuit"}, classe="public",
                               compat={"classes": ["public"]}, quotas={"octets": 1000}))
    _ecrire(tmp, ex)
    r = c.post(f"/api/v1/mirrornet/espaces/{esp}/propager", json={"jeux": [sid]})
    assert r.status_code == 200, r.text
    assert appels == [(f"/self/service/{esp}/subscribe", {"provider": g.did, "jeux": [sid]})]
    assert r.json()["jeux"] == [sid] and r.json()["etat"] == "Actif"
    assert c.post(f"/api/v1/mirrornet/espaces/{esp}/propager", json={"jeux": [sid]}).json()["existant"] is True
    assert c.post(f"/api/v1/mirrornet/espaces/{esp}/propager", json={"jeux": ["0" * 16]}).status_code == 409
    # Abonnement générique à un espace : refusé (les jeux doivent être nommés).
    assert c.post(f"/api/v1/mirrornet/services/{esp}/subscribe").status_code == 409
    lg = c.get(f"/api/v1/mirrornet/datasets/{sid}/lignee").json()
    assert lg["mien"] is True and lg["espaces"][0]["gardien"] == "gk2" and lg["espaces"][0]["etat"] == "Actif"
    e = c.get("/api/v1/mirrornet/espaces").json()["espaces"]
    assert e[0]["espace"]["octets"] == 1000 and "occupe" not in e[0]                # pas le mien
    ids = {s["id"] for s in c.get("/api/v1/mirrornet/services").json()["services"]}
    assert esp not in ids                                                           # un espace n'est pas un service


def test_gardees_et_lignee_exigent_un_administrateur(api):
    main, _tmp = api
    main.app.dependency_overrides.pop(main.require_jwt)
    c = TestClient(main.app)
    assert c.get("/api/v1/mirrornet/espaces/gardees").status_code == 401
    assert c.get("/api/v1/mirrornet/datasets/" + "a" * 32 + "/lignee").status_code == 401
    assert c.post("/api/v1/mirrornet/espaces/" + "a" * 32 + "/propager", json={"jeux": ["a" * 16]}).status_code == 401


def test_purge_ne_touche_jamais_les_objets_du_producteur(cx):
    """Objet d'un jeu de CE nœud noté sous une source inattendue (dépôt avant la première synchronisation) : gardé."""
    moi, g = Noeud("gk6"), Noeud("gk2")
    _sid, _esp, _sub, ex = _propagation(moi, g, moi, [b"v1"])
    catalogue.synchroniser(cx, ex, T0)
    e, t = objets.ecrire([b"v1"], 100)
    objets.noter(cx, e, t, "soi")
    assert espace.ranger(cx, 2) == 0 and objets.present(e)


def test_refus_elagues_quand_ils_n_ont_plus_cours(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    sid, _e, sub, ex = _propagation(p, moi, moi, [b"v1"], fmt="text/csv", compat={"classes": ["public"], "formats": ["x/y"]})
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux([b"v1"], []))
    assert len(espace.REFUS) == 1
    ex["entrees"].append(p.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub,
                                                        "subscriber": p.did, "motif": "", "revoked_at": T0.isoformat()}))
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux([b"v1"], []))
    assert espace.REFUS == {}


# --- relecture #3659 ---------------------------------------------------------------------------------------------------

def test_producteur_respecte_la_compatibilite_de_l_espace(cx):
    """Version d'une classe que l'espace ne garde pas (spécialisé vers un espace public) : jamais servie."""
    moi, g = Noeud("gk6"), Noeud("gk2")
    sid, _esp, _sub, ex = _propagation(moi, g, moi, [b"v1"], compat={"classes": ["public"]})
    ex["entrees"].append(version(moi, sid, 2, b"v2", classe="communaute", parent=b2(b"v1")))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is None
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v2")) is not None


def test_offre_elargie_apres_coup_n_elargit_rien(cx):
    """L'espace republie son offre en admettant les données agrégées : le producteur s'en tient à ce qu'il a accepté."""
    moi, g = Noeud("gk6"), Noeud("gk2")
    sid, esp, _sub, ex = _propagation(moi, g, moi, [b"v1"], classe="communaute", dp="agregees",
                                      compat={"classes": ["communaute"], "agregees": False})
    ex["entrees"].append(offre(g, sid=esp, kind="espace", tarif={"modele": "gratuit"}, classe="public",
                               compat={"classes": ["communaute"], "agregees": True}, quotas={"octets": 1000}))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is not None


def test_offre_restreinte_apres_coup_respectee(cx):
    moi, g = Noeud("gk6"), Noeud("gk2")
    _sid, esp, _sub, ex = _propagation(moi, g, moi, [b"v1"])
    ex["entrees"].append(offre(g, sid=esp, kind="espace", tarif={"modele": "gratuit"}, classe="public",
                               compat={"classes": ["public"], "licences": ["CC0-1.0"]}, quotas={"octets": 1000}))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is not None


def test_sans_compatibilite_figee_rien_n_est_servi(cx):
    moi, g = Noeud("gk6"), Noeud("gk2")
    _sid, esp, _sub, ex = _propagation(moi, g, moi, [b"v1"])
    ex["entrees"] = [e for e in ex["entrees"] if e["op"] != "service_subscribe"]
    ex["entrees"].append(moi.signe("service_subscribe", dict(abonnement(moi, esp)["payload"], jeux=[_sid])))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"v1")) is not None


def test_empreinte_reprise_par_un_tiers_n_efface_pas_la_copie(cx):
    """Un tiers déclare, dans un vieux numéro de SON jeu, l'empreinte d'une copie gardée : la copie reste."""
    p, moi, tiers = Noeud("gk6"), Noeud("gk2"), Noeud("gk12")
    _sid, _e, _s, ex = _propagation(p, moi, moi, [b"v1"])
    o = offre(tiers, kind="dataset", tarif={"modele": "gratuit"}, classe="public")
    st = o["payload"]["service_id"]
    ex["entrees"] += [o, version(tiers, st, 1, b"v1"), version(tiers, st, 2, b"t2"), version(tiers, st, 3, b"t3")]
    ex["noeuds"][tiers.did] = {"boxname": "gk12", "mesh_ip": "10.10.0.9", "niveau": "LIMITED", "cause": "t"}
    catalogue.synchroniser(cx, ex, T0)
    espace.propager(cx, REG, flux=_flux([b"v1"], []))
    transfert.ranger(cx, REG["garder"])
    assert objets.present(b2(b"v1"))


def test_taille_declaree_fausse_pour_un_objet_detenu(cx):
    p, moi = Noeud("gk6"), Noeud("gk2")
    _sid, _e, _s, ex = _propagation(p, moi, moi, [b"v1"])
    v = [e for e in ex["entrees"] if e["op"] == "service_dataset_version"][0]
    v.update(p.signe("service_dataset_version", dict(v["payload"], taille=1)))
    catalogue.synchroniser(cx, ex, T0)
    e, t = objets.ecrire([b"v1"], 100)
    objets.noter(cx, e, t, "did:plc:" + "9" * 32)
    assert espace.propager(cx, REG, flux=_flux([b"v1"], []))["refusees"] == 1
    assert espace.gardees(cx)[0]["copies"] == []


def test_espaces_anonyme_sans_occupation_ni_topologie(api):
    main, tmp = api
    moi = Noeud("gk2")
    e = offre(moi, kind="espace", tarif={"modele": "gratuit"}, classe="public", compat={"classes": ["public"]},
              quotas={"octets": 1000}, sonde="/health")
    _ecrire(tmp, export(moi, [e], [(moi, "LIMITED")]))
    main.synchroniser_maintenant()
    for ident in ({"sub": None}, {"sub": "tdb", "tableau_de_bord": True}):
        main.app.dependency_overrides[main.require_lecture] = lambda ident=ident: ident
        r = TestClient(main.app).get("/api/v1/mirrornet/espaces").json()["espaces"][0]
        assert r["mienne"] is True and "occupe" not in r and "endpoint" not in r and "sonde" not in r
