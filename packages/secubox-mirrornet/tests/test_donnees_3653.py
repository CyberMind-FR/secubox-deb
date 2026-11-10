# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3653 — jeux de données : dépôt d'objets par empreinte, index des versions signées, service aux seuls abonnés
Actif, réception vérifiée, rangement, routes de dépôt et de service."""
import hashlib
import importlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cycle_3647 import T0, Noeud, abonnement, export, offre  # noqa: E402

from secubox_mirrornet import catalogue, config, objets, schema, transfert  # noqa: E402

REG = {"taille_max_mo": 1, "garder": 2, "reserve_mo": 0}


def b2(data: bytes) -> str:
    return "b2:" + hashlib.blake2b(data, digest_size=32).hexdigest()


def version(n, sid, numero, data, classe="public", dp="non", parent=""):
    return n.signe("service_dataset_version", {
        "op": "service_dataset_version", "service_id": sid, "provider": n.did, "numero": numero, "parent": parent,
        "empreinte": b2(data), "taille": len(data), "format": "application/x-ndjson", "licence": "ODbL-1.0",
        "provenance": "capteur:banc", "classe": classe, "donnees_personnelles": dp, "fraicheur_s": 600,
        "cree_le": T0.isoformat()})


def retrait(n, sid, data):
    return n.signe("service_dataset_retract", {"op": "service_dataset_retract", "service_id": sid, "provider": n.did,
                                               "empreinte": b2(data), "motif": "", "retracted_at": T0.isoformat()})


@pytest.fixture
def cx(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OBJETS", tmp_path / "objets")
    schema.initialiser(tmp_path / "m.db")
    c = schema.ouvrir(tmp_path / "m.db")
    yield c
    c.close()


def _jeu(fournisseur, abonne, soi, data_list, mesh_ip="10.10.0.11", approuve=True):
    o = offre(fournisseur, kind="dataset", tarif={"modele": "gratuit"}, classe="public")
    sid = o["payload"]["service_id"]
    entrees = [o]
    parent = ""
    for i, d in enumerate(data_list, 1):
        entrees.append(version(fournisseur, sid, i, d, parent=parent))
        parent = b2(d)
    s = abonnement(abonne, sid)
    # Demande datée au plus tôt de T0 et de maintenant : jamais « dans le futur », ni pour l'horloge simulée ni en réel.
    debut = min(T0, datetime.now(timezone.utc)) - timedelta(minutes=1)
    s = abonne.signe("service_subscribe", dict(s["payload"], requested_at=debut.isoformat()))
    entrees.append(s)
    ex = export(soi, entrees, [(fournisseur, "LIMITED"), (abonne, "LIMITED")])
    ex["noeuds"][fournisseur.did]["mesh_ip"] = mesh_ip
    ex["noeuds"][abonne.did]["mesh_ip"] = "10.10.0.7"
    return sid, s["payload"]["subscription_id"], ex


# --- dépôt ---------------------------------------------------------------------------------------------------------

def test_objet_ecrit_verifie_et_rien_ne_reste_en_cas_de_refus(cx):
    e, t = objets.ecrire([b"abc", b"def"], 100)
    assert e == b2(b"abcdef") and t == 6 and objets.present(e)
    with pytest.raises(objets.RefusObjet, match="volumineux"):
        objets.ecrire([b"x" * 60, b"x" * 60], 100)
    with pytest.raises(objets.RefusObjet, match="empreinte"):
        objets.ecrire([b"autre"], 100, attendue=b2(b"pas ca"))
    with pytest.raises(objets.RefusObjet, match="taille"):
        objets.ecrire([b"abc"], 100, taille_attendue=4)
    assert [p.name for p in objets.dossier().iterdir()] == [e[3:]]
    with pytest.raises(objets.RefusObjet, match="espace"):
        objets.verifier_espace(1, 10 ** 9)
    with pytest.raises(objets.RefusObjet):
        objets.chemin("../../etc/passwd")


# --- index des versions -------------------------------------------------------------------------------------------------

def test_versions_du_proprietaire_seulement_et_retrait(cx):
    f, a, x = Noeud("gk6"), Noeud("gk12"), Noeud("x")
    sid, _sub, ex = _jeu(f, a, a, [b"v1", b"v2"])
    ex["entrees"].append(version(x, sid, 3, b"intrus"))                      # version signée par un autre que le fournisseur
    ex["entrees"].append(version(f, sid, 2, b"meme numero autre contenu"))    # numéro déjà pris
    ex["entrees"].append(version(f, sid, 4, b"perso", classe="public", dp="base_legale:art6"))   # vie privée
    st = catalogue.synchroniser(cx, ex, T0)
    assert st["versions"] == 2 and st["rejetees"] >= 3
    rows = cx.execute("SELECT numero, retiree FROM dataset_version ORDER BY numero").fetchall()
    assert [tuple(r) for r in rows] == [(1, 0), (2, 0)]
    ex["entrees"].append(retrait(f, sid, b"v2"))
    catalogue.synchroniser(cx, ex, T0)
    assert cx.execute("SELECT retiree FROM dataset_version WHERE numero = 2").fetchone()[0] == 1


# --- autorisation de service ---------------------------------------------------------------------------------------------

def test_autoriser_seulement_l_abonne_actif(cx):
    moi, a, autre = Noeud("gk6"), Noeud("gk12"), Noeud("gk4")
    sid, _sub, ex = _jeu(moi, a, moi, [b"v1"])
    ex["noeuds"][autre.did] = {"boxname": "gk4", "mesh_ip": "10.10.0.9", "niveau": "LIMITED", "cause": "t"}
    catalogue.synchroniser(cx, ex, T0)
    e = b2(b"v1")
    assert transfert.autoriser(cx, "10.10.0.7", e) is None
    assert "maillage" in transfert.autoriser(cx, "192.168.1.5", e)
    assert transfert.autoriser(cx, "10.10.0.9", e) is not None                # pair connu, pas abonné
    assert transfert.autoriser(cx, "10.10.0.99", e) is not None               # inconnu
    assert transfert.autoriser(cx, "10.10.0.7", b2(b"autre")) is not None     # objet hors de ses versions
    ex["entrees"].append(retrait(moi, sid, b"v1"))
    catalogue.synchroniser(cx, ex, T0)
    assert transfert.autoriser(cx, "10.10.0.7", e) is not None                # version retirée


def test_adresse_revendiquee_par_deux_noeuds_refusee(cx):
    moi, a, usurpateur = Noeud("gk6"), Noeud("gk12"), Noeud("x")
    _sid, _sub, ex = _jeu(moi, a, moi, [b"v1"])
    ex["noeuds"][usurpateur.did] = {"boxname": "x", "mesh_ip": "10.10.0.7", "niveau": "LIMITED", "cause": "t"}
    catalogue.synchroniser(cx, ex, T0)
    assert "plusieurs" in transfert.autoriser(cx, "10.10.0.7", b2(b"v1"))


# --- réception côté abonné ----------------------------------------------------------------------------------------------

def test_reception_verifiee_et_rangement(cx, monkeypatch):
    f, moi = Noeud("gk6"), Noeud("gk12")
    contenus = [b"v1", b"v2", b"v3"]
    sid, _sub, ex = _jeu(f, moi, moi, contenus)
    catalogue.synchroniser(cx, ex, T0)
    urls = []

    def flux(url):
        urls.append(url)
        yield next(c for c in contenus if b2(c) in url)
    st = transfert.tirer(cx, REG, flux=flux)
    assert st["recues"] == 1 and urls == [f"http://10.10.0.11:8799/mirrornet/objets/{b2(b'v3')}"]
    assert objets.present(b2(b"v3"))
    assert transfert.tirer(cx, REG, flux=flux)["recues"] == 0                 # rien de neuf : aucune requête
    # Contenu falsifié par le pair : refusé, rien gardé.
    contenus.append(b"v4")
    ex["entrees"].append(version(f, sid, 4, b"v4", parent=b2(b"v3")))
    catalogue.synchroniser(cx, ex, T0)
    st = transfert.tirer(cx, REG, flux=lambda url: iter([b"v4 falsifie"]))
    assert st["refusees"] == 1 and not objets.present(b2(b"v4"))
    transfert.tirer(cx, REG, flux=flux)
    assert objets.present(b2(b"v4")) and objets.present(b2(b"v3"))
    # Retrait : supprimé chez l'abonné.
    ex["entrees"].append(retrait(f, sid, b"v4"))
    catalogue.synchroniser(cx, ex, T0)
    transfert.tirer(cx, REG, flux=flux)
    assert not objets.present(b2(b"v4"))


def test_pas_de_reception_sans_abonnement_actif(cx):
    f, moi = Noeud("gk6"), Noeud("gk12")
    o = offre(f, kind="dataset", approval_mode="pending")
    sid = o["payload"]["service_id"]
    ex = export(moi, [o, version(f, sid, 1, b"v1"), abonnement(moi, sid)], [(f, "LIMITED"), (moi, "LIMITED")])
    ex["noeuds"][f.did]["mesh_ip"] = "10.10.0.11"
    catalogue.synchroniser(cx, ex, T0)                                         # Demande, pas Actif
    assert transfert.a_tirer(cx) == []


# --- API -----------------------------------------------------------------------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch):
    import secubox_core.auth as auth
    main = importlib.import_module("api.main")
    monkeypatch.setattr(auth, "_validate_token", lambda t: {"sub": "admin"} if t.startswith("jeton") else None)
    monkeypatch.setattr(config, "BASE", tmp_path / "m.db")
    monkeypatch.setattr(config, "EXPORT", tmp_path / "export.json")
    monkeypatch.setattr(config, "CONF", tmp_path / "absent.toml")
    monkeypatch.setattr(config, "OBJETS", tmp_path / "objets")
    schema.initialiser(tmp_path / "m.db")
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield main, tmp_path
    main.app.dependency_overrides.clear()


def test_depot_relaye_et_objet_efface_si_l_annuaire_refuse(api, monkeypatch):
    main, tmp = api
    moi, a = Noeud("gk6"), Noeud("gk12")
    sid, _sub, ex = _jeu(moi, a, moi, [])
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    appels = []
    monkeypatch.setattr(main.annuaire, "appeler", lambda ch, corps, j, **k: appels.append((ch, corps)) or (200, {"numero": 1}))
    c = TestClient(main.app)
    c.headers["Authorization"] = "Bearer jeton-admin"
    q = "format=application/x-ndjson&licence=ODbL-1.0&provenance=capteur:banc&classe=public"
    r = c.post(f"/api/v1/mirrornet/datasets/{sid}/versions?{q}", content=b"donnees v1")
    assert r.status_code == 200, r.text
    assert appels[0][0] == f"/self/dataset/{sid}/version" and appels[0][1]["empreinte"] == b2(b"donnees v1")
    assert objets.present(b2(b"donnees v1"))
    monkeypatch.setattr(main.annuaire, "appeler", lambda *a, **k: (409, {"detail": "version déjà publiée"}))
    r = c.post(f"/api/v1/mirrornet/datasets/{sid}/versions?{q}", content=b"refusee")
    assert r.status_code == 409 and not objets.present(b2(b"refusee"))
    r = c.post(f"/api/v1/mirrornet/datasets/{sid}/versions?{q}&donnees_personnelles=agregees", content=b"x")
    assert r.status_code == 422                                                # public + données personnelles
    autre = offre(a, kind="dataset")
    assert c.post(f"/api/v1/mirrornet/datasets/{autre['payload']['service_id']}/versions?{q}", content=b"x").status_code == 404


def test_depot_trop_volumineux(api, monkeypatch):
    main, tmp = api
    moi, a = Noeud("gk6"), Noeud("gk12")
    sid, _sub, ex = _jeu(moi, a, moi, [])
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    (tmp / "absent.toml").write_text("[donnees]\ntaille_max_mo = 1\nreserve_mo = 0\n")
    monkeypatch.setattr(main.annuaire, "appeler", lambda *a, **k: (200, {}))
    c = TestClient(main.app)
    q = "format=bin&licence=CC0-1.0&provenance=banc&classe=public"
    r = c.post(f"/api/v1/mirrornet/datasets/{sid}/versions?{q}", content=b"x" * (1024 * 1024 + 1))
    assert r.status_code == 413
    assert [p for p in objets.dossier().iterdir()] == []


def test_service_aux_pairs(api):
    main, tmp = api
    moi, a = Noeud("gk6"), Noeud("gk12")
    sid, _sub, ex = _jeu(moi, a, moi, [b"v1"])
    (tmp / "export.json").write_text(json.dumps(ex))
    main.synchroniser_maintenant()
    objets.ecrire([b"v1"], 100)
    c = TestClient(main.app)
    url = f"/pair/objets/{b2(b'v1')}"
    r = c.get(url, headers={"X-SecuBox-Pair-IP": "10.10.0.7"})
    assert r.status_code == 200 and r.content == b"v1"
    assert c.get(url, headers={"X-SecuBox-Pair-IP": "10.10.0.9"}).status_code == 404
    assert c.get(url).status_code == 404                                      # sans adresse posée par l'écouteur
    assert c.get("/pair/objets/..%2F..%2Fetc%2Fpasswd", headers={"X-SecuBox-Pair-IP": "10.10.0.7"}).status_code == 404
    # Jamais joignable par le préfixe d'administration.
    assert c.get(f"/api/v1/mirrornet/pair/objets/{b2(b'v1')}").status_code == 404
