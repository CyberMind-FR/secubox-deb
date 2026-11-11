# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3666 — publication locale (fichier d'ad-guard → objet + demande pour l'annuaire) et livraison des indices TV reçus
des autres box (abonnements Actif à une offre `usage = tv-indices`, fournisseur au niveau de confiance requis)."""
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cycle_3647 import T0, Noeud, abonnement, export, offre  # noqa: E402
from test_donnees_3653 import b2, version  # noqa: E402

from secubox_mirrornet import catalogue, config, locaux, objets, schema  # noqa: E402

REG = {"confiance_min": "LIMITED", "taille_max_mo": 4, "reserve_mo": 0}


def octets(c):
    return json.dumps(c, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def contenu(**indices):
    return {"format": 1, "jeu": "tv-indices", "indices": indices or {"ads.exemple.com": "PUBLICITE"},
            "legitimes": ["cdn.exemple.com"]}


TMP = [None]


@pytest.fixture
def banc(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OBJETS", tmp_path / "objets")
    monkeypatch.setattr(config, "CONF", tmp_path / "absent.toml")
    partage = tmp_path / "partage"
    (partage / "livraisons" / "tv-indices").mkdir(parents=True)
    monkeypatch.setattr(locaux, "PARTAGE", partage)
    monkeypatch.setattr(locaux, "PUBLICATIONS", partage / "publications.json")
    monkeypatch.setattr(locaux, "LIVRAISON", partage / "livraisons" / "tv-indices")
    monkeypatch.setattr(locaux, "SOURCE_TV", tmp_path / "indices-publication.json")
    schema.initialiser(tmp_path / "m.db")
    c = schema.ouvrir(tmp_path / "m.db")
    TMP[0] = tmp_path
    yield c
    c.close()


def poser_source(chemin, c, publier=True, recevoir=True):
    doc = {"format": 1, "publier": publier, "recevoir": recevoir, "contenu": c}
    chemin.write_text(json.dumps(doc, sort_keys=True, indent=1, ensure_ascii=False))
    return doc


def soi_connu(cx, moi):
    catalogue.synchroniser(cx, export(moi, [], [(moi, "LIMITED")]), T0)


# --- dépôt -----------------------------------------------------------------------------------------------------------

def test_depot_cree_objet_et_demande_puis_rien_si_identique(banc):
    moi = Noeud("gk12")
    soi_connu(banc, moi)
    c = contenu()
    poser_source(locaux.SOURCE_TV, c, publier=True, recevoir=False)
    d = locaux.deposer(banc, REG)
    attendu = {"format": 1, "jeux": {"tv-indices": {"publier": True, "recevoir": False, "empreinte": b2(octets(c)),
                                                    "taille": len(octets(c))}}}
    assert d == attendu
    assert json.loads(locaux.PUBLICATIONS.read_text()) == attendu
    assert stat.S_IMODE(locaux.PUBLICATIONS.stat().st_mode) == 0o640
    assert objets.present(b2(octets(c))) and objets.chemin(b2(octets(c))).read_bytes() == octets(c)
    assert banc.execute("SELECT source FROM objet WHERE empreinte = ?", (b2(octets(c)),)).fetchone()[0] == moi.did
    # Contenu identique : la demande n'est pas réécrite.
    ino = locaux.PUBLICATIONS.stat().st_ino
    assert locaux.deposer(banc, REG) == attendu
    assert locaux.PUBLICATIONS.stat().st_ino == ino
    # Contenu changé : nouvelle empreinte, nouvelle demande.
    c2 = contenu(**{"trk.exemple.net": "TRACKING"})
    poser_source(locaux.SOURCE_TV, c2)
    assert locaux.deposer(banc, REG)["jeux"]["tv-indices"]["empreinte"] == b2(octets(c2))
    assert locaux.PUBLICATIONS.stat().st_ino != ino


def test_depot_soi_inconnu_rien(banc):
    poser_source(locaux.SOURCE_TV, contenu())
    assert locaux.deposer(banc, REG) is None
    assert not locaux.PUBLICATIONS.exists()


@pytest.mark.parametrize("cas", ["absente", "trop_grosse", "lien", "dossier", "format", "jeu", "publier", "json"])
def test_depot_source_refusee_sans_exception(banc, cas):
    moi = Noeud("gk12")
    soi_connu(banc, moi)
    src = locaux.SOURCE_TV
    if cas == "trop_grosse":
        poser_source(src, dict(contenu(), bourrage="x" * (3 * 1024 * 1024)))
    elif cas == "lien":
        vrai = TMP[0] / "vrai.json"
        poser_source(vrai, contenu())
        src.symlink_to(vrai)
    elif cas == "dossier":
        src.mkdir()
    elif cas == "format":
        src.write_text(json.dumps({"format": 2, "publier": True, "recevoir": True, "contenu": contenu()}))
    elif cas == "jeu":
        poser_source(src, dict(contenu(), jeu="autre"))
    elif cas == "publier":
        src.write_text(json.dumps({"format": 1, "publier": "oui", "recevoir": True, "contenu": contenu()}))
    elif cas == "json":
        src.write_text("{pas du json")
    assert locaux.deposer(banc, REG) is None
    assert not locaux.PUBLICATIONS.exists()
    assert banc.execute("SELECT count(*) FROM objet").fetchone()[0] == 0


# --- livraison -------------------------------------------------------------------------------------------------------

def _jeu_tv(fournisseur, moi, datas, usage="tv-indices", niveau="LIMITED", sub_id=None):
    o = offre(fournisseur, kind="dataset", tarif={"modele": "gratuit"}, classe="communaute", scope={"usage": usage})
    sid = o["payload"]["service_id"]
    entrees, parent = [o], ""
    for i, d in enumerate(datas, 1):
        entrees.append(version(fournisseur, sid, i, d, classe="communaute", parent=parent))
        parent = b2(d)
    s = abonnement(moi, sid, sub_id=sub_id)
    debut = min(T0, datetime.now(timezone.utc)) - timedelta(minutes=1)
    entrees.append(moi.signe("service_subscribe", dict(s["payload"], requested_at=debut.isoformat())))
    return sid, s["payload"]["subscription_id"], entrees


def _recu(cx, data, did):
    e, t = objets.ecrire([data], len(data))
    objets.noter(cx, e, t, did)
    return e


def _synchro(cx, moi, entrees, noeuds):
    catalogue.synchroniser(cx, export(moi, entrees, [(moi, "LIMITED")] + noeuds), T0)


def test_livraison_abonnement_actif_tv_indices_seulement(banc):
    moi, f, g = Noeud("gk12"), Noeud("gk6"), Noeud("gk4")
    v1, v2 = octets(contenu()), octets(contenu(**{"x.exemple.org": "TELEMETRIE"}))
    _sid, _sub, e1 = _jeu_tv(f, moi, [v1, v2])
    _sid2, _sub2, e2 = _jeu_tv(g, moi, [b"autre jeu"], usage="")     # offre sans usage : jamais livrée
    _synchro(banc, moi, e1 + e2, [(f, "LIMITED"), (g, "LIMITED")])
    assert {r[0] for r in banc.execute("SELECT usage FROM offer")} == {"tv-indices", ""}
    _recu(banc, v1, f.did)
    _recu(banc, b"autre jeu", g.did)
    # v2 pas encore reçue : la dernière version PRÉSENTE (v1) est livrée.
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 1
    fichier = locaux.LIVRAISON / (f.did[8:] + ".json")
    assert fichier.read_bytes() == v1 and stat.S_IMODE(fichier.stat().st_mode) == 0o640
    assert json.loads((locaux.LIVRAISON / "index.json").read_text()) == {f.did: {"nom": "gk6", "empreinte": b2(v1)}}
    assert not (locaux.LIVRAISON / (g.did[8:] + ".json")).exists()
    _recu(banc, v2, f.did)
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 1
    assert fichier.read_bytes() == v2
    assert json.loads((locaux.LIVRAISON / "index.json").read_text())[f.did]["empreinte"] == b2(v2)


def test_fournisseur_observer_plus_livre(banc):
    moi, f = Noeud("gk12"), Noeud("gk6")
    v1 = octets(contenu())
    _sid, _sub, e = _jeu_tv(f, moi, [v1])
    _synchro(banc, moi, e, [(f, "LIMITED")])
    _recu(banc, v1, f.did)
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 1
    _synchro(banc, moi, e, [(f, "OBSERVER")])
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 0
    assert not (locaux.LIVRAISON / (f.did[8:] + ".json")).exists()
    assert json.loads((locaux.LIVRAISON / "index.json").read_text()) == {}
    # Seuil relevé : un LIMITED ne suffit plus quand confiance_min = PARTNER.
    _synchro(banc, moi, e, [(f, "LIMITED")])
    assert locaux.livrer(banc, locaux.LIVRAISON, "PARTNER") == 0
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 1


def test_abonnement_resilie_fichier_supprime(banc):
    moi, f = Noeud("gk12"), Noeud("gk6")
    v1 = octets(contenu())
    _sid, sub, e = _jeu_tv(f, moi, [v1])
    _synchro(banc, moi, e, [(f, "LIMITED")])
    _recu(banc, v1, f.did)
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 1
    e.append(moi.signe("service_revoke_sub", {"op": "service_revoke_sub", "subscription_id": sub, "subscriber": moi.did,
                                              "revoked_at": T0.isoformat(), "motif": "fin"}))
    _synchro(banc, moi, e, [(f, "LIMITED")])
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 0
    assert sorted(p.name for p in locaux.LIVRAISON.iterdir()) == ["index.json"]


def test_nom_invalide_ou_objet_altere_non_livre(banc):
    moi, f, g = Noeud("gk12"), Noeud("GK 6!"), Noeud("gk4")
    v1, w1 = octets(contenu()), octets(contenu(**{"y.exemple.org": "TRACKING"}))
    _s, _u, e1 = _jeu_tv(f, moi, [v1])
    _s2, _u2, e2 = _jeu_tv(g, moi, [w1])
    _synchro(banc, moi, e1 + e2, [(f, "LIMITED"), (g, "LIMITED")])
    _recu(banc, v1, f.did)
    ew = _recu(banc, w1, g.did)
    objets.chemin(ew).write_bytes(b"altere")                      # objet modifié sur disque : empreinte fausse
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 0
    assert json.loads((locaux.LIVRAISON / "index.json").read_text()) == {}


def test_version_retiree_non_livree(banc):
    moi, f = Noeud("gk12"), Noeud("gk6")
    v1 = octets(contenu())
    sid, _sub, e = _jeu_tv(f, moi, [v1])
    e.append(f.signe("service_dataset_retract", {"op": "service_dataset_retract", "service_id": sid, "provider": f.did,
                                                 "empreinte": b2(v1), "motif": "", "retracted_at": T0.isoformat()}))
    _synchro(banc, moi, e, [(f, "LIMITED")])
    _recu(banc, v1, f.did)
    assert locaux.livrer(banc, locaux.LIVRAISON, "LIMITED") == 0


def test_usage_normalise():
    f = Noeud("gk6")
    for scope, attendu in (({"usage": "tv-indices"}, "tv-indices"), ({"usage": "TV!"}, ""), ({"usage": "x" * 33}, ""),
                           ({"usage": 3}, ""), ("pas un dict", ""), (None, "")):
        p = offre(f, kind="dataset", scope=scope)["payload"]
        assert catalogue.offre_normalisee(p)["usage"] == attendu, scope


# --- passe -----------------------------------------------------------------------------------------------------------

def test_passe_ne_leve_jamais(banc, monkeypatch):
    moi, f = Noeud("gk12"), Noeud("gk6")
    v1 = octets(contenu())
    _sid, _sub, e = _jeu_tv(f, moi, [v1])
    _synchro(banc, moi, e, [(f, "LIMITED")])
    _recu(banc, v1, f.did)
    poser_source(locaux.SOURCE_TV, contenu())
    r = locaux.passe(banc, REG)
    assert r["publication"] is True and r["livres"] == 1
    # Dossier de livraison remplacé par un fichier : erreur journalisée, jamais levée.
    monkeypatch.setattr(locaux, "LIVRAISON", TMP[0] / "indices-publication.json")
    r = locaux.passe(banc, REG)
    assert "erreur" in r
    assert os.path.isfile(TMP[0] / "indices-publication.json")


def test_passe_de_reception_livre_aussi(banc, monkeypatch):
    import importlib
    main = importlib.import_module("api.main")
    monkeypatch.setattr(config, "BASE", TMP[0] / "m.db")
    moi, f = Noeud("gk12"), Noeud("gk6")
    v1 = octets(contenu())
    _sid, _sub, e = _jeu_tv(f, moi, [v1])
    _synchro(banc, moi, e, [(f, "LIMITED")])
    _recu(banc, v1, f.did)
    res = main.tirer_maintenant()
    assert res["locaux"] == {"publication": False, "livres": 1}
    assert (locaux.LIVRAISON / (f.did[8:] + ".json")).read_bytes() == v1
