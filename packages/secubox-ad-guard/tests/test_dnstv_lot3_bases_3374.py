# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 3 SBX TV PRIVACY (#3374) : modes nommés (PROTECT = ancien block), suffixe de recherche, référence OQEE, portée des corrections."""
from pathlib import Path

import pytest

from api import dnstv, dnstv_taxonomie as T
from test_dnstv_ctl_api import api, monde  # noqa: F401  (fixtures)

LISTES = Path(__file__).resolve().parents[1] / "lists"


# ── modes ────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("brut,stocke", [("protect", "block"), ("PROTECT", "block"), ("block", "block"), ("observe", "observe"),
                                         ("AUTO", "auto"), ("off", "off")])
def test_normaliser_mode(brut, stocke):
    assert dnstv.normaliser_mode(brut) == stocke


@pytest.mark.parametrize("brut", ["", "bloquer", None, 3, "protect "])
def test_normaliser_mode_refuse(brut):
    with pytest.raises(dnstv.ErreurTV):
        dnstv.normaliser_mode(brut)


def test_nom_mode():
    assert [dnstv.nom_mode(m) for m in ("observe", "block", "auto", "off")] == ["OBSERVE", "PROTECT", "AUTO", "OFF"]


def test_route_mode_accepte_protect_et_garde_block_lisible(api, monde):
    api.post("/adblock-tv/clients", json={"ip": "192.168.1.50", "nom": "TV", "mode": "observe"})
    r = api.post("/adblock-tv/mode", json={"mode": "protect", "ip": "192.168.1.50"})
    assert r.status_code == 200
    c = r.json()["etat"]["clients"][0]
    assert c["mode"] == "block" and c["mode_nom"] == "PROTECT"
    assert dnstv.lire_etat()[0]["clients"][0]["mode"] == "block"            # stockage inchangé : aucune migration
    assert api.post("/adblock-tv/mode", json={"mode": "block"}).json()["etat"]["clients"][0]["mode_nom"] == "PROTECT"
    assert api.post("/adblock-tv/mode", json={"mode": "durcir"}).status_code == 422


def test_defaut_paquet_auto_et_ajout_auto():
    import tomllib
    conf = tomllib.loads((Path(__file__).resolve().parents[1] / "config" / "ad-guard.toml").read_text())
    assert conf["adblock_tv"]["ajout_auto_initial"] is True
    assert dnstv.ETAT_DEFAUT["mode_defaut"] == "auto"


def test_etat_initial_nouvelle_installation(monde):
    etat = dnstv.etat_initial({"adblock_tv": {"ajout_auto_initial": True}})
    assert etat["ajout_auto"] is True and etat["mode_defaut"] == "auto"
    assert dnstv.etat_initial({})["ajout_auto"] is False


def test_lire_etat_sans_fichier_applique_le_defaut_du_paquet(monde, monkeypatch):
    monkeypatch.setattr(dnstv, "_conf_paquet", lambda: {"adblock_tv": {"ajout_auto_initial": True}})
    etat, err = dnstv.lire_etat()
    assert err is None and etat["ajout_auto"] is True
    dnstv.ecrire_etat(dict(etat, ajout_auto=False))
    assert dnstv.lire_etat()[0]["ajout_auto"] is False                     # une box existante garde son réglage


# ── suffixe de recherche ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("brut,reel", [("googleads.g.doubleclick.net.home", "googleads.g.doubleclick.net"),
                                       ("api.oqee.net.lan", "api.oqee.net"), ("x.example.localdomain", "x.example"),
                                       ("k7.ftven.fr", "k7.ftven.fr"), ("box.home", "box.home"), ("home", "home")])
def test_domaine_reel(brut, reel):
    assert dnstv.domaine_reel(brut) == reel


def test_l_analyseur_ramene_le_suffixe_home():
    a = dnstv.Analyseur()
    e = a.ligne("[1700000000] unbound[1:0] info: reply: 192.168.1.95 pubads.g.doubleclick.net.home. A IN NXDOMAIN 0.0 0 40")
    assert e.qname == "pubads.g.doubleclick.net"


def test_la_classification_ramene_le_suffixe_home():
    t = T.Taxonomie.depuis_dossier(LISTES)
    c = t.classer("license.oqee.net.home")
    assert c["domaine"] == "license.oqee.net" and c["categorie"] == "DRM"


# ── référence : mesure gk2 2026-11-01 ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("domaine,cat", [("license.oqee.net", "DRM"), ("api.oqee.net", "STREAMING"), ("img1.oqee.net", "STREAMING"),
                                         ("img2.oqee.net", "STREAMING"), ("media4.stream.proxad.net", "STREAMING")])
def test_reference_oqee(domaine, cat):
    c = T.Taxonomie.depuis_dossier(LISTES).classer(domaine)
    assert c["categorie"] == cat and c["protegee"] is True


def test_reference_sourcee_et_manifeste():
    txt = (LISTES / "reference-tv.txt").read_text()
    assert txt.count("mesure gk2 2026-11-01") >= 5
    assert dnstv.verifier_manifeste(LISTES) == []


# ── portée : un parent ne rend pas bloquable une entrée protégée de services.txt ─────────────────────
@pytest.mark.parametrize("domaine", ["free.fr", "proxad.net"])
def test_parent_couvrant_services_proteges_refuse(domaine):
    t = T.Taxonomie.depuis_dossier(LISTES)
    with pytest.raises(T.ErreurTaxonomie, match="trop large"):
        T.corriger({}, domaine, None, "PUBLICITE", 1, reference=t.reference.items(), services=t.services.items())


def test_sous_domaine_ou_categorie_protegee_admis():
    t = T.Taxonomie.depuis_dossier(LISTES)
    kw = {"reference": t.reference.items(), "services": t.services.items()}
    assert T.corriger({}, "ads.free.fr", None, "PUBLICITE", 1, **kw)
    assert T.corriger({}, "free.fr", None, "STREAMING", 1, **kw)


def test_route_classification_refuse_free_fr(api, monde, monkeypatch):
    from api import dnstv_routes as r
    monkeypatch.setattr(r, "_ctl_entree", lambda *a: None)
    rep = api.post("/adblock-tv/classification", json={"domaine": "free.fr", "categorie": "PUBLICITE"})
    assert rep.status_code == 422 and "trop large" in rep.json()["detail"]
