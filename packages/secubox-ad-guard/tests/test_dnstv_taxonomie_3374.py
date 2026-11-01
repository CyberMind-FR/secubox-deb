# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 2 SBX TV PRIVACY (#3374) : taxonomie unique, classification sourcée, garde de sûreté du moteur AUTO, routes."""
import json
import os
import re
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_auto as M, dnstv_profil as P, dnstv_regles as R, dnstv_taxonomie as T

from test_dnstv_ctl_api import api, monde  # noqa: F401  (fixtures)

LISTES = Path(__file__).resolve().parents[1] / "lists"
IP = "192.168.1.95"
MAC = "00:24:d4:00:00:01"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto", "mac": MAC}]}


def taxo(**kw):
    return T.Taxonomie.depuis_dossier(LISTES, **kw)


# ── la taxonomie ─────────────────────────────────────────────────────────────────────────────────────
def test_dix_categories_et_six_protegees():
    assert T.CATEGORIES == ("PUBLICITE", "TRACKING", "TELEMETRIE", "STREAMING", "CDN", "DRM", "AUTHENTIFICATION",
                            "MISE_A_JOUR", "SERVICES_CONSTRUCTEUR", "INCONNU")
    assert T.PROTEGEES == frozenset({"STREAMING", "CDN", "DRM", "AUTHENTIFICATION", "MISE_A_JOUR", "INCONNU"})
    assert T.SOURCES == ("liste", "apprentissage", "ndpi", "manuelle", "profil")
    for c in T.CATEGORIES:
        assert T.blocage_auto_permis(c) is (c not in T.PROTEGEES)
    assert T.blocage_auto_permis("nimporte") is False                       # inconnue = protégée


def test_correspondance_couvre_les_trois_anciennes_taxonomies():
    anciennes = set(dnstv.CATEGORIES) | set(dnstv.TYPES_SERVICE)
    main = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text()
    bloc = main.split("class AdCategory", 1)[1].split("\n\n", 1)[0]
    anciennes |= set(re.findall(r'=\s*"([a-z_]+)"', bloc))
    assert {"analytics", "malware", "cryptominer"} <= anciennes
    for a in anciennes:
        assert T.depuis_ancienne(a) in T.CATEGORIES, a
    assert T.depuis_ancienne("advertising") == "PUBLICITE" and T.depuis_ancienne("contenu") == "STREAMING"
    assert T.depuis_ancienne("cdn") == "CDN" and T.depuis_ancienne("telemetry") == "TELEMETRIE"
    assert T.depuis_ancienne("") == "INCONNU" and T.depuis_ancienne(None) == "INCONNU" and T.depuis_ancienne("zzz") == "INCONNU"


def test_reference_tv_sourcee_valide_et_au_manifeste():
    f = LISTES / "reference-tv.txt"
    regles = T.charger_reference(f)
    assert regles, "référence vide"
    for ligne in f.read_text(encoding="utf-8").splitlines():
        brut = ligne.split("#", 1)[0].split()
        if not brut:
            continue
        assert len(brut) == 2 and dnstv.valider_domaine(brut[0]) == brut[0] and brut[1] in T.CATEGORIES, ligne
        assert "#" in ligne and len(ligne.split("#", 1)[1].strip()) > 5, f"source manquante : {ligne}"
    poc = {"cloudreplay.ftven.fr", "k7.ftven.fr", "hdfauth.ftven.fr", "geo-info.ftven.fr", "medias.france.tv",
           "proxy-mediation.yatta.francetv.fr", "assets.webservices.francetelevisions.fr"}
    assert poc <= {d for d, c in regles if c == "STREAMING"}
    assert dnstv.verifier_manifeste(LISTES) == []


def test_classer_par_source_et_confiance():
    t = taxo()
    k7 = t.classer("k7.ftven.fr")
    assert (k7["categorie"], k7["source"], k7["confiance"], k7["protegee"]) == ("STREAMING", "liste", 90, True)
    pub = t.classer("x.doubleclick.net")
    assert (pub["categorie"], pub["source"], pub["ancienne"], pub["protegee"]) == ("PUBLICITE", "liste", "advertising", False)
    assert t.classer("npaw.com")["categorie"] == "TELEMETRIE"                       # services.txt : qualite_video
    c2 = t.classer("c.2mdn.net")
    assert (c2["categorie"], c2["source"]) == ("PUBLICITE", "profil")
    inc = t.classer("rien.example.org")
    assert (inc["categorie"], inc["source"], inc["confiance"]) == ("INCONNU", "aucune", 0)
    assert t.classer("pas un domaine")["categorie"] == "INCONNU"


def test_la_reference_l_emporte_a_suffixe_egal_et_le_plus_long_suffixe_gagne():
    t = T.Taxonomie(reference=[("ex.net", "CDN"), ("pub.ex.net", "PUBLICITE")], listes={"ex.net": "advertising"})
    assert t.classer("a.ex.net")["categorie"] == "CDN"
    assert t.classer("z.pub.ex.net")["categorie"] == "PUBLICITE"


def test_apprentissage_jamais_bloquable():
    r = R.Regles()
    r.proposer("tv-banc", "inconnu.pub-variable.net", 40, "faible", 1)
    c = taxo(regles=r).classer("inconnu.pub-variable.net")
    assert (c["categorie"], c["source"], c["confiance"], c["protegee"]) == ("INCONNU", "apprentissage", 40, True)


def test_correction_manuelle_prime_par_mac_puis_globale():
    m = T.corriger({}, "fwmrm.net", None, "CDN", 10)
    m = T.corriger(m, "fwmrm.net", MAC.upper(), "PUBLICITE", 11)
    t = taxo(manuelles=m)
    assert t.classer("7cd77.v.fwmrm.net")["categorie"] == "CDN"
    c = t.classer("7cd77.v.fwmrm.net", macs=[MAC])
    assert (c["categorie"], c["source"], c["confiance"]) == ("PUBLICITE", "manuelle", 100)
    m = T.corriger(m, "fwmrm.net", None, None, 12)                                  # None : retire
    assert taxo(manuelles=m).classer("7cd77.v.fwmrm.net")["source"] == "liste"


@pytest.mark.parametrize("domaine,mac,cat", [("pas un domaine", None, "CDN"), ("a.example.com", None, "TOASTER"),
                                             ("a.example.com", "zz:zz", "CDN"), ("A.example.com\n", None, "CDN")])
def test_correction_refusee(domaine, mac, cat):
    with pytest.raises(T.ErreurTaxonomie):
        T.corriger({}, domaine, mac, cat, 1)


def test_manuelles_lecture_ecriture_atomique(tmp_path):
    assert T.charger_manuelles(tmp_path) == {}
    m = T.corriger({}, "a.example.com", MAC, "TRACKING", 5)
    T.ecrire_manuelles(m, tmp_path)
    assert T.charger_manuelles(tmp_path) == m
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".classification.")]
    brut = json.loads((tmp_path / T.FICHIER).read_text())
    assert brut["version"] == 1 and brut["manuelles"][0]["mac"] == MAC


def test_manuelles_refuse_lien_et_contenu_hostile(tmp_path):
    cible = tmp_path / "ailleurs.json"
    cible.write_text(json.dumps({"version": 1, "manuelles": []}))
    os.symlink(cible, tmp_path / T.FICHIER)
    with pytest.raises(T.ErreurTaxonomie):
        T.charger_manuelles(tmp_path)
    os.unlink(tmp_path / T.FICHIER)
    (tmp_path / T.FICHIER).write_text(json.dumps({"version": 1, "manuelles": [{"domaine": "x;rm", "mac": "", "categorie": "CDN", "maj": 1}]}))
    with pytest.raises(T.ErreurTaxonomie):
        T.charger_manuelles(tmp_path)


def test_plafond_des_corrections():
    m = {}
    for i in range(T.MANUELLES_MAX):
        m = T.corriger(m, f"d{i}.example.com", None, "CDN", 1)
    with pytest.raises(T.ErreurTaxonomie):
        T.corriger(m, "encore.example.com", None, "CDN", 1)


# ── garde de sûreté du moteur AUTO ───────────────────────────────────────────────────────────────────
def evt(ts, d, decision="ALLOWED"):
    return dnstv.Evenement(ts, IP, d, "A", "NXDOMAIN" if decision == "BLOCKED" else "NOERROR", decision)


@pytest.fixture
def magasin(tmp_path):
    return dnstv.Magasin(tmp_path / "m.db")


def coupures(magasin, t, domaine):
    magasin.ajouter([(e, "") for k in (3000, 1500) for e in (evt(t - k, "7cd77.v.fwmrm.net"), evt(t - k + 3, domaine))])


def classer(d):
    return {"7cd77.v.fwmrm.net": "advertising"}.get(d, "")


def test_garde_refuse_l_essai_automatique_d_un_domaine_protege(magasin):
    t = int(time.time())
    coupures(magasin, t, "videos-pub.ftv-publicite.fr")
    r = R.Regles()
    m = T.corriger({}, "ftv-publicite.fr", None, "CDN", t)
    M.tick(ETAT, r, magasin, classer, M.Reglage(auto_essai=True), t, taxo=taxo(manuelles=m))
    etats = {x["domaine"]: x["etat"] for x in r.liste()}
    assert etats["videos-pub.ftv-publicite.fr"] == "candidat"                  # proposé à l'humain, jamais bloqué seul
    assert "videos-pub.ftv-publicite.fr" not in r.actives("tv-banc")
    assert etats["7cd77.v.fwmrm.net"] == "essai"                                # le reste est inchangé


def test_garde_refuse_l_essai_automatique_d_un_domaine_inconnu(magasin):
    t = int(time.time())
    coupures(magasin, t, "x1.pub-inconnue.example")
    r = R.Regles()
    M.tick(ETAT, r, magasin, classer, M.Reglage(auto_essai=True), t)
    assert {x["domaine"]: x["etat"] for x in r.liste()}.get("x1.pub-inconnue.example") == "candidat"


def test_une_correction_manuelle_rend_le_domaine_eligible(magasin):
    t = int(time.time())
    coupures(magasin, t, "x1.pub-inconnue.example")
    r = R.Regles()
    m = T.corriger({}, "pub-inconnue.example", None, "PUBLICITE", t)
    M.tick(ETAT, r, magasin, classer, M.Reglage(auto_essai=True), t, taxo=taxo(manuelles=m))
    assert "x1.pub-inconnue.example" in r.actives("tv-banc")


def test_garde_refuse_la_confirmation_automatique_d_un_essai_protege(magasin):
    t = int(time.time())
    r = R.Regles()
    debut = t - R.ESSAI_S - 60
    rid = r.proposer("tv-banc", "k7.ftven.fr", 50, "faible", debut)["id"]
    r.transiter(rid, "essai", "auto", "essai automatique", debut)
    magasin.ajouter([(evt(t - i * 5, "api.contenu-habituel.fr"), "") for i in range(150)])
    M.tick(ETAT, r, magasin, classer, M.Reglage(confirmation_auto=True), t)
    assert r.get(rid)["etat"] == "retire"                                       # l'expiration normale, jamais « confirme »


def test_equiper_ne_pose_pas_un_domaine_protege():
    r = R.Regles()
    n = P.equiper(r, "tv-n", [("doubleclick.net", "profil de base"), ("k7.ftven.fr", "profil de base")], 1, taxo=taxo())
    assert n == 1 and r.actives("tv-n") == ["doubleclick.net"]


def test_un_blocage_manuel_reste_possible_sur_un_domaine_protege():
    r = R.Regles()
    rid = r.proposer("tv-banc", "k7.ftven.fr", 50, "faible", 1, origine="admin")["id"]
    r.transiter(rid, "essai", "admin", "", 2)
    r.transiter(rid, "confirme", "admin", "", 3)
    assert r.actives("tv-banc") == ["k7.ftven.fr"]


def test_refus_auto_admet_la_decision_explicite_de_l_administrateur():
    r = R.Regles()
    for app in ("tv-a", "tv-b"):
        rid = r.proposer(app, "ads.cdn-pub.example", 50, "faible", 1, origine="admin")["id"]
        r.transiter(rid, "essai", "admin", "", 2)
        r.transiter(rid, "confirme", "admin", "", 3)
    admin = T.confirmes_par_admin(r)
    assert T.refus_auto(taxo(), "ads.cdn-pub.example", confirmes_admin=admin) is None
    assert T.refus_auto(taxo(), "ads.autre.example", confirmes_admin=admin) is not None


# ── observation et routes ────────────────────────────────────────────────────────────────────────────
def test_magasin_rend_la_derniere_observation(monde):
    mag = dnstv.Magasin(monde["etat"] / "dnstv.db")
    t = int(time.time())
    mag.ajouter([(evt(t - 100, "k7.ftven.fr"), ""), (evt(t - 50, "k7.ftven.fr"), ""), (evt(t - 10, "ad.doubleclick.net", "BLOCKED"), "advertising")])
    obs = mag.observations(dnstv._jour(t - 86400))
    assert obs[IP]["k7.ftven.fr"]["derniere"] == t - 50 and obs[IP]["k7.ftven.fr"]["requetes"] == 2
    assert obs[IP]["ad.doubleclick.net"]["bloquees"] == 1


def _etat_v2(monde):
    e = dict(ETAT, schema=2, appareils={MAC: {"nom": "TV banc"}})
    dnstv.ecrire_etat(e, monde["etat"])


def test_route_classification_filtrable(api, monde):
    _etat_v2(monde)
    t = int(time.time())
    mag = dnstv.Magasin(monde["etat"] / "dnstv.db")
    mag.ajouter([(evt(t - 50, "k7.ftven.fr"), ""), (evt(t - 10, "ad.doubleclick.net", "BLOCKED"), "advertising"),
                 (dnstv.Evenement(t - 5, "192.168.1.200", "autre.example.org", "A", "NOERROR", "ALLOWED"), "")])
    etat, _ = dnstv.lire_etat(monde["etat"])
    T.ecrire_cache(T.construire_classification(etat, taxo(), mag.observations(dnstv._jour(t - 86400)), []), t, monde["etat"])
    j = api.get("/adblock-tv/classification/detail").json()
    assert j["categories"] == list(T.CATEGORIES) and set(j["protegees"]) == set(T.PROTEGEES)
    lignes = {(x["domaine"], x["mac"]): x for x in j["domaines"]}
    k7 = lignes[("k7.ftven.fr", MAC)]
    assert {"categorie", "source", "confiance", "derniere_observation", "protegee"} <= set(k7)
    assert k7["categorie"] == "STREAMING" and k7["derniere_observation"] == t - 50
    seul = api.get(f"/adblock-tv/classification/detail?mac={MAC}&categorie=PUBLICITE").json()["domaines"]
    assert [x["domaine"] for x in seul] == ["ad.doubleclick.net"]
    assert api.get("/adblock-tv/classification?categorie=TOASTER").status_code == 422
    assert api.get("/adblock-tv/classification?mac=zz").status_code == 422


def test_route_correction_manuelle(api, monde, monkeypatch):
    from api import dnstv_routes as rt
    audits = []
    monkeypatch.setattr(rt, "_ctl_entree", lambda action, entree: audits.append((action, json.loads(entree))))
    _etat_v2(monde)
    r = api.post("/adblock-tv/classification", json={"domaine": "Ads.Exemple.NET", "categorie": "PUBLICITE", "mac": MAC})
    assert r.status_code == 200 and r.json()["categorie"] == "PUBLICITE" and r.json()["source"] == "manuelle"
    assert T.charger_manuelles(monde["etat"])[(MAC, "ads.exemple.net")]["categorie"] == "PUBLICITE"
    assert audits[0][0] == "audit-classification" and audits[0][1]["nouvelle"] == "PUBLICITE"
    assert api.post("/adblock-tv/classification", json={"domaine": "ads.exemple.net", "categorie": None, "mac": MAC}).status_code == 200
    assert T.charger_manuelles(monde["etat"]) == {}
    for corps in ({"domaine": "x;rm -rf", "categorie": "CDN"}, {"domaine": "a.example.com", "categorie": "TOASTER"},
                  {"domaine": "a.example.com", "categorie": "CDN", "role": "admin"}, {"domaine": "a.example.com", "categorie": "CDN", "mac": "zz"}):
        assert api.post("/adblock-tv/classification", json=corps).status_code == 422, corps


def test_gardes_des_routes_de_classification():
    from secubox_core import auth
    from api import dnstv_routes as r
    gardes = {(x.path, tuple(sorted(x.methods))): {d.call for d in x.dependant.dependencies} for x in r.router.routes if x.path.endswith("/classification")}
    assert auth.require_lecture in gardes[("/adblock-tv/classification", ("GET",))]
    assert auth.require_jwt in gardes[("/adblock-tv/classification", ("POST",))]


def test_le_moteur_tient_compte_des_corrections_manuelles_a_l_ajout(monkeypatch, tmp_path):
    from test_dnstv_ajout_moteur import Rep, charger_script, donnees_tv, lancer
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    T.ecrire_manuelles(T.corriger({}, "c.2mdn.net", None, "CDN", t), tmp_path)
    assert lancer(mod, lambda: Rep(), t) == 0
    assert R.charger(tmp_path).actives("tv-fb5b") == ["videos-pub.ftv-publicite.fr"]     # le domaine protégé n'est pas posé


def test_corrections_illisibles_suspendent_les_blocages_automatiques(monkeypatch, tmp_path, capsys):
    from test_dnstv_ajout_moteur import Rep, charger_script, lancer
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, ETAT)
    (tmp_path / T.FICHIER).write_text("{pas du json")
    assert lancer(mod, lambda: Rep(), t) == 0
    assert "corrections de classification illisibles" in capsys.readouterr().err
