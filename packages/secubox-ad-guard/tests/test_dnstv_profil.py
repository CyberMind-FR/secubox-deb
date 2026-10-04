# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1959 : profil de base (graine validée) et agrégation des règles confirmées sur plusieurs appareils."""
import os

from api import dnstv, dnstv_profil as P, dnstv_regles as R

T0 = 1_800_000_000


def confirmer(r, app, dom, origine="admin", motif="ok"):
    rid = r.proposer(app, dom, 50, "faible", T0, origine=origine)["id"]
    r.transiter(rid, "essai", origine, motif, T0)
    r.transiter(rid, "confirme", origine, motif, T0 + 5)


def test_graine_est_le_profil_valide_et_le_manifeste_concorde():
    g = P.graine()
    assert {"videos-pub.ftv-publicite.fr", "c.2mdn.net", "7cd77.v.fwmrm.net"} <= set(g) and len(g) == 35
    assert dnstv.verifier_manifeste(dnstv.DOSSIER_LISTES if (dnstv.DOSSIER_LISTES / "MANIFEST.json").is_file() else P.DOSSIER_LISTES_PAQUET) == []


def test_proposer_garde_le_motif_donne():
    r = R.Regles()
    n = r.proposer("tv-c", "pub.example.com", 90, "faible", T0, motif="confirmé sur 2 autres appareils")
    assert n["motif"] == "confirmé sur 2 autres appareils" and r.get(n["id"])["historique"][0]["motif"] == "confirmé sur 2 autres appareils"
    assert r.proposer("tv-c", "pub2.example.com", 1, "faible", T0)["motif"] == "proposé"


def test_agregation_seuil_deux_appareils_et_provenance():
    r = R.Regles()
    confirmer(r, "tv-a", "pub.example.com")
    confirmer(r, "tv-b", "pub.example.com")
    confirmer(r, "tv-a", "seul.example.com")
    a = P.agreger(r, min_appareils=2)
    assert set(a) == {"pub.example.com"} and sorted(a["pub.example.com"]["appareils"]) == ["tv-a", "tv-b"] and a["pub.example.com"]["maj"] == T0 + 5
    assert set(P.agreger(r, min_appareils=1)) == {"pub.example.com", "seul.example.com"}


def test_les_regles_du_profil_ne_s_auto_renforcent_pas():
    r = R.Regles()
    P.equiper(r, "tv-a", [("pub.example.com", "profil de base")], T0)
    P.equiper(r, "tv-b", [("pub.example.com", "profil de base")], T0)
    assert P.agreger(r, 2) == {}


def test_une_regle_apprise_localement_puis_confirmee_par_l_admin_compte():
    r = R.Regles()
    rid = r.proposer("tv-a", "pub.example.com", 50, "faible", T0, origine="auto")["id"]       # apprise par le moteur
    r.transiter(rid, "essai", "admin", "essai", T0)
    r.transiter(rid, "confirme", "admin", "ok", T0 + 5)                                       # confirmée par l'administrateur
    confirmer(r, "tv-b", "pub.example.com")
    assert "pub.example.com" in P.agreger(r, 2)


def test_equiper_cree_des_regles_confirmees_idempotent():
    r = R.Regles()
    assert P.equiper(r, "tv-n", [("a.example.com", "profil de base"), ("b.example.com", "profil agrégé (2 appareils)")], T0) == 2
    assert r.actives("tv-n") == ["a.example.com", "b.example.com"]
    assert P.equiper(r, "tv-n", [("a.example.com", "profil de base")], T0 + 9) == 0
    assert all(x["etat"] == "confirme" and x["origine"] == "auto" for x in r.liste())


def test_profil_effectif_graine_plus_agrege_sans_doublon():
    eff = P.profil_effectif(["a.example.com", "b.example.com"], {"b.example.com": {"appareils": ["x", "y"], "maj": T0}, "c.example.com": {"appareils": ["x", "y", "z"], "maj": T0}})
    assert dict(eff)["a.example.com"] == "profil de base" and dict(eff)["b.example.com"] == "profil de base"
    assert dict(eff)["c.example.com"] == "profil agrégé (3 appareils)" and len(eff) == 3


def test_candidats_agreges_jamais_actifs_et_pas_chez_ceux_qui_l_ont_ou_l_ont_rejete():
    r = R.Regles()
    confirmer(r, "tv-a", "pub.example.com")
    confirmer(r, "tv-b", "pub.example.com")
    rid = r.proposer("tv-d", "pub.example.com", 1, "faible", T0)["id"]
    r.transiter(rid, "rejete", "admin", "non", T0)
    n = P.candidats_agreges(r, P.agreger(r, 2), ["tv-a", "tv-b", "tv-c", "tv-d"], T0 + 10)
    assert n == 1
    assert [x["etat"] for x in r.liste() if x["appareil"] == "tv-c"] == ["candidat"]
    assert "confirmé sur 2 autres" in r.get(R.identifiant("tv-c", "pub.example.com"))["historique"][0]["motif"]
    assert r.actives("tv-c") == []


def test_agrege_ecriture_atomique_lien_symbolique_et_fichier_corrompu_refuses(tmp_path):
    P.ecrire_agrege({"pub.example.com": {"appareils": ["tv-a", "tv-b"], "maj": T0}}, tmp_path)
    assert "pub.example.com" in P.charger_agrege(tmp_path)
    (tmp_path / "profil-agrege.json").unlink()
    (tmp_path / "ailleurs.json").write_text('{"pub.example.com": {"appareils": ["x"], "maj": 1}}')
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "profil-agrege.json")
    assert P.charger_agrege(tmp_path) == {}                                      # refusé, jamais suivi
    (tmp_path / "profil-agrege.json").unlink()
    (tmp_path / "profil-agrege.json").write_text("{corrompu")
    assert P.charger_agrege(tmp_path) == {}
    (tmp_path / "profil-agrege.json").write_text('{"a b": {"appareils": ["x"], "maj": 1}, "ok.example.com": {"appareils": "pas une liste", "maj": 1}}')
    assert P.charger_agrege(tmp_path) == {}                                      # entrées invalides ignorées, jamais recopiées


def test_absent_donne_un_agrege_vide(tmp_path):
    assert P.charger_agrege(tmp_path) == {}
