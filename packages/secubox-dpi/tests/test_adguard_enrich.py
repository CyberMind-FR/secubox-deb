# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1960 : étiquettes d'ad-guard pour les destinations que le DPI ne classe pas (lecture des FICHIERS DE DONNÉES d'ad-guard, jamais de son code)."""
import copy
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # api importable
from api import adguard_enrich as E  # noqa: E402

SERVICES = """# suffixe  organisation  type
fwmrm.net        FreeWheel              publicite
ftven.fr         France_Télévisions     contenu
ftv-publicite.fr France_Télévisions_Publicité publicite
youboranqs01.com NPAW_(Youbora)         qualite_video
ligne invalide
mauvais.example  Org                    typeinconnu
"""
PUB = "# version: t\nads.example.com\n7cd77.v.fwmrm.net\n"
TRACK = "tracker.example.net\n"


def dossier(tmp_path, services=SERVICES, pub=PUB, track=TRACK):
    (tmp_path / "services.txt").write_text(services)
    (tmp_path / "advertising.txt").write_text(pub)
    (tmp_path / "tracking.txt").write_text(track)
    return tmp_path


def etiqueteur(tmp_path):
    return E.Etiqueteur.depuis_dossier(dossier(tmp_path))


def test_un_suffixe_de_services_etiquette_organisation_et_type(tmp_path):
    e = etiqueteur(tmp_path).etiqueter("7cbf2.v.fwmrm.net")
    assert e["organisation"] == "FreeWheel" and e["type"] == "publicite" and e["source"] == "ad-guard"
    assert etiqueteur(tmp_path).etiqueter("cloudreplay.ftven.fr")["organisation"] == "France Télévisions"
    assert etiqueteur(tmp_path).etiqueter("infinity.youboranqs01.com")["organisation"] == "NPAW (Youbora)"


def test_le_plus_long_suffixe_gagne(tmp_path):
    assert etiqueteur(tmp_path).etiqueter("videos-pub.ftv-publicite.fr")["organisation"] == "France Télévisions Publicité"


def test_une_categorie_de_liste_etiquette_un_domaine_absent_de_services(tmp_path):
    e = etiqueteur(tmp_path).etiqueter("sub.tracker.example.net")
    assert e["categorie"] == "tracking" and e["organisation"] == "" and e["type"] == ""
    assert etiqueteur(tmp_path).etiqueter("7cd77.v.fwmrm.net")["categorie"] == "advertising"       # services ET liste : les deux champs


def test_inconnu_pour_ad_guard_ne_donne_rien(tmp_path):
    assert etiqueteur(tmp_path).etiqueter("inconnu.example.org") == {}


def test_normalisation_et_valeurs_hostiles_sans_exception(tmp_path):
    et = etiqueteur(tmp_path)
    assert et.etiqueter("CloudReplay.FTVEN.fr.")["organisation"] == "France Télévisions"            # majuscules et point final : normalisés
    for hostile in (None, "", "82.67.100.75", "2a01::1", 'x"; reboot.ftven.fr', "a b.ftven.fr", "../etc", "x" * 400 + ".ftven.fr", 42, b"ftven.fr"):
        assert et.etiqueter(hostile) == {}


def test_lignes_invalides_des_donnees_ignorees(tmp_path):
    s = E.charger_services(dossier(tmp_path) / "services.txt")
    assert {x[0] for x in s} == {"fwmrm.net", "ftven.fr", "ftv-publicite.fr", "youboranqs01.com"}
    assert E.charger_services(tmp_path / "absent.txt") == [] and E.charger_listes(tmp_path / "absent") == {}


def classer_dpi(nom):
    return {"id": "app-x"} if str(nom).endswith("connu.example.org") else {}


def usage(*noms):
    return {"usages": [{"name": "streaming"}], "unknown": [{"name": n, "flows": 3, "bytes": 1000, "pct": 0.0} for n in noms]}


def test_enrichir_ajoute_etiquette_et_compteur_sans_rien_retirer(tmp_path):
    u = usage("7cd77.v.fwmrm.net", "inconnu.example.org", "cloudreplay.ftven.fr")
    avant = copy.deepcopy(u)
    r = E.enrichir_usage(u, etiqueteur(tmp_path), classer_dpi)
    assert u == avant                                                                       # l'usage d'origine n'est pas modifié
    assert [x["name"] for x in r["unknown"]] == [x["name"] for x in avant["unknown"]] and r["usages"] == avant["usages"]
    par = {x["name"]: x for x in r["unknown"]}
    assert par["7cd77.v.fwmrm.net"]["etiquette"]["type"] == "publicite" and "etiquette" not in par["inconnu.example.org"]
    assert r["adguard"] == {"etiquetes": 2, "total": 3}


def test_la_regle_du_dpi_gagne(tmp_path):
    r = E.enrichir_usage(usage("connu.example.org", "7cd77.v.fwmrm.net"), E.Etiqueteur.depuis_dossier(dossier(tmp_path, services=SERVICES + "connu.example.org Autre contenu\n")), classer_dpi)
    par = {x["name"]: x for x in r["unknown"]}
    assert "etiquette" not in par["connu.example.org"] and "etiquette" in par["7cd77.v.fwmrm.net"]


def test_donnees_absentes_usage_identique(tmp_path):
    u = usage("7cd77.v.fwmrm.net")
    vide = E.Etiqueteur.depuis_dossier(tmp_path / "absent")
    assert vide.vide is True and E.enrichir_usage(u, vide, classer_dpi) == u and "adguard" not in E.enrichir_usage(u, vide, classer_dpi)
    assert E.enrichir_usage({"usages": []}, etiqueteur(tmp_path), classer_dpi) == {"usages": []}          # pas de liste « unknown » : rien à faire
    assert E.enrichir_usage("pas un dict", etiqueteur(tmp_path), classer_dpi) == "pas un dict"


def test_entrees_inconnues_mal_formees_ignorees(tmp_path):
    u = {"unknown": [None, 5, {"name": None}, {"bytes": 1}, {"name": "7cd77.v.fwmrm.net"}]}
    r = E.enrichir_usage(u, etiqueteur(tmp_path), classer_dpi)
    assert r["adguard"]["etiquetes"] == 1


def test_quatre_mille_noms_en_moins_d_une_seconde(tmp_path):
    et = etiqueteur(tmp_path)
    u = usage(*[f"h{i}.sub{i % 50}.example.org" for i in range(3990)], "7cd77.v.fwmrm.net", "a.ftven.fr", "b.ftven.fr", "c.ftven.fr", "d.ftven.fr", "e.ftven.fr", "f.ftven.fr", "g.ftven.fr", "h.ftven.fr", "i.ftven.fr")
    t = time.perf_counter()
    r = E.enrichir_usage(u, et, classer_dpi)
    assert time.perf_counter() - t < 1.0 and r["adguard"]["etiquetes"] == 10 and r["adguard"]["total"] == 4000
