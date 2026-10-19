# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2819 — le contenu des profils est LU des meta-paquets secubox-<profil> a la construction, jamais saisi a la main."""
import importlib.util
import json
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gen", PKG / "scripts" / "gen-profils-contenu.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def meta(racine, nom, depends, version="1.0"):
    d = racine / f"secubox-{nom}" / "debian"
    d.mkdir(parents=True)
    corps = ",\n".join(f" {x}" for x in depends)
    (d / "control").write_text(f"Source: secubox-{nom}\n\nPackage: secubox-{nom}\nArchitecture: all\nDepends: ${{misc:Depends}},\n# un commentaire au milieu\n{corps}\nDescription: x\n y\n")
    (d / "changelog").write_text(f"secubox-{nom} ({version}-1~bookworm1) bookworm; urgency=medium\n\n  * x\n\n -- A <a@b.c>  Mon, 12 Oct 2026 10:00:00 +0200\n")


@pytest.fixture()
def arbre(tmp_path):
    p = tmp_path / "packages"
    meta(p, "minimal", ["secubox-core (>= 1.0)", "secubox-dpi (>= 1.7.0)", "secubox-nac"])
    meta(p, "lite", ["secubox-core", "secubox-dpi", "secubox-nac", "secubox-waf-ng (>= 1.0)", "secubox-wireguard"])
    meta(p, "isp", ["secubox-lite (>= 1.5.0)", "secubox-mail", "secubox-gitea"])
    meta(p, "full", ["secubox-isp (>= 1.4.0)", "secubox-webos", "secubox-avatar | secubox-autre"])
    esp = tmp_path / "espaces.json"
    esp.write_text(json.dumps({"espaces": [{"id": "protection", "nom": "Protection", "icone": "🛡️", "ordre": 2}, {"id": "services", "nom": "Services", "icone": "📦", "ordre": 4}],
                               "modules": {"dpi": {"espace": "protection"}, "nac": {"espace": "protection"}, "waf": {"espace": "protection"}, "mail": {"espace": "services"}}}))
    return p, esp


def test_les_dependances_directes_sont_lues_sans_versions_ni_commentaires(arbre):
    p, esp = arbre
    d = gen.construire(p, esp)
    mini = next(x for x in d["profils"] if x["id"] == "minimal")
    assert {m["paquet"] for m in mini["directs"]} == {"secubox-core", "secubox-dpi", "secubox-nac"}


def test_la_chaine_d_inclusion_est_deduite_des_meta_paquets(arbre):
    p, esp = arbre
    d = {x["id"]: x for x in gen.construire(p, esp)["profils"]}
    assert d["minimal"]["inclut"] is None and d["lite"]["inclut"] is None
    assert d["isp"]["inclut"] == "lite" and d["full"]["inclut"] == "isp"
    assert d["isp"]["total"] == len(d["lite"]["modules"]) + 2          # lite + mail + gitea
    assert {m["paquet"] for m in d["full"]["ajoutes"]} == {"secubox-webos", "secubox-avatar"}   # la 1re alternative d'un « a | b »


def test_ce_que_minimal_n_a_pas_est_calcule(arbre):
    p, esp = arbre
    d = gen.construire(p, esp)
    absents = {m["paquet"] for m in d["absents_de_minimal"]}
    assert {"secubox-waf-ng", "secubox-wireguard", "secubox-mail", "secubox-webos"} <= absents and "secubox-dpi" not in absents


def test_les_modules_sont_ranges_par_espace(arbre):
    p, esp = arbre
    lite = next(x for x in gen.construire(p, esp)["profils"] if x["id"] == "lite")
    par = {m["paquet"]: m["espace"] for m in lite["modules"]}
    assert par["secubox-dpi"] == "protection" and par["secubox-waf-ng"] == "protection"     # waf-ng -> « waf » (suffixe -ng)
    assert par["secubox-wireguard"] == "autres"                                                # inconnu de espaces.json : jamais invente


def test_les_versions_viennent_du_changelog(arbre):
    p, esp = arbre
    assert next(x for x in gen.construire(p, esp)["profils"] if x["id"] == "lite")["version"] == "1.0-1~bookworm1"


def test_un_meta_paquet_absent_est_une_erreur_pas_un_profil_vide(arbre):
    p, esp = arbre
    (p / "secubox-isp" / "debian" / "control").unlink()
    with pytest.raises(gen.ProfilIncoherent):
        gen.construire(p, esp)


def test_ecriture_atomique_et_json_valide(arbre, tmp_path):
    p, esp = arbre
    sortie = tmp_path / "out" / "contenu-profils.json"
    assert gen.main([str(p), str(esp), str(sortie)]) == 0
    assert json.loads(sortie.read_text())["profils"][0]["id"] == "minimal"
    assert not list(sortie.parent.glob(".*tmp"))


def test_sur_le_vrai_depot_minimal_a_wireguard_mais_ni_waf_ni_hall_ni_metrics():
    depot = PKG.parent
    d = gen.construire(depot, depot / "secubox-hub" / "espaces.json")
    mini = {m["paquet"] for m in next(x for x in d["profils"] if x["id"] == "minimal")["modules"]}
    assert not mini & {"secubox-waf-ng", "secubox-haproxy", "secubox-webos", "secubox-metrics", "secubox-isp"}
    assert "secubox-wireguard" in mini      # #2845
    assert {"secubox-dpi", "secubox-dns-guard", "secubox-ad-guard", "secubox-nac", "secubox-freebox"} <= mini


def test_la_construction_genere_et_installe_le_contenu_des_profils():
    rules = (PKG / "debian" / "rules").read_text()
    assert "gen-profils-contenu.py" in rules and "usr/share/secubox/profiles/contenu-profils.json" in rules
    assert "secubox-hub/espaces.json" in rules
