# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2875 — le comparateur dit ce qu'un profil INSTALLE réellement : la fermeture transitive des dépendances, pas seulement celles du méta-paquet.

Constat sur la carte (minimal) : secubox-premier-pas (tiré par autoload-agent) et secubox-p2p (tiré par premier-pas) y sont installés, mais la page les rangeait dans « absents de minimal » ;
et les paquets sans entrée de menu (core, aggregator, ndpid-engine, ipv6guard, autoload-agent, courbes) tombaient dans l'espace « autres »."""
import importlib.util
import json
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gen2875", PKG / "scripts" / "gen-profils-contenu.py")
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


def paquet(racine, nom, depends, version="1.0", recommends=(), conflicts=()):
    d = racine / nom / "debian"
    d.mkdir(parents=True, exist_ok=True)
    corps = ",\n".join(f" {x}" for x in depends)
    rec = f"Recommends: {', '.join(recommends)}\n" if recommends else ""
    con = f"Conflicts: {', '.join(conflicts)}\n" if conflicts else ""
    (d / "control").write_text(f"Source: {nom}\n\nPackage: {nom}\nArchitecture: all\nDepends: ${{misc:Depends}},\n{corps}\n{rec}{con}Description: x\n")
    (d / "changelog").write_text(f"{nom} ({version}-1~bookworm1) bookworm; urgency=medium\n\n  * x\n\n -- A <a@b.c>  Mon, 12 Oct 2026 10:00:00 +0200\n")


@pytest.fixture()
def arbre(tmp_path):
    p = tmp_path / "packages"
    paquet(p, "secubox-minimal", ["secubox-core", "secubox-autoload-agent"], conflicts=["secubox-webos"])
    paquet(p, "secubox-lite", ["secubox-core", "secubox-autoload-agent", "secubox-waf-ng"])
    paquet(p, "secubox-isp", ["secubox-lite (>= 1.0)"])
    paquet(p, "secubox-full", ["secubox-isp (>= 1.0)"])
    paquet(p, "secubox-autoload-agent", ["secubox-premier-pas"])
    paquet(p, "secubox-premier-pas", ["python3"], recommends=["secubox-p2p", "secubox-webos"])      # p2p par Recommends, comme dans le depot reel
    paquet(p, "secubox-p2p", ["secubox-premier-pas"])            # cycle entre deux modules : toléré
    esp = tmp_path / "espaces.json"
    esp.write_text(json.dumps({"espaces": [], "modules": {"waf": {"espace": "protection"}}}))
    return p, esp


def _mini(d):
    return next(x for x in d["profils"] if x["id"] == "minimal")


def test_les_modules_sont_la_fermeture_transitive_des_dependances(arbre):
    p, esp = arbre
    m = _mini(gen.construire(p, esp))
    assert {x["paquet"] for x in m["modules"]} == {"secubox-core", "secubox-autoload-agent", "secubox-premier-pas", "secubox-p2p"}
    assert {x["paquet"] for x in m["directs"]} == {"secubox-core", "secubox-autoload-agent"}      # « directs » reste ce que le méta-paquet nomme
    assert m["total"] == 4


def test_ce_que_minimal_installe_par_dependance_n_est_pas_absent(arbre):
    p, esp = arbre
    absents = {x["paquet"] for x in gen.construire(p, esp)["absents_de_minimal"]}
    assert "secubox-premier-pas" not in absents and "secubox-p2p" not in absents and "secubox-waf-ng" in absents


def test_ce_que_le_metapaquet_declare_en_conflicts_n_est_pas_dans_le_contenu(arbre):
    """premier-pas RECOMMANDE secubox-webos, mais minimal le met en Conflicts : apt ne l'installe pas, donc la page non plus."""
    p, esp = arbre
    d = gen.construire(p, esp)
    assert "secubox-webos" not in {x["paquet"] for x in _mini(d)["modules"]}


def test_un_cycle_entre_modules_ne_boucle_pas(arbre):
    p, esp = arbre
    assert gen.construire(p, esp)["profils"]          # (la fixture contient premier-pas <-> p2p)


@pytest.mark.parametrize("paq,espace", [("secubox-core", "systeme"), ("secubox-aggregator", "systeme"), ("secubox-autoload-agent", "systeme"),
                                        ("secubox-ndpid-engine", "surveillance"), ("secubox-courbes", "surveillance"), ("secubox-ipv6guard", "protection")])
def test_les_paquets_sans_menu_ont_un_espace_par_defaut(paq, espace):
    assert gen._espace(paq, {}) == espace


def test_la_table_du_hub_l_emporte_sur_le_defaut():
    assert gen._espace("secubox-core", {"core": {"espace": "protection"}}) == "protection"


def test_sur_le_vrai_depot_minimal_contient_premier_pas_annuaire_p2p_et_aucun_autres():
    depot = PKG.parent
    d = gen.construire(depot, depot / "secubox-hub" / "espaces.json")
    m = _mini(d)
    noms = {x["paquet"] for x in m["modules"]}
    assert {"secubox-premier-pas", "secubox-annuaire", "secubox-p2p"} <= noms      # premier-pas par autoload-agent, annuaire par auth et p2p par premier-pas (Recommends)
    assert not noms & {x["paquet"] for x in d["absents_de_minimal"]}
    assert [x["paquet"] for x in m["modules"] if x["espace"] == "autres"] == [], [x for x in m["modules"] if x["espace"] == "autres"]
