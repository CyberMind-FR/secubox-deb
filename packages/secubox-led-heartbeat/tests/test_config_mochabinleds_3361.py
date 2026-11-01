# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Configuration livrée des 8 séquences mochabinleds (ref #3361) : leds.toml, planchers
lus par le collecteur, version 2.4.0. Sans matériel."""
import logging
import re
import sys
import tomllib
from pathlib import Path

import flux

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / "usr" / "lib" / "secubox-led-heartbeat"))
import ledcouches as lc  # noqa: E402

LEDS_TOML = PKG / "etc" / "secubox" / "leds.toml"
NOMS = ["systeme", "reseau", "firewall", "waf", "actor", "adguard", "services", "soc"]
CLES = {
    "reseau": ["reseau.octets_in", "reseau.octets_out", "reseau.connexions"],
    "firewall": ["fw.paquets_in", "fw.paquets_out", "fw.bloques"],
    "waf": ["waf.requetes", "waf.blocages", "waf.attaques"],
    "actor": ["actor.evenements", "actor.suspects", "actor.critiques"],
    "adguard": ["adguard.requetes", "adguard.trackers", "adguard.appareils"],
    "services": ["services.actifs", "services.degrades", "services.arretes"],
}
PALETTE5 = ["vert", "cyan", "jaune", "orange", "rouge"]


def test_toml_livre_charge_sans_avertissement(caplog):
    caplog.set_level(logging.WARNING)
    cfg = lc.charger_config(LEDS_TOML)
    assert [c.nom for c in cfg.couches] == NOMS
    assert not [r for r in caplog.records if r.name == "secubox-led"]


def test_couches_ordre_forme_duree_palette():
    cfg = lc.charger_config(LEDS_TOML)
    assert cfg.couches[0].sources == ["cpu", "memoire", "es"]
    for c in cfg.couches:
        assert c.duree == 8
    for c in cfg.couches[1:]:
        assert c.palette == PALETTE5
        assert "violet" not in c.palette
        assert c.rythme == "respiration"
    for c in cfg.couches[1:7]:
        assert c.forme == "par_led"
    assert cfg.couches[7].forme == "triple"
    assert cfg.couches[7].sources == ["alertes"]
    assert cfg.sources["alertes"].__class__ is lc.SourceAlertes


def test_sources_flux_referencent_les_cles_du_collecteur():
    cfg = lc.charger_config(LEDS_TOML)
    for couche, cles in CLES.items():
        c = next(x for x in cfg.couches if x.nom == couche)
        assert len(c.sources) == 3
        assert [cfg.sources[s].cle for s in c.sources] == cles
        for s in c.sources:
            assert isinstance(cfg.sources[s], lc.SourceFlux)


def test_cles_flux_connues_du_collecteur_dans_le_source():
    d = PKG / "usr" / "lib" / "secubox-led-heartbeat"
    src = (d / "releves.py").read_text() + (d / "flux.py").read_text()
    for cles in CLES.values():
        for k in cles:
            assert f'"{k}"' in src, k


def test_palette_couleurs_livree():
    brut = tomllib.loads(LEDS_TOML.read_text())
    assert brut["couleurs"]["cyan"] == [0, 220, 255]
    assert brut["couleurs"]["jaune"] == [255, 200, 0]
    assert brut["couleurs"]["orange"] == [255, 80, 0]
    cfg = lc.charger_config(LEDS_TOML)
    for nom in PALETTE5:
        assert nom in cfg.palette


def test_planchers_livres_egaux_aux_defauts():
    brut = tomllib.loads(LEDS_TOML.read_text())
    assert brut["flux"]["planchers"] == flux.PLANCHERS_DEFAUT
    assert flux.lire_planchers(LEDS_TOML) == flux.PLANCHERS_DEFAUT


def test_planchers_lecture_tolerante(tmp_path, capsys):
    p = tmp_path / "leds.toml"
    p.write_text('[flux.planchers]\n"fw.bloques" = 12\n"waf.blocages" = "beaucoup"\n'
                 '"reseau.octets_in" = 0\n"reseau.octets_out" = -3\n"fw.paquets_in" = true\n'
                 '"fw.paquets_out" = 2.5\n"adguard.requetes" = inf\n')
    r = flux.lire_planchers(p)
    assert r["fw.bloques"] == 12.0
    assert r["fw.paquets_out"] == 2.5
    for cle in ("waf.blocages", "reseau.octets_in", "reseau.octets_out", "fw.paquets_in",
                "adguard.requetes"):
        assert r[cle] == flux.PLANCHERS_DEFAUT[cle]
    err = capsys.readouterr().err
    for cle in ("waf.blocages", "reseau.octets_in", "reseau.octets_out", "fw.paquets_in",
                "adguard.requetes"):
        assert cle in err


def test_planchers_fichier_absent_ou_illisible(tmp_path, capsys):
    assert flux.lire_planchers(tmp_path / "absent.toml") == flux.PLANCHERS_DEFAUT
    p = tmp_path / "x.toml"
    p.write_text("pas = du toml [")
    assert flux.lire_planchers(p) == flux.PLANCHERS_DEFAUT
    assert "secubox-led-flux" in capsys.readouterr().err
    p.write_text("[flux]\nplanchers = 3\n")
    assert flux.lire_planchers(p) == flux.PLANCHERS_DEFAUT


def test_planchers_nouvelle_cle_acceptee(tmp_path):
    p = tmp_path / "leds.toml"
    p.write_text('[flux.planchers]\n"waf.requetes" = 7\n')
    r = flux.lire_planchers(p)
    assert r["waf.requetes"] == 7.0
    assert flux.plancher(r, "waf.requetes") == 7.0


def test_collecteur_demarre_avec_les_planchers_lus(tmp_path):
    p = tmp_path / "leds.toml"
    p.write_text('[flux.planchers]\n"fw.bloques" = 99\n')
    c = flux.Collecteur(chemin_flux=tmp_path / "f.json", chemin_ref=tmp_path / "r.json",
                        chemin_config=p)
    c.demarrer(1793509200.0)
    assert c.planchers["fw.bloques"] == 99.0


def test_version_et_paquet():
    premiere = (PKG / "debian" / "changelog").read_text().splitlines()[0]
    assert premiere.startswith("secubox-led-heartbeat (2.4.1-1~trixie1) trixie;")
    corps = (PKG / "debian" / "changelog").read_text().split("\n\n -- ")[0]
    for mot in ("collecteur", "relatifs", "critique", "adaptative", "priorité", "8 séquences",
                "#3361"):
        assert mot.lower() in corps.lower(), mot
    ctl = (PKG / "debian" / "control").read_text()
    deps = re.search(r"Depends:(.*?)\nBreaks", ctl, re.S).group(1)
    assert "nftables" in deps and "python3" in deps
    assert "2.4.1-1~trixie1" in (PKG / "README.md").read_text()
