# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteur mochabinleds (ref #3361) : source flux, niveau 4, rotation adaptative,
priorité alerte. Sans matériel."""
import json
import os
import pwd
import sys
import time
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / "usr" / "lib" / "secubox-led-heartbeat"))

import ledcouches as lc  # noqa: E402

MOI = pwd.getpwuid(os.getuid()).pw_name


def ecrire_flux(p, niveaux, apprentissage=(), genere_le=None):
    p.write_text(json.dumps({"genere_le": time.time() if genere_le is None else genere_le,
                             "niveaux": niveaux, "apprentissage": sorted(apprentissage)}))
    return p


def flux(p, cle, **kw):
    return lc.SourceFlux("s", {"type": "flux", "chemin": str(p), "cle": cle,
                               "proprietaires": [MOI], **kw})


def couche(nom, sources, duree=8, forme="par_led", rythme="fixe", palette=None):
    cfg = lc.charger_config(None)
    d = {"nom": nom, "sources": sources, "forme": forme, "rythme": rythme, "duree": duree}
    if palette:
        d["palette"] = palette
    return lc.Couche(d, cfg), cfg


# ---------- source flux ----------

def test_source_flux_lit_le_niveau(tmp_path):
    p = ecrire_flux(tmp_path / "flux.json",
                    {"waf.blocages": 3, "fw.bloques": 4, "waf.requetes": 7, "x": True,
                     "nul": None})
    assert flux(p, "waf.blocages").lire(0) == 3
    assert flux(p, "fw.bloques").lire(0) == 4
    assert flux(p, "absente").lire(0) is None
    assert flux(p, "waf.requetes").lire(0) is None        # hors 0..4
    assert flux(p, "x").lire(0) is None                   # booléen refusé
    assert flux(p, "nul").lire(0) is None


def test_source_flux_defauts_et_config(tmp_path):
    s = lc.SourceFlux("s", {"type": "flux", "cle": "waf.attaques"})
    assert str(s.chemin) == "/run/secubox-leds/flux.json"
    assert s.proprietaires == ["secubox-leds"]
    assert s.fraicheur_max == 60
    t = tmp_path / "leds.toml"
    t.write_text('[sources.waf]\ntype = "flux"\ncle = "waf.blocages"\n'
                 '[[couche]]\nnom = "waf"\nsources = ["waf"]\n')
    cfg = lc.charger_config(t)
    assert isinstance(cfg.sources["waf"], lc.SourceFlux)


def test_flux_perime_inconnu(tmp_path):
    p = ecrire_flux(tmp_path / "flux.json", {"waf.blocages": 2}, genere_le=time.time() - 120)
    assert flux(p, "waf.blocages").lire(0) is None
    ecrire_flux(p, {"waf.blocages": 2})
    assert flux(p, "waf.blocages").lire(0) == 2


def test_mauvais_proprietaire_inconnu(tmp_path):
    p = ecrire_flux(tmp_path / "flux.json", {"waf.blocages": 2})
    s = lc.SourceFlux("s", {"type": "flux", "chemin": str(p), "cle": "waf.blocages",
                            "proprietaires": ["root"] if MOI != "root" else ["nobody"]})
    assert s.lire(0) is None


def test_lien_symbolique_refuse(tmp_path):
    p = ecrire_flux(tmp_path / "vrai.json", {"waf.blocages": 2})
    lien = tmp_path / "flux.json"
    lien.symlink_to(p)
    assert flux(lien, "waf.blocages").lire(0) is None


def test_apprentissage_violet_respiration(tmp_path):
    p = ecrire_flux(tmp_path / "flux.json", {"waf.blocages": 1, "services.arretes": 4},
                    apprentissage=["waf.blocages", "services.arretes"])
    n = flux(p, "waf.blocages").lire(0)
    assert n == lc.APPRENTI and n not in range(5) and not isinstance(n, int)
    assert flux(p, "services.arretes").lire(0) == 4     # critique absolu : prime
    c, cfg = couche("c", ["a"], rythme="fixe")
    violet = cfg.couleur("violet")
    teintes = {c.teinte(lc.APPRENTI, t / 10) for t in range(0, 80)}
    assert violet in teintes and len(teintes) > 1        # respiration, pas fixe
    assert all(x[1] == 0 for x in teintes)               # toujours violet (pas de vert)
    for forme in ("jauge", "etale", "rotatif", "mono", "double", "triple"):
        cf, _ = couche("f", ["a"], forme=forme)
        cf.image(1.0, [lc.APPRENTI])                     # ne plante pas


# ---------- niveau 4 ----------

def test_palette_4_completee_rouge():
    c, cfg = couche("c", ["a"], palette=["cyan", "bleu", "violet", "rose"])
    assert c.palette == ["cyan", "bleu", "violet", "rose", "rouge"]
    c5, _ = couche("c", ["a"], palette=["vert", "cyan", "jaune", "orange", "rouge"])
    assert c5.palette == ["vert", "cyan", "jaune", "orange", "rouge"]
    assert len(lc.PALETTE_NIVEAU) == 5 and lc.PALETTE_NIVEAU[4] == "rouge"
    assert "rouge" in cfg.palette and "violet" in cfg.palette
    assert c.teinte(4, 0.0) == cfg.couleur("rouge")
    assert c.teinte(3, 0.0) == cfg.couleur("rose")


def test_alerte_critique_niveau_4(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps([{"severity": "critical"}]))
    src = lc.SourceAlertes("alertes", {"chemin": str(p), "seuils": [1, 3, 10],
                                       "fraicheur_max": 0, "vivant": ""})
    assert src.lire(0) == 4


def test_jauge_et_rythmes_niveau_4():
    c, cfg = couche("j", ["a"], forme="jauge")
    assert all(x != lc.OFF for x in c.image(0.0, [4]))
    assert lc.multiplicateur("eclats", 0.0, 4, 3.0) == 1.0
    eclats = sum(1 for k in range(300)
                 if lc.multiplicateur("eclats", k / 100, 4, 3.0) == 1.0
                 and lc.multiplicateur("eclats", (k - 1) / 100, 4, 3.0) != 1.0)
    assert eclats == 4


# ---------- ordonnancement ----------

def _ordo(*couches_):
    cfg = lc.charger_config(None)
    return lc.Ordonnanceur(list(couches_), cfg), cfg


def test_duree_adaptative_plafonnee_24():
    a, _ = couche("a", ["sa"], duree=8)
    b, _ = couche("b", ["sb"], duree=8)
    o, cfg = _ordo(a, b)
    r = cfg.repere_duree
    assert o.duree_entree(0, {}) == r + 8
    assert o.duree_entree(0, {"sa": 1}) == r + 16
    assert o.duree_entree(0, {"sa": 3}) == r + 24              # 32 plafonné à 24
    assert o.duree_entree(0, {"sa": lc.APPRENTI}) == r + 8     # apprentissage : pas un niveau
    assert o.duree_entree(0, {"sa": 4}) == r + 8               # 4 : priorité, pas allongement
    # rotation réelle : avec « sa » à 1, la couche a reste affichée 16 s
    niv = {"sa": 1, "sb": 0}
    noms = []
    for k in range(0, 300):
        o.image(k / 10, niv)
        noms.append(o.position(k / 10, niv)[0])
    assert noms[int((r + 15) * 10)] == "a" and noms[int((r + 17) * 10)] == "b"


def test_duree_longue_configuree_inchangee():
    a, _ = couche("a", ["sa"], duree=60)
    o, cfg = _ordo(a)
    assert o.duree_entree(0, {}) == cfg.repere_duree + 60


def test_priorite_alerte_interrompt():
    a, _ = couche("a", ["sa"], duree=8)
    b, _ = couche("b", ["sb"], duree=8, rythme="fixe")
    o, cfg = _ordo(a, b)
    niv = {"sa": 0, "sb": 0}
    assert o.position(0.5 + cfg.repere_duree, niv)[0] == "a"
    niv = {"sa": 0, "sb": 4}
    vus = set()
    for k in range(0, 400):
        t = k / 10
        o.image(t, niv)
        vus.add(o.position(t, niv)[0])
    assert vus == {"b"}
    # rythme forcé à « eclats » : la LED 1 de b clignote en rouge
    rouge = cfg.couleur("rouge")
    imgs = [o.image(cfg.repere_duree + k / 100, niv)[0] for k in range(0, 300)]
    assert rouge in imgs and any(x != rouge for x in imgs)   # éclats, pas fixe
    # retour sous 4 : le cycle normal reprend
    niv = {"sa": 0, "sb": 0}
    vus = {o.position(k / 10, niv)[0] for k in range(0, 400)}
    assert vus == {"a", "b"}


def test_deux_alertes_alternent_30s():
    a, _ = couche("a", ["sa"], duree=8)
    b, _ = couche("b", ["sb"], duree=8)
    c, _ = couche("c", ["sc"], duree=8)
    o, cfg = _ordo(a, b, c)
    niv = {"sa": 4, "sb": 0, "sc": 4}
    derniere = {}
    ecart_max = {"a": 0.0, "c": 0.0}
    for k in range(0, 1200):
        t = k / 10
        o.image(t, niv)
        nom, _ = o.position(t, niv)
        assert nom in ("a", "c")
        if nom in derniere:
            ecart_max[nom] = max(ecart_max[nom], t - derniere[nom])
        derniere[nom] = t
    assert set(derniere) == {"a", "c"}
    assert all(e <= 30 for e in ecart_max.values())
    # beaucoup de couches en alerte : chacune revient quand même dans les 30 s
    many = [couche(f"m{i}", [f"s{i}"], duree=20)[0] for i in range(6)]
    o2, _ = _ordo(*many)
    niv = {f"s{i}": 4 for i in range(6)}
    derniere, ecart = {}, 0.0
    for k in range(0, 1800):
        t = k / 10
        nom, _ = o2.position(t, niv)
        if nom in derniere:
            ecart = max(ecart, t - derniere[nom])
        derniere[nom] = t
    assert len(derniere) == 6 and ecart <= 30


def test_couches_existantes_inchangees():
    cfg = lc.charger_config(None)
    o = lc.Ordonnanceur(cfg.couches, cfg)
    durees = [c.duree + cfg.repere_duree for c in cfg.couches]
    cycle = sum(durees)

    def sans_etat(t):                           # calcul d'avant #3361 : t % cycle
        x = t % cycle
        for c, d in zip(cfg.couches, durees):
            if x < d:
                return c.nom, x < cfg.repere_duree
            x -= d
    ecarts = [k for k in range(0, int(2 * cycle * 20))
              if o.position(k / 20, {}) != sans_etat(k / 20)]
    assert ecarts == []
    c, _ = couche("c", ["a", "b", "d"], palette=["vert", "jaune", "orange", "rouge"])
    assert c.image(0.0, [0, 2, 3]) == [cfg.couleur("vert"), cfg.couleur("orange"),
                                       cfg.couleur("rouge")]


# ---------- continuité du mode alerte ----------

def _trois():
    a, _ = couche("a", ["sa"], duree=8)
    b, _ = couche("b", ["sb"], duree=8)
    c, _ = couche("c", ["sc"], duree=8)
    return _ordo(a, b, c)


def test_entree_alerte_commence_au_repere():
    o, cfg = _trois()
    calme = {"sa": 0, "sb": 0, "sc": 0}
    for k in range(0, 50):
        o.image(k / 10, calme)                  # au milieu de « a »
    alerte = {"sa": 0, "sb": 0, "sc": 4}
    assert o.position(5.0, alerte) == ("c", True)
    assert o.position(5.0 + cfg.repere_duree + 0.1, alerte) == ("c", False)


def test_ensemble_change_termine_le_creneau():
    o, cfg = _trois()
    r = cfg.repere_duree
    deux = {"sa": 4, "sb": 0, "sc": 4}
    assert o.position(0.0, deux)[0] == "a"
    assert o.position(r + 3, deux) == ("a", False)
    trois = {"sa": 4, "sb": 4, "sc": 4}          # b rejoint : a finit son créneau
    assert o.position(r + 5, trois) == ("a", False)
    assert o.position(r + 8.1, trois) == ("b", True)   # puis b, dans l'ordre
    # b retirée en plein créneau : passage immédiat à la suivante, au repère
    sans_b = {"sa": 4, "sb": 0, "sc": 4}
    assert o.position(r + 8.5, sans_b) == ("c", True)
    assert o.position(r + 8.5 + r + 0.1, sans_b) == ("c", False)


def test_sortie_alerte_reprend_l_entree_au_debut():
    o, cfg = _trois()
    r = cfg.repere_duree
    calme = {"sa": 0, "sb": 0, "sc": 0}
    for k in range(0, int((r + 8 + 3) * 10)):
        o.image(k / 10, calme)                  # au milieu de « b »
    assert o.position(r + 8 + 3, calme)[0] == "b"
    o.position(20.0, {"sa": 0, "sb": 0, "sc": 4})
    o.position(25.0, {"sa": 0, "sb": 0, "sc": 4})
    assert o.position(26.0, calme) == ("b", True)        # « b » reprise à son début
    assert o.position(26.0 + r + 7.5, calme) == ("b", False)
    assert o.position(26.0 + r + 8.1, calme) == ("c", True)


def test_creneau_alerte_minimum():
    many = [couche(f"m{i}", [f"s{i}"], duree=8)[0] for i in range(20)]
    o, cfg = _ordo(*many)
    niv = {f"s{i}": 4 for i in range(20)}
    assert o.position(0.0, niv)[0] == "m0"
    assert o.position(cfg.repere_duree + 1.9, niv)[0] == "m0"
    assert o.position(cfg.repere_duree + 2.05, niv)[0] == "m1"
