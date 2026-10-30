# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteur d'affichage en couches des LED MOCHAbin (tranche 2, ref #3290).

Sans matériel : /proc factices, écrivain simulé, horloge injectée."""
import json
import logging
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / "usr" / "lib" / "secubox-led-heartbeat"))

import ledcouches as lc  # noqa: E402

LEDS_TOML = PKG / "etc" / "secubox" / "leds.toml"


# ---------- écrivain et horloge simulés ----------

class EcrivainSimule:
    def __init__(self, echecs=0):
        self.ecritures = []
        self.echecs = echecs

    def ecrire(self, canal, valeur):
        if self.echecs > 0:
            self.echecs -= 1
            raise OSError(5, "EIO")
        self.ecritures.append((canal, valeur))


class Horloge:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def proc_stat(tmp_path, user, idle, iowait, nom="stat"):
    p = tmp_path / nom
    p.write_text(f"cpu  {user} 0 0 {idle} {iowait} 0 0 0 0 0\ncpu0 1 0 0 1 0 0 0 0 0 0\n")
    return p


# ---------- niveaux depuis des /proc factices ----------

def test_niveau_par_seuils():
    assert lc.niveau(10, [50, 75, 90]) == 0
    assert lc.niveau(50, [50, 75, 90]) == 1
    assert lc.niveau(80, [50, 75, 90]) == 2
    assert lc.niveau(95, [50, 75, 90]) == 3


def test_source_cpu_delta(tmp_path):
    p = proc_stat(tmp_path, 0, 0, 0)
    src = lc.SourceCpu("cpu", {"chemin": str(p), "seuils": [50, 75, 90]})
    assert src.lire(0) is None                 # premier relevé : pas de delta
    proc_stat(tmp_path, 80, 20, 0)             # 80 % occupé
    assert src.lire(5) == 2
    proc_stat(tmp_path, 85, 115, 0)            # +5 occupé / +100 : 5 %
    assert src.lire(10) == 0


def test_source_es_iowait(tmp_path):
    p = proc_stat(tmp_path, 0, 0, 0)
    src = lc.SourceIowait("es", {"chemin": str(p), "seuils": [5, 15, 30]})
    src.lire(0)
    proc_stat(tmp_path, 10, 50, 40)            # iowait 40 %
    assert src.lire(5) == 3


def test_source_memoire(tmp_path):
    p = tmp_path / "meminfo"
    p.write_text("MemTotal: 1000 kB\nMemFree: 10 kB\nMemAvailable: 150 kB\n")
    src = lc.SourceMemoire("memoire", {"chemin": str(p), "seuils": [60, 80, 92]})
    assert src.lire(0) == 2                     # 85 % utilisés


def test_source_compteur_json_debit_par_minute(tmp_path):
    p = tmp_path / "metrics.json"
    p.write_text(json.dumps({"waf": {"waf_blocked": 100}}))
    src = lc.SourceCompteurJson("attaques", {"chemin": str(p), "cle": "waf.waf_blocked",
                                              "seuils": [1, 10, 60], "fraicheur_max": 0})
    assert src.lire(0) is None
    p.write_text(json.dumps({"waf": {"waf_blocked": 120}}))
    assert src.lire(60) == 2                    # 20 / min
    p.write_text(json.dumps({"waf": {"waf_blocked": 3}}))   # remise à zéro
    assert src.lire(120) == 0


def test_source_jauge_json(tmp_path):
    p = tmp_path / "metrics.json"
    p.write_text(json.dumps({"connections": {"https": 25}}))
    src = lc.SourceJaugeJson("visites", {"chemin": str(p), "cle": "connections.https",
                                          "seuils": [1, 20, 100], "fraicheur_max": 0})
    assert src.lire(0) == 2


def test_source_alertes(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps([{"severity": "medium"}, {"severity": "low", "acknowledged": True}]))
    src = lc.SourceAlertes("alertes", {"chemin": str(p), "seuils": [1, 3, 10], "fraicheur_max": 0,
                                       "vivant": ""})
    assert src.lire(0) == 1
    p.write_text(json.dumps([{"severity": "critical"}]))
    assert src.lire(1) == 3                     # critique non vue : niveau max
    p.write_text("[]")
    assert src.lire(2) == 0


@pytest.mark.parametrize("cls,opts", [
    (lc.SourceCpu, {}), (lc.SourceIowait, {}), (lc.SourceMemoire, {}),
    (lc.SourceCompteurJson, {"cle": "a"}), (lc.SourceJaugeJson, {"cle": "a"}),
    (lc.SourceAlertes, {}),
])
def test_source_absente_inconnu(tmp_path, cls, opts):
    src = cls("x", {"chemin": str(tmp_path / "absent"), "seuils": [1, 2, 3], **opts})
    assert src.lire(0) is None
    assert src.lire(10) is None


def test_source_json_perimee_inconnu(tmp_path):
    import os
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"a": 5}))
    os.utime(p, (1, 1))
    src = lc.SourceJaugeJson("v", {"chemin": str(p), "cle": "a", "seuils": [1, 2, 3],
                                    "fraicheur_max": 300})
    assert src.lire(0) is None


def test_inconnu_jamais_vert():
    cfg = lc.charger_config(None)
    c = lc.Couche({"nom": "t", "sources": ["a", "b", "c"], "forme": "par_led",
                   "palette": ["vert", "jaune", "orange", "rouge"], "rythme": "fixe"}, cfg)
    img = c.image(0.0, [None, None, None])
    for rgb in img:
        assert rgb == cfg.inconnu
        assert not (rgb[1] > 0 and rgb[0] == 0 and rgb[2] == 0)


# ---------- formes ----------

def couche(forme, nb_sources=1, **kw):
    cfg = lc.charger_config(None)
    d = {"nom": forme, "sources": ["s%d" % i for i in range(nb_sources)], "forme": forme,
         "palette": ["vert", "jaune", "orange", "rouge"], "rythme": "fixe", **kw}
    return lc.Couche(d, cfg), cfg


def allumees(img):
    return [i for i, rgb in enumerate(img) if any(rgb)]


def test_forme_par_led():
    c, cfg = couche("par_led", 3)
    img = c.image(0.0, [0, 2, 3])
    assert img[0] == cfg.couleur("vert")
    assert img[1] == cfg.couleur("orange")
    assert img[2] == cfg.couleur("rouge")


def test_forme_jauge():
    c, cfg = couche("jauge")
    assert allumees(c.image(0.0, [3])) == [0, 1, 2]
    assert allumees(c.image(0.0, [2])) == [0, 1]
    assert allumees(c.image(0.0, [1])) == [0]
    img0 = c.image(0.0, [0])                    # nominal : LED 1 faible, vivante
    assert allumees(img0) == [0] and max(img0[0]) < max(cfg.couleur("vert"))


@pytest.mark.parametrize("forme,attendu", [("mono", [0]), ("double", [0, 1]),
                                           ("triple", [0, 1, 2])])
def test_forme_mono_double_triple(forme, attendu):
    c, cfg = couche(forme)
    img = c.image(0.0, [2])
    assert allumees(img) == attendu
    assert all(img[i] == cfg.couleur("orange") for i in attendu)


def test_forme_etale_dephasage():
    c, _ = couche("etale", rythme="pulsation")
    images = [c.image(t / 10, [1]) for t in range(0, 30)]
    # les trois LEDs ne sont pas toutes identiques à chaque instant : séquence étalée
    assert any(len({img[0], img[1], img[2]}) > 1 for img in images)
    # chaque LED s'allume à un moment
    for i in range(3):
        assert any(any(img[i]) for img in images)


def test_forme_rotatif_une_led_qui_defile():
    c, _ = couche("rotatif")
    vues = set()
    for t in range(0, 60):
        img = c.image(t / 10, [2])
        assert len(allumees(img)) == 1
        vues.add(allumees(img)[0])
    assert vues == {0, 1, 2}


def test_rythme_respiration_basse_resolution():
    c, _ = couche("triple", rythme="respiration")
    valeurs = {c.image(t / 20, [0])[0] for t in range(0, 400)}
    assert 2 <= len(valeurs) <= 6               # quelques paliers seulement


def test_pulsation_proportionnelle_au_niveau():
    c, _ = couche("triple", rythme="pulsation")

    def transitions(niv):
        imgs = [c.image(t / 20, [niv])[0] for t in range(0, 240)]
        return sum(1 for a, b in zip(imgs, imgs[1:]) if a != b)
    assert transitions(3) > transitions(1) > 0


# ---------- rendu : écrire seulement sur changement, débit borné ----------

def test_ecrit_seulement_sur_changement():
    e, h = EcrivainSimule(), Horloge()
    r = lc.Rendu(e, debit_max=1000, horloge=h)
    img = [(10, 0, 0), (0, 10, 0), (0, 0, 10)]
    r.afficher(img)
    n = len(e.ecritures)
    assert n == 9
    for _ in range(5):
        h.t += 1
        r.afficher(img)
    assert len(e.ecritures) == n
    h.t += 1
    r.afficher([(11, 0, 0), (0, 10, 0), (0, 0, 10)])
    assert e.ecritures[-1] == ("red:led1", 11) and len(e.ecritures) == n + 1


def test_debit_borne():
    e, h = EcrivainSimule(), Horloge()
    r = lc.Rendu(e, debit_max=20, horloge=h)
    for k in range(100):                        # 10 s à 10 images/s, tout change
        v = 1 + (k % 2) * 100
        r.afficher([(v, v, v)] * 3)
        h.t += 0.1
    assert len(e.ecritures) <= 20 * 10 + 20     # seau initial compris


def test_debit_borne_rattrape_la_derniere_image():
    e, h = EcrivainSimule(), Horloge()
    r = lc.Rendu(e, debit_max=4, horloge=h)
    cible = [(1, 2, 3), (4, 5, 6), (7, 8, 9)]
    for _ in range(40):
        r.afficher(cible)
        h.t += 0.25
    assert r.etat == {f"{c}:led{i + 1}": cible[i][j]
                      for i in range(3) for j, c in enumerate(lc.COULEURS)}


def test_erreur_ecriture_reprise():
    e, h = EcrivainSimule(echecs=3), Horloge()
    appels = []
    r = lc.Rendu(e, debit_max=1000, horloge=h, seuil_reprise=3, reprise=lambda: appels.append(1))
    r.afficher([(1, 0, 0), (0, 0, 0), (0, 0, 0)])
    assert appels == [1]
    h.t += 1
    r.afficher([(1, 0, 0), (0, 0, 0), (0, 0, 0)])   # réécrit ce qui a échoué
    assert ("red:led1", 1) in e.ecritures


def test_extinction():
    e, h = EcrivainSimule(), Horloge()
    r = lc.Rendu(e, debit_max=1000, horloge=h)
    r.afficher([(9, 9, 9)] * 3)
    r.eteindre()
    assert all(v == 0 for v in r.etat.values())


# ---------- ordonnanceur : couches, repère, rotation ----------

def test_alternance_avec_repere():
    cfg = lc.charger_config(None)
    o = lc.Ordonnanceur(cfg.couches, cfg)
    noms = []
    t = 0.0
    while t < 2 * sum(c.duree + cfg.repere_duree for c in cfg.couches):
        nom, repere = o.position(t)
        if not noms or noms[-1] != (nom, repere):
            noms.append((nom, repere))
        t += 0.05
    assert ("systeme", True) in noms and ("systeme", False) in noms
    assert ("trafic", True) in noms and ("trafic", False) in noms
    assert noms.index(("systeme", True)) < noms.index(("systeme", False))


def test_repere_nombre_d_eclats_selon_rang():
    assert lc.eclats_repere(0) == 1 and lc.eclats_repere(1) == 2 and lc.eclats_repere(7) == 3


def test_rotation_plus_de_trois_couches_mono():
    cfg = lc.charger_config(None)
    monos = [lc.Couche({"nom": f"m{i}", "sources": ["s"], "forme": "mono",
                        "palette": ["vert", "jaune", "orange", "rouge"], "rythme": "fixe",
                        "duree": 2}, cfg) for i in range(5)]
    o = lc.Ordonnanceur(monos, cfg)
    vues, fenetres = set(), set()
    t = 0.0
    while t < 30:
        fen = o.fenetre_mono(t)
        assert 1 <= len(fen) <= 3
        fenetres.add(tuple(c.nom for c in fen))
        vues.update(c.nom for c in fen)
        t += 0.5
    assert vues == {f"m{i}" for i in range(5)}
    assert len(fenetres) == 5                   # la fenêtre glisse d'une couche à la fois


def test_image_rotation_mono_place_chaque_couche_sur_sa_led():
    cfg = lc.charger_config(None)
    monos = [lc.Couche({"nom": f"m{i}", "sources": [f"s{i}"], "forme": "mono",
                        "palette": ["vert", "jaune", "orange", "rouge"], "rythme": "fixe",
                        "duree": 2}, cfg) for i in range(4)]
    o = lc.Ordonnanceur(monos, cfg)
    niveaux = {"s0": 0, "s1": 1, "s2": 2, "s3": 3}
    img = o.image(cfg.repere_duree + 0.1, niveaux)
    assert img == [cfg.couleur("vert"), cfg.couleur("jaune"), cfg.couleur("orange")]


# ---------- configuration ----------

def test_toml_livre_valide_sans_avertissement(caplog):
    caplog.set_level(logging.WARNING)
    cfg = lc.charger_config(LEDS_TOML)
    assert [c.nom for c in cfg.couches] == ["systeme", "trafic"]
    assert cfg.couches[0].sources == ["cpu", "memoire", "es"]
    assert cfg.couches[1].sources == ["attaques", "visites", "alertes"]
    assert cfg.couches[0].rythme == "respiration"
    assert cfg.couches[1].rythme == "pulsation"
    assert cfg.debit_max == 20
    assert not [r for r in caplog.records if r.name == "secubox-led"]


def test_palette_validee():
    cfg = lc.charger_config(None)
    assert cfg.couleur("orange", 1.0) == (255, 80, 0)
    assert cfg.couleur("violet", 1.0) == (150, 0, 255)
    assert cfg.couleur("rose", 1.0) == (255, 20, 120)
    assert cfg.couleur("turquoise", 1.0) == (0, 255, 90)
    assert cfg.couleur("blanc_chaud", 1.0) == (255, 150, 60)


def test_toml_invalide_defauts_et_avertissement(tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    p = tmp_path / "leds.toml"
    p.write_text("""
[moteur]
debit_max = 5000
luminosite = "fort"
[sources.cpu]
type = "cpu"
seuils = [90, 50, 10]
[[couche]]
nom = "x"
sources = ["cpu", "inexistante"]
forme = "spirale"
rythme = "disco"
palette = ["vert", "fuchsia"]
duree = -3
""")
    cfg = lc.charger_config(p)
    assert cfg.debit_max == 20
    assert cfg.luminosite == lc.DEFAUT_LUMINOSITE
    assert cfg.sources["cpu"].seuils == lc.SOURCES_DEFAUT["cpu"]["seuils"]
    c = cfg.couches[0]
    assert c.forme == "par_led" and c.rythme == "fixe" and c.duree > 0
    assert "inexistante" in c.sources           # gardée : affichée « inconnu »
    assert len(caplog.records) >= 6


def test_toml_illisible_defauts(tmp_path, caplog):
    p = tmp_path / "leds.toml"
    p.write_text("[[[ pas du toml")
    cfg = lc.charger_config(p)
    assert [c.nom for c in cfg.couches] == ["systeme", "trafic"]


def test_toml_sans_couche_defauts(tmp_path):
    p = tmp_path / "leds.toml"
    p.write_text("[general]\nenabled = true\n")
    cfg = lc.charger_config(p)
    assert [c.nom for c in cfg.couches] == ["systeme", "trafic"]


# ---------- démo ----------

def test_demo_simulee_chaque_forme(capsys):
    for forme in lc.FORMES:
        assert lc.main(["demo", forme, "--simule", "--duree", "2"]) == 0
    out = capsys.readouterr().out
    assert "red:led1" in out


def test_demo_couche_simulee():
    assert lc.main(["demo", "trafic", "--simule", "--duree", "1"]) == 0
    assert lc.main(["demo", "inconnue", "--simule", "--duree", "1"]) == 2


# ---------- paquet ----------

def test_paquet_coherent():
    rules = (PKG / "debian" / "rules").read_text()
    assert "usr/lib/secubox-led-heartbeat/ledcouches.py" in rules
    unite = (PKG / "systemd" / "secubox-led-pulse.service").read_text()
    assert "ExecStart=/usr/sbin/secubox-led-pulse servir" in unite
    assert "Conflicts=secubox-healthbump.timer" in unite
    post = (PKG / "debian" / "postinst").read_text()
    assert "disable --now" in post and "secubox-healthbump.timer" in post
    reset = (PKG / "usr" / "sbin" / "secubox-led-reset").read_text()
    assert "systemctl start secubox-healthbump.timer" not in reset
    assert "2.3.2-1~trixie1" in (PKG / "debian" / "changelog").read_text().splitlines()[0]
