# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#4050 — ressources par appli lues dans le cgroup de leur unité."""
import json
from pathlib import Path

from api import ressources as R

PKG = Path(__file__).resolve().parents[2]


def _unite(racine: Path, nom: str, usec: int, mem: int) -> None:
    d = racine / "system.slice" / "system-streamlit\\x2dapp.slice" / f"streamlit-app@{nom}.service"
    d.mkdir(parents=True, exist_ok=True)
    (d / "cpu.stat").write_text(f"usage_usec {usec}\nuser_usec 1\nsystem_usec 1\n")
    (d / "memory.current").write_text(f"{mem}\n")


def _racine(tmp_path: Path, conteneur_usec: int = 0) -> Path:
    r = tmp_path / "lxc.payload.streamlit"
    r.mkdir(parents=True, exist_ok=True)
    (r / "cpu.stat").write_text(f"usage_usec {conteneur_usec}\n")
    (r / "memory.current").write_text("1000\n")
    return r


def test_cpu_depuis_deux_releves():
    # 2 s de CPU en 10 s sur 4 cœurs = 5 % de la box
    assert R.cpu_pourcent(1_000_000, 3_000_000, 10.0, 4) == 5.0
    assert R.cpu_pourcent(None, 3_000_000, 10.0, 4) is None       # premier relevé
    assert R.cpu_pourcent(5_000_000, 1_000_000, 10.0, 4) is None  # unité redémarrée
    assert R.cpu_pourcent(0, 1, 0, 4) is None


def test_releve_lit_les_unites_et_desechappe(tmp_path):
    r = _racine(tmp_path)
    _unite(r, "files_51", 10, 2048)
    _unite(r, "mon\\x2dappli", 20, 4096)
    rel = R.relever(r, maintenant=100.0)
    assert rel["complet"] is True
    assert set(rel["applis"]) == {"files_51", "mon-appli"}
    assert rel["applis"]["files_51"]["memoire"] == 2048


def test_collecteur_deux_passes_et_histo(tmp_path):
    r = _racine(tmp_path)
    c = R.Collecteur(cache=tmp_path / "c" / "ressources.json", coeurs=4)
    _unite(r, "files_51", 0, 100)
    m1 = c.passe(r, maintenant=100.0)
    assert m1["applis"]["files_51"]["cpu_pct"] is None
    _unite(r, "files_51", 4_000_000, 100)   # 4 s CPU en 10 s / 4 cœurs = 10 %
    m2 = c.passe(r, maintenant=110.0)
    assert m2["applis"]["files_51"]["cpu_pct"] == 10.0
    assert m2["applis"]["files_51"]["histo_cpu"] == [10.0]
    assert json.loads((tmp_path / "c" / "ressources.json").read_text())["ts"] == 110.0


def test_double_tampon_passe_degradee_ne_remplace_pas(tmp_path):
    r = _racine(tmp_path)
    cache = tmp_path / "ressources.json"
    c = R.Collecteur(cache=cache, coeurs=4)
    _unite(r, "files_51", 0, 100)
    c.passe(r, maintenant=100.0)
    avant = cache.read_text()
    assert c.passe(tmp_path / "absent", maintenant=110.0) is None
    assert cache.read_text() == avant            # jamais de page vide
    assert c.dernier_complet["ts"] == 100.0
    assert R.lire_cache(cache)["ts"] == 100.0


def test_vue_eveillees_en_haut_endormies_a_zero():
    mesures = {"ts": 200.0, "coeurs": 4, "intervalle_s": 10,
               "applis": {"lent": {"cpu_pct": 2.0, "memoire": 10, "debut": 100.0, "histo_cpu": [2.0]},
                          "gourmand": {"cpu_pct": 30.0, "memoire": 50, "debut": 150.0, "histo_cpu": [30.0]}},
               "conteneur": {"cpu_pct": 33.0, "memoire": 99, "histo_cpu": [33.0]}}
    inv = [{"name": "aaa_dort", "state": "sleeping", "last_active": 50},
           {"name": "zzz_arch", "state": "archived"},
           {"name": "lent", "state": "sleeping"},          # inventaire en retard : le cgroup fait foi
           {"name": "gourmand", "state": "running"}]
    v = R.construire_vue(mesures, inv, maintenant=210.0)
    noms = [a["name"] for a in v["applis"]]
    assert noms == ["gourmand", "lent", "aaa_dort", "zzz_arch"]
    dort = v["applis"][2]
    assert dort["eveillee"] is False and dort["cpu_pct"] == 0.0 and dort["memoire"] == 0
    assert dort["histo_cpu"] == [] and dort["dernier_acces"] == 50
    assert v["applis"][0]["age_s"] == 60
    assert v["total"]["eveillees"] == 2 and v["total"]["cpu_pct"] == 32.0 and v["total"]["memoire"] == 60


def test_route_gardee_en_lecture():
    src = (PKG / "api" / "main.py").read_text()
    assert '@router.get("/apps/ressources", dependencies=[Depends(require_lecture)])' in src


def test_minuterie_audit_espacee_et_basse_priorite():
    t = (PKG / "debian" / "streamlit-audit.timer").read_text()
    s = (PKG / "debian" / "streamlit-audit.service").read_text()
    assert "OnUnitActiveSec=30min" in t
    assert "Nice=15" in s and "IOSchedulingClass=idle" in s


def test_panneau_estompe_et_demo():
    h = (PKG / "www" / "streamlit" / "index.html").read_text()
    assert ".cl.dort{opacity:" in h
    assert "'/apps/ressources'" in h            # données de démonstration
