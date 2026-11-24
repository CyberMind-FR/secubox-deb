# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3907 — entrées/sorties : débits par disque, pression, swap, services qui écrivent le plus."""
import importlib.util
from pathlib import Path

# Chargé par son chemin : importer le paquet « api » ici masquerait celui d'autres composants (ksm) pour la suite.
_spec = importlib.util.spec_from_file_location("system_es_3907", Path(__file__).resolve().parents[1] / "api" / "es.py")
es = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(es)

DISK1 = """ 179       0 mmcblk0 100 0 2000 50 200 0 4000 80 0 1000 130 0 0 0 0 0 0
 179       2 mmcblk0p2 90 0 1800 40 190 0 3900 70 0 900 110 0 0 0 0 0 0
   8       0 sda 1000 0 20000 500 3000 0 60000 900 0 5000 1400 0 0 0 0 0 0
   7       0 loop0 5 0 10 1 0 0 0 0 0 1 1 0 0 0 0 0 0
 253       0 zram0 50 0 400 0 70 0 560 0 0 0 0 0 0 0 0 0 0
"""
DISK2 = DISK1.replace("sda 1000 0 20000 500 3000 0 60000 900 0 5000",
                      "sda 1100 0 22048 500 3200 0 80480 900 0 6000")
PSI_CPU = "some avg10=75.94 avg60=77.10 avg300=75.60 total=1\n"
PSI_IO = "some avg10=5.31 avg60=11.61 avg300=14.28 total=1\nfull avg10=0.43 avg60=0.29 avg300=0.21 total=1\n"


def arbre(tmp: Path, disk: str, swap=(100, 200), ecrit=None) -> Path:
    (tmp / "proc" / "pressure").mkdir(parents=True, exist_ok=True)
    (tmp / "proc" / "diskstats").write_text(disk)
    (tmp / "proc" / "pressure" / "cpu").write_text(PSI_CPU)
    (tmp / "proc" / "pressure" / "memory").write_text(PSI_IO)
    (tmp / "proc" / "pressure" / "io").write_text(PSI_IO)
    (tmp / "proc" / "vmstat").write_text(f"nr_free_pages 1\npswpin {swap[0]}\npswpout {swap[1]}\n")
    cg = tmp / "cg"
    for unite, w in (ecrit or {}).items():
        d = cg / unite
        d.mkdir(parents=True, exist_ok=True)
        (d / "io.stat").write_text(f"8:0 rbytes=10 wbytes={w} rios=1 wios=1 dbytes=0 dios=0\n"
                                   f"179:0 rbytes=0 wbytes={w} rios=0 wios=1 dbytes=0 dios=0\n")
    cg.mkdir(exist_ok=True)
    return tmp


def test_disques_physiques_seuls():
    d = es.lire_disques(DISK1)
    assert set(d) == {"mmcblk0", "sda"}


def test_premier_releve_sans_debit(tmp_path):
    m = es.Mesure(racine_proc=arbre(tmp_path, DISK1) / "proc", racine_cg=tmp_path / "cg")
    r = m.releve(maintenant=1000.0)
    assert r["intervalle_s"] is None
    assert r["disques"][0]["ecriture_o_s"] is None
    assert r["pression"]["cpu"]["some"] == 75.94 and r["pression"]["io"]["full"] == 0.43
    assert r["pression"]["cpu"]["full"] is None


def test_debits_entre_deux_releves(tmp_path):
    racine = arbre(tmp_path, DISK1, ecrit={"system.slice/sbxdpi.service": 0, "system.slice/unbound.service": 0})
    m = es.Mesure(racine_proc=racine / "proc", racine_cg=racine / "cg")
    m.releve(maintenant=1000.0)
    arbre(tmp_path, DISK2, swap=(110, 260),
          ecrit={"system.slice/sbxdpi.service": 10_000_000, "system.slice/unbound.service": 1000})
    r = m.releve(maintenant=1010.0)
    assert r["intervalle_s"] == 10.0
    sda = next(x for x in r["disques"] if x["nom"] == "sda")
    assert sda["lecture_o_s"] == 2048 * 512 / 10 and sda["ecriture_o_s"] == 20480 * 512 / 10
    assert sda["lectures_s"] == 10.0 and sda["ecritures_s"] == 20.0
    assert sda["occupe_pct"] == 10.0                       # 1000 ms occupés sur 10 s
    assert r["swap"] == {"entrees_s": 1.0, "sorties_s": 6.0}
    top = r["ecrivains"]
    assert top[0] == {"unite": "sbxdpi.service", "ecriture_o_s": 2_000_000.0}   # 2 disques × 10 Mo / 10 s
    assert [x["unite"] for x in top] == ["sbxdpi.service", "unbound.service"]


def test_ecrivains_bornes_et_sans_inactifs(tmp_path):
    ecrit = {f"system.slice/s{i}.service": 0 for i in range(8)}
    racine = arbre(tmp_path, DISK1, ecrit=ecrit)
    m = es.Mesure(racine_proc=racine / "proc", racine_cg=racine / "cg")
    m.releve(maintenant=1.0)
    arbre(tmp_path, DISK1, ecrit={k: (i + 1) * 100 if i else 0 for i, k in enumerate(ecrit)})
    r = m.releve(maintenant=11.0)
    assert len(r["ecrivains"]) == 5 and all(x["ecriture_o_s"] > 0 for x in r["ecrivains"])


def test_compteur_qui_recule_ignore(tmp_path):
    """Service redémarré : son compteur repart de zéro, jamais un débit négatif."""
    racine = arbre(tmp_path, DISK1, ecrit={"system.slice/x.service": 5000})
    m = es.Mesure(racine_proc=racine / "proc", racine_cg=racine / "cg")
    m.releve(maintenant=1.0)
    arbre(tmp_path, DISK1, ecrit={"system.slice/x.service": 10})
    assert m.releve(maintenant=11.0)["ecrivains"] == []


def test_sources_absentes_sans_planter(tmp_path):
    m = es.Mesure(racine_proc=tmp_path / "rien", racine_cg=tmp_path / "rien")
    r = m.releve(maintenant=1.0)
    assert r["disques"] == [] and r["pression"]["cpu"]["some"] is None and r["swap"] == {"entrees_s": None, "sorties_s": None}


def test_releves_rapproches_rendent_le_dernier(tmp_path):
    racine = arbre(tmp_path, DISK1)
    m = es.Mesure(racine_proc=racine / "proc", racine_cg=racine / "cg")
    m.releve(maintenant=100.0)
    a = m.releve(maintenant=110.0)
    assert m.releve(maintenant=110.5) is a                 # < 2 s : pas d'intervalle trop court


def test_route_io_protegee_et_relative():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    assert '@router.get("/io", dependencies=[Depends(require_lecture)])' in src
    assert "from .es import Mesure" in src


def test_page_panneau_es():
    src = (Path(__file__).resolve().parents[1] / "www" / "system" / "index.html").read_text(encoding="utf-8")
    for x in ("id=\"pEs\"", "lire('/io')", "id=\"esDisques\"", "id=\"esPres\"", "id=\"esSwap\"", "id=\"esEcr\"", "première mesure"):
        assert x in src, x
    assert "innerHTML" not in src
