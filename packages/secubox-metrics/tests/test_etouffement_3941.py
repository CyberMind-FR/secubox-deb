# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Conteneur ou service « étouffé » par sa limite mémoire (#3941) : relectures de pages, pression, part de la limite.

gk2, gitea : 13 700 relectures/s à 100 % de son frein, jamais tué, rien ne le signalait."""
import json
from pathlib import Path

import memoire
import pytest

MO = 1 << 20


class Cg:
    def __init__(self, racine: Path):
        self.racine = racine
        (racine / "system.slice").mkdir(parents=True)

    def pose(self, chemin, refaults=0, courant=383 * MO, dur=384 * MO, haut="max", psi=0.0):
        d = self.racine / chemin
        d.mkdir(parents=True, exist_ok=True)
        (d / "memory.current").write_text(f"{courant}\n")
        (d / "memory.max").write_text(f"{dur}\n")
        (d / "memory.high").write_text(f"{haut}\n")
        (d / "memory.stat").write_text(f"anon 1\nworkingset_refault_anon {refaults // 2}\n"
                                       f"workingset_refault_file {refaults - refaults // 2}\n")
        (d / "memory.pressure").write_text(f"some avg10=0.00 avg60={psi:.2f} avg300=0.00 total=1\n"
                                           "full avg10=0.00 avg60=0.00 avg300=0.00 total=1\n")


@pytest.fixture
def cg(tmp_path):
    return Cg(tmp_path / "cg")


def passe(cg, etat, t):
    return memoire.etouffement(cg.racine, etat, maintenant=t)


def test_gitea_etouffe_relectures_et_limite_atteinte(cg):
    cg.pose("lxc.payload.gitea", 1_000_000, 383 * MO, 512 * MO, 384 * MO)
    e1 = passe(cg, {}, 1000)
    assert e1["etouffes"] == [], "aucun débit au premier relevé"
    cg.pose("lxc.payload.gitea", 1_000_000 + 13_700 * 300, 383 * MO, 512 * MO, 384 * MO)
    e = passe(cg, e1, 1300)["etouffes"][0]
    assert e["nom"] == "gitea" and e["genre"] == "conteneur" and e["refaults_s"] == 13700
    assert e["limite_mb"] == 384 and e["part"] == 99 and e["depuis_s"] == 0


@pytest.mark.parametrize("refaults_s,courant,psi,attendu", [
    (2000, 383, 0, True), (2000, 300, 0, False), (900, 383, 0, False), (0, 383, 21, True), (0, 383, 20, False),
    (0, 100, 60, False)])
def test_regle(cg, refaults_s, courant, psi, attendu):
    cg.pose("lxc.payload.x", 0, courant * MO, 384 * MO)
    e1 = passe(cg, {}, 0 + 1000)
    cg.pose("lxc.payload.x", refaults_s * 300, courant * MO, 384 * MO, psi=psi)
    assert bool(passe(cg, e1, 1300)["etouffes"]) is attendu


def test_compteur_remis_a_zero_ou_releve_trop_vieux_pas_de_debit(cg):
    cg.pose("lxc.payload.x", 9_000_000, 383 * MO, 384 * MO)
    e1 = passe(cg, {}, 1000)
    cg.pose("lxc.payload.x", 10, 383 * MO, 384 * MO)
    assert passe(cg, e1, 1300)["etouffes"] == []
    cg.pose("lxc.payload.x", 90_000_000, 383 * MO, 384 * MO)
    assert passe(cg, e1, 1000 + 7200)["etouffes"] == []


def test_duree_puis_fin(cg):
    cg.pose("lxc.payload.x", psi=50)
    e = {}
    for t in (1000, 1300, 1600):
        e = passe(cg, e, t)
    assert e["etouffes"][0]["depuis_s"] == 600
    cg.pose("lxc.payload.x", psi=1)
    assert passe(cg, e, 1900)["etouffes"] == []


def test_services_bornes_seulement(cg):
    cg.pose("system.slice/secubox-aggregator.service", 0, 760 * MO, 1024 * MO, 768 * MO)
    cg.pose("system.slice/libre.service", 0, dur="max", psi=80)
    e1 = passe(cg, {}, 1000)
    cg.pose("system.slice/secubox-aggregator.service", 5000 * 300, 760 * MO, 1024 * MO, 768 * MO)
    e = passe(cg, e1, 1300)
    assert [(x["nom"], x["genre"]) for x in e["etouffes"]] == [("secubox-aggregator.service", "service")]
    assert "system.slice/libre.service" not in e["refaults"], "un service sans limite n'est pas lu en détail"


def test_cgroups_absents_ou_sans_psi(cg, tmp_path):
    assert memoire.etouffement(tmp_path / "absent", {}, 1000)["etouffes"] == []
    cg.pose("lxc.payload.x", 0, 383 * MO, 384 * MO)
    (cg.racine / "lxc.payload.x" / "memory.pressure").unlink()
    (cg.racine / "lxc.payload.x" / "memory.stat").write_text("n'importe quoi\n")
    assert passe(cg, {}, 1000)["etouffes"] == []


def test_nombre_de_cgroups_borne(cg, monkeypatch):
    monkeypatch.setattr(memoire, "MAX_CGROUPS", 5)
    for i in range(20):
        cg.pose(f"lxc.payload.c{i:02}", psi=50)
    assert len(passe(cg, {}, 1000)["etouffes"]) == 5


def test_audit_une_seule_ligne_par_episode(cg, tmp_path):
    f, journal = tmp_path / "m" / "memoire.jsonl", tmp_path / "audit.log"
    journal.write_text("")
    cg.pose("lxc.payload.gitea", psi=50)
    for t in (1000, 1300, 1600, 1900, 2200):
        memoire.suivre_etouffement(f, cg.racine, t, journal)
    cg.pose("lxc.payload.gitea", psi=0)
    memoire.suivre_etouffement(f, cg.racine, 2500, journal)
    lignes = [json.loads(x) for x in journal.read_text().splitlines()]
    assert [x["evenement"] for x in lignes] == ["etouffement", "fin_etouffement"]
    assert lignes[0]["nom"] == "gitea" and lignes[0]["depuis_s"] >= 600 and lignes[0]["type"] == "memoire"


def test_audit_absent_ne_casse_pas_le_releve(cg, tmp_path, capsys):
    cg.pose("lxc.payload.gitea", psi=50)
    for t in (1000, 1300, 1600):
        memoire.suivre_etouffement(tmp_path / "memoire.jsonl", cg.racine, t, tmp_path / "non" / "audit.log")
    assert "audit" in capsys.readouterr().err


def test_pression_generale_sans_limite_propre_rien(cg):
    """I2 : la box entière sous pression ne désigne pas 120 services ; un étouffé a sa propre limite, atteinte."""
    for i in range(120):
        cg.pose(f"system.slice/s{i:03}.service", dur="max", psi=70)
    cg.pose("lxc.payload.sans", dur="max", psi=70)
    cg.pose("lxc.payload.loin", courant=100 * MO, psi=70)
    assert passe(cg, {}, 1000)["etouffes"] == []


def test_lignes_d_audit_bornees(cg, tmp_path):
    f, journal = tmp_path / "memoire.jsonl", tmp_path / "audit.log"
    journal.write_text("")
    for i in range(25):
        cg.pose(f"lxc.payload.c{i:02}", psi=50)
    for t in (1000, 1300, 1600, 1900):
        memoire.suivre_etouffement(f, cg.racine, t, journal)
    lignes = [json.loads(x) for x in journal.read_text().splitlines()]
    assert len(lignes) == 11 and lignes[-1]["nombre"] == 15 and "et 15 autres" in lignes[-1]["message"]
    for i in range(25):
        cg.pose(f"lxc.payload.c{i:02}", psi=0)
    memoire.suivre_etouffement(f, cg.racine, 2200, journal)
    fins = [json.loads(x) for x in journal.read_text().splitlines()][11:]
    assert len(fins) == 11 and fins[-1]["nombre"] == 15


def test_etat_casse_ignore(cg, tmp_path):
    (tmp_path / memoire.ETAT_ETOUFFEMENT).write_text('{"refaults": 3, "depuis": []}')
    cg.pose("lxc.payload.x", psi=50)
    assert memoire.suivre_etouffement(tmp_path / "memoire.jsonl", cg.racine, 1000, tmp_path / "a")["etouffes"]


def test_vue_api_et_alerte_apres_dix_minutes(cg, tmp_path):
    f = tmp_path / "memoire.jsonl"
    cg.pose("lxc.payload.gitea", psi=50, courant=383 * MO, dur=384 * MO)
    for t in (1000, 1300):
        memoire.suivre_etouffement(f, cg.racine, t, tmp_path / "a")
    v = memoire.vue(1, f, maintenant=1301)
    assert [x["nom"] for x in v["etouffes"]] == ["gitea"] and v["alertes"] == []
    memoire.suivre_etouffement(f, cg.racine, 1600, tmp_path / "a")
    assert any("gitea" in a and "étouffé" in a for a in memoire.vue(1, f, maintenant=1601)["alertes"])
    assert memoire.vue(1, f, maintenant=1601 + 3600)["etouffes"] == [], "un relevé périmé n'est pas servi"


def test_tache_planifiee_et_unite(cg, tmp_path, capsys):
    (tmp_path / "meminfo").write_text("MemTotal: 8113216 kB\nMemAvailable: 4000000 kB\n")
    (tmp_path / "loadavg").write_text("1 1 1 1/1 1\n")
    assert memoire.main(["--meminfo", str(tmp_path / "meminfo"), "--loadavg", str(tmp_path / "loadavg"),
                         "--fichier", str(tmp_path / "memoire.jsonl"), "--cgroups", str(cg.racine)]) == 0
    assert (tmp_path / memoire.ETAT_ETOUFFEMENT).exists()
    pkg = Path(__file__).resolve().parents[1]
    unite = (pkg / "systemd" / "secubox-metrics-memoire.service").read_text()
    assert "ReadWritePaths=-/var/log/secubox/audit.log" in unite and "User=secubox" in unite
    assert "memoire.etouffes_durables()" in (pkg / "api" / "main.py").read_text()
    code = (pkg / "api" / "memoire.py").read_text()
    assert "subprocess" not in code and "/proc/[" not in code
