# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3914 : une décision qui tient plusieurs adresses d'une même MAC est levée en UN geste (un seul rendu Unbound)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from garde import base, effets, moteur  # noqa: E402
from tests.test_moteur_3794 import MAC, T, Effets  # noqa: E402

IPS = ["192.168.1.112", "2a01:e0a::1", "2a01:e0a::2"]
AUTRE = "aa:bb:cc:dd:ee:ff"


def _decision(db, did, mac, ips, etat="levee_en_cours", menace="evasion"):
    db.execute("INSERT INTO decisions(id, menace, cible, mac, ip, debut, fin, etat, leve_par) VALUES "
               "(?,?,?,?,?,?,?,?,'reevaluation')", (did, menace, mac, mac, ips[0], T - 90000, T - 3600, etat))
    db.executemany("INSERT INTO adresses(decision_id, ip, fin) VALUES (?,?,?)", [(did, ip, T - 3600) for ip in ips])
    db.commit()


def test_plusieurs_adresses_un_seul_geste_par_mac(tmp_path):
    db, ef = base.ouvrir(tmp_path / "g.db"), Effets()
    _decision(db, "A", MAC, IPS)
    assert moteur._lever_tout(db, ef, "A", "evasion", MAC, "m") is True
    assert ef.appels == [("lever_mac", "evasion", MAC)]
    assert not db.execute("SELECT 1 FROM adresses WHERE decision_id='A'").fetchone()


def test_une_seule_adresse_reste_par_ip(tmp_path):
    db, ef = base.ouvrir(tmp_path / "g.db"), Effets()
    _decision(db, "A", MAC, IPS[:1])
    assert moteur._lever_tout(db, ef, "A", "evasion", MAC, "m") is True
    assert ef.appels == [("rouvrir", IPS[0])]


def test_mac_tenue_par_une_autre_decision_active_leve_par_ip(tmp_path):
    db, ef = base.ouvrir(tmp_path / "g.db"), Effets()
    _decision(db, "A", MAC, IPS[:2])
    _decision(db, "B", MAC, ["2a01:e0a::9"], etat="active")
    assert moteur._lever_tout(db, ef, "A", "evasion", MAC, "m") is True
    assert ("lever_mac", "evasion", MAC) not in ef.appels      # B tient encore une entrée de cette MAC
    assert [a for a in ef.appels if a[0] == "rouvrir"] == [("rouvrir", ip) for ip in sorted(IPS[:2])]


def test_autre_menace_meme_mac_n_empeche_pas(tmp_path):
    db, ef = base.ouvrir(tmp_path / "g.db"), Effets()
    _decision(db, "A", MAC, IPS)
    _decision(db, "B", MAC, ["192.168.1.9"], etat="active", menace="infection")
    assert moteur._lever_tout(db, ef, "A", "evasion", MAC, "m") is True
    assert ef.appels == [("lever_mac", "evasion", MAC)]


def test_echec_par_mac_repli_par_ip(tmp_path):
    db, ef = base.ouvrir(tmp_path / "g.db"), Effets(echec={"lever_mac"})
    _decision(db, "A", MAC, IPS)
    assert moteur._lever_tout(db, ef, "A", "evasion", MAC, "m") is True
    assert ef.appels[0] == ("lever_mac", "evasion", MAC)
    assert sorted(a[1] for a in ef.appels[1:]) == sorted(IPS)


def test_sans_mac_par_ip(tmp_path):
    db, ef = base.ouvrir(tmp_path / "g.db"), Effets()
    _decision(db, "A", None, IPS)
    assert moteur._lever_tout(db, ef, "A", "evasion", None, "m") is True
    assert [a[0] for a in ef.appels] == ["rouvrir"] * 3


def test_effet_lever_mac_arguments():
    vus = []
    ef = effets.Effets(audit=Path("/nonexistent/audit.log"), ctl=lambda a: vus.append(a) or '{"ok": true}')
    assert ef.lever_mac("evasion", MAC.upper(), "m")["ok"] is True
    assert ef.lever_mac("infection", MAC, "m")["ok"] is True
    assert vus == [["evasion", "lever", MAC], ["quarantaine", "lever", MAC]]
    assert ef.lever_mac("evasion", "-", "m")["ok"] is False          # jamais « lever - » : refus local, aucun sudo
    assert ef.lever_mac("intrusion", MAC, "m")["ok"] is False
    assert len(vus) == 2
