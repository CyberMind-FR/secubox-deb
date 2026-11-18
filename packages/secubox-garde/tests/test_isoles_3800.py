# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3800 — liste des adresses isolées publiée pour sbxwaf."""
import json
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from garde import base, isoles  # noqa: E402

RACINE = Path(__file__).resolve().parent.parent
T = 1_800_000_000


def _decision(db, did, menace, etat="active", ip="192.168.1.20", motif="infection : c2", debut=T):
    db.execute("INSERT INTO decisions(id, menace, cible, mac, ip, motif, signe, debut, fin, etat) "
               "VALUES (?,?,?,?,?,?,?,?,?,?)", (did, menace, "cle-" + did, None, ip, motif, "c2", debut, T + 86400, etat))


def test_vide(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    chemin = tmp_path / "garde-isoles.json"
    assert isoles.ecrire(db, T, chemin) == 0
    assert json.loads(chemin.read_text()) == {"genere_le": T, "isoles": []}
    assert stat.S_IMODE(chemin.stat().st_mode) == 0o644


def test_seules_les_infections_actives_toutes_adresses(tmp_path):
    db = base.ouvrir(tmp_path / "g.db")
    _decision(db, "a", "infection")
    db.execute("INSERT INTO adresses(decision_id, ip, fin) VALUES ('a','192.168.1.20',0),('a','fd00::20',0)")
    db.execute("INSERT INTO decision_noms(decision_id, noms) VALUES ('a','TV <salon>,autre')")
    _decision(db, "b", "evasion", ip="192.168.1.30")
    _decision(db, "c", "intrusion", ip="8.8.8.8")
    _decision(db, "d", "infection", etat="echue", ip="192.168.1.40")
    _decision(db, "e", "infection", ip="192.168.1.50", motif="x" * 500)
    chemin = tmp_path / "garde-isoles.json"
    assert isoles.ecrire(db, T + 5, chemin) == 3
    d = json.loads(chemin.read_text())
    assert d["genere_le"] == T + 5
    ips = {e["ip"]: e for e in d["isoles"]}
    assert set(ips) == {"192.168.1.20", "fd00::20", "192.168.1.50"}
    assert ips["fd00::20"] == {"ip": "fd00::20", "nom": "TV <salon>", "depuis": T, "motif": "infection : c2"}
    assert ips["192.168.1.50"]["nom"] == "cle-e" and len(ips["192.168.1.50"]["motif"]) == isoles.MOTIF_MAX
    assert not list(tmp_path.glob(".isoles.*"))


def test_passage_publie_et_profils():
    script = (RACINE / "sbin" / "secubox-garde-passage").read_text()
    assert script.count("_publier_isoles(db, maintenant)") == 2
    profil = (RACINE / "apparmor" / "secubox-garde-passage").read_text()
    assert "/run/secubox/garde/isoles.json rw," in profil and "/run/secubox/garde/.isoles.* rw," in profil
    assert "/run/secubox/garde-isoles" not in profil
    unite = (RACINE / "debian" / "secubox-garde-passage.service").read_text()
    rw = " ".join(re.findall(r"^ReadWritePaths=(.*)$", unite, re.M)).split()
    assert "-/run/secubox/garde" in rw and "/run/secubox" not in rw
    assert isoles.CHEMIN == Path("/run/secubox/garde/isoles.json")


def test_dossier_dedie_tmpfiles_postinst_postrm():
    conf = (RACINE / "tmpfiles.d" / "secubox-garde.conf").read_text()
    assert "d /run/secubox/garde 0755 secubox-garde secubox-garde -" in conf
    assert "tmpfiles.d/secubox-garde.conf $(P)/usr/lib/tmpfiles.d/" in (RACINE / "debian" / "rules").read_text()
    assert "systemd-tmpfiles --create /usr/lib/tmpfiles.d/secubox-garde.conf" in (
        RACINE / "debian" / "postinst").read_text()
    postrm = (RACINE / "debian" / "postrm").read_text()
    assert "remove|purge)" in postrm and "rm -rf /run/secubox/garde" in postrm
