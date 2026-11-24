# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3910 : une levée réussie est gardée même si le passage est tué ensuite ; audit.log ouvert sans création."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from garde import base, effets, moteur  # noqa: E402
from tests.test_moteur_3794 import MAC, REG, T, Notifs, sources  # noqa: E402

IPS = ["192.168.1.112", "2a01:e0a::1", "2a01:e0a::2"]


class Tue(Exception):
    pass


class EffetsTues:
    """Rouvre la 1re adresse, puis le passage est « tué » (TimeoutStartSec) pendant la 2e."""
    def __init__(self):
        self.appels = []

    def rouvrir(self, ip, mac=None, motif=""):
        self.appels.append(ip)
        if len(self.appels) > 1:
            raise Tue(ip)
        return {"ok": True, "motif": ""}

    def alerte(self, texte):
        pass


def test_levee_reussie_gardee_si_passage_tue(tmp_path):
    chemin = tmp_path / "g.db"
    db = base.ouvrir(chemin)
    db.execute("INSERT INTO decisions(id, menace, cible, mac, ip, debut, fin, etat, leve_par) VALUES "
               "('A','evasion',?,?,?,?,?,'levee_en_cours','reevaluation')", (MAC, MAC, IPS[0], T - 90000, T - 3600))
    db.executemany("INSERT INTO adresses(decision_id, ip, fin) VALUES ('A',?,?)", [(ip, T - 3600) for ip in IPS])
    db.commit()
    with pytest.raises(Tue):
        moteur.passage(db, REG, sources(), EffetsTues(), Notifs(), T)
    db.close()
    relu = base.ouvrir(chemin)
    assert sorted(r[0] for r in relu.execute("SELECT ip FROM adresses WHERE decision_id='A'")) == IPS[1:]


def test_audit_sans_creation(tmp_path):
    absent = tmp_path / "audit.log"
    ef = effets.Effets(audit=absent)
    ef.audit("rouvrir", "192.168.1.112", "test", "ok")
    assert not absent.exists()                              # jamais créé par garde (profil AppArmor : ajout seul)
    absent.write_text("")
    os.chmod(absent, 0o600)
    ef.audit("rouvrir", "192.168.1.112", "test", "ok")
    assert '"action": "rouvrir"' in absent.read_text()


def test_profils_ecrivent_audit_en_w():
    """« a » seul refusait chaque write() (revérifié en MAY_WRITE par le noyau de gk2)."""
    ici = Path(__file__).resolve().parents[1] / "apparmor"
    for profil in ("secubox-garde", "secubox-garde-passage"):
        txt = (ici / profil).read_text(encoding="utf-8")
        assert "  /var/log/secubox/audit.log w," in txt and "audit.log a," not in txt, profil


def test_unite_laisse_le_temps_et_la_memoire_au_rendu():
    unite = (Path(__file__).resolve().parents[1] / "debian" / "secubox-garde-passage.service").read_text(encoding="utf-8")
    assert "TimeoutStartSec=300" in unite and "MemoryMax=448M" in unite
