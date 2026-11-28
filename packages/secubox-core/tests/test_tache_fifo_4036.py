# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#4036 — file FIFO à concurrence bornée des tâches de fond (/usr/lib/secubox/tache-fifo).

Aucune attente fixe : chaque étape attend un fait observable (une ligne de journal, un ticket
dans la file) avec un plafond large, pour rester stable sur une CI chargée."""
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

TACHE = Path(__file__).resolve().parents[1] / "usr" / "lib" / "secubox" / "tache-fifo"
PLAFOND = 30.0

pytestmark = pytest.mark.skipif(shutil.which("flock") is None, reason="flock absent")


def _attendre(cond, plafond=PLAFOND):
    fin = time.monotonic() + plafond
    while time.monotonic() < fin:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


@pytest.fixture
def banc(tmp_path):
    d = tmp_path / "taches"
    (d / "file").mkdir(parents=True)
    conf = tmp_path / "taches.toml"
    journal = tmp_path / "journal"
    journal.touch()
    env = dict(os.environ, SECUBOX_TACHES_DIR=str(d), SECUBOX_TACHES_CONF=str(conf),
               SECUBOX_TACHES_PAS="0.05")
    procs = []

    class Banc:
        dossier = d
        file = d / "file"

        def concurrence(self, n, actif="true"):
            conf.write_text(f'[autre]\nconcurrence = 9\n\n[file]\nactif = {actif}  # commentaire\n'
                            f'concurrence = "{n}"\n')

        def lancer(self, nom, *, attente=60, bloque=False):
            """Tâche qui note son départ ; si bloque, attend le fichier <nom>.libre."""
            libre = tmp_path / f"{nom}.libre"
            corps = f'echo {nom} >> "{journal}"'
            if bloque:
                corps += f'; while [ ! -e "{libre}" ]; do sleep 0.02; done'
            p = subprocess.Popen([str(TACHE), "--nom", nom, "--attente-max", str(attente), "--",
                                  "sh", "-c", corps], env=env, stderr=subprocess.PIPE, text=True)
            procs.append(p)
            return p

        def liberer(self, nom):
            (tmp_path / f"{nom}.libre").touch()

        def partis(self):
            return journal.read_text().split()

        def tickets(self):
            return sorted(p.name for p in self.file.iterdir() if p.name[:1].isdigit())

    yield Banc()
    for p in procs:
        if p.poll() is None:
            p.kill()
        p.wait()


def test_la_concurrence_est_bornee(banc):
    banc.concurrence(2)
    for n in ("a", "b", "c", "d"):
        banc.lancer(n, bloque=True)
    # Deux partent, deux attendent leur tour avec un ticket dans la file.
    assert _attendre(lambda: len(banc.partis()) == 2 and len(banc.tickets()) == 2)
    assert len(banc.partis()) == 2
    for n in banc.partis():
        banc.liberer(n)
    assert _attendre(lambda: len(banc.partis()) == 4)
    for n in ("a", "b", "c", "d"):
        banc.liberer(n)


def test_l_ordre_d_arrivee_est_respecte(banc):
    banc.concurrence(1)
    banc.lancer("a", bloque=True)
    assert _attendre(lambda: banc.partis() == ["a"])
    for i, n in enumerate(("b", "c", "d", "e"), start=1):
        banc.lancer(n)
        assert _attendre(lambda i=i: len(banc.tickets()) == i)
    banc.liberer("a")
    assert _attendre(lambda: len(banc.partis()) == 5)
    assert banc.partis() == ["a", "b", "c", "d", "e"]


def test_abandon_propre_au_dela_de_l_attente(banc):
    banc.concurrence(1)
    banc.lancer("a", bloque=True)
    assert _attendre(lambda: banc.partis() == ["a"])
    p = banc.lancer("b", attente=1)
    assert p.wait(timeout=PLAFOND) == 0
    assert "abandonnée" in p.stderr.read()
    assert banc.partis() == ["a"]
    assert banc.tickets() == []
    banc.liberer("a")


def test_ticket_d_un_processus_mort_ignore_et_nettoye(banc):
    banc.concurrence(1)
    # Ticket plus ancien que tout, sans verrou : son porteur est mort (SIGKILL).
    mort = banc.file / "1000000000000000000-0000099999"
    mort.write_text("fantome\n")
    p = banc.lancer("a", attente=5)
    assert p.wait(timeout=PLAFOND) == 0
    assert banc.partis() == ["a"]
    assert not mort.exists()


def test_emplacement_libere_quand_le_porteur_est_tue(banc):
    banc.concurrence(1)
    a = banc.lancer("a", bloque=True)
    assert _attendre(lambda: banc.partis() == ["a"])
    b = banc.lancer("b")
    assert _attendre(lambda: len(banc.tickets()) == 1)
    a.send_signal(signal.SIGKILL)    # exec : le PID suivi est la commande elle-même
    assert b.wait(timeout=PLAFOND) == 0
    assert banc.partis() == ["a", "b"]


def test_file_desactivee_ou_absente_lance_directement(banc, tmp_path):
    banc.concurrence(1, actif="false")
    banc.lancer("a", bloque=True)
    banc.lancer("b", bloque=True)
    assert _attendre(lambda: sorted(banc.partis()) == ["a", "b"])
    banc.liberer("a")
    banc.liberer("b")
    banc.concurrence(1)
    shutil.rmtree(banc.file)
    p = banc.lancer("c")
    assert p.wait(timeout=PLAFOND) == 0
    assert "lancement direct" in p.stderr.read()


def test_concurrence_illisible_retombe_sur_deux(banc):
    banc.concurrence("beaucoup")
    for n in ("a", "b", "c"):
        banc.lancer(n, bloque=True)
    assert _attendre(lambda: len(banc.partis()) == 2 and len(banc.tickets()) == 1)
    for n in ("a", "b", "c"):
        banc.liberer(n)
    assert _attendre(lambda: len(banc.partis()) == 3)


def test_code_de_sortie_de_la_commande_transmis(banc):
    banc.concurrence(2)
    env = dict(os.environ, SECUBOX_TACHES_DIR=str(banc.dossier),
               SECUBOX_TACHES_CONF="/nonexistent", SECUBOX_TACHES_PAS="0.05")
    r = subprocess.run([str(TACHE), "--nom", "x", "--", "sh", "-c", "exit 3"], env=env)
    assert r.returncode == 3
