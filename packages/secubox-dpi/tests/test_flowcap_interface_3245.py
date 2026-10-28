# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3245 — flowcap ne relance plus ndpiReader en boucle.

CONSTAT (gk1, 2026-10-28) : `wg-toolbox` n'existe pas, ndpiReader échoue aussitôt et le script le relançait sans pause
(PAUSE=0, `|| true`) : 54 % de CPU. Interface absente : on le dit UNE fois et on revérifie toutes les N s (défaut 300)
sans lancer ndpiReader. ndpiReader qui sort trop vite : délai croissant plafonné (10, 20, 40 … 300 s), remis à zéro
après une passe normale. Le comportement nominal (fenêtre, collecteur) ne change pas.

Substitutions (tests) : SECUBOX_SYS_NET, SECUBOX_DPI_SLEEP_CMD, SECUBOX_DPI_MAX_ITER (borne la boucle, ignorée hors test
quand elle est absente), SECUBOX_DPI_STATE."""
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / "sbin" / "secubox-dpi-flowcap"


@pytest.fixture
def banc(tmp_path):
    sys_net = tmp_path / "net"
    sys_net.mkdir()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    lancements = tmp_path / "lancements.txt"
    attentes = tmp_path / "attentes.txt"
    collecte = tmp_path / "collecte.txt"
    csv = tmp_path / "flows.csv"

    sleep = tmp_path / "faux-sleep"
    sleep.write_text(f'#!/bin/sh\necho "$@" >> {attentes}\n')
    sleep.chmod(0o755)
    collecteur = tmp_path / "collecteur"
    collecteur.write_text(f'#!/bin/sh\necho "$@" >> {collecte}\n')
    collecteur.chmod(0o755)

    def ndpi(code=0, ecrit_csv=False):
        corps = f'echo "$@" >> {lancements}\n'
        if ecrit_csv:
            corps += f"echo flux > {csv}\n"
        (bin_ / "ndpiReader").write_text("#!/bin/sh\n" + corps + f"exit {code}\n")
        (bin_ / "ndpiReader").chmod(0o755)

    def lance(iterations, interface="wg-toolbox", **extra):
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "SECUBOX_SYS_NET": str(sys_net),
               "SECUBOX_DPI_SLEEP_CMD": str(sleep), "SECUBOX_DPI_MAX_ITER": str(iterations),
               "SECUBOX_DPI_STATE": str(tmp_path / "etat"), "SECUBOX_DPI_CSV": str(csv),
               "SECUBOX_DPI_COLLECTOR": str(collecteur), "SECUBOX_DPI_IFACE": interface}
        env.update({k: str(v) for k, v in extra.items()})
        r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=env, timeout=20)
        lire = lambda p: p.read_text().split("\n")[:-1] if p.exists() else []  # noqa: E731
        return r, lire(lancements), lire(attentes), lire(collecte)
    return sys_net, ndpi, lance


def test_interface_absente_ndpireader_jamais_lance_attente_300_message_unique(banc):
    _, ndpi, lance = banc
    ndpi(code=1)
    r, lancements, attentes, _ = lance(4)
    assert r.returncode == 0
    assert lancements == [], "ndpiReader ne doit jamais être lancé sans interface"
    assert attentes == ["300"] * 4
    assert (r.stdout + r.stderr).count("n'existe pas") == 1, "le dire UNE fois"


def test_l_attente_est_configurable(banc):
    _, ndpi, lance = banc
    ndpi()
    _, _, attentes, _ = lance(2, SECUBOX_DPI_IFACE_WAIT=45)
    assert attentes == ["45", "45"]


def test_l_interface_qui_apparait_relance_la_capture(banc):
    sys_net, ndpi, lance = banc
    ndpi(ecrit_csv=True)
    (sys_net / "wg-toolbox").mkdir()
    r, lancements, attentes, collecte = lance(2, SECUBOX_DPI_FAST_EXIT=0)
    assert len(lancements) == 2 and "-i wg-toolbox -s 60" in lancements[0]
    assert attentes == [] and len(collecte) == 2


def test_ndpireader_qui_echoue_vite_delais_croissants_plafonnes(banc):
    sys_net, ndpi, lance = banc
    (sys_net / "wg-toolbox").mkdir()
    ndpi(code=1)
    _, lancements, attentes, _ = lance(7, SECUBOX_DPI_BACKOFF_MAX=300)
    assert len(lancements) == 7
    assert attentes == ["10", "20", "40", "80", "160", "300", "300"]


def test_passe_normale_pas_d_attente_et_remise_a_zero(banc):
    sys_net, ndpi, lance = banc
    (sys_net / "wg-toolbox").mkdir()
    ndpi(ecrit_csv=True)
    # FAST_EXIT=0 : aucune passe n'est « trop rapide » -> nominal, PAUSE=0 -> aucune attente
    _, lancements, attentes, collecte = lance(3, SECUBOX_DPI_FAST_EXIT=0)
    assert len(lancements) == 3 and attentes == [] and len(collecte) == 3


def test_la_pause_nominale_est_inchangee(banc):
    sys_net, ndpi, lance = banc
    (sys_net / "wg-toolbox").mkdir()
    ndpi()
    _, _, attentes, _ = lance(2, SECUBOX_DPI_FAST_EXIT=0, SECUBOX_DPI_PAUSE=240)
    assert attentes == ["240", "240"]


def test_remise_a_zero_apres_une_passe_normale(banc):
    """Deux échecs rapides (10, 20), puis une passe normale : le délai repart de 10."""
    sys_net, ndpi, lance = banc
    (sys_net / "wg-toolbox").mkdir()
    # ndpiReader : échoue vite les 2 premières fois, puis dort 1 s (passe « normale » avec FAST_EXIT=1)
    compteur = sys_net.parent / "n"
    ndpi_bin = sys_net.parent / "bin" / "ndpiReader"
    ndpi_bin.write_text(f'#!/bin/sh\nn=$(cat {compteur} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {compteur}\n'
                        f'[ "$n" -eq 3 ] && sleep 2\nexit 1\n')
    ndpi_bin.chmod(0o755)
    _, _, attentes, _ = lance(5, SECUBOX_DPI_FAST_EXIT=1)
    assert attentes == ["10", "20", "10", "20"]
