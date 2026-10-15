# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2740 — secubox-assist attend l'interface wg-mesh au lieu de redémarrer toutes les 5 s.

CONSTAT (RPi400, 2026-10-15) : `BindError: wg-mesh iface 'wg-mesh' unavailable`, 619 redémarrages en ~1 h. Le refus de servir sans wg-mesh est VOULU (fail-closed) ;
le défaut était `Restart=on-failure` + `RestartSec=5` : un interpréteur Python relancé pour rien, indéfiniment, tant que la box n'a pas rejoint le maillage."""
import re
import subprocess
import threading
import time
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
UNITE = (PKG / "systemd" / "secubox-assist.service").read_text()


def valeur(cle):
    return [m.group(1) for m in re.finditer(rf"^{cle}=(.*)$", UNITE, re.M)]


def test_l_unite_attend_wg_mesh_avant_de_lancer_le_demon():
    pre = [v for v in valeur("ExecStartPre") if "wg-mesh" in v]
    assert pre and "/sys/class/net/wg-mesh" in pre[0] and "until" in pre[0], pre


def test_l_attente_n_a_pas_de_delai_qui_la_tue():
    """Sans délai de démarrage, systemd ne tue pas une attente légitime (la box peut rejoindre le maillage des heures plus tard)."""
    assert valeur("TimeoutStartSec") == ["infinity"]


def test_le_demon_reste_lance_comme_avant_et_garde_son_refus_fail_closed():
    assert valeur("ExecStart") == ["/usr/bin/python3 -m assist.daemon"]
    assert "BindError" in (PKG / "assist" / "wsserver.py").read_text()


def test_une_vraie_panne_ne_boucle_plus_indefiniment():
    unit = UNITE.split("\n[Service]\n")[0]
    assert "StartLimitIntervalSec=300" in unit and "StartLimitBurst=10" in unit, "ces clés ne valent que dans [Unit]"
    assert int(valeur("StartLimitBurst")[0]) <= 10 and int(valeur("RestartSec")[0]) >= 5


def commande_attente(tmp_path):
    cmd = [v for v in valeur("ExecStartPre") if "wg-mesh" in v][0]
    return re.sub(r"^[+!@-]+", "", cmd).replace("/sys/class/net/wg-mesh", str(tmp_path / "wg-mesh")).replace("sleep 15", "sleep 0.2")


def test_l_attente_rend_la_main_des_que_l_interface_apparait_et_pas_avant(tmp_path):
    """On exécute la VRAIE commande de l'unité, avec l'interface simulée par un fichier."""
    t0 = time.time()
    threading.Timer(1.2, lambda: (tmp_path / "wg-mesh").write_text("")).start()
    r = subprocess.run(commande_attente(tmp_path), shell=True, timeout=20)
    assert r.returncode == 0 and 1.0 <= time.time() - t0 < 10


def test_si_l_interface_existe_deja_on_ne_perd_pas_de_temps(tmp_path):
    (tmp_path / "wg-mesh").write_text("")
    t0 = time.time()
    assert subprocess.run(commande_attente(tmp_path), shell=True, timeout=20).returncode == 0 and time.time() - t0 < 2
