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


def test_l_unite_attend_wg_mesh_puis_lance_le_demon_par_exec():
    ex = valeur("ExecStart")
    assert len(ex) == 1 and "until [ -e /sys/class/net/wg-mesh ]" in ex[0] and ex[0].rstrip("'").endswith("exec /usr/bin/python3 -m assist.daemon"), ex


def test_le_demarrage_de_l_unite_ne_bloque_pas_systemctl():
    """RÉGRESSION (RPi400) : une attente dans ExecStartPre, sans délai, rendait `systemctl restart` / `enable --now` — donc le postinst et `dpkg` — INTERMINABLES
    tant que wg-mesh n'existait pas. L'attente est dans ExecStart (un `sh` qui fait `exec` du démon) : le démarrage se termine tout de suite."""
    assert not [v for v in valeur("ExecStartPre") if "wg-mesh" in v]
    assert valeur("TimeoutStartSec") != ["infinity"]
    assert not valeur("ExecCondition")


def test_le_demon_reste_fail_closed():
    assert "BindError" in (PKG / "assist" / "wsserver.py").read_text()


def test_une_vraie_panne_ne_boucle_plus_indefiniment():
    unit = UNITE.split("\n[Service]\n")[0]
    assert "StartLimitIntervalSec=300" in unit and "StartLimitBurst=10" in unit, "ces clés ne valent que dans [Unit]"
    assert int(valeur("StartLimitBurst")[0]) <= 10 and int(valeur("RestartSec")[0]) >= 5


def commande_attente(tmp_path):
    """La VRAIE commande de l'unité ; seul le démon est remplacé par un marqueur."""
    cmd = valeur("ExecStart")[0]
    cmd = cmd.replace("/sys/class/net/wg-mesh", str(tmp_path / "wg-mesh")).replace("sleep 15", "sleep 0.2")
    return cmd.replace("exec /usr/bin/python3 -m assist.daemon", "echo DEMON-LANCE")


def lance(tmp_path):
    cmd = commande_attente(tmp_path)
    return subprocess.run(cmd.replace("/bin/sh -c ", "sh -c ", 1), shell=True, capture_output=True, text=True, timeout=20)


def test_l_attente_lance_le_demon_des_que_l_interface_apparait_et_pas_avant(tmp_path):
    t0 = time.time()
    threading.Timer(1.2, lambda: (tmp_path / "wg-mesh").write_text("")).start()
    r = lance(tmp_path)
    assert r.returncode == 0 and "DEMON-LANCE" in r.stdout and 1.0 <= time.time() - t0 < 10, (r.stdout, r.stderr)


def test_si_l_interface_existe_deja_on_ne_perd_pas_de_temps(tmp_path):
    (tmp_path / "wg-mesh").write_text("")
    t0 = time.time()
    r = lance(tmp_path)
    assert "DEMON-LANCE" in r.stdout and time.time() - t0 < 2
