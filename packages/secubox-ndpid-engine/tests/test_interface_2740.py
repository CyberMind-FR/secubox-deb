# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2740 — nDPId choisit son interface au lieu de dépendre d'un `eth2` livré en dur.

CONSTAT (RPi400, 2026-10-15) : `pcap_open_live: eth2: No such device exists`, 820 redémarrages en ~1 h. `conf/ndpid-engine.env` livrait `INTERFACE=eth2` (valeur de gk2) à toutes
les cartes ; la carte du RPi400 s'appelle `end0`. Le lanceur résout l'interface : celle configurée si elle existe, sinon celle de la route par défaut, sinon la première carte
PHYSIQUE ; et sort proprement (code 0, pas de redémarrage) s'il n'y en a aucune."""
import os
import re
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
LANCEUR = PKG / "sbin" / "secubox-ndpid-engine-run"


@pytest.fixture
def banc(tmp_path):
    sys_net = tmp_path / "net"
    sys_net.mkdir()
    appels = tmp_path / "appels.txt"
    ndpid = tmp_path / "nDPId"
    ndpid.write_text(f"#!/bin/sh\necho \"$@\" > {appels}\n")
    ndpid.chmod(0o755)
    route = tmp_path / "route.txt"
    ip = tmp_path / "ip"
    ip.write_text(f"#!/bin/sh\n[ -f {route} ] && cat {route}\nexit 0\n")
    ip.chmod(0o755)

    def carte(nom, physique=True):
        (sys_net / nom).mkdir()
        if physique:
            (sys_net / nom / "device").mkdir()

    def lance(interface="", route_defaut=None):
        if route_defaut:
            route.write_text(f"default via 192.168.1.254 dev {route_defaut} proto dhcp src 192.168.1.82 metric 1024\n")
        env = {"PATH": "/usr/bin:/bin", "SECUBOX_SYS_NET": str(sys_net), "SECUBOX_NDPID_BIN": str(ndpid), "SECUBOX_IP_CMD": str(ip),
               "INTERFACE": interface, "COLLECTEUR": "/run/c.sock", "UTILISATEUR": "u", "GROUPE": "g"}
        r = subprocess.run(["sh", str(LANCEUR)], capture_output=True, text=True, env=env, timeout=20)
        return r, (appels.read_text().strip() if appels.exists() else None)
    return carte, lance


def test_l_interface_configuree_est_utilisee_si_elle_existe(banc):
    carte, lance = banc
    carte("eth2"); carte("end0")
    r, args = lance("eth2", route_defaut="end0")
    assert r.returncode == 0 and args == "-l -i eth2 -c /run/c.sock -u u -g g"


def test_interface_configuree_absente_on_prend_celle_de_la_route_par_defaut(banc):
    """LE CAS DU RPi400 : `eth2` n'existe pas, la carte s'appelle end0."""
    carte, lance = banc
    carte("end0"); carte("wlan0"); carte("lo", physique=False)
    r, args = lance("eth2", route_defaut="end0")
    assert r.returncode == 0 and "-i end0" in args


def test_interface_vide_ou_auto_est_une_detection(banc):
    carte, lance = banc
    carte("end0")
    for valeur in ("", "auto"):
        r, args = lance(valeur, route_defaut="end0")
        assert "-i end0" in args, (valeur, r.stderr)


def test_sans_route_par_defaut_la_premiere_carte_physique(banc):
    carte, lance = banc
    for n in ("lo", "br-lan", "docker0", "wg0", "veth12"):
        carte(n, physique=False)
    carte("enp1s0")
    r, args = lance("eth2")
    assert r.returncode == 0 and "-i enp1s0" in args


def test_jamais_une_interface_virtuelle_ou_le_bouclage(banc):
    carte, lance = banc
    for n in ("lo", "br-lan", "docker0", "wg0", "veth12", "lxcbr0"):
        carte(n, physique=False)
    r, args = lance("eth2")
    assert r.returncode == 0 and args is None, "aucune carte physique : on n'écoute pas un pont ni lo"


def test_aucune_interface_sort_proprement_sans_lancer_ndpid(banc):
    """Code 0 : `Restart=on-failure` ne le relance pas. Plus de boucle de 5 s sur une box sans carte à analyser."""
    carte, lance = banc
    r, args = lance("eth2")
    assert r.returncode == 0 and args is None and "aucune interface" in (r.stdout + r.stderr).lower()


def test_une_route_par_defaut_vers_une_carte_inexistante_est_ignoree(banc):
    carte, lance = banc
    carte("enp1s0")
    r, args = lance("", route_defaut="tun9")
    assert "-i enp1s0" in args


# ---------- ce que le paquet livre ----------

ENV = (PKG / "conf" / "ndpid-engine.env").read_text()
UNITE = (PKG / "systemd" / "secubox-ndpid-engine.service").read_text()
RULES = (PKG / "debian" / "rules").read_text()


def test_la_configuration_livree_n_impose_plus_eth2():
    actives = [ligne for ligne in ENV.splitlines() if ligne.startswith("INTERFACE=")]
    assert actives == ["INTERFACE="], actives
    assert "eth2" not in "\n".join(ligne for ligne in ENV.splitlines() if not ligne.lstrip().startswith("#"))


def test_l_unite_passe_par_le_lanceur():
    assert re.search(r"^ExecStart=/usr/sbin/secubox-ndpid-engine-run\s*$", UNITE, re.M)
    assert "-i ${INTERFACE}" not in UNITE


def test_les_regles_installent_le_lanceur():
    assert "secubox-ndpid-engine-run" in RULES and "usr/sbin" in RULES


def test_le_lanceur_est_du_shell_valide_et_executable():
    assert subprocess.run(["sh", "-n", str(LANCEUR)]).returncode == 0
    assert os.access(LANCEUR, os.X_OK)
