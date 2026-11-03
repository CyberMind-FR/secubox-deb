# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3419 — premier démarrage du live (VM à une interface) : ni mode routeur, ni netplan apply au démarrage, console
silencieuse sous la TUI, nom d'hôte « secubox », DHCP du LAN jamais activé par l'image."""
import os
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
IMAGE = RACINE / "image"
HANDLER = IMAGE / "sbin" / "secubox-cmdline-handler"
LIVE = (IMAGE / "build-live-usb.sh").read_text()
SILENCE = ("loglevel=3", "systemd.show_status=false", "rd.systemd.show_status=false")


def _fonctions():
    return HANDLER.read_text().split("\n# Main\n", 1)[0]


def test_la_ligne_de_commande_est_lue(tmp_path):
    cmd = tmp_path / "cmdline"
    cmd.write_text("boot=live quiet secubox.netmode=bridge secubox.mode=tui\n")
    r = subprocess.run(["bash", str(HANDLER), "parse"], capture_output=True, text=True, timeout=30, check=True,
                       env=dict(os.environ, SECUBOX_TEST="1", SECUBOX_CMDLINE_FILE=str(cmd)))
    assert "SECUBOX_NETMODE=bridge" in r.stdout and "SECUBOX_MODE=tui" in r.stdout


def test_reseau_genere_jamais_applique_au_demarrage(tmp_path):
    appels = tmp_path / "appels"
    faux = tmp_path / "net-detect"
    faux.write_text(f'#!/bin/sh\necho "$@" >> {appels}\nexit 3\n')
    faux.chmod(0o755)
    script = _fonctions() + '\nSECUBOX_NETMODE=bogus\nlog() { :; }\n' + \
        _fonctions().split("    # Handle network mode\n", 1)[1].split("    # Handle kiosk mode\n", 1)[0]
    script = script.replace("local ", "")
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       env=dict(os.environ, SECUBOX_TEST="1", SECUBOX_NET_DETECT=str(faux)))
    assert r.returncode == 0, r.stderr
    assert appels.read_text().split() == ["generate", "single"]     # mode inconnu : jamais le routeur
    assert not re.search(r'^\s*"\$net_detect" apply', HANDLER.read_text(), re.M)


def test_unite_ne_peut_plus_echouer_au_delai():
    unite = (IMAGE / "systemd" / "secubox-cmdline.service").read_text()
    delai = int(re.search(r"^TimeoutStartSec=(\d+)s?$", unite, re.M).group(1))
    assert delai >= 60
    assert re.search(r"apply_settings\n\s+# #3419[^\n]*\n\s+exit 0", HANDLER.read_text())
    detect = (IMAGE / "systemd" / "secubox-net-detect.service").read_text()
    assert "ExecStart=/usr/sbin/secubox-net-detect generate router" in detect


def test_ancien_nom_live_migre_nom_choisi_intact(tmp_path):
    etc = tmp_path / "etc"
    (etc / "secubox").mkdir(parents=True)
    (etc / "hostname").write_text("secubox-live\n")
    (etc / "hosts").write_text("127.0.0.1  localhost secubox-live secubox secubox.local\n")
    (etc / "secubox" / "secubox.conf").write_text('[global]\nhostname = "secubox-live"\n')
    script = _fonctions() + "\nlog() { :; }\nmigrer_nom_live\n"
    env = dict(os.environ, SECUBOX_TEST="1", SECUBOX_ETC=str(etc))
    subprocess.run(["bash", "-c", script], check=True, timeout=30, env=env)
    assert (etc / "hostname").read_text() == "secubox\n"
    assert "secubox-live" not in (etc / "hosts").read_text()
    assert 'hostname = "secubox"' in (etc / "secubox" / "secubox.conf").read_text()
    (etc / "hostname").write_text("gk5\n")                            # choisi au premier pas : jamais touché
    subprocess.run(["bash", "-c", script], check=True, timeout=30, env=env)
    assert (etc / "hostname").read_text() == "gk5\n"


def test_nom_d_hote_par_defaut_secubox():
    assert 'EFFECTIVE_HOSTNAME="${STATIC_HOSTNAME:-secubox}"' in LIVE
    assert 'hostname = "secubox-live"' not in LIVE
    assert 'echo "secubox-live"' not in (IMAGE / "build-ebin-live-usb.sh").read_text()


def test_console_silencieuse_entrees_normales_seulement(tmp_path):
    ligne = next(x for x in LIVE.splitlines() if x.startswith("CONSOLE_SILENCIEUSE="))
    for mot in SILENCE:
        assert mot in ligne
    sed = next(x for x in LIVE.splitlines() if "CONSOLE_SILENCIEUSE" in x and x.startswith("sed -i"))
    cfg = tmp_path / "grub.cfg"
    cfg.write_text("linux v boot=live components persistence quiet splash\n"
                   "linux v boot=live components toram quiet\n"
                   "linux v boot=live components nomodeset console=tty0 systemd.unit=emergency.target\n")
    script = f'{ligne}\nMNT={tmp_path}\n' + sed.replace('"${MNT}/esp/boot/grub/grub.cfg"', f'"{cfg}"')
    subprocess.run(["bash", "-c", script], check=True, timeout=30)
    *normales, secours = cfg.read_text().splitlines()
    for x in normales:
        assert all(m in x for m in SILENCE), x
    assert "show_status" not in secours                               # console de secours intacte
    image = (IMAGE / "build-image.sh").read_text()
    assert all(m in image.split("GRUB_CMDLINE_LINUX_DEFAULT=", 1)[1].splitlines()[0] for m in SILENCE)


def test_image_n_active_jamais_le_dhcp_du_lan():
    boucle = LIVE.split('for svc in "${ROOTFS}/usr/lib/systemd/system/secubox-"*.service; do', 1)[1].split("done", 1)[0]
    assert "secubox-lan-dhcp*.service)" in boucle
    assert re.search(r"secubox-lan-dhcp\*\.service\)[^;]*?continue", boucle, re.S)


def _parse(tmp_path, ligne, **env):
    cmd = tmp_path / "cmdline"
    cmd.write_text(ligne)
    r = subprocess.run(["bash", str(HANDLER), "parse"], capture_output=True, text=True, timeout=30, check=True,
                       env=dict(os.environ, SECUBOX_CMDLINE_FILE=str(cmd), **env))
    return r.stdout


def test_sans_parametre_le_routeur_est_demande(tmp_path):
    # multi-ports sans secubox.netmode : « router » demandé ; secubox-net-detect le garde s'il y a des ports LAN
    # distincts (tests/test_dhcp_sonde_3419.py::test_mode_effectif) et retombe en single sinon
    assert "SECUBOX_NETMODE=router" in _parse(tmp_path, "boot=live quiet\n", SECUBOX_TEST="1")


def test_crochets_d_environnement_ignores_hors_test(tmp_path):
    # hors SECUBOX_TEST=1, /proc/cmdline est lu, jamais le fichier désigné par l'environnement
    sortie = _parse(tmp_path, "secubox.netmode=bridge\n")
    vrai = Path("/proc/cmdline").read_text()
    assert ("SECUBOX_NETMODE=bridge" in sortie) == ("secubox.netmode=bridge" in vrai)
