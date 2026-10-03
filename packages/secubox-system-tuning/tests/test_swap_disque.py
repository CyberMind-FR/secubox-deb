# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Swap disque (#1917) : le zram n'est pas un swap disque, repli hors /data, jamais d'eMMC — en `--dry-run`, commandes simulées."""
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SCRIPT = PKG / "sbin" / "secubox-tuning-apply"


def stub(chemin: Path, corps: str) -> None:
    chemin.write_text("#!/bin/sh\n" + textwrap.dedent(corps))
    chemin.chmod(0o755)


@pytest.fixture
def banc(tmp_path):
    """Une box fictive : deux dossiers candidats, des commandes système simulées par variables d'environnement."""
    data, srv = tmp_path / "data", tmp_path / "srv"
    data.mkdir()
    srv.mkdir()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stub(bin_ / "swapon", 'if [ "$1" = "--show=NAME" ] || [ "$1" = "--show" ]; then printf "%s" "$FAKE_SWAPON"; fi\n')
    stub(bin_ / "findmnt", 'for dir; do :; done\nprintf "%s\\n" "$(printf "%s" "$FAKE_SOURCES" | tr "," "\\n" | grep "^$dir=" | head -1 | cut -d= -f2)"\n')
    stub(bin_ / "df", 'for dir; do :; done\nprintf "Avail\\n %sG\\n" "$(printf "%s" "$FAKE_LIBRE" | tr "," "\\n" | grep "^$dir=" | head -1 | cut -d= -f2)"\n')
    conf = tmp_path / "config.toml"
    conf.write_text(f'[swap]\npath = "{data}/swapfile"\nsize = "8G"\nminimum_data_free_gb = 20\nfallback_path = "{srv}/swapfile"\n\n[zram]\nenabled = false\n')

    def lancer(swapon="", libre=None, sources=None):
        env = {"PATH": f"{bin_}:/usr/bin:/bin", "SECUBOX_TUNING_CONFIG": str(conf), "FAKE_SWAPON": swapon,
               "FAKE_LIBRE": ",".join(f"{k}={v}" for k, v in (libre or {}).items()),
               "FAKE_SOURCES": ",".join(f"{k}={v}" for k, v in (sources or {}).items())}
        r = subprocess.run(["bash", str(SCRIPT), "--dry-run", "swap"], capture_output=True, text=True, env=env, timeout=60)
        return r.returncode, r.stdout + r.stderr
    lancer.data, lancer.srv = data, srv
    return lancer


def test_le_zram_seul_n_empeche_pas_de_creer_le_swap_disque(banc):
    """Régression gk3 : « swap already active » à cause du zram → le fichier disque n'était jamais créé."""
    rc, sortie = banc(swapon="/dev/zram0\n", libre={banc.data: 400}, sources={banc.data: "/dev/nvme0n1p2"})
    assert rc == 0 and f"DRY-RUN: fallocate -l 8G {banc.data}/swapfile" in sortie
    assert "already active" not in sortie


def test_un_swap_disque_deja_actif_n_est_pas_double(banc):
    rc, sortie = banc(swapon="/dev/zram0\n/data/swapfile\n", libre={banc.data: 400})
    assert rc == 0 and "disk swap already active: /data/swapfile" in sortie and "fallocate" not in sortie


def test_data_trop_petit_on_se_replie_sur_le_ssd_de_srv(banc):
    """gk3 : /data n'a que 4 Go, le SSD est sous / : le fichier va sous /srv/secubox."""
    rc, sortie = banc(swapon="/dev/zram0\n", libre={banc.data: 1, banc.srv: 392},
                      sources={banc.data: "/dev/nvme0n1p3", banc.srv: "/dev/nvme0n1p2"})
    assert rc == 0 and f"DRY-RUN: fallocate -l 8G {banc.srv}/swapfile" in sortie
    assert f"{banc.data}/swapfile" not in sortie.replace("essai suivant", "")


def test_jamais_de_swap_sur_une_carte_emmc_ou_sd(banc):
    rc, sortie = banc(swapon="/dev/zram0\n", libre={banc.data: 400, banc.srv: 400},
                      sources={banc.data: "/dev/mmcblk0p2", banc.srv: "/dev/mmcblk1p1"})
    assert rc == 0 and "fallocate" not in sortie and "aucun emplacement de swap disque convenable" in sortie
    assert "eMMC/SD" in sortie


def test_aucun_emplacement_assez_grand_on_le_dit_sans_echouer(banc):
    rc, sortie = banc(swapon="/dev/zram0\n", libre={banc.data: 3, banc.srv: 5}, sources={banc.data: "/dev/sda1", banc.srv: "/dev/sda1"})
    assert rc == 0 and "fallocate" not in sortie and "swap disque non créé" in sortie


def test_le_fichier_est_protege_en_0600_et_persistant_au_redemarrage(banc):
    rc, sortie = banc(swapon="/dev/zram0\n", libre={banc.data: 400}, sources={banc.data: "/dev/nvme0n1p2"})
    assert f"chmod 600 {banc.data}/swapfile" in sortie and f"mkswap {banc.data}/swapfile" in sortie
    assert "persisting in /etc/fstab" in sortie                                 # sinon le swap disparaît au redémarrage


def test_les_valeurs_par_defaut_livrees():
    conf = (PKG / "etc" / "secubox" / "tuning" / "config.toml").read_text()
    assert 'size = "8G"' in conf and "minimum_data_free_gb = 20" in conf
    assert 'fallback_path = "/srv/secubox/swapfile"' in conf and 'path = "/data/swapfile"' in conf


def test_le_script_ne_cible_pas_de_chemin_en_dur_hors_configuration():
    src = SCRIPT.read_text()
    assert 'CONFIG_FILE="${SECUBOX_TUNING_CONFIG:-/etc/secubox/tuning/config.toml}"' in src
    assert "grep -vq '^/dev/zram'" in src and "mmcblk" in src
    assert os.access(SCRIPT, os.X_OK)
