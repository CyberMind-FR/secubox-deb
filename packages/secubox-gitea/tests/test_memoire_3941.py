# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""GOMEMLIMIT de Gitea (#3941) : 70 % du budget du conteneur, posé par `giteactl memoire`, jamais de redémarrage."""
import os
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
CTL = PAQUET / "sbin" / "giteactl"
BUDGET = "lxc.cgroup2.memory.max = 256M\nlxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 256M\n"


@pytest.fixture
def banc(tmp_path):
    racine = tmp_path / "lxc" / "gitea"
    (racine / "rootfs" / "etc" / "systemd" / "system").mkdir(parents=True)
    (racine / "config").write_text(BUDGET)
    toml = tmp_path / "gitea.toml"
    toml.write_text(f'lxc_path = "{tmp_path}/lxc"\n')
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nom, corps in (("lxc-info", 'echo "State: ${FAUX_ETAT:-STOPPED}"'),
                       ("lxc-attach", f'echo "$*" >> {tmp_path}/attach'), ("lxc-stop", f"touch {tmp_path}/stop"),
                       ("lxc-start", f"touch {tmp_path}/start")):
        (bin_ / nom).write_text(f"#!/bin/sh\n{corps}\n")
        (bin_ / nom).chmod(0o755)

    def lancer(etat="STOPPED"):
        return subprocess.run(["bash", str(CTL), "memoire"], capture_output=True, text=True, timeout=60,
                              env={"PATH": f"{bin_}:/usr/bin:/bin", "GITEA_CONFIG_FILE": str(toml), "FAUX_ETAT": etat})
    lancer.tmp, lancer.rootfs, lancer.cfg = tmp_path, racine / "rootfs", racine / "config"
    lancer.dropin = racine / "rootfs/etc/systemd/system/gitea.service.d/50-secubox-memoire.conf"
    return lancer


def unite(b):
    (b.rootfs / "etc/systemd/system/gitea.service").write_text("[Service]\nExecStart=/usr/local/bin/gitea web\n")


def test_drop_in_systemd_a_70_pour_cent_du_budget_effectif(banc):
    unite(banc)
    r = banc("RUNNING")
    assert r.returncode == 0, r.stderr
    assert "[Service]\nEnvironment=GOMEMLIMIT=358MiB\n" in banc.dropin.read_text()
    attach = (banc.tmp / "attach").read_text()
    assert "daemon-reload" in attach and "restart" not in attach
    assert not (banc.tmp / "stop").exists() and not (banc.tmp / "start").exists()


def test_idempotent(banc):
    unite(banc)
    banc()
    inode = banc.dropin.stat().st_ino
    r = banc("RUNNING")
    assert banc.dropin.stat().st_ino == inode and not (banc.tmp / "attach").exists() and r.returncode == 0


def test_suit_le_budget(banc):
    unite(banc)
    banc()
    banc.cfg.write_text("lxc.cgroup2.memory.max = 1G\n")
    banc()
    assert "GOMEMLIMIT=716MiB" in banc.dropin.read_text()


def test_alpine_script_de_demarrage(banc):
    (banc.rootfs / "opt").mkdir()
    s = banc.rootfs / "opt" / "start-gitea.sh"
    s.write_text("#!/bin/sh\n# Gitea startup script\nexec gitea web\n")
    s.chmod(0o755)
    for _ in range(2):
        assert banc().returncode == 0
    t = s.read_text().splitlines()
    assert t[0] == "#!/bin/sh" and t[1].startswith("export GOMEMLIMIT=358MiB") and t[2:] == ["# Gitea startup script", "exec gitea web"]
    assert os.access(s, os.X_OK)


def test_sans_budget_ni_conteneur_rien(banc):
    unite(banc)
    banc.cfg.write_text("lxc.uts.name = gitea\n")
    assert banc().returncode == 0 and not banc.dropin.exists()
    banc.cfg.unlink()
    assert banc().returncode == 0


def test_lien_symbolique_du_conteneur_jamais_suivi(banc, tmp_path):
    unite(banc)
    dehors = tmp_path / "dehors"
    dehors.mkdir()
    banc.dropin.parent.symlink_to(dehors)
    r = banc()
    assert r.returncode == 0 and list(dehors.iterdir()) == [] and "non posé" in r.stdout + r.stderr


def test_generateurs_bornent_l_echange_sans_frein():
    t = CTL.read_text()
    assert "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 256M\n" in t
    assert "lxc.cgroup2.memory.high" not in t and "swap.max = 0" not in t
    pi = (PAQUET / "debian" / "postinst").read_text()
    assert "giteactl memoire" in pi and "secubox-lxc-memoire migrer gitea" in pi


def test_app_ini_bornes_seulement_a_la_creation():
    """Le fichier existant (secrets) n'est jamais réécrit : les bornes ne vont que dans le modèle d'installation."""
    t = CTL.read_text()
    assert "MAX_GIT_DIFF_FILES" in t.split("create_gitea_config() {")[1].split("\n}\n")[0]
    assert "app.ini" not in t.split("cmd_memoire() {")[1].split("\n}\n")[0]
