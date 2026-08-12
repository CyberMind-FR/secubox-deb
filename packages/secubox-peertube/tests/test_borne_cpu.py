# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-peertube — la borne CPU du conteneur (#1010).

Ce qui est verifie ici est exactement ce qui a mordu sur gk2 : le conteneur
tournait avec `cpu.max = max 100000`, c'est-a-dire sans plafond, et deux ffmpeg
de transcodage ont porte la charge a 113.

Les tests s'exercent sur un FAUX arbre LXC. Ils ne touchent ni au cgroup ni a
un conteneur reel : la pose a chaud demande la racine et un conteneur vivant,
elle est verifiee sur la board, pas ici.
"""

import os
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
SCRIPT = RACINE / "lib" / "peertube" / "borne-cpu.sh"

CONFIG_SANS_BORNE = """\
# SecuBox-managed — see secubox-peertube / install-lxc.sh
lxc.include = /usr/share/lxc/config/debian.common.conf
lxc.arch = linux64
lxc.cgroup2.memory.high = 1500M
lxc.cgroup2.memory.max = 2G
lxc.start.auto = 1
"""


def lance(tmp_path, config, borne=None):
    """Deroule le script sur un faux arbre LXC et rend la configuration."""
    cfg = tmp_path / "lxc" / "peertube" / "config"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(config)

    env = dict(os.environ, SECUBOX_LXC_PATH=str(tmp_path / "lxc"))
    if borne:
        env["SECUBOX_PEERTUBE_CPU_MAX"] = borne
    r = subprocess.run(["bash", str(SCRIPT)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return cfg.read_text(), r.stdout


def lignes_borne(texte):
    return [l for l in texte.splitlines()
            if l.strip().startswith("lxc.cgroup2.cpu.max")]


def test_la_borne_est_posee_quand_elle_manque(tmp_path):
    # Le cas de gk2 : un conteneur provisionne avant que la borne n'existe.
    sortie, _ = lance(tmp_path, CONFIG_SANS_BORNE)
    assert lignes_borne(sortie) == ["lxc.cgroup2.cpu.max = 100000 100000"]


def test_la_borne_par_defaut_vaut_un_coeur(tmp_path):
    # La valeur n'est pas cosmetique : elle est la moitie de ce que les deux
    # ffmpeg consommaient. La relacher annulerait le correctif.
    sortie, _ = lance(tmp_path, CONFIG_SANS_BORNE)
    quota, periode = lignes_borne(sortie)[0].split("=")[1].split()
    assert int(quota) / int(periode) == 1.0


def test_le_reste_de_la_configuration_est_intact(tmp_path):
    # La configuration porte le reseau et les montages : en perdre une ligne
    # laisserait le conteneur sans adresse ou sans ses donnees.
    sortie, _ = lance(tmp_path, CONFIG_SANS_BORNE)
    for ligne in CONFIG_SANS_BORNE.splitlines():
        assert ligne in sortie, f"ligne perdue : {ligne}"


def test_repasser_ne_cree_pas_de_doublon(tmp_path):
    # LE PIEGE DEJA PAYE AILLEURS : un second bloc `lxc.net.0` laisse le
    # conteneur SANS adresse. Une seconde ligne `cpu.max` rendrait la valeur
    # effective dependante de l'ordre de lecture. Le postinst repasse a chaque
    # mise a jour, donc ce cas arrive vraiment.
    cfg = tmp_path / "lxc" / "peertube" / "config"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(CONFIG_SANS_BORNE)
    env = dict(os.environ, SECUBOX_LXC_PATH=str(tmp_path / "lxc"))
    for _ in range(3):
        subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True)
    assert len(lignes_borne(cfg.read_text())) == 1


def test_une_borne_differente_est_corrigee_pas_dupliquee(tmp_path):
    # Un operateur ayant pose sa propre valeur a la main doit se voir corrige
    # par le paquet, sans qu'une ligne morte ne subsiste au-dessus.
    avant = CONFIG_SANS_BORNE + "lxc.cgroup2.cpu.max = 400000 100000\n"
    sortie, journal = lance(tmp_path, avant)
    assert lignes_borne(sortie) == ["lxc.cgroup2.cpu.max = 100000 100000"]
    assert "400000 100000 -> 100000 100000" in journal


def test_sans_conteneur_installe_le_script_ne_cree_rien(tmp_path):
    # Le postinst tourne sur des boards ou `peertubectl install` n'a jamais ete
    # lance. Fabriquer une configuration sans conteneur laisserait un arbre LXC
    # incoherent — et ferait echouer le provisionnement suivant.
    env = dict(os.environ, SECUBOX_LXC_PATH=str(tmp_path / "vide"))
    r = subprocess.run(["bash", str(SCRIPT)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "vide").exists()


def test_la_borne_est_surchargeable(tmp_path):
    # Les boards n'ont pas toutes quatre coeurs : la valeur doit pouvoir suivre
    # sans modifier le paquet.
    sortie, _ = lance(tmp_path, CONFIG_SANS_BORNE, borne="200000 100000")
    assert lignes_borne(sortie) == ["lxc.cgroup2.cpu.max = 200000 100000"]
