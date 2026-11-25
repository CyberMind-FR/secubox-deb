# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Budget mémoire des conteneurs LXC (#3941) : jamais de frein sous le plafond quand l'échange est interdit.

Cas de référence relevé sur gk2 : gitea à `high = 384M` sous `max = 512M`, échange à 0, 393 Mo de mémoire anonyme —
13 700 relectures de pages par seconde et un conteneur bloqué 48 % du temps. Faux arbre LXC et faux cgroups.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
OUTIL = RACINE / "sbin" / "secubox-lxc-memoire"
TUNING = RACINE / "sbin" / "secubox-tuning-apply"

PHASE = "# Phase 6.P (#496) : memory budget\n"
GITEA = ("lxc.uts.name = gitea\n" + PHASE * 12 + "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 0\n"
         "lxc.cgroup2.memory.high = 384M\nlxc.start.auto = 1\n")
NEXTCLOUD = "lxc.uts.name = nextcloud\n" + PHASE + "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 0\n"
ROUNDCUBE = "lxc.cgroup2.memory.max = 256M\nlxc.cgroup2.memory.high = 200M\nlxc.cgroup2.memory.swap.max = 0\n"
MAIL = ("# Mémoire du conteneur (secubox-mail) — bloc unique, réécrit par le paquet\nlxc.cgroup2.memory.max = 1G\n"
        "lxc.cgroup2.memory.high = 900M\nlxc.cgroup2.memory.swap.max = 0\n")
SANS_BUDGET = "lxc.uts.name = lyrion\nlxc.start.auto = 1\n"


class Banc:
    def __init__(self, tmp: Path):
        self.lxc, self.cg, self.caps = tmp / "lxc", tmp / "cg", tmp / "caps.toml"
        self.lxc.mkdir()
        self.cg.mkdir()
        self.env = {"PATH": "/usr/sbin:/usr/bin:/bin", "SECUBOX_LXC_RACINES": f"{self.lxc}:{tmp}/absent",
                    "SECUBOX_CGROUP_RACINE": str(self.cg), "SECUBOX_TUNING_LXC_CAPS": str(self.caps),
                    "SECUBOX_TUNING_CONFIG": str(tmp / "config.toml")}

    def conteneur(self, nom, config, **cgroup):
        d = self.lxc / nom
        d.mkdir()
        (d / "config").write_text(config)
        os.chmod(d / "config", 0o640)
        if cgroup:
            c = self.cg / f"lxc.payload.{nom}"
            c.mkdir()
            for cle, val in cgroup.items():
                (c / ("memory." + cle.replace("_", "."))).write_text(val + "\n")

    def outil(self, *args):
        return subprocess.run([sys.executable, "-I", str(OUTIL), *args], env=self.env, capture_output=True, text=True, timeout=60)

    def tuning(self, caps, *args):
        self.caps.write_text("[caps]\n" + "".join(f'{k} = "{v}"\n' for k, v in caps.items()))
        source = TUNING.read_text().replace('"/data/lxc/${ctn}/config"', f'"{self.lxc}/${{ctn}}/config"')
        faux = self.caps.parent / "secubox-tuning-apply"
        faux.write_text(source)
        env = dict(self.env, SECUBOX_LXC_MEMOIRE=str(OUTIL))
        return subprocess.run(["bash", str(faux), "cgroup", *args], env=env, capture_output=True, text=True, timeout=60)

    def config(self, nom):
        return (self.lxc / nom / "config").read_text()

    def vif(self, nom, cle):
        return (self.cg / f"lxc.payload.{nom}" / f"memory.{cle}").read_text().strip()


@pytest.fixture
def banc(tmp_path):
    return Banc(tmp_path)


def test_gitea_frein_retire_echange_borne_commentaires_replies(banc):
    banc.conteneur("gitea", GITEA, max="536870912", high="402653184", swap_max="0")
    r = banc.outil("migrer")
    assert r.returncode == 0, r.stderr
    c = banc.config("gitea")
    assert "memory.high" not in c and "Phase 6.P" not in c
    assert c.count("lxc.cgroup2.memory.max = 512M\n") == 1 and c.count("lxc.cgroup2.memory.") == 2
    assert c.count("lxc.cgroup2.memory.swap.max = 256M\n") == 1
    assert "lxc.uts.name = gitea\n" in c and "lxc.start.auto = 1\n" in c
    assert (banc.vif("gitea", "high"), banc.vif("gitea", "swap.max"), banc.vif("gitea", "max")) == ("max", "256M", "536870912")
    assert "gitea" in r.stdout and "384M" in r.stdout and "256M" in r.stdout
    assert (banc.lxc / "gitea" / "config.avant-3941").read_text() == GITEA
    assert (banc.lxc / "gitea" / "config").stat().st_mode & 0o777 == 0o640


def test_idempotent_et_copie_jamais_ecrasee(banc):
    banc.conteneur("gitea", GITEA)
    banc.outil("migrer")
    apres = banc.config("gitea")
    r = banc.outil("migrer")
    assert banc.config("gitea") == apres and "gitea" not in r.stdout
    assert (banc.lxc / "gitea" / "config.avant-3941").read_text() == GITEA


def test_nextcloud_sans_frein_echange_interdit_par_l_ancien_budget(banc):
    banc.conteneur("nextcloud", NEXTCLOUD, max="536870912", high="max", swap_max="0")
    banc.outil("migrer")
    assert "lxc.cgroup2.memory.swap.max = 256M\n" in banc.config("nextcloud")
    assert banc.vif("nextcloud", "swap.max") == "256M" and banc.vif("nextcloud", "high") == "max"


def test_roundcube_frein_sous_plafond_quelle_que_soit_l_origine(banc):
    banc.conteneur("roundcube", ROUNDCUBE)
    banc.outil("migrer")
    assert banc.config("roundcube") == ("lxc.cgroup2.memory.max = 256M\n"
                                        "lxc.cgroup2.memory.swap.max = 128M\n")


def test_choix_local_sans_marque_ni_frein_non_touche(banc):
    local = "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 0\n"
    banc.conteneur("perso", local)
    r = banc.outil("migrer")
    assert banc.config("perso") == local and not (banc.lxc / "perso" / "config.avant-3941").exists()
    assert "perso" in r.stdout and "choix local" in r.stdout


def test_frein_sous_plafond_avec_echange_borne_non_touche(banc):
    ok = "lxc.cgroup2.memory.high = 1500M\nlxc.cgroup2.memory.max = 2G\nlxc.cgroup2.memory.swap.max = 1G\n"
    banc.conteneur("peertube", ok)
    libre = "lxc.cgroup2.memory.high = 1400M\nlxc.cgroup2.memory.max = 1800M\n"
    banc.conteneur("clamav", libre)
    assert banc.outil("migrer").stdout.strip() == ""
    assert banc.config("peertube") == ok and banc.config("clamav") == libre


def test_mail_bloc_du_paquet_non_touche(banc):
    banc.conteneur("mail", MAIL, max="1073741824", high="943718400", swap_max="0")
    banc.outil("migrer")
    assert banc.config("mail") == MAIL and banc.vif("mail", "high") == "943718400"


def test_derniere_ligne_gagne_et_unites_sans_espaces(banc):
    banc.conteneur("x", "lxc.cgroup2.memory.max=2G\nlxc.cgroup2.memory.high=100M\nlxc.cgroup2.memory.swap.max=0\n"
                        "lxc.cgroup2.memory.max = 300M\n")
    banc.outil("migrer")
    assert banc.config("x") == "lxc.cgroup2.memory.max = 300M\nlxc.cgroup2.memory.swap.max = 150M\n"


def test_pas_d_ecriture_a_travers_un_lien(banc, tmp_path):
    cible = tmp_path / "cible"
    cible.write_text(GITEA)
    (banc.lxc / "lien").mkdir()
    (banc.lxc / "lien" / "config").symlink_to(cible)
    r = banc.outil("migrer")
    assert cible.read_text() == GITEA and "lien" in r.stderr


def test_dry_run_n_ecrit_rien(banc):
    banc.conteneur("gitea", GITEA, max="536870912", high="402653184", swap_max="0")
    r = banc.outil("migrer", "--dry-run")
    assert banc.config("gitea") == GITEA and banc.vif("gitea", "high") == "402653184" and "gitea" in r.stdout


def test_frein_vif_seul_retire_meme_si_la_config_est_saine(banc):
    """Config corrigée à la main, conteneur encore lancé avec les anciennes limites."""
    banc.conteneur("gitea", "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.swap.max = 256M\n",
                   max="536870912", high="402653184", swap_max="0")
    banc.outil("migrer")
    assert banc.vif("gitea", "high") == "max" and banc.vif("gitea", "swap.max") == "256M"


def test_seulement_les_conteneurs_nommes(banc):
    banc.conteneur("gitea", GITEA)
    banc.conteneur("roundcube", ROUNDCUBE)
    banc.outil("migrer", "gitea")
    assert banc.config("roundcube") == ROUNDCUBE and banc.config("gitea") != GITEA


def test_sans_aucun_conteneur(banc):
    r = banc.outil("migrer")
    assert r.returncode == 0 and r.stdout.strip() == ""


# ── secubox-tuning-apply ──

def test_tuning_jamais_de_frein_sous_un_budget_propre(banc):
    """500M < 1G (mail), 200M < 256M (roundcube) : l'ancien test « cap >= max » laissait poser le frein."""
    banc.conteneur("roundcube", "lxc.cgroup2.memory.max = 256M\nlxc.cgroup2.memory.high = 200M\n",
                   max="268435456", high="209715200", swap_max="max")
    banc.conteneur("mail", MAIL, max="1073741824", high="943718400", swap_max="0")
    r = banc.tuning({"roundcube": "200M", "mail": "500M"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "memory.high" not in banc.config("roundcube") and banc.vif("roundcube", "high") == "max"
    assert "budget propre" in r.stdout + r.stderr and "200M" in r.stdout + r.stderr
    assert banc.config("mail") == MAIL and banc.vif("mail", "high") == "943718400", "bloc de secubox-mail"


def test_tuning_frein_herite_de_l_ancien_clamp_retire(banc):
    banc.conteneur("nextcloud", "lxc.cgroup2.memory.max = 512M\nlxc.cgroup2.memory.high = 435M\n")
    banc.tuning({"nextcloud": "600M"})
    assert "memory.high" not in banc.config("nextcloud")


def test_tuning_budget_vif_sans_ligne_de_config(banc):
    banc.conteneur("matrix", SANS_BUDGET, max="402653184", high="max", swap_max="max")
    banc.tuning({"matrix": "300M"})
    assert banc.vif("matrix", "high") == "max" and "memory.high" not in banc.config("matrix")


def test_tuning_sans_budget_propre_inchange(banc):
    banc.conteneur("lyrion", SANS_BUDGET, max="max", high="max", swap_max="max")
    banc.tuning({"lyrion": "500M"})
    assert "lxc.cgroup2.memory.high = 500M\n" in banc.config("lyrion") and banc.vif("lyrion", "high") == "500M"
    avant = banc.config("lyrion")
    banc.tuning({"lyrion": "500M"})
    assert banc.config("lyrion") == avant


def test_tuning_max_infini_n_est_pas_un_budget(banc):
    banc.conteneur("lyrion", "lxc.cgroup2.memory.max = max\n")
    banc.tuning({"lyrion": "500M"})
    assert "lxc.cgroup2.memory.high = 500M" in banc.config("lyrion")


def test_tuning_echange_interdit_sans_budget_pas_de_frein(banc):
    banc.conteneur("mqtt", "lxc.cgroup2.memory.swap.max = 0\n")
    r = banc.tuning({"mqtt": "150M"})
    assert "memory.high" not in banc.config("mqtt") and "mqtt" in r.stdout + r.stderr


def test_tuning_dry_run(banc):
    avant = "lxc.cgroup2.memory.max = 256M\nlxc.cgroup2.memory.high = 200M\n"
    banc.conteneur("roundcube", avant)
    banc.tuning({"roundcube": "200M"}, "--dry-run")
    assert banc.config("roundcube") == avant


def test_tuning_sans_l_outil_ne_pose_aucun_frein(banc):
    banc.conteneur("roundcube", "lxc.cgroup2.memory.max = 256M\n")
    banc.caps.write_text('[caps]\nroundcube = "200M"\n')
    source = TUNING.read_text().replace('"/data/lxc/${ctn}/config"', f'"{banc.lxc}/${{ctn}}/config"')
    faux = banc.caps.parent / "t"
    faux.write_text(source)
    subprocess.run(["bash", str(faux), "cgroup"], env=dict(banc.env, SECUBOX_LXC_MEMOIRE="/nexiste/pas"), timeout=60)
    assert "memory.high" not in banc.config("roundcube")


def test_paquet_installe_l_outil_et_migre_au_configure():
    rules = (RACINE.parents[1] / "debian" / "rules").read_text()
    assert "system-tuning/sbin/secubox-lxc-memoire" in rules
    pi = (RACINE / "debian" / "postinst").read_text()
    assert "secubox-lxc-memoire migrer" in pi
    assert pi.index("secubox-lxc-memoire migrer") < pi.index("/usr/sbin/secubox-tuning-apply ||")
    texte = OUTIL.read_text()
    for interdit in ("lxc-stop", "lxc-start", "lxc-attach", "subprocess", "os.system"):
        assert interdit not in texte
