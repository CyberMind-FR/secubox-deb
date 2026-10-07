# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-system-tuning — bornes CPU declaratives (#1011).

Les tests s'exercent sur un FAUX arbre LXC monte dans un repertoire temporaire.
L'application a chaud (ecriture dans /sys/fs/cgroup) demande la racine et un
conteneur vivant : elle est verifiee sur la board, pas ici.

Le cas central est celui de `matrix`, releve verbatim sur gk2 : deux lignes
`cpu.max` dans la meme configuration, 200000 puis 60000. LXC retient la
derniere — on lisait donc deux coeurs en haut du fichier pendant que le
conteneur tournait a 0,6, sans que rien ne le signale.
"""

import subprocess
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
OUTIL = RACINE / "sbin" / "secubox-tuning-apply"
TOML_CPU = RACINE / "etc" / "secubox" / "tuning" / "lxc-cpu.toml"

CONFIG_NUE = """\
lxc.include = /usr/share/lxc/config/debian.common.conf
lxc.arch = linux64
lxc.cgroup2.memory.high = 400M
lxc.cgroup2.cpu.idle = 1
lxc.start.auto = 1
"""


def prepare(tmp_path, conteneurs, toml_texte):
    """Monte un faux /data/lxc et un lxc-cpu.toml, puis lance la phase cpu."""
    for nom, contenu in conteneurs.items():
        cfg = tmp_path / "lxc" / nom / "config"
        cfg.parent.mkdir(parents=True)
        cfg.write_text(contenu)
    (tmp_path / "tuning").mkdir()
    (tmp_path / "tuning" / "lxc-cpu.toml").write_text(toml_texte)

    # L'outil lit des chemins absolus : on les reecrit vers l'arbre temporaire.
    source = OUTIL.read_text() \
        .replace('LXC_CPU_FILE="/etc/secubox/tuning/lxc-cpu.toml"',
                 f'LXC_CPU_FILE="{tmp_path}/tuning/lxc-cpu.toml"') \
        .replace('"/data/lxc/${ctn}/config"', f'"{tmp_path}/lxc/${{ctn}}/config"')
    faux = tmp_path / "outil"
    faux.write_text(source)

    r = subprocess.run(["bash", str(faux), "cpu"], capture_output=True, text=True)
    return r


def lignes(tmp_path, nom, cle="lxc.cgroup2.cpu.max"):
    texte = (tmp_path / "lxc" / nom / "config").read_text()
    return [l for l in texte.splitlines() if l.strip().startswith(cle)]


def test_une_borne_est_posee_ou_il_n_y_en_avait_pas(tmp_path):
    r = prepare(tmp_path, {"gitea": CONFIG_NUE},
                '[max]\ngitea = "200000 100000"\n')
    assert r.returncode == 0, r.stderr
    assert lignes(tmp_path, "gitea") == ["lxc.cgroup2.cpu.max = 200000 100000"]


def test_le_doublon_de_matrix_est_replie_sur_une_seule_ligne(tmp_path):
    # LE CAS RELEVE SUR GK2. Deux lignes, la derniere gagnait en silence.
    double = CONFIG_NUE + ("lxc.cgroup2.cpu.max = 200000 100000\n"
                           "lxc.mount.entry = /data/matrix srv none bind 0 0\n"
                           "lxc.cgroup2.cpu.max = 60000 100000\n")
    r = prepare(tmp_path, {"matrix": double}, '[max]\nmatrix = "60000 100000"\n')
    assert r.returncode == 0, r.stderr
    assert lignes(tmp_path, "matrix") == ["lxc.cgroup2.cpu.max = 60000 100000"]
    # Le repli ne doit pas emporter ce qui separait les deux lignes.
    texte = (tmp_path / "lxc" / "matrix" / "config").read_text()
    assert "lxc.mount.entry = /data/matrix srv none bind 0 0" in texte


def test_repasser_ne_cree_pas_de_doublon(tmp_path):
    # Le postinst repasse a chaque mise a jour : le cas arrive vraiment.
    r = prepare(tmp_path, {"yacy": CONFIG_NUE}, '[max]\nyacy = "40000 100000"\n')
    assert r.returncode == 0, r.stderr
    # Deux passages de plus sur le MEME arbre, avec l'outil deja reecrit.
    for _ in range(2):
        again = subprocess.run(["bash", str(tmp_path / "outil"), "cpu"],
                               capture_output=True, text=True)
        assert again.returncode == 0, again.stderr
    assert len(lignes(tmp_path, "yacy")) == 1


def test_une_borne_commentee_n_est_pas_ressuscitee_ni_dupliquee(tmp_path):
    # `gitea`, `mail` et `nextcloud` portaient une borne ECRITE PUIS COMMENTEE.
    # La ligne commentee doit rester telle quelle — c'est une trace de decision
    # — et la borne active doit etre ajoutee sans la toucher.
    avec_commentaire = CONFIG_NUE + "#lxc.cgroup2.cpu.max = 100000 100000\n"
    r = prepare(tmp_path, {"mail": avec_commentaire},
                '[max]\nmail = "200000 100000"\n')
    assert r.returncode == 0, r.stderr
    texte = (tmp_path / "lxc" / "mail" / "config").read_text()
    assert "#lxc.cgroup2.cpu.max = 100000 100000" in texte
    assert lignes(tmp_path, "mail") == ["lxc.cgroup2.cpu.max = 200000 100000"]


def test_le_reste_de_la_configuration_survit(tmp_path):
    # La config porte le reseau et les montages : en perdre une ligne laisse le
    # conteneur sans adresse ou sans ses donnees.
    r = prepare(tmp_path, {"gitea": CONFIG_NUE}, '[max]\ngitea = "200000 100000"\n')
    assert r.returncode == 0
    texte = (tmp_path / "lxc" / "gitea" / "config").read_text()
    for ligne in CONFIG_NUE.splitlines():
        assert ligne in texte, f"ligne perdue : {ligne}"


def test_un_conteneur_declare_mais_absent_n_est_pas_une_erreur(tmp_path):
    # Le fichier decrit la flotte CIBLE : toutes les boards n'ont pas tout.
    # Fabriquer une config pour un conteneur inexistant casserait le
    # provisionnement suivant.
    r = prepare(tmp_path, {"gitea": CONFIG_NUE},
                '[max]\ngitea = "200000 100000"\nfantome = "100000 100000"\n')
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "lxc" / "fantome").exists()
    assert "non provisionne" in r.stdout


def test_la_phase_seule_sort_en_succes(tmp_path):
    # Sous `set -e`, un `[[ ... ]] && phase` final rendait 1 quand la phase
    # etait desactivee : `secubox-tuning-apply cpu` sortait en erreur apres
    # avoir parfaitement fonctionne, et un postinst l'appelant aurait echoue.
    r = prepare(tmp_path, {"gitea": CONFIG_NUE}, '[max]\ngitea = "200000 100000"\n')
    assert r.returncode == 0, f"sortie {r.returncode} : {r.stderr}"


# ── Le fichier livre ──────────────────────────────────────────────────────

def test_le_toml_livre_est_lisible_et_borne_tout_le_monde():
    d = tomllib.loads(TOML_CPU.read_text())
    assert "max" in d and d["max"], "aucune borne declaree"
    for nom, val in d["max"].items():
        quota, periode = val.split()
        assert periode == "100000", f"{nom}: periode inattendue {periode}"
        # `max` signifie AUCUN plafond : le fichier ne doit jamais en declarer,
        # sans quoi il desservirait exactement ce qu'il pretend garantir.
        assert quota != "max", f"{nom} declare une borne infinie"
        assert 0 < int(quota) <= 400000, f"{nom}: {val} hors de la board (4 coeurs)"


def test_peertube_reste_borne_a_un_coeur():
    # La borne de #1010 est reprise ici depuis le paquet secubox-peertube. La
    # perdre au passage annulerait le correctif qui a ramene la charge de 113 a
    # 63 — c'est la raison d'etre de ce test.
    d = tomllib.loads(TOML_CPU.read_text())
    assert d["max"]["peertube"] == "100000 100000"
