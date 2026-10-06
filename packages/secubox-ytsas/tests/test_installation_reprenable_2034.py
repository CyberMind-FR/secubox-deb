# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2034 — l'installation du LXC doit être reprenable.

Constaté sur gk3 : un provisionnement interrompu avant le marqueur de fin laissait un conteneur nu ;
install-lxc.sh relançait lxc-create et sortait en « Container already exists », l'application n'était jamais
déployée (Médiathèque en erreur). Si le conteneur existe, on ne le recrée pas et on n'ajoute pas un second
bloc lxc.net.0 à sa config : on le démarre et on poursuit. On exécute ici la section de création du script
avec de faux lxc-* ; rien n'est touché sur la machine."""
import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "lxc" / "install-lxc.sh"


def _section():
    texte = SCRIPT.read_text()
    debut = texte.index('mkdir -p "$STATE_DIR" "$DATA_DIR"')
    fin = texte.index('log "python version')
    return texte[debut:fin]


def _lancer(tmp_path, conteneur_existe):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "appels.log"
    for nom in ("lxc-create", "lxc-start", "lxc-info", "lxc-attach", "chown", "sleep", "apt-get"):
        f = bin_ / nom
        f.write_text(f'#!/bin/sh\necho "{nom} $*" >> "{journal}"\ncat > /dev/null 2>&1 < /dev/null || true\nexit 0\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    lxc = tmp_path / "lxc"
    (lxc / "ytsas").mkdir(parents=True)
    config = lxc / "ytsas" / "config"
    if conteneur_existe:
        config.write_text("lxc.net.0.type = veth\nlxc.idmap = u 0 100000 65536\n")
    else:
        # lxc-create (faux) ne crée rien : on lui fait écrire la config comme le ferait le gabarit
        (bin_ / "lxc-create").write_text(f'#!/bin/sh\necho "lxc-create $*" >> "{journal}"\n'
                                         f'printf "lxc.net.0.type = veth\\nlxc.idmap = u 0 100000 65536\\n" > "{config}"\nexit 0\n')
        (bin_ / "lxc-create").chmod(0o755)
    entete = f'''set -euo pipefail
LXC_NAME=ytsas; LXC_PATH="{lxc}"; LXC_BRIDGE=br-lxc; LXC_GW=10.100.0.1; LXC_IP=10.100.0.180; LXC_VETH=veth-ytsas0
DATA_DIR="{tmp_path / "data"}"; STATE_DIR="{tmp_path / "etat"}"; SENTINEL="$STATE_DIR/.lxc-provisioned"; LXC_ROOT_UID=100000
log() {{ :; }}
la() {{ lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }}
'''
    script = tmp_path / "section.sh"
    script.write_text(entete + _section())
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}")
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
    appels = journal.read_text() if journal.exists() else ""
    return r, appels, config.read_text()


def test_conteneur_existant_n_est_pas_recree(tmp_path):
    r, appels, config = _lancer(tmp_path, conteneur_existe=True)
    assert r.returncode == 0, r.stderr
    assert "lxc-create" not in appels
    assert config.count("lxc.net.0.type") == 1          # aucun second bloc réseau ajouté
    assert "lxc-start" in appels                         # mais il est démarré
    assert (tmp_path / "etat" / ".lxc-provisioned").exists()


def test_conteneur_absent_est_cree_comme_avant(tmp_path):
    r, appels, config = _lancer(tmp_path, conteneur_existe=False)
    assert r.returncode == 0, r.stderr
    assert "lxc-create" in appels and "lxc-start" in appels
    assert "10.100.0.180/24" in config                   # le bloc réseau statique est bien ajouté
