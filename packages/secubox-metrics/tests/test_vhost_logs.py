# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-vhost-logs ne doit restaurer QUE ce que sa passe a touche (#1777).

Sur gk2, le 2026-09-30, un `nginx -t` deja en echec (une route en double, sans
rapport) a declenche la « restauration » de la version 1.0.0 : elle a recopie
les 90 sauvegardes accumulees depuis mai. Six vhosts decommissionnes sont
revenus, des vhosts vivants ont repris leur contenu d'aout, et `cp` sur des
liens symboliques a ecrit DANS sites-available (nextcloud, peertube, Hall).

Ces tests executent le vrai script, avec `nginx` et `systemctl` remplaces par
des doublures dont on regle le verdict appel par appel.
"""

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "sbin" / "secubox-vhost-logs"
LIGNE = "access_log /var/log/nginx/secubox-hosts.log sbx_host;"
VHOST = "server {\n    listen 9080;\n    access_log /var/log/nginx/x.log;\n}\n"


def _banc(tmp_path, verdicts):
    """Arborescence sites-available/sites-enabled + doublures nginx/systemctl.

    `verdicts` : codes de retour successifs de `nginx -t` (le dernier se
    repete).
    """
    sa = tmp_path / "sites-available"
    se = tmp_path / "sites-enabled"
    sauv = tmp_path / "sauvegardes"
    bin_ = tmp_path / "bin"
    for d in (sa, se, sauv, bin_):
        d.mkdir()
    etat = tmp_path / "nginx-appels"
    etat.write_text("0")
    (tmp_path / "nginx-verdicts").write_text(" ".join(str(v) for v in verdicts))
    nginx = bin_ / "nginx"
    nginx.write_text(
        "#!/bin/bash\n"
        f"n=$(cat {etat}); echo $((n+1)) > {etat}\n"
        f"set -- $(cat {tmp_path / 'nginx-verdicts'})\n"
        "shift $(( n < $# ? n : $# - 1 ))\n"
        "exit $1\n"
    )
    systemctl = bin_ / "systemctl"
    systemctl.write_text("#!/bin/sh\nexit 0\n")
    for f in (nginx, systemctl):
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    return sa, se, sauv, bin_


def _lancer(se, sauv, bin_):
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", SAUVEGARDES=str(sauv))
    return subprocess.run(
        ["bash", str(SCRIPT), str(se), "--apply"],
        env=env, capture_output=True, text=True, timeout=30,
    )


def test_rien_nest_touche_quand_nginx_echoue_deja(tmp_path):
    sa, se, sauv, bin_ = _banc(tmp_path, [1])
    (sa / "a.conf").write_text(VHOST)
    (se / "a.conf").symlink_to("../sites-available/a.conf")
    (se / "b.conf").write_text(VHOST)

    r = _lancer(se, sauv, bin_)

    assert r.returncode != 0
    assert "AVANT toute modification" in r.stderr
    assert (se / "a.conf").is_symlink(), "le lien a ete remplace par un fichier"
    assert (sa / "a.conf").read_text() == VHOST
    assert (se / "b.conf").read_text() == VHOST
    assert list(sauv.iterdir()) == [], "une passe refusee ne sauvegarde rien"


def test_echec_apres_modification_rend_les_liens_et_rien_dautre(tmp_path):
    # 1er nginx -t (avant) passe, 2e (apres l'ajout) echoue.
    sa, se, sauv, bin_ = _banc(tmp_path, [0, 1])
    (sa / "a.conf").write_text(VHOST)
    (se / "a.conf").symlink_to("../sites-available/a.conf")
    (se / "b.conf").write_text(VHOST)
    # Sauvegardes d'autres passes, dont un vhost retire depuis : ne JAMAIS
    # les rendre (c'est ce qui a ressuscite les sites decommissionnes).
    (sauv / "retire.conf.20260817170712").write_text(VHOST)
    (sauv / "a.conf.avant-secubox-hosts").write_text("# contenu d'aout\n")
    (sauv / "b.conf.20260820062150").write_text("# ancienne version\n")

    r = _lancer(se, sauv, bin_)

    assert r.returncode != 0
    assert (se / "a.conf").is_symlink(), "le lien n'est pas revenu lien"
    assert os.readlink(se / "a.conf") == "../sites-available/a.conf"
    assert (sa / "a.conf").read_text() == VHOST, "la cible du lien a ete ecrasee"
    assert (se / "b.conf").read_text() == VHOST, "b.conf n'a pas repris son etat d'avant la passe"
    assert sorted(p.name for p in se.iterdir()) == ["a.conf", "b.conf"], (
        "une sauvegarde d'une autre passe a ete reposee dans sites-enabled"
    )


def test_succes_ajoute_la_ligne_et_garde_la_passe_a_part(tmp_path):
    sa, se, sauv, bin_ = _banc(tmp_path, [0])
    (se / "b.conf").write_text(VHOST)
    (se / "deja.conf").write_text(VHOST.replace("}\n", f"    {LIGNE}\n}}\n"))

    r = _lancer(se, sauv, bin_)

    assert r.returncode == 0, r.stderr
    assert (se / "b.conf").read_text().count(LIGNE) == 1
    assert (se / "deja.conf").read_text().count(LIGNE) == 1
    passes = [p for p in sauv.iterdir() if p.is_dir()]
    assert len(passes) == 1 and passes[0].name.startswith("passe-")
    assert [p.name for p in passes[0].iterdir()] == ["b.conf"]
