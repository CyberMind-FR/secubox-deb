# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — points « avant déploiement » des liens directs : nginx principal, prerm, postrm.

- le location qui proxifie vers p2p.sock sur les vhosts principaux VIDE X-SecuBox-Pair (défense en profondeur) ;
- prerm arrête la minuterie et le service secubox-maillage-pairs (et désactive la minuterie au retrait) ;
- postrm purge retire la carte nginx du jeton et le jeton (dossier seulement s'il est vide), jamais l'état p2p.
Les scripts de maintenance sont exécutés avec un faux systemctl (journal des appels) et des chemins de test."""
import os
import re
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
P2P_CONF = RACINE / "nginx" / "p2p.conf"


def test_vhost_principal_vide_l_en_tete_pair():
    t = P2P_CONF.read_text()
    bloc = t[t.index("location /api/v1/p2p/ {"):]
    bloc = bloc[:bloc.index("}")]
    assert "proxy_pass http://unix:/run/secubox/p2p.sock:/;" in bloc
    assert re.search(r'^\s*proxy_set_header X-SecuBox-Pair "";\s*$', bloc, re.M)


def _faux_systemctl(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    journal = tmp_path / "systemctl.log"
    for nom, code in (("systemctl", 'echo "$*" >> "%s"; exit 1' % journal), ("nginx", "exit 1")):
        f = bin_ / nom
        f.write_text("#!/bin/sh\n" + code + "\n")
        f.chmod(0o755)
    return bin_, journal


def _lancer(script, tmp_path, *args, **env_plus):
    bin_, journal = _faux_systemctl(tmp_path)
    env = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}", **env_plus)
    r = subprocess.run(["sh", str(RACINE / "debian" / script), *args], env=env, capture_output=True, text=True,
                       timeout=30)
    appels = journal.read_text().splitlines() if journal.exists() else []
    return r, appels


@pytest.mark.parametrize("action", ["remove", "upgrade", "deconfigure"])
def test_prerm_arrete_la_minuterie_et_le_service_sans_jamais_echouer(tmp_path, action):
    r, appels = _lancer("prerm", tmp_path, action)
    assert r.returncode == 0, r.stderr                  # systemctl en échec (faux) : prerm réussit quand même
    arrets = [a for a in appels if a.startswith("stop") and "secubox-maillage-pairs" in a]
    assert arrets and "secubox-maillage-pairs.timer" in arrets[0] and "secubox-maillage-pairs.service" in arrets[0]
    desactive = any(a.startswith("disable") and "secubox-maillage-pairs.timer" in a for a in appels)
    assert desactive is (action == "remove")            # une mise à jour garde la minuterie activée


def test_prerm_minuterie_arretee_avant_le_service_principal(tmp_path):
    _, appels = _lancer("prerm", tmp_path, "remove")
    i_min = next(i for i, a in enumerate(appels) if "secubox-maillage-pairs.timer" in a)
    i_p2p = next(i for i, a in enumerate(appels) if "secubox-p2p.service" in a)
    assert i_min < i_p2p


def _arbre(tmp_path):
    ngx = tmp_path / "secubox-p2p-pair.conf"
    ngx.write_text('map $p2p_pair_maille $p2p_pair_cle {\n    default "";\n}\n')
    secrets = tmp_path / "secrets" / "p2p"
    secrets.mkdir(parents=True)
    (secrets / "pair.token").write_text("ab" * 32 + "\n")
    etat = tmp_path / "var-lib-p2p"
    etat.mkdir()
    (etat / "wg_mesh.json").write_text("{}")
    env = {"SBX_P2P_PAIR_CONF": str(ngx), "SBX_P2P_SECRETS_DIR": str(secrets)}
    return ngx, secrets, etat, env


def test_postrm_purge_retire_la_carte_et_le_jeton(tmp_path):
    ngx, secrets, etat, env = _arbre(tmp_path)
    r, _ = _lancer("postrm", tmp_path, "purge", **env)
    assert r.returncode == 0, r.stderr
    assert not ngx.exists() and not secrets.exists()
    assert (etat / "wg_mesh.json").exists()


def test_postrm_purge_garde_le_dossier_s_il_contient_autre_chose(tmp_path):
    ngx, secrets, _, env = _arbre(tmp_path)
    (secrets / "wg-ephemeral.key").write_text("x")
    r, _ = _lancer("postrm", tmp_path, "purge", **env)
    assert r.returncode == 0 and not (secrets / "pair.token").exists() and (secrets / "wg-ephemeral.key").exists()


def test_postrm_remove_garde_la_carte_et_le_jeton(tmp_path):
    ngx, secrets, _, env = _arbre(tmp_path)
    r, _ = _lancer("postrm", tmp_path, "remove", **env)
    assert r.returncode == 0 and ngx.exists() and (secrets / "pair.token").exists()


def test_postrm_purge_sans_fichiers_ne_echoue_pas(tmp_path):
    env = {"SBX_P2P_PAIR_CONF": str(tmp_path / "absent.conf"), "SBX_P2P_SECRETS_DIR": str(tmp_path / "absent")}
    r, _ = _lancer("postrm", tmp_path, "purge", **env)
    assert r.returncode == 0, r.stderr


def test_postrm_ne_touche_jamais_l_etat_p2p():
    t = (RACINE / "debian" / "postrm").read_text()
    assert "/var/lib/secubox/p2p" not in t
    assert "/etc/nginx/secubox-p2p-pair.conf" in t and "/etc/secubox/secrets/p2p" in t
