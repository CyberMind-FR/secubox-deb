# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Task 10 (#3126) : l'écouteur de tunnel (secubox-pilotage-ecoute) — nginx sur les seules IP de tunnel, règles nft insérées à chaud.

Les commandes du système (ip, nginx, nft, systemctl) sont de faux exécutables posés en tête du PATH ; les fichiers vivent sous une racine
temporaire (PILOTAGE_ECOUTE_RACINE)."""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
SCRIPT = ICI / "sbin" / "secubox-pilotage-ecoute"
REGLE_MESH = 'iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8472 accept'
REGLE_AUTOLOAD = 'iifname "wg-autoload" ip saddr 10.64.0.0/16 tcp dport 8472 accept'
NFTABLES = """#!/usr/sbin/nft -f
flush ruleset
table inet secubox_filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iifname "lo" accept
        drop
    }
}
"""


def _faux(chemin: Path, corps: str) -> None:
    chemin.write_text("#!/bin/sh\n" + corps)
    chemin.chmod(chemin.stat().st_mode | stat.S_IXUSR)


@pytest.fixture()
def banc(tmp_path):
    racine = tmp_path / "racine"
    (racine / "etc/nginx/conf.d").mkdir(parents=True)
    (racine / "usr/share/secubox/pilotage").mkdir(parents=True)
    (racine / "usr/share/secubox/pilotage/pilotage-canal.conf.tpl").write_text((ICI / "nginx/pilotage-canal.conf.tpl").read_text())
    (racine / "etc/nftables.conf").write_text(NFTABLES)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    etat = tmp_path / "etat"
    etat.mkdir()
    (etat / "chaine").write_text("")
    _faux(bin_ / "ip", 'for a in "$@"; do i="$a"; done\n'
                       'case "$i" in wg-mesh) [ -n "$BANC_MESH" ] && echo "7: wg-mesh    inet $BANC_MESH/24 scope global wg-mesh";;\n'
                       'wg-autoload) [ -n "$BANC_AUTOLOAD" ] && echo "8: wg-autoload    inet $BANC_AUTOLOAD/16 scope global wg-autoload";; esac\nexit 0\n')
    _faux(bin_ / "nginx", 'echo nginx "$@" >> "$BANC_ETAT/appels"\n[ -z "$BANC_NGINX_REFUSE" ]\n')
    _faux(bin_ / "systemctl", 'echo systemctl "$@" >> "$BANC_ETAT/appels"\n')
    _faux(bin_ / "nft", 'case "$1" in\n'
                        '  -c) echo nft "$@" >> "$BANC_ETAT/appels";;\n'
                        '  list) cat "$BANC_ETAT/chaine";;\n'
                        '  insert) shift 5; echo "$*" >> "$BANC_ETAT/chaine"; echo "insert $*" >> "$BANC_ETAT/appels";;\n'
                        'esac\nexit 0\n')
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "PILOTAGE_ECOUTE_RACINE": str(racine), "BANC_ETAT": str(etat),
           "BANC_MESH": "10.10.0.1", "BANC_AUTOLOAD": "10.64.0.1"}
    env.pop("BANC_NGINX_REFUSE", None)

    class Banc:
        pass

    b = Banc()
    b.racine, b.etat, b.env = racine, etat, env
    b.conf = racine / "etc/nginx/conf.d/secubox-pilotage-canal.conf"
    b.nft = racine / "etc/nftables.conf"

    def lancer(**surcharge):
        e = {**env, **surcharge}
        for k in [k for k, v in e.items() if v is None]:
            del e[k]
        return subprocess.run(["bash", str(SCRIPT)], env=e, capture_output=True, text=True, timeout=30)

    b.lancer = lancer
    b.appels = lambda: (etat / "appels").read_text() if (etat / "appels").exists() else ""
    return b


def test_ecouteur_seulement_sur_les_ip_de_tunnel(banc):
    r = banc.lancer()
    assert r.returncode == 0, r.stderr
    rendu = banc.conf.read_text()
    assert re.findall(r"^\s*listen\s+(\S+);", rendu, re.M) == ["10.10.0.1:8472", "10.64.0.1:8472"]
    assert "0.0.0.0" not in rendu and not re.search(r"listen\s+(\[::\]:)?8472", rendu)
    assert rendu.count("proxy_pass http://unix:/run/secubox/pilotage-canal.sock") >= 2
    assert rendu.count("proxy_set_header X-Real-IP $remote_addr;") >= 2
    assert rendu.count("client_max_body_size 256k;") >= 2 and rendu.count("proxy_read_timeout 60s;") >= 2
    assert "allow 10.10.0.0/24;" in rendu and "allow 10.64.0.0/16;" in rendu and "deny all;" in rendu
    assert "pilotage.sock" not in rendu.replace("pilotage-canal.sock", "")   # la socket d'administration n'est jamais exposée


def test_un_seul_tunnel_present(banc):
    r = banc.lancer(BANC_AUTOLOAD=None)
    assert r.returncode == 0, r.stderr
    rendu = banc.conf.read_text()
    assert "10.10.0.1:8472" in rendu and "10.64.0.1" not in rendu
    # une adresse de tunnel qui n'est pas celle du maître n'ouvre rien
    r = banc.lancer(BANC_MESH="10.10.0.7", BANC_AUTOLOAD=None)
    assert r.returncode == 0, r.stderr
    assert not banc.conf.exists()


def test_ecouteur_retire_si_nginx_refuse(banc):
    r = banc.lancer(BANC_NGINX_REFUSE="1")
    assert r.returncode == 0, r.stderr
    assert not banc.conf.exists()
    assert not list(banc.conf.parent.glob("*pilotage*")) and not list(banc.conf.parent.glob(".*"))   # aucun temporaire laissé


def test_pas_de_rechargement_si_le_rendu_ne_change_pas(banc):
    assert banc.lancer().returncode == 0
    assert banc.appels().count("systemctl reload nginx") == 1
    assert banc.lancer().returncode == 0
    assert banc.appels().count("systemctl reload nginx") == 1


def test_fichier_retire_quand_les_interfaces_disparaissent(banc):
    banc.lancer()
    assert banc.conf.exists()
    r = banc.lancer(BANC_MESH=None, BANC_AUTOLOAD=None)
    assert r.returncode == 0 and not banc.conf.exists()
    assert banc.appels().count("systemctl reload nginx") == 2


def test_regles_nft_avant_le_drop_et_idempotentes(banc):
    assert banc.lancer().returncode == 0
    lignes = [x.strip() for x in banc.nft.read_text().splitlines()]
    assert REGLE_MESH in lignes and REGLE_AUTOLOAD in lignes
    drop = lignes.index("drop")
    assert lignes.index(REGLE_MESH) < drop and lignes.index(REGLE_AUTOLOAD) < drop
    chaine = (banc.etat / "chaine").read_text()
    assert REGLE_MESH in chaine and REGLE_AUTOLOAD in chaine
    avant_fichier, avant_appels = banc.nft.read_text(), banc.appels()
    assert banc.lancer().returncode == 0
    assert banc.nft.read_text() == avant_fichier                       # fichier inchangé
    assert banc.appels().count("insert") == avant_appels.count("insert") == 2   # aucune insertion de plus
    assert banc.nft.read_text().count("dport 8472") == 2


def test_jamais_nft_f_du_fichier_entier(banc):
    banc.lancer()
    for ligne in banc.appels().splitlines():
        if ligne.startswith("nft "):
            assert ligne.startswith("nft -c -f ")                      # validation à blanc seulement
    source = SCRIPT.read_text()
    assert not re.search(r"^\s*nft -f", source, re.M)


def test_regle_vive_reparee_si_disparue(banc):
    banc.lancer()
    (banc.etat / "chaine").write_text("")
    banc.lancer()
    chaine = (banc.etat / "chaine").read_text()
    assert REGLE_MESH in chaine and REGLE_AUTOLOAD in chaine
    assert banc.nft.read_text().count("dport 8472") == 2               # le fichier n'a pas doublé


def test_regle_seulement_pour_le_tunnel_present(banc):
    banc.lancer(BANC_AUTOLOAD=None)
    assert REGLE_MESH in banc.nft.read_text() and REGLE_AUTOLOAD not in banc.nft.read_text()


def test_fichier_nft_sans_table_secubox_filter_intact(banc):
    banc.nft.write_text("table inet filter {\n chain input {\n drop\n }\n}\n")
    banc.lancer()
    assert banc.nft.read_text() == "table inet filter {\n chain input {\n drop\n }\n}\n"


def test_script_sain():
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
