# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-lo-alias (#3189) : 192.168.255.1 en /32 sur lo, sans jamais disparaitre.

Un /24 sur lo rend tout 192.168.255.0/24 local : la box repond a l'ARP de chaque
adresse et la detection de conflit des clients DHCP echoue. Un faux `ip` tient
l'etat de lo dans un fichier et journalise chaque appel.
"""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "usr" / "sbin" / "secubox-lo-alias"
WAIT = ROOT / "usr" / "bin" / "secubox-wait-network.sh"

FAUX_IP = r"""#!/usr/bin/env bash
state="$FAUX_IP_STATE"
echo "$*" >> "$FAUX_IP_JOURNAL"
case " $* " in
  *" show "*)
    while read -r a; do [ -n "$a" ] && echo "1: lo    inet $a scope global lo"; done < "$state"
    ;;
  *" add "*)
    for a in "$@"; do case "$a" in */*) echo "$a" >> "$state";; esac; done
    ;;
  *" del "*)
    for a in "$@"; do case "$a" in */*) grep -vxF "$a" "$state" > "$state.n" || true; mv "$state.n" "$state";; esac; done
    ;;
esac
"""


def lancer(tmp_path, etat, reseau=None):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    ip = bindir / "ip"
    ip.write_text(FAUX_IP)
    ip.chmod(0o755)
    state = tmp_path / "etat"
    state.write_text("".join(a + "\n" for a in etat))
    journal = tmp_path / "journal"
    journal.write_text("")
    audit = tmp_path / "audit.log"
    env = dict(os.environ,
               PATH=f"{bindir}:{os.environ['PATH']}",
               FAUX_IP_STATE=str(state), FAUX_IP_JOURNAL=str(journal),
               SECUBOX_AUDIT_LOG=str(audit),
               SECUBOX_LO_NETWORK=str(reseau or tmp_path / "absent.network"))
    r = subprocess.run(["bash", str(TOOL)], env=env, capture_output=True,
                       text=True, timeout=30)
    appels = [l for l in journal.read_text().splitlines()
              if " add " in f" {l} " or " del " in f" {l} "]
    adresses = [l for l in state.read_text().splitlines() if l]
    lignes = audit.read_text().splitlines() if audit.exists() else []
    return r, appels, adresses, lignes


def test_24_devient_32_sans_fenetre(tmp_path):
    r, appels, adresses, _ = lancer(tmp_path, ["127.0.0.1/8", "192.168.255.1/24"])
    assert r.returncode == 0, r.stderr
    ajout = "addr add 192.168.255.1/32 dev lo"
    retrait = "addr del 192.168.255.1/24 dev lo"
    assert ajout in appels and retrait in appels
    assert appels.index(ajout) < appels.index(retrait)
    assert "192.168.255.1/32" in adresses and "192.168.255.1/24" not in adresses
    assert "127.0.0.1/8" in adresses


def test_absent_pose_32(tmp_path):
    r, appels, adresses, _ = lancer(tmp_path, [])
    assert r.returncode == 0, r.stderr
    assert appels == ["addr add 192.168.255.1/32 dev lo"]
    assert adresses == ["192.168.255.1/32"]


def test_deja_32_ne_fait_rien(tmp_path):
    r, appels, _, audit = lancer(tmp_path, ["192.168.255.1/32"])
    assert r.returncode == 0, r.stderr
    assert appels == []
    assert audit == []


def test_fichier_networkd_corrige(tmp_path):
    f = tmp_path / "00-lo.network"
    f.write_text("[Match]\nName=lo\n\n[Network]\nAddress=127.0.0.1/8\n"
                 "Address=192.168.255.1/24\n")
    f.chmod(0o644)
    r, _, _, audit = lancer(tmp_path, ["192.168.255.1/32"], reseau=f)
    assert r.returncode == 0, r.stderr
    txt = f.read_text()
    assert "Address=192.168.255.1/32\n" in txt
    assert "192.168.255.1/24" not in txt
    assert "Address=127.0.0.1/8\n" in txt
    sauve = tmp_path / "00-lo.network.avant-3189"
    assert sauve.exists() and "192.168.255.1/24" in sauve.read_text()
    assert oct(f.stat().st_mode & 0o777) == "0o644"
    lignes = [json.loads(l) for l in audit]
    assert any(l["module"] == "core" and l["action"] == "lo-alias-32" for l in lignes)
    assert all({"ts", "module", "action", "acteur", "detail"} <= set(l) for l in lignes)


def test_fichier_lien_symbolique_refuse(tmp_path):
    cible = tmp_path / "ailleurs.network"
    texte = "[Network]\nAddress=192.168.255.1/24\n"
    cible.write_text(texte)
    f = tmp_path / "00-lo.network"
    f.symlink_to(cible)
    r, _, _, _ = lancer(tmp_path, ["192.168.255.1/32"], reseau=f)
    assert r.returncode == 0, r.stderr
    assert cible.read_text() == texte
    assert f.is_symlink()
    assert not (tmp_path / "00-lo.network.avant-3189").exists()


def test_wait_network_appelle_l_outil():
    txt = WAIT.read_text()
    assert 'LOOPBACK_ALIAS="${SECUBOX_LOOPBACK_ALIAS:-192.168.255.1/32}"' in txt
    assert "secubox-lo-alias" in txt
    assert 'ip addr add "$LOOPBACK_ALIAS"' not in txt
