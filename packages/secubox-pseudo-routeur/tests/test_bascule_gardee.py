# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


def _ctl(tmp_path, *args, sonde_active):
    etat = tmp_path / "sonde.json"
    etat.write_text(json.dumps({"echecs_consecutifs": 0 if sonde_active else 3, "actif": sonde_active}))
    b = tmp_path / "bin-sys"
    b.mkdir(exist_ok=True)
    (b / "systemctl").write_text("#!/bin/sh\nexit 0\n")  # jamais le vrai systemctl du poste de dev
    (b / "systemctl").chmod(0o755)
    env = {"PATH": f"{b}:/usr/bin:/bin", "SECUBOX_SONDE_ETAT": str(etat)}
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=20)


def _env_activer(tmp_path, ping_ok):
    b = tmp_path / "bin"
    b.mkdir()
    journal = tmp_path / "appels.log"
    for nom, corps in {
        "nft": f'echo "nft $*" >> {journal}',
        "sysctl": f'echo "sysctl $*" >> {journal}; [ "$1" = "-n" ] && echo 1; exit 0',
        "systemctl": f'echo "systemctl $*" >> {journal}',
        "ping": f"exit {0 if ping_ok else 1}",
        "freeboxctl": f'echo "freeboxctl $*" >> {journal}',
        "sudo": 'while [ "$1" = "-u" ] || [ "$1" = "-n" ]; do [ "$1" = "-u" ] && shift; shift; done; exec "$@"',
    }.items():
        (b / nom).write_text("#!/bin/sh\n" + corps + "\n")
        (b / nom).chmod(0o755)
    rep = tmp_path / "nftables.d"
    rep.mkdir()
    env = {"PATH": f"{b}:/usr/bin:/bin", "SECUBOX_PR_NFT": str(b / "nft"),
           "SECUBOX_PR_NFT_PERSIST": str(rep / "zz-secubox-pseudo-routeur.nft"),
           "SECUBOX_PR_FREEBOXCTL": str(b / "freeboxctl"),
           "SECUBOX_PR_AUDIT_LOG": str(tmp_path / "audit.log"),
           "SECUBOX_PR_CONF": str(tmp_path / "absent.toml"), "SECUBOX_PR_LAN_IF": "eth2",
           "SECUBOX_SONDE_ETAT": str(tmp_path / "sonde.json")}
    return env, journal


def test_activer_arme_la_sonde_puis_bascule(tmp_path):
    """#3803 : la sonde n'est active qu'une fois le transfert charge ; activer l'arme lui-meme."""
    env, journal = _env_activer(tmp_path, ping_ok=True)
    r = subprocess.run(["bash", str(CTL), "activer"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "freeboxctl passerelle-dhcp 192.168.1.200" in journal.read_text()


def test_activer_refuse_et_revient_si_le_controle_echoue(tmp_path):
    env, journal = _env_activer(tmp_path, ping_ok=False)
    r = subprocess.run(["bash", str(CTL), "activer"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 2
    assert "sonde" in r.stderr.lower()
    appels = journal.read_text()
    assert "passerelle-dhcp 192.168.1.200" not in appels
    assert "delete table inet secubox_pseudo_routeur" in appels


def test_retour_freebox_fonctionne_meme_sonde_inactive(tmp_path):
    r = _ctl(tmp_path, "retour-freebox", sonde_active=False)
    assert r.returncode in (0, 1)  # peut echouer sur l'appel reseau en test, jamais sur la garde elle-meme
    assert "sonde" not in (r.stderr or "").lower()


def test_commandes_ecrivantes_sortent_du_bac_a_sable():
    """#3803 : lance par l'API (ProtectSystem=strict), le ctl ne peut pas ecrire /etc/nftables.d ;
    activer / activer-transfert / retour-freebox se relancent en tache systemd transitoire."""
    src = CTL.read_text()
    assert "activer|activer-transfert|retour-freebox)" in src
    assert "exec systemd-run --quiet --wait --pipe --collect" in src
    assert "SECUBOX_PR_HORS_BAC" in src
