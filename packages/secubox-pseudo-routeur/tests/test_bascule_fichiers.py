# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3803 relecture : double tampon du fichier persistant, retour-freebox audite."""
import os
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


def _faux(binaires, nom, corps):
    p = binaires / nom
    p.write_text("#!/bin/sh\n" + corps + "\n")
    p.chmod(0o755)


def _env(tmp_path, nft_corps):
    b = tmp_path / "bin"
    b.mkdir()
    journal = tmp_path / "appels.log"
    _faux(b, "nft", f'echo "nft $*" >> {journal}\n' + nft_corps)
    _faux(b, "sudo", 'while [ "$1" = "-u" ] || [ "$1" = "-n" ]; do [ "$1" = "-u" ] && shift; shift; done; exec "$@"')
    _faux(b, "freeboxctl", f'echo "freeboxctl $*" >> {journal}')
    _faux(b, "sysctl", f'echo "sysctl $*" >> {journal}')
    rep = tmp_path / "nftables.d"
    rep.mkdir()
    return {"PATH": f"{b}:/usr/bin:/bin", "SECUBOX_PR_NFT": str(b / "nft"),
            "SECUBOX_PR_NFT_PERSIST": str(rep / "zz-secubox-pseudo-routeur.nft"),
            "SECUBOX_PR_FREEBOXCTL": str(b / "freeboxctl"),
            "SECUBOX_PR_AUDIT_LOG": str(tmp_path / "audit.log"),
            "SECUBOX_PR_CONF": str(tmp_path / "absent.toml"),
            "SECUBOX_PR_LAN_IF": "eth2"}, rep, journal


def _ctl(env, *args):
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=30)


def test_nft_c_en_echec_laisse_le_fichier_precedent(tmp_path):
    env, rep, journal = _env(tmp_path, '[ "$1" = "-c" ] && exit 1; exit 0')
    persistant = rep / "zz-secubox-pseudo-routeur.nft"
    persistant.write_text("ANCIEN\n")
    r = _ctl(env, "activer-transfert")
    assert r.returncode != 0
    assert persistant.read_text() == "ANCIEN\n"
    assert sorted(os.listdir(rep)) == ["zz-secubox-pseudo-routeur.nft"]  # temporaire supprime
    appels = journal.read_text()
    assert "nft -f" not in appels.replace("nft -c -f", "") and "sysctl" not in appels


def test_activer_transfert_valide_puis_renomme(tmp_path):
    env, rep, journal = _env(tmp_path, "exit 0")
    r = _ctl(env, "activer-transfert")
    assert r.returncode == 0, r.stderr
    assert sorted(os.listdir(rep)) == ["zz-secubox-pseudo-routeur.nft"]
    assert (rep / "zz-secubox-pseudo-routeur.nft").read_text().startswith("table inet secubox_pseudo_routeur {}")
    lignes = [l for l in journal.read_text().splitlines() if l.startswith(("nft -c", "nft -f"))]
    assert lignes[0].startswith("nft -c -f ") and "/.zz-secubox-pseudo-routeur." in lignes[0]
    assert lignes[1] == f"nft -f {rep / 'zz-secubox-pseudo-routeur.nft'}"


def test_retour_freebox_suppression_en_echec_audite_mais_dhcp_rendu(tmp_path):
    # delete echoue, la table reste listee
    env, rep, journal = _env(tmp_path, '[ "$1" = "delete" ] && exit 1; exit 0')
    (rep / "zz-secubox-pseudo-routeur.nft").write_text("x\n")
    r = _ctl(env, "retour-freebox")
    assert r.returncode == 0, r.stderr
    assert "toujours presente" in r.stderr
    assert "retour_freebox_table_restante" in (tmp_path / "audit.log").read_text()
    assert not (rep / "zz-secubox-pseudo-routeur.nft").exists()
    assert "freeboxctl passerelle-dhcp 192.168.1.254" in journal.read_text()


def test_retour_freebox_nominal_sans_audit(tmp_path):
    env, rep, journal = _env(tmp_path, '[ "$1" = "list" ] && exit 1; exit 0')
    r = _ctl(env, "retour-freebox")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "audit.log").exists()
    assert "freeboxctl passerelle-dhcp 192.168.1.254" in journal.read_text()
