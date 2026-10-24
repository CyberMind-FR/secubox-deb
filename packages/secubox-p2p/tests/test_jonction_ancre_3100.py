# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — sbx-mesh-join n'accepte que le maître ancré ; sbx-mesh-up attend l'adresse.

Maître simulé : un faux `curl` et un faux `wg` en tête du PATH ; ancre, audit et état sont dans tmp_path.
"""
import base64
import json
import os
import subprocess
import textwrap
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
JOIN = PKG / "scripts" / "sbx-mesh-join"
UP = PKG / "scripts" / "sbx-mesh-up"
CLE_MAITRE = base64.b64encode(b"m" * 32).decode()
CLE_AUTRE = base64.b64encode(b"x" * 32).decode()
CLE_PAIR = base64.b64encode(b"p" * 32).decode()


def _env(tmp_path, cle_offerte):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    reponse = {"status": "approved", "depth": 1,
               "wg": {"master_public_key": cle_offerte, "master_port": 51822,
                      "master_mesh_ip": "10.10.0.1", "address": "10.10.0.7/24",
                      "network": "10.10.0.0/24"}}
    (tmp_path / "reponse.json").write_text(json.dumps(reponse, separators=(",", ":")))
    (bin_ / "curl").write_text(textwrap.dedent(f"""\
        #!/bin/sh
        case "$*" in
          *master-link/status*) echo '{{"role":"master"}}' ;;
          *) cat {tmp_path}/reponse.json ;;
        esac
        """))
    (bin_ / "wg").write_text(textwrap.dedent(f"""\
        #!/bin/sh
        case "$1" in genkey) echo {CLE_PAIR} ;; pubkey) cat >/dev/null; echo {CLE_PAIR} ;; esac
        """))
    for f in ("curl", "wg"):
        (bin_ / f).chmod(0o755)
    p2p = tmp_path / "p2p"
    p2p.mkdir()
    (p2p / "node.id").write_text("sbx-test\n")
    etat = {"private_key": CLE_PAIR, "public_key": CLE_PAIR, "listen_port": 51822,
            "peers": [], "role": "peer"}
    (p2p / "wg_mesh.json").write_text(json.dumps(etat))
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}", "SBX_P2P_DIR": str(p2p),
           "SBX_P2P_LIB": str(PKG), "SBX_ANCRE": str(tmp_path / "ancre.json"),
           "SBX_AUDIT": str(tmp_path / "audit.log")}
    (tmp_path / "audit.log").write_text("")
    return env, p2p, etat


def _ancrer(tmp_path, cle):
    (tmp_path / "ancre.json").write_text(json.dumps(
        {"cle_publique": cle, "adresse": "10.64.0.1", "nom": "gk2", "empreinte": "abcd"}))


def _joindre(env):
    return subprocess.run(["sh", str(JOIN), "10.64.0.1", "t" * 64], env=env,
                          capture_output=True, text=True, timeout=30)


def test_jonction_refusee_si_cle_differente_de_l_ancre(tmp_path):
    env, p2p, etat = _env(tmp_path, CLE_AUTRE)
    _ancrer(tmp_path, CLE_MAITRE)
    r = _joindre(env)
    assert r.returncode == 3, r.stdout + r.stderr
    assert json.loads((p2p / "wg_mesh.json").read_text()) == etat
    assert not (p2p / "mesh.json").exists()
    lignes = [json.loads(ligne) for ligne in (tmp_path / "audit.log").read_text().splitlines()]
    assert [ligne["evenement"] for ligne in lignes] == ["maitre_refuse"]
    assert "t" * 64 not in (tmp_path / "audit.log").read_text()


def test_jonction_acceptee_si_meme_cle(tmp_path):
    env, p2p, _ = _env(tmp_path, CLE_MAITRE)
    _ancrer(tmp_path, CLE_MAITRE)
    r = _joindre(env)
    assert r.returncode == 0, r.stdout + r.stderr
    st = json.loads((p2p / "wg_mesh.json").read_text())
    assert st["peers"][0]["public_key"] == CLE_MAITRE and st["address"] == "10.10.0.7/24"
    assert (tmp_path / "audit.log").read_text() == ""


def test_jonction_sans_ancre_garde_le_comportement_d_avant(tmp_path):
    env, p2p, _ = _env(tmp_path, CLE_AUTRE)
    r = _joindre(env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads((p2p / "wg_mesh.json").read_text())["peers"][0]["public_key"] == CLE_AUTRE


def test_sbx_mesh_up_sans_adresse_sort_proprement(tmp_path):
    """Copie du script dont les chemins pointent dans tmp_path et dont le garde root est neutralisé."""
    etat = tmp_path / "wg_mesh.json"
    etat.write_text(json.dumps({"private_key": CLE_PAIR, "peers": []}))
    src = UP.read_text().replace("/var/lib/secubox/p2p/wg_mesh.json", str(etat)) \
        .replace("/etc/wireguard/wg-mesh.conf", str(tmp_path / "wg-mesh.conf")) \
        .replace('"/usr/lib/secubox/p2p"', f'"{PKG}"') \
        .replace("[[ $EUID -eq 0 ]] ||", "true ||")
    script = tmp_path / "up.sh"
    script.write_text(src)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for f in ("ip", "wg", "wg-quick"):  # jamais appelés : un appel ferait échouer le test
        (bin_ / f).write_text("#!/bin/sh\nexit 99\n")
        (bin_ / f).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"}
    r = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "adresse maillée pas encore attribuée" in r.stdout
    assert "KeyError" not in r.stderr
    assert not (tmp_path / "wg-mesh.conf").exists()
