# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — secubox-relais-maillage face aux liens directs entre pairs.

- `pairs_32` ne compte plus un lien direct (entrée `direct: true` de wg_mesh.json) comme un pair à relayer : sinon tout
  satellite se prendrait pour un relais de ses frères (joker DNS-01, certbot, vhosts, routes sbxwaf).
- `pair_du_maillage` tolère « (none) », la sortie de `wg show allowed-ips` pour une sonde (pair sans AllowedIPs).
Le script exige root : on exécute le Python réel de ses fonctions (heredoc), avec la sortie de `wg` en argument."""
import base64
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
TEXTE = SCRIPT.read_text()


def _cle(c):
    return base64.b64encode(c.encode() * 32).decode()


K_MAITRE, K_PAIR, K_DIRECT, K_SONDE = _cle("M"), _cle("P"), _cle("D"), _cle("S")
WG = (f"{K_PAIR}\t10.10.0.8/32\n"
      f"{K_DIRECT}\t10.10.0.3/32\n"
      f"{K_SONDE}\t(none)\n")


def _python_de(fonction):
    debut = TEXTE.index(fonction + "() {")
    fin = TEXTE.index("\n}\n", debut)
    m = re.search(r"<<'PY'\n(.*?)\nPY\n", TEXTE[debut:fin + 3], re.S)
    assert m, f"{fonction} : pas de Python en heredoc"
    return m.group(1)


def _execute(tmp_path, fonction, *args):
    code = tmp_path / (fonction + ".py")
    code.write_text(_python_de(fonction))
    return subprocess.run([sys.executable, "-I", str(code), *map(str, args)], capture_output=True, text=True)


def _etat(tmp_path, peers):
    f = tmp_path / "wg_mesh.json"
    f.write_text(json.dumps({"role": "peer", "peers": peers}))
    return f


def test_pairs_32_ignore_les_liens_directs(tmp_path):
    etat = _etat(tmp_path, [
        {"public_key": K_PAIR, "allowed_ips": "10.10.0.8/32", "mesh_ip": "10.10.0.8"},      # pair relayé (maître)
        {"public_key": K_DIRECT, "allowed_ips": "10.10.0.3/32", "mesh_ip": "10.10.0.3", "direct": True,
         "direct_etat": "actif"},
        {"public_key": K_SONDE, "mesh_ip": "10.10.0.4", "direct": True, "direct_etat": "sonde"},
    ])
    r = _execute(tmp_path, "pairs_32", etat, WG)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["10.10.0.8"]


def test_pairs_32_etat_absent_ou_illisible_comportement_d_avant(tmp_path):
    for etat in (tmp_path / "absent.json", tmp_path / "corrompu.json", tmp_path / "liste.json"):
        if etat.name == "corrompu.json":
            etat.write_text("{pas du json")
        elif etat.name == "liste.json":
            etat.write_text("[1, 2]")
        r = _execute(tmp_path, "pairs_32", etat, WG)
        assert r.returncode == 0, r.stderr
        assert r.stdout.split() == ["10.10.0.8", "10.10.0.3"]


def test_pairs_32_sans_interface(tmp_path):
    r = _execute(tmp_path, "pairs_32", tmp_path / "absent.json", "")
    assert r.returncode == 0 and r.stdout == ""


def test_pair_du_maillage_tolere_une_sonde(tmp_path):
    wg = f"{K_SONDE}\t(none)\n{K_MAITRE}\t10.10.0.0/24\n"
    assert _execute(tmp_path, "pair_du_maillage", "10.10.0.1", wg).returncode == 0
    assert _execute(tmp_path, "pair_du_maillage", "10.10.1.1", wg).returncode == 1
    assert _execute(tmp_path, "pair_du_maillage", "pas-une-ip", wg).returncode == 1
    assert _execute(tmp_path, "pair_du_maillage", "10.10.0.1", "").returncode == 1


def test_synchroniser_appelle_les_fonctions_reecrites():
    assert 'pairs="$(pairs_32 || true)"' in TEXTE
    for f in ("pairs_32", "pair_du_maillage"):
        corps = TEXTE[TEXTE.index(f + "() {"):]
        corps = corps[:corps.index("\n}\n")]
        assert "wg show wg-mesh allowed-ips 2>/dev/null || true" in corps
    assert '"$WG_ETAT"' in TEXTE[TEXTE.index("pairs_32() {"):TEXTE.index("maitre_du_satellite() {")]
