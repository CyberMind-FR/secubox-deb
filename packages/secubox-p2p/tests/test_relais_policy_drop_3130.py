# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3130 — gk1 : « pas de drop terminal » toutes les heures. Le nftables.conf de secubox-hardening met la chaîne input
en `policy drop` sans ligne `drop` finale : la règle du relais va alors juste avant l'accolade fermante de cette chaîne.
On exécute le Python RÉEL de cmd_ouvrir (extrait du script), avec un faux `nft` (le script exige root)."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
REGLE = "ip saddr 10.10.0.1 tcp dport 9080 accept comment \"secubox-relais-maillage\""

POLICY = """#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    include "/etc/secubox/hardening/nft-input-trust.d/*.nft"
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
}
"""

TERMINAL = """table inet secubox_filter {
  chain input {
    type filter hook input priority 0; policy accept;
    iif lo accept
    drop
  }
}
"""


def _python_de_cmd_ouvrir():
    s = SCRIPT.read_text()
    debut = s.index("cmd_ouvrir() {")
    m = re.search(r"<<'PY'\n(.*?)\nPY\n", s[debut:], re.S)
    return m.group(1)


def _insere(tmp_path, contenu, nft_rc=0):
    conf = tmp_path / "nftables.conf"
    conf.write_text(contenu)
    binaire = tmp_path / "bin"
    binaire.mkdir(exist_ok=True)
    (binaire / "nft").write_text(f"#!/bin/sh\nexit {nft_rc}\n")
    (binaire / "nft").chmod(0o755)
    code = tmp_path / "inserer.py"
    code.write_text(_python_de_cmd_ouvrir())
    r = subprocess.run([sys.executable, "-I", str(code), str(conf), REGLE], capture_output=True, text=True,
                       env={"PATH": f"{binaire}:/usr/bin:/bin"})
    return r, conf.read_text()


def test_policy_drop_sans_drop_final(tmp_path):
    r, t = _insere(tmp_path, POLICY)
    assert r.returncode == 0, r.stderr
    lignes = t.splitlines()
    i = lignes.index("    " + REGLE)
    assert lignes[i - 1].strip().startswith("include") and lignes[i + 1] == "  }"   # fin de la chaîne input
    assert t.count(REGLE) == 1 and "chain forward" in t
    assert list(tmp_path.glob("nftables.conf.avant-relais-*"))                       # copie de l'original


def test_drop_terminal_toujours_avant_lui(tmp_path):
    r, t = _insere(tmp_path, TERMINAL)
    assert r.returncode == 0, r.stderr
    lignes = t.splitlines()
    assert lignes[lignes.index("    drop") - 1] == "    " + REGLE


@pytest.mark.parametrize("contenu", [
    "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy accept;\n  }\n}\n",
    "table inet filter {\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n  }\n}\n",
])
def test_ni_drop_ni_policy_drop_refuse(tmp_path, contenu):
    r, t = _insere(tmp_path, contenu)
    assert r.returncode != 0 and t == contenu


def test_nft_refuse_rien_ne_change(tmp_path):
    r, t = _insere(tmp_path, POLICY, nft_rc=1)
    assert r.returncode != 0 and t == POLICY
