# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3154 — relais des ports médias par le maître : ports publiés par le pair, DNAT/masquerade/forward sur wg-mesh.
Le script exige root : on exécute son Python réel (extraction) et, pour relayer-port/retirer-port, le script entier
avec un `id` et un `nft` simulés sur PATH."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
TEXTE = SCRIPT.read_text()


def _python_de(fonction):
    debut = TEXTE.index(fonction + "() {")
    corps = TEXTE[debut:TEXTE.index("\n}\n", debut)]       # la seule fonction demandée
    m = re.search(r"<<'PY'\n(.*?)\nPY", corps, re.S) or re.search(r"python3 -c '(.*)'", corps, re.S)
    return m.group(1)


def _execute(tmp_path, fonction, *args, entree=None):
    code = tmp_path / (fonction + ".py")
    code.write_text(_python_de(fonction))
    return subprocess.run([sys.executable, "-I", str(code), *map(str, args)], input=entree, capture_output=True, text=True)


def _rc(tmp_path, fonction, etat, *args):
    f = tmp_path / "etat.json"
    f.write_text(json.dumps(etat))
    return _execute(tmp_path, fonction, f, *args).returncode


def _rendu(tmp_path, etat):
    f = tmp_path / "etat.json"
    f.write_text(json.dumps(etat))
    r = _execute(tmp_path, "rendu_nft_ports", f)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_ports_du_pair_rejette_une_liste_illisible(tmp_path):
    def ports(corps):
        return _execute(tmp_path, "ports_du_pair", entree=corps)
    for corps in ('{"ports": "x"}', "pas du json", "{}", '{"ports": null}'):
        assert ports(corps).returncode == 1, corps
    ok = ports(json.dumps({"domaine": "gk1.x.test", "ports": [
        {"proto": "tcp", "port": 7881, "module": "meet"}, {"proto": "udp", "port": 7882, "module": "meet"},
        {"proto": "icmp", "port": 5000, "module": "meet"}, {"proto": "tcp", "port": 22, "module": "meet"},
        {"proto": "tcp", "port": 5000, "module": "Mauvais;Nom"}, {"proto": "tcp", "port": "6000", "module": "m"}]}))
    assert ok.returncode == 0 and ok.stdout.splitlines() == ["tcp/7881 meet", "udp/7882 meet"]
    assert ports('{"ports": []}').returncode == 0 and ports('{"ports": []}').stdout.strip() == ""


def test_port_tenu_par_autre_refuse_le_second_declarant(tmp_path):
    etat = {"udp/7882": {"ip": "10.10.0.5", "module": "meet"}}
    assert _rc(tmp_path, "port_tenu_par_autre", etat, "10.10.0.8", "udp/7882") == 0
    assert _rc(tmp_path, "port_tenu_par_autre", etat, "10.10.0.5", "udp/7882") == 1
    assert _rc(tmp_path, "port_tenu_par_autre", etat, "10.10.0.8", "tcp/7881") == 1     # libre
    # le relais lui-même (127.0.0.1) compte comme un déclarant
    assert _rc(tmp_path, "port_tenu_par_autre", {"tcp/7881": {"ip": "127.0.0.1", "module": "meet"}}, "10.10.0.8", "tcp/7881") == 0


def test_fichier_nft_regenere_dnat_masquerade_forward(tmp_path):
    t = _rendu(tmp_path, {"udp/7882": {"ip": "10.10.0.8", "module": "meet"}, "tcp/7881": {"ip": "10.10.0.8", "module": "meet"}})
    assert "table inet secubox-relais-ports {" in t
    assert 'iifname != "wg-mesh" udp dport 7882 counter dnat ip to 10.10.0.8:7882 comment "relais-ports meet"' in t
    assert 'iifname != "wg-mesh" tcp dport 7881 counter dnat ip to 10.10.0.8:7881 comment "relais-ports meet"' in t
    assert 'oifname "wg-mesh" ip daddr 10.10.0.8 udp dport 7882 counter masquerade' in t
    assert 'oifname "wg-mesh" ip daddr 10.10.0.8 udp dport 7882 accept' in t
    assert "type nat hook prerouting priority dstnat; policy accept;" in t
    assert "type nat hook postrouting priority srcnat; policy accept;" in t
    assert "type filter hook forward priority 0; policy accept;" in t


def test_rendu_ignore_le_local_et_les_entrees_invalides(tmp_path):
    assert _rendu(tmp_path, {"tcp/7881": {"ip": "127.0.0.1", "module": "meet"}}) == ""      # local : pas de règle ici
    assert _rendu(tmp_path, {"tcp/7881": {"ip": "8.8.8.8", "module": "meet"},
                             "tcp/22": {"ip": "10.10.0.8", "module": "meet"},
                             "tcp/7881\nflush ruleset": {"ip": "10.10.0.8", "module": "meet"},
                             "udp/7882": {"ip": "10.10.0.8", "module": 'x" accept #'}}) == ""
    assert _rendu(tmp_path, {}) == ""


def test_synchroniser_appelle_le_relais_des_ports():
    s = TEXTE[TEXTE.index("cmd_synchroniser() {"):TEXTE.index("cmd_retirer() {")]
    assert "public/ports" in s and "port_tenu_par_autre" in s and "relais_port_refuse" in s
    assert "relais_port_retire" in s and "ports_locaux" in s and "ports_nft_appliquer" in s


def test_jamais_nft_f_sur_nftables_conf_pour_les_ports():
    f = TEXTE[TEXTE.index("ports_nft_appliquer() {"):TEXTE.index("port_cle_valide()")]
    assert "nft delete table inet secubox-relais-ports" in f and 'nft -f "$RELAIS_PORTS_NFT"' in f
    assert "NFT_CONF" not in f


def _banc(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "id").write_text("#!/bin/sh\necho 0\n")
    (bin_dir / "nft").write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/nft-appels"\nexit 0\n')
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "SECUBOX_RELAIS_PORTS_ETAT": str(tmp_path / "etat" / "relais-ports.json"),
            "SECUBOX_RELAIS_PORTS_NFT": str(tmp_path / "nftables.d" / "secubox-relais-ports.nft")}


def _lance(tmp_path, env, *args):
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, timeout=60)


def test_relayer_puis_retirer_regenere_le_fichier_et_l_applique(tmp_path):
    env = _banc(tmp_path)
    etat, nft = tmp_path / "etat" / "relais-ports.json", tmp_path / "nftables.d" / "secubox-relais-ports.nft"
    r = _lance(tmp_path, env, "relayer-port", "udp/7882", "10.10.0.8", "meet")
    assert r.returncode == 0, r.stderr
    assert json.loads(etat.read_text()) == {"udp/7882": {"ip": "10.10.0.8", "module": "meet"}}
    assert "dnat ip to 10.10.0.8:7882" in nft.read_text()
    appels = (tmp_path / "nft-appels").read_text().splitlines()
    assert appels == ["delete table inet secubox-relais-ports", f"-f {nft}"]        # table supprimée avant, fichier rechargé seul
    # un second pair ne peut pas prendre le même port
    r = _lance(tmp_path, env, "relayer-port", "udp/7882", "10.10.0.9", "meet")
    assert r.returncode == 1 and json.loads(etat.read_text())["udp/7882"]["ip"] == "10.10.0.8"
    # entrées invalides
    for args in (("udp/22", "10.10.0.8", "meet"), ("icmp/7882", "10.10.0.8", "meet"), ("udp/7882", "8.8.8.8", "meet"), ("udp/7882", "10.10.0.8", "M;x")):
        assert _lance(tmp_path, env, "relayer-port", *args).returncode == 1, args
    # retrait : état vide → table supprimée et fichier retiré
    assert _lance(tmp_path, env, "retirer-port", "udp/7882").returncode == 0
    assert json.loads(etat.read_text()) == {} and not nft.exists()
    assert (tmp_path / "nft-appels").read_text().splitlines()[-1] == "delete table inet secubox-relais-ports"
