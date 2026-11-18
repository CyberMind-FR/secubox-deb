# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import re
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


NFT_GABARIT = CTL.parents[1] / "nft" / "secubox-pseudo-routeur.nft"


def _executer(tmp_path, lan_if="eth2", conf=None):
    env = {"PATH": "/usr/bin:/bin", "SECUBOX_PR_NFT_OUT": str(tmp_path / "chaine.nft"),
           "SECUBOX_PR_CONF": str(conf or tmp_path / "absent.toml"),
           # sous-reseau de documentation : la detection par route ne trouve rien ici
           "SECUBOX_PR_IP_GK2": "192.0.2.200"}
    if lan_if is not None:
        env["SECUBOX_PR_LAN_IF"] = lan_if
    return subprocess.run(["bash", str(CTL), "generer-chaine"], env=env,
                          capture_output=True, text=True, timeout=30)


def _generer(tmp_path, **kw):
    r = _executer(tmp_path, **kw)
    assert r.returncode == 0, r.stderr
    return (tmp_path / "chaine.nft").read_text()


def _regles(txt):
    corps = re.search(r"chain forward \{(.*?)\n\t\}", txt, re.S).group(1)
    return [l.strip() for l in corps.splitlines() if l.strip() and not l.strip().startswith("type ")]


def _verdict(txt, iif, ensembles_mac):
    """Evaluation statique de la chaine generee : premiere regle qui correspond."""
    for r in _regles(txt):
        m = re.match(r'iifname != "([^"]+)" accept$', r)
        if m:
            if iif != m.group(1):
                return "accept"
            continue
        if r.startswith("update @vus_lan "):
            continue  # memorise la MAC, sans verdict
        m = re.match(r"ether saddr @(\w+) .*\b(drop|accept)$", r)
        if m:
            if m.group(1) in ensembles_mac:
                return m.group(2)
            continue
        m = re.match(r"(counter name \w+ )?(accept|drop)$", r)
        assert m, f"regle non modelisee : {r}"
        return m.group(2)
    return re.search(r"policy (\w+);", txt).group(1)


def test_politique_accept_jamais_drop(tmp_path):
    txt = _generer(tmp_path)
    assert "policy drop" not in txt
    assert re.search(r"chain forward \{[^}]*policy accept;", txt, re.S)


def test_garde_iifname_en_tete(tmp_path):
    regles = _regles(_generer(tmp_path))
    assert regles[0] == 'iifname != "eth2" accept'


def test_ingress_br_lxc_et_wg_acceptes_meme_bloque(tmp_path):
    txt = _generer(tmp_path)
    for iif in ("br-lxc", "wg0", "mesh0", "lo"):
        assert _verdict(txt, iif, set()) == "accept"
        assert _verdict(txt, iif, {"blocked", "quarantine_zone"}) == "accept"


def test_lan_non_classe_accepte(tmp_path):
    assert _verdict(_generer(tmp_path), "eth2", set()) == "accept"


def test_lan_bloque_ou_quarantaine_jete(tmp_path):
    txt = _generer(tmp_path)
    assert _verdict(txt, "eth2", {"blocked"}) == "drop"
    assert _verdict(txt, "eth2", {"quarantine_zone"}) == "drop"


def test_aucun_drop_sans_ensemble_nac(tmp_path):
    for r in _regles(_generer(tmp_path)):
        if r.endswith("drop"):
            assert re.match(r"ether saddr @(blocked|quarantine_zone) ", r), r


def test_refus_sans_interface_lan(tmp_path):
    r = _executer(tmp_path, lan_if=None)
    assert r.returncode == 2
    assert not (tmp_path / "chaine.nft").exists()


def test_refus_interface_invalide(tmp_path):
    r = _executer(tmp_path, lan_if='eth2" accept; drop')
    assert r.returncode == 2


def test_interface_lue_dans_le_toml(tmp_path):
    conf = tmp_path / "pr.toml"
    conf.write_text('lan_if = "enp1s0"\n')
    assert 'iifname != "enp1s0" accept' in _generer(tmp_path, lan_if=None, conf=conf)


def test_gabarit_identique_a_la_sortie_du_ctl(tmp_path):
    gabarit = NFT_GABARIT.read_text()
    corps = gabarit[gabarit.index("table inet"):]
    assert corps == _generer(tmp_path)


def test_ensembles_locaux_declares(tmp_path):
    # Un ensemble nft est propre a sa table : @blocked doit exister dans la notre.
    txt = _generer(tmp_path)
    assert "set blocked {" in txt and "set quarantine_zone {" in txt
    assert "counter sbx_pr_forward_rejete {" in txt and "counter sbx_pr_forward_lan {" in txt


def test_nftables_valide_la_syntaxe(tmp_path):
    import shutil
    if not shutil.which("nft"):
        pytest.skip("nft absent")
    base = tmp_path / "base.nft"
    base.write_text(_generer(tmp_path))
    cmd = ["nft", "-c", "-f", str(base)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 and "cache initialization failed" in r.stderr and shutil.which("unshare"):
        r = subprocess.run(["unshare", "-rn", *cmd], capture_output=True, text=True)
    if r.returncode != 0 and ("cache initialization failed" in r.stderr or "unshare" in r.stderr):
        pytest.skip("nft -c sans acces netlink dans cet environnement")
    assert r.returncode == 0, r.stderr


def test_activation_idempotente(tmp_path):
    # Fix #3803 : le fichier supprime puis redeclare la table dans la meme transaction.
    txt = _generer(tmp_path)
    lignes = txt.splitlines()
    assert lignes[0] == "table inet secubox_pseudo_routeur {}"
    assert lignes[1] == "delete table inet secubox_pseudo_routeur"
    assert txt.count("chain forward {") == 1
    # regenerer donne exactement le meme fichier (une seule copie des regles)
    assert _generer(tmp_path) == txt

