# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3958 : une mise à jour du paquet ne redémarre ni ne recharge Unbound quand rien n'a changé, et jamais par restart/reload."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TORCTL = ROOT / "sbin/torctl"
WPAD = ROOT / "composants/proxypac/sbin/proxypac-wpad"


@pytest.fixture
def banc(tmp_path):
    binaires = tmp_path / "bin"
    binaires.mkdir()
    journal = tmp_path / "journal"
    journal.touch()
    for nom in ("systemctl", "unbound-control", "unbound-checkconf", "sysctl", "nft", "python3"):
        f = binaires / nom
        f.write_text(f'#!/bin/sh\nprintf "%s\\n" "{nom} $(echo "$*" | tr "\\n" " ")" >> "{journal}"\nexit ${{FAUX_RC:-0}}\n')
        f.chmod(0o755)
    for d in ("share", "torrc", "unbound", "nft", "dnsmasq"):
        (tmp_path / d).mkdir()
    for src in ("conf/torrc.d/60-secubox-transparent.conf", "conf/unbound/secubox-onion-forward.conf",
                "nft.d/secubox-tor-transparent.nft"):
        shutil.copy(ROOT / src, tmp_path / "share")
    env = {**os.environ, "PATH": f"{binaires}:{os.environ['PATH']}",
           "TORCTL_SHARE_D": str(tmp_path / "share"), "TORCTL_TORRC_D": str(tmp_path / "torrc"),
           "TORCTL_UNBOUND_D": str(tmp_path / "unbound"), "TORCTL_NFT_D": str(tmp_path / "nft"), "TORCTL_DRYRUN": "0",
           "WPAD_UNBOUND_D": str(tmp_path / "unbound"), "WPAD_DNSMASQ_D": str(tmp_path / "dnsmasq"), "WPAD_DRYRUN": "0",
           "WPAD_DOMAIN": "exemple.test", "WPAD_LAN_IP": "192.0.2.1"}

    def lancer(script, *args, **sup):
        journal.write_text("")
        r = subprocess.run(["bash", str(script), *args], capture_output=True, text=True, env={**env, **sup})
        assert r.returncode == 0, r.stderr
        return [x.strip() for x in journal.read_text().splitlines()]
    return lancer, tmp_path


def recharges(j):
    return [x for x in j if x.startswith("python3") and "recharger_unbound" in x]


def sans_coupure(j):
    return not [x for x in j if x.startswith(("systemctl restart unbound", "systemctl try-restart unbound", "unbound-control"))]


def test_torctl_on_deux_fois_ne_recharge_qu_une_fois(banc):
    lancer, _ = banc
    j = lancer(TORCTL, "transparent", "on")
    assert len(recharges(j)) == 1 and sans_coupure(j)
    j = lancer(TORCTL, "transparent", "on")
    assert recharges(j) == [] and sans_coupure(j)


def test_torctl_off_recharge_une_fois(banc):
    lancer, _ = banc
    lancer(TORCTL, "transparent", "on")
    j = lancer(TORCTL, "transparent", "off")
    assert len(recharges(j)) == 1 and sans_coupure(j)
    j = lancer(TORCTL, "transparent", "off")
    assert recharges(j) == [] and sans_coupure(j)


def test_dropin_modifie_est_repose_et_recharge(banc):
    lancer, tmp = banc
    (tmp / "unbound/secubox-onion-forward.conf").write_text("ancien\n")
    assert len(recharges(lancer(TORCTL, "transparent", "on"))) == 1
    assert "onion." in (tmp / "unbound/secubox-onion-forward.conf").read_text()


def test_wpad_dns_deux_fois_ne_recharge_qu_une_fois(banc):
    lancer, tmp = banc
    j = lancer(WPAD, "apply", WPAD_ROLE="slave-dns")
    assert len(recharges(j)) == 1 and sans_coupure(j)
    avant = (tmp / "unbound/secubox-wpad.conf").read_text()
    assert avant == '# secubox-proxypac WPAD via DNS (auto)\nserver:\n    local-data: "wpad.exemple.test. A 192.0.2.1"\n'
    j = lancer(WPAD, "apply", WPAD_ROLE="slave-dns")
    assert recharges(j) == [] and sans_coupure(j)
    assert (tmp / "unbound/secubox-wpad.conf").read_text() == avant


def test_wpad_sans_domaine_ne_recharge_rien(banc):
    """Le cas de la box de production : aucun dropin avant, aucun après."""
    lancer, tmp = banc
    j = lancer(WPAD, "apply", WPAD_ROLE="slave-dns", WPAD_DOMAIN="", WPAD_LAN_IP="192.0.2.1")
    if "wpad.." in "".join(p.read_text() for p in (tmp / "unbound").iterdir()):
        pytest.fail("label vide écrit")
    lancer(WPAD, "apply", WPAD_ROLE="off")
    j = lancer(WPAD, "apply", WPAD_ROLE="off")
    assert recharges(j) == [] and not [x for x in j if "dnsmasq" in x] and sans_coupure(j)


def test_wpad_bascule_recharge_les_deux_services(banc):
    lancer, tmp = banc
    lancer(WPAD, "apply", WPAD_ROLE="master")
    j = lancer(WPAD, "apply", WPAD_ROLE="slave-dns")
    assert "systemctl reload dnsmasq" in j and len(recharges(j)) == 1
    assert not (tmp / "dnsmasq/secubox-wpad.conf").exists()


def test_unbound_arrete_rien_a_recharger(banc):
    lancer, tmp = banc
    j = lancer(TORCTL, "transparent", "on", FAUX_RC="3")
    assert recharges(j) == [] and (tmp / "unbound/secubox-onion-forward.conf").exists()


def test_postinst_une_seule_passe():
    assert (ROOT / "debian/postinst").read_text().count("maintscripts/*.postinst") == 1
