# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2240 : la sonde du capteur pare-feu est additive, bornée, livrée par le paquet et chargée sans jamais recharger nftables."""
import shutil
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
NFT = PKG / "nftables.d" / "zz-secubox-scan-tap.nft"


def test_la_sonde_est_additive_et_bornee():
    t = NFT.read_text()
    regles = [l for l in t.splitlines() if l.startswith("add rule")]
    assert len(regles) == 2 and all("add @sbx_scan_seen" in r and "drop" not in r and "accept" not in r for r in regles)
    assert t.count("size 65536") == 2 and t.count("timeout 10m") == 2
    assert "flush" not in t and "delete" not in t


def test_le_paquet_livre_et_le_postinst_charge_sans_recharger():
    rules = (PKG / "debian" / "rules").read_text()
    post = (PKG / "debian" / "postinst").read_text()
    assert "zz-secubox-scan-tap.nft" in rules and "zz-secubox-scan-tap.nft" in post
    bloc = post[post.index("zz-secubox-scan-tap.nft") - 400:]
    assert "systemctl reload nftables" not in bloc.split("# #758 — enable the collector timer")[0].replace("JAMAIS de reload de nftables", "")
    assert "! nft list set inet filter sbx_scan_seen4" in post          # chargée seulement si absente : pas de règle en double


@pytest.mark.skipif(not shutil.which("unshare") or not shutil.which("nft"), reason="unshare/nft absents")
def test_la_sonde_se_charge_vraiment_dans_un_espace_de_noms_jetable():
    script = (f"nft add table inet filter && nft add chain inet filter input '{{ type filter hook input priority 0; policy drop; }}' "
              f"&& nft -f {NFT} && nft list chain inet filter input && nft add element inet filter sbx_scan_seen4 '{{ 203.0.113.9 . 22 }}' "
              f"&& nft -j list set inet filter sbx_scan_seen4")
    r = subprocess.run(["unshare", "-Urn", "sh", "-c", script], capture_output=True, text=True, timeout=30)
    if r.returncode != 0 and ("Operation not permitted" in r.stderr or "unshare" in r.stderr):
        pytest.skip("espace de noms utilisateur non disponible : " + r.stderr.strip()[:80])
    assert r.returncode == 0, r.stderr
    assert "sbx-scan-tap4" in r.stdout and "sbx-scan-tap6" in r.stdout and '"concat": ["203.0.113.9", 22]' in r.stdout
