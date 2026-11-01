# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374), arbitrage 2 : forçage du DNS (redirection 53, blocage DoT 853 et DoH connus) pour les appareils PROTECT/AUTO, nftables
seulement, double tampon et retour arrière ; levé par la pause, « Je débloque » et OBSERVE ; suspendu si la lecture casse."""
import json
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_contournement as C
from test_dnstv_ctl_api import ctl, monde  # noqa: F401  (fixtures)

PKG = Path(__file__).resolve().parents[1]
M1, M2, M3 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"


def etat(m1="auto", m2="block", m3="observe"):
    return {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": m1, "mac": M1},
                                       {"ip": "192.168.1.51", "nom": "TV chambre", "mode": m2, "mac": M2},
                                       {"ip": "192.168.1.52", "nom": "TV banc", "mode": m3, "mac": M3},
                                       {"ip": "192.168.1.53", "nom": "Sans mac", "mode": "auto"}]}


def test_seuls_protect_et_auto_sont_forces():
    assert C.forces(etat()) == [M1, M2]
    assert C.forces(etat("observe", "off")) == []
    assert C.forces(etat(), suspendus={M1}) == [M2]


def test_regles_nft_redirigent_53_et_bloquent_853_et_doh():
    t = C.rendre(etat(), {"8.8.8.8", "2001:4860:4860::8888", "pas-une-ip"})
    assert t.startswith("table inet secubox_adguard_contournement\ndelete table inet secubox_adguard_contournement\n")
    assert f"elements = {{ {M1}, {M2} }}" in t and M3 not in t
    assert "udp dport 53" in t and "tcp dport 53" in t and "redirect to :53" in t
    assert "tcp dport 853" in t and "udp dport 853" in t
    assert "ip daddr @sbx_doh_v4" in t and "elements = { 8.8.8.8 }" in t and "elements = { 2001:4860:4860::8888 }" in t
    assert "pas-une-ip" not in t and "iptables" not in t
    assert "drop" not in t.replace("policy accept", "")          # rejet explicite, jamais un drop silencieux


def test_rien_a_forcer_rend_une_table_sans_elements():
    t = C.rendre(etat("observe", "observe"), set())
    assert "elements" not in t and "redirect" in t                # règles inertes : ensemble vide


def test_suspensions_valides_et_expirees():
    now = 1_800_000_000
    s = C.lire_suspensions(json.dumps({"version": 1, "suspendus": {M1: now - 10, M2: now - C.DUREE_SUSPENSION_S - 1, "x": now}}), now)
    assert s == {M1}


@pytest.fixture
def nft(monde, monkeypatch):  # noqa: F811
    t = monde["tmp"]
    s = t / "nft"
    s.write_text(f"#!/bin/sh\necho \"nft $*\" >> {monde['journal']}\n[ -f {t}/nft-refuse ] && exit 1\nexit 0\n")
    s.chmod(0o755)
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_NFT", str(s))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_NFT_FICHIER", str(t / "nftables.d" / "zz-secubox-adguard-contournement.nft"))
    return monde


def test_apply_pose_le_forcage_par_double_tampon_et_l_audite(nft):
    dnstv.ecrire_etat(etat(), nft["etat"])
    assert ctl(nft, "apply") == 0
    j = nft["journal"].read_text()
    assert "nft -c -f" in j and j.index("nft -c -f") < j.index("nft -f ")
    f = nft["tmp"] / "nftables.d" / "zz-secubox-adguard-contournement.nft"
    assert M1 in f.read_text()
    a = (nft["tmp"] / "audit.log").read_text()
    assert "contournement" in a and "appareils=2" in a


def test_pause_ou_observe_leve_le_forcage(nft):
    dnstv.ecrire_etat(etat(), nft["etat"])
    ctl(nft, "apply")
    dnstv.ecrire_etat(etat("observe", "observe"), nft["etat"])          # pause / Je débloque = mode observe effectif
    ctl(nft, "apply")
    assert M1 not in (nft["tmp"] / "nftables.d" / "zz-secubox-adguard-contournement.nft").read_text()


def test_contrôle_refuse_garde_l_ancienne_version(nft):
    dnstv.ecrire_etat(etat(), nft["etat"])
    ctl(nft, "apply")
    f = nft["tmp"] / "nftables.d" / "zz-secubox-adguard-contournement.nft"
    avant = f.read_text()
    (nft["tmp"] / "nft-refuse").touch()
    dnstv.ecrire_etat(etat("auto", "observe"), nft["etat"])
    assert ctl(nft, "apply") == 0                                       # le DNS est appliqué ; le forçage garde sa version précédente
    assert f.read_text() == avant
    assert "contournement-refuse" in (nft["tmp"] / "audit.log").read_text()


def test_suspension_lue_par_le_controleur(nft):
    dnstv.ecrire_etat(etat(), nft["etat"])
    (nft["etat"] / "contournement-suspendu.json").write_text(json.dumps({"version": 1, "suspendus": {M1: int(time.time())}}))
    ctl(nft, "apply")
    t = (nft["tmp"] / "nftables.d" / "zz-secubox-adguard-contournement.nft").read_text()
    assert M1 not in t and M2 in t


def test_disable_retire_la_table(nft):
    dnstv.ecrire_etat(etat(), nft["etat"])
    ctl(nft, "apply")
    ctl(nft, "disable")
    assert "nft delete table inet secubox_adguard_contournement" in nft["journal"].read_text()
    assert not (nft["tmp"] / "nftables.d" / "zz-secubox-adguard-contournement.nft").exists()
