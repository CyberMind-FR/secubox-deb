# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374) : verbes root bornés du DPI — conntrack-dump (lecture seule), dpi-cibles (filtre BPF par MAC, cibles de sbxdpi),
ndpid-arreter / ndpid-reprendre (garde de charge)."""
import json
from pathlib import Path

import pytest

from api import dnstv
from test_dnstv_ctl_api import ctl, monde  # noqa: F401  (fixtures)

PKG = Path(__file__).resolve().parents[1]
MAC = "aa:bb:cc:00:00:01"


@pytest.fixture
def dpi(monde, monkeypatch):  # noqa: F811
    t = monde["tmp"]
    ct = t / "nf_conntrack"
    sysctl = t / "systemctl"
    sysctl.write_text(f"#!/bin/sh\necho \"systemctl $*\" >> {monde['journal']}\nexit 0\n")
    sysctl.chmod(0o755)
    ipcmd = t / "ip"
    ipcmd.write_text("#!/bin/sh\ncase \"$2\" in -6) echo '[{\"dst\":\"2a01:e0a::1\",\"lladdr\":\"AA:BB:CC:00:00:01\",\"dev\":\"eth0\"}]';; "
                     "*) echo '[]';; esac\n")
    ipcmd.chmod(0o755)
    for k, v in {"SECUBOX_ADGUARD_TV_CONNTRACK": ct, "SECUBOX_ADGUARD_TV_SYSTEMCTL": sysctl, "SECUBOX_ADGUARD_TV_IP": ipcmd,
                 "SECUBOX_ADGUARD_TV_CIBLES": t / "run" / "sbxdpi-cibles.json"}.items():
        monkeypatch.setenv(k, str(v))
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC},
                                                  {"ip": "192.168.1.60", "nom": "Hors", "mode": "off", "mac": "aa:bb:cc:00:00:09"}]},
                      monde["etat"])
    return {"ct": ct, **monde}


def test_conntrack_dump_ne_rend_que_le_perimetre_et_n_ecrit_rien(dpi, capsys):
    dpi["ct"].write_text(
        "ipv4     2 tcp      6 100 ESTABLISHED src=192.168.1.50 dst=151.101.1.9 sport=1 dport=443 src=151.101.1.9 dst=192.168.1.50 sport=443 dport=1 use=1\n"
        "ipv4     2 tcp      6 100 ESTABLISHED src=192.168.1.60 dst=151.101.1.9 sport=1 dport=443 src=151.101.1.9 dst=192.168.1.60 sport=443 dport=1 use=1\n"
        "ipv6     10 udp      17 29 src=2a01:e0a::1 dst=2001:4860:4860::8888 sport=4 dport=853 src=2001:4860:4860::8888 dst=2a01:e0a::1 sport=853 dport=4 use=1\n")
    assert ctl(dpi, "conntrack-dump") == 0
    out = capsys.readouterr().out
    assert "192.168.1.50 dst=151.101.1.9" in out and "2a01:e0a::1" in out and "192.168.1.60" not in out


def test_conntrack_absent_rend_vide(dpi, capsys):
    assert ctl(dpi, "conntrack-dump") == 0 and capsys.readouterr().out == ""


def test_dpi_cibles_ecrit_les_cibles_de_sbxdpi_sans_filtre_de_capture(dpi):
    assert ctl(dpi, "dpi-cibles") == 0
    c = json.loads((dpi["tmp"] / "run" / "sbxdpi-cibles.json").read_text())
    assert c["appareils"] == [{"mac": MAC, "adresses": ["192.168.1.50", "2a01:e0a::1"]}]
    assert (not dpi["journal"].exists() or "restart" not in dpi["journal"].read_text()) and not (dpi["tmp"] / "ndpid-engine.d").exists()
    assert ctl(dpi, "dpi-cibles") == 0
    assert (dpi["tmp"] / "audit.log").read_text().count("dpi-cibles") == 1          # inchangé : pas de nouvelle entrée


def test_garde_de_charge_arrete_puis_reprend_nDPId(dpi):
    assert ctl(dpi, "ndpid-arreter") == 0 and ctl(dpi, "ndpid-reprendre") == 0
    j = dpi["journal"].read_text()
    assert "systemctl stop secubox-ndpid-engine.service" in j and "systemctl start secubox-ndpid-engine.service" in j
    a = (dpi["tmp"] / "audit.log").read_text()
    assert "ndpid-arret" in a and "ndpid-reprise" in a


def test_sudoers_nomme_les_nouveaux_verbes_exactement():
    s = (PKG / "sudoers.d" / "secubox-adguard-tv").read_text()
    for v in ("conntrack-dump", "dpi-cibles", "ndpid-arreter", "ndpid-reprendre"):
        assert f"/usr/sbin/secubox-adguard-tv {v}" in s
