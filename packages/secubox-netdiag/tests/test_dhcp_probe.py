# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-dhcp-probe : trame bien formée, offre bien lue, verdicts, et AUCUN DHCPREQUEST (#1935)."""
import importlib.machinery
import importlib.util
import struct
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "sbin" / "secubox-dhcp-probe"
loader = importlib.machinery.SourceFileLoader("dhcp_probe", str(SRC))
spec = importlib.util.spec_from_loader("dhcp_probe", loader)
p = importlib.util.module_from_spec(spec)
loader.exec_module(p)

MAC = bytes.fromhex("0a1b2c3d4e5f")
XID = 0x12345678


def offre(dns=("192.168.1.200",), serveur="192.168.1.254", xid=XID, mac=MAC, type_=2):
    o = (bytes([53, 1, type_]) + bytes([54, 4]) + bytes(map(int, serveur.split("."))) + bytes([1, 4, 255, 255, 255, 0])
         + bytes([3, 4, 192, 168, 1, 254]) + bytes([6, 4 * len(dns)]) + b"".join(bytes(map(int, d.split("."))) for d in dns)
         + bytes([51, 4]) + struct.pack("!I", 86400) + b"\xff")
    b = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0, b"\0" * 4, bytes([192, 168, 1, 77]), b"\0" * 4,
                    b"\0" * 4, mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    return b + p.MAGIC + o


def test_le_discover_est_un_discover_et_jamais_un_request():
    c = p.construire_discover(XID, MAC)
    assert c[240:243] == b"\x35\x01\x01"                       # option 53 = 1 (DISCOVER)
    assert b"\x35\x01\x03" not in c                           # jamais 3 (REQUEST)
    assert c[28:34] == MAC and c[0] == 1


def test_la_trame_est_en_diffusion_et_les_sommes_sont_justes():
    t = p.trame(MAC, p.construire_discover(XID, MAC))
    assert t[:6] == b"\xff" * 6 and t[6:12] == MAC and t[12:14] == b"\x08\x00"
    assert p.checksum(t[14:34]) == 0                          # en-tête IP : somme valide
    assert struct.unpack("!HH", t[34:38]) == (68, 67)


def test_l_offre_est_lue_avec_passerelle_dns_et_bail():
    o = p.analyser_offre(offre(("192.168.1.200", "1.1.1.1")), XID, MAC)
    assert o["serveur"] == "192.168.1.254" and o["passerelles"] == ["192.168.1.254"]
    assert o["dns"] == ["192.168.1.200", "1.1.1.1"] and o["bail_s"] == 86400 and o["adresse_offerte"] == "192.168.1.77"


def test_une_reponse_a_quelqu_un_d_autre_est_ignoree():
    assert p.analyser_offre(offre(xid=XID + 1), XID, MAC) is None
    assert p.analyser_offre(offre(mac=bytes(6)), XID, MAC) is None
    assert p.analyser_offre(offre(type_=5), XID, MAC) is None   # un ACK n'est pas une offre
    assert p.analyser_offre(b"\0" * 10, XID, MAC) is None


def test_options_tronquees_ne_font_pas_planter():
    assert p.analyser_options(bytes([6, 8, 1, 2])) == {}


def test_verdicts():
    o1 = dict(p.analyser_offre(offre(), XID, MAC), mac_serveur="aa:bb:cc:dd:ee:01", ip_source="192.168.1.254")
    o2 = dict(o1, mac_serveur="aa:bb:cc:dd:ee:02", serveur="192.168.1.99")
    assert p.verdict([], None)[0] == 1
    assert p.verdict([o1], "192.168.1.200")[0] == 0
    assert p.verdict([o1], "10.0.0.1")[0] == 2
    code, msgs = p.verdict([o1, o2], None)
    assert code == 2 and "2 serveurs" in msgs[0]


def test_l_adresse_aleatoire_est_locale_et_unicast():
    for _ in range(50):
        m = p.mac_aleatoire()
        assert m[0] & 0x02 and not m[0] & 0x01


def test_pas_de_requete_ni_de_liaison_au_port_68():
    code = SRC.read_text()
    assert "bind((" in code and "SOCK_DGRAM" not in code and "\\x35\\x01\\x03" not in code
