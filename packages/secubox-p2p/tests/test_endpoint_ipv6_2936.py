# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2936 — le point d'accès WireGuard d'un pair IPv6 s'écrit entre crochets : « [2001:db8::7]:51822 »."""
import base64

from api import main, mesh

CLE = base64.b64encode(b"k" * 32).decode()


def _req(adresse, port=None):
    return main.JoinRequest(token="t", fingerprint="fp", hostname="h", address=adresse, wg_public_key=CLE, wg_port=port)


def test_endpoint_ipv4_inchange():
    jr = {"address": "192.0.2.9"}
    main._record_wg_identity(jr, _req("192.0.2.9", 51822))
    assert jr["wg_endpoint"] == "192.0.2.9:51822"


def test_endpoint_ipv6_entre_crochets():
    jr = {"address": "2001:db8::7"}
    main._record_wg_identity(jr, _req("2001:db8::7", 51822))
    assert jr["wg_endpoint"] == "[2001:db8::7]:51822"


def test_le_conf_wireguard_rendu_accepte_un_pair_ipv6():
    etat = {"private_key": CLE, "address": "10.10.0.1/24", "peers": [
        {"public_key": CLE, "endpoint": "[2001:db8::7]:51822", "allowed_ips": "10.10.0.7/32"}]}
    assert "Endpoint = [2001:db8::7]:51822" in mesh.render_wg_conf(etat)
