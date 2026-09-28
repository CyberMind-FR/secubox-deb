# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests du garde-fou SSRF + du client d'égress urlshot (#1120)."""
import egress


def test_ssrf_bloque_interne():
    for u in [
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "https://x.gk2.secubox.in/",
        "http://169.254.169.254/",
        "ftp://x/",
        "file:///etc/passwd",
        "http://[::1]/",
    ]:
        assert egress.url_interdite(u), u


def test_ssrf_laisse_passer_externe():
    assert egress.url_interdite("https://example.com/page") is None


# ── La sortie ne mène qu'à l'extérieur (#1609) ─────────────────────────────
import socket  # noqa: E402

import pytest  # noqa: E402

_PUBLIQUE = "93.184.216.34"
_BOX_V6 = "2a0c:5a80:1:2::200"


@pytest.fixture
def reseau_simule(monkeypatch):
    """Résolveur simulé et adresses de box fixes : aucun vrai réseau."""
    table = {
        "exemple.test": [_PUBLIQUE],
        "nas.exemple.test": ["192.168.1.50"],
        "mixte.exemple.test": [_PUBLIQUE, "10.100.0.1"],
        "box.exemple.test": [_BOX_V6],
        "voisin.exemple.test": ["2a0c:5a80:1:2::77"],
    }

    def resout(hote, port, *a, **k):
        if hote not in table:
            raise socket.gaierror(socket.EAI_NONAME, "inconnu")
        return [((socket.AF_INET6 if ":" in ip else socket.AF_INET),
                 socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in table[hote]]

    monkeypatch.setattr(egress.socket, "getaddrinfo", resout)
    propres = (frozenset({egress.ipaddress.ip_address(_BOX_V6)}),
               (egress.ipaddress.ip_network("2a0c:5a80:1:2::/64"),))
    monkeypatch.setattr(egress, "_adresses_de_la_box", lambda: propres)


def test_plages_internes_refusees(reseau_simule):
    for u in [
        "http://10.100.0.1/",
        "http://100.64.0.1/",
        "http://224.0.0.251/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:10.100.0.1]/",
        "http://[fe80::1]/",
        "http://[fd00::1]/",
        "http://app.localhost/",
    ]:
        assert egress.url_interdite(u), u


def test_nom_resolu_vers_le_lan_refuse(reseau_simule):
    assert egress.url_interdite("https://nas.exemple.test/")
    assert egress.url_interdite("https://mixte.exemple.test/")


def test_adresses_de_la_box_refusees(reseau_simule):
    assert egress.url_interdite("https://box.exemple.test/")
    assert egress.url_interdite("https://voisin.exemple.test/")
    assert egress.url_interdite(f"http://[{_BOX_V6}]/")


def test_adresse_publique_admise(reseau_simule):
    assert egress.url_interdite("https://exemple.test/page") is None


def test_client_garde_chaque_saut(monkeypatch):
    httpx = pytest.importorskip("httpx")
    vus = {}

    class Capture:
        def __init__(self, **kw):
            vus.update(kw)

    monkeypatch.setattr(httpx, "Client", Capture)
    egress.client()
    assert egress._garde_saut in vus["event_hooks"]["request"]
    assert vus["follow_redirects"] is True


def test_redirection_vers_la_boucle_locale_refusee(reseau_simule):
    httpx = pytest.importorskip("httpx")
    demandes = []

    def amont(request):
        demandes.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})

    with httpx.Client(transport=httpx.MockTransport(amont), follow_redirects=True,
                      event_hooks={"request": [egress._garde_saut]}) as cli:
        with pytest.raises(egress.DestinationRefusee):
            cli.get("https://exemple.test/")
    assert demandes == ["https://exemple.test/"]
