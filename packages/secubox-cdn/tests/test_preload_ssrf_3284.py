# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3284 : /preload_url allait chercher n'importe quelle URL http(s), y compris le LAN et 127.0.0.1 (SSRF).
La cible doit résoudre UNIQUEMENT vers des adresses publiques."""
import re
import socket
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG / "api"))
import cible  # noqa: E402


def _resolution(monkeypatch, adresses):
    def faux(hote, port, *a, **k):
        if adresses is None:
            raise socket.gaierror("introuvable")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in adresses]
    monkeypatch.setattr(cible.socket, "getaddrinfo", faux)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.200", "169.254.169.254", "::1",
                                "fc00::1", "fe80::1", "0.0.0.0", "100.64.0.1", "224.0.0.1", "10.10.0.1"])
def test_adresses_non_publiques_refusees(monkeypatch, ip):
    _resolution(monkeypatch, [ip])
    assert cible.verifier("https://exemple.test/x")[0] is False


def test_une_seule_adresse_privee_suffit_a_refuser(monkeypatch):
    _resolution(monkeypatch, ["93.184.216.34", "192.168.1.1"])
    assert cible.verifier("https://exemple.test/")[0] is False


def test_adresse_publique_acceptee(monkeypatch):
    _resolution(monkeypatch, ["93.184.216.34"])
    assert cible.verifier("https://exemple.test/a.js") == (True, "")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/", "http://", "https://user:pw@exemple.test/",
                                 "gopher://x", "", None, "https://exemple.test:22/"])
def test_url_invalide_refusee(monkeypatch, url):
    _resolution(monkeypatch, ["93.184.216.34"])
    assert cible.verifier(url)[0] is False


def test_nom_introuvable_refuse(monkeypatch):
    _resolution(monkeypatch, None)
    assert cible.verifier("https://nulle-part.test/")[0] is False


def test_route_utilise_la_verification_et_borne_la_reponse():
    src = (PKG / "api" / "main.py").read_text()
    corps = src[src.index('@router.post("/preload_url")'):src.index('@router.get("/list_rules")')]
    assert "cible.cible" in corps   # cible validée et épinglée (#3284)
    assert "follow_redirects=False" in corps
    assert "TAILLE_MAX_PRECHARGE" in corps and "aiter_bytes" in corps


@pytest.mark.parametrize("ip", ["64:ff9b::7f00:1", "::ffff:127.0.0.1", "2002:7f00:1::1"])
def test_ipv6_encapsulant_une_ipv4_privee_refusee(monkeypatch, ip):
    _resolution(monkeypatch, [ip])
    assert cible.verifier("https://exemple.test/")[0] is False


def test_port_zero_refuse(monkeypatch):
    _resolution(monkeypatch, ["93.184.216.34"])
    assert cible.verifier("http://exemple.test:0/")[0] is False


def test_message_generique(monkeypatch):
    _resolution(monkeypatch, None)
    introuvable = cible.verifier("https://a.test/")[1]
    _resolution(monkeypatch, ["10.0.0.1"])
    privee = cible.verifier("https://a.test/")[1]
    assert introuvable == privee == cible.MESSAGE_REFUS


def test_cible_epinglee(monkeypatch):
    """La connexion se fait sur l'IP validée (pas de seconde résolution : rebinding)."""
    _resolution(monkeypatch, ["93.184.216.34"])
    c = cible.cible("https://exemple.test/a.js?x=1")
    assert c.ip == "93.184.216.34" and c.hote == "exemple.test"
    assert c.url_epinglee == "https://93.184.216.34:443/a.js?x=1"
    _resolution(monkeypatch, ["2606:2800::1"])
    assert cible.cible("http://exemple.test/").url_epinglee == "http://[2606:2800::1]:80/"


def test_route_durcie():
    src = (PKG / "api" / "main.py").read_text()
    corps = src[src.index('@router.post("/preload_url")'):src.index('@router.get("/list_rules")')]
    assert "asyncio.to_thread(cible.cible" in corps
    assert "asyncio.timeout(" in corps
    assert "trust_env=False" in corps
    assert "sni_hostname" in corps and "url_epinglee" in corps
    assert "httpx.InvalidURL" in corps
    assert "audit" in corps
