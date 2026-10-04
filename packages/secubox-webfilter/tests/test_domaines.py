# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pytest

from webfilter import domaines


@pytest.mark.parametrize("brut,attendu", [
    ("Example.COM", "example.com"), ("example.com.", "example.com"), ("a-b.example.org", "a-b.example.org"),
    ("xn--nxasmq6b.com", "xn--nxasmq6b.com"), ("sub.dom_ain.example.net", "sub.dom_ain.example.net"),
])
def test_valides(brut, attendu):
    assert domaines.valider(brut) == attendu


@pytest.mark.parametrize("brut", [
    "", "localhost", "nodot", "1.2.3.4", "::1", "exa mple.com", "example..com", "-bad.example.com", "bad-.example.com",
    "exa\nmple.com", "exa\x00mple.com", "a" * 64 + ".com", ("a." * 130) + "com", "example.c", "example.123", 'x".com', "é.com", None, 42,
])
def test_refuses(brut):
    assert domaines.valider(brut) is None
