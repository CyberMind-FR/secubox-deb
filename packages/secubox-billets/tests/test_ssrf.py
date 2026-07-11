# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import httpx
import pytest

from api.services import ssrf


def _resolver(mapping):
    def r(host, port):
        ip = mapping.get(host, "93.184.216.34")  # default: a public TEST-NET IP
        return [(0, 0, 0, "", (ip, port))]
    return r


def test_is_public_ip():
    assert ssrf.is_public_ip("93.184.216.34") is True
    for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", "::1",
                "fe80::1", "0.0.0.0", "224.0.0.1"):
        assert ssrf.is_public_ip(bad) is False, bad


def test_validate_rejects_non_https():
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url("http://example.com/x", resolver=_resolver({}))
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url("file:///etc/passwd", resolver=_resolver({}))


def test_validate_rejects_private_resolution():
    for ip in ("127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.0.9"):
        with pytest.raises(ssrf.SSRFError):
            ssrf.validate_url("https://evil.example", resolver=_resolver({"evil.example": ip}))


def test_validate_accepts_public():
    host = ssrf.validate_url("https://youtube.com/watch?v=x",
                             resolver=_resolver({"youtube.com": "142.250.1.1"}))
    assert host == "youtube.com"


async def test_fetch_refuses_redirect_to_private():
    # first host public, redirect Location points at a host that resolves private
    resolver = _resolver({"good.example": "93.184.216.34", "meta.example": "169.254.169.254"})

    def handler(request):
        if request.url.host == "good.example":
            return httpx.Response(302, headers={"location": "https://meta.example/latest/meta-data/"})
        return httpx.Response(200, text="secret")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ssrf.SSRFError):
        await ssrf.fetch("https://good.example/x", client=client, resolver=resolver)
    await client.aclose()


async def test_fetch_size_cap():
    resolver = _resolver({"big.example": "93.184.216.34"})

    def handler(request):
        return httpx.Response(200, content=b"A" * 5000)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(ssrf.SSRFError):
        await ssrf.fetch("https://big.example/x", client=client, resolver=resolver, max_bytes=1000)
    await client.aclose()


async def test_fetch_ok():
    resolver = _resolver({"ok.example": "93.184.216.34"})

    def handler(request):
        return httpx.Response(200, content=b"<html>hi</html>",
                              headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    final, ctype, body = await ssrf.fetch("https://ok.example/p", client=client, resolver=resolver)
    assert body == b"<html>hi</html>" and "html" in ctype
    await client.aclose()
