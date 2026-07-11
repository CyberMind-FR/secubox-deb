# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from publish.certs import provision_cert, is_wildcard_domain


def test_gk2_is_wildcard():
    assert is_wildcard_domain("zem.gk2.secubox.in") is True
    assert is_wildcard_domain("blog.example.com") is False


def test_provision_gk2_returns_wildcard():
    res = provision_cert("zem.gk2.secubox.in", runner=lambda v, *a: {"ok": True, "detail": "wildcard"})
    assert res["mode"] == "wildcard"


def test_provision_custom_issued():
    res = provision_cert("blog.example.com", runner=lambda v, *a: {"ok": True, "detail": "issued"})
    assert res["mode"] == "issued"


def test_provision_custom_failure_is_pending():
    res = provision_cert("blog.example.com", runner=lambda v, *a: {"ok": False, "detail": "certbot failed"})
    assert res["mode"] == "pending"
    assert "certbot" in res["detail"]
