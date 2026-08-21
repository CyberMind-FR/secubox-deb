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
