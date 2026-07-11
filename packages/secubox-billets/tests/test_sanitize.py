# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from api.services.sanitize import sanitize_embed

ALLOWED = {"youtube.com", "player.vimeo.com", "vimeo.com"}


def test_strips_script_and_handlers():
    out = sanitize_embed('<div onclick="x()">hi<script>alert(1)</script></div>', ALLOWED)
    assert "<script>" not in out and "alert(1)" not in out
    assert "onclick" not in out


def test_strips_javascript_href():
    out = sanitize_embed('<a href="javascript:alert(1)">x</a>', ALLOWED)
    assert "javascript:" not in out


def test_allowed_iframe_kept_and_hardened():
    html = '<iframe src="https://www.youtube.com/embed/abc" width="560" height="315" onload="evil()"></iframe>'
    out = sanitize_embed(html, ALLOWED)
    assert 'src="https://www.youtube.com/embed/abc"' in out
    assert 'sandbox="allow-scripts allow-same-origin allow-popups allow-presentation"' in out
    assert 'loading="lazy"' in out
    assert "onload" not in out  # forced-canonical iframe drops all other attrs


def test_disallowed_iframe_removed():
    html = '<iframe src="https://evil.example/x"></iframe>'
    out = sanitize_embed(html, ALLOWED)
    assert "<iframe" not in out
    assert "evil.example" not in out


def test_non_https_iframe_removed():
    html = '<iframe src="http://www.youtube.com/embed/x"></iframe>'
    out = sanitize_embed(html, ALLOWED)
    assert "<iframe" not in out


def test_subdomain_allowlist_match():
    html = '<iframe src="https://www.youtube.com/embed/x"></iframe>'
    out = sanitize_embed(html, {"youtube.com"})
    assert "<iframe" in out  # www.youtube.com matches suffix youtube.com


def test_srcdoc_and_data_uri_iframe_removed():
    # an iframe with no allowlisted https src (srcdoc / data:) must be dropped
    out = sanitize_embed('<iframe srcdoc="<script>alert(1)</script>"></iframe>', ALLOWED)
    assert "<iframe" not in out and "alert(1)" not in out
