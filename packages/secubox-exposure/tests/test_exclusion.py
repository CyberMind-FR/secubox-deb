# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tor-exclusion reader — reads the toolbox MITM-bypass (regex) + TLS-splice
(suffix) lists so cert-pinned hosts can never be Tor-exposed."""
import api.exclusion as ex


def _seed(tmp_path, monkeypatch, bypass="", splice=""):
    b = tmp_path / "mitm-bypass-seed.conf"
    b.write_text(bypass)
    s = tmp_path / "tls-splice-seed.conf"
    s.write_text(splice)
    monkeypatch.setattr(ex, "_BYPASS_FILES", (str(b),))
    monkeypatch.setattr(ex, "_SPLICE_FILES", (str(s),))


def test_signal_matched_via_bypass_regex(tmp_path, monkeypatch):
    # the real seed ships Signal as a regex; a subdomain must match.
    _seed(tmp_path, monkeypatch, bypass=r"(.+\.)?signal\.org")
    assert ex.is_excluded("chat.signal.org")
    assert ex.is_excluded("signal.org")


def test_anthropic_and_chatgpt_matched_via_splice_suffix(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, splice="api.anthropic.com\nchatgpt.com\n")
    assert ex.is_excluded("api.anthropic.com")
    assert ex.is_excluded("chatgpt.com")
    assert ex.is_excluded("web.chatgpt.com")   # suffix → subdomain


def test_internal_vhost_not_excluded(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, bypass=r"(.+\.)?signal\.org", splice="api.anthropic.com\n")
    assert not ex.is_excluded("zigbee.gk2.secubox.in")
    assert not ex.is_excluded("lyrion.gk2.secubox.in")


def test_lookalike_not_excluded(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, bypass=r"(.+\.)?signal\.org", splice="api.anthropic.com\n")
    assert not ex.is_excluded("evilsignal.org")          # fullmatch, not substring
    assert not ex.is_excluded("api.anthropic.com.evil.io")


def test_missing_lists_fail_open(tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "_BYPASS_FILES", (str(tmp_path / "nope.conf"),))
    monkeypatch.setattr(ex, "_SPLICE_FILES", (str(tmp_path / "nope2.conf"),))
    assert not ex.is_excluded("api.anthropic.com")       # no toolbox → nothing excluded


def test_malformed_regex_is_skipped_not_fatal(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, bypass="(unclosed\n(.+\\.)?signal\\.org")
    # bad line skipped, good line still matches
    assert ex.is_excluded("signal.org")


def test_non_utf8_bytes_fail_open_not_500(tmp_path, monkeypatch):
    """A corrupt / non-UTF-8 byte in a list file must not raise into the request
    path (UnicodeDecodeError is a ValueError, not OSError)."""
    b = tmp_path / "mitm-bypass-seed.conf"
    b.write_bytes(b"(.+\\.)?signal\\.org\n\xff\xfe garbage\n")
    s = tmp_path / "tls-splice-seed.conf"
    s.write_text("api.anthropic.com\n")
    monkeypatch.setattr(ex, "_BYPASS_FILES", (str(b),))
    monkeypatch.setattr(ex, "_SPLICE_FILES", (str(s),))
    # must not raise; the undecodable bypass file contributes nothing, but the
    # splice file still gates.
    assert ex.is_excluded("api.anthropic.com") is True
    assert ex.is_excluded("signal.org") is False   # bypass file unreadable → not seen


def test_reason_names_the_matching_list(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch, bypass=r"(.+\.)?signal\.org", splice="api.anthropic.com\n")
    ok, why = ex.exclusion_reason("signal.org")
    assert ok and "bypass" in why.lower()
    ok, why = ex.exclusion_reason("api.anthropic.com")
    assert ok and "splice" in why.lower()
