# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.generator tests."""
import pytest

from proxypac.generator import generate, write_atomic


def test_generate_composes_override_over_service(tmp_path):
    (tmp_path / "10.rules").write_text("x.com direct\n")
    svcs = [{"service_id": "s1", "enabled": True, "endpoint": "http://10.10.0.1/tor",
             "macro": {"params": {"socks_port": 9050}},
             "pac": {"match": ["x.com", "*.onion"], "proxy": "socks5"}}]
    pac = generate(tmp_path, svcs, toolbox_directive="PROXY 127.0.0.1:8081; DIRECT")
    # override x.com -> DIRECT wins; *.onion via socks; toolbox catch-all last
    assert pac.index('shExpMatch(host, "x.com")') < pac.index('shExpMatch(host, "*.onion")')
    assert 'return "DIRECT";' in pac and 'SOCKS5 10.10.0.1:9050; DIRECT' in pac
    assert 'shExpMatch(host, "*")' in pac


def test_write_atomic_swaps_and_validates(tmp_path):
    out = tmp_path / "proxy.pac"
    write_atomic('function FindProxyForURL(url, host) {\n  return "DIRECT";\n}\n', out)
    assert out.read_text().startswith("function FindProxyForURL")
    assert not (tmp_path / "proxy.pac.shadow").exists()


def test_write_atomic_rejects_invalid_keeps_lastgood(tmp_path):
    out = tmp_path / "proxy.pac"
    write_atomic('function FindProxyForURL(url, host) { return "DIRECT"; }\n', out)
    good = out.read_text()
    with pytest.raises(ValueError):
        write_atomic("garbage not a pac", out)      # no FindProxyForURL → rejected
    assert out.read_text() == good                   # last-good preserved
    assert not (tmp_path / "proxy.pac.shadow").exists()


def test_run_once_failsafe_on_malformed_rule(tmp_path):
    from proxypac.generator import run_once, write_atomic
    rules = tmp_path / "rules.d"; rules.mkdir()
    (rules / "10.rules").write_text("onlyonetoken\n")   # missing proxy_type -> IndexError in parse
    out = tmp_path / "proxy.pac"
    write_atomic('function FindProxyForURL(url, host) {\n  return "DIRECT";\n}\n', out)
    good = out.read_text()
    ok = run_once(rules_dir=rules, sock="/nonexistent.sock", out=out)
    assert ok is False          # generation failed
    assert out.read_text() == good   # last-good preserved, not clobbered
