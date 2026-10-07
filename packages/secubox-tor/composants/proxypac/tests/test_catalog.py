# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from proxypac.catalog import service_rules

def test_socks5_service_rule():
    svcs = [{"service_id": "s1", "enabled": True,
             "endpoint": "http://10.10.0.1/tor",
             "macro": {"kind": "tor-exit", "params": {"socks_port": 9050}},
             "pac": {"match": ["*.onion"], "proxy": "socks5"}}]
    rules = service_rules(svcs)
    assert (rules[0].host, rules[0].directive) == ("*.onion", "SOCKS5 10.10.0.1:9050; DIRECT")
    assert rules[0].source == "service:s1"

def test_disabled_and_pacless_skipped():
    svcs = [
        {"service_id": "s2", "enabled": False, "endpoint": "http://10.10.0.2/x",
         "pac": {"match": ["a"], "proxy": "socks5"}},
        {"service_id": "s3", "enabled": True, "endpoint": "http://10.10.0.3/x"},  # no pac
    ]
    assert service_rules(svcs) == []

def test_gateway_service_uses_endpoint_host():
    svcs = [{"service_id": "s4", "enabled": True, "endpoint": "http://gk2.secubox.in/app",
             "pac": {"match": ["app.local"], "proxy": "gateway"}}]
    rules = service_rules(svcs)
    assert rules[0].directive == "PROXY gk2.secubox.in; DIRECT"
