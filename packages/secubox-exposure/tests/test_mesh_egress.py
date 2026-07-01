# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""secubox-exposure :: mesh_egress pure-helper tests (appstore-federation #768)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from mesh_egress import (  # noqa: E402
    insert_before_drop, mesh_endpoint, mesh_nft_line, offer_argv,
)


def test_mesh_nft_line():
    assert mesh_nft_line(8090) == 'iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8090 accept'


def test_mesh_endpoint_and_offer_argv():
    assert mesh_endpoint("10.10.0.1", 8090) == "http://10.10.0.1:8090/"
    argv = offer_argv("yacy", 8090, "10.10.0.1")
    assert argv[:3] == ["annuairectl", "offer", "--name"]
    assert "emancipated" in argv and "channel=mesh" in argv
    assert "http://10.10.0.1:8090/" in argv and "port=8090" in argv


def test_insert_before_drop_places_rule_and_is_idempotent():
    conf = (
        "table inet secubox_filter {\n"
        "    chain input {\n"
        "        tcp dport { 80, 443 } accept\n"
        "        drop\n"
        "    }\n"
        "}\n"
    )
    rule = mesh_nft_line(8090)
    out = insert_before_drop(conf, rule)
    lines = [l.strip() for l in out.splitlines()]
    # rule sits immediately before the terminal drop
    assert lines[lines.index("drop") - 1] == rule
    # idempotent
    assert insert_before_drop(out, rule) == out


def test_insert_before_drop_noop_without_terminal_drop():
    # a hub 'inet filter' with only a chain policy drop (no standalone drop line)
    conf = "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    ip saddr 10.0.0.0/8 accept\n  }\n}\n"
    rule = mesh_nft_line(8090)
    assert insert_before_drop(conf, rule) == conf
