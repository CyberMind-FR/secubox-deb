# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import ip_dns


def test_load_cdn_allowlist_parses_and_skips(tmp_path):
    f = tmp_path / "cdn.txt"
    f.write_text(
        "# comment\n"
        "104.16.0.0/13\n"
        "\n"
        "2606:4700::/32\n"
        "not-a-cidr\n"
    )
    nets = ip_dns.load_cdn_allowlist(str(f))
    assert len(nets) == 2


def test_ip_in_allowlist_v4_and_v6(tmp_path):
    f = tmp_path / "cdn.txt"
    f.write_text("104.16.0.0/13\n2606:4700::/32\n")
    nets = ip_dns.load_cdn_allowlist(str(f))
    assert ip_dns.ip_in_allowlist("104.16.5.5", nets) is True
    assert ip_dns.ip_in_allowlist("8.8.8.8", nets) is False
    assert ip_dns.ip_in_allowlist("2606:4700::1111", nets) is True
    assert ip_dns.ip_in_allowlist("garbage", nets) is False


def test_load_missing_file_returns_empty():
    assert ip_dns.load_cdn_allowlist("/no/such/file.txt") == []


def test_exclusive_tracker_ips_excludes_cdn(tmp_path):
    f = tmp_path / "cdn.txt"
    f.write_text("104.16.0.0/13\n")
    nets = ip_dns.load_cdn_allowlist(str(f))
    resolve = {"pure1.trk": ["203.0.113.7"],
               "pure2.trk": ["104.16.9.9"]}.get
    out = ip_dns.exclusive_tracker_ips(
        ["pure1.trk", "pure2.trk"], lambda h: resolve(h) or [], nets)
    assert out == {"203.0.113.7"}


def test_exclusive_tracker_ips_dedups_and_handles_empty():
    out = ip_dns.exclusive_tracker_ips(
        ["a.trk", "b.trk"],
        lambda h: ["198.51.100.5"],
        [])
    assert out == {"198.51.100.5"}
    assert ip_dns.exclusive_tracker_ips([], lambda h: ["1.2.3.4"], []) == set()


def test_unbound_block_lines_folds_dedups_sorts():
    lines = ip_dns.unbound_block_lines(
        ["www.criteo.com", "doubleclick.net", "criteo.com", ""])
    assert lines[0] == "server:"
    lz = [l for l in lines if "local-zone:" in l]
    assert lz == [
        '    local-zone: "criteo.com." always_nxdomain',
        '    local-zone: "doubleclick.net." always_nxdomain',
    ]


def test_unbound_block_lines_empty_has_only_server_header():
    lines = ip_dns.unbound_block_lines([])
    assert "server:" in lines
    assert not any("local-zone:" in l for l in lines)
