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
