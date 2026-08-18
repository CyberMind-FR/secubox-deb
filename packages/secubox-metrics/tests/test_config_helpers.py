# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for the three new config helpers in secubox_core.config."""
from pathlib import Path

import secubox_core.config as cfg


def _reload_with(monkeypatch, tmp_path: Path, toml_text: str):
    monkeypatch.setattr(cfg, "_CONFIG", None)
    fake = tmp_path / "_secubox_test_conf.toml"
    fake.write_text(toml_text)
    monkeypatch.setattr(cfg, "_CONF_PATHS", [fake])


def test_visitor_origin_defaults_when_absent(monkeypatch, tmp_path):
    _reload_with(monkeypatch, tmp_path, "[global]\nhostname='test'\n")
    out = cfg.get_visitor_origin_config()
    assert out["enabled"] is False
    assert out["window_minutes"] == 60
    assert out["min_count"] == 5
    assert out["top_n"] == 5
    assert out["asn_db_path"] == "/var/lib/GeoIP/GeoLite2-ASN.mmdb"
    assert out["nft_table"] == "secubox_metrics"
    assert out["nft_set"] == "seen_src"
    assert out["nft_family"] == "inet"


def test_visitor_origin_overrides(monkeypatch, tmp_path):
    _reload_with(
        monkeypatch,
        tmp_path,
        "[visitor_origin]\nenabled=true\nmin_count=2\ntop_n=3\n",
    )
    out = cfg.get_visitor_origin_config()
    assert out["enabled"] is True
    assert out["min_count"] == 2
    assert out["top_n"] == 3
    assert out["window_minutes"] == 60


def test_live_hosts_defaults(monkeypatch, tmp_path):
    _reload_with(monkeypatch, tmp_path, "[global]\nhostname='test'\n")
    out = cfg.get_live_hosts_config()
    assert out["enabled"] is False
    assert out["window_minutes"] == 60
    assert out["top_n"] == 5
    assert out["haproxy_socket"] == "/run/haproxy/admin.sock"
    assert out["frontend_filter"] == "*"


def test_cert_status_defaults(monkeypatch, tmp_path):
    _reload_with(monkeypatch, tmp_path, "[global]\nhostname='test'\n")
    out = cfg.get_cert_status_config()
    assert out["enabled"] is False
    assert out["letsencrypt_live_dir"] == "/etc/letsencrypt/live"
    assert out["warn_days"] == 30
    assert out["critical_days"] == 7
