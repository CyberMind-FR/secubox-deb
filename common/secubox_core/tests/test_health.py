# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for secubox_core.health.{parse_units,systemd_batch} — shared systemd
health-batch helper (ref #1175), ported from secubox-hub's
_refresh_health_batch() 5-branch classification."""
from pathlib import Path

from secubox_core.health import parse_units, systemd_batch

SAMPLE = (
    "secubox-waf.service loaded active running SecuBox WAF\n"
    "secubox-dpi.service loaded active reloading SecuBox DPI\n"
    "secubox-auth.service loaded failed failed SecuBox Auth\n"
    "secubox-foo.service loaded inactive dead SecuBox Foo\n"
)


def test_parse_units_ok_running():
    d = parse_units(SAMPLE)
    assert d["waf"] == {"status": "ok", "msg": "Running"}


def test_parse_units_warn_active_not_running():
    d = parse_units(SAMPLE)
    assert d["dpi"] == {"status": "warn", "msg": "Active (reloading)"}


def test_parse_units_error_failed():
    d = parse_units(SAMPLE)
    assert d["auth"] == {"status": "error", "msg": "Failed"}


def test_parse_units_warn_inactive_not_sleepable():
    d = parse_units(SAMPLE)
    assert d["foo"] == {"status": "warn", "msg": "inactive/dead"}


def test_parse_units_sleepable_inactive_is_ok():
    d = parse_units(SAMPLE, sleepable={"foo"})
    assert d["foo"] == {"status": "ok", "msg": "Asleep (on-demand)"}


def test_parse_units_sleepable_failed_still_error():
    # A crash is a real alarm even for a sleepable module (ref hub comment):
    # intentional sleep goes through disable+stop (inactive/dead), never failed.
    d = parse_units(SAMPLE, sleepable={"auth"})
    assert d["auth"] == {"status": "error", "msg": "Failed"}


def test_systemd_batch_uses_injected_run(tmp_path: Path):
    batch = systemd_batch(sock_dir=str(tmp_path), _run=lambda: SAMPLE)
    assert batch["waf"]["status"] == "ok"
    assert batch["dpi"]["status"] == "warn"
    assert batch["auth"]["status"] == "error"
    assert batch["foo"]["status"] == "warn"
    assert len(batch) == 4


def test_systemd_batch_adds_socket_only_modules(tmp_path: Path):
    (tmp_path / "extra.sock").touch()
    batch = systemd_batch(sock_dir=str(tmp_path), _run=lambda: SAMPLE)
    assert batch["extra"] == {"status": "ok", "msg": "Socket active"}


def test_systemd_batch_socket_does_not_override_known_module(tmp_path: Path):
    (tmp_path / "auth.sock").touch()
    batch = systemd_batch(sock_dir=str(tmp_path), _run=lambda: SAMPLE)
    # auth is already known (failed) from systemctl output — a stray
    # matching .sock file must never clobber that with "Socket active".
    assert batch["auth"] == {"status": "error", "msg": "Failed"}


def test_systemd_batch_sleepable_passthrough(tmp_path: Path):
    batch = systemd_batch(sock_dir=str(tmp_path), sleepable={"foo"}, _run=lambda: SAMPLE)
    assert batch["foo"] == {"status": "ok", "msg": "Asleep (on-demand)"}
