# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from api import alerts
from api.execwatch import ExecEvent


def test_ioc_match():
    assert alerts.ioc_match("5.182.207.11", {"ips": ["5.182.207.11"]}) is True
    assert alerts.ioc_match("1.1.1.1", {"ips": ["5.182.207.11"]}) is False


def test_ioc_match_empty_ioc():
    assert alerts.ioc_match("5.182.207.11", {}) is False


def test_emit_swallows_sink_error():
    a = {"x": 1}

    def boom(_):
        raise RuntimeError("soc down")

    called = []
    alerts.emit(
        a,
        soc_post=boom,
        mailer=lambda x: called.append("mail"),
        mesh=lambda x: called.append("mesh"),
    )
    assert "mail" in called and "mesh" in called


def test_emit_calls_all_sinks_on_success():
    a = {"x": 1}
    called = []
    alerts.emit(
        a,
        soc_post=lambda x: called.append("soc"),
        mailer=lambda x: called.append("mail"),
        mesh=lambda x: called.append("mesh"),
    )
    assert called == ["soc", "mail", "mesh"]


def test_emit_all_sinks_fail_never_raises():
    def boom(_):
        raise RuntimeError("down")

    alerts.emit({"x": 1}, soc_post=boom, mailer=boom, mesh=boom)


def test_build_alert_shape_no_dest():
    e = ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    a = alerts.build_alert(e, score=4, reasons=["non-dpkg-exec-path"])
    assert a["exe"] == "/tmp/x"
    assert a["pid"] == 7
    assert a["score"] == 4
    assert a["reasons"] == ["non-dpkg-exec-path"]
    assert a["dest"] is None
    assert a["ioc"] is False


def test_build_alert_ioc_true_when_dest_matches():
    e = ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    ioc = {"ips": ["5.182.207.11"]}
    a = alerts.build_alert(
        e, score=4, reasons=["non-dpkg-exec-path"], dest="5.182.207.11", ioc=ioc
    )
    assert a["dest"] == "5.182.207.11"
    assert a["ioc"] is True
    assert a["ioc"] == alerts.ioc_match("5.182.207.11", ioc)


def test_build_alert_ioc_false_when_dest_not_in_ioc():
    e = ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    ioc = {"ips": ["5.182.207.11"]}
    a = alerts.build_alert(
        e, score=4, reasons=["non-dpkg-exec-path"], dest="1.1.1.1", ioc=ioc
    )
    assert a["dest"] == "1.1.1.1"
    assert a["ioc"] is False


def test_build_alert_ioc_false_when_no_ioc_given():
    e = ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    a = alerts.build_alert(
        e, score=4, reasons=["non-dpkg-exec-path"], dest="5.182.207.11"
    )
    assert a["dest"] == "5.182.207.11"
    assert a["ioc"] is False
